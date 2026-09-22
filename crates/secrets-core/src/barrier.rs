use async_trait::async_trait;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::crypto::Aead;
use crate::storage::{StorageBackend, StorageEntry, StorageResult};

/// Wraps a raw `StorageBackend`, transparently AEAD-encrypting/decrypting
/// values. Paths are left in plaintext (same as Vault's own barrier).
pub struct Barrier<B: StorageBackend> {
    inner: B,
    aead: Arc<dyn Aead>,
}

impl<B: StorageBackend> Barrier<B> {
    pub fn new(inner: B, aead: Arc<dyn Aead>) -> Self {
        Self { inner, aead }
    }
}

/// What a rewrap pass did. `unchanged` is the steady state — everything is
/// already on the active key — and `contended` counts values a concurrent
/// write claimed first, which is benign: that write used the active key too.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RewrapReport {
    pub scanned: usize,
    pub rewrapped: usize,
    pub unchanged: usize,
    pub contended: usize,
    pub failed: usize,
}

/// Re-encrypting the whole store under a new master key. Separate from
/// `StorageBackend` because only the barrier knows about keys, and exposed as
/// a trait so the server can hold it behind an `Arc` without naming the
/// concrete backend.
#[async_trait]
pub trait KeyRotation: Send + Sync {
    /// Rewraps every value not already sealed under the active key.
    /// Idempotent and safe to re-run: a second pass reports everything as
    /// `unchanged`.
    async fn rewrap_all(&self) -> StorageResult<RewrapReport>;

    /// The active key's derived id, so an operator can confirm which key a
    /// replica is actually sealing with.
    fn active_key_id(&self) -> String;
}

#[async_trait]
impl<B: StorageBackend> KeyRotation for Barrier<B> {
    async fn rewrap_all(&self) -> StorageResult<RewrapReport> {
        let mut report = RewrapReport::default();

        // Reads the raw backend, not ourselves: rewrapping is the one
        // operation that has to see ciphertext.
        for path in self.inner.list("").await? {
            report.scanned += 1;
            let Some(entry) = self.inner.get(&path).await? else {
                continue; // deleted while we were scanning
            };
            if self.aead.is_current(&entry.value) {
                report.unchanged += 1;
                continue;
            }

            let Ok(plaintext) = self.aead.open(&entry.value) else {
                // A value whose key is no longer in the ring. Keep going —
                // stopping would leave the rest of the store un-rotated, and
                // the count is what tells the operator to restore the key.
                tracing::error!(path, "cannot rewrap: no key in the ring opens this value");
                report.failed += 1;
                continue;
            };
            let resealed = self
                .aead
                .seal(&plaintext)
                .map_err(|e| crate::storage::StorageError::Backend(e.to_string()))?;

            // Conditional on the ciphertext we read. Without this, a write
            // landing between the read and the write would be overwritten by
            // a re-encryption of the value it replaced.
            let replaced = self
                .inner
                .replace_if_unchanged(
                    &path,
                    &entry.value,
                    StorageEntry {
                        value: resealed,
                        expires_at: entry.expires_at,
                    },
                )
                .await?;
            if replaced {
                report.rewrapped += 1;
            } else {
                report.contended += 1;
            }
        }

        tracing::info!(
            scanned = report.scanned,
            rewrapped = report.rewrapped,
            failed = report.failed,
            "rewrap pass complete"
        );
        Ok(report)
    }

    fn active_key_id(&self) -> String {
        self.aead.active_key_id()
    }
}

#[async_trait]
impl<B: StorageBackend> StorageBackend for Barrier<B> {
    async fn get(&self, path: &str) -> StorageResult<Option<StorageEntry>> {
        let Some(entry) = self.inner.get(path).await? else {
            return Ok(None);
        };
        let plaintext = self
            .aead
            .open(&entry.value)
            .map_err(|e| crate::storage::StorageError::Backend(e.to_string()))?;
        Ok(Some(StorageEntry {
            value: plaintext,
            expires_at: entry.expires_at,
        }))
    }

    async fn put(&self, path: &str, entry: StorageEntry) -> StorageResult<()> {
        let ciphertext = self
            .aead
            .seal(&entry.value)
            .map_err(|e| crate::storage::StorageError::Backend(e.to_string()))?;
        self.inner
            .put(
                path,
                StorageEntry {
                    value: ciphertext,
                    expires_at: entry.expires_at,
                },
            )
            .await
    }

    async fn delete(&self, path: &str) -> StorageResult<()> {
        self.inner.delete(path).await
    }

    async fn list(&self, prefix: &str) -> StorageResult<Vec<String>> {
        self.inner.list(prefix).await
    }

    // Neither of these touches stored values, so the barrier has nothing to
    // encrypt or decrypt — but it must still pass them through, or wrapping a
    // backend would silently downgrade it to the permissive defaults.
    async fn ping(&self) -> StorageResult<()> {
        self.inner.ping().await
    }

    async fn list_expired(
        &self,
        prefix: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> StorageResult<Vec<String>> {
        // Expiry is stored in plaintext alongside the ciphertext precisely so
        // it can be queried without unsealing anything.
        self.inner.list_expired(prefix, now).await
    }

    async fn replace_if_unchanged(
        &self,
        path: &str,
        expected: &[u8],
        entry: StorageEntry,
    ) -> StorageResult<bool> {
        let ciphertext = self
            .aead
            .seal(&entry.value)
            .map_err(|e| crate::storage::StorageError::Backend(e.to_string()))?;
        self.inner
            .replace_if_unchanged(
                path,
                expected,
                StorageEntry {
                    value: ciphertext,
                    expires_at: entry.expires_at,
                },
            )
            .await
    }

    async fn try_acquire_lock(&self, key: &str) -> StorageResult<bool> {
        self.inner.try_acquire_lock(key).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Aes256GcmAead, KeyRing};
    use crate::storage::StorageResult;
    use std::collections::HashMap;
    use std::sync::Mutex;

    const OLD: [u8; 32] = [7u8; 32];
    const NEW: [u8; 32] = [11u8; 32];

    #[derive(Default)]
    struct MemStorage(Mutex<HashMap<String, StorageEntry>>);

    #[async_trait]
    impl StorageBackend for MemStorage {
        async fn get(&self, path: &str) -> StorageResult<Option<StorageEntry>> {
            Ok(self.0.lock().unwrap().get(path).cloned())
        }
        async fn put(&self, path: &str, entry: StorageEntry) -> StorageResult<()> {
            self.0.lock().unwrap().insert(path.to_string(), entry);
            Ok(())
        }
        async fn delete(&self, path: &str) -> StorageResult<()> {
            self.0.lock().unwrap().remove(path);
            Ok(())
        }
        async fn list(&self, prefix: &str) -> StorageResult<Vec<String>> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }
    }

    fn entry(value: &[u8]) -> StorageEntry {
        StorageEntry {
            value: value.to_vec(),
            expires_at: None,
        }
    }

    #[tokio::test]
    async fn rewrap_moves_pre_rotation_values_onto_the_active_key() {
        // Seed the raw store exactly as version 0.1 would have left it.
        let raw = MemStorage::default();
        let legacy = Aes256GcmAead::new(&OLD);
        raw.put("secret/a", entry(&legacy.seal(b"alpha").unwrap()))
            .await
            .unwrap();

        let barrier = Barrier::new(raw, Arc::new(KeyRing::new(&NEW, &[OLD])));
        assert_eq!(barrier.get("secret/a").await.unwrap().unwrap().value, b"alpha");

        let report = barrier.rewrap_all().await.unwrap();
        assert_eq!((report.scanned, report.rewrapped, report.failed), (1, 1, 0));
        assert_eq!(barrier.get("secret/a").await.unwrap().unwrap().value, b"alpha");

        // The point of the exercise: the old key can now be dropped.
        let rotated = Barrier::new(barrier.inner, Arc::new(KeyRing::new(&NEW, &[])));
        assert_eq!(rotated.get("secret/a").await.unwrap().unwrap().value, b"alpha");
    }

    #[tokio::test]
    async fn rewrap_is_idempotent() {
        let barrier = Barrier::new(MemStorage::default(), Arc::new(KeyRing::new(&NEW, &[OLD])));
        barrier.put("secret/a", entry(b"alpha")).await.unwrap();

        let first = barrier.rewrap_all().await.unwrap();
        assert_eq!(first.unchanged, 1, "a fresh write is already on the active key");

        let second = barrier.rewrap_all().await.unwrap();
        assert_eq!((second.rewrapped, second.unchanged), (0, 1));
    }

    /// A value whose key was dropped must be counted and reported, not
    /// silently skipped and not fatal to the rest of the pass.
    #[tokio::test]
    async fn rewrap_reports_values_it_cannot_open() {
        let raw = MemStorage::default();
        let orphan = KeyRing::new(&OLD, &[]);
        raw.put("secret/orphan", entry(&orphan.seal(b"lost").unwrap()))
            .await
            .unwrap();

        let barrier = Barrier::new(raw, Arc::new(KeyRing::new(&NEW, &[])));
        barrier.put("secret/fine", entry(b"kept")).await.unwrap();

        let report = barrier.rewrap_all().await.unwrap();
        assert_eq!(report.failed, 1, "the orphan should be reported");
        assert_eq!(report.unchanged, 1, "the healthy value should still be seen");
        assert_eq!(barrier.get("secret/fine").await.unwrap().unwrap().value, b"kept");
    }

    /// The race rewrap has to survive: a write lands between our read and our
    /// write. The conditional replace must decline rather than resurrect the
    /// stale plaintext.
    #[tokio::test]
    async fn conditional_replace_declines_when_the_value_moved() {
        let raw = MemStorage::default();
        raw.put("secret/a", entry(b"first")).await.unwrap();

        let replaced = raw
            .replace_if_unchanged("secret/a", b"stale-expectation", entry(b"second"))
            .await
            .unwrap();
        assert!(!replaced);
        assert_eq!(raw.get("secret/a").await.unwrap().unwrap().value, b"first");

        let replaced = raw
            .replace_if_unchanged("secret/a", b"first", entry(b"second"))
            .await
            .unwrap();
        assert!(replaced);
        assert_eq!(raw.get("secret/a").await.unwrap().unwrap().value, b"second");
    }
}
