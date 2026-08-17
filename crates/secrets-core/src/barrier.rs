use async_trait::async_trait;
use std::sync::Arc;

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
}
