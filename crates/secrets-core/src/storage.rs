use async_trait::async_trait;
use chrono::{DateTime, Utc};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("backend error: {0}")]
    Backend(String),
    #[error("not found")]
    NotFound,
}

pub type StorageResult<T> = Result<T, StorageError>;

#[derive(Debug, Clone)]
pub struct StorageEntry {
    pub value: Vec<u8>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[async_trait]
pub trait StorageBackend: Send + Sync {
    async fn get(&self, path: &str) -> StorageResult<Option<StorageEntry>>;
    async fn put(&self, path: &str, entry: StorageEntry) -> StorageResult<()>;
    async fn delete(&self, path: &str) -> StorageResult<()>;
    async fn list(&self, prefix: &str) -> StorageResult<Vec<String>>;

    /// Paths under `prefix` whose `expires_at` has already passed.
    ///
    /// The default walks every key and fetches it, which is what the lease
    /// reaper used to do unconditionally. A backend that keeps expiry in a
    /// queryable column should override this: the reaper runs on an interval
    /// forever, so the naive scan is O(all leases) per pass per deployment.
    async fn list_expired(&self, prefix: &str, now: DateTime<Utc>) -> StorageResult<Vec<String>> {
        let mut expired = Vec::new();
        for path in self.list(prefix).await? {
            if let Some(entry) = self.get(&path).await?
                && entry.expires_at.is_some_and(|at| at <= now)
            {
                expired.push(path);
            }
        }
        Ok(expired)
    }

    /// Replaces `path`'s value only if it still holds exactly `expected`,
    /// returning false when it changed underneath.
    ///
    /// Needed by key rotation, which decrypts and re-encrypts in three steps:
    /// without this, a write landing between the read and the write would be
    /// silently overwritten by a re-encryption of stale plaintext.
    ///
    /// The default is read-compare-write, which is *not* atomic — override it
    /// wherever the backend can do the comparison itself.
    async fn replace_if_unchanged(
        &self,
        path: &str,
        expected: &[u8],
        entry: StorageEntry,
    ) -> StorageResult<bool> {
        match self.get(path).await? {
            Some(current) if current.value == expected => {
                self.put(path, entry).await?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Cheap liveness probe for the health endpoint. It must stay cheap: a
    /// load balancer calls it constantly, against every replica, forever.
    async fn ping(&self) -> StorageResult<()> {
        Ok(())
    }

    /// Best-effort cross-process mutual exclusion, so exactly one replica
    /// runs a singleton background task. Granting unconditionally is correct
    /// for a single-node or in-memory backend, which is why that is the
    /// default.
    ///
    /// A real implementation must tie the lock to the connection holding it,
    /// so that a crashed node releases it without anyone noticing — that is
    /// what makes failover work without heartbeats or timeouts. There is
    /// deliberately no `release`: the lock is held for the process lifetime
    /// and the backend reclaims it when the connection dies.
    async fn try_acquire_lock(&self, _key: &str) -> StorageResult<bool> {
        Ok(true)
    }
}
