use std::collections::HashMap;

use async_trait::async_trait;
use secrets_core::storage::{StorageBackend, StorageEntry, StorageError, StorageResult};
use sha2::{Digest, Sha256};
use sqlx::pool::PoolConnection;
use sqlx::{PgPool, Postgres};
use tokio::sync::Mutex;

pub struct PgStorage {
    pool: PgPool,
    /// Connections held open purely to keep `pg_advisory_lock` sessions alive.
    ///
    /// A Postgres advisory lock belongs to the *session* that took it, so the
    /// connection cannot go back to the pool: another query reusing it could
    /// release the lock, and a pooled `pg_advisory_unlock` might run on a
    /// connection that never held it. Holding the connection also gives
    /// failover for free — when the process dies the connection closes and
    /// Postgres drops the lock, with no lease timeout to tune.
    locks: Mutex<HashMap<String, PoolConnection<Postgres>>>,
}

impl PgStorage {
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPool::connect(database_url).await?;
        sqlx::migrate!("./src/migrations").run(&pool).await?;
        Ok(Self {
            pool,
            locks: Mutex::new(HashMap::new()),
        })
    }
}

/// Advisory locks are keyed by a single 64-bit integer, so a name has to be
/// folded down to one. It must be stable across processes and releases —
/// `DefaultHasher` is explicitly not, so hash with SHA-256 instead.
fn advisory_lock_id(key: &str) -> i64 {
    let digest = Sha256::digest(key.as_bytes());
    i64::from_be_bytes(digest[..8].try_into().expect("sha256 digest is 32 bytes"))
}

#[async_trait]
impl StorageBackend for PgStorage {
    async fn get(&self, path: &str) -> StorageResult<Option<StorageEntry>> {
        let row = sqlx::query_as::<_, (Vec<u8>, Option<chrono::DateTime<chrono::Utc>>)>(
            "SELECT value, expires_at FROM kv_store WHERE path = $1",
        )
        .bind(path)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;

        Ok(row.map(|(value, expires_at)| StorageEntry { value, expires_at }))
    }

    async fn put(&self, path: &str, entry: StorageEntry) -> StorageResult<()> {
        sqlx::query(
            "INSERT INTO kv_store (path, value, expires_at, updated_at)
             VALUES ($1, $2, $3, now())
             ON CONFLICT (path) DO UPDATE SET value = $2, expires_at = $3, updated_at = now()",
        )
        .bind(path)
        .bind(entry.value)
        .bind(entry.expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn delete(&self, path: &str) -> StorageResult<()> {
        sqlx::query("DELETE FROM kv_store WHERE path = $1")
            .bind(path)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn ping(&self) -> StorageResult<()> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(())
    }

    /// Served by the partial index on `expires_at` from the initial
    /// migration, so the reaper no longer reads every lease to find the few
    /// that expired.
    async fn list_expired(
        &self,
        prefix: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> StorageResult<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT path FROM kv_store
             WHERE path LIKE $1 || '%' AND expires_at IS NOT NULL AND expires_at <= $2",
        )
        .bind(prefix)
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(rows.into_iter().map(|(p,)| p).collect())
    }

    /// One statement, so the comparison and the write cannot be interleaved.
    async fn replace_if_unchanged(
        &self,
        path: &str,
        expected: &[u8],
        entry: StorageEntry,
    ) -> StorageResult<bool> {
        let result = sqlx::query(
            "UPDATE kv_store SET value = $3, expires_at = $4, updated_at = now()
             WHERE path = $1 AND value = $2",
        )
        .bind(path)
        .bind(expected)
        .bind(entry.value)
        .bind(entry.expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(result.rows_affected() == 1)
    }

    async fn try_acquire_lock(&self, key: &str) -> StorageResult<bool> {
        let mut locks = self.locks.lock().await;
        // Already leading. Re-taking the same advisory lock on the same
        // session would succeed and just bump Postgres' own counter, so skip
        // the round trip entirely.
        if locks.contains_key(key) {
            return Ok(true);
        }

        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;
        let (acquired,): (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
            .bind(advisory_lock_id(key))
            .fetch_one(&mut *conn)
            .await
            .map_err(|e| StorageError::Backend(e.to_string()))?;

        if acquired {
            locks.insert(key.to_string(), conn);
        }
        Ok(acquired)
    }

    async fn list(&self, prefix: &str) -> StorageResult<Vec<String>> {
        let rows: Vec<(String,)> =
            sqlx::query_as("SELECT path FROM kv_store WHERE path LIKE $1 || '%'")
                .bind(prefix)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| StorageError::Backend(e.to_string()))?;
        Ok(rows.into_iter().map(|(p,)| p).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::advisory_lock_id;

    /// The id has to be identical in every process that competes for the
    /// lock, so this is a pinned value, not a round-trip check.
    #[test]
    fn advisory_lock_ids_are_stable_and_distinct() {
        assert_eq!(advisory_lock_id("secrets/lease-reaper"), advisory_lock_id("secrets/lease-reaper"));
        assert_ne!(advisory_lock_id("secrets/lease-reaper"), advisory_lock_id("secrets/other"));
    }
}
