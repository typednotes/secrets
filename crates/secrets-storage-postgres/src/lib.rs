use async_trait::async_trait;
use secrets_core::storage::{StorageBackend, StorageEntry, StorageError, StorageResult};
use sqlx::PgPool;

pub struct PgStorage {
    pool: PgPool,
}

impl PgStorage {
    pub async fn connect(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPool::connect(database_url).await?;
        sqlx::migrate!("./src/migrations").run(&pool).await?;
        Ok(Self { pool })
    }
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
