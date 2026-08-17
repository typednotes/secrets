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
}
