use async_trait::async_trait;
use thiserror::Error;

use crate::lease::Lease;
use crate::storage::StorageBackend;

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("not found")]
    NotFound,
    #[error("operation not supported by this engine")]
    Unsupported,
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("storage error: {0}")]
    Storage(#[from] crate::storage::StorageError),
    #[error("engine error: {0}")]
    Other(String),
}

pub type EngineResult<T> = Result<T, EngineError>;

#[async_trait]
pub trait SecretsEngine: Send + Sync {
    async fn read(&self, storage: &dyn StorageBackend, path: &str) -> EngineResult<serde_json::Value>;
    async fn write(
        &self,
        storage: &dyn StorageBackend,
        path: &str,
        data: serde_json::Value,
    ) -> EngineResult<()>;
    async fn delete(&self, storage: &dyn StorageBackend, path: &str) -> EngineResult<()>;
    async fn list(&self, storage: &dyn StorageBackend, prefix: &str) -> EngineResult<Vec<String>>;

    /// Dynamic-secret engines (e.g. Postgres) override these; static
    /// engines (e.g. KV) inherit the default `Unsupported`.
    async fn generate(
        &self,
        _storage: &dyn StorageBackend,
        _role: &str,
    ) -> EngineResult<(serde_json::Value, Lease)> {
        Err(EngineError::Unsupported)
    }

    async fn revoke(&self, _storage: &dyn StorageBackend, _lease: &Lease) -> EngineResult<()> {
        Err(EngineError::Unsupported)
    }
}
