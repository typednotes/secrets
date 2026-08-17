use async_trait::async_trait;
use thiserror::Error;

use crate::storage::StorageBackend;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("storage error: {0}")]
    Storage(#[from] crate::storage::StorageError),
    #[error("auth error: {0}")]
    Other(String),
}

pub type AuthResult<T> = Result<T, AuthError>;

pub enum LoginRequest {
    UserPass { username: String, password: String },
    OidcAuthCodeCallback { code: String, state: String },
    OidcBearerJwt { jwt: String },
}

pub struct AuthOutcome {
    pub policies: Vec<String>,
    pub display_name: String,
    pub ttl_seconds: Option<i64>,
}

#[async_trait]
pub trait AuthMethod: Send + Sync {
    async fn login(
        &self,
        storage: &dyn StorageBackend,
        request: LoginRequest,
    ) -> AuthResult<AuthOutcome>;
}
