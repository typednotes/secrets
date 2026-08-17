use async_trait::async_trait;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use secrets_core::auth::{AuthError, AuthMethod, AuthOutcome, AuthResult, LoginRequest};
use secrets_core::storage::{StorageBackend, StorageEntry};
use serde::{Deserialize, Serialize};

const USER_PREFIX: &str = "auth/userpass/users/";
const DEFAULT_TTL_SECONDS: i64 = 3600;

#[derive(Debug, Serialize, Deserialize)]
struct UserRecord {
    password_hash: String,
    policies: Vec<String>,
}

pub struct UserPassAuth;

impl Default for UserPassAuth {
    fn default() -> Self {
        Self::new()
    }
}

impl UserPassAuth {
    pub fn new() -> Self {
        Self
    }

    pub fn hash_password(password: &str) -> AuthResult<String> {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| AuthError::Other(e.to_string()))
    }

    pub async fn user_exists(storage: &dyn StorageBackend, username: &str) -> AuthResult<bool> {
        Ok(storage.get(&format!("{USER_PREFIX}{username}")).await?.is_some())
    }

    pub async fn create_user(
        storage: &dyn StorageBackend,
        username: &str,
        password: &str,
        policies: Vec<String>,
    ) -> AuthResult<()> {
        let record = UserRecord {
            password_hash: Self::hash_password(password)?,
            policies,
        };
        let value = serde_json::to_vec(&record).map_err(|e| AuthError::Other(e.to_string()))?;
        storage
            .put(
                &format!("{USER_PREFIX}{username}"),
                StorageEntry {
                    value,
                    expires_at: None,
                },
            )
            .await?;
        Ok(())
    }
}

#[async_trait]
impl AuthMethod for UserPassAuth {
    async fn login(
        &self,
        storage: &dyn StorageBackend,
        request: LoginRequest,
    ) -> AuthResult<AuthOutcome> {
        let LoginRequest::UserPass { username, password } = request else {
            return Err(AuthError::InvalidRequest(
                "expected username/password".into(),
            ));
        };

        let entry = storage
            .get(&format!("{USER_PREFIX}{username}"))
            .await?
            .ok_or(AuthError::InvalidCredentials)?;
        let record: UserRecord = serde_json::from_slice(&entry.value)
            .map_err(|e| AuthError::Other(e.to_string()))?;

        let hash = PasswordHash::new(&record.password_hash)
            .map_err(|e| AuthError::Other(e.to_string()))?;
        Argon2::default()
            .verify_password(password.as_bytes(), &hash)
            .map_err(|_| AuthError::InvalidCredentials)?;

        Ok(AuthOutcome {
            policies: record.policies,
            display_name: username,
            ttl_seconds: Some(DEFAULT_TTL_SECONDS),
        })
    }
}
