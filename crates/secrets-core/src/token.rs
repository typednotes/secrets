use chrono::{DateTime, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::storage::{StorageBackend, StorageEntry, StorageError};

const TOKEN_PREFIX: &str = "sys/token/";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenEntry {
    pub id_hash: String,
    pub policies: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Generates a fresh opaque bearer token. Returns the raw token (given to the
/// caller once) and the entry to persist, keyed by `sha256(token)`.
pub fn generate_token(policies: Vec<String>, ttl_seconds: Option<i64>) -> (String, TokenEntry) {
    let mut raw = [0u8; 24];
    rand::rng().fill_bytes(&mut raw);
    let token = format!("s.{}", hex::encode(raw));
    let now = Utc::now();
    let entry = TokenEntry {
        id_hash: hash_token(&token),
        policies,
        created_at: now,
        expires_at: ttl_seconds.map(|s| now + chrono::Duration::seconds(s)),
    };
    (token, entry)
}

pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

pub async fn store_token(
    storage: &dyn StorageBackend,
    token: &str,
    entry: &TokenEntry,
) -> Result<(), StorageError> {
    let path = format!("{TOKEN_PREFIX}{}", hash_token(token));
    let value = serde_json::to_vec(entry).map_err(|e| StorageError::Backend(e.to_string()))?;
    storage
        .put(
            &path,
            StorageEntry {
                value,
                expires_at: entry.expires_at,
            },
        )
        .await
}

/// Looks up a token, treating an expired entry as absent.
pub async fn lookup_token(
    storage: &dyn StorageBackend,
    token: &str,
) -> Result<Option<TokenEntry>, StorageError> {
    let path = format!("{TOKEN_PREFIX}{}", hash_token(token));
    let Some(entry) = storage.get(&path).await? else {
        return Ok(None);
    };
    if let Some(expires_at) = entry.expires_at
        && expires_at < Utc::now()
    {
        return Ok(None);
    }
    let token_entry: TokenEntry =
        serde_json::from_slice(&entry.value).map_err(|e| StorageError::Backend(e.to_string()))?;
    Ok(Some(token_entry))
}

pub async fn revoke_token(storage: &dyn StorageBackend, token: &str) -> Result<(), StorageError> {
    let path = format!("{TOKEN_PREFIX}{}", hash_token(token));
    storage.delete(&path).await
}

pub async fn renew_token(
    storage: &dyn StorageBackend,
    token: &str,
    ttl_seconds: i64,
) -> Result<Option<TokenEntry>, StorageError> {
    let Some(mut entry) = lookup_token(storage, token).await? else {
        return Ok(None);
    };
    entry.expires_at = Some(Utc::now() + chrono::Duration::seconds(ttl_seconds));
    store_token(storage, token, &entry).await?;
    Ok(Some(entry))
}
