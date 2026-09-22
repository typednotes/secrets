//! Shared plumbing for the `{mount}/config/{name}` + `{mount}/roles/{role}`
//! convention that every dynamic engine follows.
//!
//! Without this, each engine reimplements the same prefix-stripping and
//! JSON round-tripping. The one rule worth centralising is that **config is
//! never readable**: it holds the provider root credential, so a read returns
//! an existence probe instead of the stored document.

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::json;

use crate::engine::{EngineError, EngineResult};
use crate::storage::{StorageBackend, StorageEntry};

/// The storage prefixes an engine keeps its operator documents under.
pub struct ConfigRoleStore {
    pub config_prefix: &'static str,
    pub role_prefix: &'static str,
}

impl ConfigRoleStore {
    pub const fn new(config_prefix: &'static str, role_prefix: &'static str) -> Self {
        Self {
            config_prefix,
            role_prefix,
        }
    }

    pub async fn load_config<C: DeserializeOwned>(
        &self,
        storage: &dyn StorageBackend,
        name: &str,
    ) -> EngineResult<Option<C>> {
        load(storage, self.config_prefix, name).await
    }

    pub async fn load_role<R: DeserializeOwned>(
        &self,
        storage: &dyn StorageBackend,
        name: &str,
    ) -> EngineResult<Option<R>> {
        load(storage, self.role_prefix, name).await
    }

    /// Loads a role, or fails with the error an engine's `generate()` should
    /// surface when the role was never defined.
    pub async fn require_role<R: DeserializeOwned>(
        &self,
        storage: &dyn StorageBackend,
        name: &str,
    ) -> EngineResult<R> {
        self.load_role(storage, name).await?.ok_or(EngineError::NotFound)
    }

    pub async fn require_config<C: DeserializeOwned>(
        &self,
        storage: &dyn StorageBackend,
        name: &str,
    ) -> EngineResult<C> {
        self.load_config(storage, name).await?.ok_or_else(|| {
            EngineError::InvalidRequest(format!("unknown config '{name}' — POST it first"))
        })
    }

    /// `read` dispatch. Roles are returned in full; a config read deliberately
    /// returns only whether it exists, because the document holds the root
    /// credential and nothing above this layer should be able to read it back.
    pub async fn handle_read<R: DeserializeOwned + Serialize>(
        &self,
        storage: &dyn StorageBackend,
        path: &str,
    ) -> EngineResult<serde_json::Value> {
        if let Some(name) = path.strip_prefix("roles/") {
            let role: R = self.require_role(storage, name).await?;
            serde_json::to_value(role).map_err(|e| EngineError::Other(e.to_string()))
        } else if let Some(name) = path.strip_prefix("config/") {
            let exists = storage.get(&format!("{}{name}", self.config_prefix)).await?.is_some();
            if exists {
                Ok(json!({
                    "configured": true,
                    "note": "config is write-only — it holds this engine's root \
                             credential and is never returned. POST to replace it.",
                }))
            } else {
                Err(EngineError::NotFound)
            }
        } else {
            Err(EngineError::InvalidRequest(
                "expected config/{name} or roles/{name}".into(),
            ))
        }
    }

    pub async fn handle_write<C, R>(
        &self,
        storage: &dyn StorageBackend,
        path: &str,
        data: serde_json::Value,
    ) -> EngineResult<()>
    where
        C: DeserializeOwned + Serialize,
        R: DeserializeOwned + Serialize,
    {
        if let Some(name) = path.strip_prefix("config/") {
            let config: C =
                serde_json::from_value(data).map_err(|e| EngineError::InvalidRequest(e.to_string()))?;
            save(storage, self.config_prefix, name, &config).await
        } else if let Some(name) = path.strip_prefix("roles/") {
            let role: R =
                serde_json::from_value(data).map_err(|e| EngineError::InvalidRequest(e.to_string()))?;
            save(storage, self.role_prefix, name, &role).await
        } else {
            Err(EngineError::InvalidRequest(
                "expected config/{name} or roles/{name}".into(),
            ))
        }
    }

    pub async fn handle_delete(
        &self,
        storage: &dyn StorageBackend,
        path: &str,
    ) -> EngineResult<()> {
        if let Some(name) = path.strip_prefix("config/") {
            storage.delete(&format!("{}{name}", self.config_prefix)).await?;
            Ok(())
        } else if let Some(name) = path.strip_prefix("roles/") {
            storage.delete(&format!("{}{name}", self.role_prefix)).await?;
            Ok(())
        } else {
            Err(EngineError::InvalidRequest(
                "expected config/{name} or roles/{name}".into(),
            ))
        }
    }

    pub async fn handle_list(
        &self,
        storage: &dyn StorageBackend,
        prefix: &str,
    ) -> EngineResult<Vec<String>> {
        let (storage_prefix, rest) = if let Some(rest) = prefix.strip_prefix("roles/") {
            (self.role_prefix, rest)
        } else if let Some(rest) = prefix.strip_prefix("config/") {
            (self.config_prefix, rest)
        } else {
            return Err(EngineError::InvalidRequest(
                "expected config/ or roles/ prefix".into(),
            ));
        };
        let keys = storage.list(&format!("{storage_prefix}{rest}")).await?;
        Ok(keys
            .into_iter()
            .filter_map(|k| k.strip_prefix(storage_prefix).map(|s| s.to_string()))
            .collect())
    }
}

async fn load<T: DeserializeOwned>(
    storage: &dyn StorageBackend,
    prefix: &str,
    name: &str,
) -> EngineResult<Option<T>> {
    let Some(entry) = storage.get(&format!("{prefix}{name}")).await? else {
        return Ok(None);
    };
    Ok(Some(
        serde_json::from_slice(&entry.value).map_err(|e| EngineError::Other(e.to_string()))?,
    ))
}

async fn save<T: Serialize>(
    storage: &dyn StorageBackend,
    prefix: &str,
    name: &str,
    value: &T,
) -> EngineResult<()> {
    let bytes = serde_json::to_vec(value).map_err(|e| EngineError::Other(e.to_string()))?;
    storage
        .put(
            &format!("{prefix}{name}"),
            StorageEntry {
                value: bytes,
                expires_at: None,
            },
        )
        .await?;
    Ok(())
}
