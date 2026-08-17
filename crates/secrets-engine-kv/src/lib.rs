use std::collections::BTreeMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use secrets_core::engine::{EngineError, EngineResult, SecretsEngine};
use secrets_core::storage::{StorageBackend, StorageEntry};
use serde::{Deserialize, Serialize};
use serde_json::json;

const METADATA_PREFIX: &str = "kv-metadata/";
const DATA_PREFIX: &str = "kv-data/";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VersionMetadata {
    created_at: DateTime<Utc>,
    deleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SecretMetadata {
    current_version: u32,
    versions: BTreeMap<u32, VersionMetadata>,
}

/// Versioned static KV engine (kv-v2-style): every write creates a new
/// version, `delete` soft-deletes the current version without erasing
/// history, `read` always returns the latest non-deleted version.
#[derive(Default)]
pub struct KvEngine;

impl KvEngine {
    pub fn new() -> Self {
        Self
    }

    async fn load_metadata(
        storage: &dyn StorageBackend,
        path: &str,
    ) -> EngineResult<Option<SecretMetadata>> {
        let key = format!("{METADATA_PREFIX}{path}");
        let Some(entry) = storage.get(&key).await? else {
            return Ok(None);
        };
        let metadata: SecretMetadata =
            serde_json::from_slice(&entry.value).map_err(|e| EngineError::Other(e.to_string()))?;
        Ok(Some(metadata))
    }

    async fn save_metadata(
        storage: &dyn StorageBackend,
        path: &str,
        metadata: &SecretMetadata,
    ) -> EngineResult<()> {
        let key = format!("{METADATA_PREFIX}{path}");
        let value = serde_json::to_vec(metadata).map_err(|e| EngineError::Other(e.to_string()))?;
        storage
            .put(
                &key,
                StorageEntry {
                    value,
                    expires_at: None,
                },
            )
            .await?;
        Ok(())
    }

    fn data_key(path: &str, version: u32) -> String {
        format!("{DATA_PREFIX}{path}/v{version}")
    }
}

#[async_trait]
impl SecretsEngine for KvEngine {
    async fn read(&self, storage: &dyn StorageBackend, path: &str) -> EngineResult<serde_json::Value> {
        let metadata = Self::load_metadata(storage, path)
            .await?
            .ok_or(EngineError::NotFound)?;
        let version_meta = metadata
            .versions
            .get(&metadata.current_version)
            .ok_or(EngineError::NotFound)?;
        if version_meta.deleted {
            return Err(EngineError::NotFound);
        }
        let key = Self::data_key(path, metadata.current_version);
        let entry = storage.get(&key).await?.ok_or(EngineError::NotFound)?;
        let value: serde_json::Value =
            serde_json::from_slice(&entry.value).map_err(|e| EngineError::Other(e.to_string()))?;
        Ok(json!({
            "data": value,
            "metadata": {
                "version": metadata.current_version,
                "created_at": version_meta.created_at,
            },
        }))
    }

    async fn write(
        &self,
        storage: &dyn StorageBackend,
        path: &str,
        data: serde_json::Value,
    ) -> EngineResult<()> {
        let mut metadata = Self::load_metadata(storage, path).await?.unwrap_or_default();
        let new_version = metadata.current_version + 1;
        let key = Self::data_key(path, new_version);
        let value = serde_json::to_vec(&data).map_err(|e| EngineError::Other(e.to_string()))?;
        storage
            .put(
                &key,
                StorageEntry {
                    value,
                    expires_at: None,
                },
            )
            .await?;
        metadata.current_version = new_version;
        metadata.versions.insert(
            new_version,
            VersionMetadata {
                created_at: Utc::now(),
                deleted: false,
            },
        );
        Self::save_metadata(storage, path, &metadata).await
    }

    async fn delete(&self, storage: &dyn StorageBackend, path: &str) -> EngineResult<()> {
        let mut metadata = Self::load_metadata(storage, path)
            .await?
            .ok_or(EngineError::NotFound)?;
        if let Some(version_meta) = metadata.versions.get_mut(&metadata.current_version) {
            version_meta.deleted = true;
        }
        Self::save_metadata(storage, path, &metadata).await
    }

    async fn list(&self, storage: &dyn StorageBackend, prefix: &str) -> EngineResult<Vec<String>> {
        let full_prefix = format!("{METADATA_PREFIX}{prefix}");
        let keys = storage.list(&full_prefix).await?;
        Ok(keys
            .into_iter()
            .filter_map(|k| k.strip_prefix(METADATA_PREFIX).map(|s| s.to_string()))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrets_core::storage::StorageResult;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MemStorage(Mutex<HashMap<String, StorageEntry>>);

    #[async_trait]
    impl StorageBackend for MemStorage {
        async fn get(&self, path: &str) -> StorageResult<Option<StorageEntry>> {
            Ok(self.0.lock().unwrap().get(path).cloned())
        }
        async fn put(&self, path: &str, entry: StorageEntry) -> StorageResult<()> {
            self.0.lock().unwrap().insert(path.to_string(), entry);
            Ok(())
        }
        async fn delete(&self, path: &str) -> StorageResult<()> {
            self.0.lock().unwrap().remove(path);
            Ok(())
        }
        async fn list(&self, prefix: &str) -> StorageResult<Vec<String>> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }
    }

    #[tokio::test]
    async fn write_then_read_round_trip() {
        let storage = MemStorage::default();
        let engine = KvEngine::new();
        engine
            .write(&storage, "app/db", json!({"password": "hunter2"}))
            .await
            .unwrap();
        let result = engine.read(&storage, "app/db").await.unwrap();
        assert_eq!(result["data"]["password"], "hunter2");
        assert_eq!(result["metadata"]["version"], 1);
    }

    #[tokio::test]
    async fn write_bumps_version() {
        let storage = MemStorage::default();
        let engine = KvEngine::new();
        engine.write(&storage, "app/db", json!({"v": 1})).await.unwrap();
        engine.write(&storage, "app/db", json!({"v": 2})).await.unwrap();
        let result = engine.read(&storage, "app/db").await.unwrap();
        assert_eq!(result["data"]["v"], 2);
        assert_eq!(result["metadata"]["version"], 2);
    }

    #[tokio::test]
    async fn soft_delete_hides_current_version() {
        let storage = MemStorage::default();
        let engine = KvEngine::new();
        engine.write(&storage, "app/db", json!({"v": 1})).await.unwrap();
        engine.delete(&storage, "app/db").await.unwrap();
        assert!(matches!(
            engine.read(&storage, "app/db").await,
            Err(EngineError::NotFound)
        ));
    }

    #[tokio::test]
    async fn read_missing_returns_not_found() {
        let storage = MemStorage::default();
        let engine = KvEngine::new();
        assert!(matches!(
            engine.read(&storage, "nope").await,
            Err(EngineError::NotFound)
        ));
    }

    #[tokio::test]
    async fn list_returns_paths_under_prefix() {
        let storage = MemStorage::default();
        let engine = KvEngine::new();
        engine.write(&storage, "app/db", json!({})).await.unwrap();
        engine.write(&storage, "app/api", json!({})).await.unwrap();
        engine.write(&storage, "other/x", json!({})).await.unwrap();
        let mut listed = engine.list(&storage, "app/").await.unwrap();
        listed.sort();
        assert_eq!(listed, vec!["app/api".to_string(), "app/db".to_string()]);
    }
}
