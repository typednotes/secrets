use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::storage::{StorageBackend, StorageEntry, StorageError};

const LEASE_PREFIX: &str = "sys/leases/";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    pub id: Uuid,
    pub token_id_hash: String,
    /// The `EngineMount::prefix` (see `router.rs`) that owns this lease and
    /// must be asked to `revoke()` it.
    pub engine_mount: String,
    pub internal_data: serde_json::Value,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

pub async fn store_lease(storage: &dyn StorageBackend, lease: &Lease) -> Result<(), StorageError> {
    let path = format!("{LEASE_PREFIX}{}", lease.id);
    let value = serde_json::to_vec(lease).map_err(|e| StorageError::Backend(e.to_string()))?;
    storage
        .put(
            &path,
            StorageEntry {
                value,
                expires_at: Some(lease.expires_at),
            },
        )
        .await
}

pub async fn get_lease(storage: &dyn StorageBackend, id: Uuid) -> Result<Option<Lease>, StorageError> {
    let path = format!("{LEASE_PREFIX}{id}");
    let Some(entry) = storage.get(&path).await? else {
        return Ok(None);
    };
    let lease: Lease =
        serde_json::from_slice(&entry.value).map_err(|e| StorageError::Backend(e.to_string()))?;
    Ok(Some(lease))
}

pub async fn delete_lease(storage: &dyn StorageBackend, id: Uuid) -> Result<(), StorageError> {
    storage.delete(&format!("{LEASE_PREFIX}{id}")).await
}

/// Lists every lease currently persisted. Fine at v1 scale (single node, no
/// distributed lock needed); a busier deployment would want this paginated
/// or index-scanned by `expires_at` instead.
pub async fn list_leases(storage: &dyn StorageBackend) -> Result<Vec<Lease>, StorageError> {
    let keys = storage.list(LEASE_PREFIX).await?;
    let mut leases = Vec::with_capacity(keys.len());
    for key in keys {
        if let Some(entry) = storage.get(&key).await?
            && let Ok(lease) = serde_json::from_slice::<Lease>(&entry.value)
        {
            leases.push(lease);
        }
    }
    Ok(leases)
}
