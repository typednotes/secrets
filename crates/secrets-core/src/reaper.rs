use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use thiserror::Error;

use crate::engine::EngineError;
use crate::lease::{self, Lease};
use crate::router::Router;
use crate::storage::{StorageBackend, StorageError};

#[derive(Debug, Error)]
pub enum ReaperError {
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("engine error: {0}")]
    Engine(#[from] EngineError),
}

/// Revokes one lease by asking its owning engine mount to `revoke()` it,
/// then removing the lease record. Best-effort: engine failures are
/// reported to the caller but the lease record is only deleted on success,
/// so a failed revoke is retried on the next pass rather than silently lost.
pub async fn revoke_lease(
    storage: &dyn StorageBackend,
    router: &Router,
    lease: &Lease,
) -> Result<(), ReaperError> {
    if let Some((mount, _)) = router.resolve(&lease.engine_mount) {
        mount.engine.revoke(storage, lease).await?;
    }
    lease::delete_lease(storage, lease.id).await?;
    Ok(())
}

/// Revokes every lease owned by `token_id_hash` — called when a token is
/// revoked so its dynamic credentials don't outlive it.
pub async fn revoke_leases_for_token(
    storage: &dyn StorageBackend,
    router: &Router,
    token_id_hash: &str,
) -> Result<(), ReaperError> {
    for lease in lease::list_leases(storage).await? {
        if lease.token_id_hash == token_id_hash {
            revoke_lease(storage, router, &lease).await?;
        }
    }
    Ok(())
}

/// Scans all leases once and revokes any that have expired. Returns the
/// number successfully reaped; individual failures are logged and skipped
/// (they'll be retried on the next pass).
pub async fn reap_once(storage: &dyn StorageBackend, router: &Router) -> Result<usize, ReaperError> {
    let now = Utc::now();
    let mut reaped = 0;
    for lease in lease::list_leases(storage).await? {
        if lease.expires_at <= now {
            match revoke_lease(storage, router, &lease).await {
                Ok(()) => reaped += 1,
                Err(e) => tracing::warn!(lease_id = %lease.id, error = %e, "failed to reap lease"),
            }
        }
    }
    Ok(reaped)
}

/// Elects the single replica allowed to reap. Every node competes for this
/// one name, so the value matters only in that it must be identical
/// everywhere.
pub const REAPER_LOCK: &str = "secrets/lease-reaper";

/// Runs one reap pass, but only on the replica that holds the reaper lock.
/// Returns `None` on a standby node, which has nothing to do.
///
/// Without this, every replica would scan the same leases and revoke each one
/// concurrently — mostly harmless, since engines treat an already-revoked
/// credential as success, but it multiplies provider API calls by the replica
/// count and races on engines that cannot.
pub async fn reap_once_if_leader(
    storage: &dyn StorageBackend,
    router: &Router,
) -> Result<Option<usize>, ReaperError> {
    if !storage.try_acquire_lock(REAPER_LOCK).await? {
        return Ok(None);
    }
    reap_once(storage, router).await.map(Some)
}

/// Spawns a background task that reaps on a fixed interval for the lifetime of
/// the process, on whichever replica wins the lock.
///
/// The lock is taken once and held, rather than passed around each tick: a
/// stable leader avoids re-contending every interval, and because the lock
/// lives on a held connection, a crashed leader releases it automatically and
/// the next tick elsewhere picks the work up.
pub fn spawn_reaper(
    storage: Arc<dyn StorageBackend>,
    router: Arc<Router>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        let mut announced_standby = false;
        loop {
            ticker.tick().await;
            match reap_once_if_leader(storage.as_ref(), router.as_ref()).await {
                Ok(Some(count)) if count > 0 => {
                    tracing::info!(count, "reaped expired leases")
                }
                Ok(Some(_)) => {}
                // Logged once, not every tick: on a multi-replica deployment
                // most nodes are standbys for their whole lifetime.
                Ok(None) => {
                    if !announced_standby {
                        announced_standby = true;
                        tracing::info!(
                            lock = REAPER_LOCK,
                            "another replica holds the lease-reaper lock; standing by"
                        );
                    }
                }
                Err(e) => tracing::warn!(error = %e, "lease reaper pass failed"),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{EngineResult, SecretsEngine};
    use crate::router::EngineMount;
    use crate::storage::{StorageEntry, StorageResult};
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use uuid::Uuid;

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

    #[derive(Default)]
    struct FakeEngine {
        revoked: AtomicUsize,
    }

    #[async_trait]
    impl SecretsEngine for FakeEngine {
        fn doc(&self) -> crate::engine::EngineDoc {
            crate::engine::EngineDoc {
                provider: "fake".to_string(),
                mechanism: "test double".to_string(),
                shape: crate::engine::CredentialShape::MintAndRevoke,
                revocable: true,
                revoke_effect: "counts the call".to_string(),
                ttl: crate::engine::TtlDoc::fixed(60, "test"),
                scoping: "none".to_string(),
                root_credential: "none".to_string(),
                paths: vec![],
                docs_url: None,
                caveats: vec![],
            }
        }
        async fn read(&self, _storage: &dyn StorageBackend, _path: &str) -> EngineResult<serde_json::Value> {
            unimplemented!()
        }
        async fn write(
            &self,
            _storage: &dyn StorageBackend,
            _path: &str,
            _data: serde_json::Value,
        ) -> EngineResult<()> {
            unimplemented!()
        }
        async fn delete(&self, _storage: &dyn StorageBackend, _path: &str) -> EngineResult<()> {
            unimplemented!()
        }
        async fn list(&self, _storage: &dyn StorageBackend, _prefix: &str) -> EngineResult<Vec<String>> {
            unimplemented!()
        }
        async fn revoke(&self, _storage: &dyn StorageBackend, _lease: &Lease) -> EngineResult<()> {
            self.revoked.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn lease(token_id_hash: &str, expires_at: chrono::DateTime<Utc>) -> Lease {
        Lease {
            id: Uuid::new_v4(),
            token_id_hash: token_id_hash.to_string(),
            engine_mount: "database/creds/".to_string(),
            internal_data: serde_json::json!({}),
            issued_at: Utc::now(),
            expires_at,
        }
    }

    /// Stands in for a replica that lost the reaper election: it stores
    /// normally but never wins the lock.
    struct Standby<B>(B);

    #[async_trait]
    impl<B: StorageBackend> StorageBackend for Standby<B> {
        async fn get(&self, path: &str) -> StorageResult<Option<StorageEntry>> {
            self.0.get(path).await
        }
        async fn put(&self, path: &str, entry: StorageEntry) -> StorageResult<()> {
            self.0.put(path, entry).await
        }
        async fn delete(&self, path: &str) -> StorageResult<()> {
            self.0.delete(path).await
        }
        async fn list(&self, prefix: &str) -> StorageResult<Vec<String>> {
            self.0.list(prefix).await
        }
        async fn try_acquire_lock(&self, _key: &str) -> StorageResult<bool> {
            Ok(false)
        }
    }

    /// The whole point of the lock: a standby must not touch the provider.
    /// Without this, every replica revokes every expired lease.
    #[tokio::test]
    async fn a_standby_replica_does_not_reap() {
        let storage = Standby(MemStorage::default());
        let engine = Arc::new(FakeEngine::default());
        let router = Router::new(vec![EngineMount {
            prefix: "database/creds/".to_string(),
            engine: engine.clone() as Arc<dyn SecretsEngine>,
        }]);

        let expired = lease("tok", Utc::now() - chrono::Duration::seconds(10));
        lease::store_lease(&storage, &expired).await.unwrap();

        let outcome = reap_once_if_leader(&storage, &router).await.unwrap();
        assert!(outcome.is_none(), "standby reported a reap pass");
        assert_eq!(
            engine.revoked.load(Ordering::SeqCst),
            0,
            "standby called the provider anyway"
        );
        assert_eq!(
            lease::list_leases(&storage).await.unwrap().len(),
            1,
            "standby deleted a lease it does not own"
        );
    }

    /// The default `try_acquire_lock` grants unconditionally, so a single-node
    /// deployment keeps reaping with no lock support in its backend.
    #[tokio::test]
    async fn the_leader_reaps() {
        let storage = MemStorage::default();
        let engine = Arc::new(FakeEngine::default());
        let router = Router::new(vec![EngineMount {
            prefix: "database/creds/".to_string(),
            engine: engine.clone() as Arc<dyn SecretsEngine>,
        }]);

        let expired = lease("tok", Utc::now() - chrono::Duration::seconds(10));
        lease::store_lease(&storage, &expired).await.unwrap();

        assert_eq!(reap_once_if_leader(&storage, &router).await.unwrap(), Some(1));
        assert_eq!(engine.revoked.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn reap_once_revokes_only_expired_leases() {
        let storage = MemStorage::default();
        let engine: Arc<dyn SecretsEngine> = Arc::new(FakeEngine::default());
        let router = Router::new(vec![EngineMount {
            prefix: "database/creds/".to_string(),
            engine: engine.clone(),
        }]);

        let expired = lease("tok", Utc::now() - chrono::Duration::seconds(10));
        let active = lease("tok", Utc::now() + chrono::Duration::seconds(3600));
        lease::store_lease(&storage, &expired).await.unwrap();
        lease::store_lease(&storage, &active).await.unwrap();

        let reaped = reap_once(&storage, &router).await.unwrap();
        assert_eq!(reaped, 1);
        assert_eq!(lease::list_leases(&storage).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn revoke_leases_for_token_cascades() {
        let storage = MemStorage::default();
        let engine: Arc<dyn SecretsEngine> = Arc::new(FakeEngine::default());
        let router = Router::new(vec![EngineMount {
            prefix: "database/creds/".to_string(),
            engine,
        }]);

        let mine = lease("tok-a", Utc::now() + chrono::Duration::seconds(3600));
        let theirs = lease("tok-b", Utc::now() + chrono::Duration::seconds(3600));
        lease::store_lease(&storage, &mine).await.unwrap();
        lease::store_lease(&storage, &theirs).await.unwrap();

        revoke_leases_for_token(&storage, &router, "tok-a").await.unwrap();

        let remaining = lease::list_leases(&storage).await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].token_id_hash, "tok-b");
    }
}
