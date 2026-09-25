use std::sync::Arc;

use secrets_auth_oidc::OidcAuthMethod;
use secrets_auth_userpass::UserPassAuth;
use secrets_core::barrier::{Barrier, KeyRotation};
use secrets_core::crypto::{Aead, KeyRing, MasterKeyProvider, StaticMasterKeyProvider};
use secrets_core::engine::SecretsEngine;
use secrets_core::policy::{self, Capability, PathRule, Policy};
use secrets_core::router::{EngineMount, Router};
use secrets_core::storage::StorageBackend;
use secrets_engine_kv::KvEngine;
use secrets_engine_postgres::PostgresEngine;
use secrets_storage_postgres::PgStorage;

use crate::config::{Config, ServiceIdentity};

pub const ROOT_POLICY_NAME: &str = "root";

/// Application state shared across HTTP handlers. This is the single place
/// storage backends, secrets engines, and auth methods get constructed and
/// registered — adding a new engine/auth method means implementing its
/// trait elsewhere and wiring it in here.
pub struct AppState {
    pub storage: Arc<dyn StorageBackend>,
    /// The same barrier as `storage`, kept behind its rotation trait so
    /// `sys/rewrap` can reach the keys — which nothing above the barrier
    /// otherwise knows about.
    pub rotation: Arc<dyn KeyRotation>,
    pub router: Arc<Router>,
    pub userpass: UserPassAuth,
    pub oidc: OidcAuthMethod,
}

/// Every engine this server mounts, and where. This is the composition root's
/// composition root: adding a provider means adding it here and nowhere else.
///
/// Separated from `build` so tests can assert against the real mount table
/// rather than a copy of it that drifts.
pub fn engine_mounts() -> Vec<EngineMount> {
        let kv: Arc<dyn SecretsEngine> = Arc::new(KvEngine::new());
        let postgres: Arc<dyn SecretsEngine> = Arc::new(PostgresEngine::new());
        // Each third-party engine is mounted twice: once at `{name}/creds/` so a
        // generate request resolves to just the role name, and once at `{name}/`
        // for the operator's config/roles surface and the help endpoint.
        let github: Arc<dyn SecretsEngine> = Arc::new(secrets_engine_github::GithubEngine::new());
        let gitlab: Arc<dyn SecretsEngine> = Arc::new(secrets_engine_gitlab::GitlabEngine::new());
        let aws: Arc<dyn SecretsEngine> = Arc::new(secrets_engine_aws::AwsEngine::new());
        let gcp: Arc<dyn SecretsEngine> = Arc::new(secrets_engine_gcp::GcpEngine::new());
        let gworkspace: Arc<dyn SecretsEngine> = Arc::new(secrets_engine_gworkspace::GworkspaceEngine::new());
        let dropbox: Arc<dyn SecretsEngine> = Arc::new(secrets_engine_dropbox::DropboxEngine::new());
        let m365: Arc<dyn SecretsEngine> = Arc::new(secrets_engine_m365::M365Engine::new());
        let federation: Arc<dyn SecretsEngine> = Arc::new(secrets_engine_federation::FederationEngine::new());
        vec![
            EngineMount {
                prefix: "secret/data/".to_string(),
                engine: kv.clone(),
            },
            EngineMount {
                prefix: "secret/metadata/".to_string(),
                engine: kv.clone(),
            },
            // Catch-all for the KV mount so `GET /v1/secret/help` resolves. Longest
            // -prefix match means data/ and metadata/ still win for real requests.
            EngineMount {
                prefix: "secret/".to_string(),
                engine: kv,
            },
            EngineMount {
                prefix: "database/creds/".to_string(),
                engine: postgres.clone(),
            },
            EngineMount {
                prefix: "database/".to_string(),
                engine: postgres,
            },
            EngineMount {
                prefix: "github/creds/".to_string(),
                engine: github.clone(),
            },
            EngineMount {
                prefix: "github/".to_string(),
                engine: github,
            },
            EngineMount {
                prefix: "gitlab/creds/".to_string(),
                engine: gitlab.clone(),
            },
            EngineMount {
                prefix: "gitlab/".to_string(),
                engine: gitlab,
            },
            EngineMount {
                prefix: "aws/creds/".to_string(),
                engine: aws.clone(),
            },
            EngineMount {
                prefix: "aws/".to_string(),
                engine: aws,
            },
            EngineMount {
                prefix: "gcp/creds/".to_string(),
                engine: gcp.clone(),
            },
            EngineMount {
                prefix: "gcp/".to_string(),
                engine: gcp,
            },
            EngineMount {
                prefix: "gworkspace/creds/".to_string(),
                engine: gworkspace.clone(),
            },
            EngineMount {
                prefix: "gworkspace/".to_string(),
                engine: gworkspace,
            },
            EngineMount {
                prefix: "dropbox/creds/".to_string(),
                engine: dropbox.clone(),
            },
            EngineMount {
                prefix: "dropbox/".to_string(),
                engine: dropbox,
            },
            EngineMount {
                prefix: "m365/creds/".to_string(),
                engine: m365.clone(),
            },
            EngineMount {
                prefix: "m365/".to_string(),
                engine: m365,
            },
            EngineMount {
                prefix: "federation/creds/".to_string(),
                engine: federation.clone(),
            },
            EngineMount {
                prefix: "federation/".to_string(),
                engine: federation,
            },
        ]
}

pub async fn build(config: &Config) -> anyhow::Result<AppState> {
    let master_key = StaticMasterKeyProvider::from_env(&config.master_key_env)
        .map_err(|_| anyhow::anyhow!("failed to load master key from {}", config.master_key_env))?
        .with_retired_from_env(&config.master_key_retired_env)
        .map_err(|_| {
            anyhow::anyhow!(
                "failed to parse retired master keys from {}",
                config.master_key_retired_env
            )
        })?;
    let retired = master_key.retired_keys();
    let aead: Arc<dyn Aead> = Arc::new(KeyRing::new(&master_key.current_key(), &retired));

    if !config.storage_migrate {
        tracing::info!("storage migrations disabled; expecting the schema to be applied externally");
    }
    let raw_storage =
        PgStorage::connect_with(&config.storage_database_url, config.storage_migrate).await?;
    let barrier = Arc::new(Barrier::new(raw_storage, aead));
    let storage: Arc<dyn StorageBackend> = barrier.clone();
    let rotation: Arc<dyn KeyRotation> = barrier;
    if !retired.is_empty() {
        tracing::warn!(
            retired = retired.len(),
            active_key = %rotation.active_key_id(),
            "running with retired master keys — POST /v1/sys/rewrap, then remove them"
        );
    }

    if let (Some(username), Some(password)) = (&config.bootstrap_username, &config.bootstrap_password) {
        bootstrap_admin(storage.as_ref(), username, password).await?;
    }
    apply_service_identities(storage.as_ref(), &config.service_identities).await?;

    let router = Arc::new(Router::new(engine_mounts()));

    secrets_core::reaper::spawn_reaper(
        storage.clone(),
        router.clone(),
        std::time::Duration::from_secs(config.lease_reap_interval_seconds),
    );

    Ok(AppState {
        storage,
        rotation,
        router,
        userpass: UserPassAuth::new(),
        oidc: OidcAuthMethod::new(),
    })
}

async fn bootstrap_admin(
    storage: &dyn StorageBackend,
    username: &str,
    password: &str,
) -> anyhow::Result<()> {
    if UserPassAuth::user_exists(storage, username).await? {
        return Ok(());
    }

    let root_policy = Policy {
        name: ROOT_POLICY_NAME.to_string(),
        rules: vec![PathRule {
            prefix: String::new(),
            capabilities: vec![
                Capability::Read,
                Capability::Create,
                Capability::Update,
                Capability::Delete,
                Capability::List,
                Capability::Sudo,
            ],
        }],
    };
    policy::store_policy(storage, &root_policy).await?;
    UserPassAuth::create_user(storage, username, password, vec![ROOT_POLICY_NAME.to_string()]).await?;
    tracing::info!(username, "bootstrapped initial admin user");
    Ok(())
}

/// Makes each declared service identity exist exactly as configured: its
/// policy (named after it) is rewritten, and its user is written only if
/// the password or policy list differ. Runs on every start, so the services
/// that depend on this server need no out-of-band setup, and rotating a
/// password is a restart with the new value.
async fn apply_service_identities(
    storage: &dyn StorageBackend,
    identities: &[ServiceIdentity],
) -> anyhow::Result<()> {
    for identity in identities {
        let name = &identity.username;
        let policy = Policy {
            name: name.clone(),
            rules: identity.rules.clone(),
        };
        policy::store_policy(storage, &policy).await?;
        let written =
            UserPassAuth::ensure_user(storage, name, &identity.password()?, vec![name.clone()])
                .await
                .map_err(|e| anyhow::anyhow!("service identity '{name}': {e}"))?;
        tracing::info!(
            username = %name,
            "service identity {}",
            if written { "written" } else { "unchanged" }
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use secrets_core::auth::{AuthMethod, LoginRequest};
    use secrets_core::storage::{StorageEntry, StorageResult};
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
            let map = self.0.lock().unwrap();
            Ok(map.keys().filter(|k| k.starts_with(prefix)).cloned().collect())
        }
    }

    fn identity(username: &str, password_env: &str, caps: Vec<Capability>) -> ServiceIdentity {
        ServiceIdentity {
            username: username.into(),
            password_env: password_env.into(),
            rules: vec![PathRule {
                prefix: "secret/data/thirdparty/".into(),
                capabilities: caps,
            }],
        }
    }

    async fn login(storage: &MemStorage, username: &str, password: &str) -> Option<Vec<String>> {
        UserPassAuth::new()
            .login(
                storage,
                LoginRequest::UserPass {
                    username: username.into(),
                    password: password.into(),
                },
            )
            .await
            .ok()
            .map(|o| o.policies)
    }

    /// The identity can log in, holds only its own policy, and that policy
    /// grants exactly the declared rules; a second start changes nothing and
    /// a rotated password replaces the old one.
    #[tokio::test]
    async fn service_identities_are_applied_on_every_start() {
        const ENV: &str = "SECRETS_TEST_WIRING_APP_PW";
        let storage = MemStorage::default();
        let identities = [identity("typednotes-app", ENV, vec![Capability::Create, Capability::Delete])];

        // SAFETY: this test is the only reader and writer of this variable.
        unsafe { std::env::set_var(ENV, "first password, long enough") };
        apply_service_identities(&storage, &identities).await.unwrap();
        assert_eq!(
            login(&storage, "typednotes-app", "first password, long enough").await,
            Some(vec!["typednotes-app".to_string()])
        );
        let policy = policy::get_policy(&storage, "typednotes-app").await.unwrap().unwrap();
        assert!(policy.is_allowed("secret/data/thirdparty/gdrive/u/c", Capability::Create));
        assert!(!policy.is_allowed("secret/data/thirdparty/gdrive/u/c", Capability::Read));

        let user_key = "auth/userpass/users/typednotes-app";
        let before = storage.0.lock().unwrap()[user_key].value.clone();
        apply_service_identities(&storage, &identities).await.unwrap();
        assert_eq!(storage.0.lock().unwrap()[user_key].value, before);

        unsafe { std::env::set_var(ENV, "rotated password, long enough") };
        apply_service_identities(&storage, &identities).await.unwrap();
        assert_eq!(login(&storage, "typednotes-app", "first password, long enough").await, None);
        assert!(login(&storage, "typednotes-app", "rotated password, long enough").await.is_some());
        unsafe { std::env::remove_var(ENV) };
    }

    /// Declared identities coexist with the admin, whose root policy they
    /// cannot touch.
    #[tokio::test]
    async fn service_identities_leave_the_admin_alone() {
        const ENV: &str = "SECRETS_TEST_WIRING_LIAISON_PW";
        let storage = MemStorage::default();
        bootstrap_admin(&storage, "admin", "change-me").await.unwrap();
        // SAFETY: this test is the only reader and writer of this variable.
        unsafe { std::env::set_var(ENV, "liaison password, long enough") };
        apply_service_identities(&storage, &[identity("liaison", ENV, vec![Capability::Read])])
            .await
            .unwrap();
        unsafe { std::env::remove_var(ENV) };

        assert_eq!(login(&storage, "admin", "change-me").await, Some(vec![ROOT_POLICY_NAME.to_string()]));
        let root = policy::get_policy(&storage, ROOT_POLICY_NAME).await.unwrap().unwrap();
        assert!(root.is_allowed("anything", Capability::Sudo));
    }
}
