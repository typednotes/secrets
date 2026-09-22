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

use crate::config::Config;

const ROOT_POLICY_NAME: &str = "root";

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

    let raw_storage = PgStorage::connect(&config.storage_database_url).await?;
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
