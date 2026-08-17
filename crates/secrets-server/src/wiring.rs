use std::sync::Arc;

use secrets_auth_oidc::OidcAuthMethod;
use secrets_auth_userpass::UserPassAuth;
use secrets_core::barrier::Barrier;
use secrets_core::crypto::{Aead, Aes256GcmAead, MasterKeyProvider, StaticMasterKeyProvider};
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
    pub router: Arc<Router>,
    pub userpass: UserPassAuth,
    pub oidc: OidcAuthMethod,
}

pub async fn build(config: &Config) -> anyhow::Result<AppState> {
    let master_key = StaticMasterKeyProvider::from_env(&config.master_key_env)
        .map_err(|_| anyhow::anyhow!("failed to load master key from {}", config.master_key_env))?;
    let aead: Arc<dyn Aead> = Arc::new(Aes256GcmAead::new(&master_key.current_key()));

    let raw_storage = PgStorage::connect(&config.storage_database_url).await?;
    let storage: Arc<dyn StorageBackend> = Arc::new(Barrier::new(raw_storage, aead));

    if let (Some(username), Some(password)) = (&config.bootstrap_username, &config.bootstrap_password) {
        bootstrap_admin(storage.as_ref(), username, password).await?;
    }

    let kv: Arc<dyn SecretsEngine> = Arc::new(KvEngine::new());
    let postgres: Arc<dyn SecretsEngine> = Arc::new(PostgresEngine::new());
    let router = Arc::new(Router::new(vec![
        EngineMount {
            prefix: "secret/data/".to_string(),
            engine: kv.clone(),
        },
        EngineMount {
            prefix: "secret/metadata/".to_string(),
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
    ]));

    secrets_core::reaper::spawn_reaper(
        storage.clone(),
        router.clone(),
        std::time::Duration::from_secs(config.lease_reap_interval_seconds),
    );

    Ok(AppState {
        storage,
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
