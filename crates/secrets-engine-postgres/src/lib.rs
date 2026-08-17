use std::collections::HashMap;

use async_trait::async_trait;
use chrono::Utc;
use rand::RngExt;
use secrets_core::engine::{EngineError, EngineResult, SecretsEngine};
use secrets_core::lease::Lease;
use secrets_core::storage::{StorageBackend, StorageEntry};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;
use tokio::sync::RwLock;
use uuid::Uuid;

const CONFIG_PREFIX: &str = "database/config/";
const ROLE_PREFIX: &str = "database/roles/";

/// Operator-supplied connection info for a *target* database this engine
/// manages credentials on — distinct from this server's own storage DB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbConfig {
    pub connection_url: String,
}

/// A named role: which target DB it applies to, the SQL run to create and
/// revoke a credential (with `{{name}}`/`{{password}}` placeholders), and
/// how long a generated credential lives before the reaper revokes it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleConfig {
    pub db_name: String,
    pub creation_statements: Vec<String>,
    pub revocation_statements: Vec<String>,
    #[serde(default = "default_ttl_seconds")]
    pub default_ttl_seconds: i64,
}

fn default_ttl_seconds() -> i64 {
    3600
}

/// Dynamic PostgreSQL credentials engine. Mounted twice in practice: once at
/// `database/` for `config`/`roles` CRUD, once at `database/creds/` for
/// on-demand generation — see `secrets-server`'s wiring.
pub struct PostgresEngine {
    pools: RwLock<HashMap<String, PgPool>>,
}

impl Default for PostgresEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PostgresEngine {
    pub fn new() -> Self {
        Self {
            pools: RwLock::new(HashMap::new()),
        }
    }

    async fn pool_for(&self, storage: &dyn StorageBackend, db_name: &str) -> EngineResult<PgPool> {
        if let Some(pool) = self.pools.read().await.get(db_name) {
            return Ok(pool.clone());
        }
        let config = Self::load_config(storage, db_name)
            .await?
            .ok_or_else(|| EngineError::InvalidRequest(format!("unknown database config '{db_name}'")))?;
        let pool = PgPool::connect(&config.connection_url)
            .await
            .map_err(|e| EngineError::Other(e.to_string()))?;
        self.pools.write().await.insert(db_name.to_string(), pool.clone());
        Ok(pool)
    }

    async fn load_config(storage: &dyn StorageBackend, name: &str) -> EngineResult<Option<DbConfig>> {
        let Some(entry) = storage.get(&format!("{CONFIG_PREFIX}{name}")).await? else {
            return Ok(None);
        };
        Ok(Some(
            serde_json::from_slice(&entry.value).map_err(|e| EngineError::Other(e.to_string()))?,
        ))
    }

    async fn save_config(storage: &dyn StorageBackend, name: &str, config: &DbConfig) -> EngineResult<()> {
        let value = serde_json::to_vec(config).map_err(|e| EngineError::Other(e.to_string()))?;
        storage
            .put(
                &format!("{CONFIG_PREFIX}{name}"),
                StorageEntry {
                    value,
                    expires_at: None,
                },
            )
            .await?;
        Ok(())
    }

    async fn load_role(storage: &dyn StorageBackend, name: &str) -> EngineResult<Option<RoleConfig>> {
        let Some(entry) = storage.get(&format!("{ROLE_PREFIX}{name}")).await? else {
            return Ok(None);
        };
        Ok(Some(
            serde_json::from_slice(&entry.value).map_err(|e| EngineError::Other(e.to_string()))?,
        ))
    }

    async fn save_role(storage: &dyn StorageBackend, name: &str, role: &RoleConfig) -> EngineResult<()> {
        let value = serde_json::to_vec(role).map_err(|e| EngineError::Other(e.to_string()))?;
        storage
            .put(
                &format!("{ROLE_PREFIX}{name}"),
                StorageEntry {
                    value,
                    expires_at: None,
                },
            )
            .await?;
        Ok(())
    }
}

/// Generated usernames are restricted to `[a-z0-9_]`, so substituting one
/// into a `"{{name}}"`-quoted identifier in an operator's SQL template can
/// never break out of the quotes — the actual defense against
/// SQL-injection-via-role-name that free-form user input would require.
fn generate_username(role: &str) -> String {
    let safe_role: String = role
        .chars()
        .map(|c| c.to_ascii_lowercase())
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    let suffix = Uuid::new_v4().simple().to_string();
    format!("v_{safe_role}_{}", &suffix[..12])
}

/// Hex-encoded, so it can never contain a `'` that would break out of a
/// `'{{password}}'`-quoted literal in an operator's SQL template.
fn generate_password() -> String {
    let bytes: [u8; 24] = rand::rng().random();
    hex::encode(bytes)
}

fn render_template(template: &str, username: &str, password: &str) -> String {
    template.replace("{{name}}", username).replace("{{password}}", password)
}

#[async_trait]
impl SecretsEngine for PostgresEngine {
    async fn read(&self, storage: &dyn StorageBackend, path: &str) -> EngineResult<serde_json::Value> {
        if let Some(name) = path.strip_prefix("roles/") {
            let role = Self::load_role(storage, name).await?.ok_or(EngineError::NotFound)?;
            serde_json::to_value(role).map_err(|e| EngineError::Other(e.to_string()))
        } else {
            Err(EngineError::InvalidRequest("expected roles/{name}".into()))
        }
    }

    async fn write(
        &self,
        storage: &dyn StorageBackend,
        path: &str,
        data: serde_json::Value,
    ) -> EngineResult<()> {
        if let Some(name) = path.strip_prefix("config/") {
            let config: DbConfig =
                serde_json::from_value(data).map_err(|e| EngineError::InvalidRequest(e.to_string()))?;
            Self::save_config(storage, name, &config).await
        } else if let Some(name) = path.strip_prefix("roles/") {
            let role: RoleConfig =
                serde_json::from_value(data).map_err(|e| EngineError::InvalidRequest(e.to_string()))?;
            Self::save_role(storage, name, &role).await
        } else {
            Err(EngineError::InvalidRequest("expected config/{name} or roles/{name}".into()))
        }
    }

    async fn delete(&self, storage: &dyn StorageBackend, path: &str) -> EngineResult<()> {
        if let Some(name) = path.strip_prefix("config/") {
            storage.delete(&format!("{CONFIG_PREFIX}{name}")).await?;
            self.pools.write().await.remove(name);
            Ok(())
        } else if let Some(name) = path.strip_prefix("roles/") {
            storage.delete(&format!("{ROLE_PREFIX}{name}")).await?;
            Ok(())
        } else {
            Err(EngineError::InvalidRequest("expected config/{name} or roles/{name}".into()))
        }
    }

    async fn list(&self, storage: &dyn StorageBackend, prefix: &str) -> EngineResult<Vec<String>> {
        if let Some(rest) = prefix.strip_prefix("roles/") {
            let keys = storage.list(&format!("{ROLE_PREFIX}{rest}")).await?;
            Ok(keys
                .into_iter()
                .filter_map(|k| k.strip_prefix(ROLE_PREFIX).map(|s| s.to_string()))
                .collect())
        } else if let Some(rest) = prefix.strip_prefix("config/") {
            let keys = storage.list(&format!("{CONFIG_PREFIX}{rest}")).await?;
            Ok(keys
                .into_iter()
                .filter_map(|k| k.strip_prefix(CONFIG_PREFIX).map(|s| s.to_string()))
                .collect())
        } else {
            Err(EngineError::InvalidRequest("expected config/ or roles/ prefix".into()))
        }
    }

    async fn generate(
        &self,
        storage: &dyn StorageBackend,
        role_name: &str,
    ) -> EngineResult<(serde_json::Value, Lease)> {
        let role = Self::load_role(storage, role_name).await?.ok_or(EngineError::NotFound)?;
        let pool = self.pool_for(storage, &role.db_name).await?;

        let username = generate_username(role_name);
        let password = generate_password();

        for statement in &role.creation_statements {
            let rendered = render_template(statement, &username, &password);
            sqlx::raw_sql(sqlx::AssertSqlSafe(rendered))
                .execute(&pool)
                .await
                .map_err(|e| EngineError::Other(e.to_string()))?;
        }

        let now = Utc::now();
        let lease = Lease {
            id: Uuid::new_v4(),
            // Set by the caller (the HTTP handler knows the requesting
            // token) before the lease is persisted.
            token_id_hash: String::new(),
            engine_mount: "database/creds/".to_string(),
            internal_data: json!({
                "role": role_name,
                "db_name": role.db_name,
                "username": username,
            }),
            issued_at: now,
            expires_at: now + chrono::Duration::seconds(role.default_ttl_seconds),
        };

        Ok((json!({ "username": username, "password": password }), lease))
    }

    async fn revoke(&self, storage: &dyn StorageBackend, lease: &Lease) -> EngineResult<()> {
        let role_name = lease.internal_data["role"]
            .as_str()
            .ok_or_else(|| EngineError::Other("lease missing 'role'".into()))?;
        let db_name = lease.internal_data["db_name"]
            .as_str()
            .ok_or_else(|| EngineError::Other("lease missing 'db_name'".into()))?;
        let username = lease.internal_data["username"]
            .as_str()
            .ok_or_else(|| EngineError::Other("lease missing 'username'".into()))?;

        let role = Self::load_role(storage, role_name).await?.ok_or(EngineError::NotFound)?;
        let pool = self.pool_for(storage, db_name).await?;

        for statement in &role.revocation_statements {
            let rendered = render_template(statement, username, "");
            sqlx::raw_sql(sqlx::AssertSqlSafe(rendered))
                .execute(&pool)
                .await
                .map_err(|e| EngineError::Other(e.to_string()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_username_is_sql_identifier_safe() {
        let username = generate_username("app'; DROP TABLE users; --");
        assert!(username.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
    }

    #[test]
    fn generated_password_has_no_quote_characters() {
        let password = generate_password();
        assert!(!password.contains('\''));
        assert!(!password.contains('"'));
    }

    #[test]
    fn template_substitution() {
        let rendered = render_template(
            "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}';",
            "v_app_abc123",
            "deadbeef",
        );
        assert_eq!(
            rendered,
            "CREATE ROLE \"v_app_abc123\" WITH LOGIN PASSWORD 'deadbeef';"
        );
    }
}
