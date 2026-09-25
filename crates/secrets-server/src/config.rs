use figment::providers::{Env, Format, Toml};
use figment::Figment;
use secrets_core::policy::PathRule;
use serde::Deserialize;

use crate::wiring::ROOT_POLICY_NAME;

#[derive(Debug, Deserialize)]
pub struct Config {
    /// Address the HTTP server binds to.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    /// Connection string for this server's own encrypted storage database.
    pub storage_database_url: String,
    /// Whether to apply the storage schema's migrations at startup
    /// (`SECRETS_SERVER_STORAGE_MIGRATE`). Defaults to `true`. Set it to
    /// `false` when the schema is applied by something else — e.g. declared
    /// in `typednotes-infra` — so the server only checks that `kv_store`
    /// exists and its database identity needs no DDL rights.
    #[serde(default = "default_storage_migrate")]
    pub storage_migrate: bool,
    /// Env var name holding the hex-encoded 32-byte master key (or a path to
    /// a file containing it).
    #[serde(default = "default_master_key_env")]
    pub master_key_env: String,
    /// Env var name holding comma-separated hex keys kept for *decryption
    /// only*, so values written under a previous master key still open while
    /// a rotation is in progress. Unset is normal.
    #[serde(default = "default_master_key_retired_env")]
    pub master_key_retired_env: String,
    /// If set (together with `bootstrap_password`) and the user does not
    /// already exist, creates an initial admin user with a full-access
    /// "root" policy on first startup.
    pub bootstrap_username: Option<String>,
    pub bootstrap_password: Option<String>,
    /// Userpass identities for the services that use this server, applied on
    /// **every** start (`SECRETS_SERVER_SERVICE_IDENTITIES`). Each gets a
    /// policy named after it holding exactly `rules`, and a user holding only
    /// that policy, whose password is read from the env var `password_env`.
    /// Unlike the bootstrap admin, a changed password or rule list takes
    /// effect on the next restart. An identity removed from this list is
    /// left in place: delete it over HTTP.
    #[serde(default)]
    pub service_identities: Vec<ServiceIdentity>,
    /// How often the background reaper scans for expired leases.
    #[serde(default = "default_lease_reap_interval_seconds")]
    pub lease_reap_interval_seconds: u64,
}

/// One service's userpass identity, declared in config. The password itself
/// never appears here — the list is plain configuration — only the name of
/// the env var that holds it, as for the master key.
#[derive(Debug, Clone, Deserialize)]
pub struct ServiceIdentity {
    pub username: String,
    pub password_env: String,
    pub rules: Vec<PathRule>,
}

impl ServiceIdentity {
    /// The password from `password_env`, required and non-empty.
    pub fn password(&self) -> anyhow::Result<String> {
        std::env::var(&self.password_env)
            .ok()
            .filter(|p| !p.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "service identity '{}': {} is not set",
                    self.username,
                    self.password_env
                )
            })
    }
}

fn default_listen_addr() -> String {
    "0.0.0.0:8200".to_string()
}

fn default_storage_migrate() -> bool {
    true
}

fn default_master_key_env() -> String {
    "SECRETS_MASTER_KEY".to_string()
}

fn default_master_key_retired_env() -> String {
    "SECRETS_MASTER_KEY_RETIRED".to_string()
}

fn default_lease_reap_interval_seconds() -> u64 {
    30
}

impl Config {
    pub fn load() -> Result<Self, Box<figment::Error>> {
        Figment::new()
            .merge(Toml::file("secrets-server.toml"))
            .merge(Env::prefixed("SECRETS_SERVER_"))
            .extract()
            .map_err(Box::new)
    }

    /// Checked separately from deserialization so misconfiguration fails
    /// loudly at startup instead of surfacing as a confusing error on the
    /// first request that happens to touch the broken setting.
    pub fn validate(&self) -> anyhow::Result<()> {
        self.listen_addr
            .parse::<std::net::SocketAddr>()
            .map_err(|e| anyhow::anyhow!("invalid listen_addr '{}': {e}", self.listen_addr))?;

        if !self.storage_database_url.starts_with("postgres://")
            && !self.storage_database_url.starts_with("postgresql://")
        {
            anyhow::bail!("storage_database_url must be a postgres:// connection string");
        }

        if self.lease_reap_interval_seconds == 0 {
            anyhow::bail!("lease_reap_interval_seconds must be greater than zero");
        }

        if self.bootstrap_username.is_some() != self.bootstrap_password.is_some() {
            anyhow::bail!("bootstrap_username and bootstrap_password must be set together");
        }

        let mut seen = std::collections::HashSet::new();
        for identity in &self.service_identities {
            let name = &identity.username;
            validate_username(name)
                .and_then(|()| validate_password(&identity.password()?))
                .map_err(|e| anyhow::anyhow!("service identity '{name}': {e}"))?;
            if !seen.insert(name) {
                anyhow::bail!("service identity '{name}' is declared twice");
            }
            // Its policy is named after it, so it must not take over the
            // admin's, and must not be the admin (whose rights it would cut).
            if name == ROOT_POLICY_NAME || self.bootstrap_username.as_ref() == Some(name) {
                anyhow::bail!("service identity '{name}' would replace the bootstrap admin or its root policy");
            }
        }

        Ok(())
    }
}

fn validate_username(name: &str) -> anyhow::Result<()> {
    secrets_auth_userpass::validate_username(name).map_err(|e| anyhow::anyhow!("{e}"))
}

fn validate_password(password: &str) -> anyhow::Result<()> {
    secrets_auth_userpass::validate_password(password).map_err(|e| anyhow::anyhow!("{e}"))
}

#[cfg(test)]
// `Jail::expect_with` fixes the closure's error type to `figment::Error`.
#[allow(clippy::result_large_err)]
mod tests {
    use super::*;
    use figment::Jail;
    use secrets_core::policy::Capability;

    /// Byte for byte what `typednotes-infra` sets (its `vaultServiceIdentities`).
    const IDENTITIES: &str = concat!(
        r#"[{username="typednotes-app", password_env="APP_SECRETS_PASSWORD", "#,
        r#"rules=[{prefix="secret/data/thirdparty/", capabilities=["create","delete"]}]}, "#,
        r#"{username="liaison", password_env="LIAISON_SECRETS_PASSWORD", "#,
        r#"rules=[{prefix="secret/data/thirdparty/", capabilities=["read","create"]}]}]"#
    );

    fn base(jail: &mut Jail) {
        jail.set_env("SECRETS_SERVER_STORAGE_DATABASE_URL", "postgres://u@h/db");
        jail.set_env("SECRETS_SERVER_BOOTSTRAP_USERNAME", "admin");
        jail.set_env("SECRETS_SERVER_BOOTSTRAP_PASSWORD", "change-me");
    }

    fn err(config: &Config) -> String {
        config.validate().unwrap_err().to_string()
    }

    /// The shape a deploy tool puts in one env var, as figment parses it.
    #[test]
    fn service_identities_parse_from_one_env_var() {
        Jail::expect_with(|jail| {
            base(jail);
            jail.set_env("SECRETS_SERVER_SERVICE_IDENTITIES", IDENTITIES);
            jail.set_env("APP_SECRETS_PASSWORD", "an app password long enough");
            jail.set_env("LIAISON_SECRETS_PASSWORD", "a liaison password long enough");
            let config = Config::load().unwrap();
            config.validate().unwrap();

            let [app, liaison] = config.service_identities.as_slice() else {
                panic!("{:?}", config.service_identities)
            };
            assert_eq!(app.username, "typednotes-app");
            assert_eq!(app.password().unwrap(), "an app password long enough");
            assert_eq!(app.rules[0].prefix, "secret/data/thirdparty/");
            assert_eq!(app.rules[0].capabilities, [Capability::Create, Capability::Delete]);
            assert_eq!(liaison.rules[0].capabilities, [Capability::Read, Capability::Create]);
            Ok(())
        });
    }

    #[test]
    fn no_service_identities_by_default() {
        Jail::expect_with(|jail| {
            base(jail);
            let config = Config::load().unwrap();
            assert!(config.service_identities.is_empty());
            config.validate().unwrap();
            Ok(())
        });
    }

    /// Misconfiguration stops the server at startup, naming the identity —
    /// never the password.
    #[test]
    fn invalid_service_identities_fail_validation() {
        Jail::expect_with(|jail| {
            base(jail);
            jail.set_env("SHORT_PW", "tiny-pw-7");
            jail.set_env("GOOD_PW", "a password long enough");
            for (identities, expected) in [
                (r#"[{username="svc", password_env="UNSET_PW", rules=[]}]"#, "UNSET_PW is not set"),
                (r#"[{username="svc", password_env="SHORT_PW", rules=[]}]"#, "at least 12"),
                (r#"[{username="a/b", password_env="GOOD_PW", rules=[]}]"#, "username"),
                (r#"[{username="admin", password_env="GOOD_PW", rules=[]}]"#, "bootstrap admin"),
                (r#"[{username="root", password_env="GOOD_PW", rules=[]}]"#, "root policy"),
                (
                    r#"[{username="svc", password_env="GOOD_PW", rules=[]},
                        {username="svc", password_env="GOOD_PW", rules=[]}]"#,
                    "declared twice",
                ),
            ] {
                jail.set_env("SECRETS_SERVER_SERVICE_IDENTITIES", identities);
                let message = err(&Config::load().unwrap());
                assert!(message.contains(expected), "{identities}: {message}");
                assert!(!message.contains("tiny-pw-7"), "leaked the password: {message}");
            }
            Ok(())
        });
    }
}
