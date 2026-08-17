use figment::providers::{Env, Format, Toml};
use figment::Figment;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    /// Address the HTTP server binds to.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    /// Connection string for this server's own encrypted storage database.
    pub storage_database_url: String,
    /// Env var name holding the hex-encoded 32-byte master key (or a path to
    /// a file containing it).
    #[serde(default = "default_master_key_env")]
    pub master_key_env: String,
    /// If set (together with `bootstrap_password`) and the user does not
    /// already exist, creates an initial admin user with a full-access
    /// "root" policy on first startup.
    pub bootstrap_username: Option<String>,
    pub bootstrap_password: Option<String>,
    /// How often the background reaper scans for expired leases.
    #[serde(default = "default_lease_reap_interval_seconds")]
    pub lease_reap_interval_seconds: u64,
}

fn default_listen_addr() -> String {
    "0.0.0.0:8200".to_string()
}

fn default_master_key_env() -> String {
    "SECRETS_MASTER_KEY".to_string()
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

        Ok(())
    }
}
