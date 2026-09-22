//! GitHub App installation tokens — the one provider in this set where a lease
//! means exactly what it says: credentials are short-lived by construction,
//! narrowable to named repositories *and* a subset of permissions, and
//! genuinely revocable before expiry.
//!
//! See `docs/delegation/github.md` for the mechanism and
//! `docs/delegation/setup/github.md` for the operator walkthrough.

use std::collections::BTreeMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use secrets_core::engine::{
    CredentialShape, EngineDoc, EngineError, EngineResult, GeneratedCredential, PathDoc,
    SecretsEngine, TtlDoc,
};
use secrets_core::lease::Lease;
use secrets_core::mount::ConfigRoleStore;
use secrets_core::storage::StorageBackend;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

const STORE: ConfigRoleStore = ConfigRoleStore::new("github/config/", "github/roles/");
const MOUNT: &str = "github/creds/";
const DEFAULT_API: &str = "https://api.github.com";

/// GitHub caps an App JWT at 10 minutes. We ask for 9 to leave room for clock
/// skew on their side as well as ours.
const APP_JWT_TTL_SECONDS: i64 = 540;
/// `iat` is backdated by a minute, the conventional guard against our clock
/// running ahead of GitHub's — which GitHub rejects outright.
const APP_JWT_BACKDATE_SECONDS: i64 = 60;
/// Installation tokens always live one hour. GitHub does not let us choose.
const INSTALLATION_TOKEN_TTL_SECONDS: i64 = 3600;

/// The App's identity. `private_key_pem` is the only durable secret this
/// engine needs, and it is never read back out (see `ConfigRoleStore`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GithubConfig {
    /// The App's client ID. The numeric App ID also works as a legacy fallback.
    pub app_id: String,
    /// RSA private key PEM generated for the App.
    pub private_key_pem: String,
    /// Override for GitHub Enterprise Server, e.g. `https://ghe.example.com/api/v3`.
    #[serde(default = "default_api")]
    pub base_url: String,
}

fn default_api() -> String {
    DEFAULT_API.to_string()
}

/// What one consumer may mint. Both `repositories` and `permissions` narrow the
/// token *down* from what the installation was granted — they can never widen
/// it, so the App's own permissions remain the ceiling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleConfig {
    /// Which `github/config/{name}` document to authenticate with.
    pub target: String,
    pub installation_id: u64,
    /// Repository names (not full `owner/repo` paths). Empty means every
    /// repository the App is installed on — rarely what you want.
    #[serde(default)]
    pub repositories: Vec<String>,
    /// e.g. `{"contents": "read", "pull_requests": "write"}`. Empty means the
    /// installation's full permission set.
    #[serde(default)]
    pub permissions: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct InstallationTokenResponse {
    token: String,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct AppJwtClaims {
    iat: i64,
    exp: i64,
    iss: String,
}

#[derive(Default)]
pub struct GithubEngine {
    http: reqwest::Client,
}

impl GithubEngine {
    pub fn new() -> Self {
        Self {
            // GitHub rejects requests without a User-Agent.
            http: reqwest::Client::builder()
                .user_agent("secrets-server")
                .build()
                .unwrap_or_default(),
        }
    }

    /// Builds the short-lived JWT that proves "I am this App". This is not a
    /// repository credential — it only authenticates the installation-token
    /// request below.
    fn app_jwt(config: &GithubConfig, now: DateTime<Utc>) -> EngineResult<String> {
        let claims = AppJwtClaims {
            iat: now.timestamp() - APP_JWT_BACKDATE_SECONDS,
            exp: now.timestamp() + APP_JWT_TTL_SECONDS,
            iss: config.app_id.clone(),
        };
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(config.private_key_pem.as_bytes())
            .map_err(|e| {
                EngineError::InvalidRequest(format!(
                    "github/config private_key_pem is not a valid RSA PEM: {e}"
                ))
            })?;
        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
            &claims,
            &key,
        )
        .map_err(|e| EngineError::Other(format!("failed to sign App JWT: {e}")))
    }

    fn scope_description(role: &RoleConfig) -> Vec<String> {
        let mut scoped = Vec::new();
        if role.repositories.is_empty() {
            scoped.push("repos:ALL (every repository the App is installed on)".to_string());
        } else {
            scoped.extend(role.repositories.iter().map(|r| format!("repo:{r}")));
        }
        if role.permissions.is_empty() {
            scoped.push("permissions:ALL (the installation's full grant)".to_string());
        } else {
            scoped.extend(role.permissions.iter().map(|(k, v)| format!("{k}:{v}")));
        }
        scoped
    }
}

#[async_trait]
impl SecretsEngine for GithubEngine {
    fn doc(&self) -> EngineDoc {
        EngineDoc {
            provider: "GitHub".to_string(),
            mechanism: "GitHub App installation access tokens, minted per request \
                        and narrowed to named repositories and a permission subset"
                .to_string(),
            shape: CredentialShape::MintAndRevoke,
            revocable: true,
            revoke_effect: "DELETE /installation/token, authenticated with the leased \
                            token itself — the credential stops working immediately. \
                            GitHub is the only provider here where lease revocation \
                            is a real guarantee rather than an advisory one."
                .to_string(),
            ttl: TtlDoc::fixed(
                INSTALLATION_TOKEN_TTL_SECONDS,
                "GitHub fixes installation tokens at one hour and offers no way to \
                 shorten, lengthen or refresh them. Roles therefore carry no TTL \
                 setting; mint again to get a fresh hour.",
            ),
            scoping: "per role: a list of repositories (at most 500) and a subset of \
                      the App's permissions. Both only ever narrow what the \
                      installation already has — the App's grant is the ceiling."
                .to_string(),
            root_credential: "the GitHub App's RSA private key PEM, at \
                              github/config/{target}. It can mint tokens for every \
                              repository the App is installed on, so install the App \
                              narrowly."
                .to_string(),
            paths: vec![
                PathDoc::new(
                    "github/config/{target}",
                    &["POST", "GET", "DELETE"],
                    "sudo",
                    "register the App id and private key. GET reports only whether \
                     it is configured — the key is never returned.",
                ),
                PathDoc::new(
                    "github/roles/{role}",
                    &["POST", "GET", "DELETE"],
                    "create / read / sudo",
                    "define one consumer's installation, repositories and permissions",
                ),
                PathDoc::new(
                    "github/creds/{role}",
                    &["GET"],
                    "read",
                    "mint a one-hour installation token and open a lease",
                ),
                PathDoc::new(
                    "github/help",
                    &["GET"],
                    "authenticated",
                    "this document",
                ),
            ],
            docs_url: Some("docs/delegation/github.md".to_string()),
            caveats: vec![
                "Token creation is rate-limited to roughly 2,000 per hour across the \
                 whole App — not per installation. Under load, reuse a token for most \
                 of its hour rather than minting per request."
                    .to_string(),
                "A token may name at most 500 repositories, and a wide permission set \
                 crossed with a wide repository set can be rejected for 'complexity'."
                    .to_string(),
                "Treat the token as opaque. GitHub is rolling out a stateless \
                 JWT-shaped installation token on some plans, so never parse it."
                    .to_string(),
                "Personal access tokens cannot be created by any API, so they are not \
                 available here — store one in KV if you truly need it."
                    .to_string(),
            ],
        }
    }

    async fn read(&self, storage: &dyn StorageBackend, path: &str) -> EngineResult<serde_json::Value> {
        STORE.handle_read::<RoleConfig>(storage, path).await
    }

    async fn write(
        &self,
        storage: &dyn StorageBackend,
        path: &str,
        data: serde_json::Value,
    ) -> EngineResult<()> {
        STORE.handle_write::<GithubConfig, RoleConfig>(storage, path, data).await
    }

    async fn delete(&self, storage: &dyn StorageBackend, path: &str) -> EngineResult<()> {
        STORE.handle_delete(storage, path).await
    }

    async fn list(&self, storage: &dyn StorageBackend, prefix: &str) -> EngineResult<Vec<String>> {
        STORE.handle_list(storage, prefix).await
    }

    async fn generate(
        &self,
        storage: &dyn StorageBackend,
        role_name: &str,
    ) -> EngineResult<GeneratedCredential> {
        let role: RoleConfig = STORE.require_role(storage, role_name).await?;
        let config: GithubConfig = STORE.require_config(storage, &role.target).await?;

        let now = Utc::now();
        let jwt = Self::app_jwt(&config, now)?;

        let mut body = serde_json::Map::new();
        if !role.repositories.is_empty() {
            body.insert("repositories".to_string(), json!(role.repositories));
        }
        if !role.permissions.is_empty() {
            body.insert("permissions".to_string(), json!(role.permissions));
        }

        let url = format!(
            "{}/app/installations/{}/access_tokens",
            config.base_url.trim_end_matches('/'),
            role.installation_id
        );
        let response = self
            .http
            .post(&url)
            .bearer_auth(&jwt)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .json(&serde_json::Value::Object(body))
            .send()
            .await
            .map_err(|e| EngineError::Provider(format!("GitHub request failed: {e}")))?;

        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(EngineError::Provider(format!(
                "GitHub returned {status} for {url}: {text}"
            )));
        }
        let token: InstallationTokenResponse = serde_json::from_str(&text)
            .map_err(|e| EngineError::Provider(format!("unexpected GitHub response: {e}")))?;

        let lease = Lease {
            id: Uuid::new_v4(),
            // Set by the HTTP handler, which knows the requesting token.
            token_id_hash: String::new(),
            engine_mount: MOUNT.to_string(),
            // Revocation authenticates with the token being revoked, so it has
            // to be kept: an engine that discarded it could not revoke.
            internal_data: json!({
                "token": token.token,
                "base_url": config.base_url,
                "role": role_name,
            }),
            issued_at: now,
            // GitHub's own expiry, not ours — a lease must never outlive the
            // credential it governs.
            expires_at: token.expires_at,
        };

        Ok(GeneratedCredential::new(
            json!({
                "token": token.token,
                "expires_at": token.expires_at,
                "git_clone_username": "x-access-token",
            }),
            lease,
            Self::scope_description(&role),
        ))
    }

    async fn revoke(&self, _storage: &dyn StorageBackend, lease: &Lease) -> EngineResult<()> {
        let token = lease.internal_data["token"]
            .as_str()
            .ok_or_else(|| EngineError::Other("lease missing 'token'".into()))?;
        let base_url = lease.internal_data["base_url"]
            .as_str()
            .unwrap_or(DEFAULT_API)
            .trim_end_matches('/');

        let response = self
            .http
            .delete(format!("{base_url}/installation/token"))
            .bearer_auth(token)
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
            .map_err(|e| EngineError::Provider(format!("GitHub revoke failed: {e}")))?;

        // An already-expired or already-revoked token is not an error — the
        // reaper must be able to retry without tripping over its own success.
        if response.status().is_success()
            || response.status() == reqwest::StatusCode::UNAUTHORIZED
            || response.status() == reqwest::StatusCode::NOT_FOUND
        {
            Ok(())
        } else {
            Err(EngineError::Provider(format!(
                "GitHub returned {} when revoking the installation token",
                response.status()
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role(repos: &[&str], perms: &[(&str, &str)]) -> RoleConfig {
        RoleConfig {
            target: "acme".to_string(),
            installation_id: 1,
            repositories: repos.iter().map(|r| r.to_string()).collect(),
            permissions: perms
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn scope_description_lists_repos_and_permissions() {
        let scoped = GithubEngine::scope_description(&role(
            &["reports"],
            &[("contents", "read"), ("pull_requests", "write")],
        ));
        assert!(scoped.contains(&"repo:reports".to_string()));
        assert!(scoped.contains(&"contents:read".to_string()));
        assert!(scoped.contains(&"pull_requests:write".to_string()));
    }

    /// An unscoped role is a footgun, so the `_doc` a consumer receives must
    /// say so out loud rather than showing an empty list.
    #[test]
    fn scope_description_is_explicit_when_unscoped() {
        let scoped = GithubEngine::scope_description(&role(&[], &[]));
        assert!(scoped.iter().any(|s| s.contains("repos:ALL")));
        assert!(scoped.iter().any(|s| s.contains("permissions:ALL")));
    }

    #[test]
    fn app_jwt_respects_githubs_ten_minute_ceiling() {
        // A real 2048-bit key is needed to exercise signing, so assert on the
        // claim arithmetic, which is where the 10-minute rule gets broken.
        let now = Utc::now();
        let claims = AppJwtClaims {
            iat: now.timestamp() - APP_JWT_BACKDATE_SECONDS,
            exp: now.timestamp() + APP_JWT_TTL_SECONDS,
            iss: "123".to_string(),
        };
        assert!(
            claims.exp - claims.iat <= 600,
            "App JWT lifetime must stay within GitHub's 10-minute limit"
        );
        assert!(claims.iat < now.timestamp(), "iat must be backdated for clock skew");
    }

    #[test]
    fn rejects_a_private_key_that_is_not_a_pem() {
        let config = GithubConfig {
            app_id: "123".to_string(),
            private_key_pem: "not a pem".to_string(),
            base_url: default_api(),
        };
        let err = GithubEngine::app_jwt(&config, Utc::now()).unwrap_err();
        assert!(matches!(err, EngineError::InvalidRequest(_)), "got {err:?}");
    }

    #[test]
    fn doc_agrees_with_its_shape() {
        let doc = GithubEngine::new().doc();
        assert_eq!(doc.shape, CredentialShape::MintAndRevoke);
        assert_eq!(doc.revocable, doc.shape.revocable());
        assert!(doc.ttl.fixed);
    }
}
