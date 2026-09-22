//! GitLab project and group access tokens — mintable and revocable through the
//! API, but with expiry that GitLab only accepts as a *date*. There is no such
//! thing as a fifteen-minute GitLab token, so this engine keeps two clocks: it
//! asks GitLab for the nearest possible date as a backstop, and holds the real
//! deadline in the lease, where the reaper can enforce it to the second.
//!
//! See `docs/delegation/gitlab.md` for the mechanism and
//! `docs/delegation/setup/gitlab.md` for the operator walkthrough.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
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

const STORE: ConfigRoleStore = ConfigRoleStore::new("gitlab/config/", "gitlab/roles/");
const MOUNT: &str = "gitlab/creds/";
const DEFAULT_API: &str = "https://gitlab.com/api/v4";

/// Reporter. Deliberately lower than GitLab's own default of 40 (Maintainer),
/// which is far more authority than a consumer usually needs.
const DEFAULT_ACCESS_LEVEL: u8 = 20;
const DEFAULT_TTL_SECONDS: i64 = 900;

/// How the server authenticates to GitLab. `private_token` is an Owner-level
/// PAT (or an admin PAT for instance-wide work) and is never read back out.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitlabConfig {
    /// Override for self-managed, e.g. `https://gitlab.example.com/api/v4`.
    #[serde(default = "default_api")]
    pub base_url: String,
    pub private_token: String,
}

fn default_api() -> String {
    DEFAULT_API.to_string()
}

/// Whether a role mints a project- or group-scoped token. Group tokens reach
/// every project in the group, so prefer `Project` unless the consumer really
/// needs the breadth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Resource {
    #[default]
    Project,
    Group,
}

impl Resource {
    fn api_segment(self) -> &'static str {
        match self {
            Self::Project => "projects",
            Self::Group => "groups",
        }
    }
}

/// What one consumer may mint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleConfig {
    /// Which `gitlab/config/{name}` document to authenticate with.
    pub target: String,
    #[serde(default)]
    pub resource: Resource,
    /// Numeric project or group id. GitLab also accepts a URL-encoded path,
    /// but ids do not break when a project is renamed or moved.
    pub resource_id: String,
    /// GitLab rejects a token with no scopes, so this must be non-empty.
    /// `read_repository` for cloning, `read_api` for read-only API access.
    pub scopes: Vec<String>,
    #[serde(default = "default_access_level")]
    pub access_level: u8,
    /// The deadline the reaper enforces. GitLab cannot express anything this
    /// short — see the module docs.
    #[serde(default = "default_ttl_seconds")]
    pub default_ttl_seconds: i64,
}

fn default_access_level() -> u8 {
    DEFAULT_ACCESS_LEVEL
}

fn default_ttl_seconds() -> i64 {
    DEFAULT_TTL_SECONDS
}

#[derive(Debug, Deserialize)]
struct AccessTokenResponse {
    /// Revocation addresses the token by id, not by its secret value.
    id: u64,
    token: String,
    #[serde(default)]
    expires_at: Option<String>,
}

#[derive(Default)]
pub struct GitlabEngine {
    http: reqwest::Client,
}

impl GitlabEngine {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::builder()
                .user_agent("secrets-server")
                .build()
                .unwrap_or_default(),
        }
    }

    /// The soonest expiry GitLab will accept. `expires_at` is a date, and a
    /// token expires at midnight UTC on it, so "tomorrow" is the floor — the
    /// resulting token lives between 24 and 48 hours depending on when we ask.
    /// This is only a backstop for a lease record we somehow lose.
    fn nearest_expiry_date(now: DateTime<Utc>) -> String {
        (now + Duration::days(1)).format("%Y-%m-%d").to_string()
    }

    /// The deadline that actually governs the credential.
    fn lease_expiry(now: DateTime<Utc>, ttl_seconds: i64) -> DateTime<Utc> {
        now + Duration::seconds(ttl_seconds)
    }

    /// Token names show up in GitLab's UI and audit log, so they carry the role
    /// they were minted for plus enough entropy to stay unique.
    fn token_name(role: &str) -> String {
        let suffix = Uuid::new_v4().simple().to_string();
        format!("secrets-{role}-{}", &suffix[..8])
    }

    fn access_level_name(level: u8) -> &'static str {
        match level {
            10 => "guest",
            20 => "reporter",
            30 => "developer",
            40 => "maintainer",
            50 => "owner",
            _ => "unknown",
        }
    }

    fn scope_description(role: &RoleConfig) -> Vec<String> {
        let mut scoped = vec![format!(
            "{}:{}",
            match role.resource {
                Resource::Project => "project",
                Resource::Group => "group",
            },
            role.resource_id
        )];
        scoped.extend(role.scopes.iter().map(|s| format!("scope:{s}")));
        scoped.push(format!(
            "access_level:{}",
            Self::access_level_name(role.access_level)
        ));
        scoped
    }

    fn tokens_url(base_url: &str, resource: Resource, resource_id: &str) -> String {
        format!(
            "{}/{}/{}/access_tokens",
            base_url.trim_end_matches('/'),
            resource.api_segment(),
            resource_id
        )
    }
}

#[async_trait]
impl SecretsEngine for GitlabEngine {
    fn doc(&self) -> EngineDoc {
        EngineDoc {
            provider: "GitLab".to_string(),
            mechanism: "project or group access tokens, minted per request with the \
                        role's scopes and membership level"
                .to_string(),
            shape: CredentialShape::MintAndRevoke,
            revocable: true,
            revoke_effect: "DELETE /{projects|groups}/{id}/access_tokens/{token_id} \
                            using the configured root PAT — the credential stops \
                            working immediately. GitLab purges its own record of a \
                            revoked token after 30 days."
                .to_string(),
            ttl: TtlDoc::range(
                1,
                365 * 24 * 3600,
                "The lease TTL is enforced by our reaper and can be as short as you \
                 like. GitLab's own expires_at is a DATE, so the token it issues is \
                 additionally capped at midnight UTC tomorrow — a backstop, not the \
                 real deadline. There is no way to make GitLab itself expire a token \
                 in minutes.",
            ),
            scoping: "per role: one project or one group, a list of token scopes, and \
                      a membership access level that bounds authority within those \
                      scopes. Group tokens reach every project in the group."
                .to_string(),
            root_credential: "a GitLab PAT with the `api` scope at \
                              gitlab/config/{target}. It must be Owner on the target \
                              group or project — or an instance admin for user-level \
                              tokens — so it is a broad blast radius. Prefer an \
                              Owner PAT scoped to one group over an admin token."
                .to_string(),
            paths: vec![
                PathDoc::new(
                    "gitlab/config/{target}",
                    &["POST", "GET", "DELETE"],
                    "sudo",
                    "register the instance URL and root PAT. GET reports only whether \
                     it is configured — the PAT is never returned.",
                ),
                PathDoc::new(
                    "gitlab/roles/{role}",
                    &["POST", "GET", "DELETE"],
                    "create / read / sudo",
                    "define one consumer's project or group, scopes, access level and TTL",
                ),
                PathDoc::new(
                    "gitlab/creds/{role}",
                    &["GET"],
                    "read",
                    "mint an access token and open a lease",
                ),
                PathDoc::new("gitlab/help", &["GET"], "authenticated", "this document"),
            ],
            docs_url: Some("docs/delegation/gitlab.md".to_string()),
            caveats: vec![
                "GitLab's expires_at has DATE granularity — a token expires at \
                 midnight UTC, and the soonest it accepts is tomorrow. Sub-day expiry \
                 does not exist at the provider, so the lease is the only tight clock."
                    .to_string(),
                "expires_at has been mandatory since GitLab 16.0, and omitting it \
                 yields 365 days. This engine always sends the nearest date so a lost \
                 lease record cannot leave a year-long credential behind."
                    .to_string(),
                "The root PAT needs the `api` scope and Owner (or admin) authority, \
                 which is far more reach than any token it mints. Rotate it on a \
                 schedule and scope it to one group where possible."
                    .to_string(),
                "GitLab has a token rotation endpoint, but rotating an ALREADY-REVOKED \
                 token triggers family-wide revocation as a reuse-detection measure. \
                 Never blindly retry a rotation — re-read state first. This engine \
                 mints and revokes rather than rotating, precisely to avoid that."
                    .to_string(),
                "Deploy tokens and deploy keys cannot call the GitLab API at all \
                 (repository and registry only), so they are not offered here."
                    .to_string(),
                "CI job tokens and GitLab ID tokens exist only inside a running \
                 pipeline and cannot be minted from outside."
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
        STORE.handle_write::<GitlabConfig, RoleConfig>(storage, path, data).await
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
        let config: GitlabConfig = STORE.require_config(storage, &role.target).await?;

        // GitLab rejects a scopeless token with an opaque 400, so say what is
        // actually wrong with the role.
        if role.scopes.is_empty() {
            return Err(EngineError::InvalidRequest(format!(
                "gitlab/roles/{role_name} has no scopes — GitLab requires at least \
                 one, e.g. [\"read_repository\"]"
            )));
        }

        let now = Utc::now();
        let url = Self::tokens_url(&config.base_url, role.resource, &role.resource_id);
        let response = self
            .http
            .post(&url)
            .header("PRIVATE-TOKEN", &config.private_token)
            .json(&json!({
                "name": Self::token_name(role_name),
                "scopes": role.scopes,
                "access_level": role.access_level,
                "expires_at": Self::nearest_expiry_date(now),
            }))
            .send()
            .await
            .map_err(|e| EngineError::Provider(format!("GitLab request failed: {e}")))?;

        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(EngineError::Provider(format!(
                "GitLab returned {status} for {url}: {text}"
            )));
        }
        let token: AccessTokenResponse = serde_json::from_str(&text)
            .map_err(|e| EngineError::Provider(format!("unexpected GitLab response: {e}")))?;

        let lease = Lease {
            id: Uuid::new_v4(),
            // Set by the HTTP handler, which knows the requesting token.
            token_id_hash: String::new(),
            engine_mount: MOUNT.to_string(),
            // Revocation needs the token id and the root PAT, so keep the id and
            // enough context to load the config again. The token value itself is
            // not needed and is deliberately not stored.
            internal_data: json!({
                "target": role.target,
                "resource": role.resource,
                "resource_id": role.resource_id,
                "token_id": token.id,
            }),
            issued_at: now,
            // Our clock, not GitLab's date. GitLab cannot expire a token in
            // minutes, so the reaper is what makes this credential short-lived.
            expires_at: Self::lease_expiry(now, role.default_ttl_seconds),
        };

        Ok(GeneratedCredential::new(
            json!({
                "token": token.token,
                "git_clone_username": "oauth2",
                // GitLab's own expiry, exposed so a caller can see that it is
                // later than the lease and understand which one binds.
                "provider_expires_at": token.expires_at,
            }),
            lease,
            Self::scope_description(&role),
        ))
    }

    async fn revoke(&self, storage: &dyn StorageBackend, lease: &Lease) -> EngineResult<()> {
        let target = lease.internal_data["target"]
            .as_str()
            .ok_or_else(|| EngineError::Other("lease missing 'target'".into()))?;
        let resource_id = lease.internal_data["resource_id"]
            .as_str()
            .ok_or_else(|| EngineError::Other("lease missing 'resource_id'".into()))?;
        let token_id = lease.internal_data["token_id"]
            .as_u64()
            .ok_or_else(|| EngineError::Other("lease missing 'token_id'".into()))?;
        let resource: Resource = serde_json::from_value(lease.internal_data["resource"].clone())
            .map_err(|e| EngineError::Other(format!("lease has an invalid 'resource': {e}")))?;

        // The operator can delete a config while leases against it are still
        // open. Failing here would wedge the reaper on a lease it can never
        // clear, so report it loudly and let the lease record go.
        let Some(config) = STORE.load_config::<GitlabConfig>(storage, target).await? else {
            tracing::warn!(
                target,
                token_id,
                "gitlab/config was deleted before this lease expired — cannot revoke \
                 the access token. Revoke it by hand in GitLab."
            );
            return Ok(());
        };

        let response = self
            .http
            .delete(format!(
                "{}/{token_id}",
                Self::tokens_url(&config.base_url, resource, resource_id)
            ))
            .header("PRIVATE-TOKEN", &config.private_token)
            .send()
            .await
            .map_err(|e| EngineError::Provider(format!("GitLab revoke failed: {e}")))?;

        // A token GitLab has already dropped is not an error — the reaper must
        // be able to retry without tripping over its own success.
        if response.status().is_success() || response.status() == reqwest::StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(EngineError::Provider(format!(
                "GitLab returned {} when revoking access token {token_id}",
                response.status()
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn role(scopes: &[&str]) -> RoleConfig {
        RoleConfig {
            target: "acme".to_string(),
            resource: Resource::Project,
            resource_id: "42".to_string(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            access_level: DEFAULT_ACCESS_LEVEL,
            default_ttl_seconds: DEFAULT_TTL_SECONDS,
        }
    }

    #[test]
    fn nearest_expiry_is_tomorrows_date() {
        let now = Utc.with_ymd_and_hms(2026, 3, 4, 23, 50, 0).unwrap();
        assert_eq!(GitlabEngine::nearest_expiry_date(now), "2026-03-05");

        // Month and year boundaries are where naive date arithmetic breaks.
        let eom = Utc.with_ymd_and_hms(2026, 12, 31, 9, 0, 0).unwrap();
        assert_eq!(GitlabEngine::nearest_expiry_date(eom), "2027-01-01");
    }

    /// The whole point of this engine: the lease binds long before the token
    /// GitLab issued would have expired on its own.
    #[test]
    fn lease_expiry_follows_our_ttl_not_gitlabs_date() {
        let now = Utc.with_ymd_and_hms(2026, 3, 4, 9, 0, 0).unwrap();
        let expiry = GitlabEngine::lease_expiry(now, DEFAULT_TTL_SECONDS);

        assert_eq!(expiry, now + Duration::seconds(900));

        // GitLab's backstop is midnight UTC on the date we asked for, which is
        // many hours later than the deadline the reaper will enforce.
        let provider_date = GitlabEngine::nearest_expiry_date(now);
        let provider_expiry = DateTime::parse_from_rfc3339(&format!("{provider_date}T00:00:00Z"))
            .unwrap()
            .with_timezone(&Utc);
        assert!(
            expiry < provider_expiry,
            "lease ({expiry}) must expire before GitLab's date backstop ({provider_expiry})"
        );
    }

    #[test]
    fn scope_description_names_the_resource_scopes_and_level() {
        let scoped = GitlabEngine::scope_description(&role(&["read_repository", "read_api"]));
        assert!(scoped.contains(&"project:42".to_string()));
        assert!(scoped.contains(&"scope:read_repository".to_string()));
        assert!(scoped.contains(&"scope:read_api".to_string()));
        assert!(scoped.contains(&"access_level:reporter".to_string()));
    }

    #[test]
    fn scope_description_distinguishes_groups_from_projects() {
        let mut group_role = role(&["read_registry"]);
        group_role.resource = Resource::Group;
        group_role.resource_id = "7".to_string();
        let scoped = GitlabEngine::scope_description(&group_role);
        assert!(scoped.contains(&"group:7".to_string()));
    }

    #[test]
    fn token_name_carries_the_role_and_is_unique() {
        let first = GitlabEngine::token_name("report-service");
        let second = GitlabEngine::token_name("report-service");
        assert!(first.starts_with("secrets-report-service-"));
        assert_ne!(first, second);
    }

    #[test]
    fn tokens_url_matches_the_resource_kind() {
        assert_eq!(
            GitlabEngine::tokens_url("https://gitlab.com/api/v4/", Resource::Project, "42"),
            "https://gitlab.com/api/v4/projects/42/access_tokens"
        );
        assert_eq!(
            GitlabEngine::tokens_url(DEFAULT_API, Resource::Group, "7"),
            "https://gitlab.com/api/v4/groups/7/access_tokens"
        );
    }

    /// A role defaulting to Maintainer would hand consumers far more authority
    /// than they need, so the default must stay below GitLab's own.
    #[test]
    fn default_access_level_is_narrower_than_gitlabs() {
        assert_eq!(default_access_level(), 20);
        assert_eq!(GitlabEngine::access_level_name(default_access_level()), "reporter");
    }

    #[test]
    fn role_defaults_fill_in_from_minimal_json() {
        let parsed: RoleConfig = serde_json::from_value(json!({
            "target": "acme",
            "resource_id": "42",
            "scopes": ["read_repository"],
        }))
        .unwrap();
        assert_eq!(parsed.resource, Resource::Project);
        assert_eq!(parsed.access_level, DEFAULT_ACCESS_LEVEL);
        assert_eq!(parsed.default_ttl_seconds, DEFAULT_TTL_SECONDS);
    }

    #[test]
    fn doc_agrees_with_its_shape() {
        let doc = GitlabEngine::new().doc();
        assert_eq!(doc.shape, CredentialShape::MintAndRevoke);
        assert_eq!(doc.revocable, doc.shape.revocable());
        assert!(!doc.ttl.fixed);
        // The date-granularity trap is the single most surprising thing about
        // this provider; the docs must not omit it.
        assert!(
            doc.caveats.iter().any(|c| c.contains("DATE granularity")),
            "doc() must warn about date-only expiry"
        );
    }
}
