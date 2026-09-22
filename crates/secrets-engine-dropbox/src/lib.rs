//! Dropbox access tokens, brokered from a stored refresh token.
//!
//! Dropbox offers no API that mints a sub-credential, so this engine cannot be
//! anything but a broker: it holds the one long-lived refresh token per
//! authorisation and hands out four-hour access tokens. The consumer never
//! sees the durable secret, which is the whole of the benefit.
//!
//! The consequence worth internalising before reading further: because nothing
//! is mintable, **isolation between consumers comes from separate OAuth
//! authorisations, not from this engine**. One config document per consumer.
//! Share one authorisation across several consumers and you lose the ability
//! to revoke any of them independently — there is no server-side trick that
//! recovers it.
//!
//! See `docs/delegation/dropbox.md` for the mechanism and
//! `docs/delegation/setup/dropbox.md` for the operator walkthrough.

use async_trait::async_trait;
use base64::prelude::{BASE64_STANDARD, Engine as _};
use chrono::Utc;
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

const STORE: ConfigRoleStore = ConfigRoleStore::new("dropbox/config/", "dropbox/roles/");
const MOUNT: &str = "dropbox/creds/";
const TOKEN_ENDPOINT: &str = "https://api.dropbox.com/oauth2/token";
const REVOKE_ENDPOINT: &str = "https://api.dropboxapi.com/2/auth/token/revoke";

/// Dropbox fixes access tokens at four hours and offers no way to shorten
/// them, so this is documentation rather than a setting. The value actually
/// used for a lease comes from the token response.
const ACCESS_TOKEN_TTL_SECONDS: i64 = 14400;

/// One consumer's OAuth authorisation. All three fields are durable secrets:
/// the refresh token never expires and never rotates on use, so this document
/// is the blast radius of the mount and is never read back out (see
/// `ConfigRoleStore`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DropboxConfig {
    pub app_key: String,
    pub app_secret: String,
    /// Obtained once, interactively, with `token_access_type=offline`. Without
    /// that parameter Dropbox issues no refresh token at all.
    pub refresh_token: String,
}

/// What one consumer may ask for. Nothing here can widen the authorisation —
/// `scopes` only ever narrows it, and the `select_*` fields merely name whom to
/// act as, which is not the same as being limited to them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleConfig {
    /// Which `dropbox/config/{name}` authorisation to broker from.
    pub target: String,
    /// A subset of the scopes the authorisation already holds. Empty means the
    /// full set it was granted.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Team member id to act as, sent by the consumer as
    /// `Dropbox-API-Select-User`. Only meaningful for a team authorisation.
    #[serde(default)]
    pub select_user: Option<String>,
    /// Acts over team-owned content, sent as `Dropbox-API-Select-Admin`.
    #[serde(default)]
    pub select_admin: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: i64,
    /// Present when the grant was downscoped; echoed back so the consumer sees
    /// what it actually got rather than what the role asked for.
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Default)]
pub struct DropboxEngine {
    http: reqwest::Client,
}

impl DropboxEngine {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::new(),
        }
    }

    /// Dropbox authenticates the refresh grant with the app credentials in an
    /// HTTP Basic header. Built by hand rather than with `reqwest`'s helper so
    /// the encoding is directly testable — getting this wrong fails as an
    /// opaque `invalid_client` at runtime.
    fn basic_auth_header(app_key: &str, app_secret: &str) -> String {
        format!(
            "Basic {}",
            BASE64_STANDARD.encode(format!("{app_key}:{app_secret}"))
        )
    }

    fn scope_description(role: &RoleConfig) -> Vec<String> {
        let mut scoped = Vec::new();
        if role.scopes.is_empty() {
            scoped.push("scopes:ALL (every scope this authorisation was granted)".to_string());
        } else {
            scoped.extend(role.scopes.iter().map(|s| format!("scope:{s}")));
        }
        // Spelled out because the blast radius here surprises people: the
        // header picks whom to act as, it does not confine the token to them.
        if let Some(member) = &role.select_user {
            scoped.push(format!(
                "acting-as:{member} (team token — selects a target, does NOT reduce reach)"
            ));
        }
        if let Some(admin) = &role.select_admin {
            scoped.push(format!(
                "acting-as-admin:{admin} (team-owned content — selects a target, does NOT reduce reach)"
            ));
        }
        scoped
    }
}

#[async_trait]
impl SecretsEngine for DropboxEngine {
    fn doc(&self) -> EngineDoc {
        EngineDoc {
            provider: "Dropbox".to_string(),
            mechanism: "short-lived OAuth access tokens brokered from one stored \
                        refresh token per consumer authorisation"
                .to_string(),
            shape: CredentialShape::RefreshBroker,
            // False in the sense the field means: revoking the lease does not
            // kill the token the consumer is holding. The durable half *is*
            // revocable, but only as the destructive operator action below.
            revocable: false,
            revoke_effect: "nothing, deliberately. Dropbox's /2/auth/token/revoke \
                            invalidates the refresh token together with the access \
                            token, so revoking on lease expiry would destroy the \
                            authorisation and require a human to re-consent. The \
                            reaper therefore only drops our lease record and lets the \
                            four-hour token lapse. Real revocation is an operator \
                            action: DELETE dropbox/config/{target}, then POST \
                            https://api.dropboxapi.com/2/auth/token/revoke by hand."
                .to_string(),
            ttl: TtlDoc::fixed(
                ACCESS_TOKEN_TTL_SECONDS,
                "Dropbox fixes access tokens at four hours and offers no way to \
                 shorten them, including for testing. Roles carry no TTL setting. \
                 This is the longest window in this deployment, so prefer an \
                 App-folder app to limit what the four hours can reach.",
            ),
            scoping: "per role: a subset of the scopes the authorisation already \
                      holds. Beyond that, scope is fixed by the Dropbox app itself — \
                      an App-folder app is sandboxed to /Apps/{name}, a Full Dropbox \
                      app sees everything the user has. There is no per-path scoping."
                .to_string(),
            root_credential: "a non-expiring Dropbox refresh token plus the app key \
                              and secret, at dropbox/config/{target}. It can mint \
                              access tokens for that authorisation indefinitely, so \
                              use one authorisation — and one config document — per \
                              consumer."
                .to_string(),
            paths: vec![
                PathDoc::new(
                    "dropbox/config/{target}",
                    &["POST", "GET", "DELETE"],
                    "sudo",
                    "register one consumer's app key, secret and refresh token. GET \
                     reports only whether it is configured — the secrets are never \
                     returned. DELETE is the first half of a real revocation.",
                ),
                PathDoc::new(
                    "dropbox/roles/{role}",
                    &["POST", "GET", "DELETE"],
                    "create / read / sudo",
                    "define which authorisation a consumer brokers from, the scope \
                     subset it gets, and any team member to act as",
                ),
                PathDoc::new(
                    "dropbox/creds/{role}",
                    &["GET"],
                    "read",
                    "exchange the stored refresh token for a four-hour access token \
                     and open a lease",
                ),
                PathDoc::new("dropbox/help", &["GET"], "authenticated", "this document"),
            ],
            docs_url: Some("docs/delegation/dropbox.md".to_string()),
            caveats: vec![
                "The four-hour TTL is fixed. Dropbox offers no way to shorten it, so \
                 a leaked token is a four-hour problem and the lease expiry cannot \
                 make it shorter."
                    .to_string(),
                "Revoking an access token also kills its refresh token and every \
                 other token from the same authorisation, so revocation requires a \
                 human to re-consent. That is why this engine never revokes \
                 automatically."
                    .to_string(),
                "App-folder versus Full Dropbox is chosen when the app is created and \
                 is immutable afterwards — changing it means a new app and re-linking \
                 every consumer. Choose App folder unless you are certain."
                    .to_string(),
                "There is no per-path scoping beyond App-folder mode. Narrowness comes \
                 from the app's access type and its scopes, not from anything a role \
                 can express."
                    .to_string(),
                "A team token plus a Dropbox-API-Select-User header can act as ANY \
                 team member: the header selects a target, it does not reduce what the \
                 token can reach. A team credential should stay in the server's own \
                 custody for administrative jobs, not be leased to consumers — give a \
                 consumer its own per-user authorisation instead."
                    .to_string(),
                "Dropbox does not rotate refresh tokens on use, so there is no \
                 write-back to design for — but equally nothing ages out on its own."
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
        STORE
            .handle_write::<DropboxConfig, RoleConfig>(storage, path, data)
            .await
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
        let config: DropboxConfig = STORE.require_config(storage, &role.target).await?;

        let mut form = vec![
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", config.refresh_token.clone()),
        ];
        // Dropbox accepts `scope` on the refresh grant to request a subset of
        // what was authorised. It can only narrow, so passing it is safe.
        if !role.scopes.is_empty() {
            form.push(("scope", role.scopes.join(" ")));
        }

        let now = Utc::now();
        let response = self
            .http
            .post(TOKEN_ENDPOINT)
            .header(
                reqwest::header::AUTHORIZATION,
                Self::basic_auth_header(&config.app_key, &config.app_secret),
            )
            .form(&form)
            .send()
            .await
            .map_err(|e| EngineError::Provider(format!("Dropbox request failed: {e}")))?;

        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(EngineError::Provider(format!(
                "Dropbox returned {status} for the refresh grant: {text}"
            )));
        }
        let token: TokenResponse = serde_json::from_str(&text)
            .map_err(|e| EngineError::Provider(format!("unexpected Dropbox response: {e}")))?;

        let expires_at = now + chrono::Duration::seconds(token.expires_in);
        let lease = Lease {
            id: Uuid::new_v4(),
            // Set by the HTTP handler, which knows the requesting token.
            token_id_hash: String::new(),
            engine_mount: MOUNT.to_string(),
            // The access token is deliberately NOT stored. Keeping it would put
            // a one-call, authorisation-destroying revocation within reach of
            // the reaper, and nothing here needs it: see `revoke` below.
            internal_data: json!({
                "role": role_name,
                "target": role.target,
                "access_token_stored": false,
            }),
            issued_at: now,
            // Dropbox's own figure rather than our constant, so the lease can
            // never outlive the credential if Dropbox ever changes it.
            expires_at,
        };

        let mut data = json!({
            "access_token": token.access_token,
            "expires_at": expires_at,
            "granted_scopes": token.scope,
        });
        // Surfaced so the consumer knows which header to send; without it a
        // team-scoped token acts as the team, not the intended member.
        if let Some(member) = &role.select_user {
            data["dropbox_api_select_user"] = json!(member);
        }
        if let Some(admin) = &role.select_admin {
            data["dropbox_api_select_admin"] = json!(admin);
        }

        Ok(GeneratedCredential::new(
            data,
            lease,
            Self::scope_description(&role),
        ))
    }

    async fn revoke(&self, _storage: &dyn StorageBackend, lease: &Lease) -> EngineResult<()> {
        // Intentionally a no-op. Dropbox revokes an access token and its
        // refresh token as a set, so calling the revoke endpoint here would
        // break the consumer's *next* request and need a human to re-consent —
        // a far worse outcome than letting a four-hour token lapse. Returning
        // Ok lets the reaper clean up the lease record, which is all it can
        // honestly do.
        tracing::warn!(
            lease_id = %lease.id,
            revoke_endpoint = REVOKE_ENDPOINT,
            "dropbox lease revoked locally only: the access token keeps working until \
             it expires. Revoking it at Dropbox would also destroy the refresh token \
             and require re-consent, so that is left to a deliberate operator action."
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role(scopes: &[&str], select_user: Option<&str>) -> RoleConfig {
        RoleConfig {
            target: "report-service".to_string(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            select_user: select_user.map(|s| s.to_string()),
            select_admin: None,
        }
    }

    #[test]
    fn basic_auth_header_encodes_key_and_secret() {
        let header = DropboxEngine::basic_auth_header("app-key", "app-secret");
        let encoded = header.strip_prefix("Basic ").expect("Basic prefix");
        let decoded = BASE64_STANDARD.decode(encoded).expect("valid base64");
        assert_eq!(String::from_utf8(decoded).unwrap(), "app-key:app-secret");
    }

    /// A colon in the secret must not shift the field boundary, which is the
    /// classic way a hand-built Basic header goes subtly wrong.
    #[test]
    fn basic_auth_header_keeps_the_first_colon_as_the_separator() {
        let header = DropboxEngine::basic_auth_header("key", "sec:ret");
        let encoded = header.strip_prefix("Basic ").unwrap();
        let decoded = String::from_utf8(BASE64_STANDARD.decode(encoded).unwrap()).unwrap();
        let (user, pass) = decoded.split_once(':').unwrap();
        assert_eq!(user, "key");
        assert_eq!(pass, "sec:ret");
    }

    #[test]
    fn scope_description_lists_requested_scopes() {
        let scoped = DropboxEngine::scope_description(&role(
            &["files.content.read", "files.metadata.read"],
            None,
        ));
        assert!(scoped.contains(&"scope:files.content.read".to_string()));
        assert!(scoped.contains(&"scope:files.metadata.read".to_string()));
        assert!(!scoped.iter().any(|s| s.contains("acting-as")));
    }

    /// An unscoped role is a footgun, so the `_doc` must say so rather than
    /// showing an empty list.
    #[test]
    fn scope_description_is_explicit_when_unscoped() {
        let scoped = DropboxEngine::scope_description(&role(&[], None));
        assert!(scoped.iter().any(|s| s.contains("scopes:ALL")));
    }

    /// The consumer must be told that Select-User picks a target rather than
    /// confining the token, because assuming otherwise understates the risk.
    #[test]
    fn scope_description_warns_that_select_user_does_not_narrow() {
        let scoped = DropboxEngine::scope_description(&role(&["files.content.read"], Some("dbmid:abc")));
        let acting = scoped
            .iter()
            .find(|s| s.starts_with("acting-as:"))
            .expect("select_user should be described");
        assert!(acting.contains("dbmid:abc"));
        assert!(acting.contains("does NOT reduce reach"));
    }

    #[test]
    fn select_admin_is_described_separately() {
        let mut r = role(&[], None);
        r.select_admin = Some("dbmid:admin".to_string());
        let scoped = DropboxEngine::scope_description(&r);
        assert!(scoped.iter().any(|s| s.starts_with("acting-as-admin:")));
    }

    #[test]
    fn ttl_is_documented_as_fixed_at_four_hours() {
        let doc = DropboxEngine::new().doc();
        assert!(doc.ttl.fixed, "Dropbox cannot shorten its token lifetime");
        assert_eq!(doc.ttl.min_seconds, Some(ACCESS_TOKEN_TTL_SECONDS));
        assert_eq!(doc.ttl.max_seconds, Some(ACCESS_TOKEN_TTL_SECONDS));
    }

    #[test]
    fn doc_agrees_with_its_shape() {
        let doc = DropboxEngine::new().doc();
        assert_eq!(doc.shape, CredentialShape::RefreshBroker);
        assert_eq!(doc.revocable, doc.shape.revocable());
    }

    /// The whole point of this engine is that the reaper must not call
    /// Dropbox's revoke endpoint, so the documented effect has to say so.
    #[test]
    fn revoke_effect_warns_that_revocation_is_manual_and_destructive() {
        let doc = DropboxEngine::new().doc();
        assert!(doc.revoke_effect.contains("refresh token"));
        assert!(doc.revoke_effect.contains("re-consent"));
    }

    #[test]
    fn token_response_parses_a_dropbox_payload() {
        let token: TokenResponse = serde_json::from_str(
            r#"{"access_token":"sl.abc","token_type":"bearer","expires_in":14400,
                "scope":"files.content.read"}"#,
        )
        .expect("should parse");
        assert_eq!(token.access_token, "sl.abc");
        assert_eq!(token.expires_in, 14400);
        assert_eq!(token.scope.as_deref(), Some("files.content.read"));
    }

    /// `scope` is absent unless the grant was downscoped, so its absence must
    /// not fail the exchange.
    #[test]
    fn token_response_parses_without_a_scope_field() {
        let token: TokenResponse =
            serde_json::from_str(r#"{"access_token":"sl.x","token_type":"bearer","expires_in":14400}"#)
                .expect("should parse");
        assert!(token.scope.is_none());
    }
}
