//! Google Workspace and Drive — nothing here is mintable, so this engine's
//! value is *custody*: the long-lived refresh token stays on the server and
//! consumers only ever receive an access token good for about an hour. The
//! consumer never holds the durable secret, which is most of the benefit.
//!
//! Domain-wide delegation is offered as a second mode, but it is a materially
//! worse trade — see the caveats in `doc()` — and Google's own guidance is now
//! to avoid it for new integrations.
//!
//! See `docs/delegation/google-workspace.md` for the mechanism and
//! `docs/delegation/setup/google-workspace.md` for the operator walkthrough.

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

const STORE: ConfigRoleStore = ConfigRoleStore::new("gworkspace/config/", "gworkspace/roles/");
const MOUNT: &str = "gworkspace/creds/";
const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const REVOKE_ENDPOINT: &str = "https://oauth2.googleapis.com/revoke";
const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// Google accepts a delegation assertion with `exp` up to an hour out, but the
/// assertion is exchanged immediately — a short window limits the damage if one
/// ever reaches a log.
const ASSERTION_TTL_SECONDS: i64 = 600;

/// Google's access tokens are ~1 hour and it tells us so in `expires_in`; this
/// is only the fallback for a response that omits it.
const FALLBACK_ACCESS_TOKEN_TTL_SECONDS: i64 = 3600;

/// One authorised account. Every field here is durable secret material, which
/// is why `ConfigRoleStore` makes config write-only: a read reports existence
/// and nothing else.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GworkspaceConfig {
    /// OAuth client credentials from the Google Cloud console. Required for
    /// `refresh_token` mode, unused by domain-wide delegation.
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
    /// The long-lived half, obtained once through an interactive consent flow.
    /// This is the secret consumers must never see.
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Service-account key JSON, for domain-wide delegation only.
    #[serde(default)]
    pub service_account_key_json: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Broker an access token from a stored refresh token. The recommended mode.
    #[default]
    RefreshToken,
    /// Impersonate a named user with a service account the domain admin has
    /// authorised. Convenient, and far more dangerous.
    DomainWideDelegation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleConfig {
    /// Which `gworkspace/config/{name}` document to authenticate with.
    pub target: String,
    #[serde(default)]
    pub mode: Mode,
    /// OAuth scopes, e.g. `https://www.googleapis.com/auth/drive.readonly`.
    /// Prefer the narrowest scope that works: this is the only scoping Google
    /// offers at the credential level.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// The user to impersonate. Required for `domain_wide_delegation`,
    /// meaningless otherwise.
    #[serde(default)]
    pub subject: Option<String>,
}

/// The fields we need out of a service-account key file.
#[derive(Debug, Deserialize)]
struct ServiceAccountKey {
    client_email: String,
    private_key: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<i64>,
    /// Google does not rotate refresh tokens on every use, but it may reissue
    /// one near end of life. Dropping it silently would strand the account.
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct AssertionClaims {
    iss: String,
    sub: String,
    scope: String,
    aud: String,
    iat: i64,
    exp: i64,
}

#[derive(Default)]
pub struct GworkspaceEngine {
    http: reqwest::Client,
}

impl GworkspaceEngine {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::new(),
        }
    }

    fn require_refresh_token(config: &GworkspaceConfig) -> EngineResult<&str> {
        config.refresh_token.as_deref().filter(|t| !t.is_empty()).ok_or_else(|| {
            EngineError::InvalidRequest(
                "this gworkspace/config has no refresh_token. Complete the consent \
                 flow once and POST the resulting refresh token to the config path."
                    .into(),
            )
        })
    }

    fn service_account(config: &GworkspaceConfig) -> EngineResult<ServiceAccountKey> {
        let raw = config
            .service_account_key_json
            .as_deref()
            .filter(|k| !k.is_empty())
            .ok_or_else(|| {
                EngineError::InvalidRequest(
                    "domain_wide_delegation needs service_account_key_json in \
                     gworkspace/config"
                        .into(),
                )
            })?;
        serde_json::from_str(raw).map_err(|e| {
            EngineError::InvalidRequest(format!("service_account_key_json is not a valid key: {e}"))
        })
    }

    /// Builds the delegation assertion's claims. The `sub` claim is what turns a
    /// service-account token into "act as this user", so an unset subject would
    /// silently produce a credential for the service account itself rather than
    /// the intended person — refuse instead.
    fn assertion_claims(
        service_account_email: &str,
        role: &RoleConfig,
        now: DateTime<Utc>,
    ) -> EngineResult<AssertionClaims> {
        let subject = role.subject.as_deref().filter(|s| !s.is_empty()).ok_or_else(|| {
            EngineError::InvalidRequest(
                "domain_wide_delegation requires `subject`: the email address of the \
                 user to impersonate"
                    .into(),
            )
        })?;
        Ok(AssertionClaims {
            iss: service_account_email.to_string(),
            sub: subject.to_string(),
            scope: role.scopes.join(" "),
            aud: TOKEN_ENDPOINT.to_string(),
            iat: now.timestamp(),
            exp: now.timestamp() + ASSERTION_TTL_SECONDS,
        })
    }

    fn sign_assertion(key: &ServiceAccountKey, claims: &AssertionClaims) -> EngineResult<String> {
        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(key.private_key.as_bytes())
            .map_err(|e| {
                EngineError::InvalidRequest(format!(
                    "service account private_key is not a valid RSA PEM: {e}"
                ))
            })?;
        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
            claims,
            &encoding_key,
        )
        .map_err(|e| EngineError::Other(format!("failed to sign delegation assertion: {e}")))
    }

    async fn post_token_form(&self, form: &[(&str, &str)]) -> EngineResult<TokenResponse> {
        let response = self
            .http
            .post(TOKEN_ENDPOINT)
            .form(form)
            .send()
            .await
            .map_err(|e| EngineError::Provider(format!("Google token request failed: {e}")))?;

        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            // `invalid_grant` is terminal, not transient: the authorisation is
            // gone and a human has to consent again. Callers that retry it will
            // retry forever, so name it in the error.
            if text.contains("invalid_grant") {
                return Err(EngineError::Provider(format!(
                    "Google returned invalid_grant — the authorisation is gone \
                     (revoked, expired, or the consent screen is still in Testing). \
                     Re-consent is required; retrying will not help. Body: {text}"
                )));
            }
            return Err(EngineError::Provider(format!(
                "Google returned {status}: {text}"
            )));
        }
        serde_json::from_str(&text)
            .map_err(|e| EngineError::Provider(format!("unexpected Google response: {e}")))
    }

    fn scope_description(role: &RoleConfig) -> Vec<String> {
        let mut scoped = Vec::new();
        match role.mode {
            Mode::RefreshToken => {
                scoped.push("identity:the user who granted consent".to_string());
            }
            Mode::DomainWideDelegation => scoped.push(format!(
                "identity:{} (impersonated via domain-wide delegation)",
                role.subject.as_deref().unwrap_or("UNSET")
            )),
        }
        if role.scopes.is_empty() {
            scoped.push("scopes:NONE — Google will reject the exchange".to_string());
        } else {
            scoped.extend(role.scopes.iter().map(|s| format!("scope:{s}")));
        }
        scoped
    }

    /// Persists a reissued refresh token. Uses the store's own write path so the
    /// document stays in the same shape the operator POSTed.
    async fn persist_rotated_refresh_token(
        storage: &dyn StorageBackend,
        target: &str,
        config: &GworkspaceConfig,
        new_refresh_token: &str,
    ) -> EngineResult<()> {
        let mut updated = config.clone();
        updated.refresh_token = Some(new_refresh_token.to_string());
        let value = serde_json::to_value(&updated).map_err(|e| EngineError::Other(e.to_string()))?;
        STORE
            .handle_write::<GworkspaceConfig, RoleConfig>(
                storage,
                &format!("config/{target}"),
                value,
            )
            .await
    }
}

#[async_trait]
impl SecretsEngine for GworkspaceEngine {
    fn doc(&self) -> EngineDoc {
        EngineDoc {
            provider: "Google Workspace".to_string(),
            mechanism: "brokered OAuth access tokens: the server holds the \
                        long-lived refresh token and exchanges it for a ~1 hour \
                        access token per request, so the consumer never sees the \
                        durable secret. Domain-wide delegation is available as a \
                        second mode."
                .to_string(),
            shape: CredentialShape::RefreshBroker,
            // Deliberately contradicts `shape.revocable()`. Shape C means the
            // *durable* half is revocable, which is true here — but unlike
            // Dropbox, revoking Google's refresh token does nothing to an access
            // token already issued. The field that a consumer reads must
            // describe the credential it was actually handed.
            revocable: false,
            revoke_effect: "nothing at the provider. Google cannot invalidate an \
                            individual access token, so a revoked lease only \
                            deletes our record and stops renewal — the token keeps \
                            working for the rest of its hour. We deliberately do \
                            NOT call Google's /revoke on lease expiry: that would \
                            destroy the whole authorisation and require a human to \
                            re-consent. To do that on purpose, DELETE the config \
                            document and POST the refresh token to \
                            https://oauth2.googleapis.com/revoke."
                .to_string(),
            ttl: TtlDoc::range(
                600,
                3600,
                "Google decides, and reports it in expires_in — about an hour in \
                 practice. The lease is set from that value rather than from a \
                 requested TTL, so it can never outlive the token.",
            ),
            scoping: "OAuth scopes only, chosen per role. There is no per-file or \
                      per-folder scoping in the credential: narrowness comes from \
                      picking drive.readonly or drive.metadata.readonly over drive, \
                      and from Drive ACLs on the content itself."
                .to_string(),
            root_credential: "a refresh token per authorised account (refresh_token \
                              mode), or a service-account key authorised for \
                              domain-wide delegation. Both live at \
                              gworkspace/config/{target} and are never readable back."
                .to_string(),
            paths: vec![
                PathDoc::new(
                    "gworkspace/config/{target}",
                    &["POST", "GET", "DELETE"],
                    "sudo",
                    "register one account's OAuth client, refresh token or \
                     service-account key. GET reports only whether it is \
                     configured — no secret is ever returned.",
                ),
                PathDoc::new(
                    "gworkspace/roles/{role}",
                    &["POST", "GET", "DELETE"],
                    "create / read / sudo",
                    "define one consumer's mode, scopes and impersonated subject",
                ),
                PathDoc::new(
                    "gworkspace/creds/{role}",
                    &["GET"],
                    "read",
                    "exchange the stored grant for a short-lived access token and \
                     open a lease",
                ),
                PathDoc::new("gworkspace/help", &["GET"], "authenticated", "this document"),
            ],
            docs_url: Some("docs/delegation/google-workspace.md".to_string()),
            caveats: vec![
                "A refresh token expires after SEVEN DAYS while the OAuth consent \
                 screen's publishing status is still 'Testing'. This catches almost \
                 everyone once — publish the app."
                    .to_string(),
                "Refresh tokens also die after six months of non-use, when the user \
                 revokes access, and in some cases on password change."
                    .to_string(),
                "`invalid_grant` on refresh means the authorisation is gone and a \
                 human must re-consent. It is never a transient error, so never \
                 retry it as one."
                    .to_string(),
                "Domain-wide delegation lets one service account impersonate ANY \
                 user in the domain for the granted scopes, with no user able to \
                 see or revoke it. Google's own guidance is to avoid it for new \
                 integrations — prefer per-user consent, i.e. refresh_token mode."
                    .to_string(),
                "Shared drives are governed by ACL membership, not by scopes: the \
                 consenting user or impersonated subject must be an explicit member \
                 of the shared drive, and queries need corpora=drive with driveId."
                    .to_string(),
                "Restricted Gmail and Drive scopes require app verification, and the \
                 most sensitive ones a third-party security assessment."
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
            .handle_write::<GworkspaceConfig, RoleConfig>(storage, path, data)
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
        let config: GworkspaceConfig = STORE.require_config(storage, &role.target).await?;

        let now = Utc::now();
        let token = match role.mode {
            Mode::RefreshToken => {
                let refresh_token = Self::require_refresh_token(&config)?;
                self.post_token_form(&[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", refresh_token),
                    ("client_id", &config.client_id),
                    ("client_secret", &config.client_secret),
                ])
                .await?
            }
            Mode::DomainWideDelegation => {
                let key = Self::service_account(&config)?;
                let claims = Self::assertion_claims(&key.client_email, &role, now)?;
                let assertion = Self::sign_assertion(&key, &claims)?;
                self.post_token_form(&[
                    ("grant_type", JWT_BEARER_GRANT),
                    ("assertion", &assertion),
                ])
                .await?
            }
        };

        if let Some(rotated) = token.refresh_token.as_deref()
            && Some(rotated) != config.refresh_token.as_deref()
        {
            Self::persist_rotated_refresh_token(storage, &role.target, &config, rotated).await?;
            tracing::info!(target = %role.target, "stored a reissued Google refresh token");
        }

        let ttl_seconds = token.expires_in.unwrap_or(FALLBACK_ACCESS_TOKEN_TTL_SECONDS);
        let lease = Lease {
            id: Uuid::new_v4(),
            // Set by the HTTP handler, which knows the requesting token.
            token_id_hash: String::new(),
            engine_mount: MOUNT.to_string(),
            // The access token is deliberately absent: it cannot be revoked, so
            // keeping a copy would widen exposure for no operational gain.
            internal_data: json!({
                "role": role_name,
                "target": role.target,
                "mode": role.mode,
            }),
            issued_at: now,
            expires_at: now + chrono::Duration::seconds(ttl_seconds),
        };

        let credential = GeneratedCredential::new(
            json!({
                "access_token": token.access_token,
                "token_type": "Bearer",
                "expires_in": ttl_seconds,
                "granted_scope": token.scope,
            }),
            lease,
            Self::scope_description(&role),
        );

        Ok(match role.mode {
            // Nothing durable is brokered here — the service-account key is the
            // secret, and it can reach every user in the domain.
            Mode::DomainWideDelegation => credential.with_shape(
                CredentialShape::MintExpiryOnly,
                "nothing. This token was minted by impersonating a user through \
                 domain-wide delegation, and Google cannot invalidate it. It stops \
                 working when it expires. To cut off delegation entirely, remove \
                 the service account's client ID from the Admin console.",
            ),
            Mode::RefreshToken => credential,
        })
    }

    async fn revoke(&self, _storage: &dyn StorageBackend, lease: &Lease) -> EngineResult<()> {
        // A deliberate refusal, not an omission. Google offers no way to kill a
        // single access token, and the one endpoint that does work
        // (REVOKE_ENDPOINT, on the refresh token) would destroy the entire
        // authorisation and require a human to re-consent — a catastrophic
        // response to a lease simply reaching its expiry. Returning Ok lets the
        // reaper clear its record, which is all that is actually possible.
        tracing::warn!(
            lease = %lease.id,
            "gworkspace lease revoked locally only: Google cannot invalidate an \
             issued access token, so it remains valid until it expires. To revoke \
             the underlying authorisation on purpose, DELETE the config document \
             and POST its refresh token to {REVOKE_ENDPOINT}"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role(mode: Mode, subject: Option<&str>, scopes: &[&str]) -> RoleConfig {
        RoleConfig {
            target: "acme".to_string(),
            mode,
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            subject: subject.map(|s| s.to_string()),
        }
    }

    #[test]
    fn assertion_claims_impersonate_the_subject() {
        let now = Utc::now();
        let claims = GworkspaceEngine::assertion_claims(
            "svc@acme.iam.gserviceaccount.com",
            &role(
                Mode::DomainWideDelegation,
                Some("alice@acme.com"),
                &["https://www.googleapis.com/auth/drive.readonly"],
            ),
            now,
        )
        .expect("claims");

        assert_eq!(claims.iss, "svc@acme.iam.gserviceaccount.com");
        // `sub` is the whole point of delegation — it is what makes the token
        // act as the user rather than as the service account.
        assert_eq!(claims.sub, "alice@acme.com");
        assert_eq!(claims.aud, TOKEN_ENDPOINT);
        assert_eq!(claims.scope, "https://www.googleapis.com/auth/drive.readonly");
        assert!(claims.exp - claims.iat <= 3600, "Google caps the assertion at one hour");
    }

    #[test]
    fn assertion_claims_join_multiple_scopes_with_spaces() {
        let claims = GworkspaceEngine::assertion_claims(
            "svc@acme.iam.gserviceaccount.com",
            &role(Mode::DomainWideDelegation, Some("alice@acme.com"), &["a", "b"]),
            Utc::now(),
        )
        .expect("claims");
        assert_eq!(claims.scope, "a b");
    }

    /// Without `sub` the exchange would quietly yield a token for the service
    /// account itself, which is a different and broader identity than intended.
    #[test]
    fn domain_wide_delegation_requires_a_subject() {
        for subject in [None, Some("")] {
            let err = GworkspaceEngine::assertion_claims(
                "svc@acme.iam.gserviceaccount.com",
                &role(Mode::DomainWideDelegation, subject, &["a"]),
                Utc::now(),
            )
            .expect_err("a missing subject must be refused");
            assert!(matches!(err, EngineError::InvalidRequest(_)), "got {err:?}");
            assert!(err.to_string().contains("subject"));
        }
    }

    #[test]
    fn domain_wide_delegation_requires_a_service_account_key() {
        let config = GworkspaceConfig {
            client_id: String::new(),
            client_secret: String::new(),
            refresh_token: None,
            service_account_key_json: None,
        };
        let err = GworkspaceEngine::service_account(&config).expect_err("must be refused");
        assert!(matches!(err, EngineError::InvalidRequest(_)), "got {err:?}");
    }

    #[test]
    fn refresh_token_mode_requires_a_stored_refresh_token() {
        for stored in [None, Some(String::new())] {
            let config = GworkspaceConfig {
                client_id: "id".to_string(),
                client_secret: "secret".to_string(),
                refresh_token: stored,
                service_account_key_json: None,
            };
            let err = GworkspaceEngine::require_refresh_token(&config)
                .expect_err("must be refused");
            assert!(matches!(err, EngineError::InvalidRequest(_)), "got {err:?}");
        }
    }

    #[test]
    fn rejects_a_service_account_key_that_is_not_a_pem() {
        let key = ServiceAccountKey {
            client_email: "svc@acme.iam.gserviceaccount.com".to_string(),
            private_key: "not a pem".to_string(),
        };
        let claims = GworkspaceEngine::assertion_claims(
            &key.client_email,
            &role(Mode::DomainWideDelegation, Some("alice@acme.com"), &["a"]),
            Utc::now(),
        )
        .expect("claims");
        let err = GworkspaceEngine::sign_assertion(&key, &claims).expect_err("must be refused");
        assert!(matches!(err, EngineError::InvalidRequest(_)), "got {err:?}");
    }

    #[test]
    fn scope_description_names_the_impersonated_user() {
        let scoped = GworkspaceEngine::scope_description(&role(
            Mode::DomainWideDelegation,
            Some("alice@acme.com"),
            &["https://www.googleapis.com/auth/drive.readonly"],
        ));
        assert!(scoped.iter().any(|s| s.contains("alice@acme.com")));
        assert!(
            scoped.contains(&"scope:https://www.googleapis.com/auth/drive.readonly".to_string())
        );
    }

    #[test]
    fn scope_description_flags_a_role_with_no_scopes() {
        let scoped = GworkspaceEngine::scope_description(&role(Mode::RefreshToken, None, &[]));
        assert!(scoped.iter().any(|s| s.contains("scopes:NONE")));
    }

    #[test]
    fn mode_defaults_to_the_safer_refresh_token_flow() {
        let role: RoleConfig =
            serde_json::from_value(json!({ "target": "acme" })).expect("minimal role");
        assert_eq!(role.mode, Mode::RefreshToken);
    }

    /// The headline shape is C, and an issued Google access token cannot be
    /// recalled — so `revocable` is false and must agree with the shape, which
    /// answers the narrow question "does revoking the lease kill what the
    /// consumer holds?".
    #[test]
    fn doc_reports_the_truth_about_revocation() {
        let doc = GworkspaceEngine::new().doc();
        assert_eq!(doc.shape, CredentialShape::RefreshBroker);
        assert!(!doc.revocable);
        assert!(!doc.shape.revocable());
        assert!(doc.revoke_effect.contains("nothing at the provider"));
    }
}
