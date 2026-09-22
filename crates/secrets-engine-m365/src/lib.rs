//! Microsoft 365 / Graph app-only access tokens.
//!
//! Microsoft is the provider that can be operated with **no stored secret at
//! all** — a federated identity credential on the app registration lets a
//! workload's own OIDC token stand in for a client secret. It is also a
//! provider whose issued tokens **cannot be revoked**, so the containment
//! story is entirely TTL plus resource-level scoping.
//!
//! See `docs/delegation/microsoft-365.md` for the mechanism and
//! `docs/delegation/setup/microsoft-365.md` for the operator walkthrough.

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

const STORE: ConfigRoleStore = ConfigRoleStore::new("m365/config/", "m365/roles/");
const MOUNT: &str = "m365/creds/";
const DEFAULT_AUTHORITY: &str = "https://login.microsoftonline.com";
const DEFAULT_SCOPE: &str = "https://graph.microsoft.com/.default";
const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Our own client assertion only has to survive one token request, so it gets
/// the shortest life that tolerates clock skew. A long-lived assertion is a
/// bearer credential for the whole app registration.
const CLIENT_ASSERTION_TTL_SECONDS: i64 = 300;

/// Configurable Token Lifetime's floor. Quoted in `doc()` because with
/// revocation unavailable, shortening the token is the only real control.
const MIN_CONFIGURABLE_TTL_SECONDS: i64 = 600;
/// Configurable Token Lifetime's ceiling, 23:59:59.
const MAX_CONFIGURABLE_TTL_SECONDS: i64 = 86_399;

/// How the server proves it is the app registration.
///
/// `Federated` is the one to reach for: the assertion is the workload's own
/// platform-issued identity token, so there is no durable secret to store,
/// rotate or leak.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CredentialKind {
    /// The ordinary confidential-client secret. Expires, and must be rotated
    /// by hand.
    Secret { client_secret: String },
    /// A certificate credential: we sign the assertion ourselves, so the key
    /// never crosses the wire. `x5t_s256` is the certificate's base64url
    /// SHA-256 thumbprint, which Entra uses to pick the registered public key.
    Certificate {
        private_key_pem: String,
        x5t_s256: String,
    },
    /// Workload identity federation. `token_file` is where the platform
    /// projects the workload's OIDC token — on Kubernetes this is the path
    /// `AZURE_FEDERATED_TOKEN_FILE` points at.
    Federated { token_file: String },
}

impl CredentialKind {
    /// What the server had to be trusted with, for the `_doc` block and for
    /// `root_credential`.
    fn describes_root_credential(&self) -> &'static str {
        match self {
            Self::Secret { .. } => "a client secret",
            Self::Certificate { .. } => "a certificate private key",
            Self::Federated { .. } => "nothing — the workload's own OIDC token",
        }
    }
}

/// The app registration this engine authenticates as.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct M365Config {
    pub tenant_id: String,
    pub client_id: String,
    pub credential: CredentialKind,
    /// Override for the sovereign clouds, which use their own login hosts.
    #[serde(default = "default_authority")]
    pub authority: String,
}

fn default_authority() -> String {
    DEFAULT_AUTHORITY.to_string()
}

fn default_scope() -> String {
    DEFAULT_SCOPE.to_string()
}

/// What one consumer may mint.
///
/// There is deliberately no TTL setting: Entra decides the lifetime, and the
/// only way to shorten it is a tenant-side Configurable Token Lifetime policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleConfig {
    /// Which `m365/config/{name}` document to authenticate with.
    pub target: String,
    /// Practically always `…/.default`: client credentials cannot request a
    /// subset of the app's permissions.
    #[serde(default = "default_scope")]
    pub scope: String,
    /// Free-text note about which resource the operator narrowed this app to
    /// (a mail security group, a `Sites.Selected` site, a Team). Entra does not
    /// report the narrowing back to us, so recording it here is the only way
    /// the `_doc` block can tell a consumer what it really got.
    #[serde(default)]
    pub resource_hint: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: i64,
    #[serde(default)]
    token_type: Option<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct ClientAssertionClaims {
    /// Must be the exact token endpoint being called, or Entra rejects it.
    aud: String,
    iss: String,
    sub: String,
    jti: String,
    iat: i64,
    nbf: i64,
    exp: i64,
}

#[derive(Default)]
pub struct M365Engine {
    http: reqwest::Client,
}

impl M365Engine {
    pub fn new() -> Self {
        Self::default()
    }

    fn token_endpoint(config: &M365Config) -> String {
        format!(
            "{}/{}/oauth2/v2.0/token",
            config.authority.trim_end_matches('/'),
            config.tenant_id
        )
    }

    fn assertion_claims(
        client_id: &str,
        token_endpoint: &str,
        now: DateTime<Utc>,
    ) -> ClientAssertionClaims {
        ClientAssertionClaims {
            aud: token_endpoint.to_string(),
            // Entra requires the app to be both issuer and subject of its own
            // assertion.
            iss: client_id.to_string(),
            sub: client_id.to_string(),
            jti: Uuid::new_v4().to_string(),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            exp: now.timestamp() + CLIENT_ASSERTION_TTL_SECONDS,
        }
    }

    /// The thumbprint goes in the header rather than the claims: it is how
    /// Entra selects which registered public key to verify against.
    fn assertion_header(x5t_s256: &str) -> jsonwebtoken::Header {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.x5t_s256 = Some(x5t_s256.to_string());
        header
    }

    fn client_assertion(
        client_id: &str,
        private_key_pem: &str,
        x5t_s256: &str,
        token_endpoint: &str,
        now: DateTime<Utc>,
    ) -> EngineResult<String> {
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).map_err(|e| {
            EngineError::InvalidRequest(format!(
                "m365/config credential.private_key_pem is not a valid RSA PEM: {e}"
            ))
        })?;
        jsonwebtoken::encode(
            &Self::assertion_header(x5t_s256),
            &Self::assertion_claims(client_id, token_endpoint, now),
            &key,
        )
        .map_err(|e| EngineError::Other(format!("failed to sign the client assertion: {e}")))
    }

    /// Read at every mint rather than cached: the platform rotates this file
    /// on its own schedule, and a stale token is rejected.
    fn read_federated_token(token_file: &str) -> EngineResult<String> {
        let raw = std::fs::read_to_string(token_file).map_err(|e| {
            EngineError::InvalidRequest(format!(
                "cannot read the federated token file '{token_file}': {e}. On Kubernetes \
                 this is the path AZURE_FEDERATED_TOKEN_FILE points at, and it must be \
                 projected into this server's own pod."
            ))
        })?;
        let token = raw.trim().to_string();
        if token.is_empty() {
            return Err(EngineError::InvalidRequest(format!(
                "the federated token file '{token_file}' is empty"
            )));
        }
        Ok(token)
    }

    async fn request_access_token(
        &self,
        config: &M365Config,
        scope: &str,
        now: DateTime<Utc>,
    ) -> EngineResult<TokenResponse> {
        let endpoint = Self::token_endpoint(config);
        let mut form: Vec<(&str, String)> = vec![
            ("grant_type", "client_credentials".to_string()),
            ("client_id", config.client_id.clone()),
            ("scope", scope.to_string()),
        ];

        match &config.credential {
            CredentialKind::Secret { client_secret } => {
                form.push(("client_secret", client_secret.clone()));
            }
            CredentialKind::Certificate {
                private_key_pem,
                x5t_s256,
            } => {
                let assertion = Self::client_assertion(
                    &config.client_id,
                    private_key_pem,
                    x5t_s256,
                    &endpoint,
                    now,
                )?;
                form.push(("client_assertion_type", CLIENT_ASSERTION_TYPE.to_string()));
                form.push(("client_assertion", assertion));
            }
            CredentialKind::Federated { token_file } => {
                let assertion = Self::read_federated_token(token_file)?;
                form.push(("client_assertion_type", CLIENT_ASSERTION_TYPE.to_string()));
                form.push(("client_assertion", assertion));
            }
        }

        let response = self
            .http
            .post(&endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|e| EngineError::Provider(format!("Entra ID request failed: {e}")))?;

        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            // Entra's error_description is the only place it says *why* — most
            // often that nobody granted admin consent.
            return Err(EngineError::Provider(format!(
                "Entra ID returned {status} for {endpoint}: {text}"
            )));
        }
        serde_json::from_str(&text)
            .map_err(|e| EngineError::Provider(format!("unexpected Entra ID response: {e}")))
    }

    fn scope_description(role: &RoleConfig, config: &M365Config) -> Vec<String> {
        let mut scoped = vec![
            format!("tenant:{}", config.tenant_id),
            format!("app:{}", config.client_id),
            format!("scope:{}", role.scope),
        ];
        if role.scope.ends_with("/.default") {
            // Saying this out loud matters: a consumer could otherwise read
            // "scope: Graph" and assume it was narrowed when it was not.
            scoped.push(
                "permissions:ALL application permissions consented to this app — \
                 .default cannot request a subset, so the app registration is the \
                 only boundary the token itself carries"
                    .to_string(),
            );
        }
        match &role.resource_hint {
            Some(hint) => scoped.push(format!("resource-narrowing:{hint}")),
            None => scoped.push(
                "resource-narrowing:NONE RECORDED — app-only Graph permissions are \
                 tenant-wide unless an admin narrowed them"
                    .to_string(),
            ),
        }
        scoped
    }
}

#[async_trait]
impl SecretsEngine for M365Engine {
    fn doc(&self) -> EngineDoc {
        EngineDoc {
            provider: "Microsoft 365 (Microsoft Graph)".to_string(),
            mechanism: "app-only OAuth 2 client-credentials access tokens from Entra \
                        ID, authenticated with a client secret, a certificate \
                        assertion, or — with no stored secret — a federated identity \
                        credential"
                .to_string(),
            shape: CredentialShape::MintExpiryOnly,
            revocable: false,
            revoke_effect: "nothing at the provider. No Microsoft API revokes an \
                            issued Graph access token, so revoking a lease only \
                            deletes our record of it and stops renewal — the token \
                            keeps working until it expires. revokeSignInSessions \
                            invalidates refresh tokens and future issuance, not live \
                            access tokens, and Continuous Access Evaluation is the \
                            only near-real-time path: it needs both the resource and \
                            the client to be CAE-capable, and reacts only to critical \
                            events such as the identity being disabled."
                .to_string(),
            ttl: TtlDoc::range(
                MIN_CONFIGURABLE_TTL_SECONDS,
                MAX_CONFIGURABLE_TTL_SECONDS,
                "Entra decides, and randomises the default between 60 and 90 minutes, \
                 so the lease is set from the returned expires_in rather than any \
                 figure we choose. A tenant-side Configurable Token Lifetime policy \
                 can pin it between 10 minutes and 23:59:59; 10 minutes is the \
                 defensible choice here precisely because revocation is unavailable.",
            ),
            scoping: "not in the token. Client credentials can only ask for \
                      …/.default, which carries every application permission the app \
                      has been granted, so narrowing has to happen at the resource: \
                      an Exchange Application Access Policy for mail, Sites.Selected \
                      for SharePoint and OneDrive, resource-specific consent for \
                      Teams. Record what you did in the role's resource_hint, since \
                      Entra does not report it back to us."
                .to_string(),
            root_credential: "depends on m365/config/{target}.credential: a client \
                              secret or a certificate private key — or, with the \
                              federated variant, nothing at all. Prefer federated: \
                              the assertion is this server's own platform-issued OIDC \
                              token, so there is no durable secret to store, rotate \
                              or leak, and only the trust configuration on the app \
                              registration is durable."
                .to_string(),
            paths: vec![
                PathDoc::new(
                    "m365/config/{target}",
                    &["POST", "GET", "DELETE"],
                    "sudo",
                    "register the tenant, client id and credential. GET reports only \
                     whether it is configured — the credential is never returned.",
                ),
                PathDoc::new(
                    "m365/roles/{role}",
                    &["POST", "GET", "DELETE"],
                    "create / read / sudo",
                    "define one consumer's target, scope and recorded resource narrowing",
                ),
                PathDoc::new(
                    "m365/creds/{role}",
                    &["GET"],
                    "read",
                    "mint a Graph access token and open a lease",
                ),
                PathDoc::new("m365/help", &["GET"], "authenticated", "this document"),
            ],
            docs_url: Some("docs/delegation/microsoft-365.md".to_string()),
            caveats: vec![
                "…/.default is the only usable scope for client credentials, so the \
                 app registration IS the scope boundary — you cannot ask for less at \
                 request time, and a consumer receives everything the app was \
                 consented."
                    .to_string(),
                "App-only Graph permissions are tenant-wide by default. Mail is \
                 narrowed with an Exchange Application Access Policy, whose \
                 propagation can exceed an hour; SharePoint and OneDrive with \
                 Sites.Selected, which grants zero sites until an admin grants \
                 per-site roles — though the Graph Search API queries a tenant-wide \
                 index and bypasses it; Teams with resource-specific consent."
                    .to_string(),
                "Because no issued token can be revoked, a Configurable Token \
                 Lifetime policy is the real containment control. Its minimum is 10 \
                 minutes."
                    .to_string(),
                "CAE-eligible tokens live 24–28 hours, far longer than the 60–90 \
                 minute headline, precisely because they can be re-evaluated. Do not \
                 assume the short figure holds everywhere."
                    .to_string(),
                "The federated variant removes the stored secret but does not make \
                 this shape E: the consumer still receives a bearer token from us. \
                 True federation means the consumer exchanging its own identity \
                 directly — see the federation mount."
                    .to_string(),
                "Admin consent is required for application permissions, and a missing \
                 consent surfaces as an opaque authorisation failure rather than \
                 anything that says 'nobody clicked approve'."
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
        STORE.handle_write::<M365Config, RoleConfig>(storage, path, data).await
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
        let config: M365Config = STORE.require_config(storage, &role.target).await?;

        let now = Utc::now();
        let token = self.request_access_token(&config, &role.scope, now).await?;

        let lease = Lease {
            id: Uuid::new_v4(),
            // Set by the HTTP handler, which knows the requesting token.
            token_id_hash: String::new(),
            engine_mount: MOUNT.to_string(),
            // Nothing here is needed to revoke, because nothing can be revoked.
            // These fields exist so an operator reading a lease can tell which
            // app minted it.
            internal_data: json!({
                "role": role_name,
                "tenant_id": config.tenant_id,
                "client_id": config.client_id,
                "credential_type": config.credential.describes_root_credential(),
            }),
            issued_at: now,
            // Entra's own lifetime, never a figure of ours: the default is
            // randomised, so computing it locally would drift.
            expires_at: now + chrono::Duration::seconds(token.expires_in),
        };

        Ok(GeneratedCredential::new(
            json!({
                "access_token": token.access_token,
                "token_type": token.token_type.unwrap_or_else(|| "Bearer".to_string()),
                "expires_in": token.expires_in,
            }),
            lease,
            Self::scope_description(&role, &config),
        ))
    }

    async fn revoke(&self, _storage: &dyn StorageBackend, lease: &Lease) -> EngineResult<()> {
        // Returning Ok is not a claim of success — it lets the reaper clear the
        // lease record, which is the only thing that can actually be cleared.
        // There is no Microsoft API that invalidates an issued access token.
        tracing::warn!(
            lease_id = %lease.id,
            expires_at = %lease.expires_at,
            "m365 lease revoked locally only: Microsoft cannot invalidate an issued \
             Graph access token, so it remains usable until it expires"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(credential: CredentialKind) -> M365Config {
        M365Config {
            tenant_id: "00000000-0000-0000-0000-0000000000aa".to_string(),
            client_id: "11111111-1111-1111-1111-1111111111bb".to_string(),
            credential,
            authority: default_authority(),
        }
    }

    fn role() -> RoleConfig {
        RoleConfig {
            target: "acme".to_string(),
            scope: default_scope(),
            resource_hint: None,
        }
    }

    #[test]
    fn credential_kinds_round_trip_with_a_type_tag() {
        let cases = [
            (
                CredentialKind::Secret {
                    client_secret: "s3cret".to_string(),
                },
                "secret",
            ),
            (
                CredentialKind::Certificate {
                    private_key_pem: "pem".to_string(),
                    x5t_s256: "thumb".to_string(),
                },
                "certificate",
            ),
            (
                CredentialKind::Federated {
                    token_file: "/var/run/token".to_string(),
                },
                "federated",
            ),
        ];

        for (credential, tag) in cases {
            let value = serde_json::to_value(&credential).unwrap();
            assert_eq!(value["type"], tag, "unexpected tag for {credential:?}");

            let parsed: CredentialKind = serde_json::from_value(value).unwrap();
            assert_eq!(
                serde_json::to_value(&parsed).unwrap(),
                serde_json::to_value(&credential).unwrap(),
                "{tag} did not survive a round trip"
            );
        }
    }

    /// The operator-facing config in the docs must actually deserialise.
    #[test]
    fn config_parses_the_documented_shape() {
        let parsed: M365Config = serde_json::from_value(json!({
            "tenant_id": "tenant",
            "client_id": "client",
            "credential": { "type": "federated", "token_file": "/var/run/secrets/azure/token" },
        }))
        .unwrap();
        assert_eq!(parsed.authority, DEFAULT_AUTHORITY);
        assert!(matches!(parsed.credential, CredentialKind::Federated { .. }));
    }

    #[test]
    fn token_endpoint_is_the_v2_tenant_endpoint() {
        let config = config(CredentialKind::Secret {
            client_secret: "x".to_string(),
        });
        assert_eq!(
            M365Engine::token_endpoint(&config),
            format!(
                "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
                config.tenant_id
            )
        );
    }

    /// A long-lived assertion would itself be a credential for the whole app
    /// registration, and `aud` has to be the exact endpoint or Entra rejects it.
    #[test]
    fn client_assertion_claims_are_short_lived_and_endpoint_bound() {
        let config = config(CredentialKind::Secret {
            client_secret: "x".to_string(),
        });
        let endpoint = M365Engine::token_endpoint(&config);
        let now = Utc::now();
        let claims = M365Engine::assertion_claims(&config.client_id, &endpoint, now);

        assert_eq!(claims.aud, endpoint);
        assert_eq!(claims.iss, config.client_id);
        assert_eq!(claims.sub, config.client_id);
        assert_eq!(claims.exp - claims.iat, CLIENT_ASSERTION_TTL_SECONDS);
        assert!(claims.exp - claims.iat <= 600, "assertion must be short-lived");

        let other = M365Engine::assertion_claims(&config.client_id, &endpoint, now);
        assert_ne!(claims.jti, other.jti, "jti must be unique per assertion");
    }

    #[test]
    fn assertion_header_carries_the_thumbprint_as_x5t_s256() {
        let header = M365Engine::assertion_header("Zm9vYmFy");
        assert_eq!(header.alg, jsonwebtoken::Algorithm::RS256);

        let encoded = serde_json::to_value(&header).unwrap();
        assert_eq!(
            encoded["x5t#S256"], "Zm9vYmFy",
            "Entra selects the registered key by this header, so the RFC spelling matters"
        );
    }

    #[test]
    fn rejects_a_certificate_that_is_not_a_pem() {
        let err = M365Engine::client_assertion(
            "client",
            "not a pem",
            "thumb",
            "https://login.microsoftonline.com/t/oauth2/v2.0/token",
            Utc::now(),
        )
        .unwrap_err();
        assert!(matches!(err, EngineError::InvalidRequest(_)), "got {err:?}");
    }

    #[test]
    fn missing_federated_token_file_is_a_clear_invalid_request() {
        let path = format!("/nonexistent/{}/token", Uuid::new_v4());
        let err = M365Engine::read_federated_token(&path).unwrap_err();
        match err {
            EngineError::InvalidRequest(message) => {
                assert!(message.contains(&path), "error should name the path: {message}");
                assert!(
                    message.contains("AZURE_FEDERATED_TOKEN_FILE"),
                    "error should point at the convention: {message}"
                );
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn federated_token_is_read_and_trimmed() {
        let path = std::env::temp_dir().join(format!("m365-{}.jwt", Uuid::new_v4()));
        std::fs::write(&path, "  header.payload.signature\n").unwrap();

        let token = M365Engine::read_federated_token(path.to_str().unwrap()).unwrap();
        assert_eq!(token, "header.payload.signature");

        std::fs::write(&path, "\n\n").unwrap();
        let err = M365Engine::read_federated_token(path.to_str().unwrap()).unwrap_err();
        assert!(matches!(err, EngineError::InvalidRequest(_)), "got {err:?}");

        std::fs::remove_file(&path).unwrap();
    }

    /// `.default` grants everything the app was consented, so the `_doc` a
    /// consumer receives must not let that pass silently.
    #[test]
    fn scope_description_admits_that_default_is_not_narrowing() {
        let config = config(CredentialKind::Federated {
            token_file: "/var/run/token".to_string(),
        });
        let scoped = M365Engine::scope_description(&role(), &config);

        assert!(scoped.iter().any(|s| s.contains("permissions:ALL")));
        assert!(scoped.iter().any(|s| s.contains("resource-narrowing:NONE RECORDED")));
        assert!(scoped.contains(&format!("tenant:{}", config.tenant_id)));
    }

    #[test]
    fn scope_description_reports_recorded_resource_narrowing() {
        let config = config(CredentialKind::Secret {
            client_secret: "x".to_string(),
        });
        let role = RoleConfig {
            resource_hint: Some("Sites.Selected: reports-site (read)".to_string()),
            ..role()
        };
        let scoped = M365Engine::scope_description(&role, &config);

        assert!(
            scoped
                .iter()
                .any(|s| s == "resource-narrowing:Sites.Selected: reports-site (read)")
        );
        assert!(!scoped.iter().any(|s| s.contains("NONE RECORDED")));
    }

    #[test]
    fn doc_agrees_with_its_shape() {
        let doc = M365Engine::new().doc();
        assert_eq!(doc.shape, CredentialShape::MintExpiryOnly);
        assert_eq!(doc.revocable, doc.shape.revocable());
        assert!(!doc.revocable, "Graph access tokens cannot be revoked");
        assert!(!doc.ttl.fixed, "a CTL policy can move this lifetime");
        assert_eq!(doc.ttl.min_seconds, Some(MIN_CONFIGURABLE_TTL_SECONDS));
    }

    /// The whole point of `revoke_effect` is that it does not overstate what
    /// happens, since three of the seven providers cannot revoke at all.
    #[test]
    fn doc_does_not_overstate_revocation() {
        let doc = M365Engine::new().doc();
        assert!(doc.revoke_effect.starts_with("nothing at the provider"));
        assert!(doc.revoke_effect.contains("Continuous Access Evaluation"));
    }

    #[test]
    fn federated_credential_reports_storing_no_secret() {
        let federated = CredentialKind::Federated {
            token_file: "/var/run/token".to_string(),
        };
        assert!(federated.describes_root_credential().starts_with("nothing"));
        assert_eq!(
            CredentialKind::Secret {
                client_secret: "x".to_string()
            }
            .describes_root_credential(),
            "a client secret"
        );
    }
}
