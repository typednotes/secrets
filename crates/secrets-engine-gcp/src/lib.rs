//! Google Cloud credentials — service-account impersonation, downscoped
//! Cloud Storage tokens, and HMAC keys.
//!
//! GCP can mint short-lived credentials and, uniquely among the clouds here,
//! can narrow one to a single bucket and prefix at mint time via a Credential
//! Access Boundary. What it cannot do is revoke one: an issued access token is
//! valid until `expireTime` no matter what happens in IAM. So the headline
//! shape is B — scope and TTL are the whole containment story — with HMAC keys
//! as the one genuinely revocable option.
//!
//! See `docs/delegation/gcp-storage.md` for the mechanism.

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

const STORE: ConfigRoleStore = ConfigRoleStore::new("gcp/config/", "gcp/roles/");
const MOUNT: &str = "gcp/creds/";

const METADATA_TOKEN_URL: &str = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";
const OAUTH_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const IAM_CREDENTIALS_URL: &str = "https://iamcredentials.googleapis.com/v1";
const STS_URL: &str = "https://sts.googleapis.com/v1/token";
const STORAGE_API_URL: &str = "https://storage.googleapis.com/storage/v1";

/// Google caps a self-signed JWT assertion at one hour.
const ASSERTION_TTL_SECONDS: i64 = 3600;
const DEFAULT_TTL_SECONDS: i64 = 900;
const DEFAULT_IAM_ROLE: &str = "roles/storage.objectViewer";
const DEFAULT_SCOPE: &str = "https://www.googleapis.com/auth/devstorage.read_only";

/// How the server proves its own identity to Google before it can impersonate
/// anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum GcpAuth {
    /// Ambient identity from the GCE/GKE metadata server. Stores no key, which
    /// is why it is the default.
    #[default]
    Metadata,
    /// A service-account key file. Google's own guidance calls this the last
    /// resort, because the private key inside never expires.
    ServiceAccountKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcpConfig {
    pub project_id: String,
    #[serde(default)]
    pub auth: GcpAuth,
    /// The full contents of a service-account key JSON file. Required only when
    /// `auth` is `service_account_key`; never read back out.
    #[serde(default)]
    pub service_account_key_json: Option<String>,
}

/// Which mechanism a role mints. The three differ in what they can be narrowed
/// to and — more importantly — whether they can be revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CredentialType {
    /// A plain impersonated token. Inherits *every* permission of the target
    /// service account, so prefer `downscoped`.
    Impersonated,
    /// Impersonation followed by a Credential Access Boundary exchange,
    /// narrowing to one bucket and optionally one prefix.
    #[default]
    Downscoped,
    /// An S3-interoperability HMAC key. The only revocable credential here.
    Hmac,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleConfig {
    /// Which `gcp/config/{name}` document to authenticate with.
    pub target: String,
    #[serde(default)]
    pub credential_type: CredentialType,
    /// The service account to impersonate, or to own the HMAC key.
    pub service_account: String,
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    /// Required for `downscoped` — a boundary must name a resource.
    #[serde(default)]
    pub bucket: Option<String>,
    /// Optional object-name prefix within the bucket.
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(default = "default_iam_role")]
    pub iam_role: String,
    #[serde(default = "default_ttl_seconds")]
    pub default_ttl_seconds: i64,
}

fn default_scopes() -> Vec<String> {
    vec![DEFAULT_SCOPE.to_string()]
}

fn default_iam_role() -> String {
    DEFAULT_IAM_ROLE.to_string()
}

fn default_ttl_seconds() -> i64 {
    DEFAULT_TTL_SECONDS
}

#[derive(Debug, Deserialize)]
struct ServiceAccountKey {
    client_email: String,
    private_key: String,
}

#[derive(Debug, Serialize)]
struct AssertionClaims {
    iss: String,
    scope: String,
    aud: String,
    iat: i64,
    exp: i64,
}

#[derive(Debug, Deserialize)]
struct OauthTokenResponse {
    access_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GenerateAccessTokenResponse {
    access_token: String,
    expire_time: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct StsTokenResponse {
    access_token: String,
    expires_in: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HmacKeyMetadata {
    access_id: String,
}

#[derive(Debug, Deserialize)]
struct HmacKeyResponse {
    metadata: HmacKeyMetadata,
    secret: String,
}

#[derive(Default)]
pub struct GcpEngine {
    http: reqwest::Client,
}

impl GcpEngine {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::new(),
        }
    }

    /// `generateAccessToken` wants a duration string, not a number.
    fn lifetime_string(seconds: i64) -> String {
        format!("{seconds}s")
    }

    /// The Credential Access Boundary that narrows an impersonated token to one
    /// bucket, and optionally one object prefix.
    ///
    /// The prefix condition is deliberately two clauses OR'd together: a bare
    /// `resource.name.startsWith(...)` permits reading objects but silently
    /// breaks `list`, because a list request carries no object name to test.
    /// The `objectListPrefix` attribute is what makes listing work.
    fn access_boundary(role: &RoleConfig) -> EngineResult<serde_json::Value> {
        let bucket = role.bucket.as_deref().ok_or_else(|| {
            EngineError::InvalidRequest(
                "credential_type 'downscoped' requires a bucket — a Credential Access \
                 Boundary must name the resource it narrows to"
                    .into(),
            )
        })?;

        let mut rule = json!({
            "availableResource": format!("//storage.googleapis.com/projects/_/buckets/{bucket}"),
            "availablePermissions": [format!("inRole:{}", role.iam_role)],
        });

        if let Some(prefix) = role.prefix.as_deref() {
            let objects = format!("projects/_/buckets/{bucket}/objects/{prefix}");
            rule["availabilityCondition"] = json!({
                "expression": format!(
                    "resource.name.startsWith('{objects}') || \
                     api.getAttribute('storage.googleapis.com/objectListPrefix', '').startsWith('{prefix}')"
                ),
            });
        }

        Ok(json!({ "accessBoundary": { "accessBoundaryRules": [rule] } }))
    }

    /// Where a credential type's guarantees differ from the engine's headline
    /// shape. Only HMAC keys can actually be destroyed, so only they get to
    /// claim it.
    fn revocation_override(
        credential_type: CredentialType,
    ) -> Option<(CredentialShape, &'static str)> {
        match credential_type {
            CredentialType::Hmac => Some((
                CredentialShape::MintAndRevoke,
                "deactivates the HMAC key (GCS requires INACTIVE before deletion) and \
                 then deletes it — the credential stops working immediately.",
            )),
            CredentialType::Impersonated | CredentialType::Downscoped => None,
        }
    }

    fn scope_description(role: &RoleConfig) -> Vec<String> {
        let mut scoped = vec![format!("service_account:{}", role.service_account)];
        match role.credential_type {
            CredentialType::Impersonated => {
                scoped.extend(role.scopes.iter().map(|s| format!("oauth_scope:{s}")));
                scoped.push(
                    "resources:ALL (a plain impersonated token carries every permission \
                     of the target service account — use downscoped to narrow it)"
                        .to_string(),
                );
            }
            CredentialType::Downscoped => {
                if let Some(bucket) = &role.bucket {
                    scoped.push(format!("bucket:{bucket}"));
                }
                match &role.prefix {
                    Some(prefix) => scoped.push(format!("prefix:{prefix}")),
                    None => scoped.push("prefix:ALL (the whole bucket)".to_string()),
                }
                scoped.push(format!("in_role:{}", role.iam_role));
            }
            CredentialType::Hmac => {
                scoped.push("api:s3-interoperability (XML API only)".to_string());
                scoped.push(
                    "resources:ALL (HMAC keys inherit the service account's permissions \
                     and cannot be narrowed to a bucket)"
                        .to_string(),
                );
            }
        }
        scoped
    }

    /// The server's own access token — the thing it needs before it can
    /// impersonate anything else.
    async fn caller_token(&self, config: &GcpConfig) -> EngineResult<String> {
        match config.auth {
            GcpAuth::Metadata => {
                let response = self
                    .http
                    .get(METADATA_TOKEN_URL)
                    .header("Metadata-Flavor", "Google")
                    .send()
                    .await
                    .map_err(|e| {
                        EngineError::Provider(format!(
                            "metadata server unreachable — is this server running on GCP? {e}"
                        ))
                    })?;
                Ok(Self::parse::<OauthTokenResponse>(response, "metadata server")
                    .await?
                    .access_token)
            }
            GcpAuth::ServiceAccountKey => {
                let raw = config.service_account_key_json.as_deref().ok_or_else(|| {
                    EngineError::InvalidRequest(
                        "auth is 'service_account_key' but service_account_key_json is absent"
                            .into(),
                    )
                })?;
                let key: ServiceAccountKey = serde_json::from_str(raw).map_err(|e| {
                    EngineError::InvalidRequest(format!(
                        "service_account_key_json is not a service-account key file: {e}"
                    ))
                })?;
                self.jwt_bearer_token(&key).await
            }
        }
    }

    async fn jwt_bearer_token(&self, key: &ServiceAccountKey) -> EngineResult<String> {
        let now = Utc::now().timestamp();
        let claims = AssertionClaims {
            iss: key.client_email.clone(),
            scope: "https://www.googleapis.com/auth/cloud-platform".to_string(),
            aud: OAUTH_TOKEN_URL.to_string(),
            iat: now,
            exp: now + ASSERTION_TTL_SECONDS,
        };
        let encoding_key =
            jsonwebtoken::EncodingKey::from_rsa_pem(key.private_key.as_bytes()).map_err(|e| {
                EngineError::InvalidRequest(format!(
                    "the private_key in service_account_key_json is not a valid RSA PEM: {e}"
                ))
            })?;
        let assertion = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
            &claims,
            &encoding_key,
        )
        .map_err(|e| EngineError::Other(format!("failed to sign the JWT assertion: {e}")))?;

        let response = self
            .http
            .post(OAUTH_TOKEN_URL)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &assertion),
            ])
            .send()
            .await
            .map_err(|e| EngineError::Provider(format!("Google token exchange failed: {e}")))?;
        Ok(Self::parse::<OauthTokenResponse>(response, OAUTH_TOKEN_URL)
            .await?
            .access_token)
    }

    async fn impersonate(
        &self,
        caller_token: &str,
        role: &RoleConfig,
    ) -> EngineResult<GenerateAccessTokenResponse> {
        let url = format!(
            "{IAM_CREDENTIALS_URL}/projects/-/serviceAccounts/{}:generateAccessToken",
            role.service_account
        );
        let response = self
            .http
            .post(&url)
            .bearer_auth(caller_token)
            .json(&json!({
                "scope": role.scopes,
                "lifetime": Self::lifetime_string(role.default_ttl_seconds),
            }))
            .send()
            .await
            .map_err(|e| EngineError::Provider(format!("impersonation request failed: {e}")))?;
        Self::parse(response, &url).await
    }

    async fn downscope(
        &self,
        access_token: &str,
        role: &RoleConfig,
    ) -> EngineResult<StsTokenResponse> {
        let boundary = Self::access_boundary(role)?;
        let options = serde_json::to_string(&boundary)
            .map_err(|e| EngineError::Other(format!("failed to encode access boundary: {e}")))?;

        let response = self
            .http
            .post(STS_URL)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"),
                (
                    "subject_token_type",
                    "urn:ietf:params:oauth:token-type:access_token",
                ),
                (
                    "requested_token_type",
                    "urn:ietf:params:oauth:token-type:access_token",
                ),
                ("subject_token", access_token),
                ("options", &options),
            ])
            .send()
            .await
            .map_err(|e| EngineError::Provider(format!("STS downscope failed: {e}")))?;
        Self::parse(response, STS_URL).await
    }

    async fn create_hmac_key(
        &self,
        caller_token: &str,
        config: &GcpConfig,
        role: &RoleConfig,
    ) -> EngineResult<HmacKeyResponse> {
        // Service-account emails are made of query-safe characters only, so
        // interpolating beats pulling in a query-string encoder.
        let url = format!(
            "{STORAGE_API_URL}/projects/{}/hmacKeys?serviceAccountEmail={}",
            config.project_id, role.service_account
        );
        let response = self
            .http
            .post(&url)
            .bearer_auth(caller_token)
            .send()
            .await
            .map_err(|e| EngineError::Provider(format!("HMAC key creation failed: {e}")))?;
        Self::parse(response, &url).await
    }

    async fn parse<T: serde::de::DeserializeOwned>(
        response: reqwest::Response,
        what: &str,
    ) -> EngineResult<T> {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(EngineError::Provider(format!(
                "Google returned {status} for {what}: {body}"
            )));
        }
        serde_json::from_str(&body)
            .map_err(|e| EngineError::Provider(format!("unexpected response from {what}: {e}")))
    }
}

#[async_trait]
impl SecretsEngine for GcpEngine {
    fn doc(&self) -> EngineDoc {
        EngineDoc {
            provider: "Google Cloud".to_string(),
            mechanism: "service-account impersonation via the IAM Credentials API, \
                        optionally narrowed to one bucket and prefix by a Credential \
                        Access Boundary, plus revocable Cloud Storage HMAC keys"
                .to_string(),
            shape: CredentialShape::MintExpiryOnly,
            revocable: false,
            revoke_effect: "nothing at Google. An issued service-account access token — \
                            downscoped or not — cannot be revoked: there is no endpoint \
                            for it and nothing tracks outstanding tokens. Revoking the \
                            lease deletes our record and stops renewal, and the \
                            credential keeps working until its expireTime. The only \
                            real levers are disabling the service account (which kills \
                            every consumer's tokens) or waiting out the TTL. Roles with \
                            credential_type 'hmac' are the exception and are genuinely \
                            revocable."
                .to_string(),
            ttl: TtlDoc::range(
                60,
                3600,
                "default 900s. One hour is the maximum unless the \
                 constraints/iam.allowServiceAccountCredentialLifetimeExtension org \
                 policy lists the service account, which raises it to 12 hours — the \
                 wrong direction for a credential nobody can revoke. HMAC keys ignore \
                 this entirely: they never expire and live until the reaper deletes them.",
            ),
            scoping: "credential_type 'downscoped' narrows to a single bucket, an \
                      optional object prefix and one IAM role — the only per-bucket \
                      narrowing any cloud provider here offers, and the reason to \
                      prefer it. 'impersonated' does NOT narrow: it carries every \
                      permission of the target service account. 'hmac' cannot be \
                      narrowed at all."
                .to_string(),
            root_credential: "none, preferably: with auth 'metadata' the server uses its \
                              own attached service account and stores no key, needing \
                              only roles/iam.serviceAccountTokenCreator on each target \
                              service account. With auth 'service_account_key' it holds \
                              a key file whose private key never expires — Google's own \
                              guidance calls that the last resort."
                .to_string(),
            paths: vec![
                PathDoc::new(
                    "gcp/config/{target}",
                    &["POST", "GET", "DELETE"],
                    "sudo",
                    "register the project and how the server authenticates. GET reports \
                     only whether it is configured — any key is never returned.",
                ),
                PathDoc::new(
                    "gcp/roles/{role}",
                    &["POST", "GET", "DELETE"],
                    "create / read / sudo",
                    "define one consumer's credential type, service account, bucket, \
                     prefix and TTL",
                ),
                PathDoc::new(
                    "gcp/creds/{role}",
                    &["GET"],
                    "read",
                    "mint a token (or HMAC key) and open a lease",
                ),
                PathDoc::new("gcp/help", &["GET"], "authenticated", "this document"),
            ],
            docs_url: Some("docs/delegation/gcp-storage.md".to_string()),
            caveats: vec![
                "Access tokens and downscoped tokens cannot be revoked, so the TTL is \
                 the entire containment story. Keep it short — 15 minutes is a sane \
                 default, and the one-hour maximum should be the exception."
                    .to_string(),
                "Credential Access Boundaries work for Cloud Storage ONLY. No other \
                 GCP service supports downscoping, so this approach does not \
                 generalise to the rest of GCP."
                    .to_string(),
                "A boundary can only subtract permissions. It never grants anything the \
                 target service account lacks."
                    .to_string(),
                "The bucket must have uniform bucket-level access enabled for boundary \
                 conditions to behave."
                    .to_string(),
                "A prefix condition needs two clauses: a bare resource.name.startsWith \
                 permits object reads but breaks list, because a list request carries no \
                 object name. This engine OR's in an objectListPrefix condition so \
                 listing works."
                    .to_string(),
                "HMAC keys never expire on their own, are limited to 10 per service \
                 account, are scoped to the whole service account with no bucket \
                 narrowing, and work only against the S3-compatible XML API."
                    .to_string(),
                "Signing permission for a signed URL is checked at mint time but the \
                 storage permission only when the URL is used, so a URL can be minted \
                 successfully and still 403."
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
        STORE.handle_write::<GcpConfig, RoleConfig>(storage, path, data).await
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
        let config: GcpConfig = STORE.require_config(storage, &role.target).await?;
        let caller_token = self.caller_token(&config).await?;
        let now = Utc::now();

        let (data, internal_data, expires_at) = match role.credential_type {
            CredentialType::Impersonated => {
                let token = self.impersonate(&caller_token, &role).await?;
                (
                    json!({
                        "access_token": token.access_token,
                        "token_type": "Bearer",
                        "expires_at": token.expire_time,
                    }),
                    json!({ "credential_type": "impersonated", "target": role.target }),
                    token.expire_time,
                )
            }
            CredentialType::Downscoped => {
                let token = self.impersonate(&caller_token, &role).await?;
                let downscoped = self.downscope(&token.access_token, &role).await?;
                // A downscoped token cannot outlive the token it was derived
                // from, so the lease takes whichever bound is tighter.
                let sts_expiry = now + Duration::seconds(downscoped.expires_in);
                (
                    json!({
                        "access_token": downscoped.access_token,
                        "token_type": "Bearer",
                        "expires_at": sts_expiry.min(token.expire_time),
                    }),
                    json!({ "credential_type": "downscoped", "target": role.target }),
                    sts_expiry.min(token.expire_time),
                )
            }
            CredentialType::Hmac => {
                let key = self.create_hmac_key(&caller_token, &config, &role).await?;
                (
                    json!({
                        "access_id": key.metadata.access_id,
                        "secret": key.secret,
                        "endpoint": "https://storage.googleapis.com",
                    }),
                    json!({
                        "credential_type": "hmac",
                        "target": role.target,
                        "project_id": config.project_id,
                        "access_id": key.metadata.access_id,
                    }),
                    // An HMAC key has no expiry of its own, so the lease is the
                    // only clock — a missed revocation leaves it working.
                    now + Duration::seconds(role.default_ttl_seconds),
                )
            }
        };

        let lease = Lease {
            id: Uuid::new_v4(),
            // Set by the HTTP handler, which knows the requesting token.
            token_id_hash: String::new(),
            engine_mount: MOUNT.to_string(),
            internal_data,
            issued_at: now,
            expires_at,
        };

        let credential =
            GeneratedCredential::new(data, lease, Self::scope_description(&role));
        Ok(match Self::revocation_override(role.credential_type) {
            Some((shape, effect)) => credential.with_shape(shape, effect),
            None => credential,
        })
    }

    async fn revoke(&self, storage: &dyn StorageBackend, lease: &Lease) -> EngineResult<()> {
        let credential_type = lease.internal_data["credential_type"].as_str().unwrap_or("");
        if credential_type != "hmac" {
            // Nothing to call. Google offers no way to invalidate an issued
            // access token, so the credential outlives this lease record and
            // saying otherwise would be a lie.
            tracing::warn!(
                lease_id = %lease.id,
                credential_type,
                "gcp: lease record removed, but the access token keeps working until \
                 its expireTime — Google has no token revocation endpoint"
            );
            return Ok(());
        }

        let target = lease.internal_data["target"]
            .as_str()
            .ok_or_else(|| EngineError::Other("lease missing 'target'".into()))?;
        let access_id = lease.internal_data["access_id"]
            .as_str()
            .ok_or_else(|| EngineError::Other("lease missing 'access_id'".into()))?;
        let project_id = lease.internal_data["project_id"]
            .as_str()
            .ok_or_else(|| EngineError::Other("lease missing 'project_id'".into()))?;

        let config: GcpConfig = STORE.require_config(storage, target).await?;
        let caller_token = self.caller_token(&config).await?;
        let url = format!("{STORAGE_API_URL}/projects/{project_id}/hmacKeys/{access_id}");

        // GCS refuses to delete an ACTIVE key, so deactivation is not optional.
        let deactivated = self
            .http
            .put(&url)
            .bearer_auth(&caller_token)
            .json(&json!({ "state": "INACTIVE" }))
            .send()
            .await
            .map_err(|e| EngineError::Provider(format!("HMAC deactivation failed: {e}")))?;
        if !deactivated.status().is_success() && deactivated.status() != reqwest::StatusCode::NOT_FOUND
        {
            return Err(EngineError::Provider(format!(
                "Google returned {} when deactivating HMAC key {access_id}",
                deactivated.status()
            )));
        }

        let deleted = self
            .http
            .delete(&url)
            .bearer_auth(&caller_token)
            .send()
            .await
            .map_err(|e| EngineError::Provider(format!("HMAC deletion failed: {e}")))?;
        // An already-deleted key is not an error: the reaper must be able to
        // retry without tripping over its own success.
        if deleted.status().is_success() || deleted.status() == reqwest::StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(EngineError::Provider(format!(
                "Google returned {} when deleting HMAC key {access_id}",
                deleted.status()
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role(credential_type: CredentialType, bucket: Option<&str>, prefix: Option<&str>) -> RoleConfig {
        RoleConfig {
            target: "production".to_string(),
            credential_type,
            service_account: "reports@acme.iam.gserviceaccount.com".to_string(),
            scopes: default_scopes(),
            bucket: bucket.map(|b| b.to_string()),
            prefix: prefix.map(|p| p.to_string()),
            iam_role: default_iam_role(),
            default_ttl_seconds: DEFAULT_TTL_SECONDS,
        }
    }

    #[test]
    fn lifetime_is_formatted_as_a_duration_string() {
        assert_eq!(GcpEngine::lifetime_string(900), "900s");
        assert_eq!(GcpEngine::lifetime_string(3600), "3600s");
    }

    #[test]
    fn access_boundary_without_a_prefix_covers_the_whole_bucket() {
        let boundary =
            GcpEngine::access_boundary(&role(CredentialType::Downscoped, Some("reports"), None))
                .unwrap();
        let rule = &boundary["accessBoundary"]["accessBoundaryRules"][0];
        assert_eq!(
            rule["availableResource"],
            "//storage.googleapis.com/projects/_/buckets/reports"
        );
        assert_eq!(rule["availablePermissions"][0], "inRole:roles/storage.objectViewer");
        assert!(
            rule.get("availabilityCondition").is_none(),
            "an unprefixed boundary should carry no condition"
        );
    }

    /// The OR'd `objectListPrefix` clause is the whole point: without it the
    /// credential can read objects but not list them.
    #[test]
    fn access_boundary_with_a_prefix_also_permits_listing() {
        let boundary = GcpEngine::access_boundary(&role(
            CredentialType::Downscoped,
            Some("reports"),
            Some("report-service/"),
        ))
        .unwrap();
        let expression = boundary["accessBoundary"]["accessBoundaryRules"][0]
            ["availabilityCondition"]["expression"]
            .as_str()
            .unwrap();
        assert!(
            expression.contains("resource.name.startsWith('projects/_/buckets/reports/objects/report-service/')"),
            "{expression}"
        );
        assert!(expression.contains("objectListPrefix"), "{expression}");
        assert!(expression.contains("||"), "{expression}");
    }

    #[test]
    fn downscoping_without_a_bucket_is_rejected() {
        let err = GcpEngine::access_boundary(&role(CredentialType::Downscoped, None, None))
            .unwrap_err();
        assert!(matches!(err, EngineError::InvalidRequest(_)), "got {err:?}");
    }

    /// Only HMAC keys may claim revocability. If a token type ever started
    /// claiming it, the `_doc` a consumer receives would be a lie.
    #[test]
    fn only_hmac_keys_claim_to_be_revocable() {
        let (shape, effect) = GcpEngine::revocation_override(CredentialType::Hmac).unwrap();
        assert_eq!(shape, CredentialShape::MintAndRevoke);
        assert!(shape.revocable());
        assert!(effect.contains("INACTIVE"));

        assert!(GcpEngine::revocation_override(CredentialType::Impersonated).is_none());
        assert!(GcpEngine::revocation_override(CredentialType::Downscoped).is_none());
    }

    #[test]
    fn plain_impersonation_warns_that_it_is_unscoped() {
        let scoped = GcpEngine::scope_description(&role(CredentialType::Impersonated, None, None));
        assert!(
            scoped.iter().any(|s| s.contains("resources:ALL")),
            "{scoped:?}"
        );
    }

    #[test]
    fn downscoped_scope_names_the_bucket_and_prefix() {
        let scoped = GcpEngine::scope_description(&role(
            CredentialType::Downscoped,
            Some("reports"),
            Some("report-service/"),
        ));
        assert!(scoped.contains(&"bucket:reports".to_string()), "{scoped:?}");
        assert!(scoped.contains(&"prefix:report-service/".to_string()), "{scoped:?}");
        assert!(
            scoped.contains(&"in_role:roles/storage.objectViewer".to_string()),
            "{scoped:?}"
        );
    }

    #[test]
    fn downscoped_is_the_default_credential_type() {
        assert_eq!(CredentialType::default(), CredentialType::Downscoped);
    }

    /// Storing no key is the preferred posture, so it must also be the default.
    #[test]
    fn metadata_auth_is_the_default() {
        assert_eq!(GcpAuth::default(), GcpAuth::Metadata);
    }

    #[test]
    fn doc_agrees_with_its_shape() {
        let doc = GcpEngine::new().doc();
        assert_eq!(doc.shape, CredentialShape::MintExpiryOnly);
        assert_eq!(doc.revocable, doc.shape.revocable());
        assert!(!doc.revocable, "GCP access tokens cannot be revoked");
        assert!(doc.revoke_effect.contains("cannot be revoked"));
        assert!(!doc.caveats.is_empty());
    }
}
