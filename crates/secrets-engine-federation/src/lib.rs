//! Federation (shape E) — the engine that deliberately issues nothing.
//!
//! Under federation the provider is configured to trust the *consumer's own*
//! identity, so no credential is minted, brokered, stored or handed over. What
//! a consumer needs from us is not a secret but an answer to "where do I
//! exchange my own token, and what must that token say?".
//!
//! That makes this engine a directory rather than a vault, and it is the
//! strongest outcome available: there is no root credential to compromise and
//! no leased credential to leak. See `docs/delegation/federation.md`.

use async_trait::async_trait;
use secrets_core::engine::{
    CredentialShape, EngineDoc, EngineError, EngineResult, GeneratedCredential, PathDoc,
    SecretsEngine, TtlDoc,
};
use secrets_core::mount::ConfigRoleStore;
use secrets_core::storage::StorageBackend;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const STORE: ConfigRoleStore = ConfigRoleStore::new("federation/config/", "federation/roles/");

/// Placeholder the consumer substitutes with its own workload token. Spelled
/// loudly because a consumer that sends this literal string has misread the
/// instructions, and the provider's error would not say so.
const TOKEN_PLACEHOLDER: &str = "${YOUR_OIDC_TOKEN}";

/// Where a federated identity is being exchanged, and for what.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "provider", rename_all = "snake_case")]
pub enum ProviderTarget {
    Aws {
        role_arn: String,
        #[serde(default)]
        region: Option<String>,
        #[serde(default)]
        duration_seconds: Option<i64>,
    },
    Gcp {
        /// Full resource name of the workload identity pool provider,
        /// `//iam.googleapis.com/projects/…/workloadIdentityPools/…/providers/…`.
        workload_identity_provider: String,
        /// Set only when impersonating a service account after the exchange.
        /// Leaving it unset is the better pattern: granting the federated
        /// principal IAM directly keeps the original identity in audit logs.
        #[serde(default)]
        service_account: Option<String>,
        #[serde(default = "default_gcp_scope")]
        scope: String,
    },
    Azure {
        tenant_id: String,
        client_id: String,
        #[serde(default = "default_graph_scope")]
        scope: String,
    },
}

fn default_gcp_scope() -> String {
    "https://www.googleapis.com/auth/cloud-platform".to_string()
}

fn default_graph_scope() -> String {
    "https://graph.microsoft.com/.default".to_string()
}

/// The trust relationship an operator established at the provider. None of
/// this is secret — it is the *absence* of a secret that makes federation
/// worth the setup effort — but it lives behind `sudo` with every other
/// engine's config for consistency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationConfig {
    /// The consumer's OIDC issuer, exactly as registered at the provider.
    pub issuer: String,
    /// The audience the provider was told to require.
    pub audience: String,
    #[serde(flatten)]
    pub target: ProviderTarget,
}

/// Which consumer may federate where. `subject` is the `sub` claim the
/// provider's trust policy pins, and pinning it is the whole game: a trust
/// policy that checks only the issuer lets *any* workload from that issuer in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleConfig {
    pub target: String,
    pub subject: String,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Default)]
pub struct FederationEngine;

impl FederationEngine {
    pub fn new() -> Self {
        Self
    }

    /// Turns a trust configuration into a request the consumer can actually
    /// make. This is the engine's entire product.
    fn instructions(config: &FederationConfig, role: &RoleConfig) -> Value {
        let required_claims = json!({
            "iss": config.issuer,
            "aud": config.audience,
            "sub": role.subject,
        });

        let exchange = match &config.target {
            ProviderTarget::Aws {
                role_arn,
                region,
                duration_seconds,
            } => {
                let host = region
                    .as_deref()
                    .map(|r| format!("https://sts.{r}.amazonaws.com/"))
                    .unwrap_or_else(|| "https://sts.amazonaws.com/".to_string());
                json!({
                    "method": "POST",
                    "url": host,
                    "form": {
                        "Action": "AssumeRoleWithWebIdentity",
                        "Version": "2011-06-15",
                        "RoleArn": role_arn,
                        "RoleSessionName": role.subject,
                        "WebIdentityToken": TOKEN_PLACEHOLDER,
                        "DurationSeconds": duration_seconds.unwrap_or(900).to_string(),
                    },
                    "returns": "AccessKeyId, SecretAccessKey, SessionToken, Expiration",
                    "note": "This call needs no AWS credential — only your own JWT.",
                })
            }
            ProviderTarget::Gcp {
                workload_identity_provider,
                service_account,
                scope,
            } => {
                let mut steps = vec![json!({
                    "step": 1,
                    "method": "POST",
                    "url": "https://sts.googleapis.com/v1/token",
                    "json": {
                        "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
                        "audience": workload_identity_provider,
                        "scope": scope,
                        "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
                        "subjectTokenType": "urn:ietf:params:oauth:token-type:jwt",
                        "subjectToken": TOKEN_PLACEHOLDER,
                    },
                    "returns": "access_token — usable directly if the federated principal holds IAM",
                })];
                if let Some(service_account) = service_account {
                    steps.push(json!({
                        "step": 2,
                        "method": "POST",
                        "url": format!(
                            "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{service_account}:generateAccessToken"
                        ),
                        "authorization": "Bearer <the access_token from step 1>",
                        "json": { "scope": [scope], "lifetime": "900s" },
                        "note": "Only needed when impersonating. Granting the federated \
                                 principal IAM directly is preferable — it keeps your own \
                                 identity in Cloud Storage audit logs instead of hiding it \
                                 behind a service account.",
                    }));
                }
                json!({ "steps": steps })
            }
            ProviderTarget::Azure {
                tenant_id,
                client_id,
                scope,
            } => json!({
                "method": "POST",
                "url": format!("https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"),
                "form": {
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_assertion_type":
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    "client_assertion": TOKEN_PLACEHOLDER,
                    "scope": scope,
                },
                "returns": "access_token, expires_in",
                "note": "No client_secret appears in this request. That is the point.",
            }),
        };

        json!({
            "shape": CredentialShape::Federation,
            "issued_credential": Value::Null,
            "your_token_must_present": required_claims,
            "exchange": exchange,
            "reminder": format!(
                "Replace {TOKEN_PLACEHOLDER} with the JWT your own platform issues. \
                 This server never sees it and holds no credential for this provider."
            ),
        })
    }
}

#[async_trait]
impl SecretsEngine for FederationEngine {
    fn doc(&self) -> EngineDoc {
        EngineDoc {
            provider: "AWS, Google Cloud and Microsoft Entra ID".to_string(),
            mechanism: "publishes the OIDC token-exchange instructions a consumer \
                        needs to authenticate to a provider with its own workload \
                        identity. Nothing is minted, stored or handed over."
                .to_string(),
            shape: CredentialShape::Federation,
            revocable: false,
            revoke_effect: "nothing to revoke — this engine never issues a credential. \
                            Access is withdrawn at the provider by removing the trust \
                            policy condition or the IAM grant for that subject, which \
                            takes effect on the consumer's next exchange."
                .to_string(),
            ttl: TtlDoc {
                min_seconds: None,
                max_seconds: None,
                fixed: false,
                note: "not applicable to the instructions, which are not a secret. The \
                       credential the consumer obtains for itself is governed by the \
                       provider — 15 minutes to 12 hours for AWS STS, up to 1 hour for \
                       Google, 60–90 minutes for Entra."
                    .to_string(),
            },
            scoping: "at the provider, by pinning the trust policy to one issuer, one \
                      audience and one exact subject, then attaching a least-privilege \
                      policy to the federated principal."
                .to_string(),
            root_credential: "none. This is the only engine here that stores no \
                              provider secret whatsoever, which is why it is worth \
                              preferring wherever a provider supports it."
                .to_string(),
            paths: vec![
                PathDoc::new(
                    "federation/config/{target}",
                    &["POST", "GET", "DELETE"],
                    "sudo",
                    "register a provider trust relationship: issuer, audience and the \
                     AWS role / GCP pool provider / Entra app it maps to",
                ),
                PathDoc::new(
                    "federation/roles/{role}",
                    &["GET"],
                    "read",
                    "**the consumer-facing route**: returns the exchange instructions \
                     and the claims your own token must carry. No credential is issued, \
                     so there is nothing to lease.",
                ),
                PathDoc::new(
                    "federation/roles/{role}",
                    &["POST", "DELETE"],
                    "create / sudo",
                    "define which consumer subject may federate to which target",
                ),
                PathDoc::new(
                    "federation/creds/{role}",
                    &["GET"],
                    "read",
                    "refuses, by design — see the role path above",
                ),
                PathDoc::new("federation/help", &["GET"], "authenticated", "this document"),
            ],
            docs_url: Some("docs/delegation/federation.md".to_string()),
            caveats: vec![
                "Pin the trust policy's subject to the exact workload. A wildcard \
                 subject, or a condition on audience alone, lets any identity from that \
                 issuer assume the role — the classic confused-deputy misconfiguration."
                    .to_string(),
                "Neither GitHub nor GitLab can be reached this way: their OIDC tokens \
                 authenticate a workflow *outward* to third parties, and no endpoint \
                 exchanges an external token for their own API access."
                    .to_string(),
                "Withdrawal is not instant for credentials the consumer already holds. \
                 Removing the trust stops the next exchange; an STS session or Google \
                 access token already issued runs until it expires."
                    .to_string(),
                "The consumer needs an OIDC identity of its own. Without one — no \
                 Kubernetes projected token, no cloud workload identity — federation is \
                 unavailable and a brokered engine is the fallback."
                    .to_string(),
            ],
        }
    }

    async fn read(&self, storage: &dyn StorageBackend, path: &str) -> EngineResult<Value> {
        // Roles get the full treatment: the stored definition plus resolved,
        // copy-pasteable exchange instructions. This is the one route
        // consumers actually call.
        if let Some(name) = path.strip_prefix("roles/") {
            let role: RoleConfig = STORE.require_role(storage, name).await?;
            let config: FederationConfig = STORE.require_config(storage, &role.target).await?;
            let mut value = json!({
                "role": name,
                "target": role.target,
                "subject": role.subject,
                "help": "/v1/federation/help",
            });
            if let Some(notes) = &role.notes {
                value["notes"] = json!(notes);
            }
            if let (Some(object), Value::Object(instructions)) =
                (value.as_object_mut(), Self::instructions(&config, &role))
            {
                object.extend(instructions);
            }
            return Ok(value);
        }
        STORE.handle_read::<RoleConfig>(storage, path).await
    }

    async fn write(
        &self,
        storage: &dyn StorageBackend,
        path: &str,
        data: Value,
    ) -> EngineResult<()> {
        STORE
            .handle_write::<FederationConfig, RoleConfig>(storage, path, data)
            .await
    }

    async fn delete(&self, storage: &dyn StorageBackend, path: &str) -> EngineResult<()> {
        STORE.handle_delete(storage, path).await
    }

    async fn list(&self, storage: &dyn StorageBackend, prefix: &str) -> EngineResult<Vec<String>> {
        STORE.handle_list(storage, prefix).await
    }

    /// Refuses, and explains itself. A consumer following the
    /// `{mount}/creds/{role}` convention deserves to be told why federation
    /// breaks it rather than being handed something credential-shaped.
    async fn generate(
        &self,
        _storage: &dyn StorageBackend,
        role: &str,
    ) -> EngineResult<GeneratedCredential> {
        Err(EngineError::InvalidRequest(format!(
            "federation issues no credential, so there is nothing to lease. \
             GET /v1/federation/roles/{role} for the exchange instructions, then \
             present your own OIDC token to the provider. See /v1/federation/help."
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role() -> RoleConfig {
        RoleConfig {
            target: "prod".to_string(),
            subject: "system:serviceaccount:apps:report-service".to_string(),
            notes: None,
        }
    }

    fn config(target: ProviderTarget) -> FederationConfig {
        FederationConfig {
            issuer: "https://oidc.example.com".to_string(),
            audience: "sts.amazonaws.com".to_string(),
            target,
        }
    }

    #[test]
    fn aws_instructions_need_no_aws_credential() {
        let value = FederationEngine::instructions(
            &config(ProviderTarget::Aws {
                role_arn: "arn:aws:iam::123456789012:role/reports".to_string(),
                region: Some("eu-west-3".to_string()),
                duration_seconds: Some(900),
            }),
            &role(),
        );
        let form = &value["exchange"]["form"];
        assert_eq!(form["Action"], "AssumeRoleWithWebIdentity");
        assert_eq!(form["WebIdentityToken"], TOKEN_PLACEHOLDER);
        assert_eq!(value["exchange"]["url"], "https://sts.eu-west-3.amazonaws.com/");
        // The defining property of shape E: nothing was issued.
        assert!(value["issued_credential"].is_null());
    }

    #[test]
    fn gcp_instructions_skip_impersonation_when_not_configured() {
        let direct = FederationEngine::instructions(
            &config(ProviderTarget::Gcp {
                workload_identity_provider: "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/v".to_string(),
                service_account: None,
                scope: default_gcp_scope(),
            }),
            &role(),
        );
        assert_eq!(
            direct["exchange"]["steps"].as_array().map(Vec::len),
            Some(1),
            "granting the federated principal directly should need one step"
        );

        let impersonated = FederationEngine::instructions(
            &config(ProviderTarget::Gcp {
                workload_identity_provider: "//iam.googleapis.com/x".to_string(),
                service_account: Some("reports@acme.iam.gserviceaccount.com".to_string()),
                scope: default_gcp_scope(),
            }),
            &role(),
        );
        assert_eq!(impersonated["exchange"]["steps"].as_array().map(Vec::len), Some(2));
    }

    #[test]
    fn azure_instructions_carry_no_client_secret() {
        let value = FederationEngine::instructions(
            &config(ProviderTarget::Azure {
                tenant_id: "tenant".to_string(),
                client_id: "client".to_string(),
                scope: default_graph_scope(),
            }),
            &role(),
        );
        let form = &value["exchange"]["form"];
        assert_eq!(form["client_assertion"], TOKEN_PLACEHOLDER);
        assert!(
            form.get("client_secret").is_none(),
            "a federated exchange must never carry a client secret"
        );
    }

    /// The claims block is what stops an operator pinning the trust policy to
    /// the issuer alone, so it must always name all three.
    #[test]
    fn instructions_always_state_the_required_claims() {
        let value = FederationEngine::instructions(
            &config(ProviderTarget::Azure {
                tenant_id: "t".to_string(),
                client_id: "c".to_string(),
                scope: default_graph_scope(),
            }),
            &role(),
        );
        let claims = &value["your_token_must_present"];
        assert_eq!(claims["iss"], "https://oidc.example.com");
        assert_eq!(claims["aud"], "sts.amazonaws.com");
        assert_eq!(claims["sub"], "system:serviceaccount:apps:report-service");
    }

    #[tokio::test]
    async fn generate_refuses_and_points_at_the_roles_path() {
        let engine = FederationEngine::new();
        struct NoStorage;
        #[async_trait]
        impl StorageBackend for NoStorage {
            async fn get(
                &self,
                _: &str,
            ) -> secrets_core::storage::StorageResult<Option<secrets_core::storage::StorageEntry>> {
                Ok(None)
            }
            async fn put(
                &self,
                _: &str,
                _: secrets_core::storage::StorageEntry,
            ) -> secrets_core::storage::StorageResult<()> {
                Ok(())
            }
            async fn delete(&self, _: &str) -> secrets_core::storage::StorageResult<()> {
                Ok(())
            }
            async fn list(&self, _: &str) -> secrets_core::storage::StorageResult<Vec<String>> {
                Ok(vec![])
            }
        }
        let err = engine.generate(&NoStorage, "report-service").await.unwrap_err();
        let message = err.to_string();
        assert!(message.contains("federation/roles/report-service"), "{message}");
        assert!(message.contains("nothing to lease"), "{message}");
    }

    #[test]
    fn doc_agrees_with_its_shape() {
        let doc = FederationEngine::new().doc();
        assert_eq!(doc.shape, CredentialShape::Federation);
        assert_eq!(doc.revocable, doc.shape.revocable());
        assert!(doc.root_credential.contains("none"));
    }
}
