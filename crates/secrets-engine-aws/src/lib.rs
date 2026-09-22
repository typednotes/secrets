//! AWS credentials, in the two flavours the platform actually offers.
//!
//! `assumed_role` mints an STS session: short, narrowable to a bucket and
//! prefix by a session policy, and **impossible to revoke**. `iam_user` mints a
//! throwaway IAM user with one access key, mirroring the Postgres engine's
//! create/drop pattern: long-lived until deleted, but genuinely revocable.
//!
//! Those are different promises, so a credential declares its own guarantees
//! rather than inheriting this engine's headline shape — see
//! `GeneratedCredential::with_shape`.
//!
//! See `docs/delegation/aws.md` for the mechanism and
//! `docs/delegation/setup/aws.md` for the operator walkthrough.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use aws_config::{BehaviorVersion, Region, SdkConfig};
use aws_sdk_iam::error::ProvideErrorMetadata;
use aws_sdk_sts::types::PolicyDescriptorType;
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

const STORE: ConfigRoleStore = ConfigRoleStore::new("aws/config/", "aws/roles/");
const MOUNT: &str = "aws/creds/";

/// STS refuses anything outside this envelope, and a request above the role's
/// own `MaxSessionDuration` fails outright rather than being truncated — so
/// it is worth rejecting locally with a clear message instead of sending a
/// doomed call.
const MIN_SESSION_SECONDS: i64 = 900;
const MAX_SESSION_SECONDS: i64 = 43200;

/// IAM's limits on the names we generate.
const IAM_MAX_USER_NAME: usize = 64;
const STS_MAX_SESSION_NAME: usize = 64;

/// One inline policy per generated user, named so `revoke()` can find it
/// without listing.
const INLINE_POLICY_NAME: &str = "secrets-server-lease";

/// How the server authenticates to AWS for one target account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsConfig {
    pub region: String,
    /// `default` walks AWS's own provider chain — instance profile, IRSA, ECS
    /// task role, environment. `static` uses the key pair below.
    #[serde(default = "default_auth")]
    pub auth: AuthMode,
    #[serde(default)]
    pub access_key_id: Option<String>,
    #[serde(default)]
    pub secret_access_key: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    Default,
    Static,
}

fn default_auth() -> AuthMode {
    AuthMode::Default
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialType {
    AssumedRole,
    IamUser,
}

fn default_credential_type() -> CredentialType {
    CredentialType::AssumedRole
}

/// Fifteen minutes: the shortest STS allows, and the right default for a
/// credential nobody can recall.
fn default_ttl_seconds() -> i64 {
    MIN_SESSION_SECONDS
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleConfig {
    /// Which `aws/config/{name}` document to authenticate with.
    pub target: String,
    #[serde(default = "default_credential_type")]
    pub credential_type: CredentialType,
    /// Required for `assumed_role`.
    #[serde(default)]
    pub role_arn: Option<String>,
    /// Narrows the session. Permissions end up as the *intersection* of this
    /// and the role's own policy, so it can only ever subtract.
    #[serde(default)]
    pub session_policy: Option<serde_json::Value>,
    #[serde(default)]
    pub session_policy_arns: Vec<String>,
    /// Confused-deputy guard when assuming a role in an account you do not own.
    #[serde(default)]
    pub external_id: Option<String>,
    /// Inline policy attached to a generated `iam_user`. Without it the user
    /// can do nothing, which is the safe default but rarely the useful one.
    #[serde(default)]
    pub user_policy: Option<serde_json::Value>,
    #[serde(default = "default_ttl_seconds")]
    pub default_ttl_seconds: i64,
}

#[derive(Default)]
pub struct AwsEngine {
    /// Building an `SdkConfig` can reach out to IMDS, so keep one per target
    /// rather than paying that on every mint. Never held across an await.
    configs: Mutex<HashMap<String, SdkConfig>>,
}

impl AwsEngine {
    pub fn new() -> Self {
        Self::default()
    }

    async fn sdk_config(&self, target: &str, config: &AwsConfig) -> EngineResult<SdkConfig> {
        if let Some(cached) = self
            .configs
            .lock()
            .expect("aws config cache poisoned")
            .get(target)
        {
            return Ok(cached.clone());
        }

        let mut loader = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(config.region.clone()));

        if config.auth == AuthMode::Static {
            let (Some(access_key_id), Some(secret_access_key)) =
                (&config.access_key_id, &config.secret_access_key)
            else {
                return Err(EngineError::InvalidRequest(
                    "auth 'static' needs both access_key_id and secret_access_key".into(),
                ));
            };
            loader = loader.credentials_provider(aws_sdk_sts::config::Credentials::new(
                access_key_id,
                secret_access_key,
                None,
                None,
                "secrets-server-static",
            ));
        }

        let sdk = loader.load().await;
        self.configs
            .lock()
            .expect("aws config cache poisoned")
            .insert(target.to_string(), sdk.clone());
        Ok(sdk)
    }

    async fn assume_role(
        &self,
        sdk: &SdkConfig,
        role_name: &str,
        role: &RoleConfig,
    ) -> EngineResult<GeneratedCredential> {
        let role_arn = role.role_arn.as_deref().ok_or_else(|| {
            EngineError::InvalidRequest(
                "role_arn is required for credential_type 'assumed_role'".into(),
            )
        })?;
        let duration = validate_session_ttl(role.default_ttl_seconds)?;
        let session_name = unique_name("s", role_name, 8, STS_MAX_SESSION_NAME);

        let mut request = aws_sdk_sts::Client::new(sdk)
            .assume_role()
            .role_arn(role_arn)
            .role_session_name(&session_name)
            .duration_seconds(duration);

        if let Some(policy) = &role.session_policy {
            request = request.policy(
                serde_json::to_string(policy)
                    .map_err(|e| EngineError::InvalidRequest(format!("bad session_policy: {e}")))?,
            );
        }
        for arn in &role.session_policy_arns {
            request = request.policy_arns(
                PolicyDescriptorType::builder()
                    .arn(arn)
                    .build(),
            );
        }
        if let Some(external_id) = &role.external_id {
            request = request.external_id(external_id);
        }

        let output = request
            .send()
            .await
            .map_err(|e| EngineError::Provider(format!("AWS AssumeRole failed: {}", chain(&e))))?;
        let credentials = output
            .credentials()
            .ok_or_else(|| EngineError::Provider("AWS returned no credentials".into()))?;

        // STS's own expiry, not the TTL we asked for: a lease must never
        // outlive the credential it governs.
        let expires_at = to_chrono(credentials.expiration())?;
        let now = Utc::now();

        let lease = Lease {
            id: Uuid::new_v4(),
            token_id_hash: String::new(),
            engine_mount: MOUNT.to_string(),
            // Nothing here is used to revoke, because nothing can — it is kept
            // so an operator reading the lease can tell what was handed out.
            internal_data: json!({
                "credential_type": "assumed_role",
                "target": role.target,
                "role": role_name,
                "role_arn": role_arn,
                "session_name": session_name,
            }),
            issued_at: now,
            expires_at,
        };

        Ok(GeneratedCredential::new(
            json!({
                "access_key_id": credentials.access_key_id(),
                "secret_access_key": credentials.secret_access_key(),
                "session_token": credentials.session_token(),
                "expiration": expires_at,
            }),
            lease,
            scope_description(role, role_arn),
        ))
    }

    async fn iam_user(
        &self,
        sdk: &SdkConfig,
        role_name: &str,
        role: &RoleConfig,
    ) -> EngineResult<GeneratedCredential> {
        if role.default_ttl_seconds <= 0 {
            return Err(EngineError::InvalidRequest(
                "default_ttl_seconds must be positive".into(),
            ));
        }

        let iam = aws_sdk_iam::Client::new(sdk);
        let user_name = unique_name("v", role_name, 12, IAM_MAX_USER_NAME);

        iam.create_user()
            .user_name(&user_name)
            .send()
            .await
            .map_err(|e| EngineError::Provider(format!("AWS CreateUser failed: {}", chain(&e))))?;

        // From here on, any failure would otherwise leave an orphaned IAM user
        // that no lease knows about, so unwind before returning.
        if let Some(policy) = &role.user_policy {
            let document = match serde_json::to_string(policy) {
                Ok(document) => document,
                Err(e) => {
                    cleanup_user(&iam, &user_name, false).await;
                    return Err(EngineError::InvalidRequest(format!("bad user_policy: {e}")));
                }
            };
            if let Err(e) = iam
                .put_user_policy()
                .user_name(&user_name)
                .policy_name(INLINE_POLICY_NAME)
                .policy_document(document)
                .send()
                .await
            {
                cleanup_user(&iam, &user_name, false).await;
                return Err(EngineError::Provider(format!(
                    "AWS PutUserPolicy failed: {}",
                    chain(&e)
                )));
            }
        }

        let key_output = match iam.create_access_key().user_name(&user_name).send().await {
            Ok(output) => output,
            Err(e) => {
                cleanup_user(&iam, &user_name, role.user_policy.is_some()).await;
                return Err(EngineError::Provider(format!(
                    "AWS CreateAccessKey failed: {}",
                    chain(&e)
                )));
            }
        };
        let Some(key) = key_output.access_key() else {
            cleanup_user(&iam, &user_name, role.user_policy.is_some()).await;
            return Err(EngineError::Provider(
                "AWS CreateAccessKey returned no access key".into(),
            ));
        };

        let now = Utc::now();
        let lease = Lease {
            id: Uuid::new_v4(),
            token_id_hash: String::new(),
            engine_mount: MOUNT.to_string(),
            internal_data: json!({
                "credential_type": "iam_user",
                "target": role.target,
                "role": role_name,
                "user_name": user_name,
                "access_key_id": key.access_key_id(),
                "has_inline_policy": role.user_policy.is_some(),
            }),
            issued_at: now,
            // An access key has no intrinsic expiry, so the reaper is the only
            // clock — a missed revocation leaves a permanent credential.
            expires_at: now + chrono::Duration::seconds(role.default_ttl_seconds),
        };

        let credential = GeneratedCredential::new(
            json!({
                "access_key_id": key.access_key_id(),
                "secret_access_key": key.secret_access_key(),
                "user_name": user_name,
            }),
            lease,
            scope_description(role, &format!("iam-user:{user_name}")),
        );

        Ok(match guarantees_for(CredentialType::IamUser) {
            Some((shape, effect)) => credential.with_shape(shape, effect),
            None => credential,
        })
    }
}

/// The guarantees a credential carries when they differ from this engine's
/// headline shape. Keeping this a pure function is what lets the override be
/// tested without touching AWS.
fn guarantees_for(credential_type: CredentialType) -> Option<(CredentialShape, &'static str)> {
    match credential_type {
        // Inherits the engine's headline shape: an STS session cannot be recalled.
        CredentialType::AssumedRole => None,
        CredentialType::IamUser => Some((
            CredentialShape::MintAndRevoke,
            "deletes the access key, then the inline user policy, then the IAM user, \
             so the credential stops working. IAM is eventually consistent, so allow \
             a few seconds for the deletion to take effect everywhere.",
        )),
    }
}

/// Best-effort unwind after a partial `iam_user` creation. Errors are logged
/// rather than returned: the caller is already failing, and the useful error is
/// the original one.
async fn cleanup_user(iam: &aws_sdk_iam::Client, user_name: &str, has_policy: bool) {
    if has_policy
        && let Err(e) = iam
            .delete_user_policy()
            .user_name(user_name)
            .policy_name(INLINE_POLICY_NAME)
            .send()
            .await
    {
        tracing::warn!(user_name, error = %chain(&e), "failed to unwind inline policy");
    }
    if let Err(e) = iam.delete_user().user_name(user_name).send().await {
        tracing::warn!(user_name, error = %chain(&e), "leaked an IAM user after a failed mint");
    }
}

fn validate_session_ttl(seconds: i64) -> EngineResult<i32> {
    if !(MIN_SESSION_SECONDS..=MAX_SESSION_SECONDS).contains(&seconds) {
        return Err(EngineError::InvalidRequest(format!(
            "default_ttl_seconds must be between {MIN_SESSION_SECONDS} and \
             {MAX_SESSION_SECONDS} for an assumed role, got {seconds}. The role's own \
             MaxSessionDuration may cap it further."
        )));
    }
    Ok(seconds as i32)
}

/// IAM and STS both accept only `[\w+=,.@-]` and cap names at 64 characters, so
/// a role name goes through unchanged only if it happens to be tame.
fn unique_name(prefix: &str, role: &str, suffix_len: usize, max_len: usize) -> String {
    let suffix: String = Uuid::new_v4().simple().to_string().chars().take(suffix_len).collect();
    let sanitized: String = role
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "+=,.@-_".contains(c) {
                c
            } else {
                '-'
            }
        })
        .collect();
    let budget = max_len.saturating_sub(prefix.len() + suffix.len() + 2);
    let head: String = sanitized.chars().take(budget).collect();
    format!("{prefix}-{head}-{suffix}")
}

fn scope_description(role: &RoleConfig, principal: &str) -> Vec<String> {
    let mut scoped = vec![principal.to_string()];
    match &role.session_policy {
        Some(_) => scoped.push("session_policy: applied (permissions are the intersection)".to_string()),
        None if role.credential_type == CredentialType::AssumedRole => scoped
            .push("session_policy: NONE — the session has the role's full permissions".to_string()),
        None => {}
    }
    if role.user_policy.is_none() && role.credential_type == CredentialType::IamUser {
        scoped.push("user_policy: NONE — the generated user can do nothing".to_string());
    }
    scoped.extend(
        role.session_policy_arns
            .iter()
            .map(|arn| format!("policy_arn:{arn}")),
    );
    if let Some(external_id) = &role.external_id {
        scoped.push(format!("external_id:{external_id}"));
    }
    scoped
}

fn to_chrono(timestamp: &aws_sdk_sts::primitives::DateTime) -> EngineResult<DateTime<Utc>> {
    DateTime::from_timestamp(timestamp.secs(), 0)
        .ok_or_else(|| EngineError::Provider("AWS returned an unrepresentable expiry".into()))
}

/// AWS SDK errors put the useful detail in the source chain, so `to_string()`
/// alone reports little more than "service error".
fn chain(error: &dyn std::error::Error) -> String {
    let mut parts = vec![error.to_string()];
    let mut source = error.source();
    while let Some(current) = source {
        parts.push(current.to_string());
        source = current.source();
    }
    parts.join(": ")
}

#[async_trait]
impl SecretsEngine for AwsEngine {
    fn doc(&self) -> EngineDoc {
        EngineDoc {
            provider: "AWS".to_string(),
            mechanism: "STS AssumeRole sessions narrowed by a session policy \
                        (credential_type 'assumed_role'), or a throwaway IAM user \
                        with one access key (credential_type 'iam_user')"
                .to_string(),
            shape: CredentialShape::MintExpiryOnly,
            revocable: false,
            revoke_effect: "for an assumed role: NOTHING. AWS cannot invalidate an \
                            issued STS session, so revoking the lease only deletes our \
                            record of it and the credential keeps working until it \
                            expires — keep TTLs short, that is the whole containment \
                            story. Roles with credential_type 'iam_user' are genuinely \
                            revocable and say so in their own _doc."
                .to_string(),
            ttl: TtlDoc::range(
                MIN_SESSION_SECONDS,
                MAX_SESSION_SECONDS,
                "STS allows 15 minutes to 12 hours, further capped by the role's own \
                 MaxSessionDuration. An 'iam_user' credential has no intrinsic expiry \
                 at all — its lease TTL is enforced only by our reaper.",
            ),
            scoping: "an inline session policy plus up to 10 managed policy ARNs, \
                      which narrow an assumed role to (say) one bucket and prefix. \
                      Permissions are the intersection with the role's own policy, so \
                      a session policy can only ever subtract. An 'iam_user' is scoped \
                      by its inline user_policy instead."
                .to_string(),
            root_credential: "ideally NONE: run the server on EC2, ECS or EKS and let \
                              the instance profile, task role or IRSA supply rotating \
                              credentials via the default provider chain (auth \
                              'default'). Only use auth 'static' — an IAM user access \
                              key in aws/config/{target} — where no attached role is \
                              available, and rotate it."
                .to_string(),
            paths: vec![
                PathDoc::new(
                    "aws/config/{target}",
                    &["POST", "GET", "DELETE"],
                    "sudo",
                    "register the region and how to authenticate. GET reports only \
                     whether it is configured — keys are never returned.",
                ),
                PathDoc::new(
                    "aws/roles/{role}",
                    &["POST", "GET", "DELETE"],
                    "create / read / sudo",
                    "define one consumer's credential type, role ARN, session policy \
                     and TTL",
                ),
                PathDoc::new(
                    "aws/creds/{role}",
                    &["GET"],
                    "read",
                    "mint a session or an IAM user access key, and open a lease",
                ),
                PathDoc::new("aws/help", &["GET"], "authenticated", "this document"),
            ],
            docs_url: Some("docs/delegation/aws.md".to_string()),
            caveats: vec![
                "No STS session can be revoked. The console's \"revoke active \
                 sessions\" button only attaches a role-wide Deny conditioned on \
                 aws:TokenIssueTime, which also kills every innocent session issued \
                 from that role before that moment — revocation is per-role, never \
                 per-session. Give each consumer its own role if you need precision."
                    .to_string(),
                "DurationSeconds must be 900–43200 and within the role's own \
                 MaxSessionDuration; exceeding the latter fails the call rather than \
                 truncating it."
                    .to_string(),
                "Role chaining — an assumed role assuming another role — caps the \
                 resulting session at 1 hour regardless of any other setting."
                    .to_string(),
                "Session policies only ever narrow. They cannot grant a permission \
                 the role itself lacks, so a policy that looks ignored usually means \
                 the role never had that permission."
                    .to_string(),
                "IAM allows only two access keys per user, which is why 'iam_user' \
                 creates a user per lease rather than keys on a shared user."
                    .to_string(),
                "IAM is eventually consistent: a freshly created access key may not \
                 authenticate for a few seconds, and a deleted one may keep working \
                 just as briefly. Retry rather than treating either as failure."
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
        STORE.handle_write::<AwsConfig, RoleConfig>(storage, path, data).await
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
        let config: AwsConfig = STORE.require_config(storage, &role.target).await?;
        let sdk = self.sdk_config(&role.target, &config).await?;

        match role.credential_type {
            CredentialType::AssumedRole => self.assume_role(&sdk, role_name, &role).await,
            CredentialType::IamUser => self.iam_user(&sdk, role_name, &role).await,
        }
    }

    async fn revoke(&self, storage: &dyn StorageBackend, lease: &Lease) -> EngineResult<()> {
        let credential_type = lease.internal_data["credential_type"]
            .as_str()
            .unwrap_or("assumed_role");

        if credential_type != "iam_user" {
            // Deliberately not an error. The reaper needs to clear the lease
            // record, and failing here would only make it retry forever against
            // a provider that has no revocation API at all.
            tracing::warn!(
                lease_id = %lease.id,
                "AWS cannot revoke an issued STS session; the credential remains \
                 valid until its expiry. Deleting the lease record only."
            );
            return Ok(());
        }

        let user_name = lease.internal_data["user_name"]
            .as_str()
            .ok_or_else(|| EngineError::Other("lease missing 'user_name'".into()))?;
        let target = lease.internal_data["target"]
            .as_str()
            .ok_or_else(|| EngineError::Other("lease missing 'target'".into()))?;
        let access_key_id = lease.internal_data["access_key_id"].as_str();

        let config: AwsConfig = STORE.require_config(storage, target).await?;
        let sdk = self.sdk_config(target, &config).await?;
        let iam = aws_sdk_iam::Client::new(&sdk);

        // Every step tolerates "already gone" so the reaper can retry a
        // partially-completed revocation without getting stuck.
        if let Some(access_key_id) = access_key_id
            && let Err(e) = iam
                .delete_access_key()
                .user_name(user_name)
                .access_key_id(access_key_id)
                .send()
                .await
            && !is_missing(&e)
        {
            return Err(EngineError::Provider(format!(
                "AWS DeleteAccessKey failed: {}",
                chain(&e)
            )));
        }

        if lease.internal_data["has_inline_policy"]
            .as_bool()
            .unwrap_or(true)
            && let Err(e) = iam
                .delete_user_policy()
                .user_name(user_name)
                .policy_name(INLINE_POLICY_NAME)
                .send()
                .await
            && !is_missing(&e)
        {
            return Err(EngineError::Provider(format!(
                "AWS DeleteUserPolicy failed: {}",
                chain(&e)
            )));
        }

        if let Err(e) = iam.delete_user().user_name(user_name).send().await
            && !is_missing(&e)
        {
            return Err(EngineError::Provider(format!(
                "AWS DeleteUser failed: {}",
                chain(&e)
            )));
        }

        Ok(())
    }
}

/// IAM reports an already-deleted resource as `NoSuchEntity`, which is success
/// as far as revocation is concerned. Matching the error *code* rather than the
/// message keeps the reaper's retry path from breaking on a wording change.
fn is_missing<E: ProvideErrorMetadata>(error: &E) -> bool {
    error.code() == Some("NoSuchEntity")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role(credential_type: CredentialType) -> RoleConfig {
        RoleConfig {
            target: "production".to_string(),
            credential_type,
            role_arn: Some("arn:aws:iam::123456789012:role/reports".to_string()),
            session_policy: None,
            session_policy_arns: vec![],
            external_id: None,
            user_policy: None,
            default_ttl_seconds: 900,
        }
    }

    #[test]
    fn generated_names_fit_the_provider_limits() {
        let long_role = "a-very-long-consumer-name-".repeat(10);
        let user = unique_name("v", &long_role, 12, IAM_MAX_USER_NAME);
        let session = unique_name("s", &long_role, 8, STS_MAX_SESSION_NAME);
        assert!(user.len() <= IAM_MAX_USER_NAME, "{} chars", user.len());
        assert!(session.len() <= STS_MAX_SESSION_NAME, "{} chars", session.len());
    }

    /// IAM rejects anything outside `[\w+=,.@-]`, so a role name containing a
    /// slash or a space must not reach AWS verbatim.
    #[test]
    fn generated_names_are_sanitised() {
        let name = unique_name("v", "team/reports svc!", 12, IAM_MAX_USER_NAME);
        assert!(
            name.chars()
                .all(|c| c.is_ascii_alphanumeric() || "+=,.@-_".contains(c)),
            "{name} contains a character IAM will reject"
        );
    }

    #[test]
    fn generated_names_are_unique_per_call() {
        let first = unique_name("v", "reports", 12, IAM_MAX_USER_NAME);
        let second = unique_name("v", "reports", 12, IAM_MAX_USER_NAME);
        assert_ne!(first, second);
    }

    /// The whole point of the per-credential override: an IAM user is
    /// revocable, an STS session is not, and the `_doc` must not average them.
    #[test]
    fn only_the_iam_user_path_claims_revocability() {
        assert!(guarantees_for(CredentialType::AssumedRole).is_none());
        let (shape, effect) = guarantees_for(CredentialType::IamUser).expect("override");
        assert_eq!(shape, CredentialShape::MintAndRevoke);
        assert!(shape.revocable());
        assert!(!effect.is_empty());
    }

    #[test]
    fn session_ttl_outside_the_sts_envelope_is_rejected() {
        assert!(validate_session_ttl(60).is_err());
        assert!(validate_session_ttl(MAX_SESSION_SECONDS + 1).is_err());
        assert_eq!(validate_session_ttl(900).unwrap(), 900);
        assert_eq!(
            validate_session_ttl(MAX_SESSION_SECONDS).unwrap(),
            MAX_SESSION_SECONDS as i32
        );
    }

    /// An unscoped session hands over the role's full permissions, so the
    /// consumer's `_doc` has to say that rather than showing an empty list.
    #[test]
    fn scope_description_calls_out_a_missing_policy() {
        let scoped = scope_description(&role(CredentialType::AssumedRole), "arn:aws:iam::1:role/r");
        assert!(scoped.iter().any(|s| s.contains("session_policy: NONE")));

        let mut scoped_role = role(CredentialType::AssumedRole);
        scoped_role.session_policy = Some(json!({"Version": "2012-10-17"}));
        let scoped = scope_description(&scoped_role, "arn:aws:iam::1:role/r");
        assert!(scoped.iter().any(|s| s.contains("intersection")));
    }

    #[test]
    fn scope_description_calls_out_a_powerless_iam_user() {
        let scoped = scope_description(&role(CredentialType::IamUser), "iam-user:v-reports-abc");
        assert!(scoped.iter().any(|s| s.contains("user_policy: NONE")));
    }

    #[test]
    fn doc_agrees_with_its_shape() {
        let doc = AwsEngine::new().doc();
        assert_eq!(doc.shape, CredentialShape::MintExpiryOnly);
        assert_eq!(doc.revocable, doc.shape.revocable());
        assert!(!doc.revocable, "an STS session cannot be revoked");
        assert!(
            doc.revoke_effect.contains("NOTHING"),
            "the doc must not dress up a no-op revocation"
        );
    }

    /// `assumed_role` without a role ARN is a configuration error worth
    /// catching before it becomes a confusing AWS error.
    #[test]
    fn credential_type_defaults_to_assumed_role() {
        let parsed: RoleConfig = serde_json::from_value(json!({
            "target": "production",
            "role_arn": "arn:aws:iam::123456789012:role/reports",
        }))
        .expect("role should parse with defaults");
        assert_eq!(parsed.credential_type, CredentialType::AssumedRole);
        assert_eq!(parsed.default_ttl_seconds, MIN_SESSION_SECONDS);
    }

    #[test]
    fn config_defaults_to_the_provider_chain() {
        let parsed: AwsConfig = serde_json::from_value(json!({ "region": "eu-west-3" }))
            .expect("config should parse with defaults");
        assert_eq!(parsed.auth, AuthMode::Default);
        assert!(parsed.access_key_id.is_none());
    }
}
