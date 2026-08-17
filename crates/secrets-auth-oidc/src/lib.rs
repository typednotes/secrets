//! OIDC auth: interactive authorization-code login for humans and
//! JWT-bearer validation for machine-to-machine callers. Both modes share
//! the same discovery/JWKS cache and claims-to-policies mapping — the only
//! difference is where the JWT to verify comes from (a token-endpoint
//! response vs. handed to us directly).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use rand::Rng;
use secrets_core::auth::{AuthError, AuthMethod, AuthOutcome, AuthResult, LoginRequest};
use secrets_core::storage::{StorageBackend, StorageEntry};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

const CONFIG_PATH: &str = "auth/oidc/config";
const STATE_PREFIX: &str = "auth/oidc/state/";
const STATE_TTL_SECONDS: i64 = 300;
const DISCOVERY_CACHE_TTL: Duration = Duration::from_secs(600);
const JWKS_CACHE_TTL: Duration = Duration::from_secs(600);
const DEFAULT_TTL_SECONDS: i64 = 3600;

/// Operator-supplied IdP registration. One config for the whole server at
/// v1 — multiple OIDC providers would mean keying this (and `STATE_PREFIX`)
/// by provider name, deferred until actually needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    pub issuer_url: String,
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    pub redirect_url: String,
    /// Claim (array-of-strings or space-delimited string) mapped to policy
    /// names, mirroring Vault's "claims map to policies" model.
    #[serde(default = "default_policy_claim")]
    pub policy_claim: String,
    #[serde(default)]
    pub default_policies: Vec<String>,
}

fn default_policy_claim() -> String {
    "policies".to_string()
}

#[derive(Debug, Deserialize)]
struct Discovery {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PendingState {
    nonce: String,
    pkce_verifier: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    id_token: String,
}

/// Shared by both OIDC login modes: fetches and caches discovery documents
/// and JWKS per issuer so every login doesn't round-trip to the IdP.
pub struct OidcAuthMethod {
    http: reqwest::Client,
    discovery_cache: RwLock<HashMap<String, (Instant, Discovery)>>,
    jwks_cache: RwLock<HashMap<String, (Instant, JwkSet)>>,
}

impl Default for OidcAuthMethod {
    fn default() -> Self {
        Self::new()
    }
}

impl OidcAuthMethod {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::new(),
            discovery_cache: RwLock::new(HashMap::new()),
            jwks_cache: RwLock::new(HashMap::new()),
        }
    }

    pub async fn load_config(storage: &dyn StorageBackend) -> AuthResult<Option<OidcConfig>> {
        let Some(entry) = storage.get(CONFIG_PATH).await? else {
            return Ok(None);
        };
        Ok(Some(
            serde_json::from_slice(&entry.value).map_err(|e| AuthError::Other(e.to_string()))?,
        ))
    }

    pub async fn save_config(storage: &dyn StorageBackend, config: &OidcConfig) -> AuthResult<()> {
        let value = serde_json::to_vec(config).map_err(|e| AuthError::Other(e.to_string()))?;
        storage
            .put(
                CONFIG_PATH,
                StorageEntry {
                    value,
                    expires_at: None,
                },
            )
            .await?;
        Ok(())
    }

    async fn discovery_for(&self, config: &OidcConfig) -> AuthResult<Discovery> {
        if let Some((fetched_at, discovery)) = self.discovery_cache.read().await.get(&config.issuer_url)
            && fetched_at.elapsed() < DISCOVERY_CACHE_TTL
        {
            return Ok(Discovery {
                authorization_endpoint: discovery.authorization_endpoint.clone(),
                token_endpoint: discovery.token_endpoint.clone(),
                jwks_uri: discovery.jwks_uri.clone(),
            });
        }

        let url = format!(
            "{}/.well-known/openid-configuration",
            config.issuer_url.trim_end_matches('/')
        );
        let discovery: Discovery = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| AuthError::Other(e.to_string()))?
            .json()
            .await
            .map_err(|e| AuthError::Other(e.to_string()))?;

        let clone = Discovery {
            authorization_endpoint: discovery.authorization_endpoint.clone(),
            token_endpoint: discovery.token_endpoint.clone(),
            jwks_uri: discovery.jwks_uri.clone(),
        };
        self.discovery_cache
            .write()
            .await
            .insert(config.issuer_url.clone(), (Instant::now(), discovery));
        Ok(clone)
    }

    async fn fetch_jwks(&self, jwks_uri: &str) -> AuthResult<JwkSet> {
        self.http
            .get(jwks_uri)
            .send()
            .await
            .map_err(|e| AuthError::Other(e.to_string()))?
            .json::<JwkSet>()
            .await
            .map_err(|e| AuthError::Other(e.to_string()))
    }

    async fn decoding_key_for(&self, config: &OidcConfig, kid: &str) -> AuthResult<(DecodingKey, Algorithm)> {
        let jwks_uri = self.discovery_for(config).await?.jwks_uri;

        let cached = self.jwks_cache.read().await.get(&config.issuer_url).cloned();
        let needs_fetch = match &cached {
            Some((fetched_at, jwks)) => {
                fetched_at.elapsed() >= JWKS_CACHE_TTL || jwks.find(kid).is_none()
            }
            None => true,
        };

        let jwks = if needs_fetch {
            let jwks = self.fetch_jwks(&jwks_uri).await?;
            self.jwks_cache
                .write()
                .await
                .insert(config.issuer_url.clone(), (Instant::now(), jwks.clone()));
            jwks
        } else {
            cached.unwrap().1
        };

        let jwk = jwks.find(kid).ok_or_else(|| AuthError::Other(format!("unknown signing key '{kid}'")))?;
        let algorithm = algorithm_for(jwk)?;
        let decoding_key =
            DecodingKey::from_jwk(jwk).map_err(|e| AuthError::Other(format!("invalid JWK: {e}")))?;
        Ok((decoding_key, algorithm))
    }

    async fn verify_jwt(&self, config: &OidcConfig, token: &str) -> AuthResult<Value> {
        let header = decode_header(token).map_err(|e| AuthError::Other(e.to_string()))?;
        let kid = header.kid.ok_or_else(|| AuthError::Other("jwt is missing a 'kid' header".into()))?;
        let (decoding_key, algorithm) = self.decoding_key_for(config, &kid).await?;

        let mut validation = Validation::new(algorithm);
        validation.set_audience(std::slice::from_ref(&config.client_id));
        validation.set_issuer(std::slice::from_ref(&config.issuer_url));

        let data = decode::<Value>(token, &decoding_key, &validation)
            .map_err(|_| AuthError::InvalidCredentials)?;
        Ok(data.claims)
    }

    /// Builds the URL to redirect a human to for interactive login,
    /// stashing the CSRF state / nonce / PKCE verifier so `login()` can
    /// validate them when the IdP calls back.
    pub async fn authorize_url(&self, storage: &dyn StorageBackend) -> AuthResult<String> {
        let config = Self::load_config(storage)
            .await?
            .ok_or_else(|| AuthError::Other("OIDC is not configured".into()))?;
        let discovery = self.discovery_for(&config).await?;

        let state = random_url_safe(24);
        let nonce = random_url_safe(24);
        let pkce_verifier = random_url_safe(32);
        let code_challenge = code_challenge_s256(&pkce_verifier);

        let pending = PendingState {
            nonce: nonce.clone(),
            pkce_verifier,
        };
        let value = serde_json::to_vec(&pending).map_err(|e| AuthError::Other(e.to_string()))?;
        storage
            .put(
                &format!("{STATE_PREFIX}{state}"),
                StorageEntry {
                    value,
                    expires_at: Some(Utc::now() + chrono::Duration::seconds(STATE_TTL_SECONDS)),
                },
            )
            .await?;

        Ok(format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
            discovery.authorization_endpoint,
            urlencoding::encode(&config.client_id),
            urlencoding::encode(&config.redirect_url),
            urlencoding::encode("openid profile email"),
            urlencoding::encode(&state),
            urlencoding::encode(&nonce),
            urlencoding::encode(&code_challenge),
        ))
    }

    async fn login_auth_code(
        &self,
        storage: &dyn StorageBackend,
        code: String,
        state: String,
    ) -> AuthResult<AuthOutcome> {
        let config = Self::load_config(storage)
            .await?
            .ok_or_else(|| AuthError::Other("OIDC is not configured".into()))?;

        let state_path = format!("{STATE_PREFIX}{state}");
        let entry = storage.get(&state_path).await?.ok_or(AuthError::InvalidCredentials)?;
        storage.delete(&state_path).await?;
        let pending: PendingState =
            serde_json::from_slice(&entry.value).map_err(|e| AuthError::Other(e.to_string()))?;

        let discovery = self.discovery_for(&config).await?;
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", config.redirect_url.as_str()),
            ("client_id", config.client_id.as_str()),
            ("code_verifier", pending.pkce_verifier.as_str()),
        ];
        if let Some(secret) = &config.client_secret {
            form.push(("client_secret", secret.as_str()));
        }

        let response: TokenResponse = self
            .http
            .post(&discovery.token_endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|e| AuthError::Other(e.to_string()))?
            .json()
            .await
            .map_err(|e| AuthError::Other(e.to_string()))?;

        let claims = self.verify_jwt(&config, &response.id_token).await?;
        if claims.get("nonce").and_then(Value::as_str) != Some(pending.nonce.as_str()) {
            return Err(AuthError::InvalidCredentials);
        }

        Ok(outcome_from_claims(&claims, &config))
    }

    async fn login_bearer_jwt(&self, storage: &dyn StorageBackend, jwt: String) -> AuthResult<AuthOutcome> {
        let config = Self::load_config(storage)
            .await?
            .ok_or_else(|| AuthError::Other("OIDC is not configured".into()))?;
        let claims = self.verify_jwt(&config, &jwt).await?;
        Ok(outcome_from_claims(&claims, &config))
    }
}

#[async_trait]
impl AuthMethod for OidcAuthMethod {
    async fn login(&self, storage: &dyn StorageBackend, request: LoginRequest) -> AuthResult<AuthOutcome> {
        match request {
            LoginRequest::OidcAuthCodeCallback { code, state } => {
                self.login_auth_code(storage, code, state).await
            }
            LoginRequest::OidcBearerJwt { jwt } => self.login_bearer_jwt(storage, jwt).await,
            LoginRequest::UserPass { .. } => {
                Err(AuthError::InvalidRequest("expected an OIDC login request".into()))
            }
        }
    }
}

fn outcome_from_claims(claims: &Value, config: &OidcConfig) -> AuthOutcome {
    let display_name = claims
        .get("email")
        .or_else(|| claims.get("preferred_username"))
        .or_else(|| claims.get("sub"))
        .and_then(Value::as_str)
        .unwrap_or("oidc-user")
        .to_string();

    let ttl_seconds = claims
        .get("exp")
        .and_then(Value::as_i64)
        .map(|exp| (exp - Utc::now().timestamp()).max(1))
        .unwrap_or(DEFAULT_TTL_SECONDS);

    AuthOutcome {
        policies: policies_from_claims(claims, config),
        display_name,
        ttl_seconds: Some(ttl_seconds),
    }
}

fn policies_from_claims(claims: &Value, config: &OidcConfig) -> Vec<String> {
    let policies = match claims.get(&config.policy_claim) {
        Some(Value::Array(values)) => values.iter().filter_map(Value::as_str).map(String::from).collect(),
        Some(Value::String(s)) => s.split_whitespace().map(String::from).collect(),
        _ => Vec::new(),
    };
    if policies.is_empty() {
        config.default_policies.clone()
    } else {
        policies
    }
}

fn algorithm_for(jwk: &jsonwebtoken::jwk::Jwk) -> AuthResult<Algorithm> {
    match &jwk.algorithm {
        AlgorithmParameters::RSA(_) => Ok(Algorithm::RS256),
        AlgorithmParameters::EllipticCurve(params) => match params.curve {
            jsonwebtoken::jwk::EllipticCurve::P256 => Ok(Algorithm::ES256),
            jsonwebtoken::jwk::EllipticCurve::P384 => Ok(Algorithm::ES384),
            _ => Err(AuthError::Other("unsupported elliptic curve JWK".into())),
        },
        _ => Err(AuthError::Other("unsupported JWK key type".into())),
    }
}

fn random_url_safe(len_bytes: usize) -> String {
    let mut bytes = vec![0u8; len_bytes];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn code_challenge_s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> OidcConfig {
        OidcConfig {
            issuer_url: "https://idp.example.com".to_string(),
            client_id: "client-1".to_string(),
            client_secret: None,
            redirect_url: "https://app.example.com/callback".to_string(),
            policy_claim: "policies".to_string(),
            default_policies: vec!["default".to_string()],
        }
    }

    #[test]
    fn maps_array_claim_to_policies() {
        let claims = serde_json::json!({ "policies": ["a", "b"] });
        assert_eq!(policies_from_claims(&claims, &config()), vec!["a", "b"]);
    }

    #[test]
    fn maps_space_delimited_claim_to_policies() {
        let claims = serde_json::json!({ "policies": "a b" });
        assert_eq!(policies_from_claims(&claims, &config()), vec!["a", "b"]);
    }

    #[test]
    fn falls_back_to_default_policies_when_claim_missing() {
        let claims = serde_json::json!({});
        assert_eq!(policies_from_claims(&claims, &config()), vec!["default"]);
    }

    #[test]
    fn pkce_challenge_is_deterministic_and_url_safe() {
        let verifier = "test-verifier-value";
        let challenge_a = code_challenge_s256(verifier);
        let challenge_b = code_challenge_s256(verifier);
        assert_eq!(challenge_a, challenge_b);
        assert!(!challenge_a.contains('+'));
        assert!(!challenge_a.contains('/'));
        assert!(!challenge_a.contains('='));
    }

    #[test]
    fn random_url_safe_values_are_unique() {
        assert_ne!(random_url_safe(16), random_url_safe(16));
    }
}
