use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router as AxumRouter};
use secrets_auth_oidc::OidcConfig;
use secrets_core::auth::{AuthError, AuthMethod, LoginRequest};
use secrets_core::engine::{EngineError, GeneratedCredential};
use secrets_core::lease;
use secrets_core::policy::{self, Capability, Policy};
use secrets_core::token::{self, TokenEntry};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::wiring::AppState;

pub fn router(state: Arc<AppState>) -> AxumRouter {
    AxumRouter::new()
        .route("/v1/sys/health", get(health))
        .route("/v1/auth/userpass/login", post(userpass_login))
        .route(
            "/v1/auth/userpass/users/{username}",
            get(read_user).post(write_user).delete(delete_user),
        )
        .route("/v1/auth/oidc/config", post(oidc_config_write))
        .route("/v1/auth/oidc/authorize_url", get(oidc_authorize_url))
        .route("/v1/auth/oidc/callback", get(oidc_callback))
        .route("/v1/auth/oidc/login", post(oidc_bearer_login))
        .route("/v1/auth/token/lookup-self", get(lookup_self))
        .route("/v1/auth/token/renew-self", post(renew_self))
        .route("/v1/auth/token/revoke-self", post(revoke_self))
        .route(
            "/v1/sys/policy/{name}",
            get(read_policy).post(write_policy).delete(delete_policy),
        )
        .route(
            "/v1/secret/data/{*path}",
            get(secret_read).post(secret_write).delete(secret_delete),
        )
        .route("/v1/secret/metadata/{*path}", get(secret_list))
        .route("/v1/sys/leases/revoke/{lease_id}", post(revoke_lease_handler))
        // Self-documentation. Generic over the mount so every engine — the
        // ones here today and the ones added later — is discoverable and
        // describable without touching this file again.
        .route("/v1/sys/rewrap", post(rewrap).get(rewrap_status))
        .route("/v1/sys/help", get(sys_help))
        .route("/v1/{mount}/help", get(engine_help))
        .route(
            "/v1/{mount}/config/{name}",
            get(engine_config_read)
                .post(engine_config_write)
                .delete(engine_config_delete),
        )
        .route(
            "/v1/{mount}/roles/{role}",
            get(engine_role_read).post(engine_role_write).delete(engine_role_delete),
        )
        .route("/v1/{mount}/creds/{role}", get(engine_generate_creds))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

fn err(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({ "error": message.into() }))).into_response()
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

// Err is a ready-to-send Response (large), by design: callers just `?`
// it straight back out of the handler.
#[allow(clippy::result_large_err)]
async fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<(String, TokenEntry), Response> {
    let token = bearer_token(headers).ok_or_else(|| err(StatusCode::UNAUTHORIZED, "missing bearer token"))?;
    let entry = token::lookup_token(state.storage.as_ref(), token)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| err(StatusCode::FORBIDDEN, "invalid or expired token"))?;
    Ok((token.to_string(), entry))
}

#[allow(clippy::result_large_err)]
async fn require_capability(
    state: &AppState,
    headers: &HeaderMap,
    path: &str,
    capability: Capability,
) -> Result<TokenEntry, Response> {
    let (_, entry) = authenticate(state, headers).await?;
    let policies = policy::load_policies(state.storage.as_ref(), &entry.policies)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if policy::evaluate(&policies, path, capability) {
        Ok(entry)
    } else {
        Err(err(StatusCode::FORBIDDEN, "permission denied"))
    }
}

/// Deliberately cheap. A load balancer probes this across every replica
/// forever, so it must not touch application data — it used to `list("")`,
/// which is a full scan of every key in storage. It also has to answer with a
/// non-2xx status when broken, or an LB would never take the node out of
/// rotation.
async fn health(State(state): State<Arc<AppState>>) -> Response {
    match state.storage.ping().await {
        Ok(()) => (StatusCode::OK, Json(json!({ "status": "ok" }))).into_response(),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "error", "detail": e.to_string() })),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct UserPassLoginRequest {
    username: String,
    password: String,
}

async fn userpass_login(
    State(state): State<Arc<AppState>>,
    Json(body): Json<UserPassLoginRequest>,
) -> Response {
    let outcome = match state
        .userpass
        .login(
            state.storage.as_ref(),
            LoginRequest::UserPass {
                username: body.username,
                password: body.password,
            },
        )
        .await
    {
        Ok(outcome) => outcome,
        Err(e) => return auth_error_response(e),
    };
    mint_token_response(&state, outcome).await
}

/// The capability path for managing one user. Per-user rather than one
/// `auth/userpass/users` gate, so a policy can delegate a single identity
/// (or a name prefix) without handing out every account including the admin.
fn user_path(username: &str) -> String {
    format!("auth/userpass/users/{username}")
}

#[derive(Deserialize)]
struct WriteUserRequest {
    password: String,
    policies: Vec<String>,
}

/// Creates or replaces a user. The body is extracted as a `Result` so that a
/// caller without `sudo` learns nothing from a malformed body, and a caller
/// with it gets the same `{"error": ...}` 400 as for any other invalid
/// input, rather than axum's plain-text 415/422.
async fn write_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(username): Path<String>,
    body: Result<Json<WriteUserRequest>, JsonRejection>,
) -> Response {
    if let Err(resp) = require_capability(&state, &headers, &user_path(&username), Capability::Sudo).await {
        return resp;
    }
    let Json(body) = match body {
        Ok(body) => body,
        Err(rejection) => return err(StatusCode::BAD_REQUEST, rejection.body_text()),
    };
    match secrets_auth_userpass::UserPassAuth::upsert_user(
        state.storage.as_ref(),
        &username,
        &body.password,
        body.policies,
    )
    .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => auth_error_response(e),
    }
}

/// Name and policies only — the hash never leaves the auth method.
async fn read_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> Response {
    if let Err(resp) = require_capability(&state, &headers, &user_path(&username), Capability::Sudo).await {
        return resp;
    }
    match secrets_auth_userpass::UserPassAuth::read_user(state.storage.as_ref(), &username).await {
        Ok(Some(user)) => Json(user).into_response(),
        Ok(None) => err(StatusCode::NOT_FOUND, "user not found"),
        Err(e) => auth_error_response(e),
    }
}

/// Stops future logins. Tokens the user already holds are not revoked: they
/// are not indexed by owner, so they keep working until they expire — an
/// hour after login or after the holder's last `renew-self`, which has no
/// maximum TTL.
async fn delete_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(username): Path<String>,
) -> Response {
    if let Err(resp) = require_capability(&state, &headers, &user_path(&username), Capability::Sudo).await {
        return resp;
    }
    match secrets_auth_userpass::UserPassAuth::delete_user(state.storage.as_ref(), &username).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => err(StatusCode::NOT_FOUND, "user not found"),
        Err(e) => auth_error_response(e),
    }
}

async fn mint_token_response(
    state: &AppState,
    outcome: secrets_core::auth::AuthOutcome,
) -> Response {
    let (raw_token, entry) = token::generate_token(outcome.policies, outcome.ttl_seconds);
    if let Err(e) = token::store_token(state.storage.as_ref(), &raw_token, &entry).await {
        return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }

    Json(json!({
        "auth": {
            "client_token": raw_token,
            "policies": entry.policies,
            "display_name": outcome.display_name,
            "lease_duration": outcome.ttl_seconds,
        }
    }))
    .into_response()
}

async fn oidc_config_write(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(config): Json<OidcConfig>,
) -> Response {
    if let Err(resp) = require_capability(&state, &headers, "auth/oidc/config", Capability::Sudo).await {
        return resp;
    }
    match secrets_auth_oidc::OidcAuthMethod::save_config(state.storage.as_ref(), &config).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn oidc_authorize_url(State(state): State<Arc<AppState>>) -> Response {
    match state.oidc.authorize_url(state.storage.as_ref()).await {
        Ok(url) => Json(json!({ "authorize_url": url })).into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

#[derive(Deserialize)]
struct OidcCallbackQuery {
    code: String,
    state: String,
}

async fn oidc_callback(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(query): axum::extract::Query<OidcCallbackQuery>,
) -> Response {
    let outcome = match state
        .oidc
        .login(
            state.storage.as_ref(),
            LoginRequest::OidcAuthCodeCallback {
                code: query.code,
                state: query.state,
            },
        )
        .await
    {
        Ok(outcome) => outcome,
        Err(e) => return auth_error_response(e),
    };
    mint_token_response(&state, outcome).await
}

#[derive(Deserialize)]
struct OidcBearerLoginRequest {
    jwt: String,
}

async fn oidc_bearer_login(
    State(state): State<Arc<AppState>>,
    Json(body): Json<OidcBearerLoginRequest>,
) -> Response {
    let outcome = match state
        .oidc
        .login(state.storage.as_ref(), LoginRequest::OidcBearerJwt { jwt: body.jwt })
        .await
    {
        Ok(outcome) => outcome,
        Err(e) => return auth_error_response(e),
    };
    mint_token_response(&state, outcome).await
}

async fn lookup_self(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    match authenticate(&state, &headers).await {
        Ok((_, entry)) => Json(json!({
            "policies": entry.policies,
            "created_at": entry.created_at,
            "expires_at": entry.expires_at,
        }))
        .into_response(),
        Err(resp) => resp,
    }
}

async fn renew_self(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let token = match bearer_token(&headers) {
        Some(t) => t.to_string(),
        None => return err(StatusCode::UNAUTHORIZED, "missing bearer token"),
    };
    match token::renew_token(state.storage.as_ref(), &token, 3600).await {
        Ok(Some(entry)) => Json(json!({ "expires_at": entry.expires_at })).into_response(),
        Ok(None) => err(StatusCode::FORBIDDEN, "invalid or expired token"),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn revoke_self(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let token = match bearer_token(&headers) {
        Some(t) => t.to_string(),
        None => return err(StatusCode::UNAUTHORIZED, "missing bearer token"),
    };
    let Some(entry) = (match token::lookup_token(state.storage.as_ref(), &token).await {
        Ok(entry) => entry,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }) else {
        return StatusCode::NO_CONTENT.into_response();
    };

    if let Err(e) =
        secrets_core::reaper::revoke_leases_for_token(state.storage.as_ref(), &state.router, &entry.id_hash)
            .await
    {
        return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }

    match token::revoke_token(state.storage.as_ref(), &token).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn read_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    if let Err(resp) = require_capability(&state, &headers, "sys/policy", Capability::Sudo).await {
        return resp;
    }
    match policy::get_policy(state.storage.as_ref(), &name).await {
        Ok(Some(policy)) => Json(policy).into_response(),
        Ok(None) => err(StatusCode::NOT_FOUND, "policy not found"),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn write_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(mut body): Json<Policy>,
) -> Response {
    if let Err(resp) = require_capability(&state, &headers, "sys/policy", Capability::Sudo).await {
        return resp;
    }
    body.name = name;
    match policy::store_policy(state.storage.as_ref(), &body).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn delete_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    if let Err(resp) = require_capability(&state, &headers, "sys/policy", Capability::Sudo).await {
        return resp;
    }
    match policy::delete_policy(state.storage.as_ref(), &name).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// Engine errors carry a pointer to the engine's own documentation, so a
/// caller who gets "operation not supported" can find out what this mount
/// *does* support without reading our source.
fn engine_error_response(e: EngineError, mount: &str) -> Response {
    let (status, message) = match e {
        EngineError::NotFound => (StatusCode::NOT_FOUND, "not found".to_string()),
        EngineError::Unsupported => (
            StatusCode::BAD_REQUEST,
            "operation not supported by this engine".to_string(),
        ),
        EngineError::InvalidRequest(msg) => (StatusCode::BAD_REQUEST, msg),
        EngineError::Provider(msg) => (StatusCode::BAD_GATEWAY, msg),
        e => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    (
        status,
        Json(json!({ "error": message, "hint": format!("GET /v1/{mount}/help") })),
    )
        .into_response()
}

fn auth_error_response(e: AuthError) -> Response {
    match e {
        AuthError::InvalidCredentials => err(StatusCode::UNAUTHORIZED, "invalid credentials"),
        AuthError::InvalidRequest(msg) => err(StatusCode::BAD_REQUEST, msg),
        e => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn secret_read(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(path): Path<String>,
) -> Response {
    let full_path = format!("secret/data/{path}");
    if let Err(resp) = require_capability(&state, &headers, &full_path, Capability::Read).await {
        return resp;
    }
    let Some((mount, remainder)) = state.router.resolve(&full_path) else {
        return err(StatusCode::NOT_FOUND, "no engine mounted at this path");
    };
    match mount.engine.read(state.storage.as_ref(), remainder).await {
        Ok(value) => Json(value).into_response(),
        Err(e) => engine_error_response(e, "secret"),
    }
}

async fn secret_write(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(path): Path<String>,
    Json(data): Json<serde_json::Value>,
) -> Response {
    let full_path = format!("secret/data/{path}");
    if let Err(resp) = require_capability(&state, &headers, &full_path, Capability::Create).await {
        return resp;
    }
    let Some((mount, remainder)) = state.router.resolve(&full_path) else {
        return err(StatusCode::NOT_FOUND, "no engine mounted at this path");
    };
    match mount.engine.write(state.storage.as_ref(), remainder, data).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => engine_error_response(e, "secret"),
    }
}

async fn secret_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(path): Path<String>,
) -> Response {
    let full_path = format!("secret/data/{path}");
    if let Err(resp) = require_capability(&state, &headers, &full_path, Capability::Delete).await {
        return resp;
    }
    let Some((mount, remainder)) = state.router.resolve(&full_path) else {
        return err(StatusCode::NOT_FOUND, "no engine mounted at this path");
    };
    match mount.engine.delete(state.storage.as_ref(), remainder).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => engine_error_response(e, "secret"),
    }
}

async fn secret_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(path): Path<String>,
) -> Response {
    let full_path = format!("secret/metadata/{path}");
    if let Err(resp) = require_capability(&state, &headers, &full_path, Capability::List).await {
        return resp;
    }
    let Some((mount, remainder)) = state.router.resolve(&full_path) else {
        return err(StatusCode::NOT_FOUND, "no engine mounted at this path");
    };
    match mount.engine.list(state.storage.as_ref(), remainder).await {
        Ok(keys) => Json(json!({ "keys": keys })).into_response(),
        Err(e) => engine_error_response(e, "secret"),
    }
}

/// Which key this replica is sealing with. Cheap, and the thing you want to
/// check first when a rotation looks stuck — every replica must report the
/// same active key.
async fn rewrap_status(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_capability(&state, &headers, "sys/rewrap", Capability::Sudo).await {
        return resp;
    }
    Json(json!({
        "active_key_id": state.rotation.active_key_id(),
        "note": "POST here to re-encrypt every stored value under the active key. \
                 Safe to re-run: a second pass reports everything as unchanged.",
    }))
    .into_response()
}

/// Re-encrypts the whole store under the active master key.
///
/// Deliberately synchronous: it walks every value, so an operator should see
/// it finish (or fail) rather than fire it off and hope. `failed` above zero
/// means a key that is still in use was dropped from the ring — restore it
/// and run again before removing anything.
async fn rewrap(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_capability(&state, &headers, "sys/rewrap", Capability::Sudo).await {
        return resp;
    }
    match state.rotation.rewrap_all().await {
        Ok(report) => {
            let complete = report.failed == 0;
            let mut body = serde_json::to_value(&report).unwrap_or_else(|_| json!({}));
            if let Some(object) = body.as_object_mut() {
                object.insert("active_key_id".to_string(), json!(state.rotation.active_key_id()));
                object.insert(
                    "next_step".to_string(),
                    json!(if complete {
                        "every value is on the active key — you can now remove the \
                         retired keys from SECRETS_MASTER_KEY_RETIRED and restart."
                    } else {
                        "some values could not be opened by any key in the ring. Restore \
                         the missing key and run this again BEFORE removing anything."
                    }),
                );
            }
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// Documentation is not a secret, so any authenticated caller may read it.
/// A consumer holding only `read` on one `creds` path can therefore still
/// discover what its credential is worth and what revoking it would do.
async fn engine_help(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(mount): Path<String>,
) -> Response {
    if let Err(resp) = authenticate(&state, &headers).await {
        return resp;
    }
    let Some((engine_mount, _)) = state.router.resolve(&format!("{mount}/help")) else {
        return err(StatusCode::NOT_FOUND, format!("no engine mounted at '{mount}/'"));
    };
    let doc = engine_mount.engine.doc();
    let mut value = serde_json::to_value(&doc).unwrap_or_else(|_| json!({}));
    if let Some(object) = value.as_object_mut() {
        object.insert("mount".to_string(), json!(mount));
        object.insert(
            "lease_semantics".to_string(),
            json!(if doc.revocable {
                "Revoking a lease destroys the credential at the provider."
            } else {
                "Revoking a lease only deletes our record of it. The credential \
                 keeps working until it expires — keep TTLs short."
            }),
        );
    }
    Json(value).into_response()
}

/// The index: every mounted engine, what shape it is, and where its own
/// documentation lives — plus what the five shapes mean, so the API explains
/// its own vocabulary.
async fn sys_help(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(resp) = authenticate(&state, &headers).await {
        return resp;
    }

    let mut by_mount = std::collections::BTreeMap::new();
    for mount in state.router.mounts() {
        let root = mount.prefix.split('/').next().unwrap_or(&mount.prefix).to_string();
        by_mount.entry(root).or_insert_with(|| mount.engine.doc());
    }

    let engines: Vec<serde_json::Value> = by_mount
        .iter()
        .map(|(mount, doc)| {
            json!({
                "mount": mount,
                "provider": doc.provider,
                "mechanism": doc.mechanism,
                "shape": doc.shape,
                "revocable": doc.revocable,
                "help": format!("/v1/{mount}/help"),
            })
        })
        .collect();

    Json(json!({
        "engines": engines,
        "shapes": {
            "mint-and-revoke": "Minted on demand and destroyed on demand. A lease means what it says.",
            "mint-expiry-only": "Minted on demand, but the provider cannot un-mint it. TTL is the only containment.",
            "refresh-broker": "The durable secret stays here; only a short-lived access token is handed out.",
            "static-custody": "Nothing is mintable — encrypted custody plus rotation.",
            "federation": "No credential exists anywhere; the consumer's own identity is trusted by the provider.",
        },
        "operations": {
            "GET /v1/sys/rewrap": "which master key this replica seals with (sudo)",
            "POST /v1/sys/rewrap": "re-encrypt every stored value under the active master key (sudo)",
            "POST /v1/auth/userpass/users/{username}": "create or replace a user: {\"password\", \"policies\"} (sudo on auth/userpass/users/{username})",
            "GET /v1/auth/userpass/users/{username}": "a user's name and policies, never its hash (sudo on auth/userpass/users/{username})",
            "DELETE /v1/auth/userpass/users/{username}": "delete a user; tokens already issued stay valid until they expire (sudo on auth/userpass/users/{username})",
        },
        "conventions": {
            "{mount}/config/{name}": "operator: the provider connection and root credential (sudo)",
            "{mount}/roles/{role}": "operator: what a role may mint, and its TTL (create)",
            "{mount}/creds/{role}": "consumer: mint a credential and open a lease (read)",
            "{mount}/help": "anyone authenticated: this engine's documentation",
        },
        "further_reading": "docs/delegation/README.md",
    }))
    .into_response()
}

/// `{mount}/config/{name}` and `{mount}/roles/{role}` are the operator
/// surface, shared by every engine. `config` holds root credentials, so it is
/// `sudo`; role definitions are `create`.
async fn engine_write_at(
    state: &AppState,
    headers: &HeaderMap,
    mount: &str,
    suffix: &str,
    capability: Capability,
    data: serde_json::Value,
) -> Response {
    let full_path = format!("{mount}/{suffix}");
    if let Err(resp) = require_capability(state, headers, &full_path, capability).await {
        return resp;
    }
    let Some((engine_mount, remainder)) = state.router.resolve(&full_path) else {
        return err(StatusCode::NOT_FOUND, "no engine mounted at this path");
    };
    match engine_mount.engine.write(state.storage.as_ref(), remainder, data).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => engine_error_response(e, mount),
    }
}

async fn engine_read_at(
    state: &AppState,
    headers: &HeaderMap,
    mount: &str,
    suffix: &str,
    capability: Capability,
) -> Response {
    let full_path = format!("{mount}/{suffix}");
    if let Err(resp) = require_capability(state, headers, &full_path, capability).await {
        return resp;
    }
    let Some((engine_mount, remainder)) = state.router.resolve(&full_path) else {
        return err(StatusCode::NOT_FOUND, "no engine mounted at this path");
    };
    match engine_mount.engine.read(state.storage.as_ref(), remainder).await {
        Ok(value) => Json(value).into_response(),
        Err(e) => engine_error_response(e, mount),
    }
}

async fn engine_delete_at(
    state: &AppState,
    headers: &HeaderMap,
    mount: &str,
    suffix: &str,
) -> Response {
    let full_path = format!("{mount}/{suffix}");
    if let Err(resp) = require_capability(state, headers, &full_path, Capability::Sudo).await {
        return resp;
    }
    let Some((engine_mount, remainder)) = state.router.resolve(&full_path) else {
        return err(StatusCode::NOT_FOUND, "no engine mounted at this path");
    };
    match engine_mount.engine.delete(state.storage.as_ref(), remainder).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => engine_error_response(e, mount),
    }
}

async fn engine_config_write(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((mount, name)): Path<(String, String)>,
    Json(data): Json<serde_json::Value>,
) -> Response {
    engine_write_at(
        &state,
        &headers,
        &mount,
        &format!("config/{name}"),
        Capability::Sudo,
        data,
    )
    .await
}

async fn engine_config_read(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((mount, name)): Path<(String, String)>,
) -> Response {
    engine_read_at(
        &state,
        &headers,
        &mount,
        &format!("config/{name}"),
        Capability::Sudo,
    )
    .await
}

async fn engine_config_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((mount, name)): Path<(String, String)>,
) -> Response {
    engine_delete_at(&state, &headers, &mount, &format!("config/{name}")).await
}

async fn engine_role_write(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((mount, role)): Path<(String, String)>,
    Json(data): Json<serde_json::Value>,
) -> Response {
    engine_write_at(
        &state,
        &headers,
        &mount,
        &format!("roles/{role}"),
        Capability::Create,
        data,
    )
    .await
}

async fn engine_role_read(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((mount, role)): Path<(String, String)>,
) -> Response {
    engine_read_at(
        &state,
        &headers,
        &mount,
        &format!("roles/{role}"),
        Capability::Read,
    )
    .await
}

async fn engine_role_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((mount, role)): Path<(String, String)>,
) -> Response {
    engine_delete_at(&state, &headers, &mount, &format!("roles/{role}")).await
}

/// The consumer-facing route: mint a credential, open a lease, and tell the
/// caller in the same breath what that credential is worth.
async fn engine_generate_creds(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((mount, role)): Path<(String, String)>,
) -> Response {
    let full_path = format!("{mount}/creds/{role}");
    let entry = match require_capability(&state, &headers, &full_path, Capability::Read).await {
        Ok(entry) => entry,
        Err(resp) => return resp,
    };
    let Some((engine_mount, remainder)) = state.router.resolve(&full_path) else {
        return err(StatusCode::NOT_FOUND, "no engine mounted at this path");
    };

    let GeneratedCredential {
        data,
        mut lease,
        scoped_to,
        shape,
        revoke_effect,
    } = match engine_mount.engine.generate(state.storage.as_ref(), remainder).await {
        Ok(generated) => generated,
        Err(e) => return engine_error_response(e, &mount),
    };

    lease.token_id_hash = entry.id_hash;
    if let Err(e) = lease::store_lease(state.storage.as_ref(), &lease).await {
        return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }

    let doc = engine_mount.engine.doc();
    // A credential may declare guarantees that differ from its engine's
    // headline shape, and the caller must be told the truth about the thing it
    // actually received.
    let shape = shape.unwrap_or(doc.shape);
    Json(json!({
        "lease_id": lease.id,
        "data": data,
        "lease_duration": (lease.expires_at - lease.issued_at).num_seconds(),
        "_doc": {
            "shape": shape,
            "revocable": shape.revocable(),
            "revoke_effect": revoke_effect.unwrap_or(doc.revoke_effect),
            "scoped_to": scoped_to,
            "expires_at": lease.expires_at,
            "ttl": doc.ttl,
            "help": format!("/v1/{mount}/help"),
            "revoke": format!("/v1/sys/leases/revoke/{}", lease.id),
        },
    }))
    .into_response()
}

async fn revoke_lease_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(lease_id): Path<String>,
) -> Response {
    if let Err(resp) = require_capability(&state, &headers, "sys/leases/revoke", Capability::Sudo).await {
        return resp;
    }
    let Ok(lease_id) = Uuid::parse_str(&lease_id) else {
        return err(StatusCode::BAD_REQUEST, "invalid lease id");
    };
    let Some(target_lease) = (match lease::get_lease(state.storage.as_ref(), lease_id).await {
        Ok(lease) => lease,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }) else {
        return err(StatusCode::NOT_FOUND, "lease not found");
    };
    match secrets_core::reaper::revoke_lease(state.storage.as_ref(), &state.router, &target_lease).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use secrets_core::barrier::Barrier;
    use secrets_core::crypto::KeyRing;
    use secrets_core::router::Router;
    use secrets_core::storage::{StorageBackend, StorageEntry, StorageResult};
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MemStorage(Mutex<HashMap<String, StorageEntry>>);

    #[async_trait]
    impl StorageBackend for MemStorage {
        async fn get(&self, path: &str) -> StorageResult<Option<StorageEntry>> {
            Ok(self.0.lock().unwrap().get(path).cloned())
        }
        async fn put(&self, path: &str, entry: StorageEntry) -> StorageResult<()> {
            self.0.lock().unwrap().insert(path.to_string(), entry);
            Ok(())
        }
        async fn delete(&self, path: &str) -> StorageResult<()> {
            self.0.lock().unwrap().remove(path);
            Ok(())
        }
        async fn list(&self, prefix: &str) -> StorageResult<Vec<String>> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }
    }

    /// A backend whose liveness probe fails, standing in for a lost database.
    struct Unreachable;

    #[async_trait]
    impl StorageBackend for Unreachable {
        async fn get(&self, _: &str) -> StorageResult<Option<StorageEntry>> {
            Err(secrets_core::storage::StorageError::Backend("down".into()))
        }
        async fn put(&self, _: &str, _: StorageEntry) -> StorageResult<()> {
            Err(secrets_core::storage::StorageError::Backend("down".into()))
        }
        async fn delete(&self, _: &str) -> StorageResult<()> {
            Err(secrets_core::storage::StorageError::Backend("down".into()))
        }
        async fn list(&self, _: &str) -> StorageResult<Vec<String>> {
            Err(secrets_core::storage::StorageError::Backend("down".into()))
        }
        async fn ping(&self) -> StorageResult<()> {
            Err(secrets_core::storage::StorageError::Backend("connection refused".into()))
        }
    }

    fn state_with(storage: Arc<dyn StorageBackend>) -> Arc<AppState> {
        Arc::new(AppState {
            storage,
            rotation: Arc::new(Barrier::new(
                MemStorage::default(),
                Arc::new(KeyRing::new(&[11u8; 32], &[])),
            )),
            router: Arc::new(Router::new(crate::wiring::engine_mounts())),
            userpass: secrets_auth_userpass::UserPassAuth::new(),
            oidc: secrets_auth_oidc::OidcAuthMethod::new(),
        })
    }

    #[tokio::test]
    async fn rewrap_requires_sudo() {
        let state = test_state();
        // A token whose policy does not exist has no capabilities at all.
        let headers = authenticated(&state).await;
        let response = rewrap(State(state.clone()), headers).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let anonymous = rewrap(State(state), HeaderMap::new()).await;
        assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rewrap_reports_progress_and_the_active_key() {
        let state = test_state();
        let headers = sudo(&state).await;

        state
            .storage
            .put(
                "secret/data/kv-data/app/v1",
                secrets_core::storage::StorageEntry {
                    value: b"hunter2".to_vec(),
                    expires_at: None,
                },
            )
            .await
            .unwrap();

        let body = body_json(rewrap(State(state.clone()), headers).await).await;
        assert!(body["scanned"].as_u64().unwrap() >= 1);
        // Freshly written through the barrier, so already on the active key.
        assert_eq!(body["rewrapped"], 0);
        assert_eq!(body["failed"], 0);
        assert!(body["active_key_id"].as_str().is_some_and(|id| id.len() == 8));
        assert!(body["next_step"].as_str().unwrap().contains("retired keys"));
    }

    #[tokio::test]
    async fn health_is_ok_when_storage_answers() {
        let response = health(State(test_state())).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await["status"], "ok");
    }

    /// A load balancer keys on the status code, so a broken node must not
    /// answer 200. It previously did, which would have kept it in rotation.
    #[tokio::test]
    async fn health_fails_with_a_non_2xx_status_when_storage_is_down() {
        let response = health(State(state_with(Arc::new(Unreachable)))).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = body_json(response).await;
        assert_eq!(body["status"], "error");
        assert!(body["detail"].as_str().unwrap().contains("connection refused"));
    }

    fn test_state() -> Arc<AppState> {
        // A real barrier over the in-memory store, so `sys/rewrap` exercises
        // the actual rotation path rather than a stub.
        let barrier = Arc::new(Barrier::new(
            MemStorage::default(),
            Arc::new(KeyRing::new(&[11u8; 32], &[])),
        ));
        Arc::new(AppState {
            storage: barrier.clone(),
            rotation: barrier,
            // The real mount table, so these assertions cover every engine
            // this server actually exposes.
            router: Arc::new(Router::new(crate::wiring::engine_mounts())),
            userpass: secrets_auth_userpass::UserPassAuth::new(),
            oidc: secrets_auth_oidc::OidcAuthMethod::new(),
        })
    }

    /// axum panics when two routes conflict. The generic `/v1/{mount}/…` routes
    /// sit alongside static ones like `/v1/sys/policy/{name}`, so building the
    /// table is worth asserting rather than discovering at startup.
    #[test]
    fn route_table_has_no_conflicts() {
        let _ = router(test_state());
    }

    /// Every engine must be able to describe itself — the `_doc` block and the
    /// help endpoints are only as honest as this.
    #[test]
    fn mounted_engines_document_themselves() {
        let state = test_state();
        assert!(
            state.router.mounts().len() >= 10,
            "expected the full engine set to be mounted"
        );
        for mount in state.router.mounts() {
            let doc = mount.engine.doc();
            let at = &mount.prefix;
            assert!(!doc.provider.is_empty(), "{at} has no provider");
            assert!(!doc.mechanism.is_empty(), "{at} has no mechanism");
            assert!(!doc.scoping.is_empty(), "{at} does not describe its scoping");
            assert!(
                !doc.root_credential.is_empty(),
                "{at} does not say what secret the server must hold"
            );
            assert!(
                !doc.revoke_effect.is_empty(),
                "{at} does not say what revoke does"
            );
            // The whole point of the `_doc` block is that a caller can trust
            // it. An engine claiming more revocability than its shape allows
            // would mislead every consumer that reads it.
            assert_eq!(
                doc.revocable,
                doc.shape.revocable(),
                "{at} disagrees with its own shape about revocability"
            );
            assert!(!doc.paths.is_empty(), "{at} documents no paths");
        }
    }

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("response body");
        serde_json::from_slice(&bytes).expect("response is JSON")
    }

    /// A token carrying a policy that actually grants sudo everywhere, for
    /// the operator-only routes.
    async fn sudo(state: &AppState) -> HeaderMap {
        let policy = secrets_core::policy::Policy {
            name: "root".to_string(),
            rules: vec![secrets_core::policy::PathRule {
                prefix: String::new(),
                capabilities: vec![Capability::Sudo],
            }],
        };
        secrets_core::policy::store_policy(state.storage.as_ref(), &policy)
            .await
            .expect("store policy");
        authenticated(state).await
    }

    /// Mints a real token in the in-memory store so the help handlers, which
    /// require authentication but no capability, can be exercised end to end.
    async fn authenticated(state: &AppState) -> HeaderMap {
        let (raw, entry) = token::generate_token(vec!["root".to_string()], Some(3600));
        token::store_token(state.storage.as_ref(), &raw, &entry)
            .await
            .expect("store token");
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {raw}").parse().unwrap());
        headers
    }

    #[tokio::test]
    async fn sys_help_indexes_every_engine_and_explains_the_shapes() {
        let state = test_state();
        let headers = authenticated(&state).await;
        let body = body_json(sys_help(State(state.clone()), headers).await).await;

        let mounts: Vec<&str> = body["engines"]
            .as_array()
            .expect("engines")
            .iter()
            .filter_map(|e| e["mount"].as_str())
            .collect();
        for expected in [
            "aws", "database", "dropbox", "federation", "gcp", "github", "gitlab",
            "gworkspace", "m365", "secret",
        ] {
            assert!(mounts.contains(&expected), "{expected} missing from {mounts:?}");
        }
        // The API explains its own vocabulary, so a caller never has to guess
        // what "mint-expiry-only" is promising.
        assert!(body["shapes"]["mint-expiry-only"].is_string());
        assert!(body["conventions"]["{mount}/creds/{role}"].is_string());
    }

    #[tokio::test]
    async fn help_requires_a_token_but_no_capability() {
        let state = test_state();
        let anonymous = sys_help(State(state.clone()), HeaderMap::new()).await;
        assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

        // The token carries a policy name that does not exist, so it has no
        // capabilities at all — and must still be able to read the docs.
        let headers = authenticated(&state).await;
        let response = engine_help(
            State(state.clone()),
            headers,
            Path("github".to_string()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["mount"], "github");
        assert_eq!(body["shape"], "mint-and-revoke");
        assert!(body["revoke_effect"].as_str().unwrap().contains("installation/token"));
        assert!(body["lease_semantics"].as_str().unwrap().contains("destroys"));
    }

    /// The engines that cannot revoke must say so at the point a caller looks,
    /// not only in the prose documentation.
    #[tokio::test]
    async fn help_admits_when_a_lease_cannot_be_honoured() {
        let state = test_state();
        for mount in ["aws", "gcp", "m365"] {
            let headers = authenticated(&state).await;
            let body = body_json(
                engine_help(State(state.clone()), headers, Path(mount.to_string())).await,
            )
            .await;
            assert_eq!(body["revocable"], false, "{mount} claims to be revocable");
            assert!(
                body["lease_semantics"]
                    .as_str()
                    .unwrap()
                    .contains("keeps working"),
                "{mount} does not warn that the credential outlives the lease"
            );
        }
    }

    #[tokio::test]
    async fn help_for_an_unmounted_engine_is_not_found() {
        let state = test_state();
        let headers = authenticated(&state).await;
        let response =
            engine_help(State(state.clone()), headers, Path("nope".to_string())).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    fn user_body(password: &str, policies: &[&str]) -> Result<Json<WriteUserRequest>, JsonRejection> {
        Ok(Json(WriteUserRequest {
            password: password.to_string(),
            policies: policies.iter().map(|p| p.to_string()).collect(),
        }))
    }

    #[tokio::test]
    async fn user_management_round_trip() {
        let state = test_state();
        let headers = sudo(&state).await;
        let name = || Path("svc".to_string());

        let response = write_user(
            State(state.clone()),
            headers.clone(),
            name(),
            user_body("a long enough password", &["svc-policy"]),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let response = read_user(State(state.clone()), headers.clone(), name()).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body, json!({ "username": "svc", "policies": ["svc-policy"] }));

        let response = delete_user(State(state.clone()), headers.clone(), name()).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let response = delete_user(State(state.clone()), headers.clone(), name()).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let response = read_user(State(state), headers, name()).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    /// The capability is checked before anything else, so an unauthorised
    /// caller cannot probe which users exist or which inputs are valid.
    #[tokio::test]
    async fn user_management_requires_sudo_on_the_user_path() {
        let state = test_state();
        let no_caps = authenticated(&state).await;
        let name = || Path("svc".to_string());

        let write = write_user(State(state.clone()), no_caps.clone(), name(), user_body("x", &[])).await;
        assert_eq!(write.status(), StatusCode::FORBIDDEN);
        let read = read_user(State(state.clone()), no_caps.clone(), name()).await;
        assert_eq!(read.status(), StatusCode::FORBIDDEN);
        let delete = delete_user(State(state.clone()), no_caps, name()).await;
        assert_eq!(delete.status(), StatusCode::FORBIDDEN);

        let anonymous = read_user(State(state.clone()), HeaderMap::new(), name()).await;
        assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED);

        // Sudo scoped to one user's path grants that user and no other.
        let scoped = secrets_core::policy::Policy {
            name: "root".to_string(),
            rules: vec![secrets_core::policy::PathRule {
                prefix: "auth/userpass/users/svc".to_string(),
                capabilities: vec![Capability::Sudo],
            }],
        };
        secrets_core::policy::store_policy(state.storage.as_ref(), &scoped)
            .await
            .unwrap();
        let headers = authenticated(&state).await;
        let own = read_user(State(state.clone()), headers.clone(), name()).await;
        assert_eq!(own.status(), StatusCode::NOT_FOUND);
        let other = read_user(State(state), headers, Path("admin".to_string())).await;
        assert_eq!(other.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn invalid_user_writes_are_bad_requests() {
        let state = test_state();
        let headers = sudo(&state).await;
        for (username, password, policies) in [
            (".dot", "a long enough password", vec![]),
            ("has space", "a long enough password", vec![]),
            ("svc", "short", vec![]),
            ("svc", "a long enough password", vec![""]),
        ] {
            let response = write_user(
                State(state.clone()),
                headers.clone(),
                Path(username.to_string()),
                user_body(password, &policies),
            )
            .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{username}/{password}");
            assert!(body_json(response).await["error"].is_string());
        }
    }

    #[tokio::test]
    async fn sys_help_lists_the_user_routes() {
        let state = test_state();
        let headers = authenticated(&state).await;
        let body = body_json(sys_help(State(state), headers).await).await;
        for method in ["POST", "GET", "DELETE"] {
            let key = format!("{method} /v1/auth/userpass/users/{{username}}");
            assert!(body["operations"][&key].is_string(), "{key} missing");
        }
    }

    /// Engines that cannot revoke must say so in words, not just in a boolean.
    /// This is the claim the rest of the documentation rests on.
    #[test]
    fn non_revocable_engines_explain_themselves() {
        let state = test_state();
        for mount in state.router.mounts() {
            let doc = mount.engine.doc();
            if !doc.revocable {
                let effect = doc.revoke_effect.to_lowercase();
                assert!(
                    effect.contains("nothing")
                        || effect.contains("not applicable")
                        || effect.contains("keeps working")
                        || effect.contains("until it expires")
                        || effect.contains("cannot"),
                    "{} is not revocable but its revoke_effect does not admit it: {}",
                    mount.prefix,
                    doc.revoke_effect
                );
            }
        }
    }
}
