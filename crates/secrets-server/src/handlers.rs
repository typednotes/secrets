use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router as AxumRouter};
use secrets_auth_oidc::OidcConfig;
use secrets_core::auth::{AuthError, AuthMethod, LoginRequest};
use secrets_core::engine::EngineError;
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
        .route("/v1/database/config/{name}", post(database_config_write))
        .route("/v1/database/roles/{role}", post(database_role_write))
        .route("/v1/database/creds/{role}", get(database_generate_creds))
        .route("/v1/sys/leases/revoke/{lease_id}", post(revoke_lease_handler))
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

async fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<(String, TokenEntry), Response> {
    let token = bearer_token(headers).ok_or_else(|| err(StatusCode::UNAUTHORIZED, "missing bearer token"))?;
    let entry = token::lookup_token(state.storage.as_ref(), token)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| err(StatusCode::FORBIDDEN, "invalid or expired token"))?;
    Ok((token.to_string(), entry))
}

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

async fn health(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    match state.storage.list("").await {
        Ok(_) => Json(json!({ "status": "ok" })),
        Err(e) => Json(json!({ "status": "error", "detail": e.to_string() })),
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

fn engine_error_response(e: EngineError) -> Response {
    match e {
        EngineError::NotFound => err(StatusCode::NOT_FOUND, "not found"),
        EngineError::Unsupported => err(StatusCode::BAD_REQUEST, "operation not supported"),
        EngineError::InvalidRequest(msg) => err(StatusCode::BAD_REQUEST, msg),
        e => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
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
        Err(e) => engine_error_response(e),
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
        Err(e) => engine_error_response(e),
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
        Err(e) => engine_error_response(e),
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
        Err(e) => engine_error_response(e),
    }
}

async fn database_config_write(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(data): Json<serde_json::Value>,
) -> Response {
    let full_path = format!("database/config/{name}");
    if let Err(resp) = require_capability(&state, &headers, &full_path, Capability::Sudo).await {
        return resp;
    }
    let Some((mount, remainder)) = state.router.resolve(&full_path) else {
        return err(StatusCode::NOT_FOUND, "no engine mounted at this path");
    };
    match mount.engine.write(state.storage.as_ref(), remainder, data).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => engine_error_response(e),
    }
}

async fn database_role_write(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(role): Path<String>,
    Json(data): Json<serde_json::Value>,
) -> Response {
    let full_path = format!("database/roles/{role}");
    if let Err(resp) = require_capability(&state, &headers, &full_path, Capability::Create).await {
        return resp;
    }
    let Some((mount, remainder)) = state.router.resolve(&full_path) else {
        return err(StatusCode::NOT_FOUND, "no engine mounted at this path");
    };
    match mount.engine.write(state.storage.as_ref(), remainder, data).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => engine_error_response(e),
    }
}

async fn database_generate_creds(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(role): Path<String>,
) -> Response {
    let full_path = format!("database/creds/{role}");
    let entry = match require_capability(&state, &headers, &full_path, Capability::Read).await {
        Ok(entry) => entry,
        Err(resp) => return resp,
    };
    let Some((mount, remainder)) = state.router.resolve(&full_path) else {
        return err(StatusCode::NOT_FOUND, "no engine mounted at this path");
    };
    let (data, mut new_lease) = match mount.engine.generate(state.storage.as_ref(), remainder).await {
        Ok(result) => result,
        Err(e) => return engine_error_response(e),
    };
    new_lease.token_id_hash = entry.id_hash;
    if let Err(e) = lease::store_lease(state.storage.as_ref(), &new_lease).await {
        return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }

    Json(json!({
        "lease_id": new_lease.id,
        "data": data,
        "lease_duration": (new_lease.expires_at - new_lease.issued_at).num_seconds(),
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
