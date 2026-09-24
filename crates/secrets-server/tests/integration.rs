//! End-to-end tests against a *running* secrets-server, local or deployed.
//!
//! ```bash
//! SECRETS_TEST_URL=https://host \
//! SECRETS_TEST_USERNAME=admin SECRETS_TEST_PASSWORD=... \
//!   cargo test -p secrets-server --test integration -- --nocapture
//! ```
//!
//! Every test skips (rather than fails) when `SECRETS_TEST_URL` is unset, so
//! `cargo test --workspace` stays offline by default. Tests needing a token
//! additionally skip without `SECRETS_TEST_USERNAME`/`SECRETS_TEST_PASSWORD`.
//!
//! These run against real, possibly shared state, so every test namespaces
//! the paths and policy names it touches under a fresh UUID and cleans up
//! after itself — they are safe to run repeatedly and in parallel.

use std::sync::LazyLock;
use std::time::Duration;

use reqwest::{Client, Response, StatusCode};
use tokio::sync::{OnceCell, Semaphore};
use serde_json::{json, Value};
use uuid::Uuid;

const URL_ENV: &str = "SECRETS_TEST_URL";
const USERNAME_ENV: &str = "SECRETS_TEST_USERNAME";
const PASSWORD_ENV: &str = "SECRETS_TEST_PASSWORD";
const CONCURRENCY_ENV: &str = "SECRETS_TEST_CONCURRENCY";

/// Generous because the target may be a serverless deployment paying a cold
/// start on the first request of a run.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Cargo runs these tests in parallel, one thread each, which is far more
/// load than a small single-instance deployment expects — and `userpass`
/// login is deliberately expensive (Argon2id), so a burst of them starves
/// the server and everything times out. Cap in-flight requests instead of
/// asking the caller to remember `--test-threads`.
static IN_FLIGHT: LazyLock<Semaphore> = LazyLock::new(|| {
    let limit = std::env::var(CONCURRENCY_ENV)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4);
    Semaphore::new(limit)
});

/// One login shared by every test that just needs *some* admin token, for the
/// same reason. Tests that must own their token still log in themselves.
static ADMIN_TOKEN: OnceCell<String> = OnceCell::const_new();

#[derive(Clone)]
struct Server {
    client: Client,
    base: String,
}

impl Server {
    fn from_env() -> Option<Self> {
        let base = std::env::var(URL_ENV).ok()?.trim_end_matches('/').to_string();
        let client = Client::builder().timeout(REQUEST_TIMEOUT).build().unwrap();
        Some(Self { client, base })
    }

    fn url(&self, path: &str) -> String {
        format!("{}/{}", self.base, path.trim_start_matches('/'))
    }

    async fn get(&self, path: &str, token: Option<&str>) -> (StatusCode, Value) {
        let req = self.client.get(self.url(path));
        send(bearer(req, token)).await
    }

    async fn post(&self, path: &str, token: Option<&str>, body: &Value) -> (StatusCode, Value) {
        let req = self.client.post(self.url(path)).json(body);
        send(bearer(req, token)).await
    }

    async fn delete(&self, path: &str, token: Option<&str>) -> (StatusCode, Value) {
        let req = self.client.delete(self.url(path));
        send(bearer(req, token)).await
    }

    /// Logs in with the configured admin credentials, returning a fresh token.
    async fn login(&self, username: &str, password: &str) -> String {
        let (status, body) = self
            .post(
                "/v1/auth/userpass/login",
                None,
                &json!({ "username": username, "password": password }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "login failed: {body}");
        body["auth"]["client_token"]
            .as_str()
            .unwrap_or_else(|| panic!("login response has no client_token: {body}"))
            .to_string()
    }
}

fn bearer(req: reqwest::RequestBuilder, token: Option<&str>) -> reqwest::RequestBuilder {
    match token {
        Some(token) => req.bearer_auth(token),
        None => req,
    }
}

async fn send(req: reqwest::RequestBuilder) -> (StatusCode, Value) {
    let _permit = IN_FLIGHT.acquire().await.expect("semaphore closed");
    let resp = req.send().await.expect("request failed");
    decode(resp).await
}

async fn decode(resp: Response) -> (StatusCode, Value) {
    let status = resp.status();
    let body = resp.text().await.expect("failed to read body");
    if body.trim().is_empty() {
        return (status, Value::Null);
    }
    // Extractor rejections (bad JSON, wrong content-type) come back as plain
    // text rather than the handlers' `{"error": ...}` shape.
    let value = serde_json::from_str(&body).unwrap_or(Value::String(body));
    (status, value)
}

/// Binds `$server`, or returns early when the suite is not configured.
macro_rules! server {
    () => {
        match Server::from_env() {
            Some(server) => server,
            None => {
                eprintln!("skipping: {URL_ENV} is not set");
                return;
            }
        }
    };
}

/// Binds a `Server` plus the shared admin token, or returns early when the
/// suite has no credentials configured.
macro_rules! authed_server {
    () => {{
        let server = server!();
        if credentials().is_none() {
            eprintln!("skipping: {USERNAME_ENV}/{PASSWORD_ENV} are not set");
            return;
        }
        let token = admin_token(&server).await;
        (server, token)
    }};
}

fn credentials() -> Option<(String, String)> {
    Some((
        std::env::var(USERNAME_ENV).ok()?,
        std::env::var(PASSWORD_ENV).ok()?,
    ))
}

/// Logs in at most once per test binary; later callers await that same login.
async fn admin_token(server: &Server) -> &'static str {
    ADMIN_TOKEN
        .get_or_init(|| async {
            let (username, password) = credentials().expect("credentials are set");
            server.login(&username, &password).await
        })
        .await
}

/// A path prefix unique to one test run, so parallel runs never collide.
fn scratch_path(suffix: &str) -> String {
    format!("itest/{}/{suffix}", Uuid::new_v4())
}

// ---------------------------------------------------------------------------
// Unauthenticated surface
// ---------------------------------------------------------------------------

#[tokio::test]
async fn health_reports_ok() {
    let server = server!();
    let (status, body) = server.get("/v1/sys/health", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok", "storage is not reachable: {body}");
}

#[tokio::test]
async fn unknown_route_is_not_found() {
    let server = server!();
    let (status, _) = server.get("/v1/definitely/not/a/route", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn secret_read_without_token_is_unauthorized() {
    let server = server!();
    let (status, body) = server.get("/v1/secret/data/itest/nope", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "missing bearer token");
}

#[tokio::test]
async fn secret_read_with_bogus_token_is_forbidden() {
    let server = server!();
    let (status, body) = server
        .get("/v1/secret/data/itest/nope", Some("s.0000deadbeef"))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "invalid or expired token");
}

#[tokio::test]
async fn policy_read_without_token_is_unauthorized() {
    let server = server!();
    let (status, _) = server.get("/v1/sys/policy/root", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// A token is a bearer secret: an unauthenticated caller must not be able to
/// tell "no such policy" apart from "not allowed to look".
#[tokio::test]
async fn unknown_policy_without_token_is_unauthorized_not_not_found() {
    let server = server!();
    let (status, _) = server
        .get(&format!("/v1/sys/policy/{}", Uuid::new_v4()), None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_with_wrong_credentials_is_unauthorized() {
    let server = server!();
    let (status, body) = server
        .post(
            "/v1/auth/userpass/login",
            None,
            &json!({ "username": format!("nobody-{}", Uuid::new_v4()), "password": "wrong" }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "invalid credentials");
}

#[tokio::test]
async fn login_with_malformed_body_is_client_error() {
    let server = server!();
    let resp = server
        .client
        .post(server.url("/v1/auth/userpass/login"))
        .header("content-type", "application/json")
        .body("{\"username\": ")
        .send()
        .await
        .expect("request failed");
    let status = resp.status();
    assert!(
        status.is_client_error(),
        "malformed JSON should be rejected as a client error, got {status}"
    );
}

#[tokio::test]
async fn login_with_missing_fields_is_client_error() {
    let server = server!();
    let (status, _) = server
        .post("/v1/auth/userpass/login", None, &json!({ "username": "admin" }))
        .await;
    assert!(
        status.is_client_error(),
        "missing password should be rejected as a client error, got {status}"
    );
}

/// The OIDC route must answer coherently whether or not an IdP is registered:
/// an authorize URL when configured, a 400 when not — never a 500.
#[tokio::test]
async fn oidc_authorize_url_responds_without_server_error() {
    let server = server!();
    let (status, body) = server.get("/v1/auth/oidc/authorize_url", None).await;
    match status {
        StatusCode::OK => assert!(
            body["authorize_url"].as_str().is_some_and(|u| u.starts_with("http")),
            "expected an absolute authorize_url: {body}"
        ),
        StatusCode::BAD_REQUEST => assert!(body["error"].is_string(), "expected an error body: {body}"),
        other => panic!("unexpected status {other}: {body}"),
    }
}

#[tokio::test]
async fn oidc_config_write_requires_sudo() {
    let server = server!();
    let (status, _) = server
        .post(
            "/v1/auth/oidc/config",
            None,
            &json!({
                "issuer_url": "https://example.invalid",
                "client_id": "itest",
                "redirect_url": "https://example.invalid/callback",
            }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_issues_an_opaque_token_with_policies() {
    let server = server!();
    let Some((username, password)) = credentials() else {
        eprintln!("skipping: {USERNAME_ENV}/{PASSWORD_ENV} are not set");
        return;
    };
    let (status, body) = server
        .post(
            "/v1/auth/userpass/login",
            None,
            &json!({ "username": username, "password": password }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let auth = &body["auth"];
    let token = auth["client_token"].as_str().expect("client_token");
    assert!(token.starts_with("s."), "unexpected token format: {token}");
    assert!(
        auth["policies"].as_array().is_some_and(|p| !p.is_empty()),
        "token carries no policies: {body}"
    );
    assert_eq!(auth["display_name"], username);
    assert!(auth["lease_duration"].as_i64().is_some_and(|d| d > 0), "{body}");
}

#[tokio::test]
async fn each_login_mints_a_distinct_token() {
    let (server, first) = authed_server!();
    let (username, password) = credentials().unwrap();
    let second = server.login(&username, &password).await;
    assert_ne!(first, second, "logins reused a token");

    for token in [first, second.as_str()] {
        let (status, _) = server.get("/v1/auth/token/lookup-self", Some(token)).await;
        assert_eq!(status, StatusCode::OK, "both tokens should stay valid");
    }
}

#[tokio::test]
async fn lookup_self_reports_token_metadata() {
    let (server, token) = authed_server!();
    let (status, body) = server.get("/v1/auth/token/lookup-self", Some(token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["policies"].as_array().is_some_and(|p| !p.is_empty()), "{body}");
    let created_at = parse_time(&body["created_at"]);
    let expires_at = parse_time(&body["expires_at"]);
    assert!(expires_at > created_at, "token expires before it was created: {body}");
}

#[tokio::test]
async fn renew_self_pushes_out_the_expiry() {
    let (server, token) = authed_server!();
    let (_, before) = server.get("/v1/auth/token/lookup-self", Some(token)).await;

    let (status, renewed) = server.post("/v1/auth/token/renew-self", Some(token), &json!({})).await;
    assert_eq!(status, StatusCode::OK, "{renewed}");
    assert!(
        parse_time(&renewed["expires_at"]) >= parse_time(&before["expires_at"]),
        "renew moved the expiry backwards: {before} -> {renewed}"
    );

    let (status, _) = server.get("/v1/auth/token/lookup-self", Some(token)).await;
    assert_eq!(status, StatusCode::OK, "token unusable after renewal");
}

#[tokio::test]
async fn renew_self_without_token_is_unauthorized() {
    let server = server!();
    let (status, _) = server.post("/v1/auth/token/renew-self", None, &json!({})).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// Uses a throwaway login so revocation cannot disturb other tests.
#[tokio::test]
async fn revoke_self_invalidates_the_token() {
    let server = server!();
    let Some((username, password)) = credentials() else {
        eprintln!("skipping: {USERNAME_ENV}/{PASSWORD_ENV} are not set");
        return;
    };
    let doomed = server.login(&username, &password).await;

    let (status, _) = server.post("/v1/auth/token/revoke-self", Some(&doomed), &json!({})).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, body) = server.get("/v1/auth/token/lookup-self", Some(&doomed)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "revoked token still works: {body}");
}

#[tokio::test]
async fn revoke_self_is_idempotent_for_unknown_tokens() {
    let server = server!();
    let (status, _) = server
        .post("/v1/auth/token/revoke-self", Some("s.deadbeef"), &json!({}))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

// ---------------------------------------------------------------------------
// KV engine
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kv_write_read_delete_round_trip() {
    let (server, token) = authed_server!();
    let path = scratch_path("round-trip");
    let data = json!({ "password": "hunter2", "port": 5432 });

    let (status, _) = server.post(&data_url(&path), Some(token), &data).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, body) = server.get(&data_url(&path), Some(token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"], data);
    assert_eq!(body["metadata"]["version"], 1);

    let (status, _) = server.delete(&data_url(&path), Some(token)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, body) = server.get(&data_url(&path), Some(token)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "deleted secret is still readable: {body}");
}

#[tokio::test]
async fn kv_rewrite_bumps_the_version_and_returns_the_latest() {
    let (server, token) = authed_server!();
    let path = scratch_path("versioned");

    server
        .post(&data_url(&path), Some(token), &json!({ "v": "first" }))
        .await;
    server
        .post(&data_url(&path), Some(token), &json!({ "v": "second" }))
        .await;

    let (status, body) = server.get(&data_url(&path), Some(token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["v"], "second");
    assert_eq!(body["metadata"]["version"], 2);

    server.delete(&data_url(&path), Some(token)).await;
}

#[tokio::test]
async fn kv_read_of_unwritten_path_is_not_found() {
    let (server, token) = authed_server!();
    let (status, _) = server.get(&data_url(&scratch_path("absent")), Some(token)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn kv_delete_of_unwritten_path_is_not_found() {
    let (server, token) = authed_server!();
    let (status, _) = server
        .delete(&data_url(&scratch_path("absent")), Some(token))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn kv_metadata_lists_keys_under_a_prefix() {
    let (server, token) = authed_server!();
    let prefix = format!("itest/{}", Uuid::new_v4());
    let paths = [format!("{prefix}/alpha"), format!("{prefix}/beta")];

    for path in &paths {
        let (status, _) = server
            .post(&data_url(path), Some(token), &json!({ "k": "v" }))
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    let (status, body) = server
        .get(&format!("/v1/secret/metadata/{prefix}"), Some(token))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let keys: Vec<&str> = body["keys"]
        .as_array()
        .expect("keys array")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for path in &paths {
        assert!(keys.contains(&path.as_str()), "{path} missing from {keys:?}");
    }

    for path in &paths {
        server.delete(&data_url(path), Some(token)).await;
    }
}

/// Deep paths and non-ASCII values must survive the AEAD barrier untouched.
#[tokio::test]
async fn kv_preserves_nested_paths_and_unicode_values() {
    let (server, token) = authed_server!();
    let path = scratch_path("deeply/nested/child");
    let data = json!({ "note": "clé secrète — 🔐", "nested": { "list": [1, 2, 3] } });

    server.post(&data_url(&path), Some(token), &data).await;
    let (status, body) = server.get(&data_url(&path), Some(token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"], data);

    server.delete(&data_url(&path), Some(token)).await;
}

/// Serverless deployments pool connections lazily; overlapping first writes
/// are where that goes wrong. How much really overlaps is bounded by
/// `SECRETS_TEST_CONCURRENCY`; the assertions hold either way.
#[tokio::test(flavor = "multi_thread")]
async fn kv_handles_concurrent_writes_to_distinct_paths() {
    let (server, token) = authed_server!();
    let prefix = format!("itest/{}", Uuid::new_v4());

    let mut writes = tokio::task::JoinSet::new();
    for i in 0..3 {
        let server = server.clone();
        let path = format!("{prefix}/concurrent-{i}");
        writes.spawn(async move {
            server
                .post(&data_url(&path), Some(token), &json!({ "index": i }))
                .await
        });
    }
    while let Some(result) = writes.join_next().await {
        let (status, body) = result.expect("write task panicked");
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    }

    for i in 0..3 {
        let path = format!("{prefix}/concurrent-{i}");
        let (status, body) = server.get(&data_url(&path), Some(token)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["data"]["index"], i);
        server.delete(&data_url(&path), Some(token)).await;
    }
}

// ---------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------

#[tokio::test]
async fn policy_write_read_delete_round_trip() {
    let (server, token) = authed_server!();
    let name = format!("itest-{}", Uuid::new_v4());
    let url = format!("/v1/sys/policy/{name}");
    let rules = json!([{ "prefix": "secret/data/itest/", "capabilities": ["read", "list"] }]);

    let (status, _) = server
        .post(&url, Some(token), &json!({ "name": name, "rules": rules }))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, body) = server.get(&url, Some(token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["name"], name);
    assert_eq!(body["rules"], rules);

    let (status, _) = server.delete(&url, Some(token)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = server.get(&url, Some(token)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// The path segment is authoritative: a mismatched `name` in the body must not
/// let a caller write a policy under a different name.
#[tokio::test]
async fn policy_name_comes_from_the_path_not_the_body() {
    let (server, token) = authed_server!();
    let name = format!("itest-{}", Uuid::new_v4());
    let impostor = format!("itest-{}", Uuid::new_v4());

    server
        .post(
            &format!("/v1/sys/policy/{name}"),
            Some(token),
            &json!({ "name": impostor, "rules": [] }),
        )
        .await;

    let (status, body) = server.get(&format!("/v1/sys/policy/{name}"), Some(token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["name"], name);

    let (status, _) = server
        .get(&format!("/v1/sys/policy/{impostor}"), Some(token))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "policy leaked under the body's name");

    server.delete(&format!("/v1/sys/policy/{name}"), Some(token)).await;
}

#[tokio::test]
async fn policy_read_of_unknown_name_is_not_found() {
    let (server, token) = authed_server!();
    let (status, _) = server
        .get(&format!("/v1/sys/policy/itest-{}", Uuid::new_v4()), Some(token))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Userpass user management
// ---------------------------------------------------------------------------

/// A scoped service identity created by the admin. Each test cleans it up at
/// the end; a failing assertion skips that, but the names are unique, so a
/// leftover never collides with a later run.
struct ScopedUser {
    username: String,
    password: String,
    policy: String,
    prefix: String,
}

impl ScopedUser {
    /// A policy granting `create`/`read`/`delete` under a fresh
    /// `secret/data/itest/<uuid>/` prefix, and a user holding only it.
    async fn create(server: &Server, admin: &str) -> Self {
        let id = Uuid::new_v4();
        let user = Self {
            username: format!("itest-{id}"),
            password: format!("pw-{}", Uuid::new_v4()),
            policy: format!("itest-{id}"),
            prefix: format!("itest/{id}"),
        };
        let (status, body) = server
            .post(
                &format!("/v1/sys/policy/{}", user.policy),
                Some(admin),
                &json!({
                    "name": user.policy,
                    "rules": [{
                        "prefix": format!("secret/data/{}/", user.prefix),
                        "capabilities": ["create", "read", "delete"],
                    }],
                }),
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        let (status, body) = server
            .post(
                &user.url(),
                Some(admin),
                &json!({ "password": user.password, "policies": [user.policy] }),
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        user
    }

    fn url(&self) -> String {
        format!("/v1/auth/userpass/users/{}", self.username)
    }

    async fn login(&self, server: &Server, password: &str) -> (StatusCode, Value) {
        server
            .post(
                "/v1/auth/userpass/login",
                None,
                &json!({ "username": self.username, "password": password }),
            )
            .await
    }

    async fn cleanup(&self, server: &Server, admin: &str) {
        server.delete(&self.url(), Some(admin)).await;
        server
            .delete(&format!("/v1/sys/policy/{}", self.policy), Some(admin))
            .await;
    }
}

/// The point of the feature: a service gets its own identity, holding exactly
/// the policies it was given, allowed under its prefix and denied elsewhere.
#[tokio::test]
async fn created_user_logs_in_with_exactly_its_scoped_policies() {
    let (server, admin) = authed_server!();
    let user = ScopedUser::create(&server, admin).await;

    let (status, body) = user.login(&server, &user.password).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["auth"]["policies"], json!([user.policy]));
    assert_eq!(body["auth"]["display_name"], user.username);
    let token = body["auth"]["client_token"].as_str().unwrap().to_string();

    let allowed = format!("{}/secret", user.prefix);
    let (status, body) = server
        .post(&data_url(&allowed), Some(&token), &json!({ "k": "v" }))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let (status, body) = server.get(&data_url(&allowed), Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["k"], "v");

    let elsewhere = scratch_path("not-yours");
    let (status, _) = server
        .post(&data_url(&elsewhere), Some(&token), &json!({ "k": "v" }))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = server
        .get(&format!("/v1/sys/policy/{}", user.policy), Some(&token))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    server.delete(&data_url(&allowed), Some(&token)).await;
    server.post("/v1/auth/token/revoke-self", Some(&token), &json!({})).await;
    user.cleanup(&server, admin).await;
}

#[tokio::test]
async fn reading_a_user_returns_its_policies_and_never_the_hash() {
    let (server, admin) = authed_server!();
    let user = ScopedUser::create(&server, admin).await;

    let (status, body) = server.get(&user.url(), Some(admin)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({ "username": user.username, "policies": [user.policy] })
    );
    let raw = body.to_string();
    assert!(!raw.contains("hash") && !raw.contains("argon2"), "leaked: {raw}");
    assert!(!raw.contains(&user.password), "leaked the password: {raw}");

    user.cleanup(&server, admin).await;
}

/// POST replaces: the old password stops working and the new one logs in
/// with the new policy list.
#[tokio::test]
async fn replacing_a_user_changes_its_password_and_policies() {
    let (server, admin) = authed_server!();
    let user = ScopedUser::create(&server, admin).await;

    let new_password = format!("pw-{}", Uuid::new_v4());
    let (status, body) = server
        .post(
            &user.url(),
            Some(admin),
            &json!({ "password": new_password, "policies": [] }),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");

    let (status, _) = user.login(&server, &user.password).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "the old password still works");
    let (status, body) = user.login(&server, &new_password).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["auth"]["policies"], json!([]));
    let token = body["auth"]["client_token"].as_str().unwrap();
    server.post("/v1/auth/token/revoke-self", Some(token), &json!({})).await;

    user.cleanup(&server, admin).await;
}

#[tokio::test]
async fn deleting_a_user_stops_its_logins() {
    let (server, admin) = authed_server!();
    let user = ScopedUser::create(&server, admin).await;

    let (status, _) = server.delete(&user.url(), Some(admin)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = user.login(&server, &user.password).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = server.get(&user.url(), Some(admin)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = server.delete(&user.url(), Some(admin)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    user.cleanup(&server, admin).await;
}

/// A token without `sudo` on the user's path must not be able to mint
/// itself — or anyone — a new identity.
#[tokio::test]
async fn user_endpoints_require_sudo() {
    let (server, admin) = authed_server!();
    let user = ScopedUser::create(&server, admin).await;
    let (status, body) = user.login(&server, &user.password).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let token = body["auth"]["client_token"].as_str().unwrap().to_string();

    let target = format!("/v1/auth/userpass/users/itest-{}", Uuid::new_v4());
    let (status, _) = server
        .post(
            &target,
            Some(&token),
            &json!({ "password": "a long enough password", "policies": ["root"] }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = server.get(&user.url(), Some(&token)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = server.delete(&user.url(), Some(&token)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = server.get(&user.url(), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = server.get(&user.url(), Some("s.0000deadbeef")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    server.post("/v1/auth/token/revoke-self", Some(&token), &json!({})).await;
    user.cleanup(&server, admin).await;
}

#[tokio::test]
async fn invalid_user_writes_are_bad_requests() {
    let (server, admin) = authed_server!();
    let ok_name = format!("itest-{}", Uuid::new_v4());
    let cases = [
        (format!(".itest-{}", Uuid::new_v4()), json!({ "password": "a long enough password", "policies": [] })),
        (format!("itest-{}", "x".repeat(64)), json!({ "password": "a long enough password", "policies": [] })),
        (ok_name.clone(), json!({ "password": "short", "policies": [] })),
        (ok_name.clone(), json!({ "password": "a long enough password", "policies": [""] })),
        (ok_name.clone(), json!({ "password": "a long enough password", "policies": "root" })),
        (ok_name.clone(), json!({ "password": "a long enough password" })),
    ];
    for (username, body) in cases {
        let (status, response) = server
            .post(&format!("/v1/auth/userpass/users/{username}"), Some(admin), &body)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{username} {body}: {response}");
        assert!(response["error"].is_string(), "{response}");
    }
    let (status, _) = server
        .get(&format!("/v1/auth/userpass/users/{ok_name}"), Some(admin))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "an invalid write created the user");
}

// ---------------------------------------------------------------------------
// Database engine and leases
// ---------------------------------------------------------------------------

#[tokio::test]
async fn database_creds_for_unknown_role_is_not_found() {
    let (server, token) = authed_server!();
    let (status, body) = server
        .get(&format!("/v1/database/creds/itest-{}", Uuid::new_v4()), Some(token))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn database_creds_without_token_is_unauthorized() {
    let server = server!();
    let (status, _) = server.get("/v1/database/creds/anything", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn revoking_a_malformed_lease_id_is_bad_request() {
    let (server, token) = authed_server!();
    let (status, body) = server
        .post("/v1/sys/leases/revoke/not-a-uuid", Some(token), &json!({}))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid lease id");
}

#[tokio::test]
async fn revoking_an_unknown_lease_id_is_not_found() {
    let (server, token) = authed_server!();
    let (status, body) = server
        .post(
            &format!("/v1/sys/leases/revoke/{}", Uuid::new_v4()),
            Some(token),
            &json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "lease not found");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn data_url(path: &str) -> String {
    format!("/v1/secret/data/{path}")
}

fn parse_time(value: &Value) -> chrono::DateTime<chrono::Utc> {
    let raw = value.as_str().unwrap_or_else(|| panic!("expected a timestamp, got {value}"));
    raw.parse().unwrap_or_else(|e| panic!("unparseable timestamp {raw}: {e}"))
}
