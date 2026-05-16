use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use rand::RngCore;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::auth::{AuthError, Manager};
use crate::config::Config;
use crate::model::{AgentStatus, AgentType, AuditEvent, Binding, Operation, RunSession};
use crate::store::{Store, StoreError};
use crate::vaultbridge::{Backend, VaultError};

#[derive(Clone)]
struct AppState {
    config: Config,
    store: Arc<Store>,
    vault: Arc<Backend>,
    auth: Arc<Manager>,
}

#[derive(Clone, Debug)]
struct ActorContext {
    agent_id: String,
    token_jti: String,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

pub async fn run(config: Config, store: Arc<Store>) -> Result<()> {
    let vault = Arc::new(Backend::new(crate::vaultbridge::Config {
        safe_root: config.safe_root.clone(),
        keyring_path: config.keyring_path.clone(),
        extra_priv_keys: config.extra_private_keys.clone(),
    })?);
    let auth = Arc::new(Manager {
        signing_key: config.signing_key.as_bytes().to_vec(),
        issuer: None,
        store: Arc::clone(&store),
    });
    let state = AppState {
        config: config.clone(),
        store,
        vault,
        auth,
    };
    let app = router(state);
    let addr = normalize_socket_addr(&config.addr)?;
    println!("fortd listening on {}", config.addr);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {}", addr))?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("serve fortd")?;
    Ok(())
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/health", get(handle_health))
        .route("/v1/ready", get(handle_ready))
        .route("/v1/auth/token", post(handle_auth_token))
        .route("/v1/auth/session/open", post(handle_auth_session_open))
        .route(
            "/v1/auth/session/refresh",
            post(handle_auth_session_refresh),
        )
        .route("/v1/auth/session/close", post(handle_auth_session_close))
        .route("/v1/auth/whoami", get(handle_auth_whoami))
        .route("/v1/auth/list", get(handle_auth_list))
        .route("/v1/auth/revoke", post(handle_auth_revoke))
        .route("/v1/secrets/get", post(handle_secret_get))
        .route("/v1/secrets/batch-get", post(handle_secret_batch_get))
        .route("/v1/secrets/list", post(handle_secret_list))
        .route("/v1/secrets/set", post(handle_secret_set))
        .route("/v1/run/session/open", post(handle_run_session_open))
        .route(
            "/v1/run/session/materialize",
            post(handle_run_session_materialize),
        )
        .route("/v1/run/session/close", post(handle_run_session_close))
        .route(
            "/v1/agents",
            get(handle_agent_list).post(handle_agent_create),
        )
        .route(
            "/v1/agents/{id}",
            get(handle_agent_get).delete(handle_agent_remove),
        )
        .route("/v1/agents/{id}/rotate", post(handle_agent_rotate))
        .route("/v1/agents/{id}/disable", post(handle_agent_disable))
        .route("/v1/agents/{id}/enable", post(handle_agent_enable))
        .route(
            "/v1/agents/{id}/policy",
            get(handle_agent_policy_get).put(handle_agent_policy_set),
        )
        .route("/v1/agents/{id}/policy/add", post(handle_agent_policy_add))
        .route(
            "/v1/agents/{id}/policy/remove",
            post(handle_agent_policy_remove),
        )
        .route(
            "/v1/agents/{id}/policy/check",
            post(handle_agent_policy_check),
        )
        .with_state(state)
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

fn normalize_socket_addr(raw: &str) -> Result<SocketAddr> {
    let trimmed = raw.trim();
    if let Ok(addr) = trimmed.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Some(port) = trimmed.strip_prefix(':') {
        return Ok(format!("0.0.0.0:{port}").parse()?);
    }
    Ok(trimmed.parse()?)
}

fn require_actor(headers: &HeaderMap, state: &AppState) -> Result<ActorContext, ApiError> {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .trim();
    let token = auth.strip_prefix("Bearer ").unwrap_or("").trim();
    if token.is_empty() {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "missing bearer token",
        ));
    }
    let claims = state
        .auth
        .parse(token)
        .map_err(|_| ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized"))?;
    Ok(ActorContext {
        agent_id: claims.agent_id,
        token_jti: claims.jti,
    })
}

fn require_admin(headers: &HeaderMap, state: &AppState) -> Result<ActorContext, ApiError> {
    let actor = require_actor(headers, state)?;
    if !is_admin_agent(state, &actor.agent_id) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "admin access required",
        ));
    }
    Ok(actor)
}

fn is_admin_agent(state: &AppState, agent_id: &str) -> bool {
    state
        .store
        .get_policy(agent_id)
        .ok()
        .map(|policy| {
            policy.bindings.iter().any(|binding| {
                binding.repo == "*" && binding.env == "*" && binding.ops.contains(&Operation::Any)
            })
        })
        .unwrap_or(false)
}

fn random_id(prefix: &str) -> String {
    let mut raw = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut raw);
    format!("{prefix}{}", hex::encode(raw))
}

#[allow(clippy::too_many_arguments)]
fn add_audit(
    state: &AppState,
    actor_id: &str,
    action: &str,
    repo: &str,
    env: &str,
    key: &str,
    decision: &str,
    reason: &str,
) {
    if action.trim().is_empty() {
        return;
    }
    let _ = state.store.add_audit(AuditEvent {
        id: random_id("aud_"),
        agent_id: actor_id.trim().to_string(),
        action: action.trim().to_string(),
        repo: repo.trim().to_string(),
        env: env.trim().to_string(),
        key: key.trim().to_string(),
        decision: decision.trim().to_string(),
        reason: reason.trim().to_string(),
        created_at: Utc::now(),
    });
}

fn parse_ttl(
    ttl: Option<&str>,
    ttl_seconds: Option<i64>,
    fallback: Duration,
) -> Result<Duration, ApiError> {
    if let Some(seconds) = ttl_seconds.filter(|value| *value > 0) {
        return Ok(Duration::from_secs(seconds as u64));
    }
    let ttl = ttl.unwrap_or("").trim();
    if ttl.is_empty() {
        return Ok(fallback);
    }
    parse_duration(ttl).ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "invalid ttl"))
}

fn parse_duration(raw: &str) -> Option<Duration> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if let Ok(seconds) = raw.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    crate::config::parse_duration_env("__unused__", Duration::from_secs(0))
        .is_zero()
        .then_some(())
        .and_then(|_| {
            let mut number = String::new();
            let mut total = Duration::from_secs(0);
            for ch in raw.chars() {
                if ch.is_ascii_digit() {
                    number.push(ch);
                    continue;
                }
                let value = number.parse::<u64>().ok()?;
                number.clear();
                total += match ch {
                    's' => Duration::from_secs(value),
                    'm' => Duration::from_secs(value * 60),
                    'h' => Duration::from_secs(value * 60 * 60),
                    'd' => Duration::from_secs(value * 60 * 60 * 24),
                    _ => return None,
                };
            }
            if number.is_empty() { Some(total) } else { None }
        })
}

fn sanitize_keys(keys: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for key in keys {
        let key = key.trim();
        if key.is_empty() || out.iter().any(|existing| existing == key) {
            continue;
        }
        out.push(key.to_string());
    }
    out
}

async fn handle_health() -> Json<Value> {
    Json(json!({ "ok": true }))
}

async fn handle_ready() -> Json<Value> {
    Json(json!({ "ok": true }))
}

#[derive(Deserialize)]
struct AuthTokenRequest {
    agent_id: String,
    #[serde(default)]
    ttl: String,
    ttl_seconds: Option<i64>,
    #[serde(default, alias = "aud")]
    audience: String,
}

async fn handle_auth_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AuthTokenRequest>,
) -> Result<Json<Value>, ApiError> {
    let _ = require_admin(&headers, &state)?;
    let agent_id = request.agent_id.trim();
    if agent_id.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "agent_id is required",
        ));
    }
    let agent = state
        .store
        .get_agent(agent_id)
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "agent not found"))?;
    if agent.status != AgentStatus::Active {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "agent is disabled"));
    }
    let ttl = parse_ttl(
        Some(&request.ttl),
        request.ttl_seconds,
        state.config.token_ttl,
    )?;
    let audience = if request.audience.trim().is_empty() {
        "fort-api"
    } else {
        request.audience.trim()
    };
    let (token, record) = state
        .auth
        .issue(&agent, ttl, audience)
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "issue token failed"))?;
    Ok(Json(json!({
        "token": token,
        "token_type": "Bearer",
        "agent_id": record.agent_id,
        "jti": record.jti,
        "aud": record.audience,
        "issued_at": record.issued_at,
        "expires_at": record.expires_at
    })))
}

#[derive(Deserialize)]
struct AuthSessionOpenRequest {
    agent_id: String,
    #[serde(default, alias = "aud")]
    audience: String,
    #[serde(default)]
    access_ttl: String,
    access_ttl_seconds: Option<i64>,
    #[serde(default)]
    refresh_ttl: String,
    refresh_ttl_seconds: Option<i64>,
}

async fn handle_auth_session_open(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AuthSessionOpenRequest>,
) -> Result<Json<Value>, ApiError> {
    let _ = require_admin(&headers, &state)?;
    let agent_id = request.agent_id.trim();
    if agent_id.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "agent_id is required",
        ));
    }
    let agent = state
        .store
        .get_agent(agent_id)
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "agent not found"))?;
    if agent.status != AgentStatus::Active {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "agent is disabled"));
    }
    let access_ttl = parse_ttl(
        Some(&request.access_ttl),
        request.access_ttl_seconds,
        state.config.token_ttl,
    )?;
    let refresh_ttl = parse_ttl(
        Some(&request.refresh_ttl),
        request.refresh_ttl_seconds,
        state.config.refresh_session_ttl,
    )?;
    let audience = if request.audience.trim().is_empty() {
        "fort-api"
    } else {
        request.audience.trim()
    };
    let (access_token, record, session, refresh_token) = state
        .auth
        .open_refresh_session(&agent, access_ttl, refresh_ttl, audience)
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "open session failed"))?;
    Ok(Json(json!({
        "session_id": session.id,
        "agent_id": record.agent_id,
        "aud": record.audience,
        "token_type": "Bearer",
        "access_token": access_token,
        "access_jti": record.jti,
        "access_issued_at": record.issued_at,
        "access_expires_at": record.expires_at,
        "refresh_token": refresh_token,
        "refresh_expires_at": session.refresh_expires_at,
    })))
}

#[derive(Deserialize)]
struct RefreshRequest {
    refresh_token: String,
}

async fn handle_auth_session_refresh(
    State(state): State<AppState>,
    Json(request): Json<RefreshRequest>,
) -> Result<Json<Value>, ApiError> {
    let refresh_token = request.refresh_token.trim();
    if refresh_token.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "refresh_token is required",
        ));
    }
    match state.auth.refresh_by_token(refresh_token) {
        Ok((access_token, record, session, next_refresh_token)) => {
            add_audit(
                &state,
                &record.agent_id,
                "auth_session_refresh",
                "",
                "",
                "",
                "allow",
                "",
            );
            Ok(Json(json!({
                "session_id": session.id,
                "agent_id": record.agent_id,
                "aud": record.audience,
                "token_type": "Bearer",
                "access_token": access_token,
                "access_jti": record.jti,
                "access_issued_at": record.issued_at,
                "access_expires_at": record.expires_at,
                "refresh_token": next_refresh_token,
                "refresh_expires_at": session.refresh_expires_at,
            })))
        }
        Err(AuthError::RefreshReuseDetected) | Err(AuthError::Unauthorized) => {
            add_audit(
                &state,
                "",
                "auth_session_refresh",
                "",
                "",
                "",
                "deny",
                "unauthorized",
            );
            Err(ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized"))
        }
        Err(AuthError::Internal) => Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "refresh failed",
        )),
    }
}

#[derive(Deserialize)]
struct SessionCloseRequest {
    #[serde(default)]
    session_id: String,
    #[serde(default)]
    refresh_token: String,
}

async fn handle_auth_session_close(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SessionCloseRequest>,
) -> Result<Json<Value>, ApiError> {
    let session_id = request.session_id.trim().to_string();
    let refresh_token = request.refresh_token.trim().to_string();
    if session_id.is_empty() && refresh_token.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "session_id or refresh_token is required",
        ));
    }
    if !refresh_token.is_empty() {
        let session = state
            .auth
            .close_refresh_session_by_token(&refresh_token)
            .map_err(|_| ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized"))?;
        return Ok(Json(json!({ "ok": true, "session_id": session.id })));
    }
    let actor = require_actor(&headers, &state)?;
    let session = state
        .store
        .get_refresh_session(&session_id)
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "session not found"))?;
    if actor.agent_id != session.agent_id && !is_admin_agent(&state, &actor.agent_id) {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "forbidden"));
    }
    let _ = state
        .auth
        .close_refresh_session_by_id(&session_id)
        .map_err(|_| ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized"))?;
    Ok(Json(json!({ "ok": true, "session_id": session_id })))
}

async fn handle_auth_whoami(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let actor = require_actor(&headers, &state)?;
    let agent = state
        .store
        .get_agent(&actor.agent_id)
        .map_err(|_| ApiError::new(StatusCode::UNAUTHORIZED, "agent not found"))?;
    Ok(Json(
        json!({ "agent": agent, "token_jti": actor.token_jti }),
    ))
}

#[derive(Deserialize)]
struct ListTokensQuery {
    #[serde(default)]
    agent_id: String,
    #[serde(default)]
    active_only: String,
}

async fn handle_auth_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListTokensQuery>,
) -> Result<Json<Value>, ApiError> {
    let _ = require_admin(&headers, &state)?;
    let active_only = matches!(query.active_only.trim(), "1" | "true" | "yes");
    Ok(Json(json!({
        "tokens": state.auth.list(&query.agent_id, active_only)
    })))
}

#[derive(Deserialize)]
struct RevokeRequest {
    jti: String,
    #[serde(default)]
    reason: String,
}

async fn handle_auth_revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RevokeRequest>,
) -> Result<Json<Value>, ApiError> {
    let _ = require_admin(&headers, &state)?;
    let record = state
        .auth
        .revoke(&request.jti, &request.reason)
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "token not found"))?;
    Ok(Json(json!({ "ok": true, "token": record })))
}

#[derive(Deserialize)]
struct SecretGetRequest {
    repo: String,
    env: String,
    key: String,
}

async fn handle_secret_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SecretGetRequest>,
) -> Result<Json<Value>, ApiError> {
    let actor = require_actor(&headers, &state)?;
    let repo = request.repo.trim();
    let env = request.env.trim();
    let key = request.key.trim();
    if repo.is_empty() || env.is_empty() || key.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "repo, env, key are required",
        ));
    }
    let (allowed, reason) =
        state
            .store
            .check_permission(&actor.agent_id, repo, env, Operation::Get);
    if !allowed {
        add_audit(
            &state,
            &actor.agent_id,
            "secret_get",
            repo,
            env,
            key,
            "deny",
            reason,
        );
        return Err(ApiError::new(StatusCode::FORBIDDEN, "forbidden"));
    }
    let value = state
        .vault
        .get(repo, env, key)
        .map_err(|error| match error {
            VaultError::NotFound => ApiError::new(StatusCode::NOT_FOUND, "secret not found"),
            VaultError::Invalid => ApiError::new(StatusCode::BAD_REQUEST, "invalid secret target"),
            _ => ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "failed to get secret"),
        })?;
    add_audit(
        &state,
        &actor.agent_id,
        "secret_get",
        repo,
        env,
        key,
        "allow",
        "",
    );
    Ok(Json(json!({
        "value": value,
        "ttl_seconds": state.config.secret_ttl.as_secs(),
        "version": 1,
        "retrieved_at": Utc::now(),
    })))
}

#[derive(Deserialize)]
struct SecretBatchGetRequest {
    repo: String,
    env: String,
    keys: Vec<String>,
}

async fn handle_secret_batch_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SecretBatchGetRequest>,
) -> Result<Json<Value>, ApiError> {
    let actor = require_actor(&headers, &state)?;
    let keys = sanitize_keys(&request.keys);
    let repo = request.repo.trim();
    let env = request.env.trim();
    if repo.is_empty() || env.is_empty() || keys.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "repo, env, keys are required",
        ));
    }
    let (allowed, reason) =
        state
            .store
            .check_permission(&actor.agent_id, repo, env, Operation::BatchGet);
    if !allowed {
        add_audit(
            &state,
            &actor.agent_id,
            "secret_batch_get",
            repo,
            env,
            "",
            "deny",
            reason,
        );
        return Err(ApiError::new(StatusCode::FORBIDDEN, "forbidden"));
    }
    let values = state
        .vault
        .batch_get(repo, env, &keys)
        .map_err(|error| match error {
            VaultError::NotFound => {
                ApiError::new(StatusCode::NOT_FOUND, "one or more secrets not found")
            }
            VaultError::Invalid => ApiError::new(StatusCode::BAD_REQUEST, "invalid secret target"),
            _ => ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "failed to batch get"),
        })?;
    add_audit(
        &state,
        &actor.agent_id,
        "secret_batch_get",
        repo,
        env,
        "",
        "allow",
        "",
    );
    Ok(Json(json!({
        "values": values,
        "ttl_seconds": state.config.secret_ttl.as_secs(),
        "retrieved_at": Utc::now(),
    })))
}

#[derive(Deserialize)]
struct SecretListRequest {
    repo: String,
    env: String,
    #[serde(default)]
    prefix: String,
}

async fn handle_secret_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SecretListRequest>,
) -> Result<Json<Value>, ApiError> {
    let actor = require_actor(&headers, &state)?;
    let repo = request.repo.trim();
    let env = request.env.trim();
    let prefix = request.prefix.trim();
    if repo.is_empty() || env.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "repo and env are required",
        ));
    }
    let (allowed, reason) =
        state
            .store
            .check_permission(&actor.agent_id, repo, env, Operation::List);
    if !allowed {
        add_audit(
            &state,
            &actor.agent_id,
            "secret_list",
            repo,
            env,
            "",
            "deny",
            reason,
        );
        return Err(ApiError::new(StatusCode::FORBIDDEN, "forbidden"));
    }
    let keys = state
        .vault
        .list(repo, env, prefix)
        .map_err(|error| match error {
            VaultError::NotFound => ApiError::new(StatusCode::NOT_FOUND, "secret scope not found"),
            VaultError::Invalid => ApiError::new(StatusCode::BAD_REQUEST, "invalid secret target"),
            _ => ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "failed to list"),
        })?;
    add_audit(
        &state,
        &actor.agent_id,
        "secret_list",
        repo,
        env,
        "",
        "allow",
        "",
    );
    Ok(Json(json!({ "keys": keys })))
}

#[derive(Deserialize)]
struct SecretSetRequest {
    repo: String,
    env: String,
    key: String,
    #[serde(default)]
    value: String,
}

async fn handle_secret_set(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SecretSetRequest>,
) -> Result<Json<Value>, ApiError> {
    let actor = require_actor(&headers, &state)?;
    let repo = request.repo.trim();
    let env = request.env.trim();
    let key = request.key.trim();
    if repo.is_empty() || env.is_empty() || key.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "repo, env, key are required",
        ));
    }
    let (allowed, reason) =
        state
            .store
            .check_permission(&actor.agent_id, repo, env, Operation::Set);
    if !allowed {
        add_audit(
            &state,
            &actor.agent_id,
            "secret_set",
            repo,
            env,
            key,
            "deny",
            reason,
        );
        return Err(ApiError::new(StatusCode::FORBIDDEN, "forbidden"));
    }
    state
        .vault
        .set(repo, env, key, &request.value)
        .map_err(|error| match error {
            VaultError::NotFound => ApiError::new(StatusCode::NOT_FOUND, "secret scope not found"),
            VaultError::Invalid => ApiError::new(StatusCode::BAD_REQUEST, "invalid secret target"),
            _ => ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "set failed"),
        })?;
    add_audit(
        &state,
        &actor.agent_id,
        "secret_set",
        repo,
        env,
        key,
        "allow",
        "",
    );
    Ok(Json(json!({ "ok": true, "version": 1 })))
}

#[derive(Deserialize)]
struct RunSessionOpenRequest {
    repo: String,
    env: String,
    keys: Vec<String>,
    #[serde(default)]
    mode: String,
    ttl_seconds: Option<i64>,
}

async fn handle_run_session_open(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RunSessionOpenRequest>,
) -> Result<Json<Value>, ApiError> {
    let actor = require_actor(&headers, &state)?;
    let repo = request.repo.trim();
    let env = request.env.trim();
    let keys = sanitize_keys(&request.keys);
    let mode = if request.mode.trim().is_empty() {
        "files".to_string()
    } else {
        request.mode.trim().to_lowercase()
    };
    if !matches!(mode.as_str(), "files" | "env") {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "mode must be files or env",
        ));
    }
    if repo.is_empty() || env.is_empty() || keys.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "repo, env, keys are required",
        ));
    }
    let (allowed, reason) =
        state
            .store
            .check_permission(&actor.agent_id, repo, env, Operation::Run);
    if !allowed {
        add_audit(
            &state,
            &actor.agent_id,
            "run_open",
            repo,
            env,
            "",
            "deny",
            reason,
        );
        return Err(ApiError::new(StatusCode::FORBIDDEN, "forbidden"));
    }
    let ttl = request
        .ttl_seconds
        .filter(|value| *value > 0)
        .map(|value| Duration::from_secs(value as u64))
        .unwrap_or(state.config.run_ttl);
    let now = Utc::now();
    let session = RunSession {
        id: random_id("sess_"),
        agent_id: actor.agent_id.clone(),
        repo: repo.to_string(),
        env: env.to_string(),
        keys,
        mode: mode.clone(),
        one_time_token: random_id("wrp_"),
        expires_at: now
            + chrono::Duration::from_std(ttl).unwrap_or_else(|_| chrono::Duration::seconds(60)),
        used_at: None,
        created_at: now,
        materialized: false,
    };
    state
        .store
        .put_session(session.clone())
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "failed to open session"))?;
    add_audit(
        &state,
        &actor.agent_id,
        "run_open",
        repo,
        env,
        "",
        "allow",
        "",
    );
    Ok(Json(json!({
        "session_id": session.id,
        "one_time_token": session.one_time_token,
        "expires_at": session.expires_at,
    })))
}

#[derive(Deserialize)]
struct RunSessionMaterializeRequest {
    session_id: String,
    one_time_token: String,
}

async fn handle_run_session_materialize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RunSessionMaterializeRequest>,
) -> Result<Json<Value>, ApiError> {
    let actor = require_actor(&headers, &state)?;
    let session_id = request.session_id.trim();
    let one_time_token = request.one_time_token.trim();
    if session_id.is_empty() || one_time_token.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "session_id and one_time_token are required",
        ));
    }
    let session = state
        .store
        .get_session(session_id)
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "session not found"))?;
    if actor.agent_id != session.agent_id && !is_admin_agent(&state, &actor.agent_id) {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "forbidden"));
    }
    if Utc::now() > session.expires_at {
        add_audit(
            &state,
            &actor.agent_id,
            "run_materialize",
            &session.repo,
            &session.env,
            "",
            "deny",
            "session_expired",
        );
        return Err(ApiError::new(StatusCode::GONE, "session expired"));
    }
    if one_time_token.as_bytes() != session.one_time_token.as_bytes() {
        add_audit(
            &state,
            &actor.agent_id,
            "run_materialize",
            &session.repo,
            &session.env,
            "",
            "deny",
            "invalid_one_time_token",
        );
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "invalid one-time token",
        ));
    }
    state
        .store
        .mark_session_used(session_id, Utc::now())
        .map_err(|error| match error {
            StoreError::Conflict => {
                ApiError::new(StatusCode::CONFLICT, "session already materialized")
            }
            _ => ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "mark used failed"),
        })?;
    let values = state
        .vault
        .batch_get(&session.repo, &session.env, &session.keys)
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "one or more secrets not found"))?;
    add_audit(
        &state,
        &actor.agent_id,
        "run_materialize",
        &session.repo,
        &session.env,
        "",
        "allow",
        "",
    );
    Ok(Json(json!({
        "mode": session.mode,
        "values": values,
        "expires_at": session.expires_at,
    })))
}

#[derive(Deserialize)]
struct RunSessionCloseRequest {
    session_id: String,
}

async fn handle_run_session_close(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RunSessionCloseRequest>,
) -> Result<Json<Value>, ApiError> {
    let actor = require_actor(&headers, &state)?;
    let session_id = request.session_id.trim();
    if session_id.is_empty() {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "session_id is required",
        ));
    }
    let session = state
        .store
        .get_session(session_id)
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "session not found"))?;
    if actor.agent_id != session.agent_id && !is_admin_agent(&state, &actor.agent_id) {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "forbidden"));
    }
    state
        .store
        .close_session(session_id)
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "close failed"))?;
    add_audit(
        &state,
        &actor.agent_id,
        "run_close",
        &session.repo,
        &session.env,
        "",
        "allow",
        "",
    );
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
struct AgentCreateRequest {
    id: String,
    #[serde(rename = "type")]
    agent_type: Option<AgentType>,
    status: Option<AgentStatus>,
}

async fn handle_agent_create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AgentCreateRequest>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let _ = require_admin(&headers, &state)?;
    let agent = state
        .store
        .create_agent(&request.id, request.agent_type, request.status, Utc::now())
        .map_err(|error| match error {
            StoreError::Conflict => ApiError::new(StatusCode::CONFLICT, "agent already exists"),
            StoreError::Invalid => ApiError::new(StatusCode::BAD_REQUEST, "invalid agent values"),
            _ => ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "create failed"),
        })?;
    Ok((StatusCode::CREATED, Json(json!(agent))))
}

#[derive(Deserialize)]
struct AgentListQuery {
    #[serde(default, rename = "type")]
    agent_type: Option<AgentType>,
    #[serde(default)]
    status: Option<AgentStatus>,
}

async fn handle_agent_list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AgentListQuery>,
) -> Result<Json<Value>, ApiError> {
    let _ = require_admin(&headers, &state)?;
    Ok(Json(json!({
        "agents": state.store.list_agents(query.agent_type, query.status)
    })))
}

async fn handle_agent_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let actor = require_actor(&headers, &state)?;
    if actor.agent_id != id && !is_admin_agent(&state, &actor.agent_id) {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "forbidden"));
    }
    let agent = state
        .store
        .get_agent(&id)
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "agent not found"))?;
    Ok(Json(json!(agent)))
}

async fn handle_agent_rotate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let _ = require_admin(&headers, &state)?;
    let (agent, revoked_tokens, revoked_sessions) = state
        .store
        .rotate_agent_credentials(&id, Utc::now())
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "agent not found"))?;
    Ok(Json(json!({
        "agent": agent,
        "revoked_token_count": revoked_tokens,
        "revoked_session_count": revoked_sessions,
        "credential_version": agent.credential_version,
        "credentials_rotated_at": agent.updated_at,
    })))
}

async fn handle_agent_disable(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    handle_agent_set_status(state, headers, id, AgentStatus::Disabled).await
}

async fn handle_agent_enable(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    handle_agent_set_status(state, headers, id, AgentStatus::Active).await
}

async fn handle_agent_set_status(
    state: AppState,
    headers: HeaderMap,
    id: String,
    status: AgentStatus,
) -> Result<Json<Value>, ApiError> {
    let _ = require_admin(&headers, &state)?;
    let agent = state
        .store
        .set_agent_status(&id, status, Utc::now())
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "agent not found"))?;
    Ok(Json(json!(agent)))
}

async fn handle_agent_remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let _ = require_admin(&headers, &state)?;
    state
        .store
        .remove_agent(&id)
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "agent not found"))?;
    Ok(Json(json!({ "ok": true })))
}

async fn handle_agent_policy_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let _ = require_admin(&headers, &state)?;
    let policy = state
        .store
        .get_policy(&id)
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "policy lookup failed"))?;
    Ok(Json(json!(policy)))
}

#[derive(Deserialize)]
struct PolicySetRequest {
    bindings: Vec<Binding>,
}

async fn handle_agent_policy_set(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<PolicySetRequest>,
) -> Result<Json<Value>, ApiError> {
    let _ = require_admin(&headers, &state)?;
    let policy = state
        .store
        .set_policy(&id, &request.bindings, Utc::now())
        .map_err(|_| ApiError::new(StatusCode::NOT_FOUND, "agent not found"))?;
    Ok(Json(json!(policy)))
}

#[derive(Deserialize)]
struct PolicyBindingRequest {
    binding: Binding,
}

async fn handle_agent_policy_add(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<PolicyBindingRequest>,
) -> Result<Json<Value>, ApiError> {
    let _ = require_admin(&headers, &state)?;
    let policy = state
        .store
        .add_binding(&id, &request.binding, Utc::now())
        .map_err(|error| match error {
            StoreError::Invalid => ApiError::new(StatusCode::BAD_REQUEST, "invalid binding"),
            StoreError::NotFound => ApiError::new(StatusCode::NOT_FOUND, "agent not found"),
            _ => ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "add binding failed"),
        })?;
    Ok(Json(json!(policy)))
}

async fn handle_agent_policy_remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<PolicyBindingRequest>,
) -> Result<Json<Value>, ApiError> {
    let _ = require_admin(&headers, &state)?;
    let policy = state
        .store
        .remove_binding(&id, &request.binding, Utc::now())
        .map_err(|error| match error {
            StoreError::Invalid => ApiError::new(StatusCode::BAD_REQUEST, "invalid binding"),
            StoreError::NotFound => ApiError::new(StatusCode::NOT_FOUND, "agent not found"),
            _ => ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "remove binding failed"),
        })?;
    Ok(Json(json!(policy)))
}

#[derive(Deserialize)]
struct PolicyCheckRequest {
    repo: String,
    env: String,
    op: Operation,
}

async fn handle_agent_policy_check(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(request): Json<PolicyCheckRequest>,
) -> Result<Json<Value>, ApiError> {
    let _ = require_admin(&headers, &state)?;
    let (allowed, reason) =
        state
            .store
            .check_permission(&id, &request.repo, &request.env, request.op);
    Ok(Json(json!({ "allowed": allowed, "reason": reason })))
}
