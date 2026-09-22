//! P4 — production controller-facing HTTP transport.
//!
//! Thin layer only: HTTP syntax/bounds → bearer extraction → P2/P3
//! authentication → `AuthenticatedController` → P1 core → HTTP response.
//! It is NOT a second authorization system: identity comes exclusively from
//! `ControllerAuth::authenticate`; caller-supplied account/controller fields
//! are neither required nor consulted.
//!
//! Endpoints (RFC §6, §13, phase slicing P4):
//!   POST /v1/register   {token} → {controller_id, credential}   (unauthed)
//!   POST /v1/rotate     Bearer  → {credential}
//!   POST /v1/poll       Bearer  → {work: WorkItem|null}         (long-poll ≤60s)
//!   POST /v1/respond    Bearer  + RespondRequest → {}
//!   GET  /healthz       → liveness, info-minimal
//!   GET  /readyz        → identity store reachable, info-minimal
//!
//! Revocation is console-side only (RFC §6 step 5) — deliberately no
//! /v1/revoke HTTP surface. No `/mcp` here (P5). No `/v1/test/*` (prototype
//! artifact, discarded).
//!
//! TLS boundary: production terminates TLS in front of this layer
//! (RFC §13 — HTTPS only). This module serves plain HTTP for local/
//! integration use; bearer credentials must never cross plaintext public
//! transport, and no application-level crypto substitutes for TLS.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use std::net::IpAddr;

use axum::body::to_bytes;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::auth::{AuthenticatedController, ControllerAuth};
use crate::cleanup::CleanupScheduler;
use crate::clock::SystemClock;
use crate::config::GwConfig;
use crate::core::GatewayCore;
use crate::id::RequestId;
use crate::mcp::{self, McpOutcome, PublicAuth, PublicAuthError, SessionManager};
use crate::metrics::{AuthFailReason, Metrics};
use crate::oauth::{JwksSource, OAuthConfig, OAuthValidator};
use crate::proto::*;
use crate::rate_limit::{
    BucketClass, ConcurrencyGate, Limited, RateLimiter, MCP_GLOBAL_CONCURRENCY,
    REGISTER_CONCURRENCY, RESPOND_CONCURRENCY, ROTATE_CONCURRENCY,
};
use crate::sqlite_store::SqliteStore;
use crate::store::IdentityStore;

/// Per-route body caps — enforced while streaming via `to_bytes(limit)`,
/// before any unbounded buffer exists.
const MAX_REGISTER_BODY: usize = 4 << 10; // token + json envelope
const MAX_POLL_BODY: usize = 4 << 10; // no payload use; tiny cap
const MAX_RESPOND_BODY: usize = MAX_MCP_RESPONSE_BYTES + (64 << 10);
/// Long-poll hold ceiling (RFC §11: ≤ 60 s).
const POLL_HOLD: Duration = Duration::from_millis(MAX_POLL_WAIT_MS);

/// Shared handler state. The HTTP layer is only ever built on the durable
/// store — `MemoryStore` remains for fast unit tests of the core.
#[derive(Clone)]
pub struct GatewayHttp {
    core: Arc<GatewayCore<SystemClock>>,
    auth: Arc<ControllerAuth<SqliteStore, SystemClock>>,
    store: Arc<dyn IdentityStore>,
    poll_hold: Duration,
    /// None => /mcp fails closed (503). P5 tests inject TestPublicAuth;
    /// P6 replaces this with OAuth validation. There is deliberately no
    /// anonymous path.
    public_auth: Option<Arc<dyn PublicAuth>>,
    sessions: Arc<SessionManager>,
    /// Public /mcp forwarded-request deadline (RFC §11 ≤ 120 s).
    mcp_deadline: Duration,
    /// RFC §9/§13: Origin allowlist for /mcp. Absent Origin = allowed
    /// (non-browser clients); present-but-unlisted = 403. Multiple Origin
    /// headers = rejected. Empty set = reject any presented Origin.
    allowed_origins: Arc<std::collections::HashSet<String>>,
    /// RFC 9728 protected-resource document — Some only when P6 OAuth is
    /// configured; the well-known route 404s otherwise.
    prm_document: Option<serde_json::Value>,
    /// P7: token-bucket limiter (memory-only; RFC §K). Keys are account,
    /// controller, or socket peer IP — never forwarded headers.
    limiter: Arc<RateLimiter<SystemClock>>,
    /// P7: bounded in-process counters (RFC §L).
    metrics: Metrics,
    /// P7: concurrency ceilings (RFC §K "Concurrency" column).
    gate_mcp: ConcurrencyGate,
    gate_respond: ConcurrencyGate,
    gate_register: ConcurrencyGate,
    gate_rotate: ConcurrencyGate,
    /// P7: optional `/metrics` admin bind (None = off; loopback-only).
    metrics_bind: Option<SocketAddr>,
    /// P7: identity/bucket GC period (RFC §M `SINTER_GW_CLEANUP_INTERVAL_SECS`).
    cleanup_interval: Duration,
}

impl GatewayHttp {
    pub fn new(
        core: Arc<GatewayCore<SystemClock>>,
        auth: Arc<ControllerAuth<SqliteStore, SystemClock>>,
        store: Arc<dyn IdentityStore>,
    ) -> Self {
        let st = Self {
            core,
            auth,
            store,
            poll_hold: POLL_HOLD,
            public_auth: None,
            sessions: Arc::new(SessionManager::default()),
            mcp_deadline: mcp::MCP_DEADLINE,
            allowed_origins: Arc::new(std::collections::HashSet::new()),
            prm_document: None,
            limiter: Arc::new(RateLimiter::new(SystemClock, Default::default())),
            metrics: Metrics::new(),
            gate_mcp: ConcurrencyGate::new(MCP_GLOBAL_CONCURRENCY),
            gate_respond: ConcurrencyGate::new(RESPOND_CONCURRENCY),
            gate_register: ConcurrencyGate::new(REGISTER_CONCURRENCY),
            gate_rotate: ConcurrencyGate::new(ROTATE_CONCURRENCY),
            metrics_bind: None,
            cleanup_interval: Duration::from_secs(3600),
        };
        // F-17: wire `sqlite_errors_total{op}` into the store at the
        // composition root — durable-store failures are observable.
        st.store.set_metrics(st.metrics.clone());
        st
    }

    /// Attach the P5 public-auth implementation (test injection now, OAuth
    /// in P6) plus the Origin allowlist for /mcp.
    pub fn with_public_auth(
        mut self,
        auth: Arc<dyn PublicAuth>,
        allowed_origins: std::collections::HashSet<String>,
    ) -> Self {
        self.public_auth = Some(auth);
        self.allowed_origins = Arc::new(allowed_origins);
        self
    }

    /// P6 production path: attach the OAuth resource-server validator as
    /// the public-auth implementation plus the Origin allowlist. Validates
    /// config at construction — fails closed, never starts anonymous.
    pub fn with_oauth(
        mut self,
        config: OAuthConfig,
        jwks_source: Box<dyn JwksSource>,
        allowed_origins: std::collections::HashSet<String>,
    ) -> Result<Self, TransportError> {
        let mut validator = OAuthValidator::new(config, jwks_source)?;
        validator.set_metrics(self.metrics.clone());
        self.prm_document = Some(validator.protected_resource_metadata());
        self.public_auth = Some(Arc::new(validator));
        self.allowed_origins = Arc::new(allowed_origins);
        Ok(self)
    }

    /// P7: apply the validated runtime configuration (RFC §M). Rate limits,
    /// metrics endpoint, cleanup period — all restart-scoped.
    pub fn with_config(mut self, cfg: &GwConfig) -> Self {
        self.limiter = Arc::new(RateLimiter::new(SystemClock, cfg.rate.clone()));
        self.metrics_bind = cfg.metrics_enabled.then_some(cfg.metrics_bind);
        self.cleanup_interval = cfg.cleanup_interval;
        self
    }

    /// P7: attach a pre-built limiter — deterministic control in tests.
    pub fn with_limiter(mut self, limiter: Arc<RateLimiter<SystemClock>>) -> Self {
        self.limiter = limiter;
        self
    }

    /// P7: shared metrics handle (for store/oauth wiring and tests).
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// P7: rate limiter handle (for the cleanup scheduler/tests).
    pub fn limiter(&self) -> &Arc<RateLimiter<SystemClock>> {
        &self.limiter
    }

    /// Test/config hook: shorten the /mcp forwarded-request deadline —
    /// never lengthen past the RFC cap.
    pub fn with_mcp_deadline(mut self, d: Duration) -> Self {
        self.mcp_deadline = d.min(mcp::MCP_DEADLINE);
        self
    }

    /// Handle to the in-memory session manager (test/introspection use;
    /// sessions are never persisted — restart creates an empty manager).
    pub fn sessions(&self) -> &Arc<SessionManager> {
        &self.sessions
    }

    /// Test/config hook: shorten the long-poll hold — never lengthen past
    /// the RFC cap.
    pub fn with_poll_hold(mut self, hold: Duration) -> Self {
        self.poll_hold = hold.min(POLL_HOLD);
        self
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route("/v1/register", post(register))
            .route("/v1/rotate", post(rotate))
            .route("/v1/poll", post(poll))
            .route("/v1/respond", post(respond))
            .route("/healthz", get(healthz))
            .route("/readyz", get(readyz))
            // /mcp: POST = JSON-RPC message; DELETE = session logout;
            // GET → 405 (RFC §9 — no SSE; sinter emits no server traffic).
            .route("/mcp", post(mcp_post).delete(mcp_delete).get(mcp_get))
            // RFC 9728 protected-resource metadata (P6): base form plus the
            // resource-path-suffixed form for the /mcp resource.
            .route(
                "/.well-known/oauth-protected-resource",
                get(protected_resource_metadata),
            )
            .route(
                "/.well-known/oauth-protected-resource/mcp",
                get(protected_resource_metadata),
            )
            .layer(middleware::from_fn_with_state(
                self.metrics.clone(),
                observe_http,
            ))
            .with_state(self.clone())
    }
}

// ---------- error mapping ----------

/// ErrorCode → HTTP status. Deliberately coarse: the wire `code` carries the
/// stable signal; status classes avoid enumeration oracles and never leak
/// store internals, verifier hashes, or credential material.
fn status_for(code: &str) -> StatusCode {
    match code {
        "malformed_request" => StatusCode::BAD_REQUEST,
        "unsupported_media_type" => StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "missing_auth" | "malformed_credential" | "invalid_credential" | "revoked_controller" => {
            StatusCode::UNAUTHORIZED
        }
        "wrong_controller" | "wrong_account" | "account_unbound" => StatusCode::FORBIDDEN,
        "unknown_request" | "unknown_controller" => StatusCode::NOT_FOUND,
        "duplicate_response"
        | "poll_conflict"
        | "account_has_controller"
        | "consumed_registration_token" => StatusCode::CONFLICT,
        "expired_request"
        | "cancelled_request"
        | "expired_registration_token"
        | "deadline_exceeded" => StatusCode::GONE,
        "invalid_lifecycle_state" => StatusCode::CONFLICT,
        "oversized_request" | "oversized_response" => StatusCode::PAYLOAD_TOO_LARGE,
        "controller_offline" | "backend_unavailable" => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn err_response(e: TransportError) -> Response {
    let status = status_for(&e.code);
    // Sanitize: internal store detail (sqlite text) never crosses the wire.
    let message = if e.code == "store_failure" {
        "internal error".to_string()
    } else {
        e.message
    };
    tracing::info!(code = %e.code, %status, "request rejected");
    (
        status,
        Json(json!({ "error": { "code": e.code, "message": message } })),
    )
        .into_response()
}

fn bad(code: ErrorCode, msg: &str) -> Box<Response> {
    Box::new(err_response(TransportError::new(code, msg)))
}

// ---------- bearer extraction ----------

/// Strict `Authorization: Bearer <opaque>` parsing.
/// - exactly ONE Authorization header (ambiguous multiples rejected)
/// - scheme `Bearer` (case-insensitive per RFC 7235), single token
/// - credential bytes fully opaque: no trimming, no case-folding, no prefix
///   matching — `ControllerCredential::parse` validates shape downstream
/// - the header value is never logged or reflected in errors
fn presented_bearer(headers: &HeaderMap) -> Result<String, Box<Response>> {
    let vals: Vec<_> = headers.get_all(header::AUTHORIZATION).iter().collect();
    let [v] = vals.as_slice() else {
        return Err(bad(ErrorCode::MissingAuth, "bearer credential required"));
    };
    let s = v
        .to_str()
        .map_err(|_| bad(ErrorCode::MalformedCredential, "malformed credential"))?;
    let cred = s
        .strip_prefix("Bearer ")
        .or_else(|| s.strip_prefix("bearer "))
        .or_else(|| s.strip_prefix("BEARER "))
        .ok_or_else(|| bad(ErrorCode::MalformedCredential, "expected Bearer scheme"))?;
    if cred.is_empty() || cred.contains(' ') {
        return Err(bad(ErrorCode::MalformedCredential, "malformed credential"));
    }
    Ok(cred.to_string())
}

fn authenticate(
    state: &GatewayHttp,
    headers: &HeaderMap,
) -> Result<(AuthenticatedController, String), Box<Response>> {
    let cred = presented_bearer(headers)?;
    match state.auth.authenticate(&cred) {
        Ok(p) => Ok((p, cred)),
        Err(e) => Err(Box::new(err_response(e))),
    }
}

/// Bounded body read: `to_bytes` enforces the cap during collection — an
/// oversized body is rejected without an unbounded buffer existing.
async fn bounded_body(req: Request, cap: usize) -> Result<Vec<u8>, Box<Response>> {
    to_bytes(req.into_body(), cap)
        .await
        .map(|b| b.to_vec())
        .map_err(|_| {
            Box::new(
                (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    Json(json!({"error":{"code":"oversized_request","message":"body too large"}})),
                )
                    .into_response(),
            )
        })
}

/// Strict JSON body: `application/json` required, shape-checked by serde
/// (`deny_unknown_fields` on the structs rejects smuggled fields).
async fn json_body<T: serde::de::DeserializeOwned>(
    headers: &HeaderMap,
    req: Request,
    cap: usize,
) -> Result<T, Box<Response>> {
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !ct.starts_with("application/json") {
        return Err(bad(
            ErrorCode::UnsupportedMediaType,
            "application/json required",
        ));
    }
    let bytes = bounded_body(req, cap).await?;
    serde_json::from_slice(&bytes)
        .map_err(|_| bad(ErrorCode::MalformedRequest, "malformed JSON body"))
}

// ---------- P7 rate-limit / metrics plumbing ----------

/// Socket peer identity for pre-auth limiter keys. Forwarded/XFF-style
/// headers are ignored entirely (RFC §K): only the TCP connection's remote
/// address is trusted.
fn peer_ip(info: &ConnectInfo<SocketAddr>) -> IpAddr {
    info.0.ip()
}

/// Uniform RFC §K rejection: `429` + `Retry-After`, categorical body.
/// No identity, bucket state, or route detail is revealed.
fn rate_limited_response(lim: Limited) -> Response {
    let mut r = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({
            "error": {"code": "rate_limited", "message": "rate limit exceeded"}
        })),
    )
        .into_response();
    r.headers_mut().insert(
        header::RETRY_AFTER,
        axum::http::HeaderValue::from(lim.retry_after_secs),
    );
    r
}

fn concurrency_limited(st: &GatewayHttp) -> Box<Response> {
    st.metrics.concurrency_limited();
    Box::new(rate_limited_response(Limited {
        retry_after_secs: 1,
    }))
}

/// Identity-keyed bucket check → uniform 429.
fn check_rate(st: &GatewayHttp, class: BucketClass, key: &str) -> Result<(), Box<Response>> {
    st.limiter.check(class, key).map_err(|lim| {
        st.metrics.rate_limited(class);
        Box::new(rate_limited_response(lim))
    })
}

/// Peer-IP-keyed bucket check → uniform 429.
fn check_rate_ip(st: &GatewayHttp, class: BucketClass, ip: IpAddr) -> Result<(), Box<Response>> {
    st.limiter.check_ip(class, ip).map_err(|lim| {
        st.metrics.rate_limited(class);
        Box::new(rate_limited_response(lim))
    })
}

/// RFC §K row 8: every credential rejection also debits the per-IP
/// `invalid_auth` bucket; when empty the caller sees 429 instead of the
/// auth error — brute-force becomes self-limiting without touching the
/// authenticated path.
fn authfail_or(st: &GatewayHttp, ip: IpAddr, reason: AuthFailReason, err: Response) -> Response {
    st.metrics.auth_failure(reason);
    match st.limiter.check_ip(BucketClass::AuthFailIp, ip) {
        Ok(()) => err,
        Err(lim) => {
            st.metrics.rate_limited(BucketClass::AuthFailIp);
            rate_limited_response(lim)
        }
    }
}

fn public_auth_reason(e: &PublicAuthError) -> AuthFailReason {
    match e {
        PublicAuthError::Missing => AuthFailReason::Missing,
        PublicAuthError::Malformed => AuthFailReason::Malformed,
        PublicAuthError::Invalid => AuthFailReason::Invalid,
        PublicAuthError::Unbound => AuthFailReason::Unbound,
    }
}

/// Whether a controller-endpoint rejection counts against the invalid-auth
/// bucket: credential/registration failures yes, protocol errors no.
fn is_auth_failure(status: StatusCode) -> bool {
    matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN)
}

/// RFC §L: `http_requests_total{route,method,status_class}` +
/// `http_request_seconds{route,method}` — the route label comes from axum's
/// `MatchedPath` so cardinality stays bounded by the router itself.
async fn observe_http(State(metrics): State<Metrics>, req: Request, next: Next) -> Response {
    let route = req
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|p| p.as_str().to_string());
    let method = req.method().to_string();
    let t0 = std::time::Instant::now();
    let resp = next.run(req).await;
    metrics.observe_http(
        route.as_deref(),
        &method,
        resp.status().as_u16(),
        t0.elapsed().as_secs_f64(),
    );
    resp
}

// ---------- handlers ----------

/// RFC §6 exchange: registration token → controller identity + credential.
/// The plaintext credential leaves in exactly this response, once.
async fn register(
    State(st): State<GatewayHttp>,
    info: ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let ip = peer_ip(&info);
    // RFC §K: 5/min per source IP — pre-auth, socket-IP keyed.
    if let Err(r) = check_rate_ip(&st, BucketClass::RegisterIp, ip) {
        return *r;
    }
    let _gate = match st.gate_register.acquire() {
        Some(g) => g,
        None => return *concurrency_limited(&st),
    };
    let headers = req.headers().clone();
    let body = match json_body::<RegisterRequest>(&headers, req, MAX_REGISTER_BODY).await {
        Ok(b) => b,
        Err(r) => return *r,
    };
    match st.auth.register(&st.core, &body.token) {
        Ok((principal, cred)) => (
            StatusCode::OK,
            Json(RegisterResponse {
                controller_id: principal.controller_id().as_str().to_string(),
                credential: cred.expose().to_string(),
            }),
        )
            .into_response(),
        Err(e) => {
            let r = err_response(e);
            if is_auth_failure(r.status()) {
                authfail_or(&st, ip, AuthFailReason::Invalid, r)
            } else {
                r
            }
        }
    }
}

/// RFC §6 rotation: authenticated; new credential returned exactly once,
/// old credential dead at commit.
async fn rotate(
    State(st): State<GatewayHttp>,
    info: ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let ip = peer_ip(&info);
    let headers = req.headers().clone();
    let (principal, cred) = match authenticate(&st, &headers) {
        Ok(v) => v,
        Err(r) => return authfail_or(&st, ip, AuthFailReason::Controller, *r),
    };
    // RFC §K: 10/min per controller.
    if let Err(r) = check_rate(
        &st,
        BucketClass::RotateController,
        principal.account_id().as_str(),
    ) {
        return *r;
    }
    let _gate = match st.gate_rotate.acquire() {
        Some(g) => g,
        None => return *concurrency_limited(&st),
    };
    match st.auth.rotate(&cred) {
        Ok(new) => (
            StatusCode::OK,
            Json(RotateResponse {
                credential: new.expose().to_string(),
            }),
        )
            .into_response(),
        Err(e) => err_response(e),
    }
}

/// Long-poll: authenticate → bind (idempotent; the P3 restart reconnect
/// path) → `poll_wait`. Work arrives → 200 {work}; hold elapses →
/// 200 {work:null}. The blocking wait runs on tokio's blocking pool so the
/// async runtime never parks on the core mutex; caller disconnect drops the
/// response — the wait itself is bounded by `poll_hold` regardless.
/// Poll bodies are accepted but carry no authorization or routing meaning.
///
/// F-07: `ensure_active` is re-checked immediately before every delivery,
/// so a mid-poll revocation aborts with `revoked_controller` and does not
/// hand out post-revocation work.
async fn poll(
    State(st): State<GatewayHttp>,
    info: ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let ip = peer_ip(&info);
    let headers = req.headers().clone();
    if let Err(r) = bounded_body(req, MAX_POLL_BODY).await {
        return *r;
    }
    let (principal, _cred) = match authenticate(&st, &headers) {
        Ok(v) => v,
        Err(r) => return authfail_or(&st, ip, AuthFailReason::Controller, *r),
    };
    // RFC §K: 2/s per controller — long-poll rate is deliberately tight.
    if let Err(r) = check_rate(
        &st,
        BucketClass::PollController,
        principal.account_id().as_str(),
    ) {
        return *r;
    }
    if let Err(e) = st.auth.bind(&st.core, &principal) {
        return err_response(e);
    }
    let core = st.core.clone();
    let ctl = principal.controller_id().clone();
    let hold = st.poll_hold;
    let auth = st.auth.clone();
    let res = tokio::task::spawn_blocking(move || {
        let auth = auth;
        let ctl_for_check = ctl.clone();
        core.poll_wait(&ctl, hold, move || auth.ensure_active(&ctl_for_check))
    })
    .await
    .unwrap_or_else(|_| {
        Err(TransportError::new(
            ErrorCode::BackendUnavailable,
            "poll worker unavailable",
        ))
    });
    match res {
        Ok(work) => (StatusCode::OK, Json(PollResponse { work })).into_response(),
        Err(e) => err_response(e),
    }
}

/// Respond: authenticated principal + parsed envelope → core.respond.
/// A valid `request_id` alone never authorizes — ownership is the core's.
/// F-07: `ensure_active` runs again after body parse, closing the
/// authenticate→respond gap against a concurrent revocation.
async fn respond(
    State(st): State<GatewayHttp>,
    info: ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let ip = peer_ip(&info);
    let headers = req.headers().clone();
    // Authenticate before body parsing — an unauthenticated request
    // receives no service.
    let (principal, _cred) = match authenticate(&st, &headers) {
        Ok(v) => v,
        Err(r) => return authfail_or(&st, ip, AuthFailReason::Controller, *r),
    };
    // RFC §K: 20/s per controller + ≤32 in-flight responses.
    if let Err(r) = check_rate(
        &st,
        BucketClass::RespondController,
        principal.account_id().as_str(),
    ) {
        return *r;
    }
    let _gate = match st.gate_respond.acquire() {
        Some(g) => g,
        None => return *concurrency_limited(&st),
    };
    let body = match json_body::<RespondRequest>(&headers, req, MAX_RESPOND_BODY).await {
        Ok(b) => b,
        Err(r) => return *r,
    };
    if let Err(e) = st.auth.ensure_active(principal.controller_id()) {
        return err_response(e);
    }
    let rid = RequestId::from_wire(body.request_id.clone());
    let outcome = match body.into_outcome() {
        Ok(o) => o,
        Err(e) => return err_response(e),
    };
    match st.core.respond(principal.controller_id(), &rid, outcome) {
        Ok(()) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(e) => err_response(e),
    }
}

/// Liveness: nothing but "the process answered". No dependency info, no
/// controller data, no counts (RFC §13: info-minimal).
async fn healthz() -> Response {
    (StatusCode::OK, Json(json!({"status": "ok"}))).into_response()
}

/// Readiness: the identity store must answer a trivial query. No detail.
async fn readyz(State(st): State<GatewayHttp>) -> Response {
    match st.store.readyz() {
        Ok(()) => (StatusCode::OK, Json(json!({"status": "ready"}))).into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "not_ready"})),
        )
            .into_response(),
    }
}

// ---------- server ----------

/// A running loopback HTTP server. `shutdown` stops accept, wakes all
/// waiting long-polls (via `GatewayCore::shutdown`), and drains.
pub struct GatewayServer {
    pub addr: SocketAddr,
    shutdown_tx: watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
    core: Arc<GatewayCore<SystemClock>>,
    /// P7: cleanup scheduler — stopped first so no GC pass runs against a
    /// torn-down server.
    cleanup: Option<CleanupScheduler>,
    /// P7: optional loopback `/metrics` listener (RFC §L; off by default).
    metrics_srv: Option<(watch::Sender<bool>, tokio::task::JoinHandle<()>)>,
    /// Bound address of the metrics listener (None when disabled).
    pub metrics_addr: Option<SocketAddr>,
}

impl GatewayServer {
    /// Bind `addr` ("127.0.0.1:0" for ephemeral test ports) and serve.
    /// Starts the P7 cleanup scheduler and (if configured) the loopback
    /// metrics listener alongside the HTTP task.
    pub async fn start(state: GatewayHttp, addr: &str) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let bound = listener.local_addr()?;
        let (tx, mut rx) = watch::channel(false);
        let core = state.core.clone();
        let cleanup = Some(CleanupScheduler::start(
            state.cleanup_interval,
            state.core.clone(),
            state.store.clone(),
            state.limiter.clone(),
            SystemClock,
            state.metrics.clone(),
        ));
        let metrics_srv = if let Some(bind) = state.metrics_bind {
            Some(start_metrics_server(state.metrics.clone(), state.core.clone(), bind).await?)
        } else {
            None
        };
        let metrics_addr = metrics_srv.as_ref().map(|(_, _, a)| *a);
        let app = state.router();
        let join = tokio::spawn(async move {
            // ConnectInfo supplies the socket peer IP — the only trusted
            // pre-auth identity (RFC §K); forwarded headers never reach a
            // limiter key.
            let _ = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async move {
                let _ = rx.changed().await;
            })
            .await;
        });
        Ok(Self {
            addr: bound,
            shutdown_tx: tx,
            join,
            core,
            cleanup,
            metrics_addr,
            metrics_srv: metrics_srv.map(|(tx, j, _)| (tx, j)),
        })
    }

    pub async fn shutdown(self) {
        if let Some(c) = self.cleanup {
            c.stop();
        }
        if let Some((tx, j)) = self.metrics_srv {
            let _ = tx.send(true);
            let _ = j.await;
        }
        let _ = self.shutdown_tx.send(true);
        self.core.shutdown(); // wake waiting polls so connections can drain
        let _ = self.join.await;
    }
}

/// P7 §L: optional loopback `/metrics` — off by default, plaintext
/// counters; gauges refreshed from core at render time. No auth: it binds
/// loopback only and `GwConfig` refuses a non-loopback bind.
async fn start_metrics_server(
    metrics: Metrics,
    core: Arc<GatewayCore<SystemClock>>,
    bind: SocketAddr,
) -> std::io::Result<(watch::Sender<bool>, tokio::task::JoinHandle<()>, SocketAddr)> {
    // F-13: the loopback invariant is enforced at the bind site, not only
    // in env-config parsing — a programmatically built GwConfig cannot
    // expose the unauthenticated metrics endpoint on a public interface.
    if !bind.ip().is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "metrics listener must bind loopback",
        ));
    }
    let listener = TcpListener::bind(bind).await?;
    let bound = listener.local_addr()?;
    let (tx, mut rx) = watch::channel(false);
    let app = Router::new()
        .route(
            "/metrics",
            get(move || {
                let m = metrics.clone();
                let c = core.clone();
                async move {
                    m.set_controller_active_polls(c.active_poll_count());
                    m.set_work_queued(c.work_queued_count());
                    m.set_controller_online(c.online_controller_count());
                    (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                        m.render(),
                    )
                }
            }),
        )
        .with_state(());
    let j = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = rx.changed().await;
            })
            .await;
    });
    Ok((tx, j, bound))
}

// ---------- /mcp public ingress (P5) ----------

const MCP_HDR_SESSION: &str = "mcp-session-id";
const MCP_HDR_VERSION: &str = "mcp-protocol-version";
/// /mcp body cap = RFC §11 MCP request limit (1 MiB) + tiny envelope slack.
const MAX_MCP_BODY: usize = MAX_MCP_REQUEST_BYTES + (4 << 10);

fn check_origin(
    headers: &HeaderMap,
    allowed: &std::collections::HashSet<String>,
) -> Result<(), Box<Response>> {
    let vals: Vec<_> = headers.get_all(header::ORIGIN).iter().collect();
    match vals.as_slice() {
        [] => Ok(()), // non-browser clients may omit it
        [v] => {
            let s = v
                .to_str()
                .map_err(|_| bad(ErrorCode::MalformedRequest, "malformed Origin"))?;
            if allowed.contains(s) {
                Ok(())
            } else {
                Err(bad(ErrorCode::WrongAccount, "origin not allowed"))
            }
        }
        _ => Err(bad(ErrorCode::MalformedRequest, "ambiguous Origin")),
    }
}

/// `MCP-Protocol-Version`: post-init required; missing → assume 2025-03-26
/// (RFC §9). Present values must be a version the edge implements;
/// malformed/unknown → 400.
fn check_protocol_version(headers: &HeaderMap) -> Result<(), Box<Response>> {
    let vals: Vec<_> = headers.get_all(MCP_HDR_VERSION).iter().collect();
    match vals.as_slice() {
        [] => Ok(()), // missing → assumed 2025-03-26 (edge default)
        [v] => {
            let s = v.to_str().unwrap_or("");
            if crate::edge::EDGE_PROTOCOL_VERSIONS.contains(&s) {
                Ok(())
            } else {
                Err(bad(
                    ErrorCode::MalformedRequest,
                    "unsupported MCP-Protocol-Version",
                ))
            }
        }
        _ => Err(bad(ErrorCode::MalformedRequest, "ambiguous version header")),
    }
}

/// RFC 9728 protected-resource metadata. 404 when OAuth is not
/// configured — the document exists only on a production-auth deployment.
async fn protected_resource_metadata(State(st): State<GatewayHttp>) -> Response {
    match &st.prm_document {
        Some(doc) => (StatusCode::OK, Json(doc.clone())).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Map a public-auth rejection to the OAuth protected-resource contract:
/// 401 (+ WWW-Authenticate) for missing/malformed/invalid credentials,
/// 403 for an authenticated-but-unbound principal.
fn auth_rejection(pa: &dyn PublicAuth, e: PublicAuthError) -> Box<Response> {
    let (code, msg) = match e {
        PublicAuthError::Missing => (ErrorCode::MissingAuth, "authentication required"),
        PublicAuthError::Malformed => (ErrorCode::MalformedCredential, "malformed credential"),
        PublicAuthError::Invalid => (ErrorCode::InvalidCredential, "invalid credential"),
        PublicAuthError::Unbound => (
            ErrorCode::UnboundAccount,
            "identity not bound to an account",
        ),
    };
    let mut resp = *bad(code, msg);
    if let Some(challenge) = pa.www_authenticate(&e) {
        if let Ok(v) = challenge.parse() {
            resp.headers_mut().insert("www-authenticate", v);
        }
    }
    Box::new(resp)
}

/// Authenticate the public caller. Runs on a blocking executor slot —
/// validators may perform bounded JWKS fetches. On failure the categorical
/// `AuthFailReason` is returned alongside the response so the caller can
/// feed `auth_failures_total{reason_class}` and the invalid-auth bucket.
async fn public_principal(
    st: &GatewayHttp,
    headers: &HeaderMap,
) -> Result<mcp::PublicPrincipal, (Option<AuthFailReason>, Box<Response>)> {
    let Some(pa) = st.public_auth.clone() else {
        return Err((
            None,
            bad(
                ErrorCode::BackendUnavailable,
                "public ingress not configured",
            ),
        ));
    };
    let h = headers.clone();
    let challenge_pa = pa.clone();
    match tokio::task::spawn_blocking(move || pa.authenticate(&h)).await {
        Ok(Ok(p)) => Ok(p),
        Ok(Err(e)) => Err((
            Some(public_auth_reason(&e)),
            auth_rejection(&*challenge_pa, e),
        )),
        Err(_) => Err((
            None,
            bad(
                ErrorCode::BackendUnavailable,
                "authentication backend failed",
            ),
        )),
    }
}

async fn mcp_post(
    State(st): State<GatewayHttp>,
    info: ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let headers = req.headers().clone();
    if let Err(r) = check_origin(&headers, &st.allowed_origins) {
        return *r;
    }
    let ip = peer_ip(&info);
    // RFC §K pre-auth ordering: global concurrency cap → 300/s global
    // bucket → 30/s/IP → OAuth → 30/s+60 burst per account.
    let _active = st.metrics.mcp_active();
    let _gate = match st.gate_mcp.acquire() {
        Some(g) => g,
        None => return *concurrency_limited(&st),
    };
    if let Err(r) = check_rate(&st, BucketClass::McpGlobal, "gateway") {
        return *r;
    }
    if let Err(r) = check_rate_ip(&st, BucketClass::McpPreAuthIp, ip) {
        return *r;
    }
    // Authenticate before any body processing — an unauthenticated request
    // receives no service beyond the auth challenge.
    let principal = match public_principal(&st, &headers).await {
        Ok(p) => p,
        Err((reason, r)) => match reason {
            Some(reason) => return authfail_or(&st, ip, reason, *r),
            // Backend failure is not a credential failure — no authfail
            // debit, no reason label.
            None => return *r,
        },
    };
    // RFC §K: 30/s + burst 60 per authenticated account.
    if let Err(r) = check_rate(
        &st,
        BucketClass::McpAccount,
        principal.account_id().as_str(),
    ) {
        return *r;
    }
    if let Err(r) = check_protocol_version(&headers) {
        return *r;
    }
    let frame: serde_json::Value = match json_body(&headers, req, MAX_MCP_BODY).await {
        Ok(v) => v,
        Err(r) => return *r,
    };
    let sid = headers.get(MCP_HDR_SESSION).and_then(|v| v.to_str().ok());
    match mcp::handle_post(
        &st.core,
        &st.sessions,
        &principal,
        sid,
        frame,
        st.mcp_deadline,
        &st.metrics,
    )
    .await
    {
        Ok((McpOutcome::Json(resp), new_session)) => {
            let mut resp_http = (StatusCode::OK, Json(resp)).into_response();
            if let Some(sid) = new_session {
                resp_http
                    .headers_mut()
                    .insert(MCP_HDR_SESSION, sid.parse().unwrap());
            }
            resp_http
        }
        Ok((McpOutcome::Accepted, _)) => StatusCode::ACCEPTED.into_response(),
        Err(e) => {
            // Errors inside an initialized session map to JSON-RPC -32000
            // where a caller id exists; envelope/identity failures are HTTP.
            err_response(e)
        }
    }
}

/// DELETE /mcp: logout — invalidate the session and cancel its live work.
/// Same principal only; repeated DELETE → 404 (deterministic).
async fn mcp_delete(
    State(st): State<GatewayHttp>,
    info: ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let headers = req.headers().clone();
    if let Err(r) = check_origin(&headers, &st.allowed_origins) {
        return *r;
    }
    let ip = peer_ip(&info);
    let _active = st.metrics.mcp_active();
    // Same bucket classes as POST /mcp (RFC §K applies to the route).
    if let Err(r) = check_rate(&st, BucketClass::McpGlobal, "gateway") {
        return *r;
    }
    if let Err(r) = check_rate_ip(&st, BucketClass::McpPreAuthIp, ip) {
        return *r;
    }
    let principal = match public_principal(&st, &headers).await {
        Ok(p) => p,
        Err((reason, r)) => match reason {
            Some(reason) => return authfail_or(&st, ip, reason, *r),
            None => return *r,
        },
    };
    if let Err(r) = check_rate(
        &st,
        BucketClass::McpAccount,
        principal.account_id().as_str(),
    ) {
        return *r;
    }
    let Some(sid) = headers.get(MCP_HDR_SESSION).and_then(|v| v.to_str().ok()) else {
        return *bad(ErrorCode::MissingAuth, "MCP-Session-Id required");
    };
    match st.sessions.delete(sid, &principal) {
        Ok(live) => {
            // F-03: cancel every in-flight request this session owns —
            // ownership-scoped to the caller's account.
            for rid in &live {
                let _ = st.core.cancel(principal.account_id(), rid);
            }
            tracing::info!(session = %sid, cancelled = live.len(), "mcp session deleted");
            StatusCode::OK.into_response()
        }
        Err(e) => err_response(e),
    }
}

/// GET /mcp → 405: Sinter emits no server-initiated traffic, so no SSE
/// stream exists to offer (RFC §9 — deliberate 405).
async fn mcp_get() -> Response {
    StatusCode::METHOD_NOT_ALLOWED.into_response()
}
