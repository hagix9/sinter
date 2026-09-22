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

use axum::body::to_bytes;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::Router;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::auth::{AuthenticatedController, ControllerAuth};
use crate::clock::SystemClock;
use crate::core::GatewayCore;
use crate::id::RequestId;
use crate::mcp::{self, McpOutcome, PublicAuth, PublicAuthError, SessionManager};
use crate::oauth::{JwksSource, OAuthConfig, OAuthValidator};
use crate::proto::*;
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
}

impl GatewayHttp {
    pub fn new(
        core: Arc<GatewayCore<SystemClock>>,
        auth: Arc<ControllerAuth<SqliteStore, SystemClock>>,
        store: Arc<dyn IdentityStore>,
    ) -> Self {
        Self {
            core,
            auth,
            store,
            poll_hold: POLL_HOLD,
            public_auth: None,
            sessions: Arc::new(SessionManager::default()),
            mcp_deadline: mcp::MCP_DEADLINE,
            allowed_origins: Arc::new(std::collections::HashSet::new()),
            prm_document: None,
        }
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
        let validator = OAuthValidator::new(config, jwks_source)?;
        self.prm_document = Some(validator.protected_resource_metadata());
        self.public_auth = Some(Arc::new(validator));
        self.allowed_origins = Arc::new(allowed_origins);
        Ok(self)
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

// ---------- handlers ----------

/// RFC §6 exchange: registration token → controller identity + credential.
/// The plaintext credential leaves in exactly this response, once.
async fn register(State(st): State<GatewayHttp>, req: Request) -> Response {
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
        Err(e) => err_response(e),
    }
}

/// RFC §6 rotation: authenticated; new credential returned exactly once,
/// old credential dead at commit.
async fn rotate(State(st): State<GatewayHttp>, req: Request) -> Response {
    let headers = req.headers().clone();
    let (_principal, cred) = match authenticate(&st, &headers) {
        Ok(v) => v,
        Err(r) => return *r,
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
async fn poll(State(st): State<GatewayHttp>, req: Request) -> Response {
    let headers = req.headers().clone();
    if let Err(r) = bounded_body(req, MAX_POLL_BODY).await {
        return *r;
    }
    let (principal, _cred) = match authenticate(&st, &headers) {
        Ok(v) => v,
        Err(r) => return *r,
    };
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
async fn respond(State(st): State<GatewayHttp>, req: Request) -> Response {
    let headers = req.headers().clone();
    // Authenticate before body parsing — an unauthenticated request
    // receives no service.
    let (principal, _cred) = match authenticate(&st, &headers) {
        Ok(v) => v,
        Err(r) => return *r,
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
}

impl GatewayServer {
    /// Bind `addr` ("127.0.0.1:0" for ephemeral test ports) and serve.
    pub async fn start(state: GatewayHttp, addr: &str) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let bound = listener.local_addr()?;
        let (tx, mut rx) = watch::channel(false);
        let core = state.core.clone();
        let app = state.router();
        let join = tokio::spawn(async move {
            let _ = axum::serve(listener, app)
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
        })
    }

    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        self.core.shutdown(); // wake waiting polls so connections can drain
        let _ = self.join.await;
    }
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
/// validators may perform bounded JWKS fetches.
async fn public_principal(
    st: &GatewayHttp,
    headers: &HeaderMap,
) -> Result<mcp::PublicPrincipal, Box<Response>> {
    let Some(pa) = st.public_auth.clone() else {
        return Err(bad(
            ErrorCode::BackendUnavailable,
            "public ingress not configured",
        ));
    };
    let h = headers.clone();
    let challenge_pa = pa.clone();
    match tokio::task::spawn_blocking(move || pa.authenticate(&h)).await {
        Ok(Ok(p)) => Ok(p),
        Ok(Err(e)) => Err(auth_rejection(&*challenge_pa, e)),
        Err(_) => Err(bad(
            ErrorCode::BackendUnavailable,
            "authentication backend failed",
        )),
    }
}

async fn mcp_post(State(st): State<GatewayHttp>, req: Request) -> Response {
    let headers = req.headers().clone();
    if let Err(r) = check_origin(&headers, &st.allowed_origins) {
        return *r;
    }
    // Authenticate before any body processing — an unauthenticated request
    // receives no service beyond the auth challenge.
    let principal = match public_principal(&st, &headers).await {
        Ok(p) => p,
        Err(r) => return *r,
    };
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
async fn mcp_delete(State(st): State<GatewayHttp>, req: Request) -> Response {
    let headers = req.headers().clone();
    if let Err(r) = check_origin(&headers, &st.allowed_origins) {
        return *r;
    }
    let principal = match public_principal(&st, &headers).await {
        Ok(p) => p,
        Err(r) => return *r,
    };
    let Some(sid) = headers.get(MCP_HDR_SESSION).and_then(|v| v.to_str().ok()) else {
        return *bad(ErrorCode::MissingAuth, "MCP-Session-Id required");
    };
    match st.sessions.delete(sid, &principal) {
        Ok(live) => {
            for rid in &live {
                let _ = st.core.cancel(rid);
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
