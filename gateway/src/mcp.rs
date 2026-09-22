//! P5 — public `/mcp` ingress: session authority + edge orchestration.
//!
//! Identity model (RFC §7/§9): an *authenticated public principal* —
//! `{account_id, subject_id}` — arrives from an authentication layer that
//! does not exist yet (P6 = OAuth). P5 therefore defines the narrow trait
//! `PublicAuth` and a feature-gated `TestPublicAuth` injection point
//! (`test-auth` / `cfg(test)` only). If no `PublicAuth` is configured,
//! `/mcp` fails closed (503) — there is no anonymous-authorized path that
//! could accidentally deploy.
//!
//! Sessions (RFC §9): `MCP-Session-Id` = `sess_` + 128-bit random, issued on
//! successful `initialize`, bound to (account, subject), memory-only
//! (RFC §10 — sessions die with the process), absolute TTL, per-account and
//! global caps. A session id is ROUTING CONTEXT, never authorization: every
//! request still requires the authenticated principal, and the session must
//! belong to that principal's account.
//!
//! Method routing (RFC §9 table):
//!   EDGE:    initialize, ping, notifications/*, tools/call name==profile,
//!            unknown methods (-32601), batches (-32600), JSON-RPC responses
//!   FORWARD: tools/list (+profile injected on the way back), tools/call
//!            (sinter tools — verbatim, opaque)
//!
//! Forwarded calls create P1 work owned by the live HTTP request:
//! caller disconnect → `CancelOnDrop` → `core.cancel` → terminal;
//! a late controller response can never complete it.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::Value;
use tracing::info;

use crate::clock::SystemClock;
use crate::core::GatewayCore;
use crate::edge::{self, EdgeAction, EdgeSession};
use crate::id::{AccountId, RequestId};
use crate::proto::*;
use crate::state::ReqState;

/// Session id wire prefix; ids are `sess_` + 128-bit random hex.
const SESSION_PREFIX: &str = "sess_";
/// Absolute session TTL — conservative P5 default (RFC gives no fixed value;
/// "bounded in lifetime"). Not sliding: logout/expiry is deterministic.
pub const SESSION_TTL: Duration = Duration::from_secs(8 * 60 * 60);
/// Per-account and global session caps — bounded creation (RFC §6 task rule).
pub const MAX_SESSIONS_PER_ACCOUNT: usize = 64;
pub const MAX_SESSIONS_GLOBAL: usize = 10_000;
/// Public `/mcp` deadline ceiling (RFC §11 request deadline ≤ 120 s).
pub const MCP_DEADLINE: Duration = Duration::from_millis(MAX_DEADLINE_MS);

// ---------- public principal ----------

/// The public identity. `account_id` is the Sinter tenant; `subject_id`
/// is the upstream identity claim. Fields are private — constructed only by
/// a `PublicAuth` implementation. `name`/`email` are optional display
/// claims for the platform profile tool; they are never routing inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicPrincipal {
    account_id: AccountId,
    subject_id: String,
    name: Option<String>,
    email: Option<String>,
}

impl PublicPrincipal {
    /// Crate-internal constructor: only authentication implementations may
    /// build a principal. Nothing else can mint account identity.
    pub(crate) fn new(
        account_id: AccountId,
        subject_id: String,
        name: Option<String>,
        email: Option<String>,
    ) -> Self {
        Self {
            account_id,
            subject_id,
            name,
            email,
        }
    }

    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }
    pub fn subject_id(&self) -> &str {
        &self.subject_id
    }
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }
}

/// Public-authentication rejection categories. Mapped by the HTTP layer to
/// the OAuth protected-resource contract (401/403 + `WWW-Authenticate`);
/// they never cross into JSON-RPC responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicAuthError {
    /// No credential presented.
    Missing,
    /// Credential present but structurally unusable (duplicated header,
    /// wrong scheme, whitespace ambiguity, oversized).
    Malformed,
    /// Credential well-formed but not valid (bad signature, expired,
    /// wrong issuer/audience, unknown key).
    Invalid,
    /// Credential valid but carries no usable account binding — the caller
    /// is authenticated yet maps to no Gateway account.
    Unbound,
}

/// Produces `PublicPrincipal` from request headers. `/mcp` never sees raw
/// identity claims — whatever proves the caller produces a
/// `PublicPrincipal`, and only that object can route work.
pub trait PublicAuth: Send + Sync {
    /// Authenticate the public request. `headers` are the raw HTTP headers;
    /// implementations extract their own credential. Rejection categories
    /// drive status + challenge; no validation internals are returned.
    /// Implementations may block (e.g. JWKS fetch) — the HTTP layer runs
    /// them on a blocking executor slot.
    fn authenticate(
        &self,
        headers: &axum::http::HeaderMap,
    ) -> Result<PublicPrincipal, PublicAuthError>;

    /// RFC 6750 `WWW-Authenticate` challenge for a rejection, if the
    /// implementation speaks the bearer contract.
    fn www_authenticate(&self, _err: &PublicAuthError) -> Option<String> {
        None
    }
}

/// TEST/INTERNAL ONLY — maps a static header to a pre-registered principal.
/// Deliberately ugly name + header (`X-Sinter-Test-Principal`) so nothing
/// production-shaped can drift into P6.
///
/// Compiled only under `cfg(test)` or the opt-in `test-auth` feature so a
/// production binary cannot construct or link this authenticator (F-01).
/// P6 MUST replace `PublicAuth` with OAuth and delete this type.
#[cfg(any(test, feature = "test-auth"))]
pub struct TestPublicAuth {
    /// presented test token -> principal
    map: HashMap<String, (AccountId, String)>,
}

#[cfg(any(test, feature = "test-auth"))]
impl TestPublicAuth {
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
    /// Console-side: register a test principal credential.
    pub fn add(&mut self, token: &str, account: &str, subject: &str) {
        self.map.insert(
            token.to_string(),
            (AccountId::new(account), subject.to_string()),
        );
    }
}

#[cfg(any(test, feature = "test-auth"))]
impl Default for TestPublicAuth {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(test, feature = "test-auth"))]
impl PublicAuth for TestPublicAuth {
    fn authenticate(
        &self,
        headers: &axum::http::HeaderMap,
    ) -> Result<PublicPrincipal, PublicAuthError> {
        let Some(v) = headers.get("x-sinter-test-principal") else {
            return Err(PublicAuthError::Missing);
        };
        let v = v.to_str().map_err(|_| PublicAuthError::Malformed)?;
        let (account, subject) = self.map.get(v).ok_or(PublicAuthError::Invalid)?;
        Ok(PublicPrincipal::new(
            account.clone(),
            subject.clone(),
            None,
            None,
        ))
    }
}

// ---------- sessions ----------

struct Session {
    account: AccountId,
    subject_id: String,
    edge: EdgeSession,
    created: Instant,
    /// Live P1 requests owned by this session — cancelled on DELETE or by
    /// `notifications/cancelled`. Keyed by the caller's canonical JSON-RPC
    /// id (`serde_json::to_string` of the id value) → internal RequestId.
    live: HashMap<String, RequestId>,
}

#[derive(Default)]
pub struct SessionManager {
    sessions: Mutex<HashMap<String, Session>>,
}

impl SessionManager {
    /// Create a session bound to (account, subject), carrying the edge
    /// lifecycle state that `initialize` just populated. Fails closed on caps.
    pub fn create(
        &self,
        principal: &PublicPrincipal,
        edge: EdgeSession,
    ) -> Result<String, TransportError> {
        let mut g = self.sessions.lock().unwrap();
        // Lazy expiry sweep — keeps the map bounded without a timer task.
        let now = Instant::now();
        g.retain(|_, s| now.duration_since(s.created) < SESSION_TTL);
        if g.len() >= MAX_SESSIONS_GLOBAL {
            return Err(TransportError::new(
                ErrorCode::BackendUnavailable,
                "session capacity reached",
            ));
        }
        let per_account = g
            .values()
            .filter(|s| s.account == *principal.account_id())
            .count();
        if per_account >= MAX_SESSIONS_PER_ACCOUNT {
            return Err(TransportError::new(
                ErrorCode::BackendUnavailable,
                "account session capacity reached",
            ));
        }
        let id = format!("{}{}", SESSION_PREFIX, {
            let mut b = [0u8; 16];
            getrandom::fill(&mut b).expect("OS CSPRNG");
            hex::encode(b)
        });
        g.insert(
            id.clone(),
            Session {
                account: principal.account_id().clone(),
                subject_id: principal.subject_id().to_string(),
                edge,
                created: now,
                live: HashMap::new(),
            },
        );
        Ok(id)
    }

    /// Run `f` against the session's edge state (validated + locked once).
    pub fn with_session<R>(
        &self,
        sid: &str,
        principal: &PublicPrincipal,
        f: impl FnOnce(&mut EdgeSession) -> R,
    ) -> Result<R, TransportError> {
        let mut g = self.sessions.lock().unwrap();
        match g.get_mut(sid) {
            Some(s)
                if s.account == *principal.account_id()
                    && s.subject_id == principal.subject_id()
                    && s.created.elapsed() < SESSION_TTL =>
            {
                Ok(f(&mut s.edge))
            }
            Some(_) => Err(TransportError::new(
                ErrorCode::WrongAccount,
                "session mismatch",
            )),
            None => Err(TransportError::new(
                ErrorCode::UnknownRequest,
                "unknown or expired session",
            )),
        }
    }

    /// Track/untrack live work owned by a session (DELETE or
    /// `notifications/cancelled` cancels it).
    pub fn track(&self, sid: &str, public_id: &Value, rid: &RequestId) {
        if let Some(s) = self.sessions.lock().unwrap().get_mut(sid) {
            s.live.insert(public_key(public_id), rid.clone());
        }
    }
    pub fn untrack(&self, sid: &str, rid: &RequestId) {
        if let Some(s) = self.sessions.lock().unwrap().get_mut(sid) {
            s.live.retain(|_, r| r != rid);
        }
    }

    /// `notifications/cancelled`: resolve the session (same ownership rules)
    /// and remove the live entry for the caller's public id, if any.
    /// Returns the internal request id to cancel.
    pub fn cancel_live(
        &self,
        sid: &str,
        principal: &PublicPrincipal,
        public_id: &Value,
    ) -> Option<RequestId> {
        let mut g = self.sessions.lock().unwrap();
        let s = g.get_mut(sid)?;
        if s.account != *principal.account_id() || s.subject_id != principal.subject_id() {
            return None; // ownership failure is silent — notifications get 202 anyway
        }
        s.live.remove(&public_key(public_id))
    }

    /// DELETE: remove the session; returns live request ids the caller must
    /// cancel. Cross-account/unknown are rejected before anything is touched.
    pub fn delete(
        &self,
        sid: &str,
        principal: &PublicPrincipal,
    ) -> Result<Vec<RequestId>, TransportError> {
        let mut g = self.sessions.lock().unwrap();
        match g.get(sid) {
            Some(s)
                if s.account == *principal.account_id()
                    && s.subject_id == principal.subject_id() => {}
            Some(_) => {
                return Err(TransportError::new(
                    ErrorCode::WrongAccount,
                    "session mismatch",
                ))
            }
            None => {
                return Err(TransportError::new(
                    ErrorCode::UnknownRequest,
                    "unknown or expired session",
                ))
            }
        }
        let s = g.remove(sid).unwrap();
        Ok(s.live.into_values().collect())
    }
}

/// Canonical key for a caller's JSON-RPC id: `serde_json::to_string` keeps
/// `7` and `"7"` distinct — they are different ids per the spec.
fn public_key(id: &Value) -> String {
    serde_json::to_string(id).unwrap_or_default()
}

// ---------- edge orchestration ----------

/// Cancels owned P1 work if the HTTP request is dropped mid-wait
/// (caller disconnect) — the RFC's caller-ownership rule. Completed calls
/// set `done` so a normal return doesn't cancel a finished request.
struct CancelOnDrop<'a> {
    core: &'a GatewayCore<SystemClock>,
    sessions: &'a SessionManager,
    sid: &'a str,
    account: &'a AccountId,
    rid: RequestId,
    done: bool,
}

impl Drop for CancelOnDrop<'_> {
    fn drop(&mut self) {
        self.sessions.untrack(self.sid, &self.rid);
        if !self.done {
            // F-03: ownership-scoped cancel — this request's own account.
            let _ = self.core.cancel(self.account, &self.rid);
            info!(request_id = %self.rid, "mcp caller disconnected — work cancelled");
        }
    }
}

/// Outcome of a POST /mcp after edge classification + optional forwarding.
pub enum McpOutcome {
    /// JSON body with 200 (single JSON-RPC object).
    Json(Value),
    /// 202 no body (notifications, JSON-RPC responses).
    Accepted,
}

/// Process one POST /mcp body for an authenticated principal.
/// `session_id` is the presented `MCP-Session-Id` (None on initialize).
/// `on_forward` is the HTTP deadline for forwarded work — capped at
/// `MCP_DEADLINE` internally.
pub async fn handle_post(
    core: &GatewayCore<SystemClock>,
    sessions: &SessionManager,
    principal: &PublicPrincipal,
    session_id: Option<&str>,
    frame: Value,
    deadline: Duration,
    metrics: &crate::metrics::Metrics,
) -> Result<(McpOutcome, Option<String>), TransportError> {
    let deadline = deadline.min(MCP_DEADLINE);
    // Session required for everything except initialize. (Batch arrays are
    // classified by the edge itself → -32600 answer, consistent either way.)
    let is_initialize = frame.get("method").and_then(Value::as_str) == Some("initialize");

    if is_initialize {
        // initialize runs against a fresh edge state; the session is created
        // only after a successful edge answer.
        let mut edge_state = EdgeSession::default();
        match edge::handle_frame(&mut edge_state, &frame) {
            EdgeAction::Answer(resp) => {
                let sid = sessions.create(principal, edge_state)?;
                info!(account = %principal.account_id(), "mcp session created");
                Ok((McpOutcome::Json(resp), Some(sid)))
            }
            // initialize can only ever produce Answer; treat anything else as
            // malformed rather than silently forwarding lifecycle traffic.
            _ => Err(TransportError::new(
                ErrorCode::MalformedRequest,
                "unexpected initialize classification",
            )),
        }
    } else {
        let sid = session_id.ok_or_else(|| {
            TransportError::new(ErrorCode::MissingAuth, "MCP-Session-Id required")
        })?;
        let account = principal.account_id().clone();
        let action = sessions.with_session(sid, principal, |edge_state| {
            edge::handle_frame(edge_state, &frame)
        })?;
        match action {
            EdgeAction::Answer(resp) => Ok((McpOutcome::Json(resp), None)),
            EdgeAction::AcceptOnly => Ok((McpOutcome::Accepted, None)),
            EdgeAction::Profile(id) => Ok((
                McpOutcome::Json(edge::profile_result(
                    &id,
                    principal.account_id(),
                    principal.name(),
                    principal.email(),
                )),
                None,
            )),
            EdgeAction::Cancel(public_id) => {
                // RFC §8: edge maps notifications/cancelled to the cancelled
                // request state. Best-effort: unknown/stale ids are a no-op,
                // the notification is still 202'd.
                if let Some(rid) = sessions.cancel_live(sid, principal, &public_id) {
                    // F-03: ownership-scoped cancel — the caller's account.
                    let _ = core.cancel(&account, &rid);
                    info!(request_id = %rid, "mcp request cancelled by notification");
                }
                Ok((McpOutcome::Accepted, None))
            }
            EdgeAction::Forward(f) => {
                let resp = forward(core, sessions, sid, &account, f, deadline, metrics).await;
                Ok((McpOutcome::Json(resp), None))
            }
        }
    }
}

/// Forward a frame through P1 work. The caller's JSON-RPC `id` round-trips
/// verbatim inside the frame — internal `request_id` stays separate.
async fn forward(
    core: &GatewayCore<SystemClock>,
    sessions: &SessionManager,
    sid: &str,
    account: &AccountId,
    frame: Value,
    deadline: Duration,
    metrics: &crate::metrics::Metrics,
) -> Value {
    let caller_id = frame.get("id").cloned().unwrap_or(Value::Null);
    let is_tools_list = frame.get("method").and_then(Value::as_str) == Some("tools/list");
    // Enqueue failure (no controller, offline, caps, oversize) is still a
    // JSON-RPC answer: the frame was valid, delivery failed.
    let (rid, rx) = match core.submit(account, frame, Some(deadline.as_millis() as u64)) {
        Ok(v) => v,
        Err(e) => return edge::transport_error_jsonrpc(&caller_id, &e),
    };
    sessions.track(sid, &caller_id, &rid);
    let mut guard = CancelOnDrop {
        core,
        sessions,
        sid,
        account,
        rid: rid.clone(),
        done: false,
    };

    // Blocking recv with absolute deadline, off the async executor. A
    // timeout/disconnect returns early with done=false → CancelOnDrop
    // cancels the work, so a late controller response can never complete it.
    let outcome = match tokio::task::spawn_blocking(move || rx.recv_timeout(deadline)).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => {
            // Timeout = honest deadline. Disconnected = the request reached a
            // terminal state without an outcome send — report its real state.
            if matches!(e, std::sync::mpsc::RecvTimeoutError::Timeout) {
                metrics.deadline_exceeded(1);
            }
            let code = match e {
                std::sync::mpsc::RecvTimeoutError::Timeout => ErrorCode::DeadlineExceeded,
                std::sync::mpsc::RecvTimeoutError::Disconnected => match core.request_state(&rid) {
                    Some(ReqState::Cancelled) => ErrorCode::CancelledRequest,
                    Some(ReqState::Expired) => ErrorCode::DeadlineExceeded,
                    _ => ErrorCode::BackendUnavailable,
                },
            };
            return edge::transport_error_jsonrpc(
                &caller_id,
                &TransportError::new(code, "request terminated"),
            );
        }
        Err(_) => {
            return edge::transport_error_jsonrpc(
                &caller_id,
                &TransportError::new(ErrorCode::BackendUnavailable, "response worker unavailable"),
            );
        }
    };
    guard.done = true;
    match outcome {
        Outcome::Mcp(v) => {
            // tools/list gets the single documented edge injection (RFC §9),
            // keyed off the REQUEST method — never inferred from result shape.
            if is_tools_list {
                edge::inject_profile_tool(&v)
            } else {
                v
            }
        }
        Outcome::Transport(e) => edge::transport_error_jsonrpc(&caller_id, &e),
    }
}
