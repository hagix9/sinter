//! Wire protocol v1 — Gateway ↔ controller work envelope.
//!
//! SECURITY: this envelope deliberately contains NO field capable of selecting
//! an executable, argv, environment, path, or any execution control. The only
//! payload is an opaque MCP JSON-RPC frame. `deny_unknown_fields` makes that
//! structural, not conventional.

use serde::{Deserialize, Serialize};

pub const PROTO_VERSION: u32 = 1;

// --- P1 implementation limits (RFC §11; conservative, easy to revise) ---
pub const MAX_MCP_REQUEST_BYTES: usize = 1 << 20; // 1 MiB
pub const MAX_MCP_RESPONSE_BYTES: usize = 4 << 20; // 4 MiB
pub const MAX_POLL_WAIT_MS: u64 = 60_000;
pub const DEFAULT_DEADLINE_MS: u64 = 120_000;
pub const MAX_DEADLINE_MS: u64 = 120_000;
pub const QUEUE_CAP_PER_CONTROLLER: usize = 8;
pub const MAX_INFLIGHT_PER_ACCOUNT: usize = 64;
/// Terminal-state records retained to absorb late/duplicate traffic.
pub const TOMBSTONE_TTL_MS: u64 = 15 * 60_000;
/// Controller is offline if it has not polled within this window.
pub const OFFLINE_AFTER_MS: u64 = 2 * MAX_POLL_WAIT_MS + 10_000;

/// Stable error taxonomy. Codes are wire-stable strings; messages are safe,
/// static-ish text — never internal details, credentials, or payload content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    MalformedRequest,
    UnsupportedMethod,
    InvalidLifecycleState,
    UnknownRequest,
    WrongController,
    WrongAccount,
    DuplicateResponse,
    ExpiredRequest,
    CancelledRequest,
    DeadlineExceeded,
    OversizedRequest,
    OversizedResponse,
    ControllerOffline,
    BackendUnavailable,
    BackendTerminated,
    // P2 — controller identity lifecycle.
    MalformedCredential,
    InvalidCredential,
    ExpiredRegistrationToken,
    ConsumedRegistrationToken,
    AccountHasController,
    UnknownController,
    RevokedController,
    StoreFailure,
    // P4 — controller transport.
    PollConflict,
    MissingAuth,
    UnsupportedMediaType,
    // P6 — public OAuth.
    UnboundAccount,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MalformedRequest => "malformed_request",
            Self::UnsupportedMethod => "unsupported_method",
            Self::InvalidLifecycleState => "invalid_lifecycle_state",
            Self::UnknownRequest => "unknown_request",
            Self::WrongController => "wrong_controller",
            Self::WrongAccount => "wrong_account",
            Self::DuplicateResponse => "duplicate_response",
            Self::ExpiredRequest => "expired_request",
            Self::CancelledRequest => "cancelled_request",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::OversizedRequest => "oversized_request",
            Self::OversizedResponse => "oversized_response",
            Self::ControllerOffline => "controller_offline",
            Self::BackendUnavailable => "backend_unavailable",
            Self::BackendTerminated => "backend_terminated",
            Self::MalformedCredential => "malformed_credential",
            Self::InvalidCredential => "invalid_credential",
            Self::ExpiredRegistrationToken => "expired_registration_token",
            Self::ConsumedRegistrationToken => "consumed_registration_token",
            Self::AccountHasController => "account_has_controller",
            Self::UnknownController => "unknown_controller",
            Self::RevokedController => "revoked_controller",
            Self::StoreFailure => "store_failure",
            Self::PollConflict => "poll_conflict",
            Self::MissingAuth => "missing_auth",
            Self::UnsupportedMediaType => "unsupported_media_type",
            Self::UnboundAccount => "account_unbound",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportError {
    pub code: String,
    pub message: String,
}

impl TransportError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code: code.as_str().into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for TransportError {}

/// One unit of work handed to a controller. `mcp` is a verbatim JSON-RPC
/// frame — opaque to the gateway. Absolute deadline for wire portability;
/// the core tracks the same deadline on monotonic time internally.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkItem {
    pub v: u32,
    pub request_id: String,
    pub deadline_unix_ms: u64,
    pub mcp: serde_json::Value,
}

/// Controller → Gateway result for a work item. Exactly one of `mcp`/`error`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RespondRequest {
    pub v: u32,
    pub request_id: String,
    #[serde(default)]
    pub mcp: Option<serde_json::Value>,
    #[serde(default)]
    pub error: Option<TransportError>,
}

impl RespondRequest {
    /// Split into the outcome the core stores; wrong version or ambiguous
    /// bodies rejected before any state is touched.
    pub fn into_outcome(self) -> Result<Outcome, TransportError> {
        if self.v != PROTO_VERSION {
            return Err(TransportError::new(
                ErrorCode::MalformedRequest,
                "unsupported protocol version",
            ));
        }
        match (self.mcp, self.error) {
            (Some(m), None) => Ok(Outcome::Mcp(m)),
            (None, Some(e)) => Ok(Outcome::Transport(e)),
            _ => Err(TransportError::new(
                ErrorCode::MalformedRequest,
                "exactly one of mcp/error required",
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Outcome {
    Mcp(serde_json::Value),
    Transport(TransportError),
}

/// Serialized-size bound checked on already-parsed values (the byte-level cap
/// at the HTTP edge additionally rejects before parsing — P5).
pub fn serialized_len(v: &serde_json::Value) -> usize {
    serde_json::to_vec(v).map(|b| b.len()).unwrap_or(usize::MAX)
}

// ---------- P4 controller transport types ----------

/// Bridge → Gateway: consume a registration token (RFC §6 exchange).
/// Plaintext token appears only in this request body and the response —
/// never stored, never logged.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterRequest {
    pub token: String,
}

/// Gateway → Bridge: the ONLY time the controller credential is revealed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub controller_id: String,
    pub credential: String,
}

/// Gateway → Bridge on rotation: new credential, revealed once.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateResponse {
    pub credential: String,
}

/// Gateway → Bridge poll result. `work == null` means hold timed out with
/// no eligible work — a normal, non-error outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollResponse {
    pub work: Option<WorkItem>,
}
