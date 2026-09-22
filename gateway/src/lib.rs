//! sinter-gateway — production public MCP Gateway for Sinter (P1 core).
//!
//! P1 scope (per approved Production Gateway Security RFC): protocol types,
//! typed identities, request lifecycle state machine, ownership binding,
//! deadline/expiry, duplicate/cancellation semantics, bounded payloads,
//! edge MCP contract — all transport-independent and memory-only.
//! No HTTP endpoints, auth, persistence, or deployment in this phase.

pub mod auth;
pub mod clock;
pub mod core;
pub mod edge;
pub mod http;
pub mod id;
pub mod mcp;
pub mod oauth;
pub mod proto;
pub mod sqlite_store;
pub mod state;
pub mod store;

pub use auth::{AuthenticatedController, ControllerAuth, ControllerCredential, RegistrationToken};
pub use clock::{Clock, SystemClock, TestClock};
pub use core::GatewayCore;
pub use edge::{EdgeAction, EdgeSession};
pub use http::{GatewayHttp, GatewayServer};
pub use id::{AccountId, ControllerId, RequestId};
#[cfg(any(test, feature = "test-auth"))]
pub use mcp::TestPublicAuth;
pub use mcp::{PublicAuth, PublicPrincipal, SessionManager};
pub use proto::*;
pub use sqlite_store::SqliteStore;
pub use state::ReqState;
pub use store::{
    ControllerRecord, ControllerStatus, IdentityStore, MemoryStore, RegistrationTokenRecord,
    StoreError, TokenTake, Verifier,
};
