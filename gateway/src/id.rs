//! Typed identities. These are routing/audit identifiers only — they are NOT
//! credentials and may appear in logs. Authentication is derived upstream
//! (P2+); the core only ever sees already-validated typed identities.

use serde::{Deserialize, Serialize};
use std::fmt;

macro_rules! typed_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Construct an explicit identity (tests, config, recovery tools).
            /// Real assignments come from the identity layer, never callers.
            pub fn new(s: impl Into<String>) -> Self {
                Self(s.into())
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

typed_id!(AccountId, "Sinter account (tenant root). Server-assigned.");
typed_id!(
    ControllerId,
    "One active controller per account (v1). Server-assigned."
);

/// Unpredictable 128-bit request identifier: `req_` + 32 hex chars (UUIDv4).
/// Not derived from any identity; safe for logs; carries no authority —
/// ownership is enforced by the inflight binding, not secrecy.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestId(String);

impl RequestId {
    pub fn generate() -> Self {
        Self(format!("req_{}", uuid::Uuid::new_v4().simple()))
    }
    /// Wrap an existing wire value. The core validates it exists/owns before use.
    pub fn from_wire(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
