//! Request lifecycle state machine (RFC §8).
//!
//!   Created ──▶ Queued ──▶ Delivered ──▶ Responded
//!      │          │            │
//!      │          ├────────────┼──▶ Expired
//!      └──────────┴────────────┴──▶ Cancelled
//!
//! Responded / Expired / Cancelled are terminal. No transition exists that
//! revives a terminal request. `created` is a transient constructor state;
//! the core never stores a request in it.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReqState {
    /// Transient constructor state — never persisted in the core maps.
    Created,
    Queued,
    Delivered,
    Responded,
    Expired,
    Cancelled,
}

impl ReqState {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Responded | Self::Expired | Self::Cancelled)
    }
}

/// The complete legal transition table. Anything not listed fails closed.
pub fn can_transition(from: ReqState, to: ReqState) -> bool {
    use ReqState::*;
    matches!(
        (from, to),
        (Created, Queued)
            | (Created, Cancelled)
            | (Queued, Delivered)
            | (Queued, Expired)
            | (Queued, Cancelled)
            | (Delivered, Responded)
            | (Delivered, Expired)
            | (Delivered, Cancelled)
    )
}

/// Attempt a transition; terminal sources and unlisted pairs fail closed.
pub fn transition(from: ReqState, to: ReqState) -> Result<ReqState, ReqState> {
    if can_transition(from, to) {
        Ok(to)
    } else {
        Err(from)
    }
}
