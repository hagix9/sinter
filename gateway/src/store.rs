//! Identity persistence boundary (P2).
//!
//! The RFC assigns durable SQLite identity state to P3. P2 defines the store
//! contract — including the atomicity guarantees the security model depends
//! on — and provides the in-memory implementation used now and in tests.
//!
//! STORE CONTRACT (security-relevant):
//! - `take_registration_token` is ATOMIC: check-present-and-unconsumed and
//!   mark-consumed happen inside one critical section. Callers can never
//!   observe an unconsumed token they fail to claim (TOCTOU-free).
//! - `insert_controller` is ATOMIC: the one-active-controller-per-account
//!   check and the insert happen inside one critical section.
//! - `rotate_credential` is ATOMIC: old verifier removal, record update, and
//!   new verifier insertion are one operation — there is no interval where
//!   both credentials authenticate.
//! - Stores never see or return plaintext secrets — only SHA-256 verifiers.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::id::{AccountId, ControllerId};

/// SHA-256 verifier of a secret, hex-encoded. Lookup keys are always full
/// digests — 256-bit CSPRNG secrets make the digest a safe, unguessable
/// primary key (no partial/prefix matching is ever performed).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Verifier(pub String);

#[derive(Debug, Clone)]
pub struct RegistrationTokenRecord {
    pub verifier: Verifier,
    pub account_id: AccountId,
    pub expires_unix_ms: u64,
    pub created_unix_ms: u64,
}

#[derive(Debug, Clone)]
pub struct ConsumedToken {
    pub verifier: Verifier,
    pub account_id: AccountId,
    pub expires_unix_ms: u64,
}

/// Result of the atomic token consume.
#[derive(Debug)]
pub enum TokenTake {
    /// Token existed and was already consumed.
    AlreadyConsumed,
    /// Token existed, unconsumed, but now >= expires_at. NOT marked consumed —
    /// repeated attempts deterministically report expired (boundary rule:
    /// now >= expires_at → expired, identical to P1 deadlines).
    Expired,
    /// Token was unconsumed and unexpired; now atomically marked consumed.
    Consumed(RegistrationTokenRecord),
    /// No such token.
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControllerStatus {
    Active,
    /// Terminal — a revoked controller can never become active again.
    Revoked,
}

#[derive(Debug, Clone)]
pub struct ControllerRecord {
    pub controller_id: ControllerId,
    pub account_id: AccountId,
    /// SHA-256 verifier of the CURRENT bearer credential. Plaintext never stored.
    pub cred_verifier: Verifier,
    pub status: ControllerStatus,
    pub created_unix_ms: u64,
    /// Last rotation time (RFC durable model: created/rotated/revoked).
    pub rotated_unix_ms: Option<u64>,
    /// Revocation time; set iff status == Revoked.
    pub revoked_unix_ms: Option<u64>,
}

#[derive(Debug)]
pub enum StoreError {
    /// Account already has an ACTIVE controller (v1: one per account).
    AccountHasActiveController,
    UnknownController,
    ControllerNotActive,
    /// Presented credential is no longer the current verifier — it was
    /// rotated away between resolution and the atomic swap.
    StaleCredential,
    Internal(String),
}

pub trait IdentityStore: Send + Sync {
    /// Persist a new (unconsumed) registration token verifier.
    fn put_registration_token(&self, rec: RegistrationTokenRecord) -> Result<(), StoreError>;

    /// ATOMIC: if the token exists, is unconsumed, and unexpired at
    /// `now_unix_ms`, mark it consumed and return it. Single-use is enforced
    /// inside the store's critical section; expiry is checked there too so an
    /// expired token is never consumed.
    fn take_registration_token(
        &self,
        verifier: &Verifier,
        now_unix_ms: u64,
    ) -> Result<TokenTake, StoreError>;

    /// ATOMIC: fail with AccountHasActiveController if the account already has
    /// an active controller, else insert. A revoked controller does NOT block
    /// re-registration (new identity, per RFC §6).
    fn insert_controller(&self, rec: ControllerRecord) -> Result<(), StoreError>;

    /// Look up a controller by current credential verifier (exact digest match).
    fn controller_by_verifier(&self, verifier: &Verifier) -> Option<ControllerRecord>;

    fn controller(&self, id: &ControllerId) -> Option<ControllerRecord>;

    /// ATOMIC credential swap for rotation. Succeeds ONLY if `expected` is
    /// still the record's current verifier — without this, two racers holding
    /// the same credential could both swap and leave two live credentials.
    /// Old verifier removal, record update, and new verifier insertion are
    /// one operation: no interval where both credentials authenticate.
    /// Fails if controller is not active.
    fn rotate_credential(
        &self,
        id: &ControllerId,
        expected: &Verifier,
        new_verifier: Verifier,
        now_unix_ms: u64,
    ) -> Result<(), StoreError>;

    /// Active -> Revoked (terminal). Idempotent-safe: revoking a revoked
    /// controller is a no-op success.
    fn set_status(
        &self,
        id: &ControllerId,
        status: ControllerStatus,
        now_unix_ms: u64,
    ) -> Result<(), StoreError>;

    /// Purge consumed/expired registration tokens older than the RFC's
    /// 24 h spent-token retention. Never touches live controllers.
    /// Returns rows removed.
    fn purge_spent_tokens(&self, now_unix_ms: u64) -> Result<u64, StoreError>;

    /// Purge controllers whose revocation is older than `retention_ms`
    /// (RFC §F: revoked +90d). Active controllers are never touched.
    /// Returns rows removed.
    fn purge_revoked_controllers(
        &self,
        now_unix_ms: u64,
        retention_ms: u64,
    ) -> Result<u64, StoreError>;

    /// Readiness probe for /readyz: is the store usable right now?
    /// In-memory is always ready; durable impls run a trivial query.
    fn readyz(&self) -> Result<(), StoreError>;

    /// Attach the shared P7 metrics handle for `sqlite_errors_total{op}`
    /// (RFC §L). Default no-op — stores without a metrics sink ignore it.
    /// F-17: wired at `GatewayHttp::new` so durable-store failures are
    /// observable without each call site remembering to attach.
    fn set_metrics(&self, _m: crate::metrics::Metrics) {}
}

/// In-memory store — correct and atomic; the P3 SQLite store must satisfy the
/// same contract (transactions where atomicity is required).
#[derive(Debug, Default)]
pub struct MemoryStore {
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    tokens: HashMap<Verifier, TokenSlot>,
    controllers: HashMap<ControllerId, ControllerRecord>,
    by_verifier: HashMap<Verifier, ControllerId>,
    by_account: HashMap<AccountId, ControllerId>,
}

#[derive(Debug)]
struct TokenSlot {
    rec: RegistrationTokenRecord,
    consumed: Option<u64>,
}

impl IdentityStore for MemoryStore {
    fn put_registration_token(&self, rec: RegistrationTokenRecord) -> Result<(), StoreError> {
        let mut g = self.inner.lock().unwrap();
        g.tokens.insert(
            rec.verifier.clone(),
            TokenSlot {
                rec,
                consumed: None,
            },
        );
        Ok(())
    }

    fn take_registration_token(
        &self,
        verifier: &Verifier,
        now_unix_ms: u64,
    ) -> Result<TokenTake, StoreError> {
        let mut g = self.inner.lock().unwrap();
        let Some(slot) = g.tokens.get_mut(verifier) else {
            return Ok(TokenTake::Missing);
        };
        if slot.consumed.is_some() {
            return Ok(TokenTake::AlreadyConsumed);
        }
        if now_unix_ms >= slot.rec.expires_unix_ms {
            return Ok(TokenTake::Expired);
        }
        slot.consumed = Some(now_unix_ms); // atomic with the read — same lock
        Ok(TokenTake::Consumed(slot.rec.clone()))
    }

    fn insert_controller(&self, rec: ControllerRecord) -> Result<(), StoreError> {
        let mut g = self.inner.lock().unwrap();
        // One ACTIVE controller per account — revoked rows do not block.
        if let Some(existing_id) = g.by_account.get(&rec.account_id) {
            if g.controllers
                .get(existing_id)
                .is_some_and(|c| c.status == ControllerStatus::Active)
            {
                return Err(StoreError::AccountHasActiveController);
            }
        }
        g.by_verifier
            .insert(rec.cred_verifier.clone(), rec.controller_id.clone());
        g.by_account
            .insert(rec.account_id.clone(), rec.controller_id.clone());
        g.controllers.insert(rec.controller_id.clone(), rec);
        Ok(())
    }

    fn controller_by_verifier(&self, verifier: &Verifier) -> Option<ControllerRecord> {
        let g = self.inner.lock().unwrap();
        g.by_verifier
            .get(verifier)
            .and_then(|id| g.controllers.get(id).cloned())
    }

    fn controller(&self, id: &ControllerId) -> Option<ControllerRecord> {
        self.inner.lock().unwrap().controllers.get(id).cloned()
    }

    fn rotate_credential(
        &self,
        id: &ControllerId,
        expected: &Verifier,
        new_verifier: Verifier,
        now_unix_ms: u64,
    ) -> Result<(), StoreError> {
        let mut g = self.inner.lock().unwrap();
        let old_verifier = {
            let Some(rec) = g.controllers.get(id) else {
                return Err(StoreError::UnknownController);
            };
            if rec.status != ControllerStatus::Active {
                return Err(StoreError::ControllerNotActive);
            }
            if rec.cred_verifier != *expected {
                return Err(StoreError::StaleCredential);
            }
            rec.cred_verifier.clone()
        };
        // One critical section: old verifier stops working exactly when the
        // new one starts — no overlap window, no gap.
        g.by_verifier.remove(&old_verifier);
        g.by_verifier.insert(new_verifier.clone(), id.clone());
        let rec = g.controllers.get_mut(id).unwrap();
        rec.cred_verifier = new_verifier;
        rec.rotated_unix_ms = Some(now_unix_ms);
        Ok(())
    }

    fn set_status(
        &self,
        id: &ControllerId,
        status: ControllerStatus,
        now_unix_ms: u64,
    ) -> Result<(), StoreError> {
        let mut g = self.inner.lock().unwrap();
        let Some(rec) = g.controllers.get_mut(id) else {
            return Err(StoreError::UnknownController);
        };
        // Revoked is terminal: never allow a transition back to Active.
        if rec.status == ControllerStatus::Revoked && status == ControllerStatus::Active {
            return Err(StoreError::ControllerNotActive);
        }
        rec.status = status;
        if status == ControllerStatus::Revoked && rec.revoked_unix_ms.is_none() {
            rec.revoked_unix_ms = Some(now_unix_ms);
        }
        Ok(())
    }

    fn purge_spent_tokens(&self, now_unix_ms: u64) -> Result<u64, StoreError> {
        const SPENT_TOKEN_RETENTION_MS: u64 = 24 * 60 * 60 * 1000; // RFC §10
        let mut g = self.inner.lock().unwrap();
        let before = g.tokens.len();
        // RFC §10: spent tokens purge after 24 h. Expired-but-unconsumed
        // tokens are retained (still deterministically `expired` on retry).
        g.tokens.retain(|_, s| match s.consumed {
            Some(at) => now_unix_ms.saturating_sub(at) < SPENT_TOKEN_RETENTION_MS,
            None => true,
        });
        Ok((before - g.tokens.len()) as u64)
    }

    fn purge_revoked_controllers(
        &self,
        now_unix_ms: u64,
        retention_ms: u64,
    ) -> Result<u64, StoreError> {
        let mut g = self.inner.lock().unwrap();
        // Collect first: verifiers must leave by_verifier with the record.
        let dead: Vec<ControllerId> = g
            .controllers
            .iter()
            .filter(|(_, c)| {
                c.status == ControllerStatus::Revoked
                    && c.revoked_unix_ms
                        .is_some_and(|t| now_unix_ms.saturating_sub(t) >= retention_ms)
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in &dead {
            if let Some(rec) = g.controllers.remove(id) {
                g.by_verifier.remove(&rec.cred_verifier);
                if g.by_account.get(&rec.account_id) == Some(id) {
                    g.by_account.remove(&rec.account_id);
                }
            }
        }
        Ok(dead.len() as u64)
    }

    fn readyz(&self) -> Result<(), StoreError> {
        Ok(())
    }
}
