//! Transport-independent gateway core: ownership, queues, inflight requests,
//! and the lifecycle state machine. One `Mutex<Inner>` guards ALL mutable
//! state — no second lock exists, so lock-ordering deadlocks (the prototype's
//! AB/BA bug) are structurally impossible.
//!
//! Memory-only by design (RFC §10): if the process dies, all active work dies
//! with it. Nothing here reconstructs stale work after restart.
//!
//! Logging policy (I-7): only request/controller/account identifiers and
//! state transitions are logged — never MCP payloads, credentials, or args.

use std::collections::{HashMap, VecDeque};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;
use tracing::{debug, info};

use crate::clock::Clock;
use crate::id::{AccountId, ControllerId, RequestId};
use crate::proto::*;
use crate::state::{can_transition, ReqState};

struct Ctrl {
    account: AccountId,
    last_seen: Instant,
    queue: VecDeque<RequestId>,
}

struct Request {
    account: AccountId,
    controller: ControllerId,
    state: ReqState,
    deadline_mono: Instant,
    deadline_unix_ms: u64,
    mcp: Value,
    tx: Option<Sender<Outcome>>,
}

struct Tombstone {
    state: ReqState,
    at: Instant,
}

#[derive(Default)]
struct Inner {
    controllers: HashMap<ControllerId, Ctrl>,
    by_account: HashMap<AccountId, ControllerId>,
    requests: HashMap<RequestId, Request>,
    tombstones: HashMap<RequestId, Tombstone>,
    /// Controllers currently inside a long-poll wait. RFC §11: at most ONE
    /// concurrent poll per controller — a second poll is rejected.
    active_polls: std::collections::HashSet<ControllerId>,
    /// Set on shutdown(): waiting polls return promptly instead of holding
    /// to their deadline.
    shutdown: bool,
}

pub struct GatewayCore<C: Clock> {
    clock: C,
    inner: Mutex<Inner>,
    /// Wakes waiting long-polls on submit/shutdown. Paired with `inner`'s
    /// mutex — the ONLY lock, so the prototype's AB/BA ordering remains
    /// structurally impossible.
    work_notify: Condvar,
}

impl<C: Clock> GatewayCore<C> {
    pub fn with_clock(clock: C) -> Self {
        Self {
            clock,
            inner: Mutex::new(Inner::default()),
            work_notify: Condvar::new(),
        }
    }

    /// P1 binding primitive: associate a controller with an account.
    /// v1 policy — exactly one active controller per account; a controller
    /// cannot be re-bound to a different account (re-registration creates a
    /// new controller identity upstream, P2).
    pub fn register_controller(
        &self,
        controller: &ControllerId,
        account: &AccountId,
    ) -> Result<(), TransportError> {
        let mut g = self.inner.lock().unwrap();
        if let Some(existing) = g.controllers.get_mut(controller) {
            if &existing.account == account {
                existing.last_seen = self.clock.mono();
                return Ok(());
            }
            return Err(TransportError::new(
                ErrorCode::WrongAccount,
                "controller bound to a different account",
            ));
        }
        if let Some(other) = g.by_account.get(account) {
            if other != controller {
                return Err(TransportError::new(
                    ErrorCode::WrongAccount,
                    "account already has an active controller",
                ));
            }
        }
        g.controllers.insert(
            controller.clone(),
            Ctrl {
                account: account.clone(),
                last_seen: self.clock.mono(),
                queue: VecDeque::new(),
            },
        );
        g.by_account.insert(account.clone(), controller.clone());
        info!(%controller, %account, "controller registered");
        Ok(())
    }

    /// Account → its bound controller, if any (observability + auth rebind).
    pub fn account_controller(&self, account: &AccountId) -> Option<ControllerId> {
        self.inner.lock().unwrap().by_account.get(account).cloned()
    }

    /// Replace an account's controller binding. Used ONLY by the auth layer
    /// after verifying the prior controller is Revoked — callers must not use
    /// this to bypass the one-active-controller rule. The old controller's
    /// queue entry is removed; its inflight requests remain owned by the old
    /// id and can never be answered (its credential is dead upstream).
    pub fn replace_account_controller(
        &self,
        account: &AccountId,
        new_controller: &ControllerId,
    ) -> Result<(), TransportError> {
        let mut g = self.inner.lock().unwrap();
        if let Some(old) = g.by_account.get(account).cloned() {
            if old == *new_controller {
                return Ok(());
            }
            g.controllers.remove(&old);
        }
        if g.controllers.contains_key(new_controller) {
            return Err(TransportError::new(
                ErrorCode::WrongAccount,
                "controller id already bound",
            ));
        }
        g.controllers.insert(
            new_controller.clone(),
            Ctrl {
                account: account.clone(),
                last_seen: self.clock.mono(),
                queue: VecDeque::new(),
            },
        );
        g.by_account.insert(account.clone(), new_controller.clone());
        info!(controller = %new_controller, %account, "controller binding replaced");
        Ok(())
    }

    fn online(&self, g: &Inner, controller: &ControllerId) -> bool {
        g.controllers.get(controller).is_some_and(|c| {
            self.clock.mono().duration_since(c.last_seen) < Duration::from_millis(OFFLINE_AFTER_MS)
        })
    }

    pub fn controller_online(&self, controller: &ControllerId) -> bool {
        let g = self.inner.lock().unwrap();
        self.online(&g, controller)
    }

    /// Public `/mcp` side: enqueue one MCP frame for the account's controller.
    /// Returns the request id and a receiver for its single completion.
    pub fn submit(
        &self,
        account: &AccountId,
        mcp: Value,
        deadline_ms: Option<u64>,
    ) -> Result<(RequestId, Receiver<Outcome>), TransportError> {
        if serialized_len(&mcp) > MAX_MCP_REQUEST_BYTES {
            return Err(TransportError::new(
                ErrorCode::OversizedRequest,
                "mcp request exceeds size limit",
            ));
        }
        let deadline_ms = deadline_ms
            .unwrap_or(DEFAULT_DEADLINE_MS)
            .min(MAX_DEADLINE_MS);

        let mut g = self.inner.lock().unwrap();
        let cid = g.by_account.get(account).cloned().ok_or_else(|| {
            TransportError::new(ErrorCode::ControllerOffline, "no controller for account")
        })?;
        if !self.online(&g, &cid) {
            return Err(TransportError::new(
                ErrorCode::ControllerOffline,
                "controller has not polled recently",
            ));
        }
        let inflight = g
            .requests
            .values()
            .filter(|r| &r.account == account)
            .count();
        if inflight >= MAX_INFLIGHT_PER_ACCOUNT {
            return Err(TransportError::new(
                ErrorCode::BackendUnavailable,
                "in-flight capacity reached",
            ));
        }
        if g.controllers[&cid].queue.len() >= QUEUE_CAP_PER_CONTROLLER {
            return Err(TransportError::new(
                ErrorCode::BackendUnavailable,
                "controller queue full",
            ));
        }

        let now = self.clock.mono();
        let request_id = RequestId::generate();
        let (tx, rx) = channel();
        g.requests.insert(
            request_id.clone(),
            Request {
                account: account.clone(),
                controller: cid.clone(),
                state: ReqState::Queued, // Created -> Queued at birth
                deadline_mono: now + Duration::from_millis(deadline_ms),
                deadline_unix_ms: self.clock.unix_ms() + deadline_ms,
                mcp,
                tx: Some(tx),
            },
        );
        g.controllers
            .get_mut(&cid)
            .expect("binding consistent")
            .queue
            .push_back(request_id.clone());
        debug!(%request_id, %account, controller = %cid, "request queued");
        drop(g);
        self.work_notify.notify_all(); // wake any waiting poll for this ctl
        Ok((request_id, rx))
    }

    /// Controller side: pop the next live work item. Dead entries are reaped
    /// lazily (a queued request may have expired/cancelled in place).
    /// Pop is destructive — a delivered item is never re-delivered.
    ///
    /// This low-level entry does not re-check controller status; callers that
    /// sit behind authentication must use `poll_wait` with `still_authorised`
    /// (F-07) or re-check before accepting the item.
    pub fn poll(&self, controller: &ControllerId) -> Result<Option<WorkItem>, TransportError> {
        let mut g = self.inner.lock().unwrap();
        self.poll_locked(&mut g, controller, &mut || Ok(()))
    }

    /// Long-poll variant (P4): if no work is queued, wait up to `hold` for a
    /// submission to arrive. The state lock is RELEASED during the wait —
    /// `Condvar::wait_timeout` parks on it, never busy-loops, and submit()
    /// `notify_all` wakes waiters. `hold` is capped by the caller/transport
    /// (RFC: <= 60 s); this method just honors whatever bound it's given.
    ///
    /// RFC §11: ONE concurrent poll per controller. A second concurrent poll
    /// for the same controller is rejected `poll_conflict` — a controller can
    /// never multiply its delivery capacity.
    ///
    /// `still_authorised` is re-checked immediately before every delivery
    /// (F-07). A mid-wait revocation therefore aborts the poll with that
    /// error and leaves the work item queued (not delivered).
    pub fn poll_wait(
        &self,
        controller: &ControllerId,
        hold: Duration,
        mut still_authorised: impl FnMut() -> Result<(), TransportError>,
    ) -> Result<Option<WorkItem>, TransportError> {
        let mut g = self.inner.lock().unwrap();
        if !g.active_polls.insert(controller.clone()) {
            return Err(TransportError::new(
                ErrorCode::PollConflict,
                "a poll for this controller is already in flight",
            ));
        }
        // RAII-free explicit release on every return path (single function).
        let release = |g: &mut Inner| {
            g.active_polls.remove(controller);
        };
        let deadline = self.clock.mono() + hold;
        loop {
            match self.poll_locked(&mut g, controller, &mut still_authorised) {
                Err(e) => {
                    release(&mut g);
                    return Err(e);
                }
                Ok(Some(w)) => {
                    release(&mut g);
                    return Ok(Some(w));
                }
                Ok(None) => {}
            }
            let now = self.clock.mono();
            if g.shutdown || now >= deadline {
                release(&mut g);
                return Ok(None);
            }
            let remaining = deadline - now;
            let (guard, _timeout) = self.work_notify.wait_timeout(g, remaining).unwrap();
            g = guard;
        }
    }

    /// Terminate all waiting long-polls promptly (Gateway shutdown path).
    /// Queued work is untouched — it dies with the process per RFC §10.
    pub fn shutdown(&self) {
        self.inner.lock().unwrap().shutdown = true;
        self.work_notify.notify_all();
    }

    /// Shared dequeue: assumes `g` is already locked. Reaps dead queue
    /// entries, updates last_seen, delivers one live item or None.
    /// `still_authorised` runs immediately before marking Delivered (F-07).
    fn poll_locked(
        &self,
        g: &mut Inner,
        controller: &ControllerId,
        still_authorised: &mut impl FnMut() -> Result<(), TransportError>,
    ) -> Result<Option<WorkItem>, TransportError> {
        {
            let Some(ctrl) = g.controllers.get_mut(controller) else {
                return Err(TransportError::new(
                    ErrorCode::WrongController,
                    "unknown controller",
                ));
            };
            ctrl.last_seen = self.clock.mono();
        }

        loop {
            let Some(rid) = g
                .controllers
                .get_mut(controller)
                .and_then(|c| c.queue.pop_front())
            else {
                return Ok(None);
            };
            let now = self.clock.mono();
            let Some(req) = g.requests.get_mut(&rid) else {
                continue; // already finalized elsewhere
            };
            if now >= req.deadline_mono {
                finalize(
                    g,
                    now,
                    &rid,
                    ReqState::Expired,
                    Some(Outcome::Transport(TransportError::new(
                        ErrorCode::DeadlineExceeded,
                        "request expired",
                    ))),
                );
                continue;
            }
            // F-07: re-check authorization immediately before delivery so a
            // mid-poll revocation cannot hand out post-revocation work.
            if let Err(e) = still_authorised() {
                if let Some(ctrl) = g.controllers.get_mut(controller) {
                    ctrl.queue.push_front(rid);
                }
                return Err(e);
            }
            debug_assert!(can_transition(req.state, ReqState::Delivered));
            req.state = ReqState::Delivered;
            debug!(request_id = %rid, %controller, "work delivered");
            return Ok(Some(WorkItem {
                v: PROTO_VERSION,
                request_id: rid.as_str().to_string(),
                deadline_unix_ms: req.deadline_unix_ms,
                mcp: req.mcp.clone(),
            }));
        }
    }

    /// Controller side: return the outcome for a delivered work item.
    /// Ownership is mandatory — knowing a request_id is never sufficient.
    pub fn respond(
        &self,
        controller: &ControllerId,
        request_id: &RequestId,
        outcome: Outcome,
    ) -> Result<(), TransportError> {
        if let Outcome::Mcp(v) = &outcome {
            if serialized_len(v) > MAX_MCP_RESPONSE_BYTES {
                return Err(TransportError::new(
                    ErrorCode::OversizedResponse,
                    "mcp response exceeds size limit",
                ));
            }
        }
        let mut g = self.inner.lock().unwrap();
        let now = self.clock.mono();
        let Some(req) = g.requests.get(request_id) else {
            return Err(match g.tombstones.get(request_id) {
                Some(t) => terminal_error(t.state),
                None => TransportError::new(ErrorCode::UnknownRequest, "unknown request_id"),
            });
        };
        // Ownership before state: a wrong-controller probe learns nothing new.
        if &req.controller != controller {
            return Err(TransportError::new(
                ErrorCode::WrongController,
                "request belongs to a different controller",
            ));
        }
        if req.state != ReqState::Delivered {
            return Err(TransportError::new(
                ErrorCode::InvalidLifecycleState,
                "request is not awaiting a response",
            ));
        }
        if now >= req.deadline_mono {
            finalize(
                &mut g,
                now,
                request_id,
                ReqState::Expired,
                Some(Outcome::Transport(TransportError::new(
                    ErrorCode::DeadlineExceeded,
                    "request expired",
                ))),
            );
            return Err(TransportError::new(
                ErrorCode::DeadlineExceeded,
                "response arrived after deadline",
            ));
        }
        finalize(&mut g, now, request_id, ReqState::Responded, Some(outcome));
        info!(request_id = %request_id, %controller, "request completed");
        Ok(())
    }

    /// Caller-side termination (HTTP disconnect or notifications/cancelled):
    /// terminal — a late controller response can never complete the call.
    ///
    /// F-03 (P7): ownership is mandatory. A `RequestId` alone never
    /// authorizes — the caller must present the owning account. Foreign
    /// rids fail `wrong_account` before any state is touched.
    pub fn cancel(
        &self,
        account: &AccountId,
        request_id: &RequestId,
    ) -> Result<(), TransportError> {
        let mut g = self.inner.lock().unwrap();
        let now = self.clock.mono();
        let Some(req) = g.requests.get(request_id) else {
            return Err(match g.tombstones.get(request_id) {
                Some(t) => terminal_error(t.state),
                None => TransportError::new(ErrorCode::UnknownRequest, "unknown request_id"),
            });
        };
        if &req.account != account {
            return Err(TransportError::new(
                ErrorCode::WrongAccount,
                "request belongs to a different account",
            ));
        }
        finalize(
            &mut g,
            now,
            request_id,
            ReqState::Cancelled,
            Some(Outcome::Transport(TransportError::new(
                ErrorCode::CancelledRequest,
                "request cancelled",
            ))),
        );
        info!(request_id = %request_id, "request cancelled");
        Ok(())
    }

    /// Expire all open requests past their deadline; sweep old tombstones.
    /// Deterministic — driven by the injected clock, not wall sleeps.
    pub fn sweep_expired(&self) -> usize {
        let mut g = self.inner.lock().unwrap();
        let now = self.clock.mono();
        let dead: Vec<RequestId> = g
            .requests
            .iter()
            .filter(|(_, r)| now >= r.deadline_mono)
            .map(|(id, _)| id.clone())
            .collect();
        let n = dead.len();
        for rid in dead {
            finalize(
                &mut g,
                now,
                &rid,
                ReqState::Expired,
                Some(Outcome::Transport(TransportError::new(
                    ErrorCode::DeadlineExceeded,
                    "request expired",
                ))),
            );
        }
        let ttl = Duration::from_millis(TOMBSTONE_TTL_MS);
        g.tombstones.retain(|_, t| now.duration_since(t.at) < ttl);
        n
    }

    /// Observability gauges (P7 metrics) — counts only, no identity labels.
    pub fn active_poll_count(&self) -> usize {
        self.inner.lock().unwrap().active_polls.len()
    }
    /// Requests in a non-terminal state (queued + delivered).
    pub fn work_queued_count(&self) -> usize {
        self.inner.lock().unwrap().requests.len()
    }
    /// Controllers seen within the online window.
    pub fn online_controller_count(&self) -> usize {
        let g = self.inner.lock().unwrap();
        g.controllers.keys().filter(|c| self.online(&g, c)).count()
    }

    /// Observability for tests/diagnostics: current state, terminal included.
    pub fn request_state(&self, request_id: &RequestId) -> Option<ReqState> {
        let g = self.inner.lock().unwrap();
        g.requests
            .get(request_id)
            .map(|r| r.state)
            .or_else(|| g.tombstones.get(request_id).map(|t| t.state))
    }
}

impl GatewayCore<crate::clock::SystemClock> {
    pub fn new() -> Self {
        Self::with_clock(crate::clock::SystemClock)
    }
}

impl Default for GatewayCore<crate::clock::SystemClock> {
    fn default() -> Self {
        Self::new()
    }
}

fn terminal_error(state: ReqState) -> TransportError {
    match state {
        ReqState::Responded => {
            TransportError::new(ErrorCode::DuplicateResponse, "request already completed")
        }
        ReqState::Expired => TransportError::new(ErrorCode::ExpiredRequest, "request expired"),
        ReqState::Cancelled => {
            TransportError::new(ErrorCode::CancelledRequest, "request cancelled")
        }
        _ => TransportError::new(ErrorCode::InvalidLifecycleState, "request is terminal"),
    }
}

/// Move a request to a terminal state: verify the transition is legal, move
/// the record to tombstones, and deliver the final outcome exactly once.
fn finalize(g: &mut Inner, now: Instant, rid: &RequestId, to: ReqState, outcome: Option<Outcome>) {
    let Some(mut req) = g.requests.remove(rid) else {
        return;
    };
    if !can_transition(req.state, to) {
        // Fail closed: an illegal transition still terminates the record so a
        // bug can never leave a request hanging — but it is loudly logged.
        tracing::error!(request_id = %rid, from = ?req.state, to = ?to, "illegal state transition");
    }
    req.state = to;
    if let (Some(tx), Some(out)) = (req.tx.take(), outcome) {
        let _ = tx.send(out);
    }
    g.tombstones
        .insert(rid.clone(), Tombstone { state: to, at: now });
}
