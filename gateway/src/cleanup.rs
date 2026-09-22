//! P7 — cleanup scheduler (RFC §F retention + §J.4b).
//!
//! Periodic reclamation of bounded lifecycle state, and nothing else:
//!   * spent registration tokens older than 24 h (store layer),
//!   * revoked controller identities older than +90 d (store layer),
//!   * expired in-flight requests / old tombstones (memory core),
//!   * idle rate-limit buckets (memory limiter).
//!
//! No durable work semantics are introduced — the scheduler only deletes
//! what the RFC retention model already says may go. Deterministic
//! lifecycle: the thread is owned by `GatewayServer`, wakes on `interval`
//! or a shutdown signal (condvar, never busy-loops), and is joined at
//! shutdown — no detached immortal task.

use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use tracing::info;

use crate::clock::Clock;
use crate::core::GatewayCore;
use crate::metrics::Metrics;
use crate::rate_limit::RateLimiter;
use crate::store::IdentityStore;

/// RFC §F: revoked controllers are retained 90 days after revocation,
/// then purgeable.
pub const REVOKED_RETENTION_MS: u64 = 90 * 24 * 60 * 60 * 1000;

/// One cleanup pass — public and side-effect-free to call for tests;
/// the scheduler is only a timer around this.
pub struct Cleanup<'a, C: Clock> {
    pub core: &'a GatewayCore<C>,
    pub store: &'a dyn IdentityStore,
    pub limiter: &'a RateLimiter<C>,
    pub clock: &'a C,
    pub metrics: &'a Metrics,
}

impl<C: Clock> Cleanup<'_, C> {
    /// Run one full pass. Returns (tokens purged, controllers purged,
    /// expired requests swept, rate buckets reclaimed).
    pub fn run_once(&self) -> (u64, u64, usize, usize) {
        let now = self.clock.unix_ms();
        let tokens = self.store.purge_spent_tokens(now).unwrap_or_else(|e| {
            self.metrics.sqlite_error(crate::metrics::SqlOp::Purge);
            tracing::warn!(error = ?e, "cleanup: spent-token purge failed");
            0
        });
        let controllers = self
            .store
            .purge_revoked_controllers(now, REVOKED_RETENTION_MS)
            .unwrap_or_else(|e| {
                self.metrics.sqlite_error(crate::metrics::SqlOp::Purge);
                tracing::warn!(error = ?e, "cleanup: revoked-controller purge failed");
                0
            });
        let expired = self.core.sweep_expired();
        if expired > 0 {
            self.metrics.deadline_exceeded(expired as u64);
        }
        let buckets = self.limiter.sweep();
        if tokens + controllers > 0 || expired > 0 || buckets > 0 {
            info!(
                tokens_purged = tokens,
                controllers_purged = controllers,
                expired_swept = expired,
                buckets_reclaimed = buckets,
                "cleanup pass complete"
            );
        }
        (tokens, controllers, expired, buckets)
    }
}

/// Periodic driver around [`Cleanup::run_once`]. Owned by `GatewayServer`:
/// `stop()` signals the thread and joins it — bounded, never detached.
///
/// The stop flag lives inside the same mutex as the condvar so the
/// check-then-wait sequence is atomic: a stop signal can never be missed
/// by a thread about to park.
pub struct CleanupScheduler {
    /// `Mutex<bool>` is the stop flag; the Condvar wakes the parker.
    wake: Arc<(Mutex<bool>, Condvar)>,
    handle: Option<JoinHandle<()>>,
}

impl CleanupScheduler {
    /// Spawn the thread. `interval` is `SINTER_GW_CLEANUP_INTERVAL_SECS`
    /// (already validated 60..=86400 at config load).
    pub fn start<C>(
        interval: Duration,
        core: Arc<GatewayCore<C>>,
        store: Arc<dyn IdentityStore>,
        limiter: Arc<RateLimiter<C>>,
        clock: C,
        metrics: Metrics,
    ) -> Self
    where
        C: Clock + 'static,
    {
        let wake: Arc<(Mutex<bool>, Condvar)> = Arc::new((Mutex::new(false), Condvar::new()));
        let handle = {
            let wk = wake.clone();
            std::thread::Builder::new()
                .name("gw-cleanup".into())
                .spawn(move || {
                    let (lock, cvar) = &*wk;
                    let mut stop = lock.lock().unwrap();
                    loop {
                        if *stop {
                            return;
                        }
                        // wait_timeout parks — no busy loop; wakes early on
                        // stop. The flag is checked under the same lock, so
                        // a notify can never be missed.
                        let (g, _t) = cvar.wait_timeout(stop, interval).unwrap();
                        stop = g;
                        if *stop {
                            return;
                        }
                        drop(stop);
                        Cleanup {
                            core: &core,
                            store: store.as_ref(),
                            limiter: &limiter,
                            clock: &clock,
                            metrics: &metrics,
                        }
                        .run_once();
                        stop = lock.lock().unwrap();
                    }
                })
                .expect("cleanup thread spawn")
        };
        Self {
            wake,
            handle: Some(handle),
        }
    }

    /// Signal + join. Bounded: the thread parks on the condvar and exits
    /// promptly on the flag; `join` therefore cannot hang indefinitely.
    pub fn stop(mut self) {
        {
            let (lock, cvar) = &*self.wake;
            *lock.lock().unwrap() = true;
            cvar.notify_all();
        }
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for CleanupScheduler {
    fn drop(&mut self) {
        // If `stop` wasn't called explicitly, still terminate deterministically.
        if self.handle.is_some() {
            let (lock, cvar) = &*self.wake;
            *lock.lock().unwrap() = true;
            cvar.notify_all();
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }
}
