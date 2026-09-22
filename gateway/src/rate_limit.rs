//! P7 — rate limiting (RFC §K).
//!
//! Token buckets + concurrency gates, memory-only. Keys are post-auth
//! identities (account/controller) or the socket peer IP — NEVER
//! `Forwarded`/`X-Forwarded-*`/`X-Real-IP` values (v1: no trusted proxy).
//!
//! State bounds (RFC §K): at most [`MAX_BUCKET_KEYS`] entries across all
//! classes; entries idle longer than [`BUCKET_IDLE_TTL`] are reclaimed by
//! `sweep()` (driven by the cleanup scheduler and opportunistically on
//! insert). A full map of still-active buckets fails closed (429) —
//! attacker-churned identities cannot grow memory or buy capacity.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::clock::Clock;

/// Hard cap on distinct bucket keys across all classes (RFC §K: ~50k).
pub const MAX_BUCKET_KEYS: usize = 50_000;
/// Buckets idle longer than this are reclaimable (RFC §K: ≤ 5 min).
pub const BUCKET_IDLE_TTL: Duration = Duration::from_secs(300);
/// Opportunistic full-sweep cadence inside `check` (avoids per-call scans).
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Rate-limit bucket classes — the complete v1 set (RFC §K). Label values
/// for `rate_limited_total{bucket_class}` come only from this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BucketClass {
    /// `POST/DELETE /mcp` — per authenticated account.
    McpAccount,
    /// `POST /mcp` — gateway-wide ceiling.
    McpGlobal,
    /// `/mcp` requests — per socket IP, consumed before authentication.
    McpPreAuthIp,
    /// `POST /v1/poll` — per authenticated controller.
    PollController,
    /// `POST /v1/respond` — per authenticated controller.
    RespondController,
    /// `POST /v1/register` — per socket IP.
    RegisterIp,
    /// `POST /v1/rotate` — per authenticated controller.
    RotateController,
    /// Failed authentication (401/403) on credential routes — per socket IP.
    AuthFailIp,
}

impl BucketClass {
    /// Metrics label (`rate_limited_total{bucket_class}`) — fixed set.
    pub fn label(self) -> &'static str {
        match self {
            Self::McpAccount => "mcp_account",
            Self::McpGlobal => "mcp_global",
            Self::McpPreAuthIp => "mcp_preauth_ip",
            Self::PollController => "poll_controller",
            Self::RespondController => "respond_controller",
            Self::RegisterIp => "register_ip",
            Self::RotateController => "rotate_controller",
            Self::AuthFailIp => "authfail_ip",
        }
    }
}

/// Ratified v1 defaults (RFC §K). Per-request rates are the `SINTER_GW_*`
/// env-configurable values; bursts not in §M stay code constants.
#[derive(Debug, Clone)]
pub struct RateLimits {
    /// Master switch (`SINTER_GW_RATE_ENABLED`). `false` = no limiting —
    /// the config-revert rollback lever (RFC §O). Default true.
    pub enabled: bool,
    /// `SINTER_GW_RATE_MCP_RPS` — per-account /mcp steady rate.
    pub mcp_rps: f64,
    /// `SINTER_GW_RATE_MCP_BURST` — per-account /mcp burst.
    pub mcp_burst: u32,
    /// `SINTER_GW_RATE_MCP_GLOBAL_RPS` — gateway-wide /mcp steady rate.
    pub mcp_global_rps: f64,
    /// `SINTER_GW_RATE_POLL_RPS` — per-controller poll rate.
    pub poll_rps: f64,
    /// `SINTER_GW_RATE_RESPOND_RPS` — per-controller respond rate.
    pub respond_rps: f64,
    /// `SINTER_GW_RATE_REGISTER_PER_MIN` — per-IP register rate.
    pub register_per_min: f64,
    /// `SINTER_GW_RATE_ROTATE_PER_MIN` — per-controller rotate rate.
    pub rotate_per_min: f64,
    /// `SINTER_GW_RATE_AUTHFAIL_PER_MIN` — per-IP invalid-auth rate.
    pub authfail_per_min: f64,
}

impl Default for RateLimits {
    /// RFC §K table defaults.
    fn default() -> Self {
        Self {
            enabled: true,
            mcp_rps: 30.0,
            mcp_burst: 60,
            mcp_global_rps: 300.0,
            poll_rps: 2.0,
            respond_rps: 20.0,
            register_per_min: 5.0,
            rotate_per_min: 10.0,
            authfail_per_min: 30.0,
        }
    }
}

// Code-constant bursts for classes without a §M env var (RFC §M: existing
// caps stay code defaults — not every knob is exported).
const MCP_GLOBAL_BURST: f64 = 600.0;
const MCP_PREAUTH_IP_RPS: f64 = 60.0;
const MCP_PREAUTH_IP_BURST: f64 = 120.0;
const POLL_BURST: f64 = 5.0;
const RESPOND_BURST: f64 = 40.0;
const REGISTER_BURST: f64 = 10.0;
const ROTATE_BURST: f64 = 20.0;
const AUTHFAIL_BURST: f64 = 60.0;

/// Concurrency ceilings (RFC §K "Concurrency" column) — code constants.
pub const MCP_GLOBAL_CONCURRENCY: usize = 256;
pub const RESPOND_CONCURRENCY: usize = 32;
pub const REGISTER_CONCURRENCY: usize = 4;
pub const ROTATE_CONCURRENCY: usize = 4;

struct Bucket {
    tokens: f64,
    /// Last refill instant — also the LRU/idle timestamp.
    touched: Instant,
}

impl Bucket {
    fn refill(&mut self, now: Instant, rate: f64, cap: f64) {
        let elapsed = now.saturating_duration_since(self.touched).as_secs_f64();
        self.tokens = (self.tokens + elapsed * rate).min(cap);
        self.touched = now;
    }
}

struct Map {
    buckets: HashMap<String, Bucket>,
    last_sweep: Instant,
}

/// Token-bucket limiter over bounded keyed state. The clock is injectable
/// so tests are deterministic — no sleeps.
pub struct RateLimiter<C: Clock> {
    clock: C,
    cfg: RateLimits,
    inner: Mutex<Map>,
}

/// Whole seconds until `key`'s bucket next admits a request — RFC §K
/// `Retry-After` value (seconds, bucket-dependent, minimum 1).
#[derive(Debug, Clone, Copy)]
pub struct Limited {
    pub retry_after_secs: u64,
}

impl<C: Clock> RateLimiter<C> {
    pub fn new(clock: C, cfg: RateLimits) -> Self {
        let now = clock.mono();
        Self {
            clock,
            cfg,
            inner: Mutex::new(Map {
                buckets: HashMap::new(),
                last_sweep: now,
            }),
        }
    }

    /// Rate/burst parameters for a class (RFC §K table).
    fn params(&self, class: BucketClass) -> (f64, f64) {
        match class {
            BucketClass::McpAccount => (self.cfg.mcp_rps, f64::from(self.cfg.mcp_burst)),
            BucketClass::McpGlobal => (self.cfg.mcp_global_rps, MCP_GLOBAL_BURST),
            BucketClass::McpPreAuthIp => (MCP_PREAUTH_IP_RPS, MCP_PREAUTH_IP_BURST),
            BucketClass::PollController => (self.cfg.poll_rps, POLL_BURST),
            BucketClass::RespondController => (self.cfg.respond_rps, RESPOND_BURST),
            BucketClass::RegisterIp => (self.cfg.register_per_min / 60.0, REGISTER_BURST),
            BucketClass::RotateController => (self.cfg.rotate_per_min / 60.0, ROTATE_BURST),
            BucketClass::AuthFailIp => (self.cfg.authfail_per_min / 60.0, AUTHFAIL_BURST),
        }
    }

    /// Reclaim idle buckets; called by the cleanup scheduler and
    /// opportunistically (at most once per `SWEEP_INTERVAL` under load).
    /// Returns the number of entries removed.
    pub fn sweep(&self) -> usize {
        let now = self.clock.mono();
        let mut g = self.inner.lock().unwrap();
        g.last_sweep = now;
        let before = g.buckets.len();
        g.buckets
            .retain(|_, b| now.duration_since(b.touched) < BUCKET_IDLE_TTL);
        before - g.buckets.len()
    }

    /// Current key count — observability/tests (bounded state proof).
    pub fn key_count(&self) -> usize {
        self.inner.lock().unwrap().buckets.len()
    }

    fn sweep_if_due(&self, g: &mut MutexGuard<'_, Map>, now: Instant) {
        if now.duration_since(g.last_sweep) >= SWEEP_INTERVAL {
            g.last_sweep = now;
            g.buckets
                .retain(|_, b| now.duration_since(b.touched) < BUCKET_IDLE_TTL);
        }
    }

    /// Consume one token for `(class, key)`. `Ok(())` admits the request;
    /// `Err(Limited)` means reject 429. A full map of active buckets fails
    /// closed — attacker key-churn cannot grow memory unboundedly.
    pub fn check(&self, class: BucketClass, key: &str) -> Result<(), Limited> {
        if !self.cfg.enabled {
            return Ok(());
        }
        let (rate, cap) = self.params(class);
        // F-14: env config validates rates/bursts, but `RateLimits` fields
        // are public — a programmatic NaN/inf/non-positive rate or a
        // sub-token burst must fail closed. (NaN would otherwise leave the
        // bucket permanently full via `f64::min` NaN semantics.)
        if !(rate.is_finite() && rate > 0.0) || !(cap.is_finite() && cap >= 1.0) {
            return Err(Limited {
                retry_after_secs: 60,
            });
        }
        let now = self.clock.mono();
        let mut g = self.inner.lock().unwrap();
        self.sweep_if_due(&mut g, now);
        let k = format!("{}:{key}", class.label());
        let b = match g.buckets.get_mut(&k) {
            Some(b) => b,
            None => {
                if g.buckets.len() >= MAX_BUCKET_KEYS {
                    // Saturated with active buckets — fail closed rather
                    // than evict live state or grow memory.
                    return Err(Limited {
                        retry_after_secs: 1,
                    });
                }
                g.buckets.insert(
                    k.clone(),
                    Bucket {
                        tokens: cap,
                        touched: now,
                    },
                );
                g.buckets.get_mut(&k).unwrap()
            }
        };
        b.refill(now, rate, cap);
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            Ok(())
        } else {
            let wait = (1.0 - b.tokens) / rate;
            Err(Limited {
                retry_after_secs: wait.ceil().max(1.0) as u64,
            })
        }
    }

    /// Convenience for socket-IP-keyed classes.
    pub fn check_ip(&self, class: BucketClass, ip: IpAddr) -> Result<(), Limited> {
        self.check(class, &ip.to_string())
    }
}

/// Bounded concurrency gate (RFC §K "Concurrency" column): an in-flight
/// counter whose guard releases on drop — RAII, panic-safe. `Clone` shares
/// the same counter (GatewayHttp is cloned per-connection).
#[derive(Clone)]
pub struct ConcurrencyGate {
    count: Arc<AtomicUsize>,
    max: usize,
}

pub struct GateGuard<'a> {
    gate: &'a ConcurrencyGate,
}

impl ConcurrencyGate {
    pub fn new(max: usize) -> Self {
        Self {
            count: Arc::new(AtomicUsize::new(0)),
            max,
        }
    }

    /// `Some(guard)` admits the request; `None` means the cap is reached —
    /// reject 429. The guard holds the slot until dropped.
    pub fn acquire(&self) -> Option<GateGuard<'_>> {
        // fetch_add-then-check is a benign race (can transiently overshoot by
        // contenders); fix up by releasing when we observe saturation.
        let prev = self.count.fetch_add(1, Ordering::SeqCst);
        if prev < self.max {
            Some(GateGuard { gate: self })
        } else {
            self.count.fetch_sub(1, Ordering::SeqCst);
            None
        }
    }

    pub fn in_flight(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }
}

impl Drop for GateGuard<'_> {
    fn drop(&mut self) {
        self.gate.count.fetch_sub(1, Ordering::SeqCst);
    }
}
