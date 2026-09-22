//! P7 — telemetry (RFC §L).
//!
//! Three separated channels — this module implements only the in-process
//! **metrics** channel: bounded counters, gauges, and one fixed-bucket
//! histogram. Structured logs stay on `tracing`; durable security audit
//! stays in `audit_events`. They are never merged.
//!
//! Cardinality is structurally bounded: every label value comes from a
//! fixed enum or a small static string set — never account ids, controller
//! ids, request ids, subjects, emails, targets, or payload data
//! (RFC §L prohibited-label list). Attackers cannot mint label values.
//!
//! Export (RFC §L): `render()` produces text exposition for the OPTIONAL
//! `GET /metrics` admin endpoint — separate bind, default off, loopback
//! only. Counters collect regardless (bounded + cheap).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;

/// Fixed route label set — matched paths plus "other". Never free-form.
const ROUTES: &[&str] = &[
    "/mcp",
    "/v1/register",
    "/v1/rotate",
    "/v1/poll",
    "/v1/respond",
    "/healthz",
    "/readyz",
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-protected-resource/mcp",
    "other",
];

/// Fixed label for `auth_failures_total{reason_class}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuthFailReason {
    Missing,
    Malformed,
    Invalid,
    Unbound,
    /// Controller-domain failures (any TransportError auth rejection).
    Controller,
}

impl AuthFailReason {
    fn label(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Malformed => "malformed",
            Self::Invalid => "invalid",
            Self::Unbound => "unbound",
            Self::Controller => "controller",
        }
    }
}

/// Fixed label for `jwks_refresh_total{result}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwksResult {
    Ok,
    Error,
}

/// Fixed label set for `sqlite_errors_total{op}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SqlOp {
    TokenPut,
    TokenTake,
    ControllerInsert,
    Rotate,
    Status,
    Purge,
    Readyz,
    Read,
}

impl SqlOp {
    pub fn label(self) -> &'static str {
        match self {
            Self::TokenPut => "token_put",
            Self::TokenTake => "token_take",
            Self::ControllerInsert => "controller_insert",
            Self::Rotate => "rotate",
            Self::Status => "status",
            Self::Purge => "purge",
            Self::Readyz => "readyz",
            Self::Read => "read",
        }
    }
}

/// Histogram buckets (seconds) for `http_request_duration_seconds`.
const DURATION_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 30.0,
];

struct Inner {
    /// (route, method, status_class) → count. Bounded: 10×4×4 = 160 cells.
    http_requests: Mutex<BTreeMap<(&'static str, &'static str, &'static str), u64>>,
    /// route → cumulative bucket counts + total. Bounded by ROUTES.
    http_duration: Mutex<BTreeMap<&'static str, ([u64; DURATION_BUCKETS.len() + 1], u64)>>,
    /// bucket_class label → count. Bounded by BucketClass variants.
    rate_limited: Mutex<BTreeMap<&'static str, u64>>,
    /// reason_class → count.
    auth_failures: Mutex<BTreeMap<&'static str, u64>>,
    /// op → count.
    sqlite_errors: Mutex<BTreeMap<&'static str, u64>>,
    /// result → count ("ok"/"error").
    jwks_refresh: Mutex<BTreeMap<&'static str, u64>>,
    mcp_active_requests: AtomicI64,
    controller_active_polls: AtomicI64,
    work_queued: AtomicI64,
    controller_online: AtomicI64,
    deadline_exceeded: AtomicI64,
}

fn norm_route(matched: Option<&str>) -> &'static str {
    // Return the canonical &'static route constant — never the caller's str.
    matched
        .and_then(|p| ROUTES.iter().copied().find(|r| *r == p))
        .unwrap_or("other")
}

fn norm_method(m: &str) -> &'static str {
    match m {
        "GET" => "GET",
        "POST" => "POST",
        "DELETE" => "DELETE",
        _ => "other",
    }
}

fn norm_status(code: u16) -> &'static str {
    match code / 100 {
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        _ => "5xx",
    }
}

/// Cloneable handle — all clones share the same counters.
#[derive(Clone, Default)]
pub struct Metrics {
    inner: std::sync::Arc<Inner>,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            http_requests: Mutex::new(BTreeMap::new()),
            http_duration: Mutex::new(BTreeMap::new()),
            rate_limited: Mutex::new(BTreeMap::new()),
            auth_failures: Mutex::new(BTreeMap::new()),
            sqlite_errors: Mutex::new(BTreeMap::new()),
            jwks_refresh: Mutex::new(BTreeMap::new()),
            mcp_active_requests: AtomicI64::new(0),
            controller_active_polls: AtomicI64::new(0),
            work_queued: AtomicI64::new(0),
            controller_online: AtomicI64::new(0),
            deadline_exceeded: AtomicI64::new(0),
        }
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// HTTP middleware observation. `route` must already be a matched-path
    /// template (axum `MatchedPath`) — it is normalized against ROUTES.
    pub fn observe_http(&self, route: Option<&str>, method: &str, status: u16, secs: f64) {
        let route = norm_route(route);
        let method = norm_method(method);
        let class = norm_status(status);
        *self
            .inner
            .http_requests
            .lock()
            .unwrap()
            .entry((route, method, class))
            .or_insert(0) += 1;
        let mut d = self.inner.http_duration.lock().unwrap();
        let (buckets, total) = d
            .entry(route)
            .or_insert(([0; DURATION_BUCKETS.len() + 1], 0));
        *total += 1;
        for (i, le) in DURATION_BUCKETS.iter().enumerate() {
            if secs <= *le {
                buckets[i] += 1;
                return;
            }
        }
        buckets[DURATION_BUCKETS.len()] += 1; // +Inf
    }

    /// `rate_limited_total{bucket_class}` — label must be a BucketClass.
    pub fn rate_limited(&self, class: crate::rate_limit::BucketClass) {
        *self
            .inner
            .rate_limited
            .lock()
            .unwrap()
            .entry(class.label())
            .or_insert(0) += 1;
    }

    /// Concurrency-cap rejection — counted with the rate-limit class label
    /// `concurrency` (same 429 contract).
    pub fn concurrency_limited(&self) {
        *self
            .inner
            .rate_limited
            .lock()
            .unwrap()
            .entry("concurrency")
            .or_insert(0) += 1;
    }

    /// `auth_failures_total{reason_class}`.
    pub fn auth_failure(&self, reason: AuthFailReason) {
        *self
            .inner
            .auth_failures
            .lock()
            .unwrap()
            .entry(reason.label())
            .or_insert(0) += 1;
    }

    /// `jwks_refresh_total{result}` — called by the JWKS fetch path.
    pub fn jwks_refresh(&self, ok: bool) {
        let label = if ok { "ok" } else { "error" };
        *self
            .inner
            .jwks_refresh
            .lock()
            .unwrap()
            .entry(label)
            .or_insert(0) += 1;
    }

    /// `sqlite_errors_total{op}` — called by SqliteStore error paths.
    pub fn sqlite_error(&self, op: SqlOp) {
        *self
            .inner
            .sqlite_errors
            .lock()
            .unwrap()
            .entry(op.label())
            .or_insert(0) += 1;
    }

    /// `deadline_exceeded_total` — mcp timeout, late respond, scheduler sweep.
    pub fn deadline_exceeded(&self, n: u64) {
        self.inner
            .deadline_exceeded
            .fetch_add(n as i64, Ordering::SeqCst);
    }

    /// `mcp_active_requests` gauge — RAII so a panic cannot leak it.
    pub fn mcp_active(&self) -> GaugeGuard<'_> {
        GaugeGuard::new(&self.inner.mcp_active_requests)
    }

    /// Set absolute gauge values (sampled at render — no label state).
    pub fn set_controller_active_polls(&self, n: usize) {
        self.inner
            .controller_active_polls
            .store(n as i64, Ordering::SeqCst);
    }
    pub fn set_work_queued(&self, n: usize) {
        self.inner.work_queued.store(n as i64, Ordering::SeqCst);
    }
    pub fn set_controller_online(&self, n: usize) {
        self.inner
            .controller_online
            .store(n as i64, Ordering::SeqCst);
    }

    /// Test/observability accessors (read cumulative counters).
    pub fn rate_limited_count(&self, class: crate::rate_limit::BucketClass) -> u64 {
        *self
            .inner
            .rate_limited
            .lock()
            .unwrap()
            .get(class.label())
            .unwrap_or(&0)
    }
    pub fn auth_failure_count(&self, reason: AuthFailReason) -> u64 {
        *self
            .inner
            .auth_failures
            .lock()
            .unwrap()
            .get(reason.label())
            .unwrap_or(&0)
    }

    /// Total distinct label combinations — the cardinality bound proof.
    pub fn cardinality(&self) -> usize {
        let i = &self.inner;
        i.http_requests.lock().unwrap().len()
            + i.http_duration.lock().unwrap().len() * (DURATION_BUCKETS.len() + 1)
            + i.rate_limited.lock().unwrap().len()
            + i.auth_failures.lock().unwrap().len()
            + i.sqlite_errors.lock().unwrap().len()
            + i.jwks_refresh.lock().unwrap().len()
    }

    /// Prometheus text exposition — for the optional loopback `/metrics`.
    /// Only fixed labels; no identities or payload data can appear.
    pub fn render(&self) -> String {
        let i = &self.inner;
        let mut out = String::new();
        let mut w = |s: &str| {
            let _ = writeln!(out, "{s}");
        };
        w("# TYPE http_requests_total counter");
        for ((route, method, class), n) in i.http_requests.lock().unwrap().iter() {
            w(&format!(
                "http_requests_total{{route=\"{route}\",method=\"{method}\",status_class=\"{class}\"}} {n}"
            ));
        }
        w("# TYPE http_request_duration_seconds histogram");
        for (route, (buckets, total)) in i.http_duration.lock().unwrap().iter() {
            for (idx, le) in DURATION_BUCKETS.iter().enumerate() {
                w(&format!(
                    "http_request_duration_seconds_bucket{{route=\"{route}\",le=\"{le}\"}} {}",
                    buckets[idx]
                ));
            }
            w(&format!(
                "http_request_duration_seconds_bucket{{route=\"{route}\",le=\"+Inf\"}} {}",
                buckets[DURATION_BUCKETS.len()]
            ));
            w(&format!(
                "http_request_duration_seconds_count{{route=\"{route}\"}} {total}"
            ));
        }
        w("# TYPE rate_limited_total counter");
        for (class, n) in i.rate_limited.lock().unwrap().iter() {
            w(&format!(
                "rate_limited_total{{bucket_class=\"{class}\"}} {n}"
            ));
        }
        w("# TYPE auth_failures_total counter");
        for (r, n) in i.auth_failures.lock().unwrap().iter() {
            w(&format!("auth_failures_total{{reason_class=\"{r}\"}} {n}"));
        }
        w("# TYPE jwks_refresh_total counter");
        for (r, n) in i.jwks_refresh.lock().unwrap().iter() {
            w(&format!("jwks_refresh_total{{result=\"{r}\"}} {n}"));
        }
        w("# TYPE sqlite_errors_total counter");
        for (op, n) in i.sqlite_errors.lock().unwrap().iter() {
            w(&format!("sqlite_errors_total{{op=\"{op}\"}} {n}"));
        }
        w(&format!(
            "mcp_active_requests {}",
            i.mcp_active_requests.load(Ordering::SeqCst)
        ));
        w(&format!(
            "controller_active_polls {}",
            i.controller_active_polls.load(Ordering::SeqCst)
        ));
        w(&format!(
            "work_queued {}",
            i.work_queued.load(Ordering::SeqCst)
        ));
        w(&format!(
            "controller_online {}",
            i.controller_online.load(Ordering::SeqCst)
        ));
        w(&format!(
            "deadline_exceeded_total {}",
            i.deadline_exceeded.load(Ordering::SeqCst)
        ));
        out
    }
}

/// RAII gauge increment — the panic-safe pattern F-8 prefers for new code.
pub struct GaugeGuard<'a> {
    g: &'a AtomicI64,
}

impl GaugeGuard<'_> {
    fn new(g: &AtomicI64) -> GaugeGuard<'_> {
        g.fetch_add(1, Ordering::SeqCst);
        GaugeGuard { g }
    }
}

impl Drop for GaugeGuard<'_> {
    fn drop(&mut self) {
        self.g.fetch_sub(1, Ordering::SeqCst);
    }
}
