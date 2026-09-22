# SINTER GATEWAY P7 — F-13 / F-14 / F-17 LIMITED REMEDIATION

Base: `eea0e3e8ee6a7d278767fd5e1487510bef7efa2d` + uncommitted P7.
Scope: the three LOW audit findings only. No redesign, no RFC changes, no
ratified-value changes. No stage/commit/push.

## F-13 — metrics bind invariant moved to the bind site

`start_metrics_server` now refuses a non-loopback `bind` with
`InvalidInput` before `TcpListener::bind`, and `GatewayServer::start`
propagates the error — server startup fails closed. The env path
(`GwConfig::from_vars`) already refused; now programmatic `GwConfig`
construction cannot expose the unauthenticated endpoint either.

Evidence: `programmatic_non_loopback_metrics_bind_refused` (new test) —
`GwConfig{metrics_enabled, metrics_bind: 0.0.0.0:0}` built by field
mutation → `GatewayServer::start` → `Err`. Independent harness check now
PASSes.

## F-14 — `RateLimits` invariant enforced in `check()`

`RateLimiter::check` returns `Err(Limited)` (deny) when the class's
`rate` is non-finite/non-positive or `cap` is non-finite/`<1.0`.
Previously `rate = NaN` kept the bucket permanently full through
`f64::min` NaN semantics → fail-open for that class. Now every such
parameter combination fails closed before any bucket state is touched.

Evidence: `invalid_rate_params_fail_closed` (new test) — NaN, +Inf, 0,
−1, burst=0 → all 10 requests denied each. Independent harness: NaN
`admitted=0/10` (was 10/10).

## F-17 — `sqlite_errors_total{op}` wired at the composition root

`set_metrics` is now a default-no-op method on `IdentityStore` (object
safe). `SqliteStore` implements it via the existing interior-mutable
slot. `GatewayHttp::new` calls `store.set_metrics(metrics.clone())` —
every construction path attaches the handle; no call site can forget.

Evidence: `sqlite_errors_total_counts_store_failures` (new test) —
schema sabotage via second connection → `store.controller()` errors →
`metrics.render()` contains `sqlite_errors_total`. Previously zero call
sites existed.

## Verification

| Gate | Result |
|---|---|
| `cargo fmt --check` | clean |
| `cargo clippy --all-targets --all-features -- -D warnings` | clean |
| Gateway suite | **178 / 0** (175 + 3 remediation tests) |
| Sinter suite | **484 / 0** |
| Independent P7 harness | all remediated checks PASS (remaining FAIL is the documented `>=` purge boundary — INFO, unchanged by design) |
| Diff scope | `http.rs` (+guard, +wiring), `rate_limit.rs` (+guard), `store.rs` (+trait method), `sqlite_store.rs` (method→trait impl), 2 test files |
| Worktree | `opencode.json` / P1–P5 report untouched; nothing staged |

# REMEDIATION: COMPLETE — F-13 / F-14 / F-17 CLOSED
