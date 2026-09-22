# SINTER GATEWAY P7 — PRODUCTION HARDENING IMPLEMENTATION REPORT

## A. Starting identity

| Item | Value |
|---|---|
| Frozen HEAD | `eea0e3e8ee6a7d278767fd5e1487510bef7efa2d` |
| Branch | `main` |
| Baseline | Gateway 131/131, Sinter 484/484 |
| Owner-controlled state preserved | `D opencode.json`, `?? gateway/SINTER_GATEWAY_P1_P5_GATE_REEVALUATION_REPORT.md` |
| Forbidden git ops used | none (`reset`/`restore`/`checkout`/`stash`/`clean`/stage all untouched) |

## B. Authoritative RFC identity

`gateway/docs/SINTER_PRODUCTION_GATEWAY_SECURITY_RFC.md` (Git-managed, ratified 2026-09-22). Sections J–O implemented exactly: §K rate table, §L telemetry, §M env contract, §N abuse plan, §O rollback. Ratification report used as provenance only.

## C. Requirement → code map

| RFC req | Implementation | Tests |
|---|---|---|
| §K token buckets | `src/rate_limit.rs` — keyed token buckets, per-class rate/burst, `TestClock`-injectable | `tests/rate_limit.rs` (12) |
| §K concurrency | `ConcurrencyGate` RAII guards (256/32/4/4) + existing 64-inflight/account + poll_conflict | unit + existing http.rs 409 test |
| §K pre-auth IP keys | `ConnectInfo<SocketAddr>` on all handlers; forwarded headers never read | `forwarded_headers_cannot_reset_ip_bucket` |
| §K 429 contract | uniform `{"error":{"code":"rate_limited","message":"rate limit exceeded"}}` + `Retry-After` ceil s | `rate_limit_body_is_uniform_across_routes` |
| §K invalid-auth | `authfail_or` debits per-IP bucket on every 401/403 credential rejection; empty → 429 | `invalid_auth_flood_self_limits` |
| §K bounded state | `MAX_BUCKET_KEYS` 50k fail-closed; `BUCKET_IDLE_TTL` 300s; `sweep()` + in-check GC | `saturated_map_fails_closed`, `sweep_*` |
| §L metrics | `src/metrics.rs` — exact ratified counter/gauge/histogram set, fixed-enum labels | `tests/telemetry.rs` (5) |
| §L metrics endpoint | separate loopback axum listener on `GatewayServer`, off by default | `metrics_endpoint_loopback_only_when_enabled` |
| §M env contract | `src/config.rs` — `GwConfig::from_vars/from_env`, fail-closed parse, loopback-bind check, TRUSTED_PROXY must be empty | `tests/config.rs` (7) |
| §F/J.4b cleanup | `src/cleanup.rs` — `Cleanup::run_once` + `CleanupScheduler` (condvar, mutex-held stop flag, join) | `tests/cleanup.rs` (7) |
| Revoked +90d purge | `purge_revoked_controllers` on `IdentityStore`; Memory + Sqlite impls | `*_revoked_retention`, `revocation_semantics_survive_purge_window` |
| F-03 ownership | `GatewayCore::cancel(account, rid)` — foreign → `wrong_account`, state untouched | `f03_*` (core + HTTP) |
| F-08 verify | panic in `still_authorised` poisons core mutex → fail-stop, no silent delivery | `f08_poll_panic_is_fail_stop_not_silent` |
| I-7 redaction | marker secrets through new paths → 0 hits in logs + audit_events + table names | `tests/p7_log_grep.rs` |
| §O rollback | `SINTER_GW_RATE_ENABLED=false` → `check()` admits all; restart-scoped | `disabled_limiter_admits_everything` |

## D. Files changed

New: `src/rate_limit.rs` (306), `src/metrics.rs` (403), `src/config.rs` (221), `src/cleanup.rs` (169); tests `abuse.rs`, `rate_limit.rs`, `config.rs`, `cleanup.rs`, `telemetry.rs`, `p7_log_grep.rs`.
Modified: `Cargo.toml` (+2 test targets), `src/core.rs` (cancel ownership + gauges), `src/http.rs` (ConnectInfo, limiter wiring, middleware, lifecycle), `src/lib.rs` (modules), `src/mcp.rs` (account-scoped cancel, deadline metric), `src/oauth.rs` (jwks_refresh_total), `src/sqlite_store.rs` (purge + sqlite_errors_total{op}), `src/store.rs` (trait + Memory impl), 3 test files (cancel call sites).

## E. Rate-limit implementation

Token buckets keyed `class:key` in one `Mutex<HashMap>`; refill = `elapsed × rate` capped at burst. Keys: account id (post-auth `/mcp`), controller's bound account (post-auth `/v1/*`), socket peer IP (pre-auth `/mcp`, `/v1/register`, invalid-auth). `check()` returns `Limited{retry_after_secs}` = ceil((1−tokens)/rate) min 1. Saturated map (50k keys) fails closed — new keys rejected rather than evicting live state. Idle buckets (>300s untouched) reclaimed by sweep (scheduler + opportunistic 60s cadence in `check`). `enabled=false` short-circuits everything — the RFC §O rollback lever, restart-scoped.

Ordering per route (RFC §K threat model):
- `POST /mcp`: Origin → gate(256) → global 300/s → pre-auth IP 60/s → **auth** → account 30/s+60 burst → version → bounded body.
- `DELETE /mcp`: same bucket classes (route-level limit).
- `/v1/poll`: bounded body → auth → 2/s → bind → `poll_wait` (existing 1-poll rule + F-07 recheck preserved).
- `/v1/respond`: auth → 20/s → gate(32) → bounded body → `ensure_active` (F-07) → respond.
- `/v1/register`: 5/min IP → gate(4) → bounded body → token exchange; 401/403 → authfail debit.
- `/v1/rotate`: auth → 10/min → gate(4) → rotate.
- `/healthz`, `/readyz`, PRM: unlimited per RFC.

## F. Configuration contract

`GwConfig::from_vars` — every §M knob parsed with declared min/max; malformed, out-of-range, `NaN`/`inf`, non-"true"/"false" bools → `Err` (refuse start). `SINTER_GW_METRICS_BIND` must be loopback (unauthenticated endpoint). `SINTER_GW_TRUSTED_PROXY` non-empty → `Err` — no proxy mode exists in v1, so the operator's stated intent can never be silently ignored. Empty string = absent. `GatewayHttp::with_config` applies limiter/metrics-bind/cleanup-interval; restart required to change — that IS the rollback contract.

## G. Cleanup scheduler

Owned `std::thread` parked on `Condvar::wait_timeout(interval)`; stop flag lives **inside the same mutex** as the condvar → check-then-wait is atomic, missed wakeups impossible (a race in the first draft — notify before first wait parked for the whole interval — was found by the drop-safety test and fixed). `stop()`/Drop signals + joins; no busy loop, no detached task, no sleeps for correctness. Lock order: `purge_spent_tokens` → `purge_revoked_controllers` → `core.sweep_expired` → `limiter.sweep` — sequential, never nested with HTTP-path locks.

## H. F-03 disposition: CLOSED

Pre-P7: `core.cancel(request_id)` — no ownership parameter; a bare rid terminated work. P7: `cancel(account, rid)` — foreign account → `wrong_account`, no state touched; tombstone replay still returns the terminal error (no existence flip). Callers updated: `CancelOnDrop` (caller disconnect), `notifications/cancelled` (session-tracked rids only — unchanged contract, now double-enforced), `DELETE /mcp` session teardown. Tests: core-level foreign cancel rejected + owner cancel still terminal + late respond still `cancelled_request`; HTTP-level: acc_b's cancel notification naming acc_a's in-flight public id is a 202 no-op and the request completes.

Note: `wrong_account` (vs `unknown_request`) matches the existing `respond` convention (`wrong_controller`) — same existence-oracle profile as before, not a new channel.

## I. F-06 verification: not worsened

Session live-request tracking (`live` set keyed by caller JSON-RPC id) is unchanged; duplicate-id overwrite semantics identical. Cancel now requires account ownership — strictly stricter. F-06 remains ACCEPTED RESIDUAL RISK / LOW.

## J. F-08 verification: verified, behavior documented

`poll_wait` releases the active-poll slot on every non-panic return path (Err/work/timeout/shutdown — audited). A panic inside the locked region (e.g. `still_authorised` → sqlite) unwinds past `release` → mutex poisoned → **all** subsequent core ops panic: fail-stop, never silent delivery through a dead auth path. Proven by `f08_poll_panic_is_fail_stop_not_silent`. RAII redesign remains FUTURE per ratification.

## K. Telemetry implementation

`Metrics` = cloneable `Arc<Inner>` of bounded maps: `http_requests_total{route,method,status_class}` (route = axum `MatchedPath` normalized to the fixed ROUTES set), `http_request_duration_seconds` fixed 12-bucket histogram per route, `rate_limited_total{bucket_class}`, `auth_failures_total{reason_class}`, `jwks_refresh_total{result}`, `sqlite_errors_total{op}`, gauges `mcp_active_requests` (RAII), `controller_active_polls`/`work_queued`/`controller_online` (sampled from core at render), `deadline_exceeded_total`. Exactly the RFC §L set — no more, no less. `render()` = text exposition for the optional loopback `/metrics`.

Structured logs stay on `tracing` (categorical fields only). Durable `audit_events` unchanged — security lifecycle only; P7 adds zero new audit rows (cleanup purges are operational, not audit-worthy per RFC).

## L. I-7 / log-redaction proof

`tests/p7_log_grep.rs`: marker JWT bearer, marker controller credential, marker registration token, marker tool argument, marker SSH key material, and the public-auth token exercised through `/mcp` (auth fail + forward attempt), `/v1/poll` flood (429 path), `/v1/register` failure — then captured tracing output AND every `audit_events` row AND table names grepped: **0 occurrences**. No `bucket`/`rate`/`metric` tables exist in SQLite.

## M. Forwarded-header hardening

All handlers extract peer identity via `ConnectInfo<SocketAddr>` (`into_make_service_with_connect_info`). No handler reads `Forwarded`, `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Host`, `X-Forwarded-Proto` anywhere — `check_rate_ip` keys on the socket tuple only. Proven: `forwarded_headers_cannot_reset_ip_bucket` sends 12 register attempts cycling through spoofed headers — the 11th still 429s at exactly the burst boundary (a header-keyed bucket would have reset). PRM immunity already proven in P6 and unchanged.

## N. Resource-bound inventory

| Route | Body cap | Rate | Concurrency | State created | Cleanup |
|---|---|---|---|---|---|
| POST/DELETE /mcp | 1MiB+4k | 30/s+60 acct · 300/s+600 global · 60/s+120 IP | 256 global + 64 inflight/acct | session (8h TTL, ≤64/acct, ≤10k) + request (deadline ≤120s) | sweep_expired + tombstone TTL + session TTL |
| /v1/register | 4KiB | 5/min+10 IP | 4 | token→controller row (SQLite) | spent-token 24h + revoked +90d purge |
| /v1/rotate | header only | 10/min+20 ctl | 4 | verifier swap | revoked purge |
| /v1/poll | 4KiB | 2/s+5 ctl | 1 (existing) | active_polls slot | RAII-free release all paths |
| /v1/respond | 4MiB+64k | 20/s+40 ctl | 32 | none durable | — |
| invalid auth | — | 30/min+60 IP | — | bucket | idle sweep |
| healthz/readyz/PRM | — | none (RFC) | — | none | — |
| /metrics | — | — | loopback bind | render only | — |

No public input creates permanent unbounded growth: buckets capped at 50k + idle-reclaimed; sessions/request maps already capped/TTL'd; SQLite grows only via ratified lifecycle rows with purges.

## O. Abuse tests (RFC §N)

All 20 items covered: burst/sustained/cross-account/poll/register/rotate/invalid-auth/oversized/concurrency-gate/slow+offline controller (existing)/deadline race (existing)/revocation race (revocation_recheck ×3)/shutdown wake (existing `shutdown_releases_waiting_poll`)/bucket cleanup/config boundaries/log grep/telemetry cardinality/forwarded immunity/F-03 both layers. Deterministic: unit tests on `TestClock` (zero sleeps); HTTP tests use near-zero configured rates so burst boundaries trip without timing dependence.

## P. Adversarial matrix

| ID | Attack | Surface | Expected | Observed | ✓ |
|---|---|---|---|---|---|
| 1 | /mcp burst | account bucket | 429 after burst | burst 4 → 5th 429+Retry-After | PASS |
| 2 | /mcp sustained | steady refill | admit at rate | TestClock refill admits | PASS |
| 3 | Cross-account flood | A exhausts, B fine | isolation | B 200 while A 429 | PASS |
| 4 | Poll abuse | 6th poll | 429 | 429+Retry-After | PASS |
| 5 | Register farming | 11th bad token | 429 pre-auth | 429 at burst+1 | PASS |
| 6 | Rotate abuse | 21st rotate | 429 (creds chained) | 429 | PASS |
| 7 | Invalid-auth flood | 61st bad auth | 429 not 401 | 429 at index 60 | PASS |
| 8 | Oversized body | 5MiB /mcp | 413 not 429 | 413 | PASS |
| 9 | Concurrency cap | gate at max | 429 | unit: acquire→None→recover | PASS |
| 10 | Slow controller | deadline | deadline_exceeded | existing + metric | PASS |
| 11 | Offline controller | submit | controller_offline | existing | PASS |
| 12 | Deadline race | respond after expire | loud terminal | existing | PASS |
| 13 | Revocation race | revoke mid-poll | revoked_controller | 4/4 ×3 runs | PASS |
| 14 | Shutdown under load | parked poll | wakes, drains | existing test | PASS |
| 15 | Bucket key churn | 50k+ distinct keys | fail closed, bounded | 50k cap → Err | PASS |
| 16 | Idle bucket reclaim | sweep | freed | 2 reclaimed, fresh kept | PASS |
| 17 | Malformed config | NaN/inf/range | refuse start | all Err | PASS |
| 18 | XFF poisoning | vary headers | same bucket | 429 at same boundary | PASS |
| 19 | Foreign cancel (core) | acc_b cancels acc_a rid | wrong_account, untouched | PASS |
| 20 | Foreign cancel (HTTP) | B cancel notif for A's id | 202 no-op, A completes | PASS |
| 21 | Secret logging | 6 marker classes | 0 hits | 0 in logs+audit+tables | PASS |
| 22 | Telemetry cardinality | 10k bogus routes/methods | bounded | ≤ bounded cells | PASS |
| 23 | Non-loopback metrics | 0.0.0.0/10.x/:: binds | refuse | all Err | PASS |
| 24 | Trusted proxy set | any value | refuse start | Err | PASS |
| 25 | Rollback | RATE_ENABLED=false | admit all | 1000 admits | PASS |
| 26 | Scheduler orphan | drop w/o stop | thread exits | joins | PASS |
| 27 | Scheduler stop | stop() | prompt join | no hang | PASS |
| 28 | Panic in auth re-check | still_authorised panic | fail-stop | mutex poison → ops panic | PASS |
| 29 | Uniform 429 oracle | cross-route body | byte-identical | identical | PASS |
| 30 | Revoked purge timing | ±90d boundary | purge only ≥+90d | exact boundary | PASS |
| 31 | SQLite persistence | schema+audit rows | no ephemeral/secret state | clean | PASS |
| 32 | Credential domains | ctrl cred → /mcp; OAuth → /v1 | rejected | P6 tests all pass | PASS |

## Q. Security questions

- Unauthenticated → controller work? **NO** — auth before body/enqueue; buckets sit before auth but allocate only bounded bucket entries.
- Account A consume B's bucket? **NO** — per-key buckets, tested.
- Unbounded limiter state? **NO** — 50k cap fail-closed + idle sweep.
- Register IP buckets grow forever? **NO** — same cap/sweep.
- Forwarded headers alter rate identity? **NO** — never read; socket IP only.
- Forwarded headers alter public identity/PRM? **NO** — principal comes from token validation; PRM static.
- Revoked controller gets new work? **NO** — F-07 recheck preserved (poll deliver + respond accept), re-proven.
- Revoked controller completes post-revocation work? **NO** — ensure_active before respond.
- Two polls bypass concurrency rule? **NO** — poll_conflict (409) intact + rate bucket.
- Telemetry labels attacker-growable? **NO** — all labels fixed enums; 10k-junk test.
- Telemetry/logs contain manifests/results/credentials? **NO** — I-7 grep clean; metrics have no payload path.
- Audit events contain payloads? **NO** — schema unchanged, grep clean.
- SQLite holds buckets/counters? **NO** — table scan clean; limiter/metrics memory-only.
- Malformed config silently disables protection? **NO** — every invalid value is a startup Err.
- Rollback via config+restart? **YES** — `SINTER_GW_RATE_ENABLED=false` + restart.
- Malformed `iat` authenticates? **NO** — F-11 CLOSED, tests still pass.
- Production TestPublicAuth? **NO** — F-01 CLOSED: default rlib 0 marker occurrences.
- Cross-domain credentials? **NO** — both directions rejected (P6 suites green).
- Arbitrary MCP methods / tunnel? **NO** — edge allowlist unchanged; -32601 for unknown.
- Cleanup blocks shutdown? **NO** — condvar+flag, joined promptly.
- Lock-order deadlock? **NO** — sequential, no nested acquisition.
- Rate limiting creates durable work? **NO** — memory-only.
- P8 activity? **NO.**

## R. OAuth/controller regressions

`oauth_http` (13), `oauth_log`, `secrets`, `revocation_recheck` (4), `mcp_http` (12), `mcp_log`, `http_log`, `http` — all green across 3 stability runs. F-01 artifact: default rlib `strings | grep -c x-sinter-test-principal` = **0**; `--features test-auth` = 1 (by design).

## S. Persistence audit

`audit_events` columns unchanged (id/ts/kind/account_id/controller_id); marker scan clean; no new tables; rate-limit/telemetry state never touches the store; revoked purge deletes only `status='revoked' AND revoked_unix_ms <= now-90d` rows — active rows provably untouched (boundary test).

## T. Dependencies

**Zero new dependencies.** Token bucket, metrics, scheduler built on std (`Mutex`, `Condvar`, `HashMap`, atomics) + existing axum `ConnectInfo`. `cargo audit`: **not installed** on this machine — recorded accurately; dependency set unchanged anyway (`Cargo.toml` gained only `[[test]]` target declarations).

## U. Gateway test evidence

`cargo test --all-targets --all-features`: **175 passed / 0 failed** (131 baseline + 44 new). Security-sensitive binaries (`abuse`, `revocation_recheck`, `oauth_http`, `concurrency`) repeated ×3 — all green. `cargo fmt --check` clean; `cargo clippy --all-targets --all-features -- -D warnings` clean.

## V. Sinter regression

484 passed / 0 failed; HEAD `eea0e3e` unchanged; Sinter source untouched.

## W. Finding ledger

| F | Status |
|---|---|
| F-01 | CLOSED (re-proven artifact-level) |
| F-03 | **CLOSED** — ownership-scoped cancel, both layers tested |
| F-06 | ACCEPTED RESIDUAL RISK / LOW — unchanged, not worsened |
| F-07 | CLOSED — re-proven through P7 paths ×3 |
| F-08 | VERIFIED — fail-stop on panic documented; RAII = future |
| F-09 | INFO — unchanged |
| F-10 | INFO — unchanged |
| F-11 | CLOSED — malformed-iat rejection untouched |
| F-12 | INFO — unchanged (JWKS mutex across bounded fetch) |

No new findings. No CRITICAL/HIGH/MEDIUM introduced.

## X. Final diff

Tracked: `Cargo.toml` (+test targets), `core.rs` (cancel ownership +3 gauges), `http.rs` (+P7 wiring), `lib.rs` (+4 modules), `mcp.rs` (account-scoped cancel + deadline metric), `oauth.rs` (+jwks metric), `sqlite_store.rs` (purge + serr instrumentation), `store.rs` (trait + Memory impl), `tests/{concurrency,http,lifecycle}.rs` (cancel call sites). Untracked: 4 new src modules + 6 new test files. `git diff --check` clean.

## Y. Final worktree

```
 M gateway/Cargo.toml, src/{core,http,lib,mcp,oauth,sqlite_store,store}.rs, tests/{concurrency,http,lifecycle}.rs
 D opencode.json                                   (owner-controlled — untouched)
?? gateway/SINTER_GATEWAY_P1_P5_GATE_REEVALUATION_REPORT.md  (untouched)
?? gateway/src/{cleanup,config,metrics,rate_limit}.rs
?? gateway/tests/{abuse,cleanup,config,p7_log_grep,rate_limit,telemetry}.rs
```

No staging, no commits, no push.

## Z. Remaining P8 work

P8 ChatGPT E2E acceptance was **NOT performed**. P8 zero-mutation re-proof was **NOT performed**. Those remain: real ChatGPT → public Gateway → sinter-bridge → official `sinter mcp` → managed target, plus the zero-mutation re-proof.

---

# SINTER GATEWAY P7: PASS
