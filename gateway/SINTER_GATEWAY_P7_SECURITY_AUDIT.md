# SINTER GATEWAY P7 — INDEPENDENT SECURITY AUDIT

## A. Audit verdict

**SINTER GATEWAY P7 SECURITY AUDIT: PASS**

No CRITICAL/HIGH/blocking-MEDIUM findings. Two LOW hardening gaps in the
internal (non-env) configuration path, one dead-instrumentation gap for a
ratified metric, two INFO notes. Details in §AB.

## B. Starting identity

| Item | Observed |
|---|---|
| HEAD | `eea0e3e8ee6a7d278767fd5e1487510bef7efa2d` ✓ |
| Branch | `main` ✓ |
| Owner state | `D opencode.json`, `?? gateway/SINTER_GATEWAY_P1_P5_GATE_REEVALUATION_REPORT.md` — both untouched throughout |
| P7 diff | uncommitted, exactly as reported |

## C. Methodology

Source-first: RFC re-read → full diff → runtime reconstruction → independent
harness (`/tmp/sinter-p7-audit`, 576 lines, real TCP) → implementation report
compared last. The pre-existing P6 harness (`/tmp/sinter-p6-audit`, real
RS256/JWKS) was re-run with the ratified rollback lever (`RateLimits.enabled
= false`) to isolate OAuth semantics from the new limiter.

## D. Source-first architecture reconstruction

| Component | Responsibility | State | Sync | Inputs | Cleanup |
|---|---|---|---|---|---|
| `rate_limit.rs` | token buckets + concurrency gates | `Mutex<HashMap<String,Bucket>>` ≤50k keys, `touched: Instant` LRU | single mutex serializes check/sweep | class enum + key string + `Clock` | `sweep()` + in-check `sweep_if_due` (60s) + scheduler |
| `metrics.rs` | RFC §L counters/gauges/histogram | `Arc<Inner>` fixed-label maps | Mutex per family + atomics for gauges | fixed enums only; MatchedPath routes | none needed (bounded) |
| `config.rs` | §M env contract | `GwConfig` value | none | env strings via injected getter | n/a — startup only |
| `cleanup.rs` | spent tokens, revoked+90d, expired reqs, idle buckets | none (borrows) | `Mutex<bool>`+Condvar for park/stop | `Clock`, stores, limiter | owned `JoinHandle`, `stop()`/Drop join |
| `http.rs` wiring | ConnectInfo peer IP, check order, 429 contract, scheduler/metrics lifecycle | `GatewayHttp` fields all Arc-shared | per-handler guards | socket addr, headers, body | server `shutdown()` joins all |
| `core.rs` | F-03 cancel ownership, gauge counts | `Mutex<Inner>` | single lock | `AccountId`, `RequestId` | tombstone TTL + sweep_expired |
| `mcp.rs` | cancel threading, deadline metric | `CancelOnDrop` RAII | — | caller principal | drop cancels own-account work |

## E. RFC conformance

| Requirement | Verdict | Notes |
|---|---|---|
| §K rate table (all 8 classes) | SATISFIED | exact rates/bursts verified in code + at runtime |
| §K dimensions (account/controller/socket-IP) | SATISFIED | controller classes keyed by bound account — 1:1 in v1, survives rotation |
| §K global ceiling 300/s+600 | SATISFIED | single `"gateway"` key — proven shared (598 admits, 62×429 over two accounts) |
| §K concurrency 256/32/4/4 + poll=1 | SATISFIED | gates are `Arc<AtomicUsize>` RAII; poll keeps existing conflict rule |
| §K 429 + Retry-After + uniform body | SATISFIED | byte-identical body, no identity/payload echo |
| §K bounded state 50k + ≤5min idle | SATISFIED | fail-closed at cap; sweep at scheduler + 60s in-check cadence |
| §K health/PRM unlimited | SATISFIED | not routed through limiter |
| §M env contract + fail-closed | SATISFIED | malformed/NaN/inf/out-of-range/non-loopback/trusted-proxy all `Err` |
| §O config-revert rollback | SATISFIED | `enabled=false` short-circuits all bucket checks; gates unaffected |
| §L metric set | **PARTIAL** | all names render; `sqlite_errors_total{op}` never wired into the store (F-17) |
| §L cardinality bound | SATISFIED | labels are enums/`MatchedPath`-normalized; junk-input bounded |
| §L metrics endpoint optional+loopback | SATISFIED* | env path enforced; *programmatic `GwConfig` bypasses (F-13) |
| Cleanup scheduler | SATISFIED | flag+condvar same mutex — missed-wakeup impossible by construction |
| Retention: tokens 24h / revoked 90d | SATISFIED | `>=` boundary, both stores identical semantics |
| F-03 ownership | SATISFIED | `cancel(account, rid)` enforced core-side; foreign → `wrong_account` |
| F-06 not worsened | SATISFIED | session tracking unchanged; cancel strictly stricter |
| F-08 verify-only | SATISFIED | panic → mutex poison → fail-stop proven |
| Forwarded-header ignore | SATISFIED | `ConnectInfo<SocketAddr>` only; no header read anywhere |
| Abuse tests | SATISFIED | deterministic, real TCP, precise status assertions |
| P7/P8 boundary | SATISFIED | no E2E/zero-mutation work present |

## F. Attack-surface inventory (derived from code)

| Route | Auth | Rate key | Rate | Concurrency | Body | Timeout | State |
|---|---|---|---|---|---|---|---|
| POST /mcp | OAuth | acct+global+preauth-IP | 30+60 / 300+600 / 60+120 | 256 | 1MiB+4k | ≤120s | session/request (TTL'd) |
| DELETE /mcp | OAuth | acct+global+preauth-IP | same | — | none | — | session teardown |
| /v1/register | token | socket IP | 5/min+10 | 4 | 4KiB | — | token→controller row |
| /v1/rotate | ctrl cred | controller(acct) | 10/min+20 | 4 | headers | — | verifier swap |
| /v1/poll | ctrl cred | controller(acct) | 2/s+5 | 1 (existing) | 4KiB | hold≤300s | poll slot (released all paths) |
| /v1/respond | ctrl cred | controller(acct) | 20/s+40 | 32 | 4MiB+64k | — | none durable |
| invalid auth | — | socket IP | 30/min+60 | — | — | — | bucket (idle-swept) |
| /healthz /readyz PRM | — | none (RFC) | — | — | — | — | none |
| GET /metrics | — | none | — | — | — | — | render only; optional loopback listener |
| GET/other /mcp | — | none (RFC scope) | — | — | — | — | static 405 |

No route creates permanent unbounded state.

## G. Rate-limiter analysis

Token bucket math audited line-by-line:

- `refill`: `min(tokens + elapsed·rate, cap)` — fractional tokens accumulate correctly; `saturating_duration_since` makes clock rollback yield 0 refill (fail-safe).
- Consume iff `tokens >= 1.0` — boundary-exact; first request creates a full bucket then consumes (burst admits exactly `cap`).
- `Retry-After` = `ceil((1−tokens)/rate)` min 1 — correct seconds until next admit.
- 50k cap checked **before** insert under the map mutex — concurrency cannot exceed the cap (serialized).
- Saturated map rejects new keys, keeps serving existing keys (verified).
- Sweeps are O(50k) inside the mutex at ≤60s cadence — bounded.
- **Edge found**: `rate=0` → permanent 429 with `Retry-After=u64::MAX` (fail-closed, odd header value, unreachable via env config).
- **Edge found**: `rate=NaN` → `f64::min(NaN,cap)=cap` keeps bucket permanently full → **admits everything** (fail-OPEN for that class). Only reachable by constructing `RateLimits` programmatically — env config rejects non-finite. → F-14.
- `check` for a miss inside a saturated map: returns `Err` — verified.
- Ordering verified: `check_origin` → gate → global → preauth-IP → **auth** → account → version → body (`/mcp`); body(4KiB) → auth → rate → bind → poll_wait (`/v1/poll`); auth → rate → gate → body (`/v1/respond`); rate-IP → gate → body (`/v1/register`); auth → rate → gate (`/v1/rotate`). Authentication precedes all expensive/allocation work on every route.

## H. 50k-cap analysis

Verified at library level: fill to exactly 50,000 → next new key `Err` (fail closed, no panic, no eviction of live buckets); existing keys still served; `sweep()` after idle TTL removes all 50,000 and admits the previously-rejected key; second churn cannot exceed cap.

**Starvation analysis**: an attacker can fill the map only with *real* socket IPs (TCP handshake — no spoofing; forwarded headers ignored). Filling 50k IP-class buckets requires ~50k distinct source addresses — feasible for a botnet/IPv6-rich attacker. Effect: new legitimate *identities* get 429 until idle entries expire (≤300s + ≤60s sweep lag). Identity-keyed classes (account/controller) are reachable only post-auth — an attacker without credentials can only fill IP-class buckets, but the map is shared across classes, so saturation still starves new account/controller keys. This is a bounded, self-healing availability residual inherent to the ratified design — LOW residual risk, consistent with the RFC's "~50k" bound. Not a memory-safety or isolation failure.

## I. Cleanup/concurrency analysis

- Stop flag lives inside the same `Mutex<bool>` as the condvar; worker checks flag while holding the lock, then `wait_timeout` releases+waits atomically → **missed wakeup impossible by construction** (the P7 fix to the original race is correct).
- `stop()`/Drop: set-under-lock → notify → join. No busy loop, no detached task, bounded join (a pass's work is bounded).
- Lock order: purge_tokens → purge_revoked → sweep_expired → limiter.sweep — sequential acquisitions, never nested with request-path locks → no lock-order cycle possible.
- Cleanup vs live ops: purge touches only `status='revoked' AND age≥90d` rows and `consumed` tokens >24h — cannot remove live identity state; active controllers never eligible (verified at `u64::MAX/2` cutoff).
- Purge boundary: `>=` retention — a record at *exactly* 90d is purged. "Purgeable after 90 days" — 1ms boundary quibble, privacy-favorable direction, identical in both stores. INFO.

## J. F-03 independent verdict: CLOSED

Core matrix verified at library level: foreign rid → `wrong_account` + state untouched (owner cancel afterwards still finalizes); owner → terminal; tombstone replay → terminal error; unknown → `unknown_request`; concurrent cancel-vs-respond serializes with exactly one winner (cancel Ok / respond `cancelled_request`). HTTP layer: foreign `notifications/cancelled` is a 202 no-op and the target completes (repo `abuse.rs`). The ratified condition is met.

## K. F-06 status: unchanged

Session `live`-map semantics untouched; cancel is strictly stricter. ACCEPTED RESIDUAL RISK / LOW stands.

## L. F-08 independent verdict: verified fail-stop

`poll_wait`'s `still_authorised` callback runs inside the core lock on `spawn_blocking`. A panic there unwinds past `release` → core mutex poisoned → **every** subsequent core op panics (proven: `poll` panics after the injected panic). Consequence: the gateway fails STOP, never delivers work through a dead auth path. Availability impact is a crash-loop, not a security hole — correct per ratified VERIFY-ONLY scope. RAII redesign remains FUTURE.

## M. Configuration audit

`from_vars` probed independently: `" 10"`→Err, `"+5"`→Ok(harmless), `"0x10"`→Err, `"1_000"`→Err, `"1e2"`→Ok(f64 field, in range), `"NaN"`/`"inf"`/`"-inf"`→Err, overflow→Err, trailing space→Err, `""`→absent, bools `"TRUE"/"True"/"1"/"yes"`→Err, u64 fields reject `"60.0"`/`"6e1"`, accept `"060"`/`"+60"` — all correct. Non-loopback binds refused; `TRUSTED_PROXY` non-empty refused; empty-string = absent.

**Cross-field**: no unsafe combination found — bounds are independent; burst/rate relationship is operator policy, not a security invariant (RFC doesn't define one).

**F-13 (LOW)**: `GwConfig` fields are `pub`; `with_config`/`start_metrics_server` trust the struct. `GwConfig{metrics_enabled:true, metrics_bind:0.0.0.0:0, ..}` (constructed programmatically, bypassing `from_vars`) **binds `/metrics` on a public interface** — verified live (`metrics_addr=0.0.0.0:50319`). The ratified env path is safe; the invariant "loopback-only" lives in the parser instead of the bind site. Recommend re-validating in `with_config` or `start_metrics_server`. Non-blocking: requires the operator to bypass the documented config contract; content is bounded categorical counters (no PII/secrets).

## N. Rollback audit

`SINTER_GW_RATE_ENABLED=false` → `check()` returns `Ok` for every class — disables **only** token buckets. Concurrency gates (`ConcurrencyGate::acquire` — proven independent), body caps, authentication, session caps, deadlines, cleanup, telemetry all remain active. The lever matches the ratified scope exactly — not a master off-switch.

## O. Telemetry/cardinality audit

Labels are exclusively fixed enums or `MatchedPath` values normalized to the 10-element `ROUTES` set (`"other"` otherwise); methods normalize to GET/POST/DELETE/other; status to 4 classes. Probed with junk routes/methods/marker strings — `http_requests_total{` series stayed ≤200, markers absent. Maximum distinct series: ~160 counter cells + ≤10 histograms × 12 buckets + 8 rate + 5 authfail + 8 sqlop + 2 jwks — hard-bounded. Counters are `u64` under mutex — wraparound unreachable at any feasible rate; no security consequence.

## P. Metrics exposure audit

- Default: `metrics_addr=None`, no listener; main router 404s `/metrics` (verified live).
- Enabled: binds loopback, serves only `GET /metrics` (POST → 405), no auth — justified by loopback binding.
- Rendered output contains no account/controller/subject/email/request-id/target/payload/JWT — probed with markers through live traffic then grepped the body: 0 hits.
- **BUT** the loopback invariant is enforced only in `from_vars` — programmatic construction bypasses it (F-13).

## Q. I-7 independent secret audit: PASS

9 fresh marker classes (OAuth bearer, JWT-claim string, controller cred, registration token, manifest field, tool argument, tool result, SSH-key-looking, password-looking) driven through: bad-bearer `/mcp`, bad-cred `/v1/poll` flood, bad-token `/v1/register`, authed `tools/call` with marker args, `respond` with marker-laden outcome, oversized body. Captured full tracing output + SQLite **raw file bytes** + `audit_events` rows + `sqlite_master` table names + rendered metrics: **0 occurrences**. No `rate`/`metric`/`bucket` tables exist.

## R. Forwarded-header audit

80 requests each carrying cycling `X-Forwarded-For`/`Forwarded`/`X-Real-IP` from a single socket: authfail bucket debited at exactly 60 — spoofing changed nothing. No code reads any forwarded variant (grepped: only the `ConnectInfo` comment mentions them). PRM/resource identity is a static document. OAuth identity derives from token claims only. Controller routing is account-bound. **Ineffective.**

## S. Authentication/credential-domain audit

- TestPublicAuth token → `/v1/poll`: 401. Controller cred → `/mcp`: 401. Registration token → both: 401. Cross-domain all rejected (limiter helpers don't blur domains — they key on already-established identity).
- Invalid-auth flood self-limits: ~60×401 then 429 (verified over real TCP).
- Valid credentials from a flooded IP still authenticate (authfail debits only on failure) — but the shared pre-auth IP bucket does 429 everyone behind one NAT'd IP during sustained floods — accepted per-IP semantics.
- Auth-before-body holds on `/mcp` and `/v1/respond`; `/v1/poll` reads a bounded 4KiB body pre-auth (cheap, pre-existing order).

## T. OAuth regressions

P6 harness re-run against the P7 tree (limiter disabled via the ratified lever): **127/127 PASS** — RS256/ES256, alg=none/HS256/tampered/wrong-iss/lookalike-iss/wrong-aud/expired/nbf-future/malformed-iat/future-iat/unbound/jku/x5u/kid-required/duplicate-kid/oversized-JWKS/JWKS-redirect, F-07 OAuth-path revocation, PRM shape, credential domains, arbitrary-method `-32601`, stale-session 404. **Unchanged.**

JWKS under abuse: unknown-kid flood bounded by existing throttle (3 fetches / 16 reqs) — invalid-auth limiting adds nothing adverse; F-12 stays INFO.

## U. Resource/body/concurrency bounds

Body caps enforced at `to_bytes(limit)` (pre-parse): register 4KiB, poll 4KiB, respond 4MiB+64k, /mcp 1MiB+4k. Gate RAII verified: 300 immediate client disconnects mid-`tools/call` → subsequent request served 200 (no permit leak — guard Drop runs on function exit regardless of connection state). `fetch_add`-then-check overshoots transiently under contention and self-corrects — verified no double-release (Drop is the only decrement on the success path; reject path decrements once).

## V. Shutdown behavior

Under load (parked poll + in-flight `/mcp` + populated buckets + metrics listener): `shutdown()` stops cleanup first (no GC against torn-down state), then metrics listener, then signals accept-stop + `core.shutdown()` (wakes parked polls), then joins. Observed: parked poll returned, join completed in ~113µs — bounded, no detached survivors. No new work after the shutdown boundary; nothing durable.

## W. Persistence boundary

`audit_events` schema unchanged (kind/account_id/controller_id); no new tables; raw-db-byte scan clean of all markers; no rate/metric/bucket/request/telemetry tables; buckets/counters are memory-only. P7 adds **zero** durable request state. Boundary preserved.

## X. Independent harness results

`/tmp/sinter-p7-audit`: 30 checks — 28 pass, 3 "failures" are two findings (F-13, F-14) plus one boundary-semantics note (purge uses `>=`, INFO). Dual-stack probe: v4 client on `[::]` listener appears as `::ffff:127.0.0.1` — distinct `IpAddr` from `::1` (F-15).

## Y. Existing test-quality review

| File | Quality |
|---|---|
| `rate_limit.rs` | STRONG — TestClock, exact boundaries, cap saturation, sweep semantics |
| `config.rs` | STRONG — full boundary/malformed matrix, loopback, proxy |
| `cleanup.rs` | STRONG — both store impls, retention boundary, scheduler drop/stop |
| `telemetry.rs` | STRONG — render contract, cardinality, real listener |
| `abuse.rs` | STRONG — real TCP, exact 429/401/403 assertions, F-03 both layers, F-08 fail-stop |
| `p7_log_grep.rs` | STRONG — captured subscriber + sqlite schema+row scan |
| Overall | Zero `sleep()` in new tests; no `!=200` assertions; no shared-state contamination. No INVALID tests. |

## Z. Adversarial matrix

| # | Attack/failure | Surface | Method | Expected | Observed | Result | Evidence |
|---|---|---|---|---|---|---|---|
| 1 | Burst exhaust | /mcp acct | burst 3 → 4th req | 429 | 429+RA≥2 | PASS | harness |
| 2 | Retry-After | 429 resp | header check | ≥1, uniform | "2", uniform body | PASS | harness |
| 3 | Body uniformity | /mcp vs /v1 | byte compare | identical | identical | PASS | repo test |
| 4 | Connection churn | acct bucket | fresh TCP each | persists | persists | PASS | harness |
| 5 | Session churn | acct bucket | new session | shared | 429 on new sid | PASS | harness |
| 6 | Cross-account | isolation | A exhaust, B ping | B ok | 429/200 | PASS | harness+repo |
| 7 | Global ceiling | 2 accounts paced | 660 @ ~50/s | ~600 cap | 598 ok, 62×429 | PASS | harness |
| 8 | Global ≠ per-acct | — | source | shared key | `"mcp_global:gateway"` | PASS | code |
| 9 | XFF spoof | authfail bucket | 80 reqs cycling IP hdrs | same bucket | 60×401→429 | PASS | harness |
| 10 | Forwarded/X-Real-IP | same | same | ignored | ignored | PASS | harness+grep |
| 11 | X-Forwarded-Host/Proto | PRM | spoofed | static doc | unchanged | PASS | code+P6 |
| 12 | v4-mapped v6 | peer key | dual-stack accept | — | `::ffff:` distinct | INFO | F-15 |
| 13 | 50k fill | map cap | lib-level fill | fail closed | Err, no panic | PASS | harness |
| 14 | Cap: existing key | saturation | check old key | served | Ok | PASS | harness |
| 15 | Cap: recovery | sweep | idle→sweep→retry | recovered | 50k freed, Ok | PASS | harness |
| 16 | Cap: rechurn | fill again | 2nd 50k | still 50k | key_count=50k | PASS | harness |
| 17 | Starvation window | new identity | while full | ≤60s+sweep | bounded | residual | §H |
| 18 | Register burst | /v1/register | 11 bad tokens | 429@boundary | 9×401,2×429 | PASS | harness |
| 19 | Poll burst | /v1/poll | 7 polls | 429@6th | 5×200,2×429 | PASS | harness |
| 20 | Respond burst | /v1/respond | 45 rapid | 429s~40 | 5×429 of 45 | PASS | harness |
| 21 | Authfail flood | any cred route | 80 bad auth | self-limit | 60×401→429 | PASS | harness |
| 22 | Valid cred flooded IP | /mcp | after flood | not 401 | 200 | PASS | harness |
| 23 | Revoked-cred flood | authfail | resolve→401 | debits bucket | debits (401 path) | PASS | code |
| 24 | rate=0 edge | bucket | lib construct | fail closed | 429, RA=u64::MAX | PASS-note | §G |
| 25 | rate=NaN edge | bucket | lib construct | fail closed | **admits all** | **F-14** | harness |
| 26 | Config malformed | all vars | 17 value classes | Err | all Err | PASS | harness |
| 27 | Metrics bind bypass | `GwConfig` pub fields | programmatic 0.0.0.0 | refuse | **binds public** | **F-13** | harness |
| 28 | Metrics default | listener | probe main router | 404/none | 404, none | PASS | harness |
| 29 | Metrics content | render | markers through traffic | 0 hits | 0 | PASS | harness |
| 30 | Metrics POST | listener | POST /metrics | 405 | 405 | PASS | harness |
| 31 | Log secrets | 9 markers | all routes+errors | 0 hits | 0 | PASS | harness |
| 32 | DB secrets | raw bytes | fs::read db file | 0 hits | 0 | PASS | harness |
| 33 | DB schema | sqlite_master | table names | no ephemeral | clean | PASS | harness |
| 34 | F-03 foreign core | cancel | a2 cancels a1 rid | wrong_account | wrong_account | PASS | harness |
| 35 | F-03 tombstone | cancel | foreign on dead rid | terminal err | cancelled_request | PASS | harness |
| 36 | F-03 race | cancel‖respond | threads | one winner | cancel won | PASS | harness |
| 37 | F-03 HTTP | notif/cancelled | B names A's rid | 202 no-op | completes | PASS | repo abuse |
| 38 | Credential domains | cross | 5 cross-posts | 401 all | 401 all | PASS | harness |
| 39 | Disconnect churn | gate | 300 drops | recover | next req 200 | PASS | harness |
| 40 | Purge boundary | revoked+90d | ±1ms | eligible≥cutoff | at-cutoff purged | INFO | `>=` semantics |
| 41 | Purge active | controllers | huge cutoff | never | survives | PASS | harness |
| 42 | Purge parity | mem/sqlite | same boundary | identical | identical | PASS | code+repo |
| 43 | Shutdown under load | server | parked poll+traffic | bounded join | 113µs, poll woke | PASS | harness |
| 44 | Scheduler missed wake | cleanup | drop test | prompt exit | exits | PASS | repo test+code |
| 45 | F-07 revocation | poll/respond | revoke mid-op | revoked_controller | all 4 paths | PASS | repo ×3 +P6 |
| 46 | OAuth regressions | full P6 rig | 127 checks | all pass | 127/127 | PASS | harness |
| 47 | F-01 artifact | release rlib | strings scan | 0 markers | 0 (1 w/ feature) | PASS | artifact |
| 48 | F-11 malformed iat | JWT | P6 rig | 401 | 401 | PASS | harness |
| 49 | Arbitrary method | /mcp | unknown method | -32601 edge | -32601, not queued | PASS | P6 harness |
| 50 | Tunnel attempt | /mcp | non-MCP verbs/paths | 405/404 | rejected | PASS | code+P6 |
| 51 | MCP id preserve | forward | int/str ids | verbatim | verbatim | PASS | repo mcp_http |
| 52 | Session isolation | cross-acct | foreign sid/cancel | rejected | rejected | PASS | repo+F-03 |
| 53 | Oversized body | /mcp 2MiB | >cap | 413 | 413 | PASS | repo+harness |
| 54 | Dead metric wiring | sqlite_errors | code audit | increments | **never called** | **F-17** | grep |
| 55 | Panic auth re-check | poll_wait | inject panic | fail-stop | mutex poison | PASS | repo abuse |

## AA. Security-question matrix

| Question | Answer | Evidence |
|---|---|---|
| Account limits reset by reconnect? | **NO** — keyed post-auth | harness: fresh TCP, bucket persists |
| Controller limits reset by reconnect? | **NO** | same |
| Forwarded headers alter rate identity? | **NO** | 80-req spoof test identical boundary |
| Equivalent IP forms bypass? | **Marginal** — v4-mapped≠v6 on dual-stack; IPv6 rotation inherent | F-15 |
| Many accounts bypass global? | **NO** — 598/660 shared | harness |
| >50k keys under concurrency? | **NO** — mutex-serialized cap check | code+harness |
| Cap exhaustion → unbounded alloc? | **NO** | fail closed |
| Cap exhaustion permanent? | **NO** — sweep recovers | harness |
| Cleanup removes live security state? | **NO** — active/recent ineligible | harness |
| Cleanup deadlocks? | **NO** — sequential, unnested | code |
| Cleanup survives owner? | **NO** — Drop joins | code+test |
| Cleanup prevents shutdown? | **NO** — condvar+flag same mutex | 113µs join |
| Revoked → forbidden work? | **NO** | F-07 ×3 + P6 |
| Revoked → forbidden response? | **NO** | ensure_active |
| Cross-account cancel? | **NO** | F-03 CLOSED |
| Malformed config → silent disable? | **NO** env path; **YES** programmatic (NaN) | F-14 |
| Rollback disables unrelated controls? | **NO** — gates/auth/caps persist | code+probe |
| Attacker metric cardinality? | **NO** | bounded series probe |
| /metrics public bind? | **NO** env; **YES** programmatic | F-13 |
| /metrics exposes identifiers? | **NO** | marker grep |
| Logs expose markers? | **NO** | 9 classes, 0 hits |
| Error logs expose markers? | **NO** | error paths included |
| audit_events payloads? | **NO** | schema+row scan |
| SQLite rate-limit state? | **NO** | no such tables |
| SQLite metrics? | **NO** | same |
| Invalid auth → controller work? | **NO** | auth before alloc |
| Invalid auth → unbounded JWKS? | **NO** — existing throttle (3/16) | P6 harness |
| Concurrency permit leak? | **NO** | 300-disconnect recovery |
| Immortal work from dead controller? | **NO** — deadline+tombstone+drop | code+repo |
| P7 merges trust domains? | **NO** | cross-domain all 401 |
| Malformed iat auth? | **NO** | P6 127/127 |
| Prod TestPublicAuth? | **NO** — 0 markers in default rlib | artifact |
| Arbitrary MCP → controller? | **NO** — -32601 edge | P6 |
| Generic tunnel? | **NO** | method allowlist |
| MCP IDs rewritten? | **NO** | repo mcp_http |
| Durable active work? | **NO** | persistence audit |
| Telemetry → payloads? | **NO** | fixed labels |
| F-08 fail-open? | **NO** — fail-stop (poison) | repo+harness |
| New dependencies? | **NO** — lockfiles untouched | git |
| P8 activity? | **NO** | none present |

## AB. Finding ledger

| ID | Severity | Component | Summary | Blocking? |
|---|---|---|---|---|
| F-01 | CLOSED | oauth | re-proven: default rlib 0 markers | — |
| F-03 | CLOSED | core | independently verified CLOSED | — |
| F-06 | ACCEPTED RESIDUAL/LOW | mcp | unchanged | — |
| F-07 | CLOSED | auth | re-proven ×3 + OAuth path | — |
| F-08 | VERIFIED | core | fail-stop proven; RAII future | — |
| F-09..F-12 | INFO/CLOSED | — | unchanged | — |
| **F-13** | **LOW** | http/config | Programmatic `GwConfig` (pub fields) bypasses loopback check → `/metrics` can bind publicly. Env path safe; content non-sensitive. Fix: re-validate in `with_config`/`start_metrics_server`. | NO |
| **F-14** | **LOW** | rate_limit | `RateLimits` pub fields accept NaN → `f64::min(NaN,cap)=cap` → class admits everything. Env path rejects non-finite. Fail-open exists only off the documented config path. | NO |
| **F-15** | **INFO** | rate_limit | v4-mapped-v6 vs native-v4/v6 peers = distinct keys on dual-stack; IPv6 /64 rotation is inherent to ratified per-IP keying. Document for deployers. | NO |
| **F-16** | **INFO** | core | `wrong_account` on foreign rid is an existence oracle — consistent with `wrong_controller` convention; 128-bit rid entropy makes probing infeasible. | NO |
| **F-17** | **LOW** | sqlite_store | `SqliteStore::set_metrics` has no call site → `sqlite_errors_total{op}` never increments on store error paths (only cleanup's own purge errors count). RFC §L metric present but dead for store ops. Observability only. | NO |

Blocking assessment: F-13/F-14 require the deployer to bypass the ratified
env configuration path — the contract itself is enforced; these are
defense-in-depth gaps in the internal API surface, not remotely reachable
failures. F-17 is observability completeness. None affect authentication,
isolation, secrets, tunneling, persistence, revocation, or resource bounds.

## AC. Gateway gates

`cargo fmt --check` clean; `cargo clippy --all-targets --all-features -- -D warnings` clean; `cargo test --all-targets --all-features` = **175 passed / 0 failed** (verified independently). Security-sensitive binaries (abuse/revocation_recheck/concurrency/oauth_http) ×3 — stable, zero flakes. `cargo audit`: NOT AVAILABLE (not installed; dependency set unchanged anyway — both lockfiles unmodified).

## AD. Sinter regression

**484 passed / 0 failed** (`cargo test --workspace --exclude sinter-gateway`). Sinter source unchanged.

## AE. Final repository integrity

`git status --short` identical to pre-flight; `git diff --check` clean; audit artifacts confined to `/tmp` + `~/sinter-public-plugin-gateway`; `opencode.json` and the P1–P5 report untouched; nothing staged.

## AF. Recommendation

P7 is **safe to publish**. Recommend a follow-up patch (non-blocking) to:
1. Re-validate metrics bind loopback at `with_config`/`start_metrics_server` (F-13).
2. Clamp/reject non-finite rates in `RateLimiter::new` or make `RateLimits` fields non-pub (F-14).
3. Wire `SqliteStore::set_metrics` at construction (F-17).
4. Document dual-stack per-IP keying for deployers (F-15).

---

# SINTER GATEWAY P7 SECURITY AUDIT: PASS
