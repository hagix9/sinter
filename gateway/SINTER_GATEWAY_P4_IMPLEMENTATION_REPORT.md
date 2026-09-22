# Sinter Public Plugin — Production Gateway P4 Implementation Report

P4 scope: production controller-facing HTTP transport — `/v1/register`,
`/v1/rotate`, `/v1/poll`, `/v1/respond`, `/healthz`, `/readyz` — wired into
the P1 core via P2/P3 authentication. No `/mcp` (P5), no revocation HTTP
surface (console-side per RFC §6.5), no `/v1/test/*` (prototype artifact).

Authoritative spec: `~/sinter-public-plugin-research/SINTER_PRODUCTION_GATEWAY_SECURITY_RFC.md`
Prior phases: `SINTER GATEWAY P1/P2/P3: PASS`

---

## A. Starting identity

| Item | State |
|---|---|
| Gateway | `~/sinter-public-plugin-gateway/`, not under git; P3 baseline **87/87** tests green before P4 |
| Sinter HEAD | `66ca3d778918e0d81500b9ba041d268ae90a9104` (unchanged) |
| Sinter status | ` D opencode.json` only — untouched |
| Prototype / RFC | not modified |

## B. Architecture

```
POST /v1/*  ──▶ axum router ──▶ body cap (streamed, to_bytes limit)
                                   │
                              bearer extraction (1 header, Bearer scheme,
                              opaque exact bytes — never logged/reflected)
                                   │
                              ControllerAuth::authenticate → SqliteStore
                                   │
                              AuthenticatedController{account_id,controller_id}
                                   │
                              P1 core (poll_wait / respond)
                                   │
                              JSON response / mapped error
```

New dependencies (each justified): `axum 0.8.9` (HTTP routing — smallest
mainstream stack that gives bounded bodies, graceful shutdown, method
scoping), `tokio 1.53` (async runtime; `spawn_blocking` hosts the
condvar-based long-poll so the runtime never parks on the core mutex).
Nothing else; no tower-http, no middleware crates.

## C. Long-poll design

`GatewayCore::poll_wait(controller, hold)`:

- One `Condvar` (`work_notify`) paired with the **same** `Mutex<Inner>` —
  the single-lock invariant survives; `wait_timeout` releases the lock
  while parked, `submit` calls `notify_all` after enqueue. No busy loop,
  no lock held during the wait.
- RFC §11 one-poll-per-controller: `active_polls` set in `Inner`; a second
  concurrent poll → `poll_conflict` → HTTP 409.
- `GatewayCore::shutdown()` sets a flag + `notify_all` → parked polls return
  `{work:null}` promptly; `GatewayServer::shutdown` invokes it so graceful
  drain isn't held hostage by 60 s waits.
- Hold capped at `MAX_POLL_WAIT_MS` (60 s) — `with_poll_hold` can only
  shorten, never lengthen.
- Handler runs `poll_wait` via `tokio::task::spawn_blocking`; caller
  disconnect drops the response while the bounded wait completes
  independently — no unbounded task/thread growth.

## D. Auth & envelope

- `presented_bearer`: exactly one `Authorization` header; `Bearer` scheme
  (case-insensitive per RFC 7235); token must be non-empty, single-token,
  byte-opaque (no trim/case-fold/prefix). Missing/ambiguous → 401.
- `/v1/register`: `{"token":"reg_…"}` (deny_unknown_fields) →
  `auth.register` → `{controller_id, credential}` — plaintext shown once.
- `/v1/rotate`: bearer → `auth.rotate` → `{credential}` — old dies at commit.
- `/v1/poll`: bearer → authenticate → `auth.bind` (idempotent; the P3
  restart reconnect path) → `poll_wait` → `{work}` or `{work:null}`.
  Body accepted-but-unused; identity is the credential alone.
- `/v1/respond`: bearer + `RespondRequest` (`v`, `request_id`, exactly one
  of `mcp`/`error`; `deny_unknown_fields` kills smuggled identity fields) →
  `core.respond(principal.controller_id(), request_id, outcome)`.
- Error mapping: stable `{error:{code,message}}`; `store_failure` bodies
  are sanitized to `internal error` (sqlite detail never crosses the wire).
  Statuses: 400 malformed, 401 auth failures, 403 ownership, 404 unknown
  request, 409 duplicate/conflict, 410 expired/cancelled/deadline, 413
  oversized, 415 wrong media type, 503 offline/unavailable, 500 other.
- `/healthz`: `{"status":"ok"}` — liveness only.
- `/readyz`: `SELECT 1` on the store → ready/not_ready. No counts, no ids.
- Non-POST methods on `/v1/*` → 405; unknown paths → 404 (framework-native,
  no debug routes).

## E. Bounds

| Surface | Cap | Enforcement |
|---|---|---|
| `/v1/register` body | 4 KiB | `to_bytes(cap)` streams with limit — 413 before full buffer |
| `/v1/poll` body | 4 KiB | same |
| `/v1/respond` body | 4 MiB + 64 KiB envelope slack | same; `mcp` payload additionally re-checked by core (`oversized_response`) |
| poll hold | ≤ 60 s | `POLL_HOLD` ceiling |
| concurrent polls/controller | 1 | `active_polls` slot |
| Header read timeouts | hyper defaults apply | documented limitation — axum does not expose per-header read deadlines at this layer; body reads bounded via cap + `Connection` handling |

## F. Restart boundary

`restart_identity_durable_work_gone`: register → submit → deliver → server
dies mid-flight → new server on the same DB file → bearer authenticates,
`bind` re-establishes the runtime binding, first poll returns `work:null`
(no pre-restart work reappears), responding to the stale request_id →
404 `unknown_request`.

## G. Tests

99 total (was 87): `tests/http.rs` 11 + `tests/http_log.rs` 1.

`http.rs` coverage (real loopback TCP, raw client for adversarial headers):

- **auth_matrix**: valid, missing, wrong-scheme, empty bearer, reg-token-as-
  bearer, random cred, duplicate Authorization, rotated-old (401), revoked
  (401 revoked_controller), rotate round-trip.
- **poll**: immediate delivery, hold-timeout `{work:null}`, wake-on-submit
  (<5 s), cross-controller isolation (B sees nothing of A), concurrent-poll
  → 409, shutdown releases a parked 60 s poll.
- **respond**: happy 200, duplicate retry → 409 `duplicate_response`,
  wrong-controller → 403, unknown → 404, late-after-deadline → 410
  `deadline_exceeded`, cancelled → 410 `cancelled_request`.
- **envelope strictness**: wrong/missing Content-Type → 415, malformed JSON
  → 400, smuggled `controller_id` field → 400 (`deny_unknown_fields`),
  ambiguous `mcp`+`error` → 400.
- **surface/methods**: GET/PUT/DELETE on /v1/* → 405; `/v1/test/call`,
  `/v1/revoke`, `/mcp`, `/admin`, `/v1/status` → 404; healthz/readyz → 200.
- **restart**: §F.

`http_log.rs`: marker registration token, bearer, rotated bearer, and a
well-formed invalid bearer exercised through real HTTP success+failure
paths under a global captured subscriber — none appear in logs; transport
metadata lines are present. (Isolated binary — the tracing callsite-
interest flake documented in P3.)

## H. Quality gates

| Gate | Result |
|---|---|
| `cargo fmt --check` | clean |
| `cargo clippy --all-targets --all-features -- -D warnings` | 0 warnings |
| `cargo test --all-targets --all-features` | 99/99, ×3 consecutive runs, bounded (~11 s; the suite's real-time waits dominate) |
| Sinter regression | 484/484 tests, 20 suites |
| Sinter HEAD/status | `66ca3d7`; ` D opencode.json` untouched |
| Prototype/RFC | untouched |

## I. Security invariant mapping

| Inv | Status | Evidence |
|---|---|---|
| I-1 | enforced | transport carries only bearer + MCP frame; no SSH/target fields anywhere |
| I-2 | enforced | `WorkItem`/`RespondRequest` unchanged; `deny_unknown_fields` + test `respond_envelope_strictness` rejects an injected `controller_id` field |
| I-3 | enforced | `/v1/respond` uses authenticated principal only; B-cred/A-request → 403 |
| I-4 | enforced | identity derives solely from the bearer→verifier lookup; no request field can alter it (tested via smuggled-field rejection + wrong-controller 403) |
| I-5 | enforced | expired/cancelled/responded reject responses over HTTP (410s) |
| I-6 | enforced | duplicate respond → 409 `duplicate_response`; single completion |
| I-7 | enforced | marker-secret log test over real HTTP paths incl. failures; Authorization never logged |
| I-8 | enforced (structural) | production binary has no `/v1/test/*` route — 404 verified |
| I-9 | enforced | all controller traffic is inbound-initiated POST; gateway never dials out |
| I-10 | partially → P5/P6 | `/mcp` not present; tool surface unchanged |
| I-11 | enforced | unchanged (edge layer) |

## J. Files changed

Created: `src/http.rs`, `tests/http.rs`, `tests/http_log.rs`, this report.
Modified: `src/proto.rs` (P4 wire types + `PollConflict`/`MissingAuth`/
`UnsupportedMediaType` codes), `src/core.rs` (`poll_wait`, `poll_locked`
refactor, `active_polls`, `shutdown`, `work_notify`), `src/store.rs`
(`readyz`), `src/sqlite_store.rs` (`readyz`), `src/lib.rs`, `Cargo.toml`
(+axum, +tokio).

Sinter / prototype / RFC: untouched.

## K. Findings

- **LOW**: `deadline_exceeded` initially unmapped → 500; caught by test,
  now 410. Status table is deliberately coarse — codes carry precision.
- **LOW**: header-read timeouts rely on hyper/axum defaults; the long-poll
  hold and body caps bound the meaningful abuse surface. P7 hardening may
  tighten header timeouts at the server layer.
- **LOW**: a parked poll is not interrupted by mid-wait revocation (the next
  poll 401s); the bounded hold caps exposure. Acceptable per RFC — revocation
  kills *future* polls; in-flight delivery of already-queued work to a
  just-revoked controller is a sub-minute edge, noted for P7 if hardening
  wants a wake-on-revoke hook.
- **INFO**: HTTP is plaintext loopback in tests; production TLS terminates
  in front (RFC §13) — no app-level crypto added.
- No BLOCKER / HIGH / MEDIUM.

## L. P5 readiness

P5 may assume:

- `GatewayHttp`/`GatewayServer` is the transport shell; `/mcp` mounts as an
  additional router on the same `GatewayCore` + auth objects.
- `core.submit(account, frame, deadline_ms)` → `(RequestId, Receiver<Outcome>)`
  is the work-creation path; `core.cancel` is the disconnect path; deadlines
  ≤120 s enforced.
- Long-poll machinery (`poll_wait`, one-poll rule, `shutdown`) is proven;
  P5 only adds edge ingress.
- Controller contract is stable: register→credential→poll→respond loop,
  409 on second concurrent poll, `{work:null}` on timeout.

SINTER GATEWAY P4: PASS
