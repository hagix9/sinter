# Sinter Gateway P1–P5 Integrated Audit Report

**Audit type:** hostile integrated security / architecture review (audit-only)  
**Date:** 2026-09-22  
**Auditor:** independent reviewer (implementation reports treated as untrusted claims)

---

## A. Starting identity

| Item | Value |
|---|---|
| Sinter HEAD | `66ca3d778918e0d81500b9ba041d268ae90a9104` |
| Sinter git status | ` D opencode.json` (user-owned, untouched) |
| Gateway dir | `~/sinter-public-plugin-gateway` |
| Gateway baseline tests | P1–P5 all PASS (per reports); independently re-run below |
| RFC | `~/sinter-public-plugin-research/SINTER_PRODUCTION_GATEWAY_SECURITY_RFC.md` |
| Prototype | `~/sinter-public-plugin-prototype/SINTER_PUBLIC_PLUGIN_TRANSPORT_PROTOTYPE_REPORT.md` |
| Audit tooling | Rust probe binaries in `/tmp/gateway-audit` (outside production; not committed) |

---

## B. Reconstructed architecture (source-backed)

```
Public MCP caller
      │  HTTP POST/DELETE/GET /mcp
      ▼
http.rs::mcp_post / mcp_delete / mcp_get
      │  check_origin · check_protocol_version · json_body (≤1 MiB)
      ▼
mcp.rs::PublicAuth::authenticate(headers) → PublicPrincipal{account_id, subject_id}
      │  (P5: TestPublicAuth; P6: OAuth — trait boundary)
      ▼
mcp.rs::SessionManager (MCP-Session-Id → Session{account, subject, EdgeSession, live})
      │  with_session: account+subject+TTL match required
      ▼
edge.rs::handle_frame → EdgeAction{Answer|Forward|AcceptOnly|Cancel}
      │  EDGE owns initialize/ping/notifications/* / openai/profile / -32601 / -32600
      │  FORWARD only tools/list + tools/call (opaque JSON-RPC frame)
      ▼
mcp.rs::forward → core.rs::GatewayCore::submit(account, mcp, deadline)
      │  Mutex<Inner> single lock: controllers, by_account, requests, tombstones, active_polls
      │  request ownership: {account, controller, state, deadline, mcp, tx}
      ▼
http.rs::POST /v1/poll  (Bearer ctrlk_ → SHA-256 verifier → AuthenticatedController)
      │  auth.bind (restart re-bind) → core.poll_wait (ONE poll/controller, ≤60 s, Condvar)
      ▼
WorkItem{v, request_id, deadline_unix_ms, mcp}   ← no exec/argv/env/path fields (deny_unknown_fields)
      ▼
controller / sinter-bridge  →  sinter mcp (stdio, opaque)
      ▼
http.rs::POST /v1/respond (Bearer + RespondRequest{v, request_id, mcp|error})
      │  core.respond(controller_id, request_id, outcome) — ownership-checked
      ▼
original /mcp caller  (JSON-RPC response or -32000)
```

**Identity lifecycle (durable SQLite):**

```
POST /v1/register {token: reg_…}
  → ControllerAuth::register
  → SqliteStore::take_registration_token (ATOMIC single-use)
  → insert_controller (partial UNIQUE index: one active/account)
  → core.register_controller / replace_account_controller
  → returns (AuthenticatedController, ctrlk_…)   ← plaintext once only

POST /v1/rotate  Bearer ctrlk_…
  → SqliteStore::rotate_credential (ATOMIC expected-verifier swap)
  → old verifier dies exactly as new is issued

console revoke_controller / POST-with-cred revoke
  → SqliteStore::set_status(Revoked)  ← terminal, never Active again
```

**Trust boundaries:**
1. Public HTTP ↔ PublicAuth (P6 OAuth; P5 test header — see F-01)
2. PublicPrincipal ↔ SessionManager (session is routing context, never auth)
3. Edge ↔ GatewayCore (opaque MCP envelope; no Sinter semantics)
4. GatewayCore ↔ controller (bearer-verified AuthenticatedController + ownership)
5. WorkItem ↔ sinter-bridge (no execution-control channel)
6. Gateway ↔ SQLite (verifiers only; no payloads/secrets)

---

## C. Attack surface (verified routes)

| Method | Path | Status |
|---|---|---|
| POST | `/mcp` | 200/202/4xx (auth required) |
| DELETE | `/mcp` | 200/403/404 |
| GET | `/mcp` | 405 |
| POST | `/v1/register` | 200/401/409/410 |
| POST | `/v1/rotate` | 200/401/410 |
| POST | `/v1/poll` | 200/401/409/503 |
| POST | `/v1/respond` | 200/401/403/404/409/410/413 |
| GET | `/healthz` | 200 |
| GET | `/readyz` | 200/503 |
| POST | `/v1/test/call` | **404** (prototype discarded) |
| GET | `/v1/register` | 405 |
| OPTIONS | `/mcp` | 405 |

No debug endpoints, no static/file serving, no permissive method fallback beyond 405.

---

## D. Trust boundaries

Listed in §B. Each is enforced in source (see §E–§L).

---

## E. Authentication review

**Public side:**
- `PublicAuth` trait; `authenticate(headers) -> Option<PublicPrincipal>`
- Default `GatewayHttp::public_auth = None` → `/mcp` **503 fail-closed** (no anonymous path)
- `TestPublicAuth` maps `X-Sinter-Test-Principal` → pre-registered principal
- **F-01:** TestPublicAuth is production-compiled (no `#[cfg(test)]`), `pub` constructor, selectable via `pub with_public_auth()`. A production `main()` can enable header-only auth. See findings.

**Controller side:**
- `Authorization: Bearer ctrlk_…` — exactly one header (duplicates → 401)
- `ControllerCredential::parse` strict shape (`ctrlk_` + 64 hex)
- SHA-256 verifier exact-map lookup; `Debug` redacted; no `Display`/`Serialize`
- Revoked → 401 `revoked_controller`; unknown → 401 `invalid_credential`
- Type confusion (reg_/ctrlk_/sess_/malformed) → all rejected (probe evidence)

---

## F. Authorization / isolation review

**Two-account adversarial evidence (fresh probes):**

| Attack | Result |
|---|---|
| A respond to B's request | rejected `wrong_controller` |
| B use A's `MCP-Session-Id` | rejected `wrong_account` (HTTP + SessionManager) |
| B `notifications/cancelled` for A's work | `cancel_live` → None (silent no-op) |
| A DELETE B's session | rejected `wrong_account` |
| spoofed `account_id` in tool arguments | forwarded as opaque payload (sinter's concern; not a Gateway authority field) |
| JSON-RPC id `7` vs `"7"` | distinct keys (`serde_json::to_string`) |

**Identity chain proven:** account ← PublicAuth; controller ← bearer verifier; session ← (account, subject) binding; work ownership ← core `Request{account, controller}`. No caller-controlled field replaces any authorization decision.

**F-03:** `core.cancel()` has **no ownership check** — any library caller with a `RequestId` can cancel foreign work. Public HTTP paths are guarded by SessionManager (ownership-checked `cancel_live`/`delete`). Missing defense-in-depth (MEDIUM).

---

## G. Session review

| Property | Evidence |
|---|---|
| Generation | `sess_` + 128-bit `getrandom` hex |
| Account/subject binding | `with_session` requires both match |
| TTL | 8 h absolute (not sliding) |
| Caps | 64/account, 10,000 global — checked inside `sessions.lock()` (race-safe) |
| Lazy expiry sweep | on `create()` |
| Deletion | `delete()` removes + returns live rids to cancel |
| Restart | memory-only; sessions die (existing test `restart_sessions_gone_identity_survives`) |
| Session fixation | ids server-generated on initialize; client-supplied sid is only a lookup key |
| Session ID ≠ auth | every request re-authenticates principal (probe: cross-account session rejected) |
| Expiry cancels work | **No** — expired sessions are retained-swept but live work is not auto-cancelled on TTL expiry (see F-08) |

**F-06 (LOW):** duplicate JSON-RPC ids in one session overwrite `Session.live` — earlier request becomes un-cancelable via public id (lifecycle hole, not cross-account).

---

## H. Request-ID / cancellation review

| Space | Form | Authority |
|---|---|---|
| Public JSON-RPC id | caller-chosen `Value` | key into `Session.live` only |
| Internal request id | `req_` + UUIDv4 | ownership enforced by `core.respond` |

- `public_key` = `serde_json::to_string(id)` — `7` ≠ `"7"` (verified)
- Cancellation: `notifications/cancelled` → `cancel_live` (session+principal checked) → `core.cancel`
- DELETE → `delete` (session+principal checked) → cancel all live
- CancelOnDrop on `/mcp` caller disconnect → `core.cancel` for owned rid
- Late `/v1/respond` after cancel → tombstone `cancelled_request` (existing tests)
- **F-03:** `core.cancel` itself is unauthenticated at the library level
- **F-06:** live-map overwrite on duplicate public ids

---

## I. Controller transport review

| Behavior | Evidence |
|---|---|
| Poll auth | Bearer → verifier → principal → `bind` (idempotent restart re-bind) |
| One poll/controller | `active_polls` set; second poll → `poll_conflict` (409) |
| Respond ownership | `req.controller != controller` → `wrong_controller` (verified) |
| Revoked mid-poll | **F-07 (MEDIUM):** already-authenticated poll continues to receive post-revocation work; `respond` does not re-check revocation (fresh probe confirmed both) |
| Rotation lost-response | old credential dead at commit; new plaintext lost with response → operational recovery = re-register after revoke, or admin re-issue (accepted operational property, documented) |
| Retry register | single-use token → 409 (verified) |
| Retry rotate | stale credential → 401 (verified) |
| Outbound-only | gateway never dials controllers (source: no listener/dialer to controllers) |

---

## J. Persistence review

**Schema (verified):** `meta`, `registration_tokens` (verifier/account/timestamps), `controllers` (id/account/cred_verifier/status/timestamps + partial UNIQUE one-active-per-account), `audit_events` (ts/kind/account_id/controller_id).

**Durable:** identity + credential verifier + status + token verifier lifecycle + audit metadata.  
**Memory-only:** MCP requests, work queues, inflight, deadlines, sessions, tool args/results (source boundary held).

**Secret inspection (source + existing tests):** only SHA-256 verifier hex is bound as SQL params. Plaintext `reg_`/`ctrlk_` never enters sqlite_store. `plaintext_secrets_absent_from_database_file_and_rows` and `sqlite_error_paths_never_echo_secret_material` pass.

**WAL:** enabled (`journal_mode=WAL`, `synchronous=FULL`, `busy_timeout=5000`). Verifier hashes persist in main db + WAL until checkpoint. `checkpoint()` available. Deleted-row remnants possible until vacuum/checkpoint — hashed verifiers are sensitive-but-not-reversible (documented, not a defect).

---

## K. MCP edge review

| Case | Behavior (verified) |
|---|---|
| Batch array | −32600 "batches not supported" |
| Non-object | −32600 |
| Wrong jsonrpc | −32600 |
| Notification | 202; `notifications/*` never forwarded (I-11) |
| `notifications/cancelled` | edge → Cancel(public id) → session-scoped cancel |
| initialize | edge-owned constant response; creates session |
| double initialize | −32600 "session already initialized" |
| methods before initialize | −32600 "session not initialized" |
| unknown method | −32601 |
| `tools/list` | Forwarded (verbatim) + `openai/profile` injected on way back |
| `tools/call` name==profile | edge-owned; returns `{id: account_id}` only |
| `tools/call` other | Forwarded verbatim (sinter is tool authority) |
| profile name collision in backend | inject skipped (fail-closed, no duplicate) |
| protocol version | `2025-03-26`/`2025-06-18`/`2025-11-25` accepted; else 400; missing → assumed 2025-03-26 |

Capabilities advertised: `tools.listChanged=false` only — no inflation.

---

## L. Payload / execution boundary

- `WorkItem`/`RespondRequest`: `deny_unknown_fields`; fields = `v, request_id, deadline_unix_ms, mcp` / `v, request_id, mcp|error` only (I-2)
- No `Command`, `process`, `shell`, `exec`, `argv`, `env` selection anywhere in Gateway source (grep verified; only doc comments)
- Edge inspects only `jsonrpc/id/method/params.name` — never `params.arguments`, manifests, resources, tool results (grep verified)
- No SSH/hostname/known_hosts/identity-file fields in Gateway schema or SQLite (grep verified)

**Boundary:** Gateway understands MCP envelope/routing; Sinter understands Sinter tools. Confirmed.

---

## M. HTTP hardening

| Check | Result (probe) |
|---|---|
| Origin allowlist exact | allowed → 200; wrong/null/prefix-lookalike/userinfo → 403 |
| Missing Origin | allowed (non-browser clients) — by design |
| Duplicate Origin | 400 |
| Content-Type | `application/json` required; charset ok; text/plain/missing → 415 |
| Duplicate Authorization | 401 |
| Body cap /mcp | 1 MiB + slack → 413 (bounded `to_bytes`) |
| Body caps /v1/register /v1/poll | 4 KiB |
| Body cap /v1/respond | 4 MiB + 64 KiB |
| Framing ambiguity | axum/hyper rejects before app (residual: proxy-layer assumption documented) |
| Compression | not supported; not decoded elsewhere |

---

## N. Concurrency / deadlock / TOCTOU

**Lock inventory:**
| Lock | Location | Held across |
|---|---|---|
| `Mutex<Inner>` + `Condvar` | `GatewayCore` | all core state; Condvar wait releases |
| `Mutex<HashMap>` | `SessionManager` | session map only |
| `Mutex<Connection>` | `SqliteStore` | single sqlite conn |
| `Mutex<Inner>` | `MemoryStore` | test store |
| `Mutex<Duration>` | `TestClock` | test clock |

**Lock-order graph:** no path takes two different mutexes simultaneously. SessionManager lock is released before `core.*` is called (verified in `handle_post`/`CancelOnDrop`/`mcp_delete`). SqliteStore lock is never held while calling core. Prototype AB/BA deadlock **not recreated**.

**TOCTOU gaps (documented, see F-07):** authenticate → (gap) → respond/poll-deliver. Revocation in the gap is not re-checked. This is the carried-forward finding.

**Panic paths reachable from untrusted input:** `core.rs:234` `.expect("binding consistent")` in `submit` — only after `by_account` lookup + `controllers` insert under the same lock (invariant holds). `wait_timeout().unwrap()` panics on poisoned mutex (requires prior panic). `http.rs:525` `sid.parse().unwrap()` — session ids are server-generated hex (safe). No attacker-controlled panic → process termination path identified. `unsafe`: **none** in Gateway source.

---

## O. Resource-exhaustion review

| Vector | Control |
|---|---|
| Sessions | 64/account, 10,000 global (race-safe) |
| Inflight requests | 64/account (`MAX_INFLIGHT_PER_ACCOUNT`) |
| Queue | 8/controller |
| Long polls | one/controller (`active_polls`) |
| Blocking threads | `spawn_blocking` per poll — bounded by one-poll-per-controller |
| Bodies | per-route caps via `to_bytes(limit)` |
| Registration | token single-use; no unauthenticated flood target except /v1/register (4 KiB) |
| Audit growth | one row per identity event — bounded by human-scale register/rotate/revoke |

Fairness: per-account inflight/queue caps prevent global starvation. Unauthenticated work is limited to body parse + header checks before rejection.

**F-08 (LOW):** `active_polls` slot is released by explicit `release()` calls, not RAII. If `poll_wait` panicked mid-hold, the slot would leak and permanently deny that controller its poll (requires a prior panic; not attacker-reachable from HTTP/JSON).

---

## P. Secret / log audit

**Log statements (grep):** only `controller_id`, `account_id`, `request_id`, `session`, error `code`/`status` — never credential/token/Authorization values, never MCP payloads.

**Existing tests:** `mcp_path_never_logs_secrets_or_payloads`, `secret_debug_and_formatting_are_redacted`, `errors_do_not_echo_presented_secrets` — all pass.

**SQLite:** verifiers only. Distinctive sentinel probe covered by `plaintext_secrets_absent_from_database_file_and_rows`.

**Error oracle:** codes distinguish `invalid_credential` vs `revoked_controller` (401 both) and `unknown_request` (404). Distinctions are coarse and do not enable practical account enumeration (verifier lookup is exact-digest). Accepted.

---

## Q. Dependency / panic / unsafe review

**Direct deps (Cargo.toml, pinned in Cargo.lock):** serde 1, serde_json 1, uuid 1 (v4), tracing 0.1, getrandom 0.3, sha2 0.10, hex 0.4, rusqlite 0.40.2 (bundled), axum 0.8.9, tokio 1.53.1. Dev: tracing-subscriber 0.3.

No unnecessary new dependencies. Local advisory data unavailable — limitation stated.

**Panic inventory:** see §N. **unsafe:** none.

---

## R. Real E2E audit

Existing test `end_to_end_real_sinter_mcp` (tests/mcp_http.rs) passes — full path Public `/mcp` → Gateway → `/v1/poll` → bridge-shaped controller → real `sinter mcp` → `/v1/respond` → Gateway → public response.

Two-account concurrent isolation with identical public JSON-RPC ids: `cross_account_work_isolation` + `concurrent_mcp_calls` pass; independent probes confirm session+ownership rejection.

Zero-mutation evidence preserved (no apply/exec paths exist in Gateway; sinter tools called in tests are read-only).

---

## S. Findings

### F-01
- **Severity:** HIGH
- **Title:** TestPublicAuth is production-compiled and selectable
- **Affected code:** `src/mcp.rs:83-120`, `src/http.rs:98-105`, `src/lib.rs:27`
- **Attack/precondition:** a production `main()` calls `GatewayHttp::with_public_auth(Arc::new(TestPublicAuth::…))`, or a future config/CLI flag wires it in
- **Evidence:** probe constructed `TestPublicAuth` and attached it via `with_public_auth` in a non-test binary; no `#[cfg(test)]` gate exists
- **Impact:** `/mcp` would accept `X-Sinter-Test-Principal` as authentication — anonymous production MCP access with attacker-chosen principal mapping if the map is also populated from config
- **Recommended remediation:** `#[cfg(any(test, feature = "test-auth"))]` gate on `TestPublicAuth` and `with_public_auth` test path; or move to a `#[doc(hidden)] test_support` module not linked in release; P6 must replace the trait impl with OAuth and delete this type
- **P6 blocker?** YES

### F-02
- Cross-account respond: **not present** (rejected `wrong_controller`). No finding.

### F-03
- **Severity:** MEDIUM
- **Title:** `GatewayCore::cancel` lacks ownership check
- **Affected code:** `src/core.rs` `pub fn cancel`
- **Attack/precondition:** any code holding a `RequestId` (e.g. a compromised in-process component, future admin API) calls `core.cancel`
- **Evidence:** probe: `core.cancel(&rid_b)` succeeded for A on B's request
- **Impact:** foreign work can be cancelled without ownership; public HTTP paths are currently guarded by SessionManager so no direct remote exploit
- **Recommended remediation:** add controller/account ownership parameter to `cancel`, or make it `pub(crate)` and route all cancels through a checked helper
- **P6 blocker?** NO (defense-in-depth; fix before public launch)

### F-04 / F-05 / F-07 (session isolation) / F-08 (type confusion)
- Not present. No findings.

### F-06
- **Severity:** LOW
- **Title:** duplicate JSON-RPC ids overwrite `Session.live`
- **Affected code:** `src/mcp.rs` `SessionManager::track`
- **Attack/precondition:** a single session issues two concurrent forwarded calls with the same JSON-RPC id
- **Evidence:** probe: `track("dup", rid1); track("dup", rid2); cancel("dup")` → only `rid2` cancelled
- **Impact:** earlier request becomes un-cancelable via `notifications/cancelled` (lifecycle hole, not cross-account)
- **Recommended remediation:** reject a second `track` for an already-live public id, or store `Vec<RequestId>`
- **P6 blocker?** NO

### F-07
- **Severity:** MEDIUM
- **Title:** revocation not re-checked during/after authentication (mid-poll exposure)
- **Affected code:** `src/http.rs::poll` / `src/core.rs::respond`
- **Attack/precondition:** controller authenticates and begins long-poll; admin revokes the credential; new work is submitted
- **Evidence (fresh probe):** post-revocation work delivered to already-authenticated poll (`elapsed=75µs`); revoked controller `respond` succeeded
- **Impact:** stale authorization remains effective for up to the poll-hold window (≤60 s) and for any already-delivered work; `respond` never re-validates the verifier
- **Recommended remediation:** re-check `controller_by_verifier`/status at `poll_wait` wake and at `respond`; or bound the exposure by checking revocation on every delivery/complete
- **P6 blocker?** YES (must fix before P6 OAuth/production)

### F-08
- **Severity:** LOW
- **Title:** `active_polls` slot released by explicit call, not RAII
- **Affected code:** `src/core.rs` `poll_wait` `release` closure
- **Attack/precondition:** a panic inside `poll_wait` before `release()` runs (not attacker-reachable from HTTP/JSON; would require a poisoned-mutex or invariant bug)
- **Evidence:** source analysis; no attacker-controlled panic path identified
- **Impact:** controller permanently denied its single poll slot until restart
- **Recommended remediation:** RAII guard struct for `active_polls`
- **P6 blocker?** NO

---

## T. Carried-forward findings

| Finding | Status |
|---|---|
| mid-wait controller revocation | **RETAINED → F-07 (MEDIUM)** — fresh evidence confirms both delivery and respond after revoke |
| HTTP header-timeout/deployment caveat | **RETAINED (INFO)** — TLS termination is deployment's responsibility (RFC §13); no application-level defect |
| TestPublicAuth production containment | **RETAINED → F-01 (HIGH)** — no compile-time gate; selectable in production builds |

---

## U. RFC invariants I-1 … I-11

| Invariant | Verdict | Evidence |
|---|---|---|
| I-1 no SSH keys/config/target data into Gateway | PASS | grep: no ssh/known_hosts/hostname/identity fields in schema or code |
| I-2 WorkItem/PollResponse/RespondRequest have no exec/argv/env/path | PASS | `deny_unknown_fields` structs; probe + source |
| I-3 respond with wrong controller → 403 | PASS | probe: `wrong_controller` |
| I-4 no request field alters identity resolution | PASS | probe: spoofed `account_id` ignored (opaque); identity from bearer/PublicAuth only |
| I-5 expired/cancelled/responded reject further responses | PASS | tombstone `terminal_error`; existing tests |
| I-6 one response completes; second → 409 | PASS | `duplicate_response`; existing tests |
| I-7 no credential/Authorization value in logs | PASS | grep + `mcp_path_never_logs_secrets_or_payloads` |
| I-8 `/v1/test/*` absent from production build | PASS | probe: 404; router has no such route |
| I-9 controller plane outbound-only | PASS | no dialer to controllers in source |
| I-10 public surface = 8 sinter tools + profile; no apply/exec | PARTIAL | tool authority stays with sinter (opaque); profile edge-owned; **but F-01 allows test-auth bypass of the public identity layer** |
| I-11 notifications never block bridge | PASS | notifications 202 at edge, never forwarded |

---

## V. Test evidence

**Existing Gateway tests (all PASS, re-run):**  
`auth.rs`, `auth_concurrency.rs`, `bounds.rs`, `concurrency.rs`, `http.rs`, `http_log.rs`, `isolation.rs`, `lifecycle.rs`, `log_capture.rs`, `logging.rs`, `mcp_contract.rs`, `mcp_http.rs` (14), `mcp_log.rs` (1), `secrets.rs` (3), `sqlite_concurrency.rs` (4), `sqlite_store.rs` (11).

**Audit-only probes (not committed):** `/tmp/gateway-audit` — cross-account, session, id collision/type, type confusion, revocation terminal, edge routing, HTTP origin/CT/body/dup-headers, register/rotate, revocation mid-poll.

**Totals:** 16 test files, 0 failures; 2 audit probe binaries, findings as listed.

---

## W. Quality gates

| Gate | Result |
|---|---|
| `cargo fmt --check` | PASS |
| `cargo clippy --all-targets --all-features -- -D warnings` | PASS |
| `cargo test --all-targets --all-features` | PASS (all suites) |
| Sinter regression (HEAD 66ca3d7) | unchanged; ` D opencode.json` untouched |

---

## X. Repository integrity

- No production Gateway source changes
- No Sinter changes
- No prototype changes
- No RFC changes
- `D opencode.json` untouched
- Audit-only artifacts: `~/sinter-public-plugin-gateway/SINTER_GATEWAY_P1_P5_INTEGRATED_AUDIT_REPORT.md` (this report) and `/tmp/gateway-audit/` (probe binaries)

---

## Y. P6 readiness

```
REMEDIATION REQUIRED BEFORE P6
```

Blocking finding IDs: **F-01**, **F-07**.

---

## Audit verdict

```
SINTER GATEWAY P1-P5 INTEGRATED AUDIT: NO-GO
```

GO is withheld solely because F-01 (HIGH: production-reachable test authentication) and F-07 (MEDIUM: mid-wait/post-auth revocation gap) are unresolved. All architecture boundaries remain intact; cross-account isolation is proven; no arbitrary execution/tunnel path exists; no plaintext credential persistence/logging; no critical deadlock/restart/cancellation flaw. After F-01 and F-07 remediation (and confirmation of F-03/F-06/F-08 as non-blocking), the gate can be re-evaluated.
