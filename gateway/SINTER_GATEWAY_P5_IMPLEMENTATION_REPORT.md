# Sinter Gateway P5 — Public MCP Ingress Implementation Report

Scope: production `POST /mcp` public ingress wired to the P1–P4 core and
controller transport, per the approved Production Gateway Security RFC.
No OAuth/CIMD/DCR/PKCE — that is P6. This phase stops at the P5 boundary.

---

## A. Starting identity

| Item | Value |
|---|---|
| Gateway baseline | P4 PASS — 99 tests, all green, 3 stable runs |
| Sinter HEAD | `66ca3d778918e0d81500b9ba041d268ae90a9104` (unchanged) |
| Sinter status | ` D opencode.json` — user-owned, untouched |
| Sinter regression | 484 passed / 0 failed (unchanged) |
| RFC | `~/sinter-public-plugin-research/SINTER_PRODUCTION_GATEWAY_SECURITY_RFC.md` — unmodified |
| Prototype evidence | `~/sinter-public-plugin-prototype/SINTER_PUBLIC_PLUGIN_TRANSPORT_PROTOTYPE_REPORT.md` — unmodified |
| New dependencies | none (`getrandom`/`hex` already present from P2/P3) |

## B. Public MCP architecture

`src/mcp.rs` (new, 443 lines) + `/mcp` wiring in `src/http.rs`.

```
POST /mcp ──▶ check_origin → check_protocol_version → JSON body (≤1MiB+4KiB)
            → public_principal (PublicAuth) → mcp::handle_post
                                                   │
                            EdgeAction (src/edge.rs)│
              ┌───────────────┬────────────────────┼─────────────────┐
           Answer          AcceptOnly           Cancel            Forward
        (initialize,    (notifications/*      (notifications/  (tools/list,
         ping, profile,   except cancelled)    cancelled →        tools/call)
         errors, batches)                        core.cancel)         │
                                                                    ▼
                                              GatewayCore::submit → /v1/poll
                                              → sinter mcp → /v1/respond
                                              → original /mcp HTTP response
```

The edge inspects only `jsonrpc`, `id`, `method`, `params.name` (profile
detection), and `params.requestId` (cancelled notifications — lifecycle
metadata, never Sinter payload). Manifests, tool arguments, and tool
results are never parsed by the Gateway.

## C. Session model

- `MCP-Session-Id` = `sess_` + 128-bit CSPRNG hex (`getrandom`), created on
  successful `initialize` only — after the edge has answered and the edge
  lifecycle state (`initialized`, negotiated version) is persisted into the
  session. Malformed/unauthorized requests create nothing.
- Bound to `(account_id, subject_id)` of the authenticated public
  principal — checked on every use. Cross-account or cross-subject
  presentation → 403 `wrong_account`.
- Memory-only (`SessionManager` holds a `Mutex<HashMap>`); nothing reaches
  SQLite. Restart → all sessions gone; stale ids → 404 `unknown_request`.
- Absolute TTL `SESSION_TTL = 8h` (RFC gives no fixed value; "bounded in
  lifetime" — conservative default, lazy sweep on create).
- Caps: `MAX_SESSIONS_PER_ACCOUNT = 64`, `MAX_SESSIONS_GLOBAL = 10_000`;
  overflow → 503 `backend_unavailable`.
- `DELETE /mcp`: requires the same authenticated principal + session id;
  removes the session and cancels all its live P1 requests. Repeated
  DELETE → deterministic 404. Cross-account DELETE → 403.
- Session ids are routing context, never authorization — every request
  still requires the authenticated principal.

## D. MCP method routing

| Method | Route | Evidence |
|---|---|---|
| `initialize` | EDGE — answered by Gateway (`sinter-gateway`, `capabilities:{tools:{listChanged:false}}`, negotiated version); creates session | `init_session` asserts exact capability shape |
| `ping` | EDGE — `{}` | matrix test |
| `notifications/initialized`, other `notifications/*` | EDGE — HTTP 202, no body, never forwarded | e2e + no-tunnel test |
| `notifications/cancelled` | EDGE — maps `params.requestId` to `cancelled` state (RFC §8); still 202 | `cancelled_notification_cancels_live_work` |
| `tools/call` name=`sinter_get_profile` | EDGE — profile built from the authenticated principal's account only | e2e + spoofing test |
| `tools/list` | FORWARD — verbatim to controller; response gets the single RFC-sanctioned `sinter_get_profile` injection keyed on the request method | e2e (9 tools = 8 sinter + profile, exactly once) |
| `tools/call` (sinter tools) | FORWARD — verbatim, opaque args | e2e `sinter_get_version`, `id` preserved (`77`, `weird-id-42`) |
| any other method | REJECT — `-32601` at the edge, never queued | `unknown_methods_never_reach_controller` |
| batch arrays | REJECT — `-32600` (Streamable HTTP = one message per POST; sinter's batch support stays on the private stdio leg) | matrix test |
| malformed / non-`2.0` / missing method | `-32600` JSON-RPC answer | matrix test |
| `GET /mcp` | 405 (no SSE — sinter emits no server-initiated traffic) | matrix test |
| `DELETE /mcp` | session logout (RFC: "we choose to implement it") | isolation + delete-cancels-live tests |

## E. Tool authority

`sinter mcp` remains the sole authority for tool definitions, argument
validation, and result semantics. The Gateway forwards frames verbatim and
never duplicates or rewrites Sinter tool schemas. The single exception is
the RFC-defined `sinter_get_profile` edge tool: injected into forwarded
`tools/list` responses keyed on the **request method** (not response shape —
a `tools/call` result could coincidentally contain a `tools` field), and
answered at the edge from validated identity. Injection is a pure append;
`inject_profile_tool` passes non-conforming shapes (e.g. error responses)
through unchanged. Verified against the real backend: 8 Sinter tools + 1
profile tool, exactly once.

## F. Public identity abstraction

```rust
pub trait PublicAuth: Send + Sync {
    fn authenticate(&self, headers: &HeaderMap) -> Option<PublicPrincipal>;
}
pub struct PublicPrincipal { account_id: AccountId, subject_id: String }
```

`PublicPrincipal` fields are private — only a `PublicAuth` impl can mint
one. P5 ships `TestPublicAuth`, a deliberately-unmistakable test injection
(`X-Sinter-Test-Principal` header over a static map). If no `PublicAuth`
is configured, `/mcp` fails closed with 503 — proven by
`mcp_fails_closed_without_public_auth`. There is no anonymous path and no
production-shaped fake bearer token that could drift into P6.

**P6 must replace:** `TestPublicAuth` with real OAuth bearer validation
producing `PublicPrincipal{account_id, subject_id}` from verified token
claims. The trait boundary, session binding, and downstream routing are
already correct — P6 swaps the implementation only.

## G. Cancellation and deadline behavior

- Forwarded calls submit P1 work with `deadline ≤ 120 s` (RFC §11);
  `with_mcp_deadline` test hook shortens but can never lengthen it.
- The wait is `rx.recv_timeout` on `spawn_blocking` — off the async
  executor.
- **Caller disconnect**: `CancelOnDrop` guard fires when the handler
  future drops → `core.cancel` → terminal. Proven over a real socket:
  `caller_disconnect_cancels_owned_work` delivers work to the controller,
  closes the socket, then confirms the late `/v1/respond` → 410
  `cancelled_request`.
- **`notifications/cancelled`**: edge maps `params.requestId` (the public
  JSON-RPC id) through the session's live-request map to the internal
  `request_id` → `core.cancel`. The waiting caller receives JSON-RPC
  `-32000` `cancelled_request`; the late respond is rejected. Unknown ids
  are a silent no-op (still 202 — notification semantics).
- **DELETE /mcp** cancels all live work owned by the session
  (`session_delete_cancels_live_request`).
- Deadline expiry → `-32000` `deadline_exceeded`; cancel → `-32000`
  `cancelled_request`; channel `Disconnected` maps to the request's actual
  tombstone state via `core.request_state`.
- No requeue, no durable work, no replay after restart.

## H. Isolation evidence

- Session↔account: A's sid + B's auth → 403; A can't DELETE B's session
  (403); A can't reuse B's sid.
- Work routing is principal-only: `caller_supplied_identity_never_routes`
  submits `account_id`/`controller_id`/`target` spoofing fields in tool
  arguments — they are opaque args; the call still routes to A's
  controller. Profile call with `account_id:"acc_b"` argument returns A's
  profile.
- `cross_account_work_isolation`: A's submitted work does not appear on
  B's `/v1/poll`; A's controller receives it, A's respond completes it,
  caller id `a-req` round-trips.
- One active controller per account (P1 invariant) — unchanged.

## I. End-to-end proof

`end_to_end_real_sinter_mcp` runs the **real** production path:

```
test caller → POST /mcp → Gateway edge → GatewayCore::submit
          → POST /v1/poll → bridge-shaped controller loop
          → real `sinter mcp` child over stdio
          → POST /v1/respond → original /mcp HTTP response
```

Verified methods: `initialize` (edge + `MCP-Session-Id` issue),
`notifications/initialized` (202), `tools/list` (8 real Sinter tools +
injected profile tool), `tools/call sinter_get_version` (caller id
`"weird-id-42"` preserved verbatim), `tools/call sinter_get_profile`
(edge). The bridge loop is exactly `poll → writeln!(sinter stdin) →
read_line → respond` — the shape `sinter-bridge` will use.

## J. Zero-mutation evidence

P5 tests use only `sinter_get_version` / `sinter_list_targets`-class
read-only tools against the stdio backend — no manifest apply, no SSH, no
managed host contact. No real host was involved; nothing to mutate.

## K. Limits and error mapping

| Condition | Result |
|---|---|
| missing public auth | 503 `backend_unavailable` (fail closed) |
| invalid/absent test principal | 401 `missing_auth` |
| missing `MCP-Session-Id` (non-init) | 401 `missing_auth` |
| unknown/expired/deleted session | 404 `unknown_request` (deterministic) |
| session/account mismatch | 403 `wrong_account` |
| wrong/absent Origin | 403 / allowed-absent; duplicate Origin → 400 |
| unsupported/duplicate `MCP-Protocol-Version` | 400; absent → assumed `2025-03-26` |
| missing/wrong Content-Type | 415 `unsupported_media_type` |
| malformed JSON | 400 `malformed_request` |
| oversized body | 413 `oversized_request` (1 MiB + 4 KiB cap, streamed) |
| unknown JSON-RPC method | 200 + `-32601` |
| invalid frame / batch | 200 + `-32600` |
| no controller for account | 200 + `-32000` `controller_offline` |
| registered controller never polls | queued until deadline → `-32000` `deadline_exceeded` |
| caller disconnect / `notifications/cancelled` / DELETE | request `cancelled`; caller (if still present) gets `-32000` `cancelled_request`; late respond → 410 |
| restart | sessions/work gone; stale sid → 404; stale rid → 404 |
| `GET /mcp` | 405 | 
| controller response errors | `-32000` with `data.code` = P1 transport code |

Body caps: request 1 MiB, response 4 MiB (P1 `MAX_MCP_*` constants reused),
poll hold ≤ 60 s, deadline ≤ 120 s, one poll per controller, bounded
in-flight work — all P1/P4 invariants unchanged.

## L. Secret/log audit

`tests/mcp_log.rs` (isolated binary, global subscriber) drives real HTTP:
test-principal token (success + failure), MCP tool **arguments** and
manifest marker bytes forwarded through `/mcp`, marker-laden controller
respond bodies, controller bearer, registration token, malformed-body
markers, and rejected-Origin values — **none** appear in captured tracing
output. Log lines carry only request_id/account/session id/method class.
P4's `http_log.rs` markers remain green.

## M. Tests

114 total (baseline 99 + 15 new):

- `tests/mcp_http.rs` — 14 integration tests: real-sinter e2e, fail-closed
  auth, session lifecycle/isolation, version/Origin/method matrix,
  caller disconnect, `notifications/cancelled`, session-delete cancel,
  offline/deadline, no-controller, restart, spoofing, no-tunnel,
  cross-account work isolation, 8-way concurrency.
- `tests/mcp_log.rs` — 1 isolated marker-secret test.
- `tests/mcp_contract.rs` — updated: `notifications/cancelled` now asserts
  `EdgeAction::Cancel(requestId)` (RFC §8 change, previously AcceptOnly).
- `tests/http.rs` — updated: `/mcp` is now a real route; the surface test
  asserts fail-closed (415 without Content-Type) instead of 404.
- All P1–P4 tests unchanged otherwise and green.

## N. Quality gates

| Gate | Result |
|---|---|
| `cargo fmt --check` | clean |
| `cargo clippy --all-targets --all-features -- -D warnings` | clean |
| `cargo test --all-targets --all-features` | **114 passed / 0 failed**, 4+ consecutive full runs + targeted stress runs |
| Sinter regression | 484 passed / 0 failed |

One TCP-level flake was found and fixed during development: early-reject
responses (400 before the body is drained) arrive followed by RST; the raw
test client now keeps buffered bytes on `read_to_end` error rather than
panicking. Suite stable afterward.

## O. Security invariant mapping (I-1 … I-11)

| # | Status | Note |
|---|---|---|
| I-1 | **enforced** | no SSH/target/credential fields exist on the public or controller wire shape; `/mcp` forwards opaque frames only |
| I-2 | **enforced** | work envelopes remain `{request_id, mcp}` — no executable/argv/env/path |
| I-3 | **enforced** | respond ownership = inflight owner (P1); covered by P4 tests, exercised again through `/mcp` |
| I-4 | **enforced** | account/controller derive only from validated credentials (controller bearer) or authenticated public principal (`/mcp`) |
| I-5 | **enforced** | cancelled/expired/responded → late responses rejected; proven via disconnect + notification-cancel + session-delete tests |
| I-6 | **enforced** | single completion; duplicate-response test unchanged |
| I-7 | **enforced** | `mcp_log.rs` marker test — no secrets/payloads/verifiers in logs |
| I-8 | **enforced** | no `/v1/test/*` surface; `/mcp` is the only public ingress |
| I-9 | **enforced** | controller plane remains outbound-only (`/v1/poll`) |
| I-10 | **enforced** | public surface = 8 Sinter tools + `sinter_get_profile`; unknown methods → `-32601` at the edge, never queued |
| I-11 | **enforced** | notifications consumed at edge → 202; none reach the controller (`unknown_methods_never_reach_controller` proves zero queue leakage) |

Deferred (by design, not gaps): public OAuth identity (P6), TLS
termination (P7/deployment), payload AEAD, connector allowlists,
multi-controller per account.

## P. Open findings

| Class | Finding |
|---|---|
| LOW | **Mid-wait revocation** (carried from P4): a controller revoked while work is in flight can no longer respond (P2 auth blocks it), but the waiting `/mcp` caller isn't proactively woken — it resolves at deadline. Prompt invalidation is P7 hardening; P1 cancel/expire semantics bound the wait correctly. |
| LOW | **`Disconnected` recv edge**: if the response channel drops without a terminal outcome (theoretically possible on an abrupt internal removal), the caller sees `-32000` mapped from `request_state` tombstone — worst case `backend_unavailable`. Correct but coarse. |
| INFO | `notifications/cancelled` for an unknown public id is a silent 202 no-op (JSON-RPC notification semantics — no error channel exists). |
| INFO | `SESSION_TTL = 8h` and session caps (64/account, 10k global) are conservative P5 defaults; RFC leaves exact values to implementation. |
| INFO | Repeated `initialize` mints a new session each time (spec-correct: initialize carries no session); the abandoned session dies by TTL. Bounded by caps. |

No BLOCKER/HIGH/MEDIUM findings.

## Q. Files changed

Gateway (not a git repo — full list):

- `src/mcp.rs` — **new** (443 lines): `PublicAuth`/`PublicPrincipal`,
  `TestPublicAuth`, `SessionManager`, `handle_post`, `forward`,
  `CancelOnDrop`, cancel-notification mapping.
- `src/edge.rs` — `EdgeAction::Cancel` variant + `notifications/cancelled`
  classification (RFC §8).
- `src/http.rs` — `/mcp` route (POST/GET/DELETE), Origin +
  `MCP-Protocol-Version` validation, public-auth plumbing, `with_mcp_deadline`
  test hook, `sessions()` accessor.
- `src/lib.rs` — export `mcp` module + P5 types.
- `tests/mcp_http.rs` — **new** (14 integration tests).
- `tests/mcp_log.rs` — **new** (marker-secret test).
- `tests/mcp_contract.rs` — cancelled-notification expectation updated.
- `tests/http.rs` — `/mcp` surface expectation updated (exists, fail-closed).

Sinter tree: unchanged (`66ca3d7`, ` D opencode.json` untouched).
Prototype and RFC: unchanged.

## R. Integrated audit readiness

P1–P5 form one system: public `/mcp` → P1 work lifecycle → P4 controller
transport → real `sinter mcp` — all proven over real loopback sockets.
The implementation is **ready** for the dedicated

`P1–P5 INTEGRATED SECURITY / ARCHITECTURE AUDIT`

Recommended next action: that audit, before any P6 OAuth work begins.

---

SINTER GATEWAY P5: PASS
