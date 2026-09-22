# Sinter Public Gateway — P1 Implementation Report

Date: 2026-09-22
Scope: P1 only — production protocol/core state-machine foundation per the
approved Production Gateway Security RFC. No HTTP endpoints, authentication,
persistence, OAuth, or deployment.

## A. Starting identities

- **Sinter repo**: `/Volumes/VGX1000 SSD/Codex/Projects/Sinter` — HEAD
  `66ca3d778918e0d81500b9ba041d268ae90a9104` (frozen v0.5.0); status ` D
  opencode.json` (intentional user-owned; untouched throughout).
- **Prototype**: `~/sinter-public-plugin-prototype/` — intact, not a git repo,
  unmodified. Reviewed for reuse; its lock-ordering deadlock informed the
  production single-lock design (§B).
- **Gateway workspace**: `~/sinter-public-plugin-gateway/` — did not exist;
  created fresh per RFC fallback location (RFC specifies no concrete path).

## B. Architecture implemented

One Rust lib crate `sinter-gateway` (`publish = false`), transport-independent:

```
src/id.rs     typed AccountId/ControllerId/RequestId (req_+128-bit UUIDv4,
              unpredictable, log-safe, carries no authority)
src/clock.rs  Clock trait: mono() for expiry + unix_ms() for wire deadlines;
              SystemClock + shared TestClock (deterministic, no sleeps)
src/proto.rs  wire v1: WorkItem/RespondRequest/Outcome, deny_unknown_fields,
              ErrorCode taxonomy (15 codes), limits table
src/state.rs  explicit transition table — anything unlisted fails closed
src/core.rs   GatewayCore: ONE Mutex<Inner> guards everything — the
              prototype's controllers↔inflight AB/BA deadlock is
              structurally impossible (no second lock exists)
src/edge.rs   public MCP edge contract (Q-2): edge lifecycle vs forwarded
              tool traffic; profile-tool definition/injection
```

Dependencies: serde, serde_json, uuid, tracing (+tracing-subscriber dev-only).
No broker/DB/OAuth/HTTP — per P1 constraints.

## C. Q-2 resolution — RESOLVED

Observed `sinter mcp` v0.5.0 (`src/mcp.rs` + live binary probes):

- methods: `initialize`, `ping`, `tools/list`, `tools/call`; all else → -32601
- `initialize` = constant idempotent response, `protocolVersion "2025-03-26"`,
  `serverInfo sinter-mcp`, `capabilities {tools:{listChanged:false}}`
- `notifications/*` → consumed, **never answered** (verified live: child stays
  silent until a subsequent `ping`)
- batches accepted (one line in → one line out when responses exist)
- never emits unsolicited server→client messages; JSON-RPC `id` echoed verbatim

Resulting edge contract (encoded in `src/edge.rs`, tested in
`tests/mcp_contract.rs`):

| Frame | Handling |
|---|---|
| `initialize` | edge answers: `sinter-gateway` serverInfo, `{tools:{listChanged:false}}`, negotiated version (echo if ∈ {2025-03-26, 2025-06-18, 2025-11-25}, else `2025-11-25`); re-init → -32600 |
| `ping` | edge `{}` |
| `notifications/*` | 202, never forwarded (forwarding would deadlock the stdio child — proven live) |
| `tools/list` | forward verbatim + profile-tool injection on response |
| `tools/call` `sinter_get_profile` | edge answers from validated account identity |
| `tools/call` other | forward verbatim (sinter remains name/arg authority) |
| anything else | edge -32601; batches → -32600 (not part of Streamable HTTP POST contract) |
| pre-init tool traffic | edge -32600 `session not initialized` |

Live chain proven end-to-end: edge `Forward` → real `target/debug/sinter mcp`
stdio → response with caller's `id` preserved (`weird-id-42`, `77`).
**Q-2: RESOLVED** — edge-owned `initialize` is compatible; the gateway
advertises nothing the backend can't honor (capabilities are the edge's own;
tool semantics remain sinter's).

## D. Request lifecycle

```
Created ──▶ Queued ──▶ Delivered ──▶ Responded
   │          │           │
   │          ├───────────┼──▶ Expired      (now >= deadline_mono)
   └──────────┴───────────┴──▶ Cancelled    (caller disconnect / cancelled)
```

Terminal: Responded, Expired, Cancelled — irreversible, tombstoned 15 min.
`Created` is a transient constructor state; stored requests begin `Queued`.

- **Delivery**: `poll` pops destructively — redelivery impossible; dead
  entries reaped lazily (never delivered).
- **Respond**: requires `Delivered` + owning controller + before deadline;
  exactly one `Outcome` is ever sent on the completion channel.
- **Boundary**: expiry iff `now >= deadline` (response must arrive strictly
  before — conservative).
- **Cancel**: terminal; late response → `cancelled_request`, never completes.
- **At-least-once correctness**: delivery duplication impossible by
  construction; response duplication → `duplicate_response` with exactly one
  completion; completion duplication impossible (single `tx` taken once).

## E. Security behavior

- **Ownership**: `respond` checks `request.controller == caller` *before*
  state — a wrong-controller probe learns nothing beyond `wrong_controller`;
  registered or not, an ID alone never suffices (tested incl. ghost identity).
- **Expiry**: monotonic internally; absolute `deadline_unix_ms` on the wire.
- **Bounds**: 1 MiB request / 4 MiB response on parsed values (byte-cap at
  HTTP edge is P5); oversized response rejects without consuming the request.
- **Execution channel**: `WorkItem`/`RespondRequest` carry exactly
  `{v,request_id,deadline_unix_ms,mcp}` — `deny_unknown_fields` + recursive
  key audit prove no exec/argv/env/path field can exist (I-2).
- **Logs**: identifiers + transitions only; marker-secret regression test.

## F. Tests — 50 total, all passing, bounded (~1 s)

| File | Tests | Covers |
|---|---|---|
| lifecycle.rs | 17 | happy path, full transition table (8 legal/10 illegal), redelivery impossibility, duplicate response, pre-delivery respond, deadline before/at/after, expired-skip on poll, sweep, cancel terminality, cancel-vs-expiry race, offline/no-controller, queue cap, inflight cap |
| isolation.rs | 7 | wrong controller answer, cross-tenant queue invisibility, unknown/ghost IDs, rebind prevention, one-controller-per-account, stolen-ID-without-delivery |
| bounds.rs | 6 | oversized request/response, malformed respond bodies, exact WorkItem schema, unknown-field rejection, recursive exec-field audit, error-code wire stability |
| mcp_contract.rs | 15 | all edge contract rows + 3 LIVE tests against real `sinter mcp` (8-tool surface, idempotent initialize contract, notification silence, verbatim id, real `sinter_validate_manifest` through the forward chain) |
| concurrency.rs | 4 | 32-request parallel lifecycle (no double completion), 16 racing responders (1 wins), cancel/respond race ×50 (one terminal outcome), 8 racing pollers (1 delivery) |
| logging.rs | 1 | marker secrets never logged; identifiers present |

## G. Quality gates

- `cargo fmt --check` — clean
- `cargo clippy --all-targets --all-features -- -D warnings` — clean, 0 warnings
- `cargo test --all-targets --all-features` — 50/50 pass
- Sinter regression (repo unchanged): `cargo fmt --check` clean; `cargo test`
  20/20 suites ok, 0 failures; `git status` still only ` D opencode.json`

## H. Security invariant mapping (RFC I-1…I-11)

| Inv | P1 status | Evidence |
|---|---|---|
| I-1 no SSH data to gateway | enforced structurally | protocol has no such fields; bounds tests; matrix in RFC holds — full proof at P8 e2e |
| I-2 no exec/argv channel | **enforced + tested** | `work_item_schema…`, `no_execution_control_fields…` |
| I-3 wrong-controller respond → refuse | **enforced + tested** | `controller_cannot_answer…`, `unregistered_controller…` |
| I-4 routing only from validated identity | **enforced** | core accepts only typed `AccountId`/`ControllerId`; no request field can set them (P2 supplies credential→identity derivation) |
| I-5 terminal requests reject further work | **enforced + tested** | transition table, expired/cancelled respond tests |
| I-6 single completion | **enforced + tested** | duplicate/racing-responder tests, single `tx.take()` |
| I-7 no secrets in logs | **enforced + tested** | `logs_never_contain_payloads_or_secret_material` |
| I-8 no prototype test paths in production | **enforced** | `/v1/test/*` never existed in this crate; no HTTP layer at all yet |
| I-9 controller connects outbound only | enforced by design | core has no dialer/listener; P4 preserves |
| I-10 only 8 sinter tools + profile reachable | **enforced + tested** | edge -32601 table, profile injection, live tools/list |
| I-11 notifications never block bridge | **enforced + tested** | `notifications_are_consumed_never_forwarded`, live silence proof |

Deferred (not P1 subsystems): none of I-1…I-11 is deferred in substance —
credential-bearing forms of I-1/I-4 harden in P2 (registration/auth), wire
forms of I-9 in P4 (endpoints), and public-surface forms of I-8/I-10 in P5
(`/mcp` listener). The core guarantees above are their foundation.

## I. Files created/changed

Created (all under `~/sinter-public-plugin-gateway/`, uncommitted):
`Cargo.toml`, `src/{lib,id,clock,proto,state,core,edge}.rs`,
`tests/{lifecycle,isolation,bounds,mcp_contract,concurrency,logging}.rs`,
this report. Not modified: Sinter repo, prototype, both RFCs, `opencode.json`.

## J. Findings

- **LOW** — `tombstones` use `Instant` from the injected clock; TTL sweep is
  clock-driven and deterministic in tests, but a clock jump only shortens
  retention (safe direction). Acceptable.
- **LOW** — `submit` resolves the account's controller via `by_account` only;
  a controller registered but never seen is treated offline — intended.
- **LOW** — `EdgeSession` is per-connection state that the future HTTP layer
  must key by `MCP-Session-Id`; P1 provides the type, P5 wires it.
- **INFO** — `Outcome::Mcp` responses pass verbatim; response size is checked
  on the parsed value — a hostile controller can't exceed 4 MiB semantic
  size; byte-cap at transport edge remains P5 hardening.
- **INFO** — one-controller-per-account enforced in `register_controller`;
  multi-controller remains deferred per RFC (Q-4).

No BLOCKER/HIGH/MEDIUM findings.

## K. P2 readiness

P2 (controller registration/auth) may now assume:

- Typed `AccountId`/`ControllerId`/`RequestId` exist and carry no authority.
- The state machine is complete, terminal, ownership-enforcing, and tested —
  P2 wraps `poll`/`respond` with credential→identity derivation and adds
  `register/rotate/revoke` endpoints feeding `register_controller`.
- `Outcome`/`TransportError`/`ErrorCode` are wire-stable.
- The edge contract is frozen and compatible with sinter v0.5.0 (Q-2 resolved).
- Limits constants are centralized in `proto.rs` for tuning.
- Nothing in P1 pre-commits to a poll wire shape — `PollRequest` auth fields
  are P2's to define.

---

SINTER GATEWAY P1: PASS
