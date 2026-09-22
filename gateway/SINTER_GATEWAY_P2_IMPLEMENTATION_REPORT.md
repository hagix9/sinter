# Sinter Public Plugin — Production Gateway P2 Implementation Report

P2 scope: production controller registration, identity, authentication,
credential rotation, and revocation — transport-independent core only.
No HTTP endpoints, no persistence implementation (P3), no OAuth (P6).

Authoritative spec: `~/sinter-public-plugin-research/SINTER_PRODUCTION_GATEWAY_SECURITY_RFC.md`
Prior phase: `SINTER GATEWAY P1: PASS` (`SINTER_GATEWAY_P1_IMPLEMENTATION_REPORT.md`)

---

## A. Starting identity

| Item | State |
|---|---|
| Gateway workspace | `~/sinter-public-plugin-gateway/` — P1 crate, not under git (unchanged from P1) |
| Sinter HEAD | `66ca3d778918e0d81500b9ba041d268ae90a9104` (unchanged) |
| Sinter status | ` D opencode.json` only — user-owned, untouched |
| Prototype | `~/sinter-public-plugin-prototype/` — not modified |
| RFC | `~/sinter-public-plugin-research/SINTER_PRODUCTION_GATEWAY_SECURITY_RFC.md` — not modified |

P1 baseline gates re-run before any P2 change: `fmt --check` clean,
`clippy -D warnings` clean, 50/50 tests pass. Confirmed green.

## B. P2 architecture

New modules:

- **`src/store.rs`** — `IdentityStore` trait (the P3 persistence boundary) +
  `MemoryStore`. Records carry only SHA-256 verifiers; indexes:
  `tokens`, `controllers`, `by_verifier`, `by_account`. All security-relevant
  operations (token take, controller insert, credential swap, status change)
  are atomic inside one lock. The trait contract states the atomicity
  requirements the future SQLite store must satisfy with transactions.
- **`src/auth.rs`** — `RegistrationToken` / `ControllerCredential` secret
  types, `ControllerAuth` (issue / register / authenticate / rotate / revoke),
  `AuthenticatedController` principal.

Identities (RFC §7): `controller_id` = `ctl_` + 128-bit CSPRNG, non-secret,
loggable, stable across rotation, derived from nothing else. `account_id`
is supplied console-side at token issue; the token binds the account —
callers never supply it at registration.

## C. Secret lifecycle

```
reg_ + 256-bit CSPRNG          ctrlk_ + 256-bit CSPRNG
  │                                │
  ▼                                ▼
issue → reveal once → verifier    register/rotate → reveal once → verifier
  │                                │
  ├─ consume (atomic, single-use)  ├─ authenticate (verifier map lookup)
  ├─ expire (now >= expires_at)    ├─ rotate → old verifier dead in same op
  ▼                                └─ revoke → status=Revoked (terminal)
permanently invalid                permanently invalid
```

`is_ascii_hexdigit` shape check + prefix check on parse; anything else is
`malformed_credential`. Verifier = SHA-256(presented), hex — full-digest
exact map key, no prefix/partial/case/whitespace-insensitive matching.
Security reasoning for full-digest lookup (RFC §9): a 256-bit CSPRNG secret
has 256 bits of entropy; its SHA-256 is unguessable, so digest-presence in
the map is exactly the question being asked — no comparison oracle exists
against a guessed plaintext.

## D. Registration semantics

- Entropy: 256-bit `getrandom` (OS CSPRNG) → `reg_` + 64 hex chars.
- TTL: `REGISTRATION_TOKEN_TTL_MS = 15*60*1000` (RFC ≤ 15 min); expiry checked
  inside the atomic take — `now >= expires_unix_ms → Expired` (same boundary
  rule as P1 deadlines).
- Single-use: `take_registration_token` marks consumed in the same critical
  section that checks presence/expiry — no TOCTOU. `Consumed` returns the
  record; `AlreadyConsumed`/`Expired`/`Missing` are distinct outcomes.
- Account binding: the token record carries `account_id`; `register` has no
  account parameter — the caller cannot redirect it.
- Concurrency: 16 racing consumers on one token → exactly 1 success, 15
  `consumed_registration_token`/`account_has_controller`. Two distinct tokens
  racing for one account → exactly 1 controller.
- One active controller per account enforced atomically in
  `insert_controller`: fails closed if the account's bound controller is
  Active; a Revoked row does not block re-registration (RFC §6 re-registration
  produces a new `controller_id` — no identity resurrection).

## E. Authentication

`authenticate(presented) → AuthenticatedController { account_id, controller_id }`:

1. `ControllerCredential::parse` — strict `ctrlk_` + 64-hex shape, else
   `malformed_credential`.
2. `verifier = SHA-256(presented)` → `by_verifier` exact lookup →
   controller record; miss → `invalid_credential`.
3. `status == Revoked → revoked_controller`; `Active → principal`.

Identity derives only from the stored record keyed by the credential.
No request field is consulted; the principal's fields are private and the
type is what future `/v1/poll`/`/v1/respond` handlers will pass into P1
`poll`/`respond`. Registration tokens are structurally excluded — wrong
prefix → `malformed_credential`, never reach the verifier map.

## F. Rotation and revocation

**Rotation** (`rotate(presented)`): resolve → `rotate_credential(id,
expected, new)` — atomic: verifies `expected` is still the record's live
verifier AND status is Active, then removes the old verifier and inserts the
new one inside one lock. Old credential invalid at the same instant the new
one becomes valid — no overlap, no gap. `StaleCredential` maps to
`invalid_credential` (the presented credential is simply no longer live).
Controller/account IDs unchanged.

**Revocation** (`revoke(presented)` / `revoke_controller(id)`):
`set_status → Revoked`. Terminal — `set_status` rejects Revoked→Active.
Idempotent (re-revoke is a no-op success). `by_verifier` rows survive, so a
stale credential resolves to the revoked record and deterministically reports
`revoked_controller` — never `invalid` — and can never re-authenticate.
Revocation keeps identity metadata for audit; nothing is deleted.

**Re-registration** (RFC §6): after revocation a new token issues a NEW
`ctl_` identity; `replace_account_controller` rebinds the account in the P1
work core only when the prior binding's controller exists (register already
proved the store allowed it because the old one is Revoked). The old
controller's queue entry is removed; its inflight requests can never be
answered (dead credential + gone binding).

## G. P1 integration

`register` binds `controller_id → account_id` in `GatewayCore` after the
store insert succeeds; on bind failure the controller record is revoked as
compensation (never a live credential for an unbound controller). Future
handlers will do:

```
authenticate(bearer) → principal → core.poll(principal.controller_id())
                                   core.respond(principal.controller_id(), ...)
```

Test `authenticated_principal_drives_p1_ownership` proves end-to-end:
A's registered principal polls/responds; B's authenticated principal cannot
see A's queue and cannot respond to A's `request_id` even holding it.
P1 state machine untouched — no P1 defect found.

## H. Concurrency evidence

| Test | Setup | Result |
|---|---|---|
| `single_use_token_16_concurrent_consumers` | 1 token, 16 racers, release barrier | exactly 1 win, 15 fail |
| `concurrent_rotations_leave_exactly_one_valid_credential` | 8 racers rotate same cred | exactly 1 swap wins; old cred `invalid`; sole new cred valid |
| `auth_vs_rotation_linearizes_cleanly` | hammer authenticate while rotating | post-rotation 100/100 old-cred auths fail; new valid |
| `concurrent_revoke_and_authenticate` | hammer authenticate while revoking | 0 successes observed after revoke completes; `revoked_controller` |
| `concurrent_duplicate_registration` | 2 tokens, 1 account, 2 racers | exactly 1 controller bound |

Defect found BY these tests during development: the initial `rotate`
resolved the credential, dropped the lock, then swapped — two racers could
both swap, leaving two live verifiers. Fixed by passing the resolved
verifier as `expected` into the atomic swap (`StaleCredential`). This was a
P2 implementation defect, caught and corrected before any PASS claim; it is
documented here as evidence the race gates have teeth, not hidden.

## I. Secret exposure audit

- **Persistence**: store records hold `Verifier` (SHA-256 hex) only;
  `plaintext_is_never_stored_only_verifiers` Debug-dumps the entire store and
  asserts no plaintext (or plaintext substring) appears.
- **Debug**: secret types have hand-written `Debug` → `RegistrationToken(REDACTED)` /
  `ControllerCredential(REDACTED)`; asserted in test.
- **Display/Serialize**: deliberately not implemented — leaking via
  `format!("{cred}")` or `serde_json::to_string(&cred)` is a compile error.
- **Errors**: fixed messages; `errors_do_not_echo_presented_secrets` asserts
  presented material never appears in error strings.
- **Logs**: `p2_logging_paths_never_emit_secrets` captures all tracing output
  across issue/register/rotate/revoke + failure paths; no token/credential
  substring appears; identity metadata (`ctl_`, `acc_`) is present (RFC §7:
  loggable).
- **Reports**: none — plaintext never reaches this document.

## J. Tests

72 total, all passing (3 consecutive full-suite runs, bounded, no hangs):

| Suite | Count | P2 coverage |
|---|---|---|
| `tests/auth.rs` | 13 | happy path, single-use, malformed/unknown, token≠bearer, expiry boundary (TTL−1 vs TTL), one-per-account, account binding, rotation swap, revocation, re-registration new identity, P1 ownership integration, post-rebind polling |
| `tests/auth_concurrency.rs` | 5 | race gates in §H |
| `tests/secrets.rs` | 4 | §I audit |
| `tests/bounds.rs` | 6 | P1 unchanged |
| `tests/concurrency.rs` | 4 | P1 unchanged |
| `tests/isolation.rs` | 7 | P1 unchanged |
| `tests/lifecycle.rs` | 17 | P1 unchanged |
| `tests/logging.rs` | 1 | P1 unchanged |
| `tests/mcp_contract.rs` | 15 | P1 unchanged (incl. live `sinter mcp`) |

## K. Quality gates

| Gate | Result |
|---|---|
| `cargo fmt --check` | clean |
| `cargo clippy --all-targets --all-features -- -D warnings` | 0 warnings |
| `cargo test --all-targets --all-features` | 72/72 pass (×3 runs, ~1s) |
| Sinter regression (`cargo test` in Sinter repo) | 484 tests / 20 suites pass |
| Sinter HEAD / status | `66ca3d7` unchanged; ` D opencode.json` untouched |

## L. Security invariant mapping (RFC §15)

| Inv | P2 status | Evidence |
|---|---|---|
| I-1 | enforced (P1+P2) | No SSH/target fields in auth or work types; `register` carries no SSH data (RFC step 2); auth grant is controller-plane only |
| I-2 | enforced (P1) | `WorkItem`/`Outcome` unchanged — no exec/argv/env/path fields; bounds test + schema audit from P1 still pass |
| I-3 | enforced (P1) | `respond` owner check; now fed by authenticated principal (test: B cannot answer A) |
| I-4 | enforced | `authenticate` derives identity solely from verifier lookup; `AuthenticatedController` fields are private, no setter; `register` has no account parameter |
| I-5 | enforced (P1) | terminal states unchanged; 17 lifecycle tests pass |
| I-6 | enforced (P1) | duplicate-response rejection unchanged |
| I-7 | enforced (P2 layer) | §I audit: redacted Debug, no Display/Serialize, captured-log grep over all auth paths; full production-wide coverage owed to P7 endpoint logging |
| I-8 | deferred → P5 | no HTTP layer exists yet; prototype ingress not compiled in |
| I-9 | enforced (P1) | no listener/dialer code; controller plane still outbound-only |
| I-10 | partially → P5/P6 | edge still forwards only `tools/list`/`tools/call`; profile tool + full audit at ingress phase |
| I-11 | enforced (P1) | notifications answered at edge, never queued |

## M. Files changed

Created: `src/store.rs` (252), `src/auth.rs` (~340), `tests/auth.rs`,
`tests/auth_concurrency.rs`, `tests/secrets.rs`.

Modified: `src/core.rs` (+`account_controller`, +`replace_account_controller`),
`src/proto.rs` (+8 auth `ErrorCode` variants), `src/lib.rs` (exports),
`Cargo.toml` (+`getrandom 0.3`, `sha2 0.10`, `hex 0.4` — CSPRNG, RFC-mandated
SHA-256 verifiers, hex encoding; nothing else).

Sinter tree, prototype tree, RFC tree: untouched. `opencode.json` untouched.

## N. Findings

- **LOW**: `by_verifier` retains verifiers of revoked/rotated credentials by
  design (needed for deterministic `revoked_controller` vs `invalid`).
  Unbounded across very long lifetimes; P3 persistence should note this as a
  deliberate tombstone.
- **LOW**: `register` binds into `GatewayCore` after the store commit; a bind
  failure compensates via revocation rather than a transaction. Acceptable —
  bind can only fail on a re-registration race already decided in the store —
  but P3's transactional store may fold this in.
- **INFO**: two intermediate P2 dev defects were caught by the mandatory race
  tests and fixed (post-resolve rotation swap without expected-verifier check;
  expiry checked after the atomic take consuming expired tokens). Neither
  survived to the gated build; both demonstrate the test gates work.
- No BLOCKER / HIGH / MEDIUM findings.

## O. P3 readiness

P3 may assume:

- `IdentityStore` is the persistence boundary; the SQLite implementation must
  provide the same atomicity: token take (single-use + expiry inside one
  transaction), insert_controller one-active-per-account, rotate with
  expected-verifier check, terminal revocation.
- Only SHA-256 verifier hex values ever cross the boundary — no plaintext,
  no key material to migrate.
- `ControllerAuth`/`AuthenticatedController` is the handler-facing API; P4
  `/v1/poll`+`/v1/respond` take `Authorization: Bearer ctrlk_…` →
  `authenticate` → principal → P1 ownership. No caller-supplied identity.
- `account_controller`/`replace_account_controller` cover the RFC
  re-registration rebind; nothing else may rebind.
- Token TTL constant, expiry boundary (`now >= expires`), and
  `TokenTake`/`StoreError` taxonomies are stable contracts.

SINTER GATEWAY P2: PASS
