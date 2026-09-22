# Sinter Public Plugin — Production Gateway P3 Implementation Report

P3 scope: durable identity/registration persistence — an embedded SQLite
implementation of the P2 `IdentityStore` contract plus the RFC's audit table.
No durable work, no HTTP endpoints, no P4 scope.

Authoritative spec: `~/sinter-public-plugin-research/SINTER_PRODUCTION_GATEWAY_SECURITY_RFC.md`
Prior phases: `SINTER GATEWAY P1: PASS`, `SINTER GATEWAY P2: PASS`

---

## A. Starting identity

| Item | State |
|---|---|
| Gateway | `~/sinter-public-plugin-gateway/`, not under git; P2 baseline 72/72 tests green before P3 changes |
| Sinter HEAD | `66ca3d778918e0d81500b9ba041d268ae90a9104` (unchanged) |
| Sinter status | ` D opencode.json` only — untouched |
| Prototype / RFC | not modified |

## B. Persistence architecture

**Durable** (SQLite, `src/sqlite_store.rs`):

- controller identity (`ctl_` id), account binding, credential *verifier*,
  status, created/rotated/revoked timestamps
- registration-token *verifier*, account binding, expiry, consumption time
- audit events: `(ts, kind, account_id, controller_id)` — metadata only
- `meta.schema_version` = `"1"`

**Memory only** (unchanged P1/P2): live MCP requests, `tools/call`/
`tools/list` envelopes, manifests, tool args/results, poll delivery, inflight
map, deadlines, sessions. The restart test proves the boundary end-to-end.

## C. SQLite dependency model

- Library: `rusqlite 0.40.2` with `features = ["bundled"]` → `libsqlite3-sys`
  compiles the SQLite C source **statically into the gateway binary**.
- External runtime requirements: **none**. No `sqlite3` CLI, no OS package,
  no shared library prerequisite. The binary carries its own SQLite.
- Boundary: `rusqlite`/`libsqlite3-sys` appear only in the `sinter-gateway`
  crate (`cargo tree` verified). Sinter's `Cargo.toml`/`Cargo.lock` contain
  zero sqlite references; nothing in `sinter`, `sinter mcp`, `sinter-bridge`,
  installers, or target hosts changes.
- Config: `journal_mode=WAL`, `synchronous=FULL`, `busy_timeout=5000`.
  Rationale: the identity workload is tiny (register/rotate/revoke are
  human-scale rare events); a single `Mutex<Connection>` serializes all
  access; WAL + FULL gives crash-safe commits; busy_timeout bounds transient
  contention rather than hanging. No connection pool — unjustified here.

## D. Schema (v1, minimal)

```sql
meta(key PRIMARY KEY, value)                    -- schema_version only

registration_tokens(
    verifier         TEXT PRIMARY KEY,          -- sha256(reg_ plaintext), hex
    account_id       TEXT NOT NULL,             -- token is account-bound
    created_unix_ms  INTEGER NOT NULL,
    expires_unix_ms  INTEGER NOT NULL,          -- unix ms; no tz, no SQLite time fns
    consumed_unix_ms INTEGER                    -- NULL = live
)

controllers(
    controller_id   TEXT PRIMARY KEY,
    account_id      TEXT NOT NULL,
    cred_verifier   TEXT NOT NULL UNIQUE,       -- sha256(ctrlk_ plaintext), hex
    status          TEXT CHECK (status IN ('active','revoked')),
    created_unix_ms INTEGER NOT NULL,
    rotated_unix_ms INTEGER,
    revoked_unix_ms INTEGER
)
CREATE UNIQUE INDEX controllers_one_active_per_account
    ON controllers(account_id) WHERE status='active';

audit_events(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_unix_ms INTEGER NOT NULL,
    kind TEXT NOT NULL,                          -- token_issued/consumed,
    account_id TEXT, controller_id TEXT          -- registered/rotated/revoked
)
```

Every column exists for a current purpose: verifiers are the lookup keys;
`consumed_unix_ms` drives both single-use and the RFC's 24h spent-token
purge; rotated/revoked timestamps satisfy the RFC's durable identity model;
the CHECK + partial unique index enforce valid status values and the v1
one-active-controller-per-account rule at the storage layer. A rotated-away
verifier is *deleted* by the swap (safely deletable immediately — its
tombstone is not needed for `invalid_credential` semantics); revoked
controller rows persist (RFC: until revoked+90d; no deletion implemented —
documented under Findings). No `accounts` table: account rows arrive with the
OAuth phase (P6); `account_id` is currently a bound string, and inventing an
accounts lifecycle now would be speculative.

## E. Transaction semantics

All mutating operations run inside `BEGIN IMMEDIATE` transactions on the
single connection:

| Operation | Boundary |
|---|---|
| `take_registration_token` | read consumed+expiry → mark consumed → audit row: one tx. Expired tokens are NOT consumed (deterministic `expired` on retry). |
| `insert_controller` | INSERT + audit: one tx. The partial unique index converts a raced second-active-insert into `AccountHasActiveController`. |
| `rotate_credential` | read status+verifier → verify `expected` still live → swap verifier + rotated_ts + audit: one tx. The P2 race defect cannot reappear — the expected-verifier check is inside the transaction; the loser's read sees the rotated verifier → `StaleCredential`. |
| `set_status` | read current → terminal check (Revoked→Active rejected) → update + audit: one tx. Idempotent no-op for repeat revocation. |
| `purge_spent_tokens` | single DELETE. |
| `ControllerAuth::register` | token take (tx) → controller insert (tx) → work-core bind; bind failure compensates by revoking the record (never a live credential for an unbound controller). |

A crash between commits can never produce a half-registered controller: the
token is either unconsumed+no controller, or consumed+controller — both are
well-defined states (the former allows retry, which is correct since the
credential was never issued to anyone).

## F. Restart evidence

`identity_survives_restart_work_does_not` and
`revoked_and_expired_state_survives_restart` (file-backed DB, two store
lifetimes on one path):

| Survives restart | Does NOT survive |
|---|---|
| rotated credential authenticates to same `ctl_`/`acc_` | P1 work queue (poll returns empty) |
| rotated-away credential stays `invalid` | queued/inflight requests |
| consumed token stays `consumed` | request deadlines |
| revoked credential stays `revoked` | controller↔core binding (re-established via `bind`) |
| expired token stays `expired` | — |
| account binding (re-registration still fails `account_has_controller`) | — |

Restart gap discovered and closed: durable identity alone left the fresh
`GatewayCore` with no queue binding, so post-restart polls would fail
`unknown controller` forever. Added `ControllerAuth::bind(core, principal)` —
idempotent re-bind of an *authenticated* principal; fails closed if the
account is bound to a different controller. This is the P4 reconnect hook
and is itself test-covered.

## G. Secret exposure audit

`plaintext_secrets_absent_from_database_file_and_rows`: full lifecycle with
distinctive `reg_`/`ctrlk_` plaintexts → WAL checkpoint → assert plaintexts
(and their post-prefix bodies) absent from raw db bytes AND from every text
column of every table; assert the expected SHA-256 verifier *is* present.
`sqlite_error_paths_never_echo_secret_material`: corrupt-file, constraint
violation, and bad-credential errors echo no presented secret or verifier.
`audit_rows_contain_metadata_no_secrets`: audit contains ids only. Log-level
secret test (isolated `tests/log_capture.rs`) covers tracing output across
issue/register/rotate/revoke/failure paths.

## H. Concurrency evidence (SQLite-backed, all bounded ~10ms)

| Test | Result |
|---|---|
| 16 consumers × 1 token | exactly 1 success, 15 fail |
| 8 racers rotate same credential | exactly 1 winner; old cred `invalid`, sole new cred valid |
| 4 tokens race for 1 account | exactly 1 controller (partial unique index holds) |
| authenticate vs revoke | 0 successes observed after revoke completes; `revoked_controller` |

Plus MemoryStore/SQLite lifecycle parity test running the identical
scenario through both implementations.

## I. Failure behavior

| Case | Behavior |
|---|---|
| Missing DB file | create + initialize schema (fresh environment self-bootstraps; no sqlite3 CLI needed) |
| Empty (0-byte) file | initialized as fresh |
| Existing DB, correct schema | verified, reopened |
| Corrupt/unreadable file | open fails — Err, no silent recreate |
| Foreign schema (no `meta.schema_version`) | Err — fail closed |
| Wrong schema version | Err — fail closed |
| Missing required table | Err — fail closed |
| Duplicate account-active insert | DB constraint → `AccountHasActiveController` |

## J. Tests

87 total (was 72): `sqlite_store` 11, `sqlite_concurrency` 4, `log_capture` 1
(isolated; see Findings), P1/P2 suites unchanged. All passing, 5 consecutive
full-suite runs, ~1.5s total, no hangs.

## K. Quality gates

| Gate | Result |
|---|---|
| `cargo fmt --check` | clean |
| `cargo clippy --all-targets --all-features -- -D warnings` | 0 warnings |
| `cargo test --all-targets --all-features` | 87/87, ×5 runs stable |
| Sinter regression | 484/484 tests, 20 suites |
| Sinter HEAD/status | `66ca3d7`; ` D opencode.json` untouched |

## L. Security invariant mapping

| Inv | Status | Evidence |
|---|---|---|
| I-1 | enforced | no SSH/target fields anywhere; identity DB schema contains no such columns |
| I-2 | enforced | work envelope unchanged; no exec/argv/env/path fields |
| I-3 | enforced | ownership check + authenticated principal; durable binding |
| I-4 | enforced | identity derives only from verifier lookup; durable across restart |
| I-5 | enforced | terminal states; revocation durable across restart |
| I-6 | enforced | duplicate-response protection unchanged |
| I-7 | enforced | plaintext absent from db bytes/rows, audit rows, errors, logs (tests §G) |
| I-8 | deferred → P5 | no HTTP layer yet |
| I-9 | enforced | still no listener/dialer; store is a local file |
| I-10 | partially → P5/P6 | edge unchanged |
| I-11 | enforced | unchanged |

## M. Installation boundary

- **Normal Sinter user:** no change. Sinter tree untouched; zero sqlite in
  its dependency graph.
- **Public Plugin / bridge user:** no change — no SQLite dependency on the
  customer side; bridge remains unimplemented (P4).
- **Central Gateway operator:** the Gateway owns an embedded-SQLite identity
  database file. It is security-sensitive (verifiers, binding/audit metadata)
  even though it contains no plaintext credentials: protect with
  owner-only file/directory permissions (e.g. 0600/0700), exclude from
  source control (`.gitignore` covers `*.db*`), and treat backups as
  sensitive. SQLite is a central-Gateway implementation detail — it is NOT a
  Sinter or sinter-bridge runtime dependency.

## N. Files changed

Created: `src/sqlite_store.rs`, `tests/sqlite_store.rs`,
`tests/sqlite_concurrency.rs`, `tests/log_capture.rs`, `.gitignore`,
this report.

Modified: `src/store.rs` (record fields `rotated_unix_ms`/`revoked_unix_ms`,
`now` params on mutating methods, `consumed: Option<u64>`, `purge_spent_tokens`),
`src/auth.rs` (`bind`, `now` args, record fields), `src/lib.rs` (exports),
`Cargo.toml` (+`rusqlite 0.40.2` bundled), `tests/secrets.rs` (log test moved
to isolated binary).

Sinter / prototype / RFC trees: untouched.

## O. Findings

- **LOW**: tracing callsite interest is process-global — a secret-capture
  test sharing a binary with parallel tests that hit the same `info!`
  callsites under no subscriber could intermittently see an empty capture
  (false-positive flake, never a secret leak). Fixed by isolation
  (`tests/log_capture.rs`); documented for future test authors.
- **LOW**: retention — RFC says controller rows persist until revoked+90d and
  audit 30–90d; no deletion implemented (correctness first, nothing is old
  enough). Spent-token 24h purge IS implemented (`purge_spent_tokens`).
  Unresolved cleanup scheduling → P7 ops hardening.
- **LOW**: rotated-away verifiers are deleted at swap time (safely deletable;
  matches P2 memory semantics). If future audit needs verifier history, add a
  credential-history table then — deliberately not speculative.
- **INFO**: restart requires `bind()` to re-establish the work-core binding —
  intended, and it is the P4 reconnect path.
- No BLOCKER / HIGH / MEDIUM findings.

## P. P4 readiness

P4 may assume:

- `SqliteStore` satisfies the full `IdentityStore` atomicity contract; the
  same contract is exercised by both backends via parity + race tests.
- `/v1/poll` + `/v1/respond` handlers: `Authorization: Bearer ctrlk_…` →
  `auth.authenticate` → `auth.bind(&core, &principal)` →
  `core.poll`/`core.respond`. Identity is durable; binding is the reconnect
  step; work remains memory-only by design.
- Revocation is durable — a revoked controller stays dead across restarts.
- DB file lifecycle: `SqliteStore::open(path)` is fail-closed on
  corrupt/foreign/wrong-version files; fresh environments self-initialize.
- Audit rows already record identity lifecycle events; P4 may append
  request-metadata events (no payloads) to the same table or extend the
  schema (bump `schema_version`).

SINTER GATEWAY P3: PASS
