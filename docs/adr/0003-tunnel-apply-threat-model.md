# ADR 0003: Changes proposed through the Secure MCP Tunnel (threat model and staged design)

- Status: **Proposed — design only.** Owner decision D-5 (2026-11-19): Sinter
  v1.15.0 contains this design and no implementation. No write-capable MCP
  tool is added, `sinter mcp` keeps its eight read-only tools, and nothing in
  this record is available.
- Date: 2026-11-19
- Baseline: Sinter at v1.14.1 (`sinter mcp`, `sinter serve`, ADR 0002 r6).
- Related: ADR 0002 (§12 keeps apply over MCP out of scope; this record does
  not change that for v1.15.0), DESIGN §43 (approvals, plan digest, ledger),
  GOALS §5.

## 1. Question

Can ChatGPT, connected through the OpenAI Secure MCP Tunnel, take part in
changing a host, and how, without letting a conversation run commands as root?

## 2. Where the read-only boundary is enforced today

Read from the code at v1.14.1:

1. Tool registry: `tools/list` and `tools/call` accept only the eight names of
   `src/mcp.rs` (`tool_names`); any other name is refused (-32602).
2. Engine mode: every engine `sinter mcp` builds is `Mode::Plan`; the file
   contains no `Mode::Apply`.
3. Runtime permit: `allow_mutation` is true only in `Mode::Apply`
   (`src/engine.rs`); every mutating operation needs a `MutationPermit`, which
   `TargetFs::mutation_permit` refuses otherwise (`src/targetfs.rs`). This is a
   runtime gate, not a type-level guarantee.
4. `run_audit` refuses an engine that could obtain a permit (`src/audit.rs`).
5. Inputs: plugins, `include`, `source`, and map-valued secrets are refused
   before loading; targets are names from the administrator's targets file;
   secrets are never decrypted.

Documentation that does not match the code (to be corrected in v1.15.0, P6):
the `src/mcp.rs` header calls the server "structurally" read-only, but the last
line of defence is the runtime gate; ADR 0002 §16 says no test covers the
`password_verifier` refusal, but one exists; the MCP reference says unexpected
parameters are rejected, which holds only for the two host tools; DESIGN §41
still says "not released" and cites a guide that is not in the docs site; and
no test asserts that `sinter_plan_host` and `sinter_audit_host` send no
mutating command (the fake executor's log makes this testable).

*Status (2026-11-20, v1.15.0 development, P6):* these points are corrected:
the `src/mcp.rs` header, ADR 0002 (later notes in §11 and §16), the MCP
reference (a per-tool argument table), DESIGN §41 (released in v1.14.0), the
new guide `guides/chatgpt-tunnel`, and the boundary tests in
`src/mcp_boundary_tests.rs`, which check the commands the host tools send.

## 3. Assets and trust boundaries

Assets: the managed hosts (root through `sudo -n -u root`), the controller's
SSH keys and secrets, the recipes and variables, the tunnel API key, the
approval records and the ledger (DESIGN §43.4).

Boundaries: ChatGPT conversation → OpenAI → tunnel client (controller) →
`sinter` process (controller) → SSH → target. Everything on the left of the
`sinter` process is untrusted input. The conversation can contain text an
attacker placed in a web page, a document or a recipe it was shown.

## 4. Threats

| # | Threat | Today (read-only) | If a write path existed naively |
|---|---|---|---|
| T1 | Prompt injection makes ChatGPT request a harmful change | Only observation and plans | Root changes on hosts |
| T2 | A recipe with a `command` resource or `command` handler | Never run over MCP (plan does not run commands) | Arbitrary root command execution: the per-run `--sudo` model has no per-resource privilege limit |
| T3 | `file` content into sensitive paths (`/etc/sudoers.d`, `authorized_keys`, `/etc/ssh`) | Plan only | Persistent access for an attacker |
| T4 | Stolen tunnel key or ChatGPT account | Read access to configured targets | Write access |
| T5 | Replay of an earlier approval, or approval of different content | — | Unreviewed change |
| T6 | Caller identity unknown (stdio child receives no identity) | Accepted for reads (ADR 0002) | No basis for authorization |
| T7 | Secret leakage through responses, logs or approval files | Secrets refused | Wider exposure |
| T8 | Tunnel drop or process kill during a change | — | Partial changes reported as done |
| T9 | Management connection cut by the change itself | — | Unreachable host (DESIGN §43) |

## 5. Decision

### 5.1 Stage W1 — proposals only (first target; not in v1.15.0)

- ChatGPT can only **propose**. A separate proposal process (not `sinter mcp`,
  which keeps its eight tools; started with its own configuration and targets
  file, disabled by default) accepts a proposed recipe for a named target,
  refuses it unless it passes the proposal policy (§5.3), plans it read-only,
  and stores an approval request (DESIGN §43.4) in a queue on the controller.
- The Owner reviews the request **on the controller's terminal**: the full
  normalized recipe and the full plan, not a summary written by ChatGPT, and
  approves with `sinter approve`. A message in the conversation is never an
  approval.
- The Owner applies on the controller with `sinter apply --approval <id>`.
  Nothing reached through the tunnel starts an apply.

W1 adds no new privilege to the tunnel path: a proposal cannot change a host
until a person at the controller approves and runs it.

### 5.2 Stage W2 — execution of approved requests (future; separate decision)

Execution of an approved, digest-bound, unexpired, single-use request by a
write process is not decided. It requires, before any implementation: caller
identity (T6) or an equivalent binding of the request to the Owner, a
separate SSH identity and targets file for the write process, the proposal
policy enforced again at execution, the guarded procedures of DESIGN §43.6
for risky resources, and a new independent security review.

### 5.3 Proposal policy (least privilege)

Applied when a proposal is accepted and again when it is applied:

- Resource types: an allow-list per target. Refused always: `command`
  resources, `command` handlers, `plugin` handlers and plugin mutate
  operations, `include`, `source`, secret references, `postgresql_role`.
- Paths: an allow-list per target; refused always: `/etc/sudoers*`,
  `/etc/ssh/**`, `**/.ssh/**`, `/etc/passwd`, `/etc/shadow`, `/etc/group`,
  `/etc/gshadow`, systemd units that run as root unless allow-listed, and any
  path outside the allow-list.
- Targets: only names in the proposal process's own targets file; the
  request cannot name connection details, `sudo` or a user.
- Connection-risk resources (DESIGN §43) follow §43 unchanged; an approval
  never authorizes a change whose effect on the management path is unknown.

### 5.4 Approval, expiry and replay

DESIGN §43.4 applies unchanged: the approval names the plan digest, host and
resources; expires (default 30 minutes); is marked used before contact; apply
re-plans and stops before any mutation if the digest differs; the ledger is
append-only and hash-chained (tamper-evident only).

### 5.5 Audit log

The ledger records proposal, request, approval, use, mismatch and outcome,
with the proposal process's record of which tunnel session delivered the
proposal (as far as the tunnel client exposes it). It contains no secret
values. Retention and off-host copies are an operator decision.

### 5.6 Failure behaviour

- Tunnel drop: in W1 the tunnel takes no part in applying; a drop loses at
  most an unsubmitted proposal.
- Interrupted apply: the approval is already used; the run is recorded as
  interrupted, state unknown; a new plan and approval are required. No
  automatic retry.
- Risky resources: DESIGN §43.6; recovery is never described as guaranteed.

### 5.7 Privilege escalation limits

The tunnel path can neither choose `--sudo` nor a user nor a target address;
those come from administrator files. A conversation cannot widen the
proposal policy. No design in this record lets an instruction from ChatGPT
run as root without the Owner's approval of the exact content on the
controller.

## 6. Why implementation is held

Caller identity is unresolved (T6); the approval primitive (DESIGN §43.4) does
not exist yet in code; Sinter's privilege model cannot limit a `command`
resource (T2), so only the proposal policy keeps it out; and the guarded
procedures of §43 are themselves new. W1 may be implemented after the approval
primitive of DESIGN §43.4 is implemented and released, this ADR passes an
independent review, and the Owner approves W1. A local approval does not resist a malicious
process of the same local account (it can read the controller key and write
records, and a pseudo-terminal satisfies the terminal check). W1 therefore
also requires that approval records be created by a different local account
than the proposal process, or be otherwise tamper-resistant (for example
signed with a key the proposal process cannot read).

## 7. Consequences

- v1.15.0: documentation and the read-only boundary tests only (P6).
- The approval primitive built for connection-risk control in v1.15.0 is the
  same one W1 will use; nothing is built twice.

## 8. Status and open requirements recorded 2026-11-26 (no decision)

Recorded for the next tunnel extension; nothing here is decided, designed for implementation or approved. W1 and W2 stay as in §5, W2's approval method and privilege boundary stay open (§5.2), the read-only MCP boundary (`sinter mcp`, `sinter serve`) is unchanged, and no message in a conversation is ever an approval.

8.1 What changed since this record was written. The approval primitive of DESIGN §43.4 (`plan --approval-request`, `sinter approve`, `apply --approval`, the append-only ledger) is implemented and released in v1.15.0. Of the conditions in §6 for W1 this one is met; the others are not: an independent review of this ADR, approval records created by another local account or otherwise tamper-resistant, and the Owner's approval of W1.

8.2 Requirements a later design must answer (W1 where it applies, otherwise W2):

| Topic | Already decided here | Open |
|---|---|---|
| Change proposals through the tunnel | W1, §5.1 and the proposal policy §5.3 | the proposal process's configuration format and how it is started and stopped |
| Remote execution of an approved apply | W2 is a separate decision, §5.2 | everything: which process executes, with which identity and targets file |
| Binding approval to recipe, target host and plan digest | §5.4 (DESIGN §43.4): digest, host and resources; re-plan before mutation | how a bundle or several hosts are bound (one approval per host and recipe, or a set) |
| Expiry and replay | §5.4: expiry, single use, marked used before contact | — |
| Caller identification and permissions | T6 unresolved; no per-user authorization in the tunnel (ADR 0002 §8.4) | the binding of a request to the Owner (W2 precondition) |
| Progress of an apply | — | a read-only way for the tunnel side to see that an approved run started, is running or ended, without a channel back into it |
| Retrieving results | §5.5 ledger records the outcome | which part of the run report may be returned (no secrets, redaction as for plan) |
| Execution continuing when the tunnel drops | W1: the tunnel takes no part in applying (§5.6) | W2: an apply must never depend on the tunnel staying up; how it is detached and supervised |
| State after reconnecting | — | how a reconnected session finds a run by approval id, read-only |
| No double execution | §5.4 single use; §5.6 no automatic retry | the same guarantee across a restarted write process |
| Operation and approval history | §5.5 ledger, hash-chained, no secret values | retention and off-host copies stay an operator decision |
| Resource Plugins | §5.3 refuses plugin mutate operations in proposals | whether an allow-listed plugin type may ever be proposed |
| Resources that can cut the connection | §5.3 and DESIGN §43 unchanged; §43.6 guarded procedures | how a remote execution reports a change whose result it cannot observe after the connection is lost |
| Secrets | proposals refuse secret references (§5.3); the ledger has no secret values | — |

8.3 Dependencies before any of it: §6 unchanged, plus a decision on the MCP protocol revision the tunnel path uses (Sinter answers `2025-03-26` today) and the result of the real-host tunnel verification still open in ADR 0002 §14.
