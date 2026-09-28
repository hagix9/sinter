# Sinter Multi-Host Foundation — focused re-audit R1

## Purpose and independence

This is an independent, focused re-audit of remediation R1 for prior findings
F-01 through F-04. I checked the working-tree source, tests, DESIGN/GOALS/CLI
documentation, and `SINTER_MULTIHOST_FOUNDATION_REVIEW.md`; the implementation
report was treated as a claim to verify. No implementation, test, product
documentation, example, or existing review artifact was changed. This file is
the only repository change made by this audit.

## Audit identity and scope

- Repository: `/Volumes/VGX1000 SSD/Codex/Projects/Sinter`
- Branch: `main`
- HEAD: `531cb24d11c2e38cc4f7bdb93a4ab7d1a04a09fa`
- `origin/main`: `531cb24d11c2e38cc4f7bdb93a4ab7d1a04a09fa`
- Merge-base: `531cb24d11c2e38cc4f7bdb93a4ab7d1a04a09fa`
- Implementation is uncommitted; `origin/main..HEAD` is empty and is not the
  audit range. I audited all pre-existing staged/unstaged and untracked
  implementation changes.
- At audit start: nothing staged; 24 tracked files modified; untracked:
  `SINTER_MULTIHOST_FOUNDATION_REVIEW.md`, `examples/multihost/`,
  `src/{backup,bundle,inventory,sshconfig,style}.rs`, and
  `tests/{backup,cli_multihost,multihost_lab,ssh_keys}.rs`.
- Initial `git diff --stat`: 24 files changed, 2,606 insertions, 269
  deletions. This excludes untracked files. `git diff --check` was clean.
- Runtime: macOS 25.6 arm64; rustc 1.98.1; cargo 1.98.1; Node 20.19.4.

The focused code paths reviewed were `src/main.rs::run_executions`,
`stops_remaining`, and `backup_record`; `src/error.rs::SinterError.backup`,
`src/backup.rs::fail`, `src/output.rs::backup_json`; related tests in
`tests/cli_multihost.rs`, `tests/multihost_lab.rs`,
`tests/backup.rs`, and `tests/json_contract.rs`; plus DESIGN §19.4, GOALS,
the English/Japanese CLI references, and review artifact Remediation R1.

## F-01 — CLOSED

Review artifact §2 now distinguishes the pre-implementation state from the
verified review-time state. It explicitly says the historical clean tree is
not provable from the repository and labels the session-transcript claim
unverified. R1.0 separately records the verified state at remediation start;
R1.1 preserves the original finding and explains the correction. R1.9 records
the later status. Those claims agree with the state observed at this audit's
start: same HEAD as `origin/main`, no staged files, uncommitted changes, and
untracked implementation files. Historical state is not presented as a Git
fact. **CLOSED.**

## F-02 — CLOSED

`src/main.rs::stops_remaining` returns true exactly for `Phase::Apply` with a
nonzero code. `run_executions` records the first failing execution, does not
call `execute` for later entries, records those entries as `not_run` with a
null exit code and reason, and computes the final code from executions that
ran. `tests::apply_stops_on_every_non_zero_exit_code` checks codes 2–7,
including code 4; `read_only_phases_never_stop` and
`aggregate_exit_code_is_the_most_severe` cover adjacent behavior. The CLI
test covers connection failure (exit 3); Linux lab evidence reports backup
failure and apply failure (exit 5) with later executions not run. An apply
engine does not currently produce a plan-phase exit 4, so code 4 is tested at
the stop-predicate unit boundary rather than by an end-to-end apply failure.

DESIGN §19.4, both CLI references, README, CHANGELOG, and review artifact §11
now describe any nonzero apply execution as fail-fast, explicitly naming
validation 2, connection 3, plan 4, backup/apply 5, and indeterminate 6.
They also document `not_run` and the aggregate exit-code rule. Tests were
added; no prior fail-closed assertions were weakened. **CLOSED.**

## F-03 — CLOSED

The aggregate JSON now gets an execution-level `backup` field from that
execution's own outcome/error. `backup_record` returns `null` for no declared
backup or audit; reports `planned`/`completed`; preserves structured partial
backup failures; reports pre-backup errors as `not_started`; and reports
skipped executions as `not_run`. `SinterError.backup` carries only the
structured `BackupReport`; the report and `backup_json` contain paths,
statuses, kinds, and destinations, never file bytes. The aggregate maps each
execution's recipe, target, result/error, and backup together without
cross-execution lookup. Bundle backup run IDs include recipe position and
label.

Independent test/source checks:

- `aggregate_backup_record_follows_recipe_identity` pairs backup/no-backup
  recipe outcomes with their expected host and checks each recipe's own
  declared path.
- `aggregate_backup_record_per_phase` checks planned, connection-failed
  `not_started`, subsequent `not_run`, audit null, and no ANSI in JSON via
  the JSON helper.
- Linux lab tests recorded in R1 test multiple same-machine host identities,
  bundle recipes with separate directories, and partial backup failure
  (`backed_up`, `failed`, `not_run`) while checking managed content is
  unchanged and canary content is absent from JSON.
- `single_host_json_has_no_execution_level_backup_field` plus the unchanged
  `tests/json_contract.rs` suite check the single-run contract.

The existing `result.backup` field is retained; aggregate `executions[].backup`
is additive. Structured aggregate JSON is not colored. **CLOSED**, with
different-physical-host backup separation still unverified as noted below.

## F-04 — CLOSED WITH LIMITATION

The review artifact R1.4 supplies a concrete Ubuntu 24.04.4 x86_64 Lima
environment, Linux kernel/tool versions, commands, opt-in environment,
source checksum claim, and per-binary ran/PASS/FAIL/SKIP/ignored/filtered
counts. It reports `tests/backup.rs`: 14 ran, 14 PASS, 0 FAIL, 0 SKIP;
`tests/multihost_lab.rs`: 7 ran, 7 PASS, 0 FAIL, 0 SKIP. The named tests are
present in the current source (8 Linux backup filesystem cases; 7 Linux
multi-host lab cases). Its total is internally consistent: 797 ran = 772
PASS + 25 SKIP, 0 FAIL; all 23 `tests/ssh.rs` are explicitly SKIP, not PASS.
Two additional remote SSH cases are separately marked SKIP/UNVERIFIED.

I could not independently reproduce the Linux run: this audit host is macOS
arm64, the cited `r3-full.log` and `r3-nocap.log` are not present in the
repository or accessible temporary locations, and both Linux-only test
targets compile to zero tests here. The evidence is specific and internally
consistent with current sources, but the logs are implementation-session
evidence rather than independently available raw output. Thus the finding is
closed with that provenance limitation, not represented as my own Linux
PASS. Two distinct physical hosts both completing backup remain UNVERIFIED;
this alone is not a release blocker under the request.

## Critical regression spot-check

| Boundary | Result and evidence |
|---|---|
| Existing single-host recipe + explicit `--host`, without `targets` | PASS — `single_host_keeps_the_single_document_contract`; legacy single-recipe execution path remains separate when inventory is absent. |
| Inventory + no recipe targets | PASS — `inventory_without_recipe_targets_fails_closed`; resolution happens before execution. |
| Untargeted inventory host | PASS in CLI fake-SSH check `skipped_hosts_are_never_resolved`; Linux real-sshd evidence `only_selected_hosts_are_contacted_and_backed_up` is reported 7/7 lab run, but not re-run here. |
| Host/group overlap | PASS — `overlapping_selection_executes_each_host_once`. |
| Backup failure before mutation | PASS in Linux evidence (`backup_failure_prevents_every_change`, lab failure test); source calls backup at the start of `Engine::run` before iterating resources. Linux execution is not independently reproduced here. |
| Validate isolation | PASS — `validate_ignores_execution_options_without_reading_anything`; nonexistent inventory/key paths and fake `ssh` log prove no inventory resolution or ssh invocation. |
| `--host` + inventory | PASS — `host_and_inventory_conflict`. |
| JSON/evidence ANSI and backup secret content | PASS — JSON assertions and canary checks; the Linux backup canary tests are reported in R1 evidence but not rerun on this host. |
| Existing MCP contract | PASS — `tests/mcp.rs` 31 tests passed in this audit. |

## Test results in this audit

**PASS**

- `cargo test --bin sinter`: 3 passed, 0 failed (includes nonzero code 4
  fail-fast predicate test).
- `cargo test --test cli_multihost`: 38 passed, 0 failed.
- `cargo test --test json_contract`: 13 passed, 0 failed.
- `cargo test --test mcp`: 31 passed, 0 failed.
- Initial Git `diff --check`: clean.

**SKIP / zero tests in this audit environment**

- `tests/multihost_lab.rs`: Linux-only, 0 tests on macOS.
- Filesystem integration portion of `tests/backup.rs`: Linux-only; not
  re-executed here. Prior focused audit on macOS had only six portable backup
  tests, but that is not evidence for the R1 Linux integration run.
- Existing `tests/ssh.rs` remote reference suite: no
  `SINTER_TEST_SSH_HOST` reference host configured; do not count as PASS.

**UNVERIFIED**

- Linux R1 run cannot be independently reproduced here; use the bounded
  evidence statement under F-04.
- Two distinct physical machines completing backups in one invocation.
- docs-site build: Node is 20.19.4, below the repository's `>=22.12.0`
  requirement. Markdown source was reviewed; no obvious broken new paths or
  malformed table/fence syntax was found. No environment upgrade performed.

## SSH historical correction

The review artifact §8 and R1.5 state that pre-change Sinter was **not**
Ed25519-only: the existing `ssh2`/libssh2 backend accepted RSA, ECDSA, and
Ed25519 key files, while the principal improvements here are OpenSSH config
inheritance, `IdentityFile`, agent use, `HostName`, `User`, and `Port`. It
distinguishes code inspection at the old HEAD from session-only measurements.
This does not overclaim that the new code introduced RSA/ECDSA support.
**Consistent.**

## DESIGN §36 / GOALS

The owner-approved direction is treated as intentional. Revised DESIGN §19.2–
19.4 describes static inventory membership separately from recipe target
authorization, rejects inventory execution without explicit targets, and
defines flat groups/bundles/fail-fast semantics. GOALS removes static
inventory and serial multi-target execution from the deferred list while
leaving dynamic inventory, host/group variables, nested groups, patterns,
parallelism, and orchestration deferred. This agrees with the implementation
and does not reintroduce implicit all-host selection or Ansible-style
inheritance.

## New findings

No new CRITICAL, HIGH, MEDIUM, or LOW findings found in the focused scope.

## Remaining limitations

- Linux integration results are detailed in the existing review artifact but
  raw logs were unavailable for independent re-execution in this environment.
- Remote reference-host SSH suite remains SKIP/UNVERIFIED.
- End-to-end backups on two distinct physical hosts remain UNVERIFIED.
- docs-site check remains UNVERIFIED due to Node version.

## Final verdict

**GO WITH NOTES.** F-01, F-02, and F-03 are CLOSED; F-04 is CLOSED WITH
LIMITATION. No focused regression or blocking finding was found. Commit
readiness is assessed as **READY WITH NOTES**, retaining the explicit
UNVERIFIED items above.

## Final Git status

Before this audit artifact was created, the implementation state remained
the same as at audit start: branch `main`, HEAD = `origin/main` =
`531cb24d11c2e38cc4f7bdb93a4ab7d1a04a09fa`, nothing staged, 24 tracked
modified files and the same untracked implementation files listed in
Audit identity. After creating this file, the only expected additional Git
status item is this new untracked audit artifact. No other repository state
was changed by the audit.
