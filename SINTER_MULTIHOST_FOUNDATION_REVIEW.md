# Sinter multi-host foundation — review report

Entry point for re-verifying this change. It is not the product
specification: the normative text lives in `DESIGN.md` (§4.1, §4.12, §19,
§19.1–19.4, §33, §36) and `GOALS.md` §13, and user documentation in
`docs-site/src/content/docs/{en,ja}/reference/cli.md`, the troubleshooting
pages, `README.md` / `README.ja.md`, `CHANGELOG.md` (Unreleased) and
`examples/multihost/`.

## 1. Purpose and scope

Add the smallest coherent skeleton for managing several hosts safely, without
turning Sinter into Ansible:

Inventory → host groups → recipe `targets` → recipe / bundle → target
resolution → plan → backup → apply → audit

plus: colored terminal status, `validate` as a purely static check, SSH that
follows the operator's OpenSSH setup, and pre-apply backups.

Guiding rule: **multi-host execution fails closed** — a host being in the
inventory never makes it a target.

Out of scope (deliberately not implemented): host/group variables, nested
groups, patterns, an implicit `all` group, dynamic inventory, parallel runs,
cross-host orchestration, rollback/restore, backup retention, ProxyJump,
chained phases in one invocation.

## 2. Starting and final state

| | |
|---|---|
| Repository | `/Volumes/VGX1000 SSD/Codex/Projects/Sinter` |
| Starting branch / HEAD | `main` @ `531cb24d11c2e38cc4f7bdb93a4ab7d1a04a09fa` ("feat: prepare Sinter skill submission package") |
| Upstream | `origin/main`, 0 ahead / 0 behind at start |
| Starting tree (before implementation) | **Not provable from the repository.** The implementing session's first command (`git status --porcelain=v1 -uall`, `git diff --cached --stat`) printed nothing, i.e. it observed a clean tree — but that evidence exists only in the session transcript, and the uncommitted working tree cannot demonstrate its own starting point. Treat "clean at start" as an unverified claim (corrected in Remediation R1, F-01). |
| State at review time (verified by the independent audit and again at R1 start) | HEAD = `origin/main` = `531cb24d11c2e38cc4f7bdb93a4ab7d1a04a09fa`; implementation **uncommitted**; nothing staged; tracked modifications plus untracked implementation files in the working tree |
| Final branch / HEAD | `main` @ `531cb24` — **not committed** (see §20) |
| Final tree | see Remediation R1 (final diffstat and git status) |

## 3. Architecture summary (what was found, what was added)

Existing (unchanged in structure):

- `src/main.rs` — clap derive CLI; one subcommand per phase; each phase
  built `RunOptions` and ran one `Engine` against one target.
- `src/model.rs` / `src/document.rs` — recipe loading (YAML/TOML → `Value` →
  `Document` → include expansion → frozen `Model`); strict unknown-field
  rejection (`only_fields`).
- `src/engine.rs` — one invocation = one target; `Engine::new` connects and
  gathers facts, `Engine::run` executes resources fail-fast.
- `src/executor.rs` — `LocalExecutor`, `SshExecutor` (libssh2 via `ssh2`),
  `FakeExecutor` (tests).
- `src/targetfs.rs` — every target filesystem operation, the §23 trust check,
  and the `MutationPermit` gate that makes plan/audit mutation-free.
- `src/output.rs` — text/JSON renderers (the only output abstraction).
- `src/targets.rs` — MCP-only named target profiles (`sinter mcp
  --targets-file`); left as is.

Added:

| Module | Role | Key symbols |
|---|---|---|
| `src/style.rs` | terminal color decision + painting | `color_enabled`, `stdout_color`, `stderr_color`, `tone_for`, `paint`, `status`, `leading_token` |
| `src/sshconfig.rs` | OpenSSH config inheritance via `ssh -G`; precedence | `query_openssh`, `parse_ssh_g`, `resolve`, `TargetRequest`, `OpenSshView`, `validate_host_arg` |
| `src/inventory.rs` | inventory + groups; fail-closed resolution | `load_inventory`, `resolve`, `Inventory`, `InventoryHost`, `Resolution`, `HostMatch` |
| `src/bundle.rs` | recipe bundles | `load_source`, `Source`, `Bundle`, `RecipeUnit` |
| `src/backup.rs` | pre-apply backup | `perform`, `planned`, `store_root`, `new_run_id`, `check_overlap`, `BackupReport` |

Changed: `src/main.rs` (shared `ExecOpts`, `run_phase`, `inventory_plan`,
`run_executions`), `src/document.rs` (`TargetSelector`, `parse_targets`,
`parse_backup`, `parse_file_value`, `valid_name`), `src/model.rs`
(`Model.targets`, `Model.backups`), `src/ir.rs` (`TOP_LEVEL_FIELDS`,
`BACKUP_FIELDS`, `TARGET_FIELDS`), `src/engine.rs` (`SshSpec` options,
`AgentSource`, backup step in `Engine::run`, `with_backup_run_id`,
`RunReport.backup`), `src/executor.rs` (host-key verification and
authentication, see §8), `src/targetfs.rs` (`backup_copy`, `mkdir_p`,
`b64_decode`), `src/output.rs` (`RenderOptions.color`, backup rendering,
`run_report_json`, `audit_report_json`).

Execution flow now:

```
run_phase
 ├─ --host + --inventory → exit 2
 ├─ load_source (recipe | bundle; everything validated)
 ├─ --inventory → inventory_plan: load_inventory → resolve() per recipe
 │                 → resolve selected hosts only (ssh -G) → duplicate check
 │                 → executions (recipe-major, hosts by name)
 ├─ recipe + (--host | local) → execute() → single document (unchanged)
 └─ bundle + (--host | local) → one execution per recipe on that target
run_executions: print resolution → execute() each → fail-fast on apply
                → summary / JSON envelope → most severe exit code
execute: Engine::new → with_backup_run_id → run (backup step first) | run_audit
```

## 4. Inventory schema

```yaml
hosts:                       # required, non-empty
  web01:
    address: 10.0.0.11       # optional; default = the host name (may be an ~/.ssh/config alias)
    port: 22                 # optional
    user: ubuntu             # optional
    known_hosts: ~/.ssh/kh   # optional, ~ expanded
    identity_files: [~/.ssh/id_lab]   # optional, ~ expanded
  cache01: {}
groups:                      # optional
  web:
    hosts: [web01]           # non-empty; defined hosts only; no repeats
```

TOML is equivalent (`[hosts.web01]`, `[groups.web] hosts = [...]`); the
format is chosen by the `.yaml`/`.yml` extension. Names: `[A-Za-z0-9._-]`,
start alphanumeric, ≤ 64 chars. Every problem is exit 2 before any
connection: missing/unreadable file, parse error, unknown field (e.g.
`host:`/`sudo:`/`vars:`), duplicate key, no hosts, bad name, a group with an
undefined or repeated member, an empty group, an address starting with `-`
or containing whitespace/`@`.

Why not the MCP `targets.<name>` schema or the suggested `hosts.x.address`
as-is: the MCP file is administrator policy for a different surface (it
requires `user`/`known_hosts` and carries `sudo`), and naming the inventory
top level `targets` would collide with the recipe's `targets` — exactly the
confusion the fail-closed rule exists to prevent. The suggested
`hosts:`/`address:`/`groups:<name>:hosts:` shape was adopted. There is no
`sudo` per host: privilege is an invocation-level `--sudo` (DESIGN §21).

## 5. Host groups, recipe targets, fail-closed semantics

Recipe (entry file only; `targets` in an included file is exit 2):

```yaml
targets:
  groups: [web]
  hosts: [special01]     # union
```

At least one name; names unique per list; static only.

Target resolution — `sinter::inventory::resolve(inv, sel, recipe)`:

1. `sel` absent → **error** ("declares no targets … never selects all
   inventory hosts implicitly").
2. any host or group name not defined in the inventory → **error**.
3. for each inventory host (name order): reasons = `host:<n>` if listed,
   plus `group:<g>` for each listed group containing it; selected iff reasons
   non-empty.
4. nothing selected → **error** (unreachable with a valid inventory, kept as
   defense in depth).

Then (`main.rs::inventory_plan`) only selected hosts are resolved to
connection parameters (`ssh -G` included); unselected hosts are never
resolved or contacted. Two selected hosts resolving to the same
address:port → exit 2.

| Invocation | Behavior |
|---|---|
| recipe, no `--host` | localhost (unchanged) |
| recipe + `--host` | that host (unchanged; `targets` ignored) |
| recipe + `--inventory`, with `targets` | only selected hosts |
| recipe + `--inventory`, no `targets` | **exit 2, nothing runs** |
| `--host` + `--inventory` | exit 2 |
| bundle + `--inventory` | each recipe on its own selection; any untargeted recipe → exit 2 before anything runs |
| bundle + `--host` / local | every recipe, in order, on that one target |

Text output (actual):

```text
== target resolution ==
recipe nginx (nginx.yaml)
  db01   SKIP   no matching target
  web01  MATCH  group:web
  web02  MATCH  group:web
  selected 2, excluded 1
executions: 2 (1 recipe(s), 3 host(s))
```

## 6. Recipe bundles

```yaml
version: 1
name: web-stack      # optional, default file stem
recipes: [common.yaml, nginx.yaml, app.yaml]   # relative to the bundle
```

- Detection: top-level `recipes` key (never valid in a recipe).
- Validation (all before anything runs): `version: 1`, only
  `version`/`name`/`recipes`, non-empty list of strings, each path exists and
  loads as a valid recipe, no duplicate (canonical path), no nesting (a
  listed bundle — including the bundle itself — is an error, so cycles cannot
  exist).
- Execution order: recipe-major in list order; within a recipe, hosts in
  name order. Example `examples/multihost/web-stack.yaml` → 4 + 2 + 1 = 7
  executions, not 3 × 4.
- Evidence: every execution carries `recipe` and `target` identity; the JSON
  envelope carries `bundle.name`/`bundle.path`.

## 7. validate semantics

- Input: a recipe or a bundle. Checks YAML/TOML, schema, recipe semantics,
  includes, `targets` syntax, `backup` syntax, bundle references.
- Every target option (`--host`, `--inventory`/`--hosts`, `--port`, `--user`,
  `--known-hosts`, `--identity`, `--no-ssh-config`, `--sudo`, `--verbose`) is
  accepted through the same flattened `ExecOpts` as plan/apply/audit and
  ignored: no inventory, key or known_hosts file is read, `ssh` is not run,
  nothing connects. `--hosts /does/not/exist.yaml` succeeds.
- Unknown or misspelled options still fail (clap, exit 2).
- clap still type-checks values of accepted options (`--port abc` fails).
- Single-recipe JSON document unchanged; for a bundle it adds `bundle` and
  `recipes` (totals in `resources`/`handlers`/`vars`).

## 8. SSH: investigation, root cause, support matrix

Backend: `ssh2` 0.9.6 → `libssh2-sys` 0.3.3 bundling libssh2 1.11.1_DEV with
the OpenSSL backend (macOS build links Homebrew OpenSSL 3; release builds use
the builder's OpenSSL). Sinter does not parse keys itself.

**Was Sinter Ed25519-only?** No — and nothing in this change claims it was.
The `ssh2`/libssh2 backend already accepted RSA and ECDSA keys before this
change (independently confirmed by the audit). The value of this change is
mainly that the operator's OpenSSH environment — `~/.ssh/config` (Host,
HostName, User, Port), `IdentityFile`, ssh-agent — is now used naturally.

Provenance of the historical observations below: items 1–3 and 5–6 follow
from reading the pre-change source at `531cb24` (`src/executor.rs`
`SshExecutor::connect`, `verify_host_key`, `src/main.rs` `build_opts`) and can
be re-checked there. The runtime measurements (key matrix; item 4's false
"mismatch"; item 5's "not present") were made in the implementing session
with a binary built from `531cb24` against a throwaway OpenSSH 10.3 `sshd` on
macOS; they are recorded in the session only and are **not** reproduced by
the committed tests, which exercise the post-change code (`tests/ssh_keys.rs`).
In that measurement, with `--identity`, the pre-change code authenticated with
Ed25519, ECDSA P-256/P-384 and RSA (OpenSSH and PEM formats). The observed
friction had these causes:

1. `~/.ssh/config` was ignored entirely — HostName, User, Port, IdentityFile,
   IdentityAgent, IdentitiesOnly. A key referenced only by `IdentityFile` was
   never tried; aliases did not resolve.
2. Without `--identity`, only `~/.ssh/id_ed25519` and `~/.ssh/id_rsa` were
   tried; `~/.ssh/id_ecdsa` never was.
3. Private keys were loaded with `userauth_pubkey_file(user, None, key,
   None)`: no passphrase, so every encrypted key failed silently, with the
   generic message "SSH authentication failed".
4. Host keys: libssh2 negotiates ECDSA first; the strict name-scoped check
   then compared the ECDSA key against the host's `known_hosts` entries of
   any type. A host recorded only with its Ed25519 (or RSA) key was refused
   as **"host key mismatch (possible man-in-the-middle)"**.
5. Hashed `known_hosts` entries (`|1|…`, default `HashKnownHosts yes` on
   Debian/Ubuntu) were never matched (`Host::name()` is `None` for them):
   "not present".
6. (Found while testing) `@revoked` lines were ignored — a revoked key also
   listed as trusted was accepted.

Chosen approach — keep the libssh2 transport, inherit OpenSSH *parameters*:

- `sshconfig::query_openssh` runs `ssh -G [-l user] [-p port] -- <host>`
  (the operator's own client evaluates `~/.ssh/config` and
  `/etc/ssh/ssh_config`, including `Match`; nothing connects; 10 s bound;
  missing `ssh` → built-in defaults). Inherited: HostName, User, Port,
  IdentityFile (with `~` and `%d %u %h %r %p %%`), IdentitiesOnly,
  IdentityAgent (`none`, `SSH_AUTH_SOCK`, `$VAR`, path), HostKeyAlias, first
  UserKnownHostsFile. Never inherited: StrictHostKeyChecking,
  UpdateHostKeys, CheckHostIP, GlobalKnownHostsFile. ProxyJump/ProxyCommand
  → exit 3 ("does not support … connect directly"). `--no-ssh-config` opts
  out. CLI only; MCP profiles never consult it.
- `executor::prefer_known_hostkey_types`: before the handshake, key types
  recorded for the exact identity (hashed entries included, tested through
  libssh2's own matcher) are put first in the host-key preference
  (`hostkey_preference`); the presented key must still match exactly.
- `executor::verify_host_key`: `KnownHosts::check(<exact identity>)` (no port
  → no portless fallback, preserving DESIGN §19), `@revoked` enforcement
  (`revoked_keys`), HostKeyAlias as identity (`known_hosts_identity`).
- `executor::try_agent_auth`: agent from `IdentityAgent`; keys matching a
  configured identity file (`<file>.pub`) first; `IdentitiesOnly` offers only
  those. Then key files; defaults `id_ed25519`, `id_ecdsa`, `id_rsa`
  (`DEFAULT_IDENTITY_FILES`).
- Failure messages list what was tried (`AuthAttempts::describe`) — never key
  material, passphrases or the agent socket path.

Rejected alternative: replacing the transport with an OpenSSH subprocess
(ControlMaster/`ssh host cmd`). It would give ProxyJump, FIDO and passphrase
prompts for free, but changes the timeout, stdin/argv, exit-status and
host-key contracts (DESIGN §19–22) that the existing tests pin; not done.

| Capability | Status |
|---|---|
| Ed25519 key file | SUPPORTED (tested) |
| ECDSA P-256 / P-384 key file (OpenSSH and PEM) | SUPPORTED (tested) |
| RSA key file (OpenSSH and PEM), rsa-sha2 signatures to OpenSSH 10 | SUPPORTED (tested) |
| Encrypted key file | PARTIALLY: via ssh-agent only (tested); never prompted, never decrypted by Sinter |
| ssh-agent (`SSH_AUTH_SOCK`, `IdentityAgent` path / `none`) | SUPPORTED (tested) |
| `IdentitiesOnly` | SUPPORTED (tested) |
| `~/.ssh/config` Host / HostName / User / Port / IdentityFile | SUPPORTED (tested with real `ssh -G` and scripted `ssh`) |
| HostKeyAlias, UserKnownHostsFile (first entry) | SUPPORTED (tested); further UserKnownHostsFile entries ignored |
| known_hosts plain / hashed / comma lists / markers | SUPPORTED (tested); `@cert-authority` not honored (no certificate support) |
| Host enrolled with a single key type (Ed25519 / ECDSA / RSA) | SUPPORTED (tested) |
| ProxyJump / ProxyCommand | UNSUPPORTED — fails closed (exit 3) |
| Password / keyboard-interactive auth | UNSUPPORTED (never existed) |
| FIDO (`sk-`) keys, OpenSSH certificates | UNVERIFIED (libssh2 1.11 has partial support; not tested) |
| `CertificateFile`, `Match exec` side effects | UNVERIFIED / operator's own config |
| Windows controller | UNVERIFIED (Sinter targets Unix controllers) |

## 9. Configuration precedence

Per field, first present wins (`sshconfig::resolve`, `main.rs::inventory_plan`):

1. explicit CLI option (`--user`, `--port`, `--known-hosts`, `--identity`)
2. inventory host field (`user`, `port`, `known_hosts`, `identity_files`)
3. OpenSSH client configuration (`ssh -G`, with 1–2 passed as `-l`/`-p`)
4. built-in default (`$USER`, 22, `~/.ssh/known_hosts`, default key files)

The connection address is the inventory `address` (default: host name) or
`--host`, mapped through ssh_config `HostName`. `--identity` / inventory
`identity_files` *replace* the inherited list. `--host` with `--inventory`
is an error, not a precedence.

## 10. Backup

Schema (`document::parse_backup`):

```yaml
backup:
  paths:
    - /etc/ssh/sshd_config
    - /etc/nginx
```

Static canonical absolute paths (§4.10), no interpolation, not `/`, unique
across the include graph, only field `paths`, non-empty.

| Phase | Behavior |
|---|---|
| validate | schema only; no target, no path existence |
| plan | `BACKUP  <path> [planned]`; observes and creates nothing |
| apply | before the first resource, on each **selected** host only |
| audit | ignored (backups are not desired state) |

Storage (on the target, `backup::store_root`):
`/var/lib/sinter/backups/<run-id>/<original path>` with `--sudo`, else
`<target-user-home>/.sinter/backups/<run-id>/<original path>`. Run id
`YYYYMMDDTHHMMSSZ-<8 hex>` (`new_run_id`), one per invocation, shared by all
hosts; suffixed `-<NN>-<recipe>` per bundle recipe. Host separation is
physical (each host stores on itself); identity in output = execution
`target` + `backup.directory`.

Copy (`TargetFs::backup_copy`): `cp -a --preserve=mode,ownership,timestamps
--no-target-directory -- SRC DEST` — files, directories (recursive), symlinks
as links; mode incl. ACLs, owner/group, timestamps mandatory; other xattrs
and SELinux labels best effort.

Failure semantics: any of — untrusted parent (§23 check on source and store
chain), unsupported type (FIFO/socket/device), unreadable source, copy
failure (disk full, permission), store path overlap, run-directory
collision (non-`-p` mkdir) — aborts before any resource runs, exit 5,
message "backup failed; no resource was executed … partial backup left at
<dir> (not removed)". A nonexistent path is recorded `absent` (not an
error). Store directories Sinter creates are 0700. Content is never read by
the controller or printed. Not a rollback: nothing restores, prunes or
rotates backups.

## 11. Multi-host failure semantics

| Failure | plan / audit | apply |
|---|---|---|
| inventory / targets / resolution / duplicate address | exit 2, nothing runs | same |
| ssh_config evaluation, ProxyJump | exit 3, nothing runs | same |
| connection failure on one host | recorded, continue | recorded, **stop**; rest `not_run` |
| backup failure | n/a | recorded (exit 5), stop |
| apply failure / indeterminate | n/a | recorded (5 / 6), stop |
| any other non-zero execution in apply (2, 4) | n/a | recorded, stop |
| audit drift / observation error | recorded (7 / 6), continue | n/a |

**Apply fail-fast (formal rule, R1 F-02):** in apply, *any* execution whose
exit code is not 0 stops the sequence (`main.rs::stops_remaining`:
`phase == Apply && code != 0`). The failed execution keeps its result/error;
every later execution (later hosts of the recipe and all later recipes) is
`not_run` with `reason` naming the failed execution, `exit_code: null`, never
contacted, no backup, no resources. Completed executions keep their results;
nothing is rolled back. plan/audit never stop.

Exit code = most severe code among executions that ran, order 6 > 5 > 4 > 3
> 2 > 7 > 0 (`main.rs::severity`; `not_run` contributes none); a partial
failure is never 0. Summary (text: `executions: N total, X exit 0, Y
non-zero, Z not run`) and `executions[]` (JSON) are deterministic (recipe
order, host name order).

## 12. CLI colors

`style::color_enabled(is_tty, NO_COLOR, TERM)`: only when the stream is a
TTY, `NO_COLOR` unset/empty, `TERM != dumb`. Decided once per stream in
`main.rs`, carried in `RenderOptions.color`; JSON ignores it; library and MCP
renderers default to no color. Only fixed Sinter tokens are painted, after
`sanitize_line` (which escapes ESC), so recipe/target text can never inject
or forge escapes. Green: ok, CHANGED, success, PASS, no_drift, BACKUP, MATCH,
backed_up. Yellow: POSSIBLE, DRIFT, drift, blocked, ?, not_run, absent.
Red: FAILED, INDET, ERROR, error, plan_error, apply_failed, indeterminate,
the `sinter:` stderr prefix. No new dependency (`std::io::IsTerminal`).

## 13. Chained validate → plan → apply → audit (investigation)

- Today: not available; each invocation runs one phase.
- Parser: clap subcommands consume the first positional as the subcommand,
  so `sinter validate plan apply audit r.yaml` would parse `plan` as the
  recipe path. `recipe.yaml` named `plan` would also be ambiguous.
- Dispatch: already prepared. All four phases share one flattened `ExecOpts`
  and `run_phase(phase, args)`; validate consumes only the recipe, the others
  consume resolved targets; `inventory_plan` is computed per call.
- Minimal future change: a `run` subcommand with an explicit, ordered phase
  list, e.g. `sinter run --phases validate,plan,apply,audit recipe.yaml
  --inventory hosts.yaml` (recommended; unambiguous), which would build the
  execution plan once and call the existing phase functions in order,
  stopping on the first non-zero phase. No change made now.

## 14. Compatibility

- Existing `validate`/`plan`/`apply`/`audit` command lines, recipes and
  single-target JSON documents are unchanged (new JSON keys only appear when
  a recipe declares `backup`, or with `--inventory`/bundles; both additive
  under the documented 1.x rules). The pinned exit-glue test passes
  unchanged.
- Behavior changes for existing single-host users (documented in
  CHANGELOG): ssh_config is now consulted (a `Host *` ProxyCommand now fails
  closed instead of being bypassed — use `--no-ssh-config`); `--port`
  default comes from ssh_config; `id_ecdsa` is tried by default; hosts that
  previously failed with a false "mismatch" or "not present" now connect.
- MCP (`sinter mcp`) is untouched apart from benefiting from the host-key
  fixes; its profiles never consult ssh_config.
- `.agents/skills/sinter` documents the released v1.0.0 and was not changed.

## 15. Security considerations

- Fail closed everywhere multi-host: no implicit all-hosts, unknown names are
  errors, resolution before any connection, unselected hosts untouched,
  duplicate endpoints rejected, apply stops on the first non-zero execution.
- Host-key policy never weakened: ssh_config cannot relax it; ordering only
  prefers already-trusted key types; exact identity matching kept (portless
  entry never authorizes a non-default port — still tested); revocation now
  enforced (strictly stronger).
- `ssh -G` host argument validated (no leading `-`, whitespace, control
  chars, `@`) and passed after `--`.
- No key material, passphrase or agent socket path in any output; backup
  content never read by the controller; tests assert canaries do not leak.
- Backups obey the §23 trust boundary for sources and store; 0700 store;
  collision fails instead of merging.
- `sudo` stays invocation-level (no per-host sudo in the inventory).

## 16. Tests

New test files and key tests:

| File | Tests (selection) |
|---|---|
| `tests/cli_multihost.rs` (38 after R1, all platforms) | `validate_ignores_execution_options_without_reading_anything`, `unknown_or_misspelled_options_fail`, `validate_bundle`, `inventory_without_recipe_targets_fails_closed`, `group_target_selects_only_its_members`, `host_and_group_targets_union`, `unknown_target_names_fail_closed`, `skipped_hosts_are_never_resolved`, `duplicate_resolved_address_is_rejected_before_connecting`, `apply_stops_at_the_first_failed_execution`, `read_only_phases_attempt_every_selected_host`, `bundle_resolves_each_recipe_against_its_own_targets`, `bundle_with_an_untargeted_recipe_fails_closed`, `single_host_keeps_the_single_document_contract`, `precedence_cli_over_inventory_over_ssh_config`, `proxy_jump_fails_closed`, `tty_output_is_colored`, `no_color_disables_tty_color`, `json_is_never_colored_even_on_a_tty`, `piped_output_is_never_colored`, `shipped_multihost_example_resolves_as_documented` |
| `tests/backup.rs` (6 all platforms + 8 Linux) | `invalid_backup_declarations_are_schema_errors`, `backup_paths_merge_across_includes_and_reject_duplicates`, `validate_does_not_touch_backup_paths`; Linux: `plan_lists_backups_and_creates_nothing`, `apply_backs_up_before_changing_and_preserves_metadata`, `backup_failure_prevents_every_change`, `unsupported_object_type_fails_backup`, `run_directory_collision_fails_without_changes`, `backup_of_the_store_itself_is_rejected`, `audit_ignores_backup_declarations`, `json_without_backup_section_has_no_backup_key` |
| `tests/ssh_keys.rs` (6, opt-in `SINTER_TEST_LOCAL_SSHD=1`) | `every_common_key_format_authenticates`, `encrypted_key_file_needs_the_agent`, `host_enrolled_with_any_single_key_type_is_accepted`, `hashed_known_hosts_entries_are_honored`, `host_key_policy_still_fails_closed`, `host_key_alias_selects_the_known_hosts_name` |
| `tests/multihost_lab.rs` (7 after R1, Linux, opt-in) | `only_selected_hosts_are_contacted_and_backed_up`, `backup_failure_on_one_host_stops_every_later_change`, `same_machine_under_two_names_collides_instead_of_mixing_backups`, `plan_and_audit_report_every_selected_host` |

Unit tests added in `src/style.rs`, `src/sshconfig.rs`, `src/inventory.rs`,
`src/bundle.rs`, `src/backup.rs`, `src/executor.rs` (`hostkey_tests`),
`src/targetfs.rs` (`base64_decode_roundtrip`).

Existing tests changed (mechanical only, no assertion weakened):
`tests/audit.rs`, `tests/json_contract.rs` (`color: false` in
`RenderOptions` literals), `tests/common/mod.rs` (`..Default::default()` in
`SshSpec`, `SshConfig::from`).

### Commands and results

| Command | Where | Result |
|---|---|---|
| `cargo test` (baseline, before any change) | macOS 26 arm64 | 498 passed, 0 failed |
| `cargo build`, `cargo clippy --all-targets`, `cargo fmt --check` | macOS | clean, no warnings |
| `SINTER_TEST_LOCAL_SSHD=1 cargo test` | macOS | **584 passed, 0 failed** (Linux-gated suites compile to 0 there) |
| `SINTER_TEST_LOCAL_SSHD=1 CARGO_PROFILE_{DEV,TEST}_DEBUG=0 cargo test --no-fail-fast` | Lima `ubuntu-amd64`, Ubuntu 24.04.4 x86_64 (reference target) | **787 passed, 0 failed**, exit 0 |
| SSH lab matrix with the pre-change binary and after (manual, `sshd -f` on 127.0.0.1:22422) | macOS, OpenSSH 10.3 | see §8; reproduced by `tests/ssh_keys.rs` |
| `npm run check` (docs-site) | macOS | **not run**: local Node 20 < Astro's required 22 (CI uses 22) |

Notes for re-verification:

- `tests/ssh.rs` (23) and other SSH-target tests report as passed but skip
  themselves (`SINTER_TEST_SKIPPED`) unless `SINTER_TEST_SSH_HOST` and
  friends point at a disposable target; they were not exercised against a
  remote host here. The new `tests/ssh_keys.rs` and `tests/multihost_lab.rs`
  cover SSH against local throwaway `sshd` instances instead.
- The first Linux run of the final code failed one test
  (`apply_backs_up_before_changing_and_preserves_metadata`): two parallel
  runs raced on creating `~/.sinter` ("File exists"). This was a real bug
  (two concurrent invocations against one host would hit it). Fixed in
  `backup::ensure_dir`: after a lost `mkdir` race the directory is
  re-inspected and accepted only if it passes the same owner/mode checks as a
  pre-existing one (never chmod-ed). The rerun above is green.
- Reproduce the Linux run: copy the tree (without `target/`) to an Ubuntu
  24.04 host with `sshd`, `ssh-keygen`, `ssh-agent`, OpenSSL headers and
  passwordless `sudo -n`, then run the command in the table.

## 17. Changed files

Superseded by the final diffstat in **Remediation R1 → R1.8** below (the
figures that stood here were taken before R1 and are no longer current).

## 18. Known limitations

- ProxyJump/ProxyCommand, FIDO keys, certificates, passphrase prompts.
- Only the first `UserKnownHostsFile` entry; `GlobalKnownHostsFile` ignored.
- Hosts run sequentially; no parallelism.
- `targets` names inventory entries only; `--host` ignores `targets`.
- Backups: no restore/prune tooling; xattr/SELinux labels best effort; a
  copy killed by timeout leaves a partial directory (reported); audit does
  not correlate backups.
- The same machine listed under two inventory names is only detected by
  address:port equality or, for backups, by run-directory collision.
- MCP plan/audit tools do not show backup or target information.

## 19. Deferred

Chained phases (`sinter run --phases …`), group/host variables, nested
groups, parallelism, jump hosts, backup restore/retention, audit ↔ backup
correlation, updating `.agents/skills/sinter` at the next release, MCP
support for inventories.

## 20. Commit / push

Not committed or pushed: the repository's history shows releases gated by
`RELEASE.md` and changes landed by the owner; this work amends `GOALS.md`
and `DESIGN.md` (§36 previously prohibited inventory), which is an owner
decision. The tree is left ready for review.

## 21. Final git status

See **Remediation R1 → R1.9**.

---

# Remediation R1 (independent audit findings F-01 – F-04)

An independent audit of the state above reported four findings. This section
records how each was closed; the sections above were corrected in place
where they were wrong (§2, §8, §11, §15) and are otherwise kept as written.
Scope was limited to closing the findings: no new features.

## R1.0 State at R1 start

`main` @ `531cb24d11c2e38cc4f7bdb93a4ab7d1a04a09fa` = `origin/main` (0/0),
nothing staged, 23 tracked files modified, 11 untracked paths (the
implementation) — identical in kind to what the audit observed.

## R1.1 F-01 (MEDIUM) — starting-tree claim

Finding: §2 asserted a clean starting tree that the repository cannot prove.

Remediation: §2 now separates (a) the pre-implementation state — observed
clean only in the implementing session's transcript, explicitly marked
**not provable from the repository / unverified** — from (b) the verified
review-time state (HEAD = origin/main = `531cb24`, uncommitted
implementation, nothing staged, tracked modifications + untracked files).
No history was reconstructed or asserted beyond that.

## R1.2 F-02 (MEDIUM) — apply fail-fast semantics

Finding: the implementation stops on `phase == Apply && code != 0`, while
DESIGN/review listed only connection/backup/apply/indeterminate.

Decision: the implemented, safer rule is the formal specification. Code was
not loosened. The predicate is now a named function with unit tests
(`src/main.rs::stops_remaining`); behavior is unchanged.

Formal semantics (DESIGN §19.4, docs en/ja "Execution and failures",
README, CHANGELOG, §11 above):

- Trigger: during apply, any execution with exit code ≠ 0 — 2 validation,
  3 connection/capability, 4 plan, 5 backup or apply failure, 6
  indeterminate. plan and audit never stop.
- `not_run`: every later execution (later hosts of the same recipe and all
  executions of later recipes) gets `status: "not_run"`, `exit_code: null`,
  `reason: "apply stopped after <recipe> @ <host> failed"`, and a `backup`
  record with status `not_run`; it is never contacted; neither its backups
  nor its resources run.
- Earlier executions keep their results; the failed execution keeps its own
  result or error; nothing is rolled back.
- Exit code: most severe code among executions that ran (6 > 5 > 4 > 3 > 2
  > 7 > 0); `not_run` contributes none; a partial failure is never 0.
- Summary: `executions: N total, X exit 0, Y non-zero, Z not run` (text);
  `exit_code` + per-execution entries (JSON).

Was the condition unintentionally broad? No. In apply mode the engine never
yields exit 4 (plan-mode-only errors) or 7 (audit-only), so in practice the
trigger set is {2, 3, 5, 6}, which matches the intent "stop on anything that
is not a clean success". The rule is stated as "any non-zero" so a future
code path cannot silently continue.

Tests: `main.rs` unit tests `apply_stops_on_every_non_zero_exit_code`
(2,3,4,5,6,7 → stop; 0 → continue), `read_only_phases_never_stop`,
`aggregate_exit_code_is_the_most_severe`; CLI `apply_stops_at_the_first_failed_execution`
(exit 3), `bundle_apply_stops_across_recipes`; Linux lab
`apply_failure_on_one_host_stops_later_hosts` (exit 5, later host
`not_run`, `exit_code: null`, never contacted — checked in its sshd log),
`backup_failure_on_one_host_stops_every_later_change`. Exit 4 cannot be
produced by an apply engine today; it is pinned by the unit test only.

## R1.3 F-03 (MEDIUM) — backup result in aggregate JSON

Finding: aggregate (inventory / bundle) JSON lost the backup result.

Analysis: for executions that completed, the backup report was already
present inside `executions[].result.backup` (the unchanged single-run
document). It was lost whenever the execution produced no document: a
**backup failure** (the error carried only a message), a plan error, an
execution that failed before the backup step, and `not_run` executions.

Remediation (additive; no field removed or renamed; single-run documents
unchanged):

- New execution-level field `executions[].backup` in the aggregate
  document, built solely from that execution's own report or error
  (`src/main.rs::backup_record`):
  - `null` — recipe declares no backup, or phase is audit;
  - object `{status, run_id, directory, entries[]}` with `status` =
    `planned` | `completed` | `failed` | `not_started` | `not_run`;
    `entries[]` = `{path, status, kind, destination}` with entry status
    `planned` | `backed_up` | `absent` | `failed` | `not_run`.
  - For a completed run it repeats `result.backup` (+ `status`).
- A backup failure now carries a structured partial report: new field
  `SinterError.backup: Option<Box<BackupReport>>` (`src/error.rs`, `None`
  everywhere else), filled by `backup::fail` (`Progress`): completed
  entries, the failing path as `failed`, the rest `not_run`, the run
  directory only if this invocation created it (a collided directory is
  not claimed → `null`). New `BackupStatus::{Failed, NotRun}` (used only in
  failure / aggregate records).
- Content is never included: only paths, statuses, kinds, locations.
- Single-target text/JSON and stderr wording are unchanged; a single-target
  backup failure still prints no document (exit 5, stderr), as documented.

Docs: DESIGN §19.4, docs en/ja "Inventory and bundles" (Execution object /
Execution `backup`).

Tests:

| Requirement | Test |
|---|---|
| multi-host apply aggregate with backup | `multihost_lab::same_machine_under_two_names_collides_instead_of_mixing_backups` (db01 `completed` with its directory; web01 `failed`, `directory: null`), `aggregate_backup_record_per_phase` |
| bundle aggregate with backup, recipe identity | `multihost_lab::bundle_backups_are_recorded_per_recipe` (two recipes → two `completed` records, directories `…-01-first` / `…-02-second`, each holding only its own path); `aggregate_backup_record_follows_recipe_identity` |
| host A / host B not mixed | the collision test above (distinct statuses/directories per host, same `run_id`); records are built per execution by construction |
| execution without backup | `aggregate_backup_record_follows_recipe_identity` (`nobackup@db01` → `null`); audit → `null` in `aggregate_backup_record_per_phase` |
| backup failure | `multihost_lab::backup_failure_record_lists_each_path_outcome` (`backed_up`, `failed`, `not_run`; managed file untouched) |
| no secret content in JSON | canaries in `backup_failure_record_lists_each_path_outcome`, `bundle_backups_are_recorded_per_recipe`, `only_selected_hosts_are_contacted_and_backed_up`, `tests/backup.rs::apply_backs_up_before_changing_and_preserves_metadata` |
| no ANSI in JSON | every `cli_multihost` JSON helper asserts no ESC; lab failure test asserts it; `json_is_never_colored_even_on_a_tty` |
| single-run contract unchanged | `single_host_json_has_no_execution_level_backup_field`, `single_host_keeps_the_single_document_contract`, `tests/json_contract.rs` (unchanged, green) |

Not covered: two *different physical machines* both completing a backup in
one run (the lab has one machine; two names for it collide by design).
Separation across machines follows from each target storing on itself and
each record being built from its own execution — UNVERIFIED end-to-end.

## R1.4 F-04 (LOW) — Linux evidence

Environment: Lima VM `ubuntu-amd64` — `Linux 6.8.0-142-generic x86_64`,
**Ubuntu 24.04.4 LTS** (the reference target), rustc 1.98.1,
`OpenSSH_9.6p1 Ubuntu-3ubuntu13.19, OpenSSL 3.0.13`, passwordless `sudo -n`.
Source copied from the working tree (checksums of `src/main.rs`,
`src/backup.rs`, `tests/multihost_lab.rs` verified identical on both sides).

Commands (in the VM, `~/sinter-cli-review`):

```
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 SINTER_TEST_LOCAL_SSHD=1
cargo test --no-fail-fast                                   # counts   (r3-full.log,  EXIT=0, 5m38s)
cargo test --no-fail-fast -- --nocapture --test-threads=1   # skip attribution (r3-nocap.log, EXIT=0)
```

Skips are counted from `SINTER_TEST_SKIPPED` markers (the harness reports a
skipped test as "ok", so they must not be read as passes).

| Binary | ran | PASS | FAIL | SKIP | ignored / filtered |
|---|---|---|---|---|---|
| lib unit tests | 226 | 226 | 0 | 0 | 0 / 0 |
| bin unit tests (`main.rs`) | 3 | 3 | 0 | 0 | 0 / 0 |
| tests/audit.rs | 86 | 86 | 0 | 0 | 0 / 0 |
| **tests/backup.rs** | **14** | **14** | 0 | 0 | 0 / 0 |
| tests/cli.rs | 20 | 20 | 0 | 0 | 0 / 0 |
| tests/cli_multihost.rs | 38 | 38 | 0 | 0 | 0 / 0 |
| tests/commands.rs | 15 | 15 | 0 | 0 | 0 / 0 |
| tests/engine.rs | 34 | 34 | 0 | 0 | 0 / 0 |
| tests/file_safety.rs | 8 | 8 | 0 | 0 | 0 / 0 |
| tests/frontends.rs | 15 | 15 | 0 | 0 | 0 / 0 |
| tests/handlers.rs | 13 | 13 | 0 | 0 | 0 / 0 |
| tests/json_contract.rs | 13 | 13 | 0 | 0 | 0 / 0 |
| tests/mcp.rs | 31 | 31 | 0 | 0 | 0 / 0 |
| **tests/multihost_lab.rs** | **7** | **7** | 0 | 0 | 0 / 0 |
| tests/package_service.rs | 7 | 7 | 0 | 0 | 0 / 0 |
| tests/platform.rs | 41 | 41 | 0 | 0 | 0 / 0 |
| tests/platform_next.rs | 8 | 8 | 0 | 0 | 0 / 0 |
| tests/remediation.rs | 79 | 77 | 0 | **2** | 0 / 0 |
| tests/remediation_r2.rs | 25 | 25 | 0 | 0 | 0 / 0 |
| tests/remediation_r4.rs | 34 | 34 | 0 | 0 | 0 / 0 |
| tests/remediation_r5.rs | 42 | 42 | 0 | 0 | 0 / 0 |
| tests/ssh.rs | 23 | 0 | 0 | **23** | 0 / 0 |
| tests/ssh_keys.rs | 6 | 6 | 0 | 0 | 0 / 0 |
| tests/truthfulness.rs | 9 | 9 | 0 | 0 | 0 / 0 |
| doc-tests | 0 | 0 | 0 | 0 | 0 / 0 |
| **Total** | **797** | **772** | **0** | **25** | 0 / 0 |

Linux-only tests actually executed (from `r3-full.log`):

- `tests/backup.rs` (14): the 6 portable schema tests plus the 8 Linux
  filesystem tests `target::plan_lists_backups_and_creates_nothing`,
  `target::apply_backs_up_before_changing_and_preserves_metadata`,
  `target::backup_failure_prevents_every_change`,
  `target::unsupported_object_type_fails_backup`,
  `target::run_directory_collision_fails_without_changes`,
  `target::backup_of_the_store_itself_is_rejected`,
  `target::audit_ignores_backup_declarations`,
  `target::json_without_backup_section_has_no_backup_key`.
- `tests/multihost_lab.rs` (7, two throwaway `sshd` over real SSH):
  `only_selected_hosts_are_contacted_and_backed_up`,
  `backup_failure_on_one_host_stops_every_later_change`,
  `same_machine_under_two_names_collides_instead_of_mixing_backups`,
  `plan_and_audit_report_every_selected_host`,
  `backup_failure_record_lists_each_path_outcome`,
  `bundle_backups_are_recorded_per_recipe`,
  `apply_failure_on_one_host_stops_later_hosts`.
- `tests/ssh_keys.rs` (6, real OpenSSH 9.6 `sshd` + `ssh-agent`).

SKIP / UNVERIFIED (need `SINTER_TEST_SSH_HOST` and the reference target —
system sshd on 22, listener on 2222, `sinter-nosudo` user; not configured on
the shared VM to avoid changing its SSH authorization):

- `tests/ssh.rs`: all 23 (`ssh_known_host_success`, `ssh_unknown_host_fails`,
  `ssh_changed_host_key_fails`, `ssh_host_port_mismatch_rejects_despite_portless_match`,
  `ssh_host_port_match_accepts`, `ssh_portless_only_non_default_port_rejects`,
  `ssh_default_port_portless_match_accepts`, argv/stdin/timeout/sudo tests …).
- `tests/remediation.rs`: `ssh_host_key_failure_fails_closed`,
  `hostile_resource_id_has_no_shell_side_effects_under_sudo` (over SSH).

The host-key rules those tests guard (portless vs `[host]:port`, changed or
unknown key) are also exercised against real `sshd` by
`ssh_keys::host_key_policy_still_fails_closed` (PASS), but the 25 above
remain UNVERIFIED in this round.

The `panicked at …` lines in `r3-nocap.log` come from intentional panics
(`#[should_panic]` in `src/platform.rs`, `catch_unwind` in `tests/audit.rs`);
all 25 result lines of that run report `0 failed`.

History: the first Linux run of the pre-R1 code failed one test (a real
`~/.sinter` creation race, fixed before the audit); see §16.

macOS (developer controller, `SINTER_TEST_LOCAL_SSHD=1 cargo test`): 591
ran, **568 PASS, 0 FAIL, 23 SKIP** (`tests/ssh.rs`); Linux-only suites
compile to 0 tests there. `cargo clippy --all-targets` and `cargo fmt
--check`: clean on macOS (Linux-only test files are compiled and run only in
the VM). docs-site `npm run check`: **not run** (local Node 20 < Astro's 22).

## R1.5 SSH historical claim

No document stated that pre-change Sinter was Ed25519-only; §8 already said
"No". §8 now also states the audit's independent confirmation (RSA/ECDSA
worked through ssh2/libssh2 before), that the main value is using the
OpenSSH environment (`~/.ssh/config`, IdentityFile, ssh-agent,
HostName/User/Port), and the provenance of each historical observation
(source reading at `531cb24` vs. session-only runtime measurements not
reproduced by committed tests).

## R1.6 Regression checklist (this round)

| Item | Evidence | Result |
|---|---|---|
| existing single-host recipe | `tests/cli.rs` (20, Linux), `single_host_keeps_the_single_document_contract` | PASS |
| `targets` without inventory (single host) | `single_host_keeps_the_single_document_contract` | PASS |
| multi-host + no targets = ERROR | `inventory_without_recipe_targets_fails_closed`, `bundle_with_an_untargeted_recipe_fails_closed` | PASS |
| skipped host untouched | `skipped_hosts_are_never_resolved`, `multihost_lab::only_selected_hosts_are_contacted_and_backed_up` | PASS |
| overlapping target executes once | `overlapping_selection_executes_each_host_once` (new) | PASS |
| validate does not resolve inventory/SSH | `validate_ignores_execution_options_without_reading_anything` | PASS |
| backup failure prevents mutation | `target::backup_failure_prevents_every_change`, lab `backup_failure_*` | PASS (Linux) |
| aggregate JSON | R1.3 tests | PASS |
| existing JSON contract | `tests/json_contract.rs` (13) | PASS |
| existing MCP contract | `tests/mcp.rs` (31) | PASS |
| CLI color / NO_COLOR | `tty_output_is_colored`, `no_color_disables_tty_color`, `json_is_never_colored_even_on_a_tty`, `piped_output_is_never_colored` | PASS |
| audit / evidence | `tests/audit.rs` (86), `plan_and_audit_report_every_selected_host`, `aggregate_backup_record_per_phase` | PASS |
| Ed25519 / RSA / ECDSA | `ssh_keys::every_common_key_format_authenticates` (macOS OpenSSH 10.3, Ubuntu OpenSSH 9.6) | PASS |
| existing remote SSH suite | `tests/ssh.rs` | **SKIP / UNVERIFIED** |

No security assertion was weakened; the only edits to pre-existing tests are
the mechanical ones listed in §16.

## R1.7 Files changed in R1

`src/error.rs` (`SinterError.backup`), `src/backup.rs` (`BackupStatus::{Failed,
NotRun}`, `Progress`, structured `fail`), `src/output.rs` (`backup_json`
public, labels for the new statuses), `src/main.rs` (`backup_record`,
`ExecResult.backup`, `stops_remaining`, unit tests), `tests/cli_multihost.rs`
(4 tests), `tests/multihost_lab.rs` (3 tests + collision assertions),
`DESIGN.md` §19.4, `docs-site/.../{en,ja}/reference/cli.md`, `README.md`,
`README.ja.md`, `CHANGELOG.md`, this report.

## R1.8 Final diffstat

Tracked files (`git diff --stat`):

```
 CHANGELOG.md                                     |  54 ++
 DESIGN.md                                        | 134 +++-
 GOALS.md                                         |   4 +-
 README.ja.md                                     |  56 +-
 README.md                                        |  57 +-
 docs-site/src/content/docs/en/reference/cli.md   | 259 +++++-
 docs-site/src/content/docs/en/troubleshooting.md |  14 +-
 docs-site/src/content/docs/ja/reference/cli.md   | 263 +++++-
 docs-site/src/content/docs/ja/troubleshooting.md |  16 +-
 src/document.rs                                  | 187 ++++-
 src/engine.rs                                    |  60 +-
 src/error.rs                                     |   9 +
 src/executor.rs                                  | 477 +++++++++--
 src/ir.rs                                        |  14 +-
 src/lib.rs                                       |   5 +
 src/main.rs                                      | 980 ++++++++++++++++++++---
 src/mcp.rs                                       |  2 +
 src/model.rs                                     |  43 +-
 src/output.rs                                    | 121 ++-
 src/targetfs.rs                                  | 107 +++
 src/targets.rs                                   |   1 +
 tests/audit.rs                                   |   2 +
 tests/common/mod.rs                              |   9 +-
 tests/json_contract.rs                           |   1 +
 24 files changed, 2606 insertions(+), 269 deletions(-)
```

Untracked (new) files, line counts: `src/backup.rs` 440, `src/bundle.rs` 236,
`src/inventory.rs` 404, `src/sshconfig.rs` 467, `src/style.rs` 211,
`tests/backup.rs` 406, `tests/cli_multihost.rs` 1164,
`tests/multihost_lab.rs` 466, `tests/ssh_keys.rs` 314,
`examples/multihost/*` 65 (5 files), and this report — 4173 lines excluding
this report.

## R1.9 Final git status

`main` @ `531cb24d11c2e38cc4f7bdb93a4ab7d1a04a09fa` = `origin/main`; not
committed, not pushed; nothing staged.

```
 M CHANGELOG.md                      M src/executor.rs
 M DESIGN.md                         M src/ir.rs
 M GOALS.md                          M src/lib.rs
 M README.ja.md                      M src/main.rs
 M README.md                         M src/mcp.rs
 M docs-site/.../en/reference/cli.md M src/model.rs
 M docs-site/.../en/troubleshooting.md M src/output.rs
 M docs-site/.../ja/reference/cli.md M src/targetfs.rs
 M docs-site/.../ja/troubleshooting.md M src/targets.rs
 M src/document.rs                   M tests/audit.rs
 M src/engine.rs                     M tests/common/mod.rs
 M src/error.rs                      M tests/json_contract.rs
?? SINTER_MULTIHOST_FOUNDATION_REVIEW.md   ?? src/sshconfig.rs
?? examples/multihost/                     ?? src/style.rs
?? src/backup.rs                           ?? tests/backup.rs
?? src/bundle.rs                           ?? tests/cli_multihost.rs
?? src/inventory.rs                        ?? tests/multihost_lab.rs
                                           ?? tests/ssh_keys.rs
```

## R1.10 Remaining findings / open items

- UNVERIFIED: the 25 remote-SSH tests (R1.4) until run against the reference
  target with `SINTER_TEST_SSH_HOST`.
- UNVERIFIED: two distinct physical hosts both completing a backup in one run.
- Not run: docs-site `npm run check` (needs Node ≥ 22).
- Unchanged decision for the owner: DESIGN §36 / GOALS amendments (§20).

---

# v1.1.0 final acceptance (GCE, two real hosts)

Performed after the focused re-audit (`SINTER_MULTIHOST_FOUNDATION_FOCUSED_REAUDIT.md`,
verdict GO WITH NOTES; that file is the independent record and is not edited
here). This section closes the re-audit's remaining UNVERIFIED items where
possible. No credentials, private keys, project identifiers or VM addresses
are recorded.

## V.1 Environment

| | |
|---|---|
| Hosts | two temporary GCE VMs created for this acceptance only: **A** (`e2-medium`, 20 GB) and **B** (`e2-small`, 10 GB), same zone, default network |
| OS | Ubuntu 24.04.5 LTS x86_64 (image `ubuntu-2404-noble-amd64-v20260918`), kernel 7.0.0-1011-gcp |
| Toolchain (A) | rustc 1.98.1, cargo 1.98.1; OpenSSH 9.6p1 / OpenSSL 3.0.13 on both |
| Roles | A = controller (runs the candidate) **and** target; B = target. Operator setup on A: a dedicated Ed25519 key authorized on A and B, `~/.ssh/config` aliases `sinter-a` / `sinter-b` (HostName, User, IdentityFile, IdentitiesOnly), host keys enrolled explicitly with `ssh-keyscan -H` (hashed) |
| Target prerequisites | `attr`/`acl` installed on both (README requirement) |
| Transport | unchanged: libssh2 (`ssh2`); OpenSSH is used only for `ssh -G` configuration resolution |
| Cleanup | both VMs deleted after acceptance (V.10) |

## V.2 Candidate identity

- Source: working tree on `main` @ `531cb24d11c2e38cc4f7bdb93a4ab7d1a04a09fa`
  (implementation uncommitted — a dirty-tree candidate), 99 files; a per-file
  SHA-256 manifest was generated on the controller and verified on A
  (`sha256sum -c`: all 99 files OK).
- Build on A: `cargo build --locked --release` (115 s).
- Candidate executable: ELF 64-bit x86-64, SHA-256
  `da00bcd5e8e051e591b8c7c55ff414ebdb2bdcba0b2a4e0ffe52dc1431dbbdb7`,
  `sinter --version` = `sinter 1.0.0` (acceptance ran before the metadata-only
  version bump; the same hash was re-read on A at the end of the run).

## V.3 Actual CLI acceptance

Every command was the real candidate CLI on A. Evidence per step: exit code,
stdout/stderr, and a state snapshot of **both** hosts taken from outside the
controller path — each host's count of sshd logins *from A's address*
(journal), SHA-256 prefixes and modes of the test files, and the backup
store listings. The test tree was `~/sinter-v110-acceptance/` on each host
(not `/tmp`: a world-writable parent fails Sinter's §23 trust check — used
deliberately in V.5).

| Step | Command (abridged) | Exit | Result |
|---|---|---|---|
| validate isolation | `validate group.yaml --host sinter-b --inventory /does/not/exist.yaml --user … --port 2222 --identity /no/such/key --known-hosts /no/such/kh --sudo` | 0 | recipe-only; no login on A or B, no file or backup change |
| | `validate group.yaml --hosts inventory.yaml --format json` | 0 | single-document validate JSON unchanged |
| | `validate stack.yaml --inventory inventory.yaml` (bundle) | 0 | per-recipe targets listed |
| | `validate group.yaml --hots inventory.yaml` (typo) | 2 | `unexpected argument '--hots'` |
| single-host (v1.0 style, recipe **without** targets) | `validate` / `plan` / `apply --format json` / `audit` / `apply` again, `--host sinter-b` | 0 ×5 | CHANGED → changed+verified → PASS/no_drift → 0 changes (idempotent); JSON keys exactly the v1 set; B +5 logins, A +0 |
| | `plan single.yaml --host <B address> --user … --identity … --known-hosts … --no-ssh-config --format json` | 0 | explicit v1.0 flags still work |
| fail-closed | `plan` / `apply` / `audit notargets.yaml --inventory inventory.yaml` | 2 ×3 | "declares no targets …"; empty stdout; both hosts byte-identical (0 connections, 0 backups, 0 mutations) |
| host target | `plan` + `apply hostonly.yaml --inventory …` (`targets: hosts [sinter-a]`) | 0 | resolution sinter-a MATCH `host:sinter-a`, sinter-b SKIP; A backed up then changed; **B state identical, 0 logins** |
| group target | `plan` / `apply` / `audit group.yaml --inventory …` (`groups: [pair]`) | 0 ×3 | each host executed once per phase (B +2 for plan+apply); audit no_drift, `backup: null` |
| overlap | `apply overlap.yaml --inventory …` (`hosts: [sinter-a]` + `groups: [pair]`) | 0 | sinter-a reasons `host:sinter-a, group:pair`; **one** execution per host (+1 login each) |
| bundle | `plan` + `apply stack.yaml --inventory …` (recipe1 → A, recipe2 → B) | 0 | recipe1 ran only on A, recipe2 only on B (both files existed on both hosts; only the targeted one changed per host); backups `…-01-recipe1` only on A, `…-02-recipe2` only on B |

## V.4 Two-host backup

`group.yaml` backs up a file, a directory, a symlink and a missing path, then
changes the file, on A and B in one invocation. Verified on each host after
apply:

| Check | A | B |
|---|---|---|
| backup record (JSON) | `completed`, entries `backed_up` file / directory / symlink, `absent` | same, own run directory |
| copy of `app.conf` = pre-change content | SHA prefix `da1d2752…` = A's original | `7771fa9d…` = B's original |
| live file after apply | new content | new content |
| mode / owner preserved | 640 a0000 | 640 a0000 |
| directory copy | complete | complete |
| symlink copy | symlink → `app.conf` | symlink → `app.conf` |
| missing path | not created | not created |
| run directory | 0700 | 0700 |

The copies hold each host's *own* pre-change content (no mixing), and the
live files changed only after the copies — backup-before-mutation on two
distinct physical hosts (previously UNVERIFIED). With `--sudo`
(`/opt/sinter-v110-acceptance/root.conf`, root 0600): both hosts
`completed` into `/var/lib/sinter/backups/<run-id>/` (store and run dir 0700
root); copies equal the pre-change hash with 0600 root preserved.

## V.5 Backup failure (negative)

`negfail.yaml` (`groups: [pair]`, backup path under world-writable `/tmp`),
`apply --format json` → exit **5**:

- sinter-a: `status: error`, `error.kind: apply`, message "backup failed; no
  resource was executed: … parent path /tmp grants group or other write
  access …; partial backup left at <run dir>"; backup record `failed`,
  entry `failed`; the managed file was **not created**.
- sinter-b: `status: not_run`, `exit_code: null`, reason "apply stopped
  after negfail @ sinter-a failed", backup `not_run`; **0 logins**, file not
  created.

## V.6 Structured JSON and secrets

- All 23 captured outputs (46 stdout/stderr files) contain **0 ANSI escape
  bytes**; all 11 JSON documents parse.
- Per execution the aggregate carries recipe, target (name, address, port,
  user), status, exit code, result or error, and the backup record; A/B and
  recipe1/recipe2 backups were distinct and correctly attributed; no-backup
  (`null`), `failed` and `not_run` are distinguishable.
- Secret-like canaries were planted in every fixture. Backup-only content
  (`conf.d/b.conf`, `root.conf`, the negative-test file) appeared **0** times.
  The only hits (5) were plan *diffs* of files that the recipes also
  *managed* without `sensitive: true` — the documented v1.0 diff behavior,
  identical on the single-host path. Re-run with a `sensitive: true` managed
  file that is also backed up: plan text, plan JSON and apply JSON contain
  **0** canary hits (`diff: redacted`), while each host's backup copy holds
  its original content.

## V.7 Linux test suites on GCE A (candidate source)

Run on A with `SINTER_TEST_STRICT=1` (an unmet prerequisite panics instead
of skipping), `SINTER_TEST_LOCAL_SSHD=1`, and `tests/ssh.rs` pointed at A
itself as the reference target (sshd on 22 and 2222, sudo-capable user, a
`sinter-nosudo` user without sudo, explicit known_hosts).

| Command | ran | PASS | FAIL | SKIP | filtered |
|---|---|---|---|---|---|
| `cargo test --locked --bin sinter` | 3 | 3 | 0 | 0 | 0 |
| `cargo test --locked --test cli_multihost` | 38 | 38 | 0 | 0 | 0 |
| `cargo test --locked --test json_contract` | 13 | 13 | 0 | 0 | 0 |
| `cargo test --locked --test mcp` | 31 | 31 | 0 | 0 | 0 |
| `cargo test --locked --test backup` | 14 | 14 | 0 | 0 | 0 |
| `cargo test --locked --test multihost_lab` | 7 | 7 | 0 | 0 | 0 |
| `cargo test --locked --test ssh` | **23** | **23** | 0 | **0** | 0 |
| `cargo test --locked --test ssh_keys` | 6 | 6 | 0 | 0 | 0 |
| `cargo test --locked --all-targets --all-features` | **797** | **797** | 0 | **0** | 0 |

The serial `--nocapture` pass reported 0 `SINTER_TEST_SKIPPED` and 0
`SINTER_TEST_REQUIRED` markers. The 25 tests that were SKIP/UNVERIFIED in R1
(`tests/ssh.rs` ×23, `tests/remediation.rs` ×2) executed against a real sshd
and passed. `ssh_keys` covers Ed25519, ECDSA and RSA (OpenSSH and PEM)
against Ubuntu's OpenSSH 9.6.

## V.8 Landing page (architecture/workflow animation)

Implementation: `docs-site/src/components/landing/SinterFlow.astro` +
`docs-site/src/styles/landing.css` — a pure-CSS 16 s loop of pulses along
the flow edges (horizontal keyframes on desktop, `-y` keyframes in the
≤ 60rem vertical layout), no IntersectionObserver / scroll trigger /
hydration; a small script only drives Pause/Play. Reduced motion shows a
static diagram and hides the toggle.

Measured with Playwright 1.63 / Chromium (iPhone 13, 1440×900, 1920×1080;
pulse opacity/position sampled every 400 ms over a full cycle):

| | production | local candidate |
|---|---|---|
| mobile | 6 running; all pulses visible; **audit pulse moved sideways** (travel x 35 px, y 0) | 6 running; all pulses visible; audit pulse travels the vertical line (x 0, y 52 px) |
| desktop 1440×900 | 6 running; every pulse visible, 144–200 px travel | unchanged (all visible, horizontal travel) |
| desktop 1920×1080 | 6 running; every pulse visible, 171–203 px travel | unchanged |
| reduced motion (mobile, desktop) | 0 animations, static dots, toggle hidden | same |
| horizontal overflow / console errors | none / 0 | none / 0 |

Verdict: desktop animation is **not disabled** — it runs with the same
timing as mobile; its lower salience comes from small 7 px pulses in a wide
diagram (a visual-design question, not changed here). A real mobile bug was
found and fixed with one CSS rule: `.e-ssh .p-audit` outranked the vertical
`.p-audit { animation-name: p-audit-y }` override, so the audit pulse kept
the horizontal keyframes on narrow screens. Fix: restate the `-y` animation
at that specificity inside the 60rem block (the later reduced-motion block
still wins). Desktop behavior is unchanged.

## V.9 Documentation validation

Node v22.23.2 (existing Homebrew `node@22`, used via `PATH` for these
commands only): `npm run check` — 0 errors, 0 warnings, 0 hints (16 files);
`npm run build` — 61 pages built; `npm run webmcp:check` — OK. Every YAML
example in README (EN/JA), the CLI reference (EN/JA) and the recipe-format
reference (EN/JA) was extracted and run through the CLI: all added or
changed examples validate (15 OK). This caught and fixed an invalid
placeholder (`resources:` followed only by a comment) in 6 examples. Not
runnable by design: the recipe-format "Skeleton" schematic and the README
template example that needs its external template file (both pre-existing).

## V.10 Final regression (final tree, after docs/UI/version changes)

Final tree = candidate + documentation finalization + the landing-page CSS
rule + the metadata-only version bump (`Cargo.toml`/`Cargo.lock` 1.1.0) + one
test-only lint fix (below). Copied to A again (99 files, manifest verified).

| Check | Linux (GCE A, Ubuntu 24.04.5) | macOS (controller) |
|---|---|---|
| `cargo build --locked --release` | OK, `sinter 1.1.0`, SHA-256 `dcc81ee8…16f8b4` | — |
| `cargo fmt --check` | 0 | 0 |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | 0 warnings / 0 errors | 0 / 0 |
| `cargo test --locked --all-targets --all-features` (strict) | **797 / 797 PASS**, 0 FAIL, 0 SKIP, 0 ignored, 0 filtered (24 binaries) | 591 PASS, 0 FAIL (Linux-only suites compile to 0; `tests/ssh.rs` 23 skip without a reference host) |
| serial `--nocapture` pass | 0 skip / 0 required markers, all result lines `0 failed` | — |
| `python3 tests/installer/test_install.py` | 18 OK | fails 8+1 on macOS **also at pristine HEAD** (`install.sh` uses GNU `stat -c`); Linux is the authoritative platform |
| `python3 -m unittest discover -s release/tests` | 54 OK | OK |
| `git diff --check` | — | clean |
| docs-site `npm run check` / `build` / `webmcp:check` | — | 0 errors / 61 pages / OK (Node 22.23.2) |

Found and fixed during this gate: Linux clippy flagged `#[allow(dead_code)]`
on `mod common;` in `tests/backup.rs` as duplicating the module's own
`#![allow(dead_code)]` (only compiled on Linux, so macOS clippy never saw
it). The attribute was removed; Linux clippy then 0/0 and `tests/backup.rs`
14/14 again. The first final-gate attempt also lacked the `rustfmt`/`clippy`
components on A (minimal toolchain) and `docs-site/public/install.sh` in the
copied tree (the installer test compares it with `install.sh`; the two are
identical and unchanged); both were supplied and the checks re-run as above.

## V.11 Version and release metadata

`Cargo.toml` and `Cargo.lock` → 1.1.0; CHANGELOG `## [1.1.0] - Unreleased`
(the v0.4.1 precedent: dated when published). Deliberately **not** changed
here: install instructions, download URLs, WebMCP release metadata and the
"current release v1.0.0 passed eight-target acceptance" statements — the
v1.1.0 artifact does not exist until the separate tag/release process
(RELEASE.md steps 4–17), and the docs site deploys on push. New features are
labeled "available from v1.1.0" in README and docs instead. No historical
release record was edited.

## V.12 GCE cleanup

Both temporary VMs were deleted by name after acceptance; no instance or disk
of this acceptance remains; the ten pre-existing instances were not touched
(all still TERMINATED). No firewall rule, address or other resource was
created.

## V.13 Commits

Following RELEASE.md steps 1–2: (1) a feature commit — implementation,
tests, examples, DESIGN/GOALS/README/docs, landing-page fix, CHANGELOG
`[Unreleased]` entry and both review artifacts — then (2) its direct child,
the metadata-only "Prepare Sinter v1.1.0 release" commit (`Cargo.toml`,
`Cargo.lock`, CHANGELOG heading). Pushed to `origin/main` without force. No
tag, GitHub Release or artifact. Commit SHAs and the post-push state are in
Git history and the final report, not in this file.

## V.14 Remaining limitations

- The v1.1.0 release artifact still has to go through RELEASE.md steps 4–17
  (Rocky 9 build, eight-target acceptance, evidence bundle, checker, human
  review, tag, release); the acceptance above is feature acceptance of the
  source candidate, not release-artifact acceptance.
- ProxyJump/ProxyCommand, FIDO keys and OpenSSH certificates remain
  unsupported/unverified (§8).
- Landing-page desktop pulses are small (7 px) in a wide diagram; making them
  more prominent would be a design change and was not made.
- `tests/installer/test_install.py` is Linux-only in practice (GNU `stat`);
  pre-existing.
