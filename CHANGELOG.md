# Changelog

All notable changes to Sinter are documented in this file.

## [Unreleased]

### Added

- `sinter secrets encrypt | decrypt | list` (not part of v1.1.3): encrypt and
  decrypt secret files in the standard age format, built on the encrypted-secret
  core. A standalone command: no recipe, resource, `plan`/`apply`/`audit` or MCP
  integration yet.
  - `encrypt` takes recipients (`-r`, or the nearest `recipients.txt` up to the
    repository root) or a passphrase (`--passphrase`, terminal only, echo off);
    input is opaque bytes up to 16 MiB; the output is written atomically
    (0600, synced), never replaces an existing file silently (`--force` replaces
    only an age file) and never writes through a symbolic link; the original is
    never changed or deleted.
  - `decrypt` writes plaintext to stdout only and refuses a terminal. Identities
    are found in this order: `--identity`, `SINTER_IDENTITY` (a path), the
    default `~/.config/sinter/identity` (outside any repository), then a
    passphrase-protected `identity.age` in the repository (explicit opt-in; a
    plaintext identity is never discovered in a repository). Plaintext identities
    must be mode 0600 and owned by the user.
  - `list` derives status, method and recipient count from age headers; it
    decrypts nothing.
  - Passphrases are accepted only on the terminal: never from argv, the
    environment or stdin. Automation uses recipients and identities.

- `group` and `user` resource types for **local** Linux accounts (not part of
  the v1.1.3 release).
  - `group`: `name`, `state` (`present`/`absent`, default `present`), `gid`,
    `system` (create-time only).
  - `user`: `name`, `state`, `uid`, `group` (primary, by name), `groups`
    (supplementary, by name, **additive**), `shell`, `home` (record only),
    `create_home` and `system` (create-time only).
  - Only declared dimensions are managed and audited. Observation uses
    `getent -s files`; an account that only another identity source (NSS)
    provides is an error, never a create. Every command is a fixed executable
    with explicit argv (`groupadd`, `groupdel`, `useradd`, `usermod`,
    `userdel`), never a shell.
  - An existing account is never renumbered (a `uid`/`gid` mismatch is
    refused in `plan`/`apply` and reported as `DRIFT` by `audit`), renamed, or
    have its home moved. Supplementary membership is never removed.
    `absent` runs `userdel`/`groupdel` without `-r`/`-f`; the home directory
    and mail spool are kept. Refused for root/uid 0, the account this run
    executes as, the session account, and a group that is some user's primary
    group.
  - Dependencies stay explicit. In `plan`, a `user` whose group is created by a
    `group` listed in its `depends_on`, and a `file`/`directory`/`template`
    whose `owner`/`group` names an account created by a `user`/`group` listed
    in its `depends_on`, are deferred (unknown until apply) instead of failing
    the plan. Without `depends_on` the plan error for an unknown account is
    unchanged.
  - Tests use a scripted fake target; behavior on real hosts of the supported
    distributions is pending real-OS acceptance.

## [1.1.3] - 2026-10-03

systemd manager synchronization and a service-stop fix. There is no new resource
type, handler action, recipe option or command-line flag; `--format json`
documents gain one additive key.

### Changed

- systemd manager synchronization. Sinter now runs `systemctl daemon-reload`
  itself when a `file`, `template` or `link` resource really changes systemd
  manager input (a unit file, a drop-in, an alias/mask/`.wants` link, or
  `system.conf` and its drop-ins) or when a fresh observation reports
  `NeedDaemonReload=yes`: before a `service` resource decides, before each
  notified handler runs, and at the end of a successful apply. A `service`
  or handler decision is always made on a fresh observation of the unit taken
  after the manager has been synchronized. The final reload at the end of an
  apply has no `service` or handler consumer, but it re-observes the managed
  units it identified; only a manager-only flush with no corresponding
  identifiable unit reports unit verification as not applicable. This is not
  a proof of global systemd consistency. `plan` and `audit` never reload, and
  an unchanged second apply performs none. A manual `daemon-reload` command
  resource is normally no longer needed. There is no new resource type,
  handler action or recipe option.
- Service observation now requests four properties
  (`LoadState,ActiveState,UnitFileState,NeedDaemonReload`) and rejects an
  answer that is missing, duplicating or malforming any of them. `audit`
  gains an independent `manager_reload` drift dimension.
- `--format json` plan/apply documents gain an additive top-level
  `manager_reloads` array. Existing keys and value sets are unchanged. The
  text output and the MCP plan tools report the reloads in the same way. A
  `plan` is still read-only: a `service` that depends on a pending manager
  input is reported as unknown (deferred until apply) instead of unchanged.
- Scope: the synchronization covers the system manager only (not
  `systemctl --user`), is local to one run, and keeps no persistent journal,
  rollback or retry. A reload that fails is reported as a failure, and the
  dependent `service` or handler does nothing.

### Fixed

- A `service` with `state: stopped` no longer fails after a successful stop of
  a unit that systemd has already unloaded (a running unit that is neither
  enabled nor referenced by another unit). `systemctl reset-failed` answering
  "Unit … not loaded." is accepted only when a fresh observation then shows the
  unit inactive; every other `reset-failed` failure is still a failure. A
  unit that is missing is still not treated as stopped.

### Documentation

- English and Japanese pages for the `service`, `file`, `template` and `link`
  resources, the execution model, the CLI and MCP references and
  troubleshooting describe the manager synchronization, its `plan` and
  `audit` behavior, its failure modes and its limits, with a unit → service →
  handler recipe example.

### Contributors

- [hagix9](https://github.com/hagix9)

## [1.1.2] - 2026-09-30

SSH security hardening, plus a stricter release validation gate. The only
change to the `sinter` runtime is the SSH algorithm policy below. Recipes,
command lines, and `--format json` documents are unchanged.

### Security

- SSH connections negotiate only modern algorithms. Key exchange, host key,
  cipher and MAC negotiation are restricted to explicit allowlists:
  curve25519, ECDH and SHA-2 Diffie-Hellman key exchange (group exchange
  with at least 2048-bit groups); Ed25519, ECDSA and RSA host keys with
  SHA-2 signatures; ChaCha20-Poly1305, AES-GCM and AES-CTR; HMAC-SHA2.
  The legacy fallbacks that the bundled libssh2 offered by default can no
  longer be negotiated: 1024-bit and SHA-1 key exchange, SHA-1 `ssh-rsa`
  host key signatures, CBC, RC4, Blowfish, CAST and 3DES ciphers, and MD5,
  SHA-1 and RIPEMD-160 MACs. Host certificate key types are no longer
  offered either, because `known_hosts` verification cannot validate them.
  There is no option to re-enable any of this. A server that offers only
  legacy algorithms is refused at the handshake (`Unable to exchange
  encryption keys`); current OpenSSH releases offer the allowed algorithms
  by default. RSA host keys keep working through `rsa-sha2-256` and
  `rsa-sha2-512`, and host key types already recorded in `known_hosts` are
  still tried first. The policy is installed before every handshake, and a
  failure to install it fails the connection.
- The public Gateway (`gateway/`, deployed separately and not part of the
  release artifact) validates JWTs with `jsonwebtoken` 10 (`aws_lc_rs`
  backend), with regression tests for `nbf` handling and the 2048-bit RSA
  key floor.

### Release validation

- The Linux validation gate runs the root test suite as `env
  SINTER_TEST_STRICT=1 SINTER_TEST_LOCAL_SSHD=1 cargo test --locked
  --all-targets --all-features`, and the acceptance checker requires exactly
  that command for every release after v1.1.1. In strict mode a test whose
  prerequisite is missing fails instead of being skipped and counted as
  passed; strict mode now also covers the throwaway-`sshd` suites and the
  extended-attribute and `script(1)` tests, which used to skip silently. The
  gate host is documented as Ubuntu 24.04 x86_64 with its prerequisites.
- The checker derives the root test harnesses and Linux-only suites from the
  candidate commit itself and requires the gate log to show every harness
  passing, adding up to the recorded counts, instead of trusting
  operator-supplied lists.
- Integration tests now prove the state they depend on before running:
  fixture setup steps that could fail silently (unit removal, private
  directory creation, seeded file contents, extended-attribute setup) are
  checked, and regression tests cover each.
- Per-commit CI builds (but does not run) the root test binaries and runs the
  gateway, installer and checker tests; a separate workflow scans
  dependencies for known advisories. The privileged root suite runs only in
  the release gate.

### Documentation

- Added `SECURITY.md` (private vulnerability reporting) and a contributing
  guide, and linked them from the README.

## [1.1.1] - 2026-09-29

Fail-closed validation fixes. Valid recipes, command lines, and `--format
json` documents are unchanged; recipes that could never run correctly are
now rejected by `validate` (exit 2) before anything connects, or fail
before any change is made.

### Fixed

- A `template` whose `state` resolved to a value other than `present` or
  `absent` was written as if it were `present`. It now fails before
  anything is observed or changed: `plan` exits 4 and `apply` reports the
  resource as failed.
- A `link` `state` other than `present` or `absent` was applied as
  `present`. It is now rejected.
- `validate` now rejects: a `file`, `directory`, `link`, or `template`
  `state` other than `present` or `absent`; a `link` whose `state` is
  `present` (or omitted) without a `target`; a literal string as a
  `service` `enabled` value; and a handler with an empty `service`.
  Previously these were accepted and failed only when the resource ran. An
  interpolated value is still checked when it is resolved.
- Mutating `systemctl` calls (`start`, `stop`, `enable`, `disable`,
  `reset-failed`, and handler `restart`/`reload`) now pass the unit name
  after `--`, as service observation already did, so a unit name beginning
  with `-` can never be read as a `systemctl` option.
- Documentation: corrected stale statements (the current release in
  `llms.txt`, the `validate` summary in the CLI reference, the WebMCP page's
  description of Sinter's own MCP server, hashed `known_hosts` and inventory
  on the supported-platforms page, `link` `target` requiredness in the
  resource metadata, and the agent skill's top-level recipe fields and
  target-option defaults) and four GitHub links missing the repository
  name.

## [1.1.0] - 2026-09-28

A small, fail-closed foundation for managing several hosts, plus SSH that
follows the operator's OpenSSH setup. Existing single-host command lines,
recipes, and `--format json` documents are unchanged.

### Added

- Inventory (`--inventory <file>`, alias `--hosts`): hosts and flat host
  groups in YAML or TOML. A host in the inventory is never a target by
  itself.
- Recipe `targets` (`hosts` / `groups`, union). With `--inventory`, a recipe
  without `targets`, an unknown host or group name, or a selection of zero
  hosts is an error before anything connects. Plan/apply/audit print the
  target resolution (MATCH/SKIP per host).
- Recipe bundles (`version: 1`, `recipes: [...]`): several recipes in one
  invocation, each resolved against its own `targets`; no nesting.
- Multi-host execution: (recipe, host) pairs run one at a time; `plan` and
  `audit` visit every selected host, `apply` stops at the first execution
  that exits non-zero (later executions are `not_run`); the
  exit code is the most severe execution code, so a partial failure is never
  0. JSON output is one document per invocation.
- Recipe `backup.paths`: copied on each selected target before `apply`
  changes anything (`~/.sinter/backups/<run-id>/` or, with `--sudo`,
  `/var/lib/sinter/backups/<run-id>/`), preserving mode, ACLs, ownership and
  timestamps. A failed backup stops the apply before any resource runs.
  Backups are not a rollback.
- OpenSSH client configuration inheritance for `--host` and inventory hosts
  through `ssh -G`: HostName, User, Port, IdentityFile, IdentitiesOnly,
  IdentityAgent, HostKeyAlias, UserKnownHostsFile. `--no-ssh-config`
  disables it. ProxyJump/ProxyCommand fail closed.
- Structured multi-host evidence: with `--inventory` or a bundle, `--format
  json` prints one document per invocation with the target resolution
  (selected/excluded hosts and why) and, per execution, the recipe, the
  target identity (inventory name, address, port, user), status, exit code,
  the single-target document or error, and a backup record (`planned`,
  `completed`, `failed`, `not_started`, `not_run`, or `null`). File content
  never appears in it. Single-target documents are unchanged.
- Colored status words on terminals only (respects `NO_COLOR`, `TERM=dumb`;
  never in pipes or JSON).

### Changed

- `validate` accepts every target option (`--host`, `--inventory`, SSH
  options) and ignores it; it reads no inventory, key or known_hosts file.
  Unknown options are still rejected.
- `--port` no longer defaults to 22 on the command line; the default comes
  from the inventory or OpenSSH configuration, then 22.
- Default identity files are `~/.ssh/id_ed25519`, `id_ecdsa`, `id_rsa`
  (`id_ecdsa` was not tried before).
- SSH authentication failures now say what was tried (agent, key files) and
  that passphrase-protected keys need ssh-agent.

### Fixed

- A host enrolled in `known_hosts` with only its Ed25519 or RSA key was
  refused as a "host key mismatch" when the server also offered ECDSA:
  known key types are now negotiated first.
- Hashed (`|1|...`) `known_hosts` entries are supported.
- Keys on `@revoked` lines in `known_hosts` are refused (they were ignored).
- Landing page: on narrow screens the audit pulse of the architecture
  diagram moved sideways across the vertical SSH line; it now travels along
  it like the other pulses.

### Not included

ProxyJump/ProxyCommand (such hosts fail closed), dynamic inventory, nested
groups, host or group variables, host patterns, parallel execution,
rollback or restore, and backup retention are not part of this release.

## [1.0.0] - 2026-09-27

First stable release. It declares the 1.x compatibility contract for the
`--format json` output and puts every release from here on behind a
mandatory Linux validation gate and published, independently verifiable
acceptance evidence. The `sinter` source is unchanged from 0.5.1 apart from
the version; configuration management behavior is unchanged.

### Added

- Documented the v1 machine-readable output contract for `--format json` on
  `validate`, `plan`, `apply`, and `audit`, with 1.x compatibility rules, and
  added contract tests for it. Output is unchanged.
- Acceptance evidence retention for v1.0.0 candidates onward
  (`release/ACCEPTANCE_EVIDENCE.md`): an Evidence Manifest, a published
  evidence bundle, acceptance checksums, and a checker
  (`release/check_acceptance_manifest.py`) with offline threat-model tests
  (`release/tests/`). The checker verifies the bundle archive in memory
  (containment, completeness, no links or special files), the artifact and
  executable hashes, the acceptance checksums, all eight required targets,
  the Linux validation gate record, and a sensitive-data scan.
- `RELEASE.md` is now a single ordered release state machine: source
  candidate, metadata, source validation, a mandatory Linux x86_64
  validation gate, one build and freeze, acceptance of that exact artifact,
  evidence and checker, human review, then tag and publish, with explicit
  invalidation rules.

### Fixed

- Documentation now attributes the current support claim to the v0.5.1
  release artifact (eight hosts, 344 checks passed, 0 failed); the v0.4.1
  acceptance is kept as history.
- The documentation site no longer defines each legacy redirect twice, which
  removes the route-collision warnings from the docs build. The generated
  site is unchanged.

## [0.5.1] - 2026-09-27

MCP tool annotations for the read-only `sinter mcp` interface, plus ChatGPT
Plugin documentation and public Gateway operator tooling. No change to
configuration management behavior.

### Added

- MCP tool annotations: every `sinter mcp` tool now declares
  `readOnlyHint: true`, `destructiveHint: false`, and `openWorldHint: false`,
  making the existing read-only guarantee explicit to MCP clients (required
  for ChatGPT plugin directory review). Tool behavior is unchanged.
- Documentation: ChatGPT Plugin guide (English and Japanese) covering the
  public Gateway / `sinter-bridge` architecture, setup, troubleshooting, and
  security/privacy, plus a README section.
- Gateway operator onboarding: `gateway/scripts/sinter-gw-admin` wraps the
  existing `sinter-gateway` operator CLI with account validation, an
  existing-controller pre-check, confirmation, `--dry-run`, and read-only
  `list`/`status`; `gateway/scripts/sinter-gw-admin-selftest` checks the
  issue → register → revoke path against a throwaway local Gateway;
  `gateway/docs/OPERATOR_ONBOARDING.md` is the operator runbook.
- `gateway/contrib/systemd/`: user unit and environment template for running
  `sinter-bridge` on Linux.

### Fixed

- `gateway/docs/PRODUCTION_DEPLOYMENT.md`: the bridge bootstrap ran
  `sinter-bridge register` twice; the first run consumed the single-use
  registration token. It now runs once and writes the credential file.

### Changed

- Gateway operator docs: administrative SSH to the Gateway host goes through
  IAP (`gcloud compute ssh --tunnel-through-iap`); the onboarding example sets
  `SINTER_GW_ADMIN_GCE_IAP=1`, and the break-glass path is documented.

## [0.5.0] - 2026-09-22

Core MCP: a read-only Model Context Protocol interface over stdio.

### Added

- `sinter mcp`: a strictly read-only MCP server speaking newline-delimited
  JSON-RPC 2.0 (protocol revision `2025-03-26`) over stdio. It is a thin
  adapter over the authoritative parser, planner, and audit engine — no
  validation or planning rule is reimplemented. stdout carries protocol
  frames only; diagnostics go to stderr.
- Eight read-only tools: `sinter_get_version`, `sinter_classify_platform`,
  `sinter_validate_manifest`, `sinter_inspect_manifest`, `sinter_plan`
  (supplied-facts in-process targets — no SSH), `sinter_list_targets`,
  `sinter_plan_host`, and `sinter_audit_host`. There is intentionally no
  apply, exec, or shell tool, and no mutation capability is exposed.
- Named target profiles via `sinter mcp --targets-file targets.toml`: an
  immutable, startup-loaded registry of administrator-owned SSH profiles.
  MCP callers reference targets by opaque name only — host, port, user,
  known_hosts, identity files, and sudo policy can never be supplied or
  overridden through tool arguments. `sinter_plan_host` and
  `sinter_audit_host` observe real hosts through the production `Mode::Plan`
  and `run_audit` paths; strict `known_hosts` verification and the existing
  bounded SSH behavior are unchanged.

### Security

- Read-only is enforced structurally, not by convention: host tools run on a
  `Mode::Plan` `TargetFs` that cannot produce a mutation permit, and
  `run_audit` independently refuses any mutation-capable engine. Command
  resources are never executed and audit as `NOT_AUDITABLE`.
- MCP manifests accept inline content only. `include:` and `source:` are
  rejected on the parsed structure before loading, so an MCP manifest grants
  no controller-local filesystem read authority. Staging uses a private
  0700 directory and a `create_new` 0600 manifest file.
- Profile internals (host, user, key paths) and staged paths are redacted
  from tool-facing diagnostics; host-plan file/template content diffs are
  always redacted regardless of manifest sensitivity flags.

### Changed

- Remote `systemctl show` observation now terminates option parsing with
  `--` before the unit name, so a manifest-controlled unit name can never
  be interpreted as a systemctl option.
- The documentation site gained a refreshed landing page, sidebar
  containment fixes, and a README terminal demo.

## [0.4.1] - 2026-09-21

Expanded acceptance-tested Linux x86_64 platform coverage and a more robust
DNF package path.

### Added

- RHEL 9 and RHEL 10 x86_64 as supported, acceptance-tested targets (`dnf`
  backend).
- AlmaLinux 9 and AlmaLinux 10 x86_64 as supported, acceptance-tested
  targets (`dnf` backend).
- DNF transaction-table parsing now accepts the wrapped header DNF emits
  when a repository ID is too long to fit on one line.

### Changed

- RPM payload acquisition now uses the native `dnf`/librepo download
  transport instead of direct URL fetching, so repository authentication —
  including authenticated cloud repository services — works without any
  Sinter-specific credential handling. Each downloaded RPM's identity is
  verified against the frozen transaction set before the final cache-only
  `dnf` install; if completeness or identity cannot be proven, the
  operation fails closed before mutation.

### Acceptance

- Sinter v0.4.1 was acceptance-tested on eight real x86_64 Linux hosts —
  Ubuntu 24.04.5 LTS, Ubuntu 26.04.1 LTS, Rocky Linux 9.8, Rocky Linux
  10.2, RHEL 9.8, RHEL 10.2, AlmaLinux 9.8, and AlmaLinux 10.2 — running
  the same frozen candidate binary and the same logical acceptance
  scenario: 344/344 checks passed, including the previously accepted
  Ubuntu and Rocky targets without regression.

## [0.4.0] - 2026-09-20

Read-only audit workflow, a verified Linux x86_64 installer, and Ubuntu
26.04 coreutils compatibility.

### Added

- `sinter audit <recipe>`: read-only audit mode answering whether the
  target currently matches the recipe. Reports `PASS`/`DRIFT`/
  `NOT_AUDITABLE`/`NOT_APPLICABLE`/`ERROR` per resource — `command`
  resources are always `NOT_AUDITABLE` and never executed, `when`-skipped
  resources are `NOT_APPLICABLE` — with deterministic dependency order,
  text and JSON output, and sensitive-value redaction. Exit codes: 0 when
  clean (non-auditable/skipped resources may still be present), 7 on drift,
  6 when one or more observation errors dominate.
- Hardened remote observation contracts in `src/targetfs.rs`: `stat`
  diagnostics are accepted only on exact program identity, exact quoted
  path, and whole-field message text on a single newline-terminated line
  with empty stdout; truncation, multiline output, wrong errno suffixes,
  and unrelated diagnostics remain ambiguous and fail closed.
- `install.sh`: verified Linux x86_64 installer that selects the latest
  stable GitHub release (or a `SINTER_VERSION` pin), verifies SHA256SUMS
  before extraction, and installs into `$HOME/.local/bin` (or
  `SINTER_INSTALL_DIR`) without sudo — atomically replacing an existing
  user-owned executable and refusing symlinks and non-regular objects.
  Covered by `tests/installer/test_install.py` against a mocked release
  server, including rejection of traversal, `;`, and multiline versions.

### Fixed

- Ubuntu 26.04 Rust coreutils emit errno-suffixed `stat` diagnostics
  (`No such file or directory (os error 2)`); the absence classifier now
  accepts the exact `No such file or directory`/errno-2 and
  `Not a directory`/errno-20 pairs and stays fail-closed for any other
  suffix, message, or shape.
- The installer rejects multiline destination values before any mutation.

### Changed

- Documentation integrates `audit` into the validate → plan → apply →
  audit workflow across README EN/JA and the documentation site, and
  improves first-recipe guidance.

## [0.3.0] - 2026-09-19

Platform extension: Ubuntu 26.04 LTS and Rocky Linux 10 support, plus a
unified Linux x86_64 release artifact.

### Added

- **Ubuntu 26.04 LTS amd64** managed-target support. Detection is unchanged
  in substance: `src/facts.rs` derives the family from `/etc/os-release`
  `ID`/`ID_LIKE` with no version gate, so 26.04 resolves to `debian` and the
  `apt` backend exactly like 24.04. Real-host acceptance on Ubuntu 26.04.1
  x86_64 passed for command, file, template, package, and service resources,
  plan/apply idempotency, and converge-back purge idempotency.
- **Rocky Linux 10 x86_64** managed-target support (family resolves to
  `redhat`, `dnf` backend). The dnf snapshot-install contract built for dnf
  4.14 on Rocky 9 holds unchanged on dnf 4.20 / rpm 4.19, verified by
  on-target output captures (`repolist -v`, `install --assumeno`,
  `repoquery --location`) and a full real-host acceptance matrix on
  Rocky Linux 10.2 x86_64.
- Actionable error when the target lacks `/usr/bin/getfattr`: filesystem
  resources still fail closed (DESIGN §24.4), but the refusal now names the
  missing program and the `attr` package that provides it. Stock Ubuntu
  cloud images ship no `attr` package, so this is a documented target
  prerequisite.
- `tests/platform_next.rs`: backend selection, apt argv, dnf snapshot
  contract, and rpm 4.19 absent-marker classification for the two new
  targets, plus real `/etc/os-release` parser fixtures for both.
- Integration suites are now family- and unit-name-agnostic (they discover
  the controller's `ssh`/`sshd` unit and OS family), so they execute
  truthfully on both Debian- and RHEL-family controllers.

### Changed

- Linux x86_64 release artifacts are unified into one
  `sinter-v${VERSION}-linux-x86_64.tar.gz` built on the oldest supported
  baseline (Rocky Linux 9 x86_64, glibc 2.34) and verified, byte-identical,
  on Ubuntu 24.04, Ubuntu 26.04, Rocky Linux 9, and Rocky Linux 10. The
  previous per-target `ubuntu24.04-amd64` and `rocky9-x86_64` artifacts are
  superseded for future releases; published v0.2.0/v0.2.1 assets are not
  renamed or re-released. See `RELEASE.md` Phase D for the required
  per-target extraction/run verification.

### Validation

- Linux-native `cargo test` executed on Ubuntu 26.04.1 x86_64, Ubuntu 24.04.4
  x86_64, and Rocky Linux 9.8 x86_64, including the previously compile-only
  Linux-gated integration suites and the SSH suite against a real loopback
  target. `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings`
  clean.
- Exact-binary experiment: one Rocky-9-built binary (SHA-256
  `af6b3384025c7033b16b26a664e11b73dd527156cd5e1d81d79d835a92f73fc2`)
  executed on all four supported Linux x86_64 platforms with identical
  checksums, `ldd` resolution, and a non-mutating `plan` on each.

- Frozen unified candidate from source `acbca6f8c726b4aed94c0b0b87c8a5506a4795af`
  passed the full four-real-host matrix on Ubuntu 24.04.5 LTS, Ubuntu 26.04.1
  LTS, Rocky Linux 9.8, and Rocky Linux 10.2 (all x86_64), including xattrs,
  applicable SELinux preservation, guard/refusal/redaction, idempotency and
  cleanup. This qualifies the candidate, not an already-published unified asset.

## [0.2.1] - 2026-09-17

Maintenance release adding explicit per-operation environment variables to
package resources.

### Added

- Optional `with.env` maps for package resources. Variables are passed to the
  selected `apt` or `dnf` operation, including privileged execution, without
  changing the host-wide environment.
- Environment variable names are validated and values are handled through the
  existing structured command and sensitive-value redaction paths.

### Validation

- Ubuntu 24.04.4 x86_64 / apt and Rocky Linux 9.8 x86_64 / dnf real-host
  acceptance passed, including plan safety, sudo propagation, idempotency,
  and sensitive-output checks.
- Forced-proxy/Squid connectivity was not part of this release acceptance.

## [0.2.0] - 2026-09-16

Second release of Sinter: RHEL-family platform support while preserving the
v0.1 contract on Ubuntu.

### Added

- RHEL-family platform detection from `/etc/os-release`.
- Rocky Linux 9 x86_64 support (`dnf` package backend, `systemd`).
- DNF package observation, install, and removal through the same
  platform-neutral `type: package` recipe contract; the backend (`apt` or
  `dnf`) is selected from the detected platform.

### Changed / improved

- Package installation on RHEL-family targets runs through a private snapshot
  of the DNF metadata cache: cache-only metadata validation and transaction
  resolution, validated RPM payload prefetch, then the final cache-only `dnf`
  mutation.
- DNF output is parsed under strict per-command grammars compatible with
  native DNF 4.14 streams, including real `repolist -v` preambles, benign
  informational stderr lines, and `--assumeno` transaction trailers.

### Security and safety

- DNF output parsing fails closed on malformed, ambiguous, or unexpected
  output.
- The private metadata snapshot is created with 0700 permissions and removed
  after the operation, including on failure.
- Mutation, cleanup, and verification outcomes are reported truthfully,
  including failure-after-mutation.
- Sensitive and derived-sensitive values remain redacted in output,
  diagnostics, and errors.
- Ubuntu 24.04 LTS behavior is unchanged.

### Supported environment

- Ubuntu 24.04 LTS amd64 — apt, systemd, OpenSSH, `/bin/sh`, passwordless
  `sudo -n` when privilege escalation is required (existing target).
- Rocky Linux 9 x86_64 — dnf, systemd, OpenSSH, `/bin/sh`, passwordless
  `sudo -n` when privilege escalation is required (new in v0.2.0).

Rocky Linux 9 acceptance reference: Rocky Linux 9.8 x86_64, DNF 4.14.0.
Other Rocky 9 minor releases share the same interfaces; 9.8 is the verified
reference.

### Validation

- Rocky Linux 9.8 x86_64 final acceptance: real SSH, `sudo -n`, package
  install/remove/idempotency, file/service/command resources, sensitive-output
  redaction, and failure-truth verification against DNF 4.14.0.
- Automated test suite green; fmt/clippy/diff-check clean.

### Known limitations

- No inventory, roles, plugins, orchestration, or embedded scripting.
- Hashed `known_hosts` entries are not supported.
- Managed hosts require no Sinter agent or runtime.

## [0.1.0] - 2026-09-13

First public release of Sinter.

### Added

- Agentless configuration management over SSH.
- `validate`, `plan`, and `apply` workflows.
- YAML and TOML recipe frontends.
- File, directory, template, link, command, package, and service resources.
- Resource dependencies, loops, variables, and delayed service handlers.
- Idempotent stateful resource management.
- Ubuntu 24.04 LTS amd64 support.
- `apt` package management.
- `systemd` service management.
- OpenSSH transport with strict `known_hosts` verification.
- Non-interactive privilege escalation through `sudo -n`.
- Text and JSON output.
- Sensitive-value redaction.
- Fail-fast execution and explicit failed/indeterminate result reporting.
- Atomic file publication and filesystem parent-path safety checks.

### Security and safety

- Plan mode performs observation only and does not mutate target state.
- Apply re-observes resources immediately before mutation decisions.
- Unknown or changed SSH host keys are rejected.
- Non-default SSH ports require an explicit `[host]:port` identity.
- Unexpected symlinks and unsafe parent paths are rejected.
- Indeterminate mutations are not automatically retried.
- Verification failures are promoted to failed execution where appropriate.

### Supported environment

The v0.1 reference target is:

- Ubuntu 24.04 LTS
- amd64
- OpenSSH
- apt
- systemd
- `/bin/sh`
- passwordless `sudo -n` when privilege escalation is required

### Known limitations

- RHEL-family distributions are not supported in v0.1.
- Hashed `known_hosts` entries are not supported.
- Sinter does not provide inventory, roles, plugins, orchestration, or embedded scripting.
- Managed hosts require no Sinter agent or runtime.
