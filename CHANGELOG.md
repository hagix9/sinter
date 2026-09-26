# Changelog

All notable changes to Sinter are documented in this file.

## [Unreleased]

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
