# Changelog

All notable changes to Sinter are documented in this file.

## [Unreleased]

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
