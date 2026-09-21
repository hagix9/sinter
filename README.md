# Sinter

**English** | [日本語](README.ja.md)

**Documentation:** <https://hagix9.github.io/sinter/> ([日本語](https://hagix9.github.io/sinter/ja/))

**Small enough to understand, strong enough to trust.**

Sinter is a lightweight, agentless configuration-management tool inspired by Itamae.
It describes and applies operating-system configuration from a single Rust binary
without requiring an agent, Ruby, Python, or a Sinter runtime on the managed host.

## Why Sinter?

- **Agentless, single-binary controller**
  Managed hosts do not need a Sinter agent or runtime, nor a Ruby or Python runtime.

- **`plan` means observation only**
  `sinter plan` observes target state without uploading staging data, changing
  permissions or ownership, installing or removing packages, changing services,
  or executing command resources.

- **`apply` re-observes before mutation**
  A previous plan is never treated as authoritative current state. Stateful
  resources are observed again immediately before Sinter decides whether to mutate them.

- **Fail closed rather than guessing**
  Unsafe parent paths, unexpected symlinks, unknown or changed SSH host keys,
  failed verification, and indeterminate state do not silently continue as success.

- **Truthful result reporting**
  Sinter keeps execution, change, verification, and disposition distinct where
  necessary, preserving states such as changed, failed, indeterminate, possible,
  verified, and blocked instead of flattening everything into a boolean result.

- **Strict SSH identity checking**
  The selected `known_hosts` file is authoritative. Sinter does not automatically
  enroll unknown hosts or fall back to insecure verification. Non-default SSH ports
  require an explicit `[host]:port` identity.

- **Idempotent by design**
  When a stateful resource already matches the desired state, applying the same
  recipe again performs zero mutations for that resource.

## Quick example

```yaml
version: 1

resources:
  - id: tree
    type: package
    with:
      name: tree
      state: present
```

```sh
sinter validate recipe.yaml
sinter plan --host server.example.com recipe.yaml
sinter apply --host server.example.com --sudo recipe.yaml
sinter audit --host server.example.com --sudo recipe.yaml
```

This repository implements **Sinter v0.2** as specified by `GOALS.md` and
`DESIGN.md`, which are the authoritative specification; v0.2 extends the v0.1
contract with RHEL-family platform support (Rocky Linux, RHEL, AlmaLinux —
`dnf`). The
implementation still adds no features beyond that scope: no roles, plugins,
inventory, orchestration, or embedded scripting.

## Install

Sinter **v0.4.1** ships one `sinter-v0.4.1-linux-x86_64.tar.gz` artifact
covering every supported Linux x86_64 platform line, adding
acceptance-tested RHEL 9 / 10 and AlmaLinux 9 / 10 support to the
Ubuntu and Rocky lines.

```sh
curl -fsSL https://hagix9.github.io/sinter/install.sh | sh
$HOME/.local/bin/sinter --version
```

Acceptance-tested point releases (v0.4.1): Ubuntu 24.04.5 LTS,
Ubuntu 26.04.1 LTS, Rocky Linux 9.8, Rocky Linux 10.2, RHEL 9.8, RHEL 10.2,
AlmaLinux 9.8 and AlmaLinux 10.2, all x86_64. Other point releases have not
each been independently accepted.

The installer selects the latest stable official GitHub release, verifies
SHA256SUMS before extraction, and installs without sudo into `$HOME/.local/bin`.
If needed, add that directory to PATH yourself; shell profiles are not edited.
For inspect-before-run and manual downloads, see
[Installation](https://hagix9.github.io/sinter/en/getting-started/installation/).

## Build

```sh
cargo build --release
# binary: target/release/sinter
```

## Workflow

```sh
sinter validate recipe.yaml
sinter plan --host host.example recipe.yaml
sinter apply --host host.example recipe.yaml
sinter audit --host host.example recipe.yaml
```

- `validate` checks recipe structure and semantics without connecting to a target.
- `plan` performs observation only and produces a non-authoritative preview
  of what `apply` would change. It never writes files, uploads staging data,
  changes permissions/ownership, changes packages or services, or executes
  command resources.
- `apply` re-observes every stateful resource immediately before deciding
  whether to mutate it.
- `audit` is also read-only, but answers a different question: whether the
  target currently matches the recipe. It reports `PASS`/`DRIFT`/
  `NOT_AUDITABLE`/`NOT_APPLICABLE`/`ERROR` per resource — `command`
  resources are always `NOT_AUDITABLE` and never executed — and exits 7 on
  drift or 6 on observation errors.

Local targets are used when `--host` is omitted. SSH and passwordless `sudo -n`
are supported with `--host … --sudo`.

### CLI exit codes

| Code | Meaning |
|------|---------|
| 0 | invocation completed successfully (plan differences still exit 0; audit: no DRIFT and no ERROR — `NOT_AUDITABLE`/`NOT_APPLICABLE` resources may still be present) |
| 2 | validation/schema error |
| 3 | target connection/capability/security error |
| 4 | plan could not be completed safely |
| 5 | apply failed |
| 6 | apply became indeterminate; audit recorded one or more ERROR results (errors dominate DRIFT) |
| 7 | audit detected DRIFT with no ERROR results |

## Recipe model

YAML and TOML are frontends for one common semantic IR. Equivalent recipes in
either format produce equivalent typed values, resource identities, ordering,
desired state, ChangeSets, and execution behavior.

Top-level fields: `version`, `vars`, `include`, `resources`, `handlers`.

Resource types in v0.2: `file`, `directory`, `template`, `link`, `command`,
`package`, `service`. Handlers are delayed `restart`/`reload` service actions.

A minimal recipe:

```yaml
version: 1
vars:
  greeting:
    value: hello
    sensitive: false
resources:
  - id: motd
    type: template
    with:
      path: /etc/motd
      source: templates/motd
      mode: "0644"
    notify:
      - restart_motd
handlers:
  - id: restart_motd
    service: motd
    action: restart
```

## Security and safety properties

- Plan performs observation only and cannot mutate state.
- Apply re-observes state immediately before every mutation decision; a plan is
  never reused as current state.
- Stateful resources are idempotent: a second apply performs zero mutations.
- SSH accepts only hosts already present in the selected `known_hosts` file.
  Unknown or changed keys are connection failures; there is no insecure
  fallback or automatic enrollment.
- Remote commands preserve exact argv with no unintended shell evaluation.
  NUL bytes are rejected.
- `--sudo` runs every target-side operation with effective UID 0 via
  non-interactive `sudo -n`. Without it, everything runs as the target user.
  Sinter never retries a permission failure with sudo.
- Command resources use a fixed baseline environment (`PATH`, `LANG`, `LC_ALL`,
  `HOME`); controller, SSH-session, sudo, and login-shell environment variables
  are not inherited. Reserved names cannot be overridden by recipes.
- Filesystem mutations enforce a parent-path trust boundary, reject unexpected
  symlinks, preserve existing metadata when omitted, refuse to discard
  unsupported security metadata, and publish content atomically by rename.
- Indeterminate mutations (timeout after dispatch, lost response, signal
  uncertainty) are never retried automatically.
- Fail-fast: the first failed or indeterminate resource stops further execution
  and reports remaining resources as blocked.
- Sensitive values never appear in normal, verbose, diff, registered-result,
  diagnostics, or structured output. For sensitive content, hashes and sizes are
  hidden.
- Failed, indeterminate, verification-failure, and possible-change outcomes are
  reported truthfully.

## Supported platforms

Managed targets:

| Platform | Architecture | Package backend | Status |
|----------|--------------|-----------------|--------|
| Ubuntu 24.04 LTS | amd64 | apt | Supported, acceptance-tested |
| Ubuntu 26.04 LTS | amd64 | apt | Supported, acceptance-tested |
| Rocky Linux 9 | x86_64 | dnf | Supported, acceptance-tested |
| Rocky Linux 10 | x86_64 | dnf | Supported, acceptance-tested |
| RHEL 9 | x86_64 | dnf | Supported, acceptance-tested |
| RHEL 10 | x86_64 | dnf | Supported, acceptance-tested |
| AlmaLinux 9 | x86_64 | dnf | Supported, acceptance-tested |
| AlmaLinux 10 | x86_64 | dnf | Supported, acceptance-tested |
| Oracle Linux | x86_64 | dnf | Expected compatible — not acceptance-tested |

Package recipes are platform-neutral: the same `type: package` / `state:
present` resource is handled by `apt` on Ubuntu and `dnf` on RHEL-family
targets, selected from the detected `/etc/os-release` identity.

Oracle Linux is recognized as a Red Hat-family platform and uses Sinter's
DNF backend. It is expected to be compatible with the corresponding Red
Hat-family implementation, but it is not currently part of Sinter's
real-host acceptance matrix.

Sinter v0.4.1 was acceptance-tested on eight real x86_64 Linux hosts — the
exact point releases listed under [Install](#install). All eight hosts
executed the same frozen candidate binary and the same logical acceptance
scenario: **344/344 checks passed**. Earlier VM and release evidence remains
historical.

All managed targets require systemd, an OpenSSH server, `/bin/sh`, the `attr`
package (`/usr/bin/getfattr`, used to inspect extended attributes and POSIX
ACLs before any write — check `test -x /usr/bin/getfattr` on each target;
install `attr` with apt or dnf if missing), and passwordless `sudo -n` when privilege escalation
is required. The controller reference environments are macOS, Ubuntu 24.04
LTS, Ubuntu 26.04 LTS, Rocky Linux 9, Rocky Linux 10, RHEL 9, RHEL 10,
AlmaLinux 9, AlmaLinux 10, and other x86_64 Linux environments where the
binary builds.

## Testing

The test suite is split into unit tests (in `src/`) and integration/acceptance
tests (in `tests/`):

| Suite | Scope |
|-------|-------|
| lib unit tests | value model, frontends, expressions/Unknown, paths, argv quoting, package states |
| `frontends` | YAML/TOML equivalence and IR fixtures, schema rejection, includes |
| `engine` | file/directory/link/template, plan safety, idempotency, fail-fast, static identifiers |
| `commands` | guards, registers, changed_when, environment baseline, exit codes |
| `handlers` | delayed handlers, dedup, fail-fast, verification gating |
| `package_service` | apt install/remove/idempotency, systemd state/enabled combinations |
| `file_safety` | trust boundary, symlink rejection, metadata preservation, atomic publication, failure injection |
| `truthfulness` | result-dimension matrix, ordering, dependency blocks |
| `cli` | exit codes, JSON output, sensitive-output redaction |
| `ssh` | real SSH integration (known_hosts, sudo, argv exactness, timeouts, signals) |

Run the full suite on the reference target:

```sh
cargo test
```

SSH integration tests are enabled by environment variables pointing at a
disposable Ubuntu target:

```sh
export SINTER_TEST_SSH_HOST=127.0.0.1
export SINTER_TEST_SSH_PORT=22
export SINTER_TEST_SSH_USER=ubuntu
export SINTER_TEST_SSH_KNOWN_HOSTS=/path/to/known_hosts
export SINTER_TEST_SSH_IDENTITY=/path/to/test_key
cargo test --test ssh
```

External observation and an instrumented command log are both used to verify
plan performs no mutation and that idempotent second applies issue no mutation
operations.

## Repository layout

```text
src/
  value.rs         common semantic value model
  yaml.rs          YAML frontend (rejects aliases/anchors/merge/dupes/non-finite)
  toml_front.rs    TOML frontend (rejects datetimes/non-finite)
  document.rs      schema validation of parsed documents
  ir.rs            intermediate representation constants
  model.rs         include expansion, loops, static identifiers, graph validation
  expressions.rs   expression language, interpolation, Unknown semantics
  facts.rs         target fact model
  executor.rs      local/SSH execution, known_hosts, sudo, exact argv
  targetfs.rs      target filesystem trust checks and atomic publication
  resources.rs     resource implementations
  engine.rs        plan/apply engine, ordering, dependencies, handlers, fail-fast
  audit.rs         read-only audit engine (per-resource compliance/drift)
  result.rs        result dimensions (execution/change/verification/disposition)
  diff.rs          truthful, sanitized diff rendering
  output.rs        human and JSON rendering with sensitive redaction
  error.rs         error kinds and exit codes
  mcp.rs           read-only MCP stdio adapter (unreleased, mainline)
  main.rs          CLI
tests/             acceptance and integration test suites
```

## MCP interface (unreleased, mainline)

**Status:** mainline development after v0.4.1. `sinter mcp` is not part of any
released artifact.

`sinter mcp` serves a minimal, strictly **read-only** MCP (Model Context
Protocol) endpoint over stdio (newline-delimited JSON-RPC 2.0). It is a thin
adapter over the authoritative core — no validation, platform, or planning
rule is reimplemented.

Tools (all read-only; there is intentionally no apply/execute/install tool):

| Tool | Purpose |
|------|---------|
| `sinter_get_version` | Crate version and read-only capability statement. |
| `sinter_classify_platform` | Classify a target from `/etc/os-release` content (family, package backend) via the real platform model. |
| `sinter_validate_manifest` | Validate recipe text with the real `load_model` parser; structured diagnostics. |
| `sinter_inspect_manifest` | Structural recipe summary: resource identities, types, dependencies, sensitivity flags. Values are never returned. |
| `sinter_plan` | Plan a recipe against a **supplied-facts** target snapshot (`ubuntu2404`, `ubuntu2604`, `rocky9`, `rocky10`) using the in-process scripted target — production planning code, no SSH, no real host, `Mode::Plan` only. |
| `sinter_list_targets` | List the opaque names of administrator-configured SSH target profiles (names only — never connection details). |
| `sinter_plan_host` | Plan a recipe against a **named** SSH target profile: real-host read-only observation via the production `Mode::Plan` path. |
| `sinter_audit_host` | Audit whether a named SSH target satisfies a recipe via the production `run_audit` path. Read-only. |

Not available: apply, arbitrary command execution, or any mutation. Remote
access is possible **only** through administrator-configured named targets —
see below.

MCP manifests accept inline content only: `include:` and `source:` are
rejected on the parsed structure before loading in every manifest-consuming
tool, so a manifest never grants controller-local filesystem read authority.
This restriction is MCP-specific — ordinary CLI recipes keep full
`include:`/`source:` support.

Client configuration example (stdio servers):

```json
{ "mcpServers": { "sinter": { "command": "sinter", "args": ["mcp"] } } }
```

### Named targets (`--targets-file`)

`sinter mcp --targets-file targets.toml` enables real-host read-only
observation through an immutable, startup-loaded registry of named SSH
profiles. The MCP client may reference a target **only by its opaque name** —
it cannot supply host, port, user, known_hosts, identity files, sudo, or any
other connection parameter. Those are exclusively administrator-owned profile
policy.

```toml
[targets.web01]
host = "web01.example.com"
port = 22                    # optional, default 22
user = "deploy"
known_hosts = "/secure/path/known_hosts"
identity_files = ["/secure/path/id_ed25519"]  # optional
sudo = false                 # optional: profile-owned privilege policy

[targets.db01]
host = "10.0.0.20"
user = "ops"
known_hosts = "/secure/path/known_hosts"
sudo = true
```

- Profile names: `[A-Za-z0-9_-]`, start alphanumeric, max 64 chars.
- The file is parsed once at startup; a missing, unreadable, malformed, or
  structurally invalid file aborts `sinter mcp` with an error. No implicit
  default locations, no environment-variable discovery.
- Without `--targets-file`, the host tools are registered but fail closed:
  `sinter_list_targets` returns an empty list and plan/audit calls report
  `unknown target`.
- Host tools reuse the production Plan/Audit paths: `Mode::Plan` on a
  read-only `TargetFs` (mutation permits are unobtainable), command
  resources never execute, and `run_audit` additionally refuses any engine
  that could produce a permit.
- `sinter_list_targets` returns names only; underlying diagnostics are
  sanitized so profile internals (host, user, key paths) do not reach MCP
  output.
- An omitted or empty `identity_files` follows the existing Sinter SSH
  authentication behavior and may use default identity resolution; it does
  not disable authentication.
- Host plan output never returns file or template bodies: content diffs are
  redacted at the MCP boundary regardless of the manifest's `sensitive`
  flags.

This is unrelated to the documentation site's WebMCP surface (browser-side,
documentation lookup only); Core MCP exposes Sinter's own operations.

## License

Sinter is licensed under either of:

- Apache License, Version 2.0 (`LICENSE-APACHE`)
- MIT License (`LICENSE-MIT`)

at your option.
