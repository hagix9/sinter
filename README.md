# Sinter

Sinter is a lightweight, agentless configuration-management tool inspired by
Itamae. It describes and applies operating-system configuration from a single
Rust binary without requiring an agent, Ruby, Python, or a Sinter runtime on the
managed host.

Guiding phrase: **Small enough to understand, strong enough to trust.**

This repository implements **Sinter v0.1** as specified by `GOALS.md` and
`DESIGN.md`, which are the authoritative specification. The implementation does
not add features beyond v0.1 scope (no roles, plugins, inventory, orchestration,
or embedded scripting).

## Build

```sh
cargo build --release
# binary: target/release/sinter
```

## Workflow

```sh
sinter validate recipe.yaml
sinter plan   recipe.yaml --host host.example
sinter apply  recipe.yaml --host host.example
```

- `validate` checks recipe structure and semantics without connecting to a target.
- `plan` performs observation only and produces a non-authoritative preview.
  It never writes files, uploads staging data, changes permissions/ownership,
  changes packages or services, or executes command resources.
- `apply` re-observes every stateful resource immediately before deciding
  whether to mutate it.

Local targets are used when `--host` is omitted. SSH and passwordless `sudo -n`
are supported with `--host … --sudo`.

### CLI exit codes

| Code | Meaning |
|------|---------|
| 0 | invocation completed successfully (plan differences still exit 0) |
| 2 | validation/schema error |
| 3 | target connection/capability/security error |
| 4 | plan could not be completed safely |
| 5 | apply failed |
| 6 | apply became indeterminate |

## Recipe model

YAML and TOML are frontends for one common semantic IR. Equivalent recipes in
either format produce equivalent typed values, resource identities, ordering,
desired state, ChangeSets, and execution behavior.

Top-level fields: `version`, `vars`, `include`, `resources`, `handlers`.

Resource types in v0.1: `file`, `directory`, `template`, `link`, `command`,
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

## Reference environment

The mandatory integration target is Ubuntu 24.04 LTS amd64/aarch64 with systemd,
apt, OpenSSH server, `/bin/sh`, and passwordless `sudo -n`. The controller
reference environments are macOS, Ubuntu 24.04 LTS, and other environments where
the binary builds.

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

```
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
  result.rs        result dimensions (execution/change/verification/disposition)
  diff.rs          truthful, sanitized diff rendering
  output.rs        human and JSON rendering with sensitive redaction
  error.rs         error kinds and exit codes
  main.rs          CLI
tests/             acceptance and integration test suites
```
