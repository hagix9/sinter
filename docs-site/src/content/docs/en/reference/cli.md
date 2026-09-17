---
title: CLI Reference
description: sinter validate, plan, apply — flags and exit codes.
---

```text
sinter <COMMAND>

Commands:
  validate  Validate a recipe without connecting to a target
  plan      Preview changes against a target without mutating it
  apply     Apply a recipe to a target
```

`sinter --version` prints the version (e.g. `sinter 0.2.1`).

## validate

```sh
sinter validate <RECIPE> [--format text|json]
```

Checks recipe structure and semantics without contacting any target. Exits 0
on success.

## plan

```sh
sinter plan <RECIPE> [target options]
```

Observation only — connects, observes state, prints a non-authoritative
preview. Never mutates.

## apply

```sh
sinter apply <RECIPE> [target options]
```

Re-observes state, applies changes, verifies outcomes, runs notified
handlers.

## Target options (plan / apply)

| Flag | Default | Description |
|------|---------|-------------|
| `--host <HOST>` | localhost | SSH host. Omit for local execution. |
| `--port <PORT>` | `22` | SSH port. |
| `--user <USER>` | `$USER` | SSH user. |
| `--known-hosts <PATH>` | `~/.ssh/known_hosts` | Host-key database (strict). |
| `--identity <PATH>` | — | Identity file; repeatable. |
| `--sudo` | off | Run target-side operations via `sudo -n`. |
| `--verbose` | off | Verbose output. |
| `--format` | `text` | `text` or `json`. |

## Reading plan / apply output

A `plan` starts with `== Sinter PLAN ==`, an `apply` with
`== Sinter APPLY ==`, followed by a `target facts:` line (hostname, OS,
family, version, architecture as detected on the target). Each resource then
prints one status line plus, where applicable, a diff and a reason:

```text
CHANGED  motd [template] known/normal
    + managed by sinter
    - (previous content)
```

| Status | Meaning |
|--------|---------|
| `ok` | Resource already matched the desired state — nothing was mutated. |
| `CHANGED` | Resource was mutated (or, in `plan`, would be mutated). |
| `POSSIBLE` | A change may have occurred but could not be confirmed. |
| `FAILED` | Resource failed — remaining resources are blocked (fail-fast). |
| `INDET` | Mutation outcome is unknown (e.g. timeout after dispatch); never auto-retried. |
| `skip` | Resource's `when` condition evaluated to false. |
| `guard` | A `creates`/`removes` guard already satisfied — command not run. |
| `blocked` | Resource was not run because an earlier resource failed/was indeterminate, or a dependency was not satisfied. |
| `?` | Result is unknown (e.g. a `command` resource in `plan`, which never executes commands). |

The `known/` prefix shows whether the resource's current state was fully
observed (`known`) or is partly unknown (`unknown`). Handlers, when they run,
are listed at the end under `handlers:`; handlers queued but not executed
appear under `pending handlers`.

Quick answers:

- **Did Sinter change anything?** Look for `CHANGED` lines; a converged run
  shows only `ok` (plus `skip`/`guard`).
- **Did plan only observe?** `plan` prints the same statuses but performs no
  mutation — a pending change appears as `CHANGED` in the plan output while
  the target stays untouched.
- **Was something skipped or blocked?** `skip` means your own `when` chose it;
  `blocked` means an earlier problem prevented it.
- **Is a result unknown?** `?` or `POSSIBLE` / `INDET` — inspect the target
  before re-applying.

`--format json` emits the same information in structured form. In a `plan`,
notified handlers are always reported as pending — a plan never executes
handlers.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Invocation completed (plan differences still exit 0) |
| 2 | Validation/schema error |
| 3 | Target connection/capability/security error |
| 4 | Plan could not be completed safely |
| 5 | Apply failed |
| 6 | Apply became indeterminate |

## SSH identity rules

- The selected `known_hosts` file is authoritative — unknown or changed host
  keys fail; there is no auto-enrollment or insecure fallback.
- Port 22 uses a portless `host` entry; other ports require `[host]:port`.
- Hashed `known_hosts` entries are not supported.
