---
title: CLI Reference
description: sinter validate, plan, apply, audit, mcp — flags and exit codes.
---

```text
sinter <COMMAND>

Commands:
  validate  Validate a recipe without connecting to a target
  plan      Preview changes against a target without mutating it
  apply     Apply a recipe to a target
  audit     Audit whether a target already satisfies a recipe. Read-only.
  mcp       Serve a read-only MCP (Model Context Protocol) endpoint on stdio
```

See [Core MCP](/en/reference/mcp/) for the `mcp` subcommand and `--targets-file`.

`sinter --version` prints the version (e.g. `sinter 0.5.1`).

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

## audit

```sh
sinter audit <RECIPE> [target options] [--format text|json]
```

Verifies whether the target already satisfies the recipe. Audit is strictly
read-only: it uses the same observation paths as `plan`, never mutates,
never executes `command` resources, and never runs handlers.

The recipe is the sole desired-state authority — audit checks the state your
recipe describes, not a separate policy baseline. A recipe that manages
`/etc/ssh/sshd_config` is audited through its `file`/`template` resource
declarations; sshd run state is audited through the `service` resource.
There is no SSH-specific audit logic.

## Target options (plan / apply / audit)

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

## Reading audit output

An `audit` starts with `== Sinter AUDIT ==`. Each resource prints one status
line in deterministic dependency/execution order — a resource's dependencies
are reported before it — plus drift details or a reason where applicable:

```text
DRIFT  motd [file]
    content: observed=[redacted] desired=[redacted]
```

Content-related drift detail is conservatively redacted: audit reports
*that* content differs, never the content or its hashes.

| Status | Meaning |
|--------|---------|
| `PASS` | Observed state satisfies the desired state. |
| `DRIFT` | Observation established the desired state is not satisfied. |
| `NOT_AUDITABLE` | Cannot be verified without an action audit never performs — `command` resources are always `NOT_AUDITABLE` and are never executed. |
| `NOT_APPLICABLE` | The resource's `when` condition evaluated to false. |
| `ERROR` | A required observation could not be completed. Never reported as drift. |

The run ends with a `summary:` line (total, compliant, drifted,
not_auditable, not_applicable, errors) and a `status:` line
(`no_drift`, `drift`, or `indeterminate`).

Exit code `0` means "no detected drift and no observation errors" — it does
**not** mean every resource was verified. `NOT_AUDITABLE` stays visible in
the output and summary so unverified resources cannot silently pass.

With `--format json`, audit emits `{"mode", "status", "summary",
"resources"}` where per-resource `status` is one of `compliant`, `drift`,
`not_auditable`, `not_applicable`, `error`. See
[JSON output contract](#json-output-contract) for the full, stable shape.

Sensitive resources never print raw values: drift details render as
`redacted` and secrets never appear in text, JSON, reasons, or stderr.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Invocation completed (plan differences still exit 0; audit found no drift and no errors) |
| 2 | Validation/schema error |
| 3 | Target connection/capability/security error |
| 4 | Plan could not be completed safely |
| 5 | Apply failed |
| 6 | Indeterminate — apply became indeterminate, or audit recorded one or more `ERROR` results (errors dominate drift) |
| 7 | Audit detected drift with no observation errors |

## JSON output contract

`--format json` is available on `validate`, `plan`, `apply`, and `audit`.
From v1.0.0, everything documented in this section is a stable interface for
the whole 1.x series. `sinter mcp` is governed by the
[Core MCP](/en/reference/mcp/) reference instead.

### Framing and errors

- Output is one JSON object on stdout, followed by a newline. Nothing else is
  written to stdout in JSON mode.
- A document is written only when the command produces a report: `validate`
  on success (exit 0); `plan` and `apply` when the run completed (exit 0, 4,
  5, or 6); `audit` when the audit completed (exit 0, 6, or 7).
- When a command fails before producing a report — for example a schema
  error (exit 2) or a connection, capability, or security error (exit 3) —
  stdout is empty and one `sinter: …` line is written to stderr. The
  [exit code](#exit-codes) is the machine-readable error class; the stderr
  wording is not part of the contract.

### validate

| Field | Type | Values |
|-------|------|--------|
| `command` | string | `"validate"` |
| `status` | string | `"ok"` |
| `resources` | integer | Number of resources in the recipe. |
| `handlers` | integer | Number of handlers. |
| `vars` | integer | Number of vars. |

### plan and apply

| Field | Type | Values |
|-------|------|--------|
| `mode` | string | `"plan"` or `"apply"` |
| `status` | string | `success` (exit 0), `plan_error` (exit 4), `apply_failed` (exit 5), `indeterminate` (exit 6) |
| `facts` | object | `hostname`, `os_name`, `os_family`, `os_version`, `arch` — strings, as detected on the target |
| `resources` | array | One resource object per resource, in execution order. |
| `handlers` | array | Handler objects for handlers that ran (always empty in `plan`). |
| `handlers_pending` | array of strings | IDs of notified handlers that did not run. A `plan` lists every notified handler here. |

Resource object (`plan` and `apply`):

| Field | Type | Values |
|-------|------|--------|
| `id` | string | Resource ID from the recipe. |
| `type` | string | Resource type, e.g. `file`, `package`. |
| `loop_index` | integer or null | Iteration index for a loop-expanded resource; `null` otherwise. |
| `origin` | string | Where the resource was declared. The field is stable; its text is informational. |
| `execution` | string | `not_run`, `succeeded`, `failed`, `indeterminate` |
| `change` | string | `none`, `changed`, `possible` |
| `verification` | string | `not_applicable`, `not_performed`, `verified`, `failed`, `unknown` |
| `disposition` | string | `normal`, `skipped_by_condition`, `guard_satisfied`, `blocked_by_dependency`, `blocked_by_fail_fast` |
| `unknown` | boolean | `true` when current state was not fully observed (`?` in text output). |
| `sensitive` | boolean | `true` for a sensitive resource. |
| `reason` | string or null | Human-readable explanation; `"<redacted>"` for a sensitive resource. |
| `diff` | object or null | `null`, or an object whose `type` is `"redacted"`, `"summary"` (with `current`, `desired`), or `"text"` (with `removed`, `added`). |
| `notes` | array of strings | Human-readable notes; each is `"<redacted>"` for a sensitive resource. |

A resource is identified by `id` together with `loop_index`.

Handler object: `id` (string), `service` (string), `action` (string),
`state` (string: `NotRun`, `Succeeded`, `Failed`, or `Indeterminate`,
capitalized exactly as shown), and `reason` (string or null).

### audit

| Field | Type | Values |
|-------|------|--------|
| `mode` | string | `"audit"` |
| `status` | string | `no_drift` (exit 0), `drift` (exit 7), `indeterminate` (exit 6) |
| `summary` | object | Integers `total`, `compliant`, `drifted`, `not_auditable`, `not_applicable`, `errors`. |
| `resources` | array | One object per resource, in dependency/execution order. |

Resource object (`audit`): `id` (string), `type` (string), `loop_index`
(integer or null), `origin` (string, informational text), `status` (string:
`compliant`, `drift`, `not_auditable`, `not_applicable`, `error`),
`sensitive` (boolean), `reason` (string or null), and `details` (array of
objects with string fields `dimension`, `observed`, and `desired`; the
`observed` and `desired` values are human-readable and are `"[redacted]"`
for a sensitive resource).

### Compatibility rules

- **Stable in 1.x:** every field listed above, with its name, type,
  nullability, and documented values and their meaning; the status-to-exit-code
  mapping; the framing and error rules; resource identity; and resource
  order.
- **Additive changes** may appear in a 1.x minor release: new fields in any
  object, and JSON output for new commands. Consumers must ignore fields they
  do not recognize.
- **Breaking changes** happen only in a new major version:
  - removing or renaming a documented field;
  - changing a documented field's type or nullability;
  - removing a documented value or changing its meaning;
  - adding a value to a documented value set (the `status`, `execution`,
    `change`, `verification`, `disposition`, audit `status`, handler `state`,
    and `diff.type` sets are closed, so consumers can match them exhaustively);
  - changing the exit code of a status.
- **Not guaranteed:**
  - object key order, whitespace, and indentation;
  - undocumented fields;
  - the wording of human-readable text (`reason`, `notes`, diff bodies, audit
    `details` values, `origin`, and the formatting of `facts` values);
  - stderr messages and text-mode output.
- **Redaction is part of the contract.** Sensitive values never appear in
  JSON output; they are replaced by the markers listed above.

## SSH identity rules

- The selected `known_hosts` file is authoritative — unknown or changed host
  keys fail; there is no auto-enrollment or insecure fallback.
- Port 22 uses a portless `host` entry; other ports require `[host]:port`.
- Hashed `known_hosts` entries are not supported.
