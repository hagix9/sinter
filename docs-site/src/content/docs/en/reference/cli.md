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

`sinter --version` prints the version (e.g. `sinter 1.1.0`).

## validate

```sh
sinter validate <RECIPE|BUNDLE> [--format text|json] [target options]
```

Checks recipe structure and semantics without contacting any target. Exits 0
on success. The result depends only on the recipe: the
[target options](#target-options) are accepted so the same command line works
for every phase, and are ignored — no host is contacted, no inventory,
key, or `known_hosts` file is read, and `ssh` is not run. Unknown or
misspelled options are still rejected.

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

## Target options

Accepted by `validate`, `plan`, `apply` and `audit`; `validate` ignores them.

| Flag | Default | Description |
|------|---------|-------------|
| `--host <HOST>` | localhost | SSH host or `~/.ssh/config` `Host` alias. Omit for local execution. |
| `--inventory <PATH>` (alias `--hosts`) | — | Hosts and groups; each recipe runs only on the hosts its `targets` select. See [Multiple hosts](#multiple-hosts). Mutually exclusive with `--host`. |
| `--port <PORT>` | inventory, ssh_config `Port`, else `22` | SSH port. |
| `--user <USER>` | inventory, ssh_config `User`, else `$USER` | SSH user. |
| `--known-hosts <PATH>` | inventory, ssh_config `UserKnownHostsFile`, else `~/.ssh/known_hosts` | Host-key database (strict). |
| `--identity <PATH>` | inventory, ssh_config `IdentityFile`, else `~/.ssh/id_ed25519`, `id_ecdsa`, `id_rsa` | Identity file; repeatable; replaces the inherited list. |
| `--no-ssh-config` | off | Do not consult the OpenSSH client configuration. |
| `--sudo` | off | Run target-side operations via `sudo -n`. |
| `--verbose` | off | Verbose output. |
| `--format` | `text` | `text` or `json`. |

### OpenSSH configuration

*Available from Sinter v1.1.0.*

If `ssh <host>` works, `sinter plan recipe.yaml --host <host>` uses the same
connection parameters. Sinter asks the installed OpenSSH client to evaluate
its configuration (`ssh -G <host>`, which does not connect) and inherits
`HostName`, `User`, `Port`, `IdentityFile`, `IdentitiesOnly`, `IdentityAgent`,
`HostKeyAlias` and the first `UserKnownHostsFile`. The SSH connection itself
is still made by Sinter's built-in transport.

- Precedence, per setting: explicit CLI option > inventory host field >
  OpenSSH configuration > built-in default.
- Host-key policy is never inherited: `StrictHostKeyChecking`,
  `UpdateHostKeys` and similar settings cannot relax the rules in
  [SSH identity rules](#ssh-identity-rules).
- `ProxyJump` / `ProxyCommand` are not supported; a host that uses them fails
  with exit 3 instead of being connected to directly.
- Keys: Ed25519, ECDSA and RSA keys (OpenSSH or PEM format) work from files.
  Passphrase-protected keys are used only through `ssh-agent` (`ssh-add`
  them first); Sinter never prompts. Agent keys are tried first, keys that
  match configured identity files before others; `IdentitiesOnly yes` offers
  only those.
- `--no-ssh-config` skips all of this. Without an installed `ssh` client,
  the built-in defaults apply.

## Multiple hosts

*Available from Sinter v1.1.0.*

Three pieces, each explicit:

1. an **inventory** says which hosts exist (and groups of them);
2. each **recipe** says which of them it may run on (`targets`);
3. the command line names both.

A host being in the inventory never makes it a target.

```yaml
# hosts.yaml
hosts:
  web01:
    address: 10.0.0.11     # optional; defaults to the name (can be an ~/.ssh/config alias)
    user: ubuntu           # optional: port, user, known_hosts, identity_files
  web02:
    address: 10.0.0.12
  db01:
    address: 10.0.0.21
    user: rocky
groups:
  web:
    hosts: [web01, web02]
  db:
    hosts: [db01]
```

```yaml
# nginx.yaml
version: 1
targets:
  groups: [web]            # union with any listed hosts: hosts: [db01]
resources:
  - id: nginx
    type: package
    with:
      name: nginx
      state: present
```

```sh
sinter plan  nginx.yaml --inventory hosts.yaml
sinter apply nginx.yaml --hosts hosts.yaml
```

Plan (and apply/audit) first print the target resolution:

```text
== target resolution ==
recipe nginx (nginx.yaml)
  db01   SKIP   no matching target
  web01  MATCH  group:web
  web02  MATCH  group:web
  selected 2, excluded 1
executions: 2 (1 recipe(s), 3 host(s))
```

Fail-closed rules (all exit 2, before anything connects):

- a recipe without `targets` used with `--inventory`;
- a target host or group the inventory does not define;
- targets that select no host;
- two selected hosts that resolve to the same address and port;
- a malformed inventory: unknown fields, a group listing an undefined host
  or the same host twice, no hosts, parse errors;
- `--host` together with `--inventory`.

Hosts that no recipe selects are never resolved or contacted. `targets`
only apply with an inventory: `--host` (or no host, i.e. localhost) keeps
the single-target behavior and ignores `targets`.

There are no nested groups, host or group variables, patterns, an implicit
"all" group, dynamic inventory or parallel runs.

### Bundles

A bundle runs several recipes as one invocation:

```yaml
# web-stack.yaml
version: 1
name: web-stack            # optional; defaults to the file name
recipes:                   # relative to this file
  - common.yaml
  - nginx.yaml
  - app.yaml
```

```sh
sinter validate web-stack.yaml
sinter apply web-stack.yaml --inventory hosts.yaml
```

Each recipe is resolved against its **own** `targets`: `common` on
`groups: [linux]` and `nginx` on `groups: [web]` give different host sets —
never "every recipe on every host". A recipe without `targets` fails the
whole bundle before anything runs. Every listed recipe must exist and
validate; a recipe may be listed once; bundles do not nest. Without an
inventory, each recipe runs in order on the one `--host` (or localhost).

### Execution and failures

- Executions are (recipe, host) pairs: recipes in bundle order, hosts in name
  order. They run one at a time.
- `plan` and `audit` are read-only and attempt every execution.
- `apply` is fail-fast: the first execution that exits non-zero, for any
  reason (2 validation, 3 connection, 4 plan, 5 backup or apply failure,
  6 indeterminate), stops the sequence. That execution keeps its own result
  or error; every later execution — later hosts of the same recipe and all
  later recipes — is reported `not_run` (reason names the failed execution),
  is never contacted, and runs neither backups nor resources. Earlier
  executions keep their results; nothing is rolled back.
- The exit code is the most severe code among executions that ran, in the
  order 6, 5, 4, 3, 2, 7, 0 (`not_run` contributes none). A partial failure
  never exits 0. The summary line counts `exit 0`, `non-zero` and `not run`.
- Text output prints `== <recipe> @ <host> (<user>@<address>:<port>) ==`
  before each execution's normal report and an `== executions ==` summary at
  the end.

## Backups before apply

*Available from Sinter v1.1.0.*

A recipe may declare paths to copy on the target before `apply` changes
anything:

```yaml
version: 1
backup:
  paths:
    - /etc/ssh/sshd_config
    - /etc/nginx
resources:
  - id: nginx
    type: package
    with:
      name: nginx
      state: present
```

- `validate` checks the declaration only. `plan` lists the paths
  (`BACKUP  <path> [planned]`) and copies nothing. `audit` ignores backups.
- `apply` copies every path before the first resource runs, into
  `/var/lib/sinter/backups/<run-id>/<original path>` with `--sudo`, or
  `~/.sinter/backups/<run-id>/<original path>` of the target user otherwise.
  One `<run-id>` (`<UTC timestamp>-<random>`) is shared by all hosts of an
  invocation (suffixed `-<NN>-<recipe>` per recipe of a bundle); each host
  keeps its backup on itself, and only selected hosts are backed up.
- Files, directories (recursively) and symlinks (as links) are copied with
  mode, ACLs, ownership and timestamps preserved; other extended attributes
  and SELinux labels are best effort. A path that does not exist is recorded
  as `absent`.
- If any backup fails, apply stops before any resource runs (exit 5) and the
  error names the partial run directory, which is kept.
- Backup content never appears in output. Sinter never restores, rotates or
  deletes backups: a backup is not a rollback.

## Terminal colors

*Available from Sinter v1.1.0.*

Text output colors status words (`ok`/`CHANGED`/`PASS`/`success` green,
`POSSIBLE`/`DRIFT`/`blocked` yellow, `FAILED`/`ERROR`/`INDET` and error
messages red) only when the stream is a terminal. Pipes, redirects and CI
logs get plain text; `NO_COLOR` (any non-empty value) and `TERM=dumb` turn
color off. `--format json` output never contains color codes.

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

### backup (plan and apply)

*Available from Sinter v1.1.0.*

Present only when the recipe declares `backup`:

| Field | Type | Values |
|-------|------|--------|
| `backup.run_id` | string or null | Run id (`apply`); `null` in `plan`. |
| `backup.directory` | string or null | Run directory on the target (`apply`); `null` in `plan`. |
| `backup.entries` | array | One object per declared path, in declaration order: `path` (string), `status` (`planned`, `backed_up`, `absent`), `kind` (`file`, `directory`, `symlink`, or null), `destination` (string or null). |

### Inventory and bundles

*Available from Sinter v1.1.0.*

With `--inventory`, or with a bundle, `plan`, `apply` and `audit` print one
document for the whole invocation once every execution has been attempted:

| Field | Type | Values |
|-------|------|--------|
| `mode` | string | `"plan"`, `"apply"` or `"audit"` |
| `exit_code` | integer | The invocation exit code. |
| `bundle` | object or null | `name`, `path` for a bundle. |
| `inventory` | string or null | Inventory path. |
| `resolution` | array or null | With an inventory: per recipe, `recipe`, `path`, and `hosts` (every inventory host: `name`, `selected` boolean, `reasons` such as `"group:web"`). |
| `executions` | array | One object per (recipe, host), in execution order. |

Execution object: `recipe` (string), `target` (`name`, and `host`, `port`,
`user` — null for localhost), `exit_code` (integer, or null when not run),
`status` (the document's `status`, or `error`, or `not_run`), `backup` (see
below), and one of `result` (the document a single-target run would print),
`error` (`kind`: `schema`, `connect`, `plan`, `apply`, `indeterminate`;
`message`), or `reason` (why it was not run).

Execution `backup`: `null` when the recipe declares no backup or in `audit`;
otherwise an object with `status` — `planned` (plan), `completed` (apply
copied every path), `failed` (the backup step failed; no resource ran),
`not_started` (the execution failed before the backup step, e.g. connection),
`not_run` (the execution was not run) — plus `run_id`, `directory` (string
or null), and `entries` (`path`, `status`: `planned`, `backed_up`, `absent`,
`failed`, `not_run`; `kind`; `destination`). It is built only from that
execution, so recipe, host and backup never mix; it never contains file
content. For a completed run it repeats `result.backup`. A problem found before any execution
(inventory, targets, resolution, duplicate hosts) prints no document and
exits as described in [Framing and errors](#framing-and-errors).

`validate` on a bundle adds `bundle` (string) and `recipes` (per recipe:
`recipe`, `path`, `resources`, `handlers`, `vars`, `targets`) to its document;
`resources`, `handlers` and `vars` are then totals.

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
- Hashed (`|1|…`) `known_hosts` entries are supported and matched against
  the same exact identity.
- A key listed on an `@revoked` line is refused.
- Host-key algorithms already recorded for the host are negotiated first, so
  a host enrolled with only its Ed25519 (or only its RSA) key is accepted.
- With an OpenSSH `HostKeyAlias`, the alias replaces the host name in the
  identity.
