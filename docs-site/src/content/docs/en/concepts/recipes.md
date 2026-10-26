---
title: Recipes
description: Recipe structure — version, vars, includes, resources, handlers.
---

A recipe declares desired state for one target. YAML and TOML are frontends
for a single semantic model — equivalent recipes in either format produce
equivalent behavior.

## Top-level fields

| Field | Type | Purpose |
|-------|------|---------|
| `version` | integer (required) | Recipe format version. Currently `1`. |
| `vars` | map | Named literal values with an optional `sensitive` flag. |
| `include` | list | Other recipe files merged into this one. |
| `resources` | list | Desired-state resources, evaluated in order. |
| `handlers` | list | Delayed `restart`/`reload` service actions. |

No other top-level fields are allowed.

## Variables

```yaml
vars:
  app_user:
    value: deploy
    sensitive: false
  db_password:
    value: s3cret
    sensitive: true
```

Variables are literals only — they cannot reference other variables.
Reference them with `{{ vars.app_user }}` in string fields and templates.

`sensitive: true` values never appear in normal output, verbose mode, diffs,
registered results, diagnostics, or JSON output — including derived values.
For sensitive content, hashes and sizes are also hidden.

## Includes

`include` expands other recipe files into the model. Relative paths are
resolved against the including recipe file's directory; absolute paths are
used as given. The same file is never expanded twice — duplicate includes
and include cycles are rejected.

## Resources

```yaml
version: 1

resources:
  - id: other_id             # the dependency named below
    type: directory
    with:
      path: /etc/example.d

  - id: unique_name          # required, unique identifier
    type: file               # one of the resource types
    sensitive: false         # redact this resource's values in output
    when: "facts.os.family == 'debian'"
    depends_on: [other_id]
    notify: [handler_id]
    with:                    # per-type parameters
      path: /etc/example

handlers:
  - id: handler_id           # the handler named in notify
    service: example
    action: restart
```

Common fields: `id`, `type`, `with`, `when`, `loop`, `depends_on`, `notify`,
`sensitive`. See [Resources](/en/concepts/resources/) for semantics and
the [Resource Reference](/en/reference/resources/) for per-type
parameters.

## Handlers

```yaml
handlers:
  - id: restart_app
    service: app.service   # systemd unit name on the target
    action: restart        # restart or reload
```

A handler may carry `type: service`; without it the handler is a service
handler, so existing recipes are unchanged. This version implements three
handler types: `service`, `ca_trust` and `command` (below). A recipe that uses
any other type is rejected at validation instead of being ignored.

`service` is the **systemd unit name on the target** — it is not resolved from
a Sinter resource id. Handlers run once at the end of an apply, only when
notified by a resource that actually changed. Multiple notifications of the
same handler are deduplicated. If a systemd unit input changed or the unit
reports `NeedDaemonReload=yes`, Sinter reloads the system manager
(`systemctl daemon-reload`) before the handler runs; a reload is not a
restart. See
[service](/en/reference/resources/service/#automatic-manager-synchronization).

### CA trust handler

```yaml
resources:
  - id: company_ca
    type: file
    with:
      path: /usr/local/share/ca-certificates/company.crt   # Debian/Ubuntu
      source: files/company.crt
    notify: [refresh_ca]
handlers:
  - id: refresh_ca
    type: ca_trust
```

A `ca_trust` handler refreshes the system CA trust store after a file that
notified it changed. It has no other fields (not `service`, not `action`). The
`file` resource places the certificate; the handler places nothing.

| Target | Command run (fixed, no shell) |
|--------|-------------------------------|
| Debian, Ubuntu | `/usr/sbin/update-ca-certificates` (no `--fresh`: the store is not rebuilt) |
| RHEL, Rocky Linux, AlmaLinux | `/usr/bin/update-ca-trust extract` |

The operating system is the detected OS family, not "whichever tool exists". If
a resource notifies a `ca_trust` handler on any other OS, the run is rejected
when the target is connected (plan, apply and audit), before any resource
runs. The handler needs root: connect as root, or pass `--sudo`; without root it
fails and runs nothing. If the tool is not executable on the target it fails
and runs nothing. Put the Debian anchor under `/usr/local/share/ca-certificates/`
with a `.crt` name, and the RHEL anchor under
`/etc/pki/ca-trust/source/anchors/`, as each tool expects.

Success means the tool exited 0; it does not prove that a particular
certificate is trusted. `plan` and `audit` never run the tool: `plan` lists the
handler under pending handlers. A handler is declared in order, so declare a
`ca_trust` handler before a `service` handler that has to see the new store.
It is unrelated to the automatic `systemctl daemon-reload`.

Verified on real hosts: none yet (tested against a scripted target only).

### Command handler

```yaml
resources:
  - id: app_config
    type: file
    with:
      path: /etc/myapp/config.yaml
      source: files/config.yaml
    notify: [rebuild_cache]
handlers:
  - id: rebuild_cache
    type: command
    with:
      program: /usr/bin/myapp
      args: [cache, rebuild]
      timeout_seconds: 300
```

A `command` handler runs one program after a resource that notified it
changed. It is for an app-specific step that belongs to a change: rebuilding a
cache, re-reading a configuration. It is not a place to run something on every
apply (use a `command` resource for that).

| Field (in `with`) | Required | Notes |
|-------------------|----------|-------|
| `program` | yes | Absolute path. Never searched for in `PATH`; no `.` or `..`; static text. |
| `args` | no | List of strings, at most 64 entries of at most 4096 bytes each; no NUL. |
| `timeout_seconds` | no | Integer 1–3600, default 300. |

The values are static text, so a value containing `{{` is rejected rather than
run literally. The program runs directly with exactly these arguments — there
is no shell, so quoting and expansion never apply — with the same fixed
environment as the `command` resource. `cwd`, `env` and `success_codes` are not
available (they are rejected). These limits belong to the handler only: the
`command` resource keeps its own.

It runs with the privilege of the run, like the `command` resource: as root, or
through `--sudo`. It never escalates by itself, and it does not check for root
in advance: a program that needs root and does not have it fails with its own
exit status. If the program is not an executable file on the target the handler
fails and runs nothing.

The result is the exit status. Exit 0 is success; any other status or a signal
is a failure even if the program had begun to change something; a timeout or a
lost connection is indeterminate and is never retried. A failed or
indeterminate handler stops the handler phase, and the handlers after it are
reported as pending. The report names the handler (`type: command`, action
`run`) and, on a failure, the program and the first line of its standard error;
it never lists the arguments. A `sensitive: true` handler (and one notified by a
sensitive resource) is redacted completely.

`plan` and `audit` never run the program; `plan` lists the handler under
pending handlers. Handlers run in declaration order, so declare a command
handler after the `ca_trust` or `service` handler it depends on, and the other
way round.

Verified on real hosts: none yet (tested against a scripted target only).

## Expressions

A deliberately small expression language is used in `when` and
`changed_when`:

- Namespaces: `vars.<name>`, `facts.hostname`, `facts.os.name`,
  `facts.os.family`, `facts.os.version`, `facts.os.version_major` (integer),
  `facts.arch`,
  `registers.<name>.<field>`, `item` (inside loops), `result.<field>` (inside
  `changed_when`). Bare names are not allowed.
- Operators: `==`, `!=`, `<`, `<=`, `>`, `>=`, `&&`, `||`, `!`, parentheses.
- `when`/`changed_when` must evaluate to a boolean — there is no truthiness
  coercion.
