---
title: Recipe Format
description: Complete recipe schema — top-level fields, expressions, interpolation.
---

Recipes may be written in YAML or TOML; both compile to the same semantic
model. The YAML examples below apply equally to TOML.

## Skeleton

```yaml
version: 1                    # required

vars:                         # optional
  <name>: { value: ..., sensitive: <bool> }

include: [...]                # optional list of recipe files

resources: [...]              # optional list of resources

handlers: [...]               # optional list of handlers

targets: { hosts: [...], groups: [...] }   # optional, v1.1.0+ (inventory runs)

backup: { paths: [...] }      # optional, v1.1.0+ (copied before apply)

env: { NAME: value }          # optional default environment for package/command
```

Top-level fields allowed: `version`, `vars`, `include`, `resources`,
`handlers`, (from v1.1.0) `targets` and `backup`, and `env`. Anything else is
a schema error.

## env

A map of environment variables given by default to every `package` and
`command` resource in the recipe. It exists so a setting that applies to all of
them — most often an HTTP(S) proxy — is written once.

```yaml
version: 1

env:
  HTTP_PROXY: "http://proxy.example.com:3128"
  HTTPS_PROXY: "http://proxy.example.com:3128"
  NO_PROXY: "localhost,127.0.0.1,.internal.example.com"

resources:
  - id: install
    type: package
    with: { name: curl, state: present }
  - id: one-off
    type: command
    with:
      program: /usr/local/bin/fetch
      env: { HTTPS_PROXY: "http://other-proxy:3128" }  # overrides for this resource
```

- **Scope.** Only `package` and `command` resources receive it — they are the
  only resources that run an external process with an environment. It is never
  passed to a connection step, a package query, a service, or a file operation.
- **Precedence.** A resource's own `env` overrides the recipe `env` for each
  name it sets; other recipe names still apply. A resource value is never
  replaced by the default.
- **Names are case-sensitive**, as on Linux: `HTTP_PROXY` and `http_proxy` are
  different variables and both are passed exactly as written. dnf and apt honor
  both spellings; Sinter does not fold case.
- **Reserved names** `PATH`, `LANG`, `LC_ALL` and `HOME` are rejected; Sinter
  always sets the baseline itself.
- **Values** may interpolate `vars`/`facts` (for example
  `"{{ vars.proxy }}"`), exactly like a resource `env`. A value derived from a
  `sensitive` variable makes each resource that inherits it sensitive, so the
  value is redacted everywhere.
- `env` may be declared only in the recipe that is run, not in an included
  file.

There is no per-host `env`: the inventory defines hosts, ports and credentials
only, with no host variables (`/en/reference/cli/#multiple-hosts`). A per-host
proxy is expressed by running a different recipe (or an included fragment with
its own resources) for that host.

## targets

*Available from Sinter v1.1.0.*

```yaml
targets:
  groups: [web]        # inventory group names
  hosts: [db01]        # inventory host names (union with the groups)
```

Names the inventory hosts this recipe may run on when it is used with
`--inventory`. At least one name is required; names are static. `targets` is
allowed only in the recipe that is run, not in an included file. With
`--inventory`, a recipe **without** `targets` is an error — inventory
membership never authorizes execution. Without an inventory (`--host` or
localhost), `targets` is ignored and the single-target behavior is unchanged.
See [Multiple hosts](/en/reference/cli/#multiple-hosts).

## backup

*Available from Sinter v1.1.0.*

```yaml
backup:
  paths:
    - /etc/ssh/sshd_config
    - /etc/nginx
```

Static absolute paths that `apply` copies on each selected target before it
changes anything; a failed backup stops the apply before any resource runs.
`plan` only lists them; `audit` ignores them. Paths may come from included
files but must be unique; `/` is rejected. See
[Backups before apply](/en/reference/cli/#backups-before-apply).

## vars

```yaml
vars:
  port:
    value: 8080
    sensitive: false
  token:
    value: abc123
    sensitive: true
```

- `value` is a literal — variables may not interpolate other variables, so
  forward references and cycles cannot exist.
- `sensitive: true` redacts the value — and everything derived from it — in
  all output and diagnostics.

## resources

| Field | Required | Type | Notes |
|-------|----------|------|-------|
| `id` | yes | string | Unique; also used by `depends_on`, `notify`, `registers`. |
| `type` | yes | string | `file`, `directory`, `link`, `template`, `command`, `package`, `service`, [`group`](/en/reference/resources/group/) and [`user`](/en/reference/resources/user/). |
| `with` | yes | map | Type-specific parameters (see each resource page). |
| `when` | no | string | Boolean expression gating this resource and dependents. |
| `loop` | no | list | Expand once per item; `{{ item }}` in fields. |
| `depends_on` | no | list | Resource ids that must complete first. |
| `notify` | no | list | Handler ids triggered on change. |
| `sensitive` | no | bool | Redact all of this resource's values. |

## handlers

| Field | Required | Notes |
|-------|----------|-------|
| `id` | yes | Unique across resources and handlers. |
| `service` | yes | Target service. |
| `action` | yes | `restart` or `reload`. |
| `sensitive` | no | Redact handler details. |

Handlers run once at apply end, only when a changed resource notified them.

Before each handler runs, Sinter synchronizes the systemd system manager
(`systemctl daemon-reload`) if a managed unit input changed or the unit reports
`NeedDaemonReload=yes`, then observes the unit again, runs the action, and
verifies it. A reload is not a restart: to apply a changed unit file to a
running process, notify a `restart` handler. Sinter does not reorder
resources, so a resource that writes a unit file must come before the service
that uses it (`depends_on` or declaration order). See
[service](/en/reference/resources/service/#automatic-manager-synchronization).

## Interpolation

Strings may embed `{{ expression }}`:

```yaml
content: "listen = {{ vars.port }}"
```

When a whole field is one `{{ ... }}` token, the typed value is preserved
(ints stay ints, etc.).

## Expressions

Used in `when`, `changed_when`, and interpolation:

- Inputs: `vars.<name>`, `facts.hostname`, `facts.os.name`,
  `facts.os.family`, `facts.os.version`, `facts.os.version_major`,
  `facts.arch`, `registers.<name>.<field>`, `item`, `result.<field>` (in
  `changed_when`).
- `facts.os.version_major` (v1.5.1) is an **integer**: the part of
  `VERSION_ID` before the first `.` (`8.10` → `8`, `24.04` → `24`). It exists
  only when `VERSION_ID` is a plain numeric version; otherwise using it is an
  error (never a guessed number). Combine it with the family:
  `when: "facts.os.family == 'redhat' && facts.os.version_major < 10"`.
- `&&` and `||` short-circuit: the right operand is not evaluated when the
  left one decides the result.
- Operators: `==` `!=` `<` `<=` `>` `>=` `&&` `||` `!` and parentheses.
- No user-defined functions; no bare identifiers.
- `when`/`changed_when` must produce a boolean — no truthiness coercion.
- Ordering comparisons apply only to numbers and strings; equality requires
  same-type operands (int/float may compare numerically).
- Comparison against an unknown value yields unknown — the resource becomes
  indeterminate rather than guessed.

## Conditions, registers and dependencies

How `when`, `register` and `depends_on` combine (the behavior is unchanged in
v1.5.1; this section states it in one place):

| Situation | Result |
|-----------|--------|
| `when` is false | The resource is `skipped_by_condition`. Its own condition is evaluated before its dependencies. |
| A dependency was skipped by its `when` | The dependent is **blocked** (a skipped resource does not satisfy `depends_on`), unless the dependent's own `when` is false first. |
| A `command` skipped by its `creates`/`removes` guard | Counts as **satisfied** for dependents; its `register` holds a not-executed result (`executed: false`, `exit_code: null`). |
| A `when` reads `registers.<name>` of a producer skipped by its own `when` | **Error** (`undefined register`): apply fails that resource and stops; plan exits with a plan error. |
| Plan | Commands do not run, so a `when` that reads a register is Unknown and the resource is reported unknown. |

Safe per-release branching (for example a step that exists only on EL8/EL9):

- A resource that reads a release-specific step's register must list that
  step directly in `depends_on` (`validate` requires it) and must carry the
  same release condition first in its own `when`. Its own condition is
  evaluated before its dependencies, so on other releases it is skipped
  instead of blocked, and the register is only read when the step ran:
  `when: "facts.os.version_major < 10 && registers.state.exit_code == 1"`.
- A resource that only needs the release-specific steps to have run (for
  example a `package` installed after a module-enable step) should not list
  them in `depends_on`, because on other releases the skipped step would block
  it. Declare it **after** those steps instead: declaration order and
  fail-fast keep them in order, and a failure stops the run.
- See [`examples/recipes/postgresql-os.yaml`](https://github.com/hagix9/sinter/blob/main/examples/recipes/postgresql-os.yaml) and [`epel-crb.yaml`](https://github.com/hagix9/sinter/blob/main/examples/recipes/epel-crb.yaml).

## Strictness

- YAML front end rejects aliases/anchors, merge keys, duplicate keys, and
  non-finite floats.
- TOML front end rejects datetimes and non-finite floats.
- Duplicate resource or handler ids are rejected; a handler id colliding with
  a resource id is an error.
- Two stateful filesystem resources may not manage the same exact path.
