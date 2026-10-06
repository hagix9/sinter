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
```

Top-level fields allowed: `version`, `vars`, `include`, `resources`,
`handlers`, and (from v1.1.0) `targets` and `backup`. Anything else is a
schema error.

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
  `facts.os.family`, `facts.os.version`, `facts.arch`,
  `registers.<name>.<field>`, `item`, `result.<field>` (in `changed_when`).
- Operators: `==` `!=` `<` `<=` `>` `>=` `&&` `||` `!` and parentheses.
- No user-defined functions; no bare identifiers.
- `when`/`changed_when` must produce a boolean — no truthiness coercion.
- Ordering comparisons apply only to numbers and strings; equality requires
  same-type operands (int/float may compare numerically).
- Comparison against an unknown value yields unknown — the resource becomes
  indeterminate rather than guessed.

## Strictness

- YAML front end rejects aliases/anchors, merge keys, duplicate keys, and
  non-finite floats.
- TOML front end rejects datetimes and non-finite floats.
- Duplicate resource or handler ids are rejected; a handler id colliding with
  a resource id is an error.
- Two stateful filesystem resources may not manage the same exact path.
