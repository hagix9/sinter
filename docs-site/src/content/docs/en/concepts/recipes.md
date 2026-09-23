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
resources:
  - id: unique_name          # required, unique identifier
    type: file               # one of the resource types
    sensitive: false         # redact this resource's values in output
    when: "facts.os.family == 'debian'"
    depends_on: [other_id]
    notify: [handler_id]
    with:                    # per-type parameters
      path: /etc/example
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

`service` is the **systemd unit name on the target** — it is not resolved from
a Sinter resource id. Handlers run once at the end of an apply, only when
notified by a resource that actually changed. Multiple notifications of the
same handler are deduplicated.

## Expressions

A deliberately small expression language is used in `when` and
`changed_when`:

- Namespaces: `vars.<name>`, `facts.hostname`, `facts.os.name`,
  `facts.os.family`, `facts.os.version`, `facts.arch`,
  `registers.<name>.<field>`, `item` (inside loops), `result.<field>` (inside
  `changed_when`). Bare names are not allowed.
- Operators: `==`, `!=`, `<`, `<=`, `>`, `>=`, `&&`, `||`, `!`, parentheses.
- `when`/`changed_when` must evaluate to a boolean — there is no truthiness
  coercion.
