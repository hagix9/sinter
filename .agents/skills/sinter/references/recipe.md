# Recipes

Source of truth: Sinter v1.0.0 `docs-site/src/content/docs/en/reference/recipe-format.md`
and `reference/resources/*.md` (published at
https://sinter.fulltrust.co.jp/en/reference/recipe-format/ and
https://sinter.fulltrust.co.jp/en/reference/resources/).
When a field detail matters, check the resource page (or the Documentation
WebMCP `sinter_get_resource` tool) instead of guessing.

## Structure

YAML and TOML compile to the same model. Allowed top-level fields are
`version`, `vars`, `include`, `resources`, and `handlers`; anything else is a
schema error.

```yaml
version: 1                  # required; the only supported value

vars:
  port: { value: 8080, sensitive: false }

resources:
  - id: tree
    type: package
    with:
      name: tree
      state: present
```

Resource fields: `id` (required, unique), `type` (required), `with`
(required, type-specific), and optional `when`, `loop`, `depends_on`,
`notify`, `sensitive`.

Handlers: `id`, `service`, `action` (`restart` or `reload`), optional
`sensitive`. They run once at the end of an apply, only if a changed resource
notified them.

## Resource types (v1.0.0)

| Type | Required `with` fields | Other fields |
|---|---|---|
| `file` | `path` | `state`, `content` or `source`, `owner`, `group`, `mode` |
| `directory` | `path` | `state`, `owner`, `group`, `mode` |
| `link` | `path`, `target` (when present) | `state` |
| `template` | `path`, `source` | `state`, `vars`, `owner`, `group`, `mode` |
| `command` | `program` | `args`, `cwd`, `env`, `timeout_seconds`, `success_codes`, `creates` or `removes`, `changed_when`, `register` |
| `package` | `name`, `state` (`present` or `absent`) | `env` |
| `service` | `name`, plus `state` (`running` or `stopped`) and/or `enabled` | — |

There are no other types. If a user asks for one (for example a firewall or
container resource), say it does not exist rather than inventing syntax.
`package` has no version pinning.

## Authoring guidance

- Start minimal; add only what the user asked for.
- `mode` is a quoted four-digit octal string, for example `"0644"`.
- Parent directories of managed paths must already exist and pass the
  trust-boundary check; paths under world-writable directories such as `/tmp`
  are refused.
- `command` runs `program` with `args` directly (no shell). Plan never runs
  it; every apply runs it again unless something keeps it from running (a
  guard, a false `when`, or an earlier failure that blocks it). Guards and
  `changed_when` do different things:
  - `creates` / `removes` are execution guards, checked before the command
    would run: if the `creates` path exists, or the `removes` path is absent,
    the command is not executed and the result is `guard_satisfied` with no
    change.
  - `changed_when` is not a guard. It is evaluated only after the command has
    run and exited with a code in `success_codes`, and it only decides whether
    that run is reported as changed (without it, every successful run is
    reported as changed). `changed_when: "false"` still runs the command on
    every apply; it only reports no change.
  - `changed_when` alone never prevents re-execution. If a command must not
    run again, use a `creates` or `removes` guard, or make the command itself
    safe to repeat.
  - `changed_when` must be a string expression (for example `"false"`); a
    YAML boolean is rejected by validate.
- Expressions (`when`, `changed_when`, `{{ ... }}`) may use `vars.<name>`,
  `facts.hostname`, `facts.os.name`, `facts.os.family`, `facts.os.version`,
  `facts.arch`, `registers.<name>.<field>`, `item`, and `result.<field>`.
- YAML aliases, anchors, merge keys, and duplicate keys are rejected.
  Duplicate ids and two stateful resources on the same path are rejected.

## Secrets

- `sensitive: true` (on a var or a resource) redacts values in all output.
  It does not protect the recipe file itself: a secret written into a recipe
  is still stored in plain text.
- Never write passwords, tokens, or private keys into a recipe you produce,
  and never ask the user to paste them. Leave a clearly marked placeholder and
  tell the user to supply the value through their own secret handling.

## Managed targets

Supported: Ubuntu 24.04 / 26.04 LTS (amd64) and Rocky Linux, RHEL, AlmaLinux
9 / 10 (x86_64). Oracle Linux is recognized but not acceptance-tested. Each
target needs systemd, an OpenSSH server, `/bin/sh`, the `attr` package
(`/usr/bin/getfattr`), and passwordless `sudo -n` when privilege is used. Do
not claim support for other platforms.
