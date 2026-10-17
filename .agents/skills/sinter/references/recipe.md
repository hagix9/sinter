# Recipes

Source of truth: Sinter v1.5.1 `docs-site/src/content/docs/en/reference/recipe-format.md`
and `reference/resources/*.md` (published at
https://sinter.fulltrust.co.jp/en/reference/recipe-format/ and
https://sinter.fulltrust.co.jp/en/reference/resources/).
When a field detail matters, check the resource page (or the Documentation
WebMCP `sinter_get_resource` tool) instead of guessing.

## Structure

YAML and TOML compile to the same model. Allowed top-level fields are
`version`, `vars`, `include`, `resources`, `handlers`, `backup`, `targets`,
and `env` (default environment for `package` and `command`, for example a
proxy); anything else is a schema error. `targets` selects hosts of an
inventory (`--inventory`); a bundle file lists several recipes.

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

## Resource types (v1.5.1)

| Type | Required `with` fields | Other fields |
|---|---|---|
| `file` | `path` | `state`, `content` or `source`, `owner`, `group`, `mode`, `validate` |
| `directory` | `path` | `state`, `owner`, `group`, `mode` |
| `link` | `path`, `target` (when present) | `state` |
| `template` | `path`, `source` | `state`, `vars`, `owner`, `group`, `mode`, `validate` |
| `command` | `program` | `args`, `cwd`, `env`, `timeout_seconds`, `success_codes`, `creates` or `removes`, `changed_when`, `register` |
| `package` | `name`, `state` (`present` or `absent`) | `env` |
| `service` | `name`, plus `state` (`running` or `stopped`) and/or `enabled` | — |
| `group` | `name` | `state`, `gid`, `system` |
| `user` | `name` | `state`, `uid`, `group`, `groups`, `shell`, `home`, `create_home`, `system`, `password_hash` |
| `postgresql_role` (v1.5.1) | `name` | `state`, `login`, `superuser`, `createdb`, `createrole`, `inherit`, `replication`, `bypassrls`, `connection_limit`, `password_verifier` |

There are no other types (there is no repository, firewall or container
resource; a dnf repository is a `file` under `/etc/yum.repos.d/`). If a user asks for one (for example a firewall or
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
- `validate` on `file`/`template` runs a checker against the staged content
  before publication (`program`, `args`, `timeout_seconds`); the staged path
  is appended last, or placed inside an argument with `{{ staged }}` (v1.5.1),
  for example `--config-file={{ staged }}`. A drop-in checked on its own does
  not prove the full configuration is valid.
- `template.vars` values are passed as written: `{{ ... }}` inside them is not
  evaluated (v1.5.1 `validate` warns). Reference `vars.*`/`facts.*` in the
  template body instead.
- Expressions (`when`, `changed_when`, `{{ ... }}`) may use `vars.<name>`,
  `facts.hostname`, `facts.os.name`, `facts.os.family`, `facts.os.version`,
  `facts.os.version_major` (v1.5.1, an integer such as `8`), `facts.arch`,
  `registers.<name>.<field>`, `item`, and `result.<field>`. `&&` and `||`
  short-circuit.
- Conditions and dependencies: a resource whose `when` is false is skipped,
  and a skipped dependency **blocks** its dependents. A resource that reads
  `registers.<x>` must list the producer in `depends_on` (validate enforces
  it) and, if the producer may be skipped, guard its own `when` with the same
  condition first (`facts.os.version_major < 10 && registers.x.exit_code ==
  1`). A resource that only needs a release-specific step to have run should
  be declared after it instead of depending on it.
- YAML aliases, anchors, merge keys, and duplicate keys are rejected.
  Duplicate ids and two stateful resources on the same path are rejected.

## Secrets

- `sensitive: true` (on a var or a resource) redacts values in all output.
  It does not protect or encrypt recipe contents: a secret written into a
  recipe remains plaintext.
- The documented encryption is an age file referenced as
  `{ secret: <relative path> }`, accepted only by `file.content`,
  `user.password_hash` and (v1.5.1) `postgresql_role.password_verifier`
  (a SCRAM-SHA-256 verifier, never a plaintext password). Files are made with
  `sinter secrets encrypt`; `validate` checks the reference without
  decrypting; `plan`/`apply`/`audit` decrypt on the controller. MCP refuses
  manifests with secret references.
- Never copy a user-supplied password, token, private key, or other secret
  into generated recipe content, command lines, example commands, logs, or
  reports merely because asked to use it. Avoid echoing the value. Do not ask
  the user to paste secrets.
- Use only an indirection supported by Sinter's documented contract. If the
  requested secret cannot be represented safely with a documented feature,
  state that limitation and use a clearly marked placeholder where useful.
  Do not invent variable interpolation, secret managers, vaults, or external
  integrations.

## Managed targets

Supported: Ubuntu 24.04 / 26.04 LTS (amd64) and Rocky Linux, RHEL, AlmaLinux
9 / 10 (x86_64). From v1.5.1, Rocky Linux / RHEL 8 works as an **SSH target
only**: the controller binary needs glibc 2.34, so it cannot run on EL8.
Oracle Linux is recognized but not acceptance-tested. Each target needs
systemd, an OpenSSH server, `/bin/sh`, the `attr` package
(`/usr/bin/getfattr`), and passwordless `sudo -n` when privilege is used. Do
not claim support for other platforms.

## Platform notes (RHEL family)

- Use real package names. On EL8 `python3` and `python311` are provides-only
  names: use `python36` / `python3.11`; Sinter refuses provides-only names
  before installing and names the real package.
- PostgreSQL: prefer **16** from the OS (module stream `postgresql:16` on
  EL8/EL9, the default on EL10) or **17** from PGDG; do not pick the default 10
  (EL8) or 13 (EL9) for a new server, both past upstream end of life. Manage
  a third-party repository and its key as `file` resources with `gpgcheck`
  on; see `examples/recipes/` in the Sinter repository.
- A package that creates its own account (for example `postgres`): declare
  the `group`/`user` before the package so plan can defer to it.
