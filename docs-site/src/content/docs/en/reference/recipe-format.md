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
  <name>: { value: ..., sensitive: <bool>, required: <bool> }

include: [...]                # optional list of recipe files

resources: [...]              # optional list of resources

handlers: [...]               # optional list of handlers

targets: { hosts: [...], groups: [...] }   # optional, v1.1.0+ (inventory runs)

backup: { paths: [...] }      # optional, v1.1.0+ (copied before apply)

env: { NAME: value }          # optional default environment for package/command

plugins: [{ id, version }]    # optional, v1.9.0+ (top-level recipe only)

allow_writable_parents: [/opt/myapp]   # optional (top-level recipe only)
```

Top-level fields allowed: `version`, `vars`, `include`, `resources`,
`handlers`, (from v1.1.0) `targets` and `backup`, `env`, (from v1.9.0)
`plugins`, and `allow_writable_parents`. Anything else is a schema error.

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

*From v1.10.0.* A recipe may say where the copies go:

```yaml
backup:
  directory: /var/backups/sinter/web      # the store of this file's paths
  paths:
    - /etc/nginx/nginx.conf
    - path: /var/lib/pgsql/.pgpass        # a store of its own
      directory: /var/backups/sinter/pg
```

A path's `directory` comes first, then `backup.directory` of the same file (an included file does
not inherit it), then the project file's, then the default store. A store is static, absolute and
on each target, may not overlap a declared path or contain another store, and is checked as the
default store is. `plan` lists each path with its store: read it before running someone else's
recipe. Do not use a directory a service reads as a store: a service that includes every entry of
a directory can fail on the run directory it finds there.

A path may also say which resources it is for:

```yaml
backup:
  paths:
    - path: /var/lib/app/data
      resources: [migrate]        # ids of resources of this recipe
    - /etc/app/app.conf
```

```toml
[backup]
paths = [
  { path = "/var/lib/app/data", resources = ["migrate"] },
  "/etc/app/app.conf",
]
```

`resources` changes nothing in a full run: every declared backup is taken. It matters only for a
[partial run](/en/reference/cli/#partial-runs): the backup is taken when one of the named resources
runs, and left out (reported as skipped) when all of them are excluded with `--skip-resource`. An id
names a resource, or a loop (all its instances). Without `resources`, Sinter keeps a backup unless
it can tell from the paths that nothing that runs can touch it.

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
- `required: true` (*from v1.10.0*) means a variables file must give it a value;
  `value` still gives the type. It cannot be combined with `sensitive: true`.
- `sensitive: true` redacts the value — and everything derived from it — in
  all output and diagnostics.
- A variables file (`--vars-file`) can give a declared variable another
  `value` for a run, an inventory group or one host; a `sensitive` variable
  cannot be set that way. See
  [Host and group variables](/en/reference/cli/#host-and-group-variables)
  (available from v1.6.0).

## plugins

*Available from v1.9.0.* Enables [Resource Plugins](/en/reference/resource-plugins/) by
`id` and `version`. Allowed only in the top-level recipe; an included file that
declares `plugins` is rejected.

## allow_writable_parents

Sinter normally refuses a path whose parent directory other accounts can write
to without the sticky bit (mode `0777`, `0775` with a shared group, …): another
account could swap an entry there between Sinter's check and its change. This
field lists such directories in which this recipe may still **publish a whole
file or remove one**:

```yaml
version: 1
allow_writable_parents: [/opt/myapp/drop]
resources:
  - id: drop_conf
    type: file
    with:
      path: /opt/myapp/drop/app.conf
      content: "level = 2\n"
```

```toml
allow_writable_parents = ["/opt/myapp/drop"]
```

Rules:

- At most 32 distinct static absolute paths (no `{{ }}`, no `.`/`..`, no
  repeated or trailing `/`); `/` is refused. Only in the top-level recipe: an
  included file that declares it is rejected, a bundle file has no such field,
  and each recipe of a bundle uses only its own list. MCP manifests may not use it.
- `sinter validate` shows one warning per listed directory.
- A listed directory is accepted only as the **direct parent** of the path, only
  when it is a real directory (not a symbolic link) owned by root (or, without
  `--sudo`, by the connecting user), not inside another account's directory,
  without an ACL, every directory above it passing the usual checks, and only
  when the run is as root (a root login or `--sudo`).
- Only `file`, `template` and `file_merge` use it, and only to create or replace
  the whole file (with its owner, group and mode) or to remove it
  (`state: absent`). Refused there, in plan and in apply: a change of owner,
  group or mode alone, a `validate` command, `directory` (also the parents
  `parents: true` would create), `link`, any other resource type, and a
  `backup` of a path in the directory.
- The existing entry must be absent, or a regular file owned by root (or the
  connecting user without `--sudo`) with one hard link; a symbolic link or a
  file of another account is refused. An existing file larger than 256 KiB is
  refused (it is read without following links, up to that size). Each read
  must see the very file that check passed (same device, inode and change
  time, still one hard link, still owned by root): a file renamed or linked
  in after the check is refused, never read.
- The existing content of a file in the directory is **never shown**: another
  account can rename any file it can reach on the same file system (a
  root-only one included) into the managed name, and to the check above it
  looks like a file Sinter wrote. Plan shows the sizes ("… bytes, content
  differs (not shown)") with the note "content diff not shown: …", also for a
  resource that is not `sensitive`; audit never shows content anyway.
- `file_merge` keeps the existing content, so in such a directory it refuses
  (in plan and in apply, with the same message) a publication that would make
  an existing file readable by more accounts: a declared `mode` that adds a
  read bit the existing mode lacks (`0600` → `0644`), or a declared `owner` or
  `group` other than the existing one. Leave them unset (the existing values
  are kept) or declare the existing ones; a narrower mode is allowed. When the
  file does not exist yet, the declared `owner`, `group` and `mode` apply.
- Every result that used the field carries the note "parent … is writable by
  other accounts; allowed by allow_writable_parents" (text and JSON). Each
  publication removes its own empty `.sinter-stage.*` directory: Sinter removes
  only the one entry with that name that is empty and has the staging
  directory's owner (root), random group and inode, which no other account can
  make. If another account renamed, filled or replaced it in the meantime, it is
  left and a note says where (the publication stands; remove it when
  convenient). If another account swaps an empty directory of its own into that
  name in the instant between Sinter's check and the removal, that empty
  directory is removed instead; that account could remove it itself, and a
  directory with anything in it is never removed. This removal has not yet been measured on a real host (GNU
  `find -inum -empty -delete`, the link count of a removed directory).

What you accept by listing a directory: any account that can write to it can
replace, rename or remove the file after Sinter wrote it, can read what the
file's mode allows, and can put another file under the managed name (Sinter
then replaces it, or `file_merge` edits it without widening who can read it).
Sinter only guarantees that root does not write, change, follow a link to or
remove anything outside the directory because of it, that it never shows (and
`file_merge` never makes more widely readable) the content of a file found in
it, and that what it published was the declared content. Without the field, `sinter audit` still observes such
a path read-only (see [audit](/en/reference/cli/)).

## resources

| Field | Required | Type | Notes |
|-------|----------|------|-------|
| `id` | yes | string | Unique; also used by `depends_on`, `notify`, `registers`. |
| `type` | yes | string | `file`, `directory`, `link`, `template`, `command`, `package`, `service`, [`group`](/en/reference/resources/group/) and [`user`](/en/reference/resources/user/), or a `<plugin>.<name>` type from an enabled [Resource Plugin](/en/reference/resource-plugins/) (from v1.9.0). |
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
| `type` | no | Handler type; default `service`. `service`, `ca_trust` and `command` are implemented; any other value is rejected at validation. |
| `service` | yes (type `service`) | Target service. Not allowed on the other types. |
| `action` | yes (type `service`) | `restart` or `reload`. Not allowed on the other types. |
| `with` | yes (type `command`) | `program` (absolute path), `args` (list of strings) and `timeout_seconds` (1–3600). Not allowed on the other types. |
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
