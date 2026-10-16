---
title: file
description: Manage a regular file's content and metadata.
---

**Purpose:** ensure a regular file exists with the desired content, ownership,
and mode — or is absent.

## Synopsis

```yaml
- id: motd
  type: file
  with:
    path: /etc/motd
    content: "managed by sinter\n"
    mode: "0644"
    owner: root
    group: root
```

## Parameters

| Parameter | Required | Type | Default | Description |
|-----------|----------|------|---------|-------------|
| `path` | yes | string (absolute path) | — | Managed file path. |
| `state` | no | string | `present` | `present` or `absent`. |
| `content` | no | string, or `{ secret: <path> }` | — | Literal content, or an encrypted secret (see [sinter secrets](/en/reference/secrets/#using-a-secret-in-a-recipe)). Mutually exclusive with `source`. |
| `source` | no | string | — | Controller-side file copied to `path`; relative paths are resolved against the recipe file's directory. Mutually exclusive with `content`. |
| `owner` | no | string | — | Owner name. |
| `group` | no | string | — | Group name. |
| `mode` | no | string | — | Quoted four-digit octal, e.g. `"0644"`. |
| `validate` | no | map | — | Command run against the staged file before publication (`program`, `args`, `timeout_seconds`). (`{{ staged }}` places the staged path inside an argument) |

## Expected behavior

- `present`: creates or updates the file. Content is published atomically by
  rename; existing metadata is preserved when `owner`/`group`/`mode` are
  omitted.
- `absent`: removes the file if it is a regular file. Refuses to remove other
  object kinds (directories, symlinks, devices) as a file.
- Parent directories must already exist and pass the trust-boundary check;
  unexpected symlinks in the path are rejected.
- A file that really changes a systemd manager input (a unit file, drop-in,
  alias/mask/`.wants`/`.requires` link, or `system.conf`) makes Sinter run
  `systemctl daemon-reload` automatically before the next service or handler
  that needs it, and at the end of a successful apply. See
  [service](/en/reference/resources/service/#automatic-manager-synchronization).

## Pre-publication validation (validate)

```yaml
- id: sshd_conf
  type: file
  with:
    path: /etc/ssh/sshd_config.d/60-app.conf
    content: "PermitRootLogin no\nMaxAuthTries 4\n"
    owner: root
    group: root
    mode: "0600"
    validate:
      program: /usr/sbin/sshd
      args: ["-t", "-f"]
      timeout_seconds: 60        # optional, default 300
```

`validate` runs a command against the **staged** file — the content Sinter has
built but not yet published — and only publishes it if the command exits 0. The
command is executed as `program args... <staged-file>`, argv-only (no shell), as
the operation's own identity, and never sees the production path. Use a tool's
non-applying syntax check:

| Software | `validate` |
|----------|-----------|
| OpenSSH | `program: /usr/sbin/sshd`, `args: ["-t", "-f"]` |
| sudo | `program: /usr/sbin/visudo`, `args: ["-cf"]` |
| rsyslog | `program: /usr/sbin/rsyslogd`, `args: ["-N1", "-f"]` |
| Samba | `program: /usr/bin/testparm`, `args: ["-s"]` |

- On a non-zero exit, a signal, or a timeout the content is **not published**
  and the destination is left exactly as it was; a timeout or lost response is
  reported as indeterminate (the file is still unchanged).
- `program` must be an absolute path. `program`/`args` may interpolate
  `vars`/`facts`. A value derived from a `sensitive` variable makes the
  resource sensitive, and the validation command's output is then never shown.
- Without `validate`, the file is published exactly as before.

### Placing the staged file inside an argument (`{{ staged }}`)

Some checkers need the file path as part of an argument rather than as a
separate last argument — `postgres` only accepts `--config-file=PATH`. Write
`{{ staged }}` (blanks inside the braces are allowed) where the staged path
belongs; it is replaced by the staged file's path, and the path is then **not**
appended at the end:

```yaml
    validate:
      program: /usr/bin/postgres
      # -C must be the first argument when postgres runs as root
      args: ["-C", "port", "-D", "/var/lib/pgsql/data", "--config-file={{ staged }}"]
```

- Only `validate.args` may contain `{{ staged }}`; it may appear in several
  arguments. In `program` it is a load error, and anywhere else it is not a
  placeholder (`staged` is not a variable).
- The command is still argv-only; the placeholder never introduces a shell.
  `\{{ staged }}` is the literal text `{{ staged }}`.
- A value interpolated into an argument cannot create a placeholder.

| Software | `validate` |
|----------|-----------|
| PostgreSQL (`postgresql.conf` or a `conf.d` drop-in) | `program: /usr/bin/postgres`, `args: ["-C", "port", "-D", "<data dir>", "--config-file={{ staged }}"]` (PGDG: `/usr/pgsql-17/bin/postgres`) |
| Apache httpd (a `conf.d` file, checked with the full configuration) | `program: /usr/sbin/httpd`, `args: ["-t", "-c", "Include {{ staged }}"]` |

## Secret content

```yaml
- id: api_key
  type: file
  with:
    path: /etc/app/api.key
    content: { secret: secrets/api.key.age }
    owner: root
    group: root
```

The file's bytes come from an encrypted [age](https://age-encryption.org/v1)
file in your repository instead of the recipe text. Create it with
[`sinter secrets encrypt`](/en/reference/secrets/). Key points; the full
contract (identity discovery, passphrases, limits) is on
[sinter secrets](/en/reference/secrets/#using-a-secret-in-a-recipe):

- **Reference.** A static **relative** path, resolved against the directory of
  the recipe file that contains it (an included recipe uses its own directory),
  never against the working directory. Refused: an absolute path, a `.`, `..` or
  empty component, a backslash, a control character, `{{ }}` interpolation, any
  symbolic link below that directory, a target that is not a regular file, or a
  value that is not exactly `{ secret: <path> }`. `content` and `source` stay
  mutually exclusive. Only `file.content`, `user.password_hash` and
  `postgresql_role.password_verifier` accept one.
- **`validate`** checks the reference and that the file is a well-formed age
  file. It never decrypts and needs no key.
- **`plan`, `apply`, `audit`** decrypt the secret in memory, compare it with the
  target by SHA-256, and publish it as **exact bytes** (binary data, NUL bytes
  and the absence of a trailing newline are preserved; at most 16 MiB). No
  plaintext temporary file is written on the controller, and the content
  reaches the target on standard input, never on a command line.
- **Always sensitive**, whatever `sensitive:` says: the content diff is shown as
  redacted, diagnostics are redacted, and a **new** file defaults to mode
  `0600` (an existing file keeps its metadata unless you declare it).
- **No key, no change (fail closed).** If no identity is available (or a
  passphrase cannot be typed), `plan` fails (exit 4), `apply` fails that
  resource and stops the run, and apply never writes a partial file; `audit`
  reports `ERROR` for a file that exists on the target and `DRIFT` for one that
  does not. `state: absent` needs no key.
  The cause is printed once on standard error; the report itself stays
  redacted. Run `plan` first to learn about a missing key before anything
  changes.
- **Limits.** 16 MiB per secret, and the write must finish within the 300 second
  command deadline (see [Limits](/en/reference/secrets/#limits)). MCP manifest
  tools refuse secret references (see [Core MCP](/en/reference/mcp/)).

## Idempotency

Fully idempotent — content, mode, and ownership that already match produce no
mutation.

## Failure behavior

- Unsafe parent paths or unexpected symlinks → failure before mutation.
- Unsupported security metadata (ACL/xattr/SELinux context) that Sinter cannot
  preserve causes a refusal rather than silent loss.
- Diff output shows content changes unless the resource or content is
  sensitive — then it shows `redacted`.
- A `content: { secret: … }` whose key is unavailable fails before any change
  (see [Secret content](#secret-content)).

## Trust boundary

Applies to all supported targets. A managed path is observed only through a
parent chain Sinter has accepted, and it refuses rather than guessing.

- A parent must be a real directory owned by root (or, without `--sudo`, by
  the connecting user) and not group- or other-writable, unless it is a shared
  directory; the path must not cross a directory owned by a third account.
- **Shared directories** (`/tmp`, `/var/tmp`): a directory others can write is
  accepted as a parent when it is owned by root (without `--sudo`, also by the
  connecting user) and has the **sticky bit**. Inside it Sinter manages only
  entries owned by root. A new file is created exclusively — content, owner,
  mode and extended attributes are fixed on a private staging file, which is
  then hard-linked at the final path — so a name another account took first is
  never replaced (the resource fails and a rerun converges). Directly in `/tmp`,
  below a directory of another account, the operation runs as that account but
  only when the recipe sets `owner` to that account; otherwise it is refused in
  `plan` and `apply`.
- **Root managing an unprivileged account's directory** (a root login or
  `--sudo`): a path such as `/home/alice/page` is accepted when the first
  untrusted ancestor is a plain directory of an unprivileged account (not
  group- or other-writable, no ACL, nothing below it owned by a third account,
  no symlink). Sinter's file operations there run as that account (`setpriv`;
  capabilities dropped), so the account's tree cannot be used to make root
  write elsewhere. `setpriv` (util-linux) is required on the target for this
  case.
- **setgid directories**: staging a `file` or `link` in a directory with the
  setgid bit is refused before anything is written (a directory created there
  would inherit the group, so Sinter could not prove it is its own). Directories,
  metadata-only changes and removals there are managed as before.
- Directories others can write without the sticky bit, shared directories owned
  by another account, and shared directories inside another account's tree stay
  refused.

## Related

[template](/en/reference/resources/template/) ·
[directory](/en/reference/resources/directory/) ·
[link](/en/reference/resources/link/)
