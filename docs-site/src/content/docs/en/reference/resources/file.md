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
| `content` | no | string, or `{ secret: <path> }` | — | Literal content, or an encrypted secret (unreleased, after v1.1.3: see [sinter secrets](/en/reference/secrets/#using-a-secret-in-a-recipe)). Mutually exclusive with `source`. |
| `source` | no | string | — | Controller-side file copied to `path`; relative paths are resolved against the recipe file's directory. Mutually exclusive with `content`. |
| `owner` | no | string | — | Owner name. |
| `group` | no | string | — | Group name. |
| `mode` | no | string | — | Quoted four-digit octal, e.g. `"0644"`. |

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

## Secret content

:::caution[Unreleased]
`content: { secret: <path> }` is on the `main` branch after v1.1.3. It is **not**
in the v1.1.3 release binary.
:::

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
  mutually exclusive. Only `file.content` and `user.password_hash` accept one.
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

## Platform notes

Applies to all supported targets. Paths under world-writable directories such
as `/tmp` fail the trust-boundary check.

## Related

[template](/en/reference/resources/template/) ·
[directory](/en/reference/resources/directory/) ·
[link](/en/reference/resources/link/)
