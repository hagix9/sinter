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
| `content` | no | string | — | Literal content. Mutually exclusive with `source`. |
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

## Idempotency

Fully idempotent — content, mode, and ownership that already match produce no
mutation.

## Failure behavior

- Unsafe parent paths or unexpected symlinks → failure before mutation.
- Unsupported security metadata (ACL/xattr/SELinux context) that Sinter cannot
  preserve causes a refusal rather than silent loss.
- Diff output shows content changes unless the resource or content is
  sensitive — then it shows `redacted`.

## Platform notes

Applies to all supported targets. Paths under world-writable directories such
as `/tmp` fail the trust-boundary check.

## Related

[template](/sinter/en/reference/resources/template/) ·
[directory](/sinter/en/reference/resources/directory/) ·
[link](/sinter/en/reference/resources/link/)
