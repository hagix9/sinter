---
title: link
description: Manage a symbolic link.
---

**Purpose:** ensure a symbolic link at `path` points to `target` — or is
absent.

## Synopsis

```yaml
- id: vimrc
  type: link
  with:
    path: /etc/vim/vimrc.local
    target: /opt/myapp/vimrc.local
```

## Parameters

| Parameter | Required | Type | Default | Description |
|-----------|----------|------|---------|-------------|
| `path` | yes | string (absolute path) | — | Symlink path. |
| `target` | when `present` | string | — | Link target. Required when `state` is `present`. |
| `state` | no | string | `present` | `present` or `absent`. |

## Expected behavior

- `present`: creates the symlink if absent, or re-points an existing symlink
  whose target differs.
- `absent`: removes the symlink. Refuses to remove non-symlink objects as a
  link.

## Idempotency

Fully idempotent — a symlink already pointing at `target` is left alone.

## Failure behavior

- `path` is an existing non-symlink (file, directory) → failure; Sinter will
  not replace it implicitly.
- Unexpected symlinks in the *parent* path are rejected before mutation.

## Platform notes

Applies to all supported targets.

## Related

[file](/sinter/en/reference/resources/file/) ·
[directory](/sinter/en/reference/resources/directory/)
