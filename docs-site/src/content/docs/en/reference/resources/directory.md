---
title: directory
description: Ensure a directory exists with the desired metadata.
---

**Purpose:** ensure a directory exists (or is absent) with the desired owner,
group, and mode.

## Synopsis

```yaml
- id: appdir
  type: directory
  with:
    path: /opt/myapp
    mode: "0755"
    owner: root
    group: root
```

## Parameters

| Parameter | Required | Type | Default | Description |
|-----------|----------|------|---------|-------------|
| `path` | yes | string (absolute path) | — | Managed directory path. |
| `state` | no | string | `present` | `present` or `absent`. |
| `owner` | no | string | — | Owner name. |
| `group` | no | string | — | Group name. |
| `mode` | no | string | — | Quoted four-digit octal, e.g. `"0755"`. |

## Expected behavior

- `present`: creates exactly that directory — the parent must already exist
  (no recursive creation).
- `absent`: removes the directory. Refuses non-empty directories and
  non-directory objects.
- Metadata is preserved when `owner`/`group`/`mode` are omitted.

## Idempotency

Fully idempotent.

## Failure behavior

- Missing parent directory → failure (no implicit recursion).
- Unexpected symlink in the path → rejected before mutation.

## Platform notes

Applies to all supported targets.

## Related

[file](/sinter/en/reference/resources/file/) ·
[link](/sinter/en/reference/resources/link/)
