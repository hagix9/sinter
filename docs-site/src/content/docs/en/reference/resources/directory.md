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
| `parents` | no | boolean (literal) | `false` | Also create the missing parent directories. See [Missing parents](#missing-parents). |

## Expected behavior

- `present`: creates exactly that directory — the parent must already exist,
  unless `parents: true` is set.
- `absent`: removes the directory. Refuses non-empty directories and
  non-directory objects.
- Metadata is preserved when `owner`/`group`/`mode` are omitted.

## Missing parents

By default a missing parent directory is an error: Sinter does not create
directories you did not ask for. With `parents: true` the directory is created
together with every missing directory above it:

```yaml
- id: data
  type: directory
  with:
    path: /srv/app/var/data
    owner: app
    group: app
    mode: "0750"
    parents: true
```

```toml
[[resources]]
id = "data"
type = "directory"
with = { path = "/srv/app/var/data", owner = "app", group = "app", mode = "0750", parents = true }
```

- `owner`, `group` and `mode` apply to the declared directory only
  (`/srv/app/var/data`).
- Each missing parent (`/srv/app`, `/srv/app/var`) is created with mode `0755`,
  owned by the account the change runs as (root with `--sudo`). Declare a
  `directory` resource of its own for a parent that needs other metadata.
- A parent that already exists is never changed — not its mode, not its owner.
- Parents are created one at a time, top down, each only after Sinter's
  [parent-path check](/en/reference/resources/file/#trust-boundary) accepted
  everything above it. A file or symbolic link in the path, or a parent that
  other accounts can write to, is refused and nothing is created below it.
- `plan` creates nothing and lists the directories `apply` will create.
- If a later step fails after a parent was created, the resource fails and the
  result names the directories that were created.
- `parents` must be written as `true` or `false` (no expression). It has no
  effect with `state: absent`: only the declared directory is removed.
- `file`, `template` and `link` never create a parent directory. Put a
  `directory` resource before them.

## Idempotency

Fully idempotent.

## Failure behavior

- Missing parent directory → failure, unless `parents: true` is set.
- Unexpected symlink in the path → rejected before mutation.

## Platform notes

Applies to all supported targets. Directory creation uses the same parent-path
trust boundary as [`file`](/en/reference/resources/file/#trust-boundary).
A directory in a directory listed in
[`allow_writable_parents`](/en/reference/recipe-format/#allow_writable_parents)
(also one that `parents: true` would create there) is refused: that exception
covers only whole files. Audit observes a directory whose direct parent others
can write by `lstat` only, with a note.

## Related

[file](/en/reference/resources/file/) ·
[link](/en/reference/resources/link/)
