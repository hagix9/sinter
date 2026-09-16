---
title: package
description: Install or remove a package via the target's package backend.
---

**Purpose:** ensure a package is installed (`present`) or removed (`absent`)
using the target's native package backend — `apt` on Ubuntu, `dnf` on
RHEL-family targets.

## Synopsis

```yaml
- id: tree
  type: package
  with:
    name: tree
    state: present
```

## Parameters

| Parameter | Required | Type | Default | Description |
|-----------|----------|------|---------|-------------|
| `name` | yes | string | — | Package name (validated). |
| `state` | yes | string | — | `present` or `absent`. Required. |

## Expected behavior

- Backend is chosen automatically from the target's `/etc/os-release`
  identity — recipes stay platform-neutral.
- `present` on Ubuntu → `apt`; on Rocky/RHEL family → `dnf`.
- No version pinning in v0.2.0.
- On dnf targets, installs run through a private cache snapshot — see
  [Execution Model](/sinter/en/concepts/execution-model/) and the
  [Rocky guide](/sinter/en/guides/rocky-linux/).
- Broken package states (half-configured etc.) fail rather than auto-repair.

## Idempotency

Fully idempotent — already-installed `present` and already-absent `absent`
produce no mutation and no package transaction.

## Failure behavior

- Unsupported platform / missing backend → capability error.
- Unresolvable package, repository errors, or ambiguous observation → failure
  or indeterminate, never a false change report.
- Observation failure before mutation is never reported as a change.

## Platform notes

| Platform | Backend |
|----------|---------|
| Ubuntu 24.04 LTS amd64 | apt |
| Rocky Linux 9 x86_64 | dnf |

## Related

[service](/sinter/en/reference/resources/service/) ·
[Execution Model](/sinter/en/concepts/execution-model/)
