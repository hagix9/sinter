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

An operation may provide environment variables explicitly. They are passed only
to this package operation (including its privileged apt/dnf execution); they do
not configure a persistent host-wide environment.

```yaml
- id: install-tools
  type: package
  with:
    name: curl
    state: present
    env:
      HTTP_PROXY: "http://proxy.example.com:3128"
      HTTPS_PROXY: "http://proxy.example.com:3128"
      NO_PROXY: "localhost,127.0.0.1,.example.internal"
```

## Parameters

| Parameter | Required | Type | Default | Description |
|-----------|----------|------|---------|-------------|
| `name` | yes | string | — | Package name (validated). |
| `state` | yes | string | — | `present` or `absent`. Required. |
| `env` | no | map of strings | empty | Environment variables for this package operation. |

## Expected behavior

- Backend is chosen automatically from the target's `/etc/os-release`
  identity — recipes stay platform-neutral.
- `present` on Ubuntu → `apt`; on RHEL-family targets (Rocky Linux, RHEL,
  AlmaLinux, Oracle Linux) → `dnf`.
- No version pinning in v0.5.1.
- On dnf targets, installs run through a private cache snapshot — see
  [Execution Model](/en/concepts/execution-model/) and the
  [Rocky guide](/en/guides/rocky-linux/).
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
| Ubuntu 24.04 / 26.04 LTS | apt |
| Rocky Linux 9 / 10 | dnf |
| RHEL 9 / 10 | dnf |
| AlmaLinux 9 / 10 | dnf |
| Oracle Linux | dnf (expected compatible — not acceptance-tested) |

## Related

[service](/en/reference/resources/service/) ·
[Execution Model](/en/concepts/execution-model/)
