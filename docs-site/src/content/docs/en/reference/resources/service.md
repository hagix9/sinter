---
title: service
description: Manage a systemd service's run state and enablement.
---

**Purpose:** ensure a systemd unit is `running`/`stopped` and/or
`enabled`/`disabled`.

## Synopsis

```yaml
- id: sshd
  type: service
  with:
    name: sshd
    state: running
    enabled: true
```

## Parameters

| Parameter | Required | Type | Default | Description |
|-----------|----------|------|---------|-------------|
| `name` | yes | string | — | systemd unit name. |
| `state` | no | string | — | `running` or `stopped`. |
| `enabled` | no | boolean | — | `true`/`false`. |

At least one of `state` or `enabled` is required.

## Expected behavior

- `state: running` starts the unit if needed; `stopped` stops it.
- `enabled: true`/`false` sets boot enablement.
- Works on any systemd target — Ubuntu and Rocky alike.
- Sinter does not run implicit `daemon-reload`; unit-file changes need their
  own handling.

## Idempotency

Fully idempotent — a unit already in the desired state is not restarted or
re-enabled.

## Failure behavior

- Unit not found → failure (in `plan`, a service depending on a
  not-yet-applied package may report deferred/unknown instead).
- `masked` unit requested `running` → failure; `static` unit with `enabled`
  → failure.
- Observation failures are reported as failure/indeterminate, never as
  change.

## Platform notes

Requires systemd on the target (all supported platforms).

## Related

[package](/sinter/en/reference/resources/package/) ·
[handlers](/sinter/en/concepts/recipes/)
