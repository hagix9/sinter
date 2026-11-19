---
title: systemd_timer
description: Manage a systemd timer unit file and its enablement and run state.
---

**Purpose:** declare one systemd timer of the system manager: the unit file
`/etc/systemd/system/<name>.timer` and, optionally, whether the timer is
enabled and running.

## Synopsis

```yaml
- id: backup-timer
  type: systemd_timer
  with:
    name: backup
    on_calendar: "*-*-* 03:00:00"
    persistent: true
    randomized_delay_sec: 10min
    state: running
    enabled: true
```

## Parameters

| Parameter | Required | Type | Default | Description |
|-----------|----------|------|---------|-------------|
| `name` | yes | string | — | Timer name without `.timer`: `[A-Za-z0-9:_.-]`, 1–200 bytes, not starting with `.` or `-`. Templates (`@`) are not supported. |
| `unit` | no | string | `<name>.service` | Unit the timer activates (`Unit=`); must end in a unit suffix other than `.timer`. |
| `on_calendar` | no | string or list | — | `OnCalendar=` expressions, one line each. |
| `on_boot_sec` | no | string | — | `OnBootSec=` time span. |
| `on_unit_active_sec` | no | string | — | `OnUnitActiveSec=` time span. |
| `persistent` | no | boolean | — | `Persistent=`; requires `on_calendar`. |
| `accuracy_sec` | no | string | — | `AccuracySec=` time span. |
| `randomized_delay_sec` | no | string | — | `RandomizedDelaySec=` time span. |
| `description` | no | string | `Sinter timer <name>` | `Description=`. |
| `state` | no | string | — | `running`, `stopped` or `absent`. |
| `enabled` | no | boolean | — | Whether the timer is enabled. |

- At least one of `on_calendar`, `on_boot_sec` and `on_unit_active_sec` is
  required, except with `state: absent`, which allows only `name`.
- `name` and `unit` may use variables but not facts or registers.
- Time spans: an integer (seconds) or groups such as `5min`, `1h 30m`, `2.5s`,
  with the units `us`, `ms`, `s`/`sec`, `m`/`min`, `h`/`hr`, `d`/`day`,
  `w`/`week`, `M`/`month`, `y`/`year` (and their long forms). Nothing else of
  systemd's time-span grammar is accepted.
- `on_calendar` and `description`: printable ASCII without `\` and `%`, with no
  leading or trailing space (`on_calendar` also not starting with `-`), so no
  specifier and no line continuation can change what is written.
- Without `state` and `enabled`, only the unit file is managed.

## Expected behavior

- The unit file is written deterministically (owner `root:root`, mode `0644`)
  through the same code as a [`file`](/en/reference/resources/file/)
  resource: compared by content, backed up and replaced safely. It always ends
  with `[Install]` `WantedBy=timers.target`.
- Writing the unit file is manager input, so Sinter's
  [automatic manager synchronization](/en/reference/resources/service/#automatic-manager-synchronization)
  runs `systemctl daemon-reload` before the timer is enabled or started.
  A content change of an active timer reloads the manager and does not
  restart, stop or start the timer.
- Enabling, disabling, starting and stopping work as for the
  [`service`](/en/reference/resources/service/) resource, on the unit
  `<name>.timer`.
- When `state: running` or `enabled: true` is requested, the activated unit
  must exist after the reload; otherwise the timer is neither enabled nor
  started and the resource fails (the written unit file is reported).
- `state: absent` stops and disables the timer, removes the unit file,
  reloads the manager and requires the unit to be gone.
- Every `on_calendar` expression is checked on the target with
  `systemd-analyze calendar <expr>` before anything changes; an invalid
  expression, or a target without `systemd-analyze`, fails the resource. A
  `systemd_timer` with only `on_boot_sec`/`on_unit_active_sec` runs no such
  check.
- Refused before any change (plan, apply and audit): a masked timer; a
  timer whose unit file exists outside `/etc/systemd/system` (for example a
  vendor unit — Sinter does not shadow or remove it); a timer with drop-ins
  (`<name>.timer.d/`), which Sinter does not manage.
- A file, template or link resource on the same path, or a second
  `systemd_timer` with the same name, is a validation error.
- A change notifies handlers like any other resource.
- Audit reports content, enablement, state and a missing activated unit as
  drift, and the refusals above as errors.
- The `--user` manager is not supported.
- Not available through MCP yet: the target-side calendar check is not yet
  confirmed read-only on every supported target.

## Relation to `service`

A [`service`](/en/reference/resources/service/) resource can still enable and
start an existing `<name>.timer` unit (for example one written by a `file`
resource). `systemd_timer` adds the unit file, its checks and removal.

## Example

```yaml
version: 1
resources:
  - id: backup-service
    type: file
    with:
      path: /etc/systemd/system/backup.service
      content: |
        [Service]
        Type=oneshot
        ExecStart=/usr/local/bin/backup
  - id: backup-timer
    type: systemd_timer
    depends_on: [backup-service]
    with:
      name: backup
      on_calendar: daily
      persistent: true
      state: running
      enabled: true
```
