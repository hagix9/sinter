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
- Works on any systemd target — Ubuntu and RHEL-family alike.
- Before a service resource observes the unit, Sinter synchronizes the
  systemd system manager (`systemctl daemon-reload`) if it has to — see
  [Automatic manager synchronization](#automatic-manager-synchronization).
  The unit is then re-observed, and only that fresh state decides
  start/stop/enable/disable.
- Observation requests exactly `LoadState,ActiveState,UnitFileState,NeedDaemonReload`.
  A missing, duplicated, invalid or truncated property, a non-zero exit or
  non-UTF-8 output is a failure — it is never read as `NeedDaemonReload=no`.
- `enable`/`disable` keep systemctl's own implicit reload (Sinter does not use
  `--no-reload`). After enabling/disabling, Sinter observes again before
  deciding whether `start` is still needed.

## Automatic manager synchronization

Sinter runs `systemctl daemon-reload` on the system manager when it is needed;
you do not write a `command` resource for it.

**A reload is needed when**

- a [`file`](/en/reference/resources/file/),
  [`template`](/en/reference/resources/template/) or
  [`link`](/en/reference/resources/link/) resource really changes (create,
  change, remove, symlink create/replace/remove) a systemd manager input:
  a unit file (`*.service`, `*.socket`, `*.target`, `*.timer`, `*.path`,
  `*.mount`, `*.automount`, `*.swap`, `*.slice`, including templates such as
  `foo@.service`), a drop-in (`<unit>.d/*.conf`, type-wide `service.d/*.conf`,
  prefix `foo-.service.d/*.conf`), or an alias/mask/`.wants`/`.requires` link —
  located directly in one of the manager's own unit load path roots (Sinter
  reads them with `systemctl show --property=UnitPath` and compares paths
  lexically; it does not assume `/etc/systemd/system`) — or the system manager
  configuration `/etc/systemd/system.conf` and `system.conf.d/*.conf`
  (`/etc`, `/run`, `/usr/lib`, `/usr/local/lib` under `systemd/`); or
- a fresh observation reports `NeedDaemonReload=yes` for a unit the recipe uses
  (a `service` resource, a notified handler's service, or a managed unit
  file/drop-in that names a single unit).

Metadata-only changes (chmod/chown), directories, ordinary application
configuration, `/etc/systemd/journald.conf`, `user.conf`, and
`/etc/systemd/user/...` never cause a reload. The `UnitPath` query is made only
when a managed path's file name looks like unit/drop-in/link input. If it
cannot be run or parsed, that resource fails **before** any mutation (in
`plan`: a plan error); Sinter never guesses.

**Where the reload happens**

1. Before a `service` resource observes and decides — before its "already
   matches" early return.
2. Before each notified handler (`restart`/`reload`) runs.
3. At the end of a successful apply, so a file-only unit update is still
   reloaded.

One reload covers every change pending at that moment. For
unit A → service A → unit B → service B, two reloads happen (one per consumer
boundary); there is no "at most once per run" rule. When nothing is pending
and the unit reports `NeedDaemonReload=no`, no reload is issued — a second
unchanged apply issues none, and an ordinary-config notify restart issues none.

Sinter does not reorder resources: put the unit producer before its consumer
with `depends_on` or declaration order. A producer placed after a service does
not redo that service; the end-of-run reload still happens.

If the unit is still `NeedDaemonReload=yes` after a reload, the apply fails as
"unresolved" (no retry loop; at most one reload per cause: pending input,
observed staleness).

**`daemon-reload` is not a restart.** It reloads the manager's unit
definitions; running processes keep running with their old configuration. To
apply new unit content to a running process, notify a `restart` handler (or a
`reload` handler if the service supports `ExecReload`). Manager reload
(`daemon-reload`), `systemctl restart foo` and `systemctl reload foo` are three
different operations. For handlers the order is: manager reload → fresh
observation → handler action → verification.

**Package → service.** Apply never reloads just because a package changed. If a
*changed* package that the service explicitly depends on (`state: present`)
leaves the unit not found, Sinter performs exactly one discovery reload and
re-observes; if the unit is still not found, the resource fails (no retry).

**Limits**

- Only the system manager is managed. The user manager (`systemctl --user`,
  `~/.config/systemd/user`, `/etc/systemd/user`, `user.conf`) is not managed
  and Sinter never uses `--user`. There is no `daemon-reexec`.
- A reload acts on the whole system manager: it also loads other pending
  on-disk edits and re-runs generators, and it does not restart services.
- systemd rate limits (`ReloadLimit*`) and authorization can make a reload
  fail. Reloading `system.conf` does not guarantee every directive takes
  effect.
- `NeedDaemonReload` cannot see an external edit with the same or an older
  mtime.
- Path comparison with `UnitPath` roots is lexical: aliases such as `/lib` vs
  `/usr/lib` are not equated, and an unrecognized path simply does not trigger
  a reload by itself. A unit file shadowed by a higher-priority root still
  triggers a reload; a fragment linked from outside the load path is noticed
  only through `NeedDaemonReload`.
- Real-OS behavior across the supported distributions is validated separately.

## Plan and audit

`plan` is read-only: it never runs `daemon-reload`, enable/disable or
start/stop/restart/reload. If an earlier resource in the plan changes managed
systemd input — or the manager currently reports `NeedDaemonReload=yes` for the
unit — the service is reported as unknown (`?`, "deferred/unknown until manager
synchronization at apply…"), not as unchanged and not as a failure. The reload
that apply would perform is listed separately in `manager_reloads`.

`audit` is read-only and never reloads. It reports an independent drift
dimension `manager_reload` (observed "daemon-reload pending
(`NeedDaemonReload=yes`)", desired "manager synchronized") on a service even
when active/enabled match, and on a managed unit file or drop-in that names a
single unit. It is separate from content/mode/owner and state/enabled drift,
and `NeedDaemonReload=yes` is never treated as repaired. `NeedDaemonReload=no` is
a limited observation (systemd compares mtimes/paths, not content hashes): it
is not proof that the loaded definition equals the bytes on disk. A managed
input that cannot be mapped to one unit (a template, a type-wide or prefix
drop-in, `system.conf`) carries a note "manager consistency not verified…". An
unobservable `NeedDaemonReload`/`UnitPath` is an observation error (aggregate
`indeterminate`), never `no_drift`. `link` resources get no manager facet in
audit.

## Idempotency

Fully idempotent — a unit already in the desired state is not restarted or
re-enabled, and a manager that is already synchronized is not reloaded.

## Failure behavior

- Unit not found → failure (in `plan`, a service depending on a
  not-yet-applied package may report deferred/unknown instead).
  A missing unit is never read as `stopped`, so a recipe that stops a unit
  and then removes its unit file succeeds the first time but fails when
  applied again ("service unit … was not found"). Once the unit is retired,
  drop its `service` resource and keep the `file` resource with
  `state: absent`.
- `masked` unit requested `running` → failure; `static` unit with `enabled`
  → failure.
- Observation failures are reported as failure/indeterminate, never as
  change.
- `daemon-reload` exits non-zero → failure (`apply_failed`): the dependent
  service resource or notified handler does nothing (no start/enable/restart),
  earlier successful file/template/link results stay `changed`, nothing is
  rolled back, and the reload is never retried in the same run.
- `daemon-reload` times out, is killed by a signal, or loses its response →
  `indeterminate`; never reported as success or as unchanged.
- Reload succeeded but the fresh observation failed → the reload stays in the
  report as executed/changed and the consumer fails (verification failed).
- A run that stopped earlier (a failed resource or handler) does not start a new
  reload. If managed input had changed, the report says the reload was **not**
  run and the manager is unsynchronized: re-apply, or run
  `systemctl daemon-reload` manually. Sinter keeps no journal across runs, so
  it cannot remember that a previous apply stopped before its reload; a later
  run reloads only if `NeedDaemonReload=yes` is observed or a new change occurs.

## Platform notes

Requires systemd on the target (all supported platforms).

## Related

[package](/en/reference/resources/package/) ·
[handlers](/en/concepts/recipes/)
