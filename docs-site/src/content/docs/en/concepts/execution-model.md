---
title: Execution Model
description: plan vs apply vs audit — observation, verification, fail-fast, indeterminate states.
---

Sinter separates observation from mutation and keeps the outcome dimensions
distinct.

## validate

`sinter validate` loads the recipe, expands includes and loops, checks schema
and semantics — and never contacts a target.

## plan — observation only

`sinter plan` connects to the target and observes each resource's current
state, then reports what an apply would do. It never:

- writes files or uploads staging data
- changes permissions or ownership
- installs or removes packages
- changes services
- runs `systemctl daemon-reload`
- executes command resources

A plan is a preview, not an approval artifact — it is never replayed as
authority.

If an earlier resource in the plan changes a systemd manager input (a unit
file, drop-in, alias link or `system.conf`), or the manager already reports
`NeedDaemonReload=yes`, later `service` resources are reported as unknown
(`?`, deferred until manager synchronization at apply) rather than "unchanged"
or failed. The reloads an apply would perform are listed separately under
`manager_reloads`.

## apply — observe, mutate, verify

`sinter apply` re-observes every stateful resource immediately before deciding
to mutate. After a mutation it verifies the outcome. Mutations that cannot be
confirmed are reported as **indeterminate**, never retried automatically
(timeout after dispatch, lost response, signal uncertainty).

**Manager synchronization.** When a changed resource touches a systemd manager
input, or a unit reports `NeedDaemonReload=yes`, `apply` runs
`systemctl daemon-reload` at the consumer boundary: before a `service`
resource decides, before each notified handler, and at the end of a successful
apply. The unit is observed again after the reload, and only that fresh state
decides what to do. A reload does not restart anything. See
[service](/en/reference/resources/service/#automatic-manager-synchronization).

**Handlers phase.** After normal traversal succeeds, handlers run in
declaration order, each preceded by a manager reload if one is pending, then a
fresh observation, the `restart`/`reload` action, and verification. A run that
stopped early does not start a new reload; the report then says the manager is
unsynchronized.

:::caution[Known limitation: a failed apply drops pending notifications]
Handlers run only when the apply did not stop, that is when no resource
failed or ended indeterminate. If an apply fails after
a resource already changed a file that notifies a handler, the handler does
not run, and the next apply — finding the file correct — notifies nobody.
After a failed apply, restart or reload the affected services by hand.

**Recovering by hand.** The report names every handler that did not run: the
text output lists them under `pending handlers`, and the JSON output lists the
IDs in `handlers_pending` (a handler that ran and failed is in `handlers` with
`state` `Failed` or `Indeterminate`). For each one, find the handler in the
recipe and perform its action yourself, for example
`systemctl restart app.service` or `systemctl reload app.service` for the
handler's `service` and `action`; for a `ca_trust` handler run
`update-ca-certificates` (Debian, Ubuntu) or `update-ca-trust extract` (RHEL,
Rocky Linux, AlmaLinux) as root; for a `command` handler run its `program`
with its `args` yourself. Sinter will not run it on the next apply:
the resource that notified it is already correct. This holds for every handler
type.
:::

## audit — read-only verification

`sinter audit` answers a different question than `plan`. Plan asks *what
would an apply change?*; audit asks *does the target already match the
recipe?* It uses the same read-only observation paths, never mutates, and
reports each resource as `PASS`, `DRIFT`, `NOT_AUDITABLE`,
`NOT_APPLICABLE`, or `ERROR` in deterministic dependency/execution order.

- Command resources are always `NOT_AUDITABLE` — audit never executes them.
- Audit never runs `daemon-reload`. A service whose manager reports
  `NeedDaemonReload=yes` shows an independent `manager_reload` drift, even when
  it is active and enabled as desired. `NeedDaemonReload=no` is a limited
  observation, not proof that the loaded definition equals the file on disk.
- Exit codes encode the verdict: `0` when nothing drifted and no observation
  errors occurred, `7` on drift, `6` when any observation errored — errors
  dominate drift. An exit-0 audit may still contain `NOT_AUDITABLE` or
  `NOT_APPLICABLE` resources, so check the summary rather than assuming
  every resource was verified.

## Result dimensions

Sinter reports execution, change, verification, and disposition separately so
states like `changed`, `failed`, `indeterminate`, `possible`, `verified`, and
`blocked` are not flattened into a boolean.

- A mutation that succeeded followed by a later failure still reports the
  change truthfully.
- A verification failure is never reported as success.

## Fail-fast

The first failed or indeterminate resource stops the run. Remaining resources
are reported as `blocked`.

## Target-side execution

- Local targets are used when `--host` is omitted; SSH otherwise.
- From v1.1.0, `--inventory` runs a recipe on several hosts — only on the
  hosts its own `targets` select. Being in the inventory never authorizes
  execution; a recipe without `targets` is an error. See
  [Multiple hosts](/en/reference/cli/#multiple-hosts).
- Remote commands run with exact argv — no unintended shell evaluation; NUL
  bytes are rejected.
- `--sudo` runs every target-side operation as root via non-interactive
  `sudo -n`. Sinter never retries a permission failure with sudo.
- Command resources get a fixed baseline environment (`PATH`, `LANG`,
  `LC_ALL`, `HOME`); controller and SSH-session variables are not inherited.
- Filesystem mutations enforce a parent-path trust boundary, reject
  unexpected symlinks, and publish content atomically: by rename outside a
  shared directory, or by hard-linking a private staging file inside a sticky
  shared directory such as `/tmp`. When running as root, a path inside an
  unprivileged account's own directory is managed as that account (`setpriv`).
- Captured stdout/stderr per command is limited (1 MiB each).

## Package backend isolation (dnf)

On RHEL-family targets, package installs run through a private snapshot of
the DNF metadata cache: cache-only metadata validation and deterministic
transaction resolution freeze the exact package identities; the resolved
RPM payloads are then downloaded through the native `dnf`/librepo transport
— repository authentication stays with dnf/librepo — and each payload's RPM
identity is verified against the frozen transaction set before a final
cache-only `dnf` install (`-C --setopt=cachedir=...`). If payload
completeness or identity cannot be proven, the install fails closed before
any mutation. The private snapshot is created with 0700 permissions and
removed after the operation, including on failure.
