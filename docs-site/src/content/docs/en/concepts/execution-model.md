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
- executes command resources

A plan is a preview, not an approval artifact — it is never replayed as
authority.

## apply — observe, mutate, verify

`sinter apply` re-observes every stateful resource immediately before deciding
to mutate. After a mutation it verifies the outcome. Mutations that cannot be
confirmed are reported as **indeterminate**, never retried automatically
(timeout after dispatch, lost response, signal uncertainty).

## audit — read-only verification

`sinter audit` answers a different question than `plan`. Plan asks *what
would an apply change?*; audit asks *does the target already match the
recipe?* It uses the same read-only observation paths, never mutates, and
reports each resource as `PASS`, `DRIFT`, `NOT_AUDITABLE`,
`NOT_APPLICABLE`, or `ERROR` in deterministic dependency/execution order.

- Command resources are always `NOT_AUDITABLE` — audit never executes them.
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
- Remote commands run with exact argv — no unintended shell evaluation; NUL
  bytes are rejected.
- `--sudo` runs every target-side operation as root via non-interactive
  `sudo -n`. Sinter never retries a permission failure with sudo.
- Command resources get a fixed baseline environment (`PATH`, `LANG`,
  `LC_ALL`, `HOME`); controller and SSH-session variables are not inherited.
- Filesystem mutations enforce a parent-path trust boundary, reject
  unexpected symlinks, and publish content atomically by rename.
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
