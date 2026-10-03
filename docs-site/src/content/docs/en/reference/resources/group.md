---
title: group
description: Ensure a local Linux group exists (or is absent), with an optional fixed gid.
---

:::caution[Unreleased]
`group` and `user` are on the `main` branch after v1.1.3. They are **not** in
the v1.1.3 release binary; they ship with the next release.
:::

**Purpose:** declare a **local** Linux group (`/etc/group`): present or
absent, with an optional fixed `gid`. It is planned, applied and audited like
any other resource.

## Synopsis

```yaml
- id: app_group
  type: group
  with:
    name: app
    gid: 990
    system: true
```

## Parameters

| Parameter | Required | Type | Default | Description |
|-----------|----------|------|---------|-------------|
| `name` | yes | string | — | Group name. Static (may use `vars` or `item`). `[a-z_][a-z0-9_-]*`, at most 32 characters. |
| `state` | no | string | `present` | `present` or `absent`. |
| `gid` | no | integer | unmanaged | Required gid, 1–4294967294. Never `0`. |
| `system` | no | boolean | `false` | Create a system group (`groupadd --system`). Create-time only; never audited or changed later. |

Unknown fields are schema errors. There are no `members`, `password` or
`force` fields.

## Expected behavior

- **Local only.** The group is observed with `getent -s files group`. A group
  that only another identity source (LDAP, SSSD, NIS) provides is an
  **error** — Sinter never creates a local group that would shadow it.
- `present`, group missing → `groupadd [--system] [-g gid] name`.
- `present`, group exists → nothing is changed. If a declared `gid` differs
  from the existing gid, the run is **refused** (plan error / apply failure)
  and `audit` reports `DRIFT` on `gid`. An existing group is never renumbered:
  that would orphan the files it owns.
- Creating with a `gid` that another local group already uses is refused
  before anything runs.
- `absent`, group exists → `groupdel name` (no force). Refused for the root
  group, for the group this run executes as, and for any group that is some
  local user's **primary** group (the refusal names those users). Files owned
  by the gid are not touched.
- Membership is managed from the [`user`](/en/reference/resources/user/)
  resource (`groups`), never here.

## Idempotency

A group that already matches (name, and `gid` when declared) mutates nothing.

## Plan and audit

- `plan` observes only and reports a create or delete as a change.
- A `file`, `directory` or `template` whose `group` names a group created by a
  `group` resource that it lists in `depends_on` is **deferred** (unknown until
  apply) instead of failing the plan. Nothing is inferred: without
  `depends_on` the plan error for an unknown group stays.
- `audit` reports drift on `state` and `gid`; an externally provided group is
  `ERROR`.

## Failure behavior

- A failing `groupadd`/`groupdel` is a failure with a *possible* change and
  unknown verification; the group is not re-observed after a failed command.
  After a command that exits 0 the group is re-observed, and a command that
  did not produce the declared state fails verification.
- Dependents of a failed group do not run.

## Platform notes

Uses `/usr/sbin/groupadd` and `/usr/sbin/groupdel` and `getent` on Ubuntu 24.04
/ 26.04 and Rocky Linux, RHEL and AlmaLinux 9 / 10. Behavior on real hosts of
each distribution is pending real-OS acceptance.

## Related

[user](/en/reference/resources/user/) ·
[Resources](/en/concepts/resources/)
