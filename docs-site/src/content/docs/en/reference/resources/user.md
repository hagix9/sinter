---
title: user
description: Ensure a local Linux user exists (or is absent) with a declared id, primary group, shell, home record and supplementary groups.
---

:::caution[Unreleased]
`group` and `user` are on the `main` branch after v1.1.3. They are **not** in
the v1.1.3 release binary; they ship with the next release.
:::

**Purpose:** declare a **local** Linux user (`/etc/passwd`): present or
absent, and — only for the dimensions you name — its uid, primary group,
shell, home directory record and supplementary groups. Unnamed dimensions are
never changed and never audited.

## Synopsis

```yaml
- id: app_group
  type: group
  with:
    name: app
    gid: 990
    system: true

- id: app_user
  type: user
  depends_on: [app_group]
  with:
    name: app
    uid: 990
    group: app
    groups: [systemd-journal]
    shell: /usr/sbin/nologin
    home: /var/lib/app
    system: true

- id: app_state
  type: directory
  depends_on: [app_user]
  with:
    path: /var/lib/app
    owner: app
    group: app
    mode: "0750"
```

## Parameters

| Parameter | Required | Type | Default | Description |
|-----------|----------|------|---------|-------------|
| `name` | yes | string | — | User name. Static. `[a-z_][a-z0-9_-]*`, at most 32 characters. |
| `state` | no | string | `present` | `present` or `absent`. |
| `uid` | no | integer | unmanaged | Required uid, 1–4294967294. Never `0`. |
| `group` | no | string | unmanaged | Primary group, **by name**. It must already exist (see Dependencies). |
| `groups` | no | list of strings | unmanaged | Supplementary groups, by name. **Additive**: the user is added to these, never removed from any group. May not repeat the primary group. |
| `shell` | no | string | unmanaged | Absolute path of the login shell (`/usr/sbin/nologin`). Not validated against `/etc/shells`. |
| `home` | no | string | unmanaged | Absolute path stored as the home directory. **Only the record is set**; nothing is created or moved. |
| `create_home` | no | boolean | `false` | Create the home directory (`useradd -m`). Create-time only. With `false`, `-M` is passed explicitly. |
| `system` | no | boolean | `false` | Create a system user (`useradd --system`). Create-time only; never audited or changed later. |

Unknown fields are schema errors. There are no password, lock, expiry, SSH key,
`move_home`, `remove_home`, `force` or `non_unique` fields: those are not part
of this resource.

When a dimension is not declared, `useradd` applies the distribution default at
creation (for example a same-named private group when `group` is omitted; if a group of that name already exists, or a `group` dependency creates it, Sinter refuses and asks you to declare `group:`). Use
the [`directory`](/en/reference/resources/directory/) resource to manage the
home directory itself.

## Expected behavior

- **Local only.** The user is observed with `getent -s files passwd`. A user
  that only another identity source provides is an **error**; Sinter never
  creates a local user that would shadow it. The same holds for the groups
  named in `group`/`groups`.
- `present`, user missing → one `useradd`
  (`[--system] [-u uid] [-g group] [-G g1,g2] [-s shell] [-d home] (-m|-M) name`).
  Creating with a `uid` already used by another local user is refused.
- `present`, user exists → at most one `usermod`
  (`-g`, `-s`, `-d`, and `-a -G` for the missing groups only). `-m` is never
  passed: **the home directory is not moved**.
- **A uid mismatch on an existing user is refused**, never repaired
  (`usermod -u` would not re-own files outside the home). `audit` reports
  `DRIFT` on `uid`.
- Supplementary membership is **additive**: groups the user is already in, and
  groups you did not declare, are left alone. Exact membership is not
  supported.
- `absent`, user exists → `userdel name` **without** `-r` or `-f`. The home
  directory and mail spool are kept, files owned by the uid remain (the result
  says so; nothing searches the file system), and, if the distribution's
  `userdel` also removes the user's same-named private group, the result notes
  it. Refused for `root`, uid 0, the account this run executes as, and the
  account running or connecting the session. A user with running processes
  makes `userdel`/`usermod` fail and is reported as a failure.

## Dependencies

Dependencies are explicit; nothing is inferred.

- A user whose `group`/`groups` name a group created by a `group` resource must
  list that resource in `depends_on`. In `plan`, such a user is **deferred**
  (unknown until apply) instead of failing; the same applies to everything that
  depends on it. A missing group with no such dependency is a plan error that
  says so.
- A `file`, `directory` or `template` whose `owner`/`group` names an account
  created by a `user`/`group` resource listed in its own `depends_on` is
  deferred in `plan`. Without `depends_on`, planning an owner that does not
  exist yet still fails with the unknown-account error.

## Idempotency

A user that matches every declared dimension mutates nothing. A converged
second `apply` runs no `useradd`/`usermod`/`userdel`.

## Audit

`audit` reports each declared dimension independently — `state`, `uid`,
`group`, `groups`, `shell`, `home` — as drift. An account provided only by
another identity source is `ERROR`. `create_home` and `system` are create-time
options and are not audited.

## Failure behavior

- A failing account command is a failure with a *possible* change and unknown
  verification; the account is not re-observed after a failed command. After a
  command that exits 0 the account is re-observed, and one that did not produce
  the declared state fails verification.
- Refusals (renumbering, protected account, in-use id, missing group,
  externally provided account) happen before any command runs and are plan
  errors in `plan`.
- Dependents of a failed user do not run.

## Platform notes

Uses `/usr/sbin/useradd`, `usermod`, `userdel` and `getent`, with argv only and
no shell. Behavior on real hosts of Ubuntu 24.04 / 26.04 and Rocky Linux,
RHEL and AlmaLinux 9 / 10 is pending real-OS acceptance.

## Related

[group](/en/reference/resources/group/) ·
[directory](/en/reference/resources/directory/) ·
[Resources](/en/concepts/resources/)
