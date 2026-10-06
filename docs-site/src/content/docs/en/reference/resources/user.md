---
title: user
description: Ensure a local Linux user exists (or is absent) with a declared id, primary group, shell, home record and supplementary groups.
---

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
| `shell` | no | string | unmanaged | Absolute path of the login shell (`/usr/sbin/nologin`). Not validated against `/etc/shells`. Same path rules as `home`. |
| `home` | no | string | unmanaged | Absolute path stored as the home directory. **Only the record is set**; nothing is created or moved. See [Path rules](#path-rules-for-home-and-shell). |
| `create_home` | no | boolean | `false` | Create the home directory (`useradd -m`). Create-time only. With `false`, `-M` is passed explicitly. |
| `system` | no | boolean | `false` | Create a system user (`useradd --system`). Create-time only; never audited or changed later. |
| `password_hash` | no | `{ secret: <path> }` | unmanaged | The password **hash** (not the password), kept as an encrypted secret. See [Password hash](#password-hash). |

Unknown fields are schema errors. There are no plaintext password, lock,
expiry, SSH key, `move_home`, `remove_home`, `force` or `non_unique` fields:
those are not part of this resource.

### Path rules for `home` and `shell`

Both are stored in a colon-separated `/etc/passwd` record, so the same rules
apply to each: an absolute path that is not `/` itself, with no empty, `.` or
`..` component, no repeated or trailing `/`, no NUL, and none of the characters
`:` or `,` or any control character. A literal that breaks the rules is a
schema error (`validate` fails). A value that uses `{{ }}` interpolation is
checked after it is evaluated, and an invalid result is an error before any
command runs. Neither case changes the account silently.

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

## Password hash

`password_hash` needs [encrypted secrets](/en/reference/secrets/#using-a-secret-in-a-recipe).

```yaml
- id: app_user
  type: user
  with:
    name: app
    password_hash: { secret: secrets/app-password-hash.age }
```

Sinter never sees a plaintext password and has no `password` field. You make a
hash with your own tooling (`mkpasswd -m sha-512`, `openssl passwd -6`,
`python -c 'import crypt…'`), store that one line with
`sinter secrets encrypt`, and reference it. **A hash is secret material**
(offline-crackable): it is never written in a recipe and never shown.

- **Accepted values:** exactly one `$y$` (yescrypt) or `$6$` (sha512crypt) hash
  (`$6$[rounds=N$]salt$hash`, N 1000–999999999), at most 256 bytes, characters
  `[./0-9A-Za-z]` only, with at most one trailing newline. Anything else (DES, `$1$`, `$5$`,
  bcrypt, a plaintext password, extra whitespace, a leading `!` or `*`) is
  refused without echoing it.
- **Salt:** `$6$` salts must be 1–16 characters of `[./0-9A-Za-z]`, which is
  stricter than crypt(5): a hash made with `openssl passwd -6 -salt 'my_salt'`
  is refused, so let the tool generate the salt.
- **EL9:** `$y$` is refused on RHEL, Rocky and AlmaLinux 9 (shadow-utils and
  libxcrypt there are built without yescrypt): use `$6$`. Sinter does not check
  other platforms: a `$y$` hash on a distribution that cannot verify yescrypt
  (older than the supported targets) would be stored but could not log in.
- **`--sudo` is required.** `/etc/shadow` is readable only by root. Without
  `--sudo`, `plan`, `apply` and `audit` fail (`audit` reports `ERROR`); they
  never report "no change". The secret is not opened before that check.
- **Always sensitive**, whatever `sensitive:` says, and this covers the **whole
  resource**, not only the password: the plan diff is shown as redacted, notes
  and errors are fixed text (the account name appears as `[redacted]` and a
  refusal gives a generic reason), and tool stderr is never shown. `audit` still
  names each drifting dimension (`uid`, `shell`, `groups`, `password_hash`, …),
  but both sides of **every** dimension are `[redacted]`, never a value. For a
  user that declares `password_hash`, observed and desired ids, paths and group
  names are therefore not visible in any output.
- **`validate` never decrypts.** It checks the reference and that an age file
  is there. `plan`, `apply` and `audit` decrypt, with the identity discovery of
  [`sinter secrets`](/en/reference/secrets/); an unavailable key fails the
  resource (`ERROR` in `audit`), never "no change".
- **Not combined with `state: absent`** (schema error).

How it is applied and observed:

- The stored field is read with `getent -s files shadow <name>` under `sudo` and
  compared **in memory** with the declared hash. A leading `!` (a locked
  account) is ignored in the comparison, so a locked account that already holds
  the declared hash is compliant and stays locked. An unreadable or missing shadow
  record, or an account that is not in the local files, is an error.
- On a mismatch, `/usr/sbin/chpasswd -e` runs under `sudo -n` with
  `name:hash` on **standard input** (never on a command line, never
  `usermod -p`, never a shell). Nothing is written when the hash already
  matches. Each write resets the account's last-change date (password aging).
- A new user is created first (`useradd`), then its password is set. If the
  password step fails after the account was created or changed, the result says
  so (change `changed`, failed); running again finishes the job.
- **A declared hash is enforced**: a password the user changed is replaced
  at the next `apply`.
- **Locked accounts:** an account locked with a *different* password hash
  (`!<hash>`) is **refused**, because `chpasswd -e` replaces the field and
  would silently unlock it; there is no lock field yet. An account with no
  password at all (an empty field, `!`, `!!`, `*`, `!*` or a similar marker)
  simply gets the hash, which also means a `!!` account becomes
  password-enabled.
- The controller briefly holds the account's *current* stored hash in memory to
  compare it; this is as sensitive as the declared one and is documented, not
  hidden. This `password_hash` behavior was accepted on real hosts on
  2026-10-04, including `sudo-rs` on Ubuntu 26.04; see
  [Supported Platforms](/en/compatibility/platforms/#real-host-acceptance-of-the-unreleased-secrets-features).

## Dependencies

Dependencies are explicit; nothing is inferred. A lookup is deferred only when
the resource that creates the account is listed **directly** in the dependent
resource's own `depends_on` and its `state` evaluates to `present` (the
default). An account created by a resource that is reachable only through a
chain of other dependencies, or by one that is `absent`, is not taken into
account, and the unknown-account plan error stays. Deferral exists only in
`plan`; `apply` runs in dependency order and looks accounts up for real.

- A user whose `group`/`groups` name a group created by a `group` resource must
  list that resource in its own `depends_on`. In `plan`, such a user is **deferred**
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
`group`, `groups`, `shell`, `home` and `password_hash` — as drift. Values are
shown for an ordinary user; for a user with `password_hash` (always sensitive)
both sides of every dimension are `[redacted]`, and `password_hash` never has a
value. An account provided only by
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

Uses `/usr/sbin/useradd`, `usermod`, `userdel`, `chpasswd` and `getent`, with
argv only and no shell. The `password_hash` behavior above was accepted on real
hosts of Ubuntu 24.04 / 26.04 and Rocky Linux, RHEL and AlmaLinux 9 / 10 on
2026-10-04. The `useradd` / `usermod` / `userdel` dimensions of this resource
were **not** exercised on real hosts and remain proven only against the
scripted fake target.

## Related

[group](/en/reference/resources/group/) ·
[directory](/en/reference/resources/directory/) ·
[Resources](/en/concepts/resources/)
