---
title: Troubleshooting
description: Common Sinter failures and what they mean.
---

## Exit codes

| Code | Meaning | Typical cause |
|------|---------|---------------|
| 0 | Success | Audit: no DRIFT and no ERROR — `NOT_AUDITABLE`/`NOT_APPLICABLE` resources may still be present |
| 2 | Validation/schema error | Bad recipe syntax, unknown field, invalid value |
| 3 | Connection/capability/security error | SSH, host key, or unsupported platform |
| 4 | Plan incomplete | Unsafe to produce a plan |
| 5 | Apply failed | A resource failed |
| 6 | Apply indeterminate / audit ERROR | Apply: timeout after dispatch, lost response, signal uncertainty. Audit: one or more ERROR results — errors dominate DRIFT |
| 7 | Audit DRIFT | One or more DRIFT results and no ERROR |

## SSH / known_hosts

**`unknown host key` / `host key changed`**

Sinter never auto-enrolls. Fix: add the correct key to the selected
`known_hosts` file (default `~/.ssh/known_hosts`), or pass
`--known-hosts <path>`.

**Non-default port rejected**

Port 22 uses a portless `host` entry; every other port needs `[host]:port`.
A portless entry does not authorize a non-default port.

**Hashed known_hosts**

Hashed (`|1|…`) entries are supported. If a hashed host is still reported as
unknown, check that the entry was recorded for the same identity (`host` on
port 22, `[host]:port` otherwise, or the configured `HostKeyAlias`).

**`ProxyJump` / `ProxyCommand` configured for the host**

Sinter's built-in SSH transport cannot use a jump host. Connect to an address
that is directly reachable, or pass `--no-ssh-config` to ignore the OpenSSH
configuration (the connection is then made directly).

**`SSH authentication failed for user@host`**

Host-key verification passed but your key was not accepted. Check that a
key is available: an ssh-agent holding the key, an explicit `--identity
<path>`, an `IdentityFile` from your OpenSSH configuration, or a default
`~/.ssh/id_ed25519` / `id_ecdsa` / `id_rsa`. Passphrase-protected keys are
used only through ssh-agent (`ssh-add` them first). The
matching public key must already be authorized for the target user — Sinter
does not provision keys. (This is separate from the host-key checks above.)

## Privilege escalation

**`sudo` failures**

`--sudo` sends every command as non-interactive `sudo -n -u root -- …`. Ensure
the target user may run commands as root without a password (`sudo -n -u root
true`). A target user that is already root runs directly; no `sudo` is needed.
When the first command fails under sudo, the connect error says which case it
is: sudo is not installed, a password is required (sudo 1.9 also says this for
a user without a rule, or a rule that does not allow root), sudoers refuses the
user, or a cause Sinter could not identify. Sinter never retries a permission
failure by escalating — failures stay failures.

**`needs root` in plan**

When the target user is not root and `--sudo` was not given, plan adds a
`needs root:` note to a planned change that only root can make (packages,
users, groups, files outside the user's own tree). It is a note only: plan
neither runs sudo nor probes for it, and the status does not change; apply then
fails unless you connect as root or add `--sudo`. A root login or `--sudo`
never gets this note. After v1.5.1 (unreleased) the note is shown in the
default text output; in v1.5.1 and earlier it appears only with `--verbose` and
in `--format json` (`notes`). For a sensitive resource the text output says
`needs root (details redacted)`.

**`cannot inspect PATH: permission denied`** (after v1.5.1, unreleased)

The target user could not look up the path, usually because a parent directory
is not searchable by it. Nothing is assumed about the path: plan, apply and
audit fail for it instead. Connect as root or use `--sudo` if the path is meant
to be managed with root privilege. As root the message says `permission denied
even with root privilege` (for example a network filesystem that maps root to
an unprivileged user). v1.5.1 and earlier report the same case as `the capture
carried an unrecognized diagnostic: "… Permission denied"`.

## Platform detection

**`package resources require a supported target platform`**

The target's `/etc/os-release` did not identify a supported platform.
Supported: Ubuntu 24.04 / 26.04 LTS amd64 (apt); Rocky Linux 9 / 10,
RHEL 9 / 10, and AlmaLinux 9 / 10 x86_64 (dnf). Oracle Linux is recognized
as RHEL family (dnf) but is not acceptance-tested.

## Resource failures

**`parent path` / symlink errors**

Filesystem mutations require a trusted parent path — unexpected symlinks, a
group- or other-writable parent that is not a sticky shared directory, or a
parent owned by a third account are refused before mutation. Sticky, root-owned
directories such as `/tmp` and `/var/tmp` are trusted, and when running as root
a path inside an unprivileged account's own directory is accepted. See
[file § Trust boundary](/en/reference/resources/file/#trust-boundary).

**`service unit ... was not found`**

The unit doesn't exist on the target. Install its package first
(`depends_on`), or check the unit name.

**`daemon-reload` failed (exit 5)**

Sinter reloads the systemd system manager automatically when a managed unit
file, drop-in, alias link or `system.conf` changed, or a unit reports
`NeedDaemonReload=yes`. A non-zero exit from `systemctl daemon-reload` fails the
run: the dependent service resource or handler does nothing, earlier file
changes stay `changed` (nothing is rolled back), and the reload is not retried
in the same run. Read the reported reason (systemd rate limits such as
`ReloadLimit*`, authorization, or a broken unit file are common causes), fix
it, and apply again. A timed-out or lost reload is reported as indeterminate
(exit 6) — inspect the manager before re-applying.

**`NeedDaemonReload` still `yes` after a reload ("unresolved")**

Sinter reloads once per cause and does not loop. If the unit still reports
`NeedDaemonReload=yes`, something outside Sinter keeps changing the unit (or a
fragment outside the unit load path is involved) and the apply fails. Check the
unit's files with `systemctl show -p FragmentPath,DropInPaths <unit>` and
`systemctl status <unit>`.

**`UnitPath` could not be read or parsed**

When a managed path looks like unit, drop-in or link input, Sinter asks the
manager for its load path with `systemctl show --property=UnitPath`. If that
fails, the resource fails before any mutation (in `plan`: a plan error; in
`audit`: an `ERROR`). Sinter never guesses the path. Check that systemd is
running and `systemctl` works for the connecting user (and with `--sudo` if
used).

**Manager unsynchronized after a stopped run**

If an apply stopped early (a failed resource or handler) after a managed unit
input had changed, no reload is started and the report states that the reload
was **not** run. Re-apply, or run `systemctl daemon-reload` manually. Sinter
keeps no journal across runs, so a later apply reloads only when it observes
`NeedDaemonReload=yes` or makes a new change. Running `sinter audit` shows
pending reloads as `manager_reload` drift.

**Indeterminate apply (exit 6)**

Sinter could not confirm whether a mutation completed. Do not retry blindly —
inspect the target state first, then re-apply if safe. After v1.5.1
(unreleased), a local run whose wait for a started command fails is reported
the same way (`failed to wait for child after dispatch`), not as "failed,
nothing changed": the command may have run, and may still be running.

## dnf-specific

**Metadata/cache failures on RHEL-family targets**

Installs run cache-only against a private snapshot of the target's dnf
metadata under `/var/tmp/sinter-dnf.*` (mode 0700), and the snapshot never
removes or copies the live cache. The snapshot needs the target's dnf metadata
cache to be complete for every enabled repository. When an enabled repository
has no cached metadata — a host that has never run `dnf makecache`, or a
repository added since the last refresh — Sinter refreshes the target's own dnf
metadata cache once (only absent metadata; present metadata is left alone) and
re-verifies the snapshot, so no manual preparation step is needed. If the
metadata still cannot be established the resource fails closed before any
package mutation. Packages already downloaded in the live cache are no longer
mistaken for the transaction payloads. The snapshot is removed after every
definite outcome, including failures. One case keeps it on purpose: when the
completion of the install itself is unknown (a timeout or a lost connection,
reported as `indeterminate`), Sinter sends nothing more to the target — dnf may
still be running — and leaves `/var/tmp/sinter-dnf.*` in place. Check that no
`dnf` process is running, then remove that directory and apply again. A
snapshot left after any other outcome is a bug:
[report it](/en/contributing/#reporting-bugs).

**Why did dnf refuse the install?** (v1.5.1)

The reason names the cause dnf reported, and nothing was installed:

| Reason | What to do |
|--------|------------|
| `… is not a package name: dnf resolves it through a provides match to package X` | Declare `name: X` (on EL8: `python36` for `python3`, `python3.11` for `python311`). |
| `no package named … is installed, but dnf reports the request already satisfied by installed package X` | The name is provided by `X`, which is installed; declare `name: X`. |
| `dnf found no package named …` | Check the name and that the repository providing it is enabled. |
| `dnf cannot resolve the dependencies of …: nothing provides …` | Enable the repository that provides the dependency (often CRB / PowerTools for EPEL packages). |
| `dnf refused a package signature … (GPG check FAILED …)` | The package is unsigned or its repository's `gpgkey` does not match; fix the key file, do not turn `gpgcheck` off. |
| `dnf could not download the metadata of repository <id> …` | That repository is unreachable or misconfigured; every enabled repository must work. |
| `… bytes of unrecognized dnf error output withheld` | Run the same install with plain `dnf` on the target to see the message. |

See [package § Why dnf refused](/en/reference/resources/package/#why-dnf-refused-dnf).

**`unknown group: apache` (or user) in plan**

The account is created by a package's scriptlet, so it does not exist while
plan runs. Declare the `group`/`user` before the package, with the attributes
the package uses (`apache`: uid/gid 48, home `/usr/share/httpd`, shell
`/sbin/nologin`); plan then defers what depends on it, and the scriptlet keeps
the declared account. See [`examples/recipes/apache-htpasswd.yaml`](https://github.com/hagix9/sinter/blob/main/examples/recipes/apache-htpasswd.yaml).

**`postgresql_role` fails**

- `postgresql_role needs root` → connect as root or use `--sudo` (psql runs as
  the cluster owner).
- `cannot observe PostgreSQL role …: psql exited 2` → the server is not
  running, or `psql`/`port` points elsewhere (PGDG: `psql:
  /usr/pgsql-17/bin/psql`).
- `could not be verified to keep statements out of the server log … not sent`
  → the session could not set or confirm the logging parameters; nothing
  carrying the password verifier was sent.

## Getting more detail

- `--verbose` for per-resource detail
- `--format json` for machine-readable results
