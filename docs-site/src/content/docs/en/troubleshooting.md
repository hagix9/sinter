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

`--sudo` uses non-interactive `sudo -n`. Ensure the target user has
passwordless sudo (`sudo -n true`). Sinter never retries a permission failure
by escalating — failures stay failures.

## Platform detection

**`package resources require a supported target platform`**

The target's `/etc/os-release` did not identify a supported platform.
Supported: Ubuntu 24.04 / 26.04 LTS amd64 (apt); Rocky Linux 9 / 10,
RHEL 9 / 10, and AlmaLinux 9 / 10 x86_64 (dnf). Oracle Linux is recognized
as RHEL family (dnf) but is not acceptance-tested.

## Resource failures

**`parent path` / symlink errors**

Filesystem mutations require a trusted parent path — unexpected symlinks or
unsafe parents (e.g. directly under `/tmp`) are rejected. Point `path` at a
trusted location.

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
inspect the target state first, then re-apply if safe.

## dnf-specific

**Metadata/cache failures on RHEL-family targets**

Installs use a private metadata snapshot under `/var/tmp/sinter-dnf.*`
(mode 0700). Snapshot residues should not persist after runs — if any remain,
[report it as a bug](/en/contributing/#reporting-bugs).

## Getting more detail

- `--verbose` for per-resource detail
- `--format json` for machine-readable results
