---
title: Troubleshooting
description: Common Sinter failures and what they mean.
---

## Exit codes

| Code | Meaning | Typical cause |
|------|---------|---------------|
| 0 | Success | — |
| 2 | Validation/schema error | Bad recipe syntax, unknown field, invalid value |
| 3 | Connection/capability/security error | SSH, host key, or unsupported platform |
| 4 | Plan incomplete | Unsafe to produce a plan |
| 5 | Apply failed | A resource failed |
| 6 | Apply indeterminate | Timeout after dispatch, lost response, signal uncertainty |

## SSH / known_hosts

**`unknown host key` / `host key changed`**

Sinter never auto-enrolls. Fix: add the correct key to the selected
`known_hosts` file (default `~/.ssh/known_hosts`), or pass
`--known-hosts <path>`.

**Non-default port rejected**

Port 22 uses a portless `host` entry; every other port needs `[host]:port`.
A portless entry does not authorize a non-default port.

**Hashed known_hosts**

Hashed entries are not supported — use unhashed entries.

## Privilege escalation

**`sudo` failures**

`--sudo` uses non-interactive `sudo -n`. Ensure the target user has
passwordless sudo (`sudo -n true`). Sinter never retries a permission failure
by escalating — failures stay failures.

## Platform detection

**`package resources require a supported target platform`**

The target's `/etc/os-release` did not identify a supported platform.
Supported: Ubuntu 24.04 LTS amd64 (apt), Rocky Linux 9 x86_64 (dnf).

## Resource failures

**`parent path` / symlink errors**

Filesystem mutations require a trusted parent path — unexpected symlinks or
unsafe parents (e.g. directly under `/tmp`) are rejected. Point `path` at a
trusted location.

**`service unit ... was not found`**

The unit doesn't exist on the target. Install its package first
(`depends_on`), or check the unit name.

**Indeterminate apply (exit 6)**

Sinter could not confirm whether a mutation completed. Do not retry blindly —
inspect the target state first, then re-apply if safe.

## dnf-specific

**Metadata/cache failures on Rocky**

Installs use a private metadata snapshot under `/var/tmp/sinter-dnf.*`
(mode 0700). Snapshot residues should not persist after runs — if any remain,
report it as a bug.

## Getting more detail

- `--verbose` for per-resource detail
- `--format json` for machine-readable results
