---
title: AlmaLinux
description: AlmaLinux 9 and 10 x86_64 managed-target guide — dnf backend.
---

AlmaLinux 9 and AlmaLinux 10 x86_64 are supported, acceptance-tested managed
targets. Both use the **dnf** package backend.

**Acceptance references:** AlmaLinux 9.8 x86_64 and AlmaLinux 10.2 x86_64 —
verified for package install/remove/idempotency, file, service, and command
resources over real SSH with `sudo -n`. AlmaLinux 9/10 are the supported
version lines; 9.8 and 10.2 are the verified references, not independent
evidence for every other minor release.

## Requirements

| Requirement | Notes |
|-------------|-------|
| AlmaLinux 9 or 10 | x86_64 |
| OpenSSH server | Strict `known_hosts` verification |
| systemd | Required for `service` resources |
| `/bin/sh` | Target-side shell |
| `attr` package | `/usr/bin/getfattr`; check on the target; install `attr` with dnf if missing |
| `sudo -n` | Passwordless sudo when using `--sudo` |
| dnf | Package backend; configured repositories must be functional |

## Package management

`type: package` recipes are platform-neutral — the same recipe runs under
dnf on AlmaLinux:

```yaml
resources:
  - id: nano
    type: package
    with:
      name: nano
      state: present
```

## How dnf installs work

A dnf install never lets the mutating `dnf` process touch the network for
metadata:

1. A private snapshot of the DNF metadata cache is created under
   `/var/tmp/sinter-dnf.*` with mode 0700.
2. Transaction resolution and metadata validation run **cache-only** against
   the snapshot, freezing the exact resolved package identities.
3. The resolved RPM payloads are downloaded into the snapshot through the
   native `dnf`/librepo transport — repository authentication stays with
   dnf/librepo — and each payload's RPM identity is verified against the
   frozen transaction set.
4. The final mutation runs `dnf -C --setopt=cachedir=<snapshot>` — cache-only.
5. The snapshot is removed afterward, including on failure.

If payload completeness or identity cannot be proven, the install fails
closed before any mutation.

## Platform detection

`/etc/os-release` `ID=almalinux` (RHEL family) selects the dnf backend.
Unknown or unsupported platforms are capability errors — Sinter does not
guess a backend.

## Limitations

- Only x86_64 is validated; do not assume aarch64 support.
- AlmaLinux 9.8 and 10.2 are the acceptance references — other minors share
  the same interfaces but are not individually verified.
- Hashed `known_hosts` entries are not supported (same as all targets).
