---
title: Rocky Linux
description: Rocky Linux 9 and 10 x86_64 managed-target guide — dnf backend.
---

Rocky Linux 9 x86_64 is supported as of v0.2.0 and Rocky Linux 10 x86_64 as
of v0.2.1; both use the **dnf** package backend.

**Acceptance references:** Rocky Linux 9.8 x86_64 with DNF 4.14.0 — verified
for package install/remove/idempotency, file, service, and command resources
over real SSH with `sudo -n` — and Rocky Linux 10.2 x86_64 with DNF 4.20.0
and rpm 4.19, verified for the same five resource types plus converge-back
purge idempotency. Other Rocky 9/10 minor releases share the same
interfaces; 9.8 and 10.2 are the verified references.

## Requirements

| Requirement | Notes |
|-------------|-------|
| Rocky Linux 9 or 10 | x86_64 |
| OpenSSH server | Strict `known_hosts` verification |
| systemd | Required for `service` resources |
| `/bin/sh` | Target-side shell |
| `attr` package | `/usr/bin/getfattr`; check on the target; install `attr` with dnf if missing |
| `sudo -n` | Passwordless sudo when using `--sudo` |
| dnf | Package backend |

## Package management

`type: package` recipes are platform-neutral — the same recipe runs under dnf
on Rocky:

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
   the snapshot.
3. Required RPM payloads are prefetched into the snapshot after URL
   validation.
4. The final mutation runs `dnf -C --setopt=cachedir=<snapshot>` — cache-only.
5. The snapshot is removed afterward, including on failure.

If any step cannot prove completeness, the install fails closed before any
mutation.

## Platform detection

`/etc/os-release` `ID=rocky` (RHEL family) selects the dnf backend. Unknown or
unsupported platforms are capability errors — Sinter does not guess a backend.

## Limitations

- Only x86_64 is validated; do not assume aarch64 support.
- Rocky 9.8 is the acceptance reference — other 9.x minors share the same
  interfaces but are not individually verified.
- Hashed `known_hosts` entries are not supported (same as all targets).
