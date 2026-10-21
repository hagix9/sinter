---
title: Rocky Linux
description: Rocky Linux 9 and 10 x86_64 managed-target guide — dnf backend.
---

Rocky Linux 9 x86_64 has been supported since v0.2.0; Rocky Linux 10 x86_64
since v0.4.0. Both lines are acceptance-tested in v1.7.0 and use the **dnf**
package backend.

**Acceptance references:** Rocky Linux 9.8 x86_64 with DNF 4.14.0 — verified
for package install/remove/idempotency, file, service, and command resources
over real SSH with `sudo -n` — and Rocky Linux 10.2 x86_64 with DNF 4.20.0
and rpm 4.19, verified for the same five resource types plus converge-back
purge idempotency. Rocky 9/10 are the supported version lines; 9.8 and 10.2 are the verified
references, not independent evidence for every other minor release.

## Unified Linux x86_64 distribution

Sinter v1.7.0 uses one `sinter-v<VERSION>-linux-x86_64.tar.gz` for all
supported x86_64 version lines. The executable is unified; runtime platform
detection still selects APT on Ubuntu and DNF on RHEL-family targets. This
is not a claim of support for arbitrary Linux systems or architectures.

The Sinter v1.7.0 release artifact passed eight-real-host acceptance on
Ubuntu 24.04, Ubuntu 26.04, Rocky Linux 9.8, Rocky Linux 10.2,
RHEL 9.8, RHEL 10.2, AlmaLinux 9.8, and AlmaLinux 10.2 — all x86_64, 264 checks
passed, 0 failed.
Other and future point releases have not each been independently validated.
Historical v0.2.1 retains its distro-specific assets; see
[Installation](https://sinter.fulltrust.co.jp/en/getting-started/installation/)
for current downloads.


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
version: 1

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

## Rocky Linux / RHEL 8 as an SSH target (v1.5.1)

Sinter itself cannot run on EL8 (the Linux build needs glibc 2.34), but it can
**manage** an EL8 host over SSH from a supported controller (EL9/EL10 or
Ubuntu; macOS only as a source build). Measured for v1.5.1 on Rocky Linux 8.10 (dnf 4.7.0) —
not yet a release acceptance claim:

- **Prerequisite:** the `attr` package (`getfattr`). Minimal and cloud images
  often lack it, and every `file`/`directory`/`template` resource then fails
  closed with a message saying so. Install it first (a `package` resource
  `attr` works).
- **Python:** declare real package names. `python36` (module stream
  `python36:3.6`, enabled automatically), `python3.11`, `python3.12`,
  `python3.11-pip`, `python39`, `python38`. `python3` and `python311` are not
  package names on EL8 (provides only); Sinter refuses them before installing
  and names the real package. See [`examples/recipes/python-el8.yaml`](https://github.com/hagix9/sinter/blob/main/examples/recipes/python-el8.yaml).
- **Module streams:** an install that enables a module's default stream works
  (`Enabling module streams:` in the transaction). To get a non-default stream,
  enable it first; see [`examples/recipes/postgresql-os.yaml`](https://github.com/hagix9/sinter/blob/main/examples/recipes/postgresql-os.yaml).

## PostgreSQL, EPEL / CRB and other repositories

- **PostgreSQL from the OS:** EL8 defaults to 10 and EL9 to 13 (both past their
  upstream end of life); EL10 ships 16. Use **16** from the OS, or **17** from
  PGDG; do not take the default 10 or 13 for a new server.
  [`examples/recipes/postgresql-os.yaml`](https://github.com/hagix9/sinter/blob/main/examples/recipes/postgresql-os.yaml) installs 16 on all three (module stream
  `postgresql:16` on EL8/EL9), with a validated `postgresql.conf`,
  `pg_hba.conf` and a [`postgresql_role`](/en/reference/resources/postgresql_role/).

  | Major | EL8 (module stream) | EL9 | EL10 | Upstream support ends |
  |-------|---------------------|-----|------|-----------------------|
  | 10 | `postgresql:10` (default) | — | — | 2022-11 (ended) |
  | 12 | `postgresql:12` | — | — | 2024-11 (ended) |
  | 13 | `postgresql:13` | default (not modular) | — | 2025-11 (ended) |
  | 15 | `postgresql:15` | `postgresql:15` | — | 2027-11 |
  | 16 | `postgresql:16` | `postgresql:16` | default | 2028-11 |
  | 17 | PGDG | PGDG | PGDG | 2029-11 |

  The EL8 streams are those `dnf module list postgresql` shows on Rocky Linux
  8.10 (it also lists 9.6). The EL8/EL9 `postgresql:16` and EL10 16 installs and
  PGDG 17 on all three were verified for v1.5.1; the other rows
  are not. The dates are the PostgreSQL project's; how long the distribution
  maintains a module stream is set by its own application-stream life cycle.
- **PostgreSQL 17 from PGDG:** [`examples/recipes/postgresql-pgdg17.yaml`](https://github.com/hagix9/sinter/blob/main/examples/recipes/postgresql-pgdg17.yaml)
  declares the PGDG repository as files with a pinned, fingerprint-checked key
  and `gpgcheck`/`repo_gpgcheck` on. Installing the PGDG repo RPM from a URL is
  not recommended: dnf does not check a local/URL RPM's signature by default
  (`localpkg_gpgcheck=0`).
- **EPEL and CRB/PowerTools:** [`examples/recipes/epel-crb.yaml`](https://github.com/hagix9/sinter/blob/main/examples/recipes/epel-crb.yaml). dnf imports a
  repository's key from its `gpgkey` file on first use; the key file is the
  trust anchor, so pin it (manage it as a file) for third-party repositories.
- **Any signed repository:** [`examples/recipes/signed-repo.yaml`](https://github.com/hagix9/sinter/blob/main/examples/recipes/signed-repo.yaml) (key file +
  repository file + package). Unsigned packages and packages signed by another
  key are refused (`GPG check FAILED`).

**How to manage repositories (recommended).** Declare a third-party
repository as files — the pinned key and the `.repo` file — with `gpgcheck`
on. Both files are planned, applied and **audited** like any managed file, and
a second apply reports no change. There is no dedicated repository resource.
A repository that ships with the OS but is disabled (CRB, PowerTools) has no
file of its own to manage; enable it with a read-only check first and the
enable command only when the check finds it disabled (`epel-crb.yaml`). The
packages are audited, but the repository's enabled state that the command
changed is **not** part of `sinter audit` (command resources are not audited).

## Platform detection

`/etc/os-release` `ID=rocky` (RHEL family) selects the dnf backend. Unknown or
unsupported platforms are capability errors — Sinter does not guess a backend.

## Limitations

- Only x86_64 is validated; do not assume aarch64 support.
- Rocky 9.8 is the acceptance reference — other 9.x minors share the same
  interfaces but are not individually verified.
- Hashed `known_hosts` entries are not supported (same as all targets).
