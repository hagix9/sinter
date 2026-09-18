---
title: Supported Platforms
description: Platform, architecture, and package-backend support matrix.
---

## Managed targets

| Platform | Architecture | Package backend | Status |
|----------|--------------|-----------------|--------|
| Ubuntu 24.04 LTS | amd64 | apt | Supported |
| Ubuntu 26.04 LTS | amd64 | apt | Supported |
| Rocky Linux 9 | x86_64 | dnf | Supported |
| Rocky Linux 10 | x86_64 | dnf | Supported |

**Acceptance references:**

- Ubuntu 24.04.4 amd64 (reference build/validation for the Linux x86_64
  artifact) and Ubuntu 26.04.1 LTS amd64 (real-host acceptance: command, file,
  template, package, and service resources, plan/apply idempotency, and
  converge-back cleanup).
- Rocky Linux 9.8 x86_64 with DNF 4.14.0 — the v0.2.0 target acceptance
  environment and the build baseline for the Linux x86_64 artifact.
- Rocky Linux 10.2 x86_64 with DNF 4.20.0 and rpm 4.19 — real-host acceptance
  for all five resource types plus purge idempotency.

Other minor releases of the same major version share the same interfaces;
the versions above are the verified references.

All managed targets require:

- systemd
- OpenSSH server (strict `known_hosts` verification)
- `/bin/sh`
- the `attr` package (`/usr/bin/getfattr`), see below
- passwordless `sudo -n` when privilege escalation is required

### The `attr` package is a target requirement

Sinter enumerates the extended attributes and POSIX ACLs of every path it
writes (or whose parent it must trust) before touching it, so a path whose
security metadata cannot be proved safe is refused rather than copied over.
Enumeration uses `/usr/bin/getfattr`, provided by the `attr` package.

Stock Ubuntu cloud images ship **no** `attr` package. On such a target every
`file`, `template`, `directory`, and `link` resource fails closed with an
error that names the missing program and how to install it:

```text
cannot inspect access metadata of parent path /; refusing unsafe path;
the target has no /usr/bin/getfattr, so access metadata cannot be inspected
(install the 'attr' package: apt install attr on Debian/Ubuntu,
dnf install attr on RHEL family)
```

Install it once per target — the refusal is by design and is not bypassed:

```sh
sudo apt install attr          # Debian / Ubuntu
sudo dnf install attr          # RHEL family (Rocky, etc.)
```

Rocky Linux images ship `attr` in the default install, so no action is needed
there.

## Controller

The controller (where `sinter` runs) is supported on macOS, Ubuntu 24.04 LTS,
Ubuntu 26.04 LTS, Rocky Linux 9, Rocky Linux 10, and other x86_64 Linux
environments where the binary builds. Release binaries are published as a
single Linux x86_64 artifact (see
[Installation](/sinter/en/getting-started/installation/)).

## Explicitly not supported

- Other distributions / releases (fail closed with a capability error rather
  than guessing a backend).
- Hashed `known_hosts` entries.
- aarch64 artifacts are not validated — presence of a build does not imply
  support.

## Scope

v0.2.1 scope does not include inventory, roles, plugins, orchestration, or
embedded scripting. See the
[CHANGELOG](https://github.com/hagix9/sinter/blob/main/CHANGELOG.md) for
release history.
