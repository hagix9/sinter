---
title: Supported Platforms
description: Platform, architecture, and package-backend support matrix.
---

## Managed targets

| Platform | Architecture | Package backend | Status |
|----------|--------------|-----------------|--------|
| Ubuntu 24.04 LTS | amd64 | apt | Supported, acceptance-tested |
| Ubuntu 26.04 LTS | amd64 | apt | Supported, acceptance-tested |
| Rocky Linux 9 | x86_64 | dnf | Supported, acceptance-tested |
| Rocky Linux 10 | x86_64 | dnf | Supported, acceptance-tested |
| RHEL 9 | x86_64 | dnf | Supported, acceptance-tested |
| RHEL 10 | x86_64 | dnf | Supported, acceptance-tested |
| AlmaLinux 9 | x86_64 | dnf | Supported, acceptance-tested |
| AlmaLinux 10 | x86_64 | dnf | Supported, acceptance-tested |
| Oracle Linux | x86_64 | dnf | Expected compatible — not acceptance-tested |

Oracle Linux is recognized as a Red Hat-family platform and uses Sinter's
DNF backend. It is expected to be compatible with the corresponding Red
Hat-family implementation, but it is not currently part of Sinter's
real-host acceptance matrix.

On RHEL-family targets, standard configured DNF repositories must be
functional. Repository transport and authentication are delegated to the
native `dnf`/librepo stack — including cloud images whose repositories are
entitled by the provider — so no Sinter-specific repository configuration
is required.

## Unified Linux x86_64 distribution

Sinter v0.5.0 uses one `sinter-v<VERSION>-linux-x86_64.tar.gz` for all
supported x86_64 version lines. The executable is unified; runtime platform
detection still selects APT on Ubuntu and DNF on RHEL-family targets. This
is not a claim of support for arbitrary Linux systems or architectures.

Sinter v0.4.1 was acceptance-tested on eight real x86_64 Linux hosts.
All eight hosts executed the same frozen candidate binary and the same
logical acceptance scenario. **Result: 344/344 checks passed.** The tested
point releases were Ubuntu 24.04.5 LTS, Ubuntu 26.04.1 LTS,
Rocky Linux 9.8, Rocky Linux 10.2, RHEL 9.8, RHEL 10.2, AlmaLinux 9.8,
and AlmaLinux 10.2, all x86_64. The canonical archive was verified to
extract to that exact binary, which was transferred and executed
identically on all eight hosts. Other and future point releases have not
each been independently validated.
Historical v0.2.1 retains its distro-specific assets; see
[Installation](https://sinter.fulltrust.co.jp/en/getting-started/installation/)
for current downloads.

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

Check `test -x /usr/bin/getfattr` on each target. If it is missing, every
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

Do not assume image defaults: install `attr` only if the required tool is missing.

## Controller

The controller (where `sinter` runs) is supported on macOS, Ubuntu 24.04 LTS,
Ubuntu 26.04 LTS, Rocky Linux 9, Rocky Linux 10, RHEL 9, RHEL 10,
AlmaLinux 9, AlmaLinux 10, and other x86_64 Linux environments where the
binary builds. Sinter release binaries use a single Linux x86_64 artifact;
published v0.2.1 retains distro-specific assets (see
[Installation](/en/getting-started/installation/)).

## Explicitly not supported

- Other distributions / releases (fail closed with a capability error rather
  than guessing a backend).
- Hashed `known_hosts` entries.
- aarch64 artifacts are not validated — presence of a build does not imply
  support.

## Scope

Sinter scope does not include inventory, roles, plugins, orchestration, or
embedded scripting. See the
[CHANGELOG](https://github.com/hagix9/blob/main/CHANGELOG.md) for
release history.
