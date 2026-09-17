---
title: Supported Platforms
description: Platform, architecture, and package-backend support matrix.
---

## Managed targets

| Platform | Architecture | Package backend | Status |
|----------|--------------|-----------------|--------|
| Ubuntu 24.04 LTS | amd64 | apt | Supported |
| Rocky Linux 9 | x86_64 | dnf | Supported |

**Rocky acceptance reference:** Rocky Linux 9.8 x86_64, DNF 4.14.0 — the
environment used for v0.2.0 target acceptance. Other Rocky 9 minor releases
share the same interfaces; 9.8 is the verified reference.

All managed targets require:

- systemd
- OpenSSH server (strict `known_hosts` verification)
- `/bin/sh`
- passwordless `sudo -n` when privilege escalation is required

## Controller

The controller (where `sinter` runs) is supported on macOS, Ubuntu 24.04 LTS,
and other environments where the binary builds. Release binaries are published
for the two managed-target platforms.

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
