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

Sinter v1.2.0 uses one `sinter-v<VERSION>-linux-x86_64.tar.gz` for all
supported x86_64 version lines. The executable is unified; runtime platform
detection still selects APT on Ubuntu and DNF on RHEL-family targets. This
is not a claim of support for arbitrary Linux systems or architectures.

Each release from v1.0.0 on is acceptance-tested as its exact release
artifact on the eight supported targets before it is published; the
acceptance manifest, raw logs, and checksums are published as release assets
(see [acceptance evidence](https://github.com/hagix9/sinter/blob/main/release/ACCEPTANCE_EVIDENCE.md)).

The current release, Sinter v1.2.0, passed the Linux x86_64 validation gate
and was then acceptance-tested as its exact release artifact,
`sinter-v1.2.0-linux-x86_64.tar.gz`, on eight real x86_64 Linux hosts. The
tested point releases were Ubuntu 24.04.5 LTS, Ubuntu 26.04.1 LTS, Rocky
Linux 9.8, Rocky Linux 10.2, RHEL 9.8, RHEL 10.2, AlmaLinux 9.8, and
AlmaLinux 10.2, all x86_64. On every host the tarball and the extracted
executable were verified byte-identical (SHA-256) and ran the established
acceptance scenario plus artifact-identity and MCP checks, and a real-host
`group` → `user` → `directory` → `file` lifecycle.
**Result: 1240 checks passed, 0 failed** (see the
[v1.2.0 acceptance evidence](https://github.com/hagix9/sinter/releases/tag/v1.2.0)). Sinter v1.1.3, v1.1.2, v1.1.1, v1.1.0 and v1.0.0 each passed the earlier
eight-host acceptance (408/408), and v0.5.1 and v0.4.1 each passed the
earlier one (344/344); those records are historical. Other and future point releases have not each been independently
validated.
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

## Real-host acceptance of the unreleased secrets features

The encrypted-secret features (`sinter secrets`, `file.content: { secret: … }`,
`user.password_hash`) shipped in v1.2.0, but they were accepted on real hosts
on **2026-10-04**, before the release, on a pre-release build from source
commit `bce63a5fe8a6ab8e8756f7e117b6c707ea124b91`, on the same eight targets
as release acceptance:

| Target | OS | sudo | Result |
|---|---|---|---|
| Ubuntu 24.04 LTS | 24.04.5 | sudo 1.9.15p5 | PASS |
| Ubuntu 26.04 LTS | 26.04.1 | **sudo-rs 0.2.13** | PASS |
| Rocky Linux 9 | 9.8 | sudo 1.9.17p2 | PASS |
| Rocky Linux 10 | 10.2 | sudo 1.9.17p2 | PASS |
| RHEL 9 | 9.8 | sudo 1.9.17p2 | PASS |
| RHEL 10 | 10.2 | sudo 1.9.17p2 | PASS |
| AlmaLinux 9 | 9.8 | sudo 1.9.17p2 | PASS |
| AlmaLinux 10 | 10.2 | sudo 1.9.17p2 | PASS |

All x86_64. **8 of 8 targets passed.**

One binary was built for the run, on Rocky Linux 9.8 x86_64 with
`cargo build --locked --release` and no extra flags; its SHA-256 is
`fe1a200e896b287c98543b6450298bc469ab3aff6bb427dbe77be91eb8b4488b` and its
highest required GLIBC symbol version is `GLIBC_2.34`. That exact binary was
verified byte-identical on all eight targets before use. **It is not the
published release artifact**: it is not
`sinter-v1.2.0-linux-x86_64.tar.gz`. The v1.2.0 acceptance evidence linked
above describes the release artifact; it did not re-run the secrets acceptance
described here, and the `user.password_hash` path was not re-run on the release
artifact.

What was accepted:

- **File secrets** — byte-exact publication (random binary with NUL, CRLF and
  no trailing newline), declared owner/group/mode, `validate`/`plan`/`apply`/
  `audit`, idempotence, out-of-band drift and restore, and fail-closed
  behaviour when the identity is missing or wrong.
- **`password_hash`** — one real `sudo -n /usr/sbin/chpasswd -e` per change,
  the hash on standard input only, verified against the stored field and by a
  functional `crypt` comparison on the target; `getent -s files shadow` under
  `sudo`; `/etc/shadow` mode and owner unchanged; failure without `--sudo`;
  last-change date recorded.
- **`$y$` behavior** — accepted and stored on Ubuntu 24.04, Ubuntu 26.04,
  Rocky Linux 10, RHEL 10 and AlmaLinux 10; **refused** on Rocky Linux 9, RHEL 9
  and AlmaLinux 9. The refusal message is
  `yescrypt ($y$) hashes are not supported on this platform (RHEL-family 9); use a $6$ hash`,
  no `chpasswd` is invoked, and the stored field is unchanged.
- **Locked-account protection** — an account locked with a *different* hash is
  refused before any command runs (zero `chpasswd`, stored field unchanged, the
  account still locked, `audit` reports `DRIFT`); the same hash is a no-op.
- **sudo-rs** — Ubuntu 26.04's native sudo is sudo-rs 0.2.13
  (`/usr/bin/sudo` → `/usr/lib/cargo/bin/sudo`). Delivering the hash and file
  payloads on standard input through it passed both over a local pipe and over
  an SSH channel with no pty. Nothing was installed or replaced on any target.
- **SSH** — Sinter over SSH to each target's own sshd with full host-key
  verification. A 16 MiB secret over SSH took **4.2 s** on Ubuntu 26.04 and
  **4.4 s** on Rocky Linux 9 (peak Sinter RSS 93,580 kB and 92,692 kB), far
  below the 300 s stdin deadline; the other six targets ran the same
  host-key-verified SSH smoke with a smaller payload.
- **No leakage** — zero confirmed secret hits in Sinter output, the sudo
  journal, the system auth log, evidence files, file names or process listings
  on all eight targets.
- **Cleanup** — every target returned to its baseline (account databases,
  sub-uid/sub-gid files, packages, enabled units, `authorized_keys`) and to its
  original `TERMINATED` power state.

Limits of this record, stated rather than implied:

- SSH was exercised over loopback to the target's own sshd. It proves Sinter's
  SSH transport, the target's sshd, host-key verification and the remote
  execution path; it does **not** measure an external network path.
- Process-argument sampling is best effort; the sudo journal and Sinter's
  stdin-only design are the stronger evidence.
- Only an Ed25519 key was deployed as a secret; other key formats were not
  exercised.
- FIPS mode, exFAT/network volumes, NSS-only accounts, the `*`/empty/`!*`
  password markers and the `user`/`group` create-and-remove dimensions were
  not exercised; those remain covered only by the scripted tests.

## Explicitly not supported

- Other distributions / releases (fail closed with a capability error rather
  than guessing a backend).
- aarch64 artifacts are not validated — presence of a build does not imply
  support.

## Scope

Sinter scope does not include dynamic inventory, roles, plugins,
orchestration, or embedded scripting. See the
[CHANGELOG](https://github.com/hagix9/sinter/blob/main/CHANGELOG.md) for
release history.
