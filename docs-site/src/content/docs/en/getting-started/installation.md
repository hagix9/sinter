---
title: Installation
description: Install Sinter from release tarballs or build from source.
---

## Install

Sinter **v0.5.0** ships one `sinter-v0.5.0-linux-x86_64.tar.gz` artifact
covering every supported Linux x86_64 platform line — Ubuntu 24.04 / 26.04
LTS, Rocky Linux 9 / 10, RHEL 9 / 10, and AlmaLinux 9 / 10.

```sh
curl -fsSL https://hagix9.github.io/sinter/install.sh | sh
$HOME/.local/bin/sinter --version
```

The installer selects the latest stable official GitHub release, verifies
SHA256SUMS before extraction, and installs without sudo into `$HOME/.local/bin`.
If needed, add that directory to PATH yourself; shell profiles are not edited.
For inspect-before-run and manual downloads, see
[Installation](https://hagix9.github.io/sinter/en/getting-started/installation/).

### Inspect before running

```sh
curl -fsSLo install.sh https://hagix9.github.io/sinter/install.sh
less install.sh
sh install.sh
```

### Version and destination

```sh
SINTER_VERSION=v0.5.0 sh install.sh
SINTER_INSTALL_DIR="$HOME/bin" sh install.sh
```

Installer support is Linux x86_64/amd64 only. It requires curl, GNU tar and
coreutils (including sha256sum). Unsupported OS/architectures fail; no ARM
artifact exists. The destination must be an absolute trusted directory.
An existing regular user-owned executable can be replaced atomically; symlinks
and nonregular objects are refused. Network/checksum/layout failures leave the
existing executable intact. No sudo, PATH or shell-profile modification occurs.
Checksums detect corruption and release consistency, not compromise of GitHub.

### Manual release installation

```sh
ASSET=sinter-v0.5.0-linux-x86_64.tar.gz
curl -fLO "https://github.com/hagix9/sinter/releases/download/v0.5.0/$ASSET"
curl -fLO https://github.com/hagix9/sinter/releases/download/v0.5.0/SHA256SUMS
grep -F "  $ASSET" SHA256SUMS | sha256sum -c -
tar -xzf "$ASSET"
sudo install -m 0755 "${ASSET%.tar.gz}/sinter" /usr/local/bin/sinter
/usr/local/bin/sinter --version
```

The environment applies to installation only, not persistent host configuration.
Historical v0.2.1 assets keep their original distro-specific names.

## Controller on macOS (or other environments)

No macOS release artifact exists. Build from source instead — see below.
Managed hosts remain the supported Linux targets regardless of where the
controller runs.

## Build from source

Requires a Rust toolchain (rustup or your distribution's packages):

```sh
git clone https://github.com/hagix9/sinter.git
cd sinter
cargo build --locked --release
./target/release/sinter --version
```

Copy `target/release/sinter` somewhere on your `PATH` to use it like an
installed binary.

## Managed host requirements

The target does not need Sinter installed. It needs:

- an OpenSSH server whose host key is already in your `known_hosts`
- systemd
- `/bin/sh`
- the `attr` package (`/usr/bin/getfattr`) — Sinter inspects extended
  attributes and POSIX ACLs before writing any path and refuses paths it
  cannot prove safe. Check `test -x /usr/bin/getfattr` on each target. If missing, install
  `attr` with `sudo apt install attr` (Ubuntu) or `sudo dnf install attr`
  (RHEL family: Rocky, RHEL, AlmaLinux)
- passwordless `sudo -n` if you use `--sudo`
- a user account whose public key you have authorized, reachable with your
  SSH agent or a key file

## SSH credentials

Sinter uses SSH for both transport and authentication. Two identities are
involved, and they are checked separately:

- **Host identity (the target's host key).** Sinter verifies the server
  against your `known_hosts` file (default `~/.ssh/known_hosts`, or
  `--known-hosts`). Unknown or changed host keys fail closed; Sinter never
  auto-enrolls.
- **User authentication (your private key).** Sinter tries, in order:
  your ssh-agent (if one is running), each `--identity` file, then the
  default `~/.ssh/id_ed25519` and `~/.ssh/id_rsa`. The corresponding public
  key must already be authorized on the target for the target user — Sinter
  does not provision keys.

Sinter refuses unknown or changed SSH host keys. Non-default SSH ports require
an explicit `[host]:port` entry in `known_hosts`.
