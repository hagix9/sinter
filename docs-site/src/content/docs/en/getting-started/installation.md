---
title: Installation
description: Install Sinter from release tarballs or build from source.
---

Sinter runs on the **controller**. The managed host needs the prerequisites
listed below, but does not need Sinter installed. Published v0.2.1 Linux
artifacts are distribution-specific. A unified Linux x86_64 artifact built
on the Rocky Linux 9 baseline has passed four-real-host candidate acceptance and is the canonical model
for future releases; it is not a v0.2.1 asset.
Controllers on macOS can build from source.

## Unified Linux x86_64 distribution

Future releases use one `sinter-v<VERSION>-linux-x86_64.tar.gz` for the
supported Ubuntu 24.04 / 26.04 and Rocky Linux 9 / 10 x86_64 version lines.
The executable is unified; runtime platform detection still selects APT on
Ubuntu and DNF on Rocky. This is not a claim of support for arbitrary Linux
systems or architectures.

The frozen candidate passed four-real-host acceptance on Ubuntu 24.04.5 LTS,
Ubuntu 26.04.1 LTS, Rocky Linux 9.8, and Rocky Linux 10.2, all x86_64.
Other and future point releases have not each been independently validated.
Published v0.2.1 still has its original distro-specific assets; see
[Installation](https://hagix9.github.io/sinter/en/getting-started/installation/)
for current downloads. The unified candidate is not yet a published asset.

## From release tarballs (recommended on Linux)

The current release is **v0.2.1**. Release assets are published on the
[GitHub Releases](https://github.com/hagix9/sinter/releases) page. Each
archive contains the `sinter` binary, both READMEs, and the license files.

```sh
# Choose the asset for your controller: Ubuntu 24.04 or Rocky Linux 9.
ASSET=sinter-v0.2.1-ubuntu24.04-amd64.tar.gz
# ASSET=sinter-v0.2.1-rocky9-x86_64.tar.gz
curl -fLO "https://github.com/hagix9/sinter/releases/download/v0.2.1/$ASSET"
curl -fLO https://github.com/hagix9/sinter/releases/download/v0.2.1/SHA256SUMS

grep -F "  $ASSET" SHA256SUMS | sha256sum -c -
tar -xzf "$ASSET"
sudo install -m 0755 "${ASSET%.tar.gz}/sinter" /usr/local/bin/sinter
sinter --version   # sinter 0.2.1
```

Placing the binary on your `PATH` (the example above uses `/usr/local/bin`)
lets you run `sinter` from any directory; you may also keep it next to your
recipes and invoke it as `./sinter`.

:::note
Newer releases replace these downloads. To install a version other than
v0.2.1, take the file names from the release you want and substitute its tag
in the URLs — the download, checksum, extraction, and verification steps stay
the same.
:::

:::note
The v0.2.1 names record the build platform. Do not rename published assets
or substitute the future unified naming in v0.2.1 URLs. Linux binaries do
not run on macOS.
:::

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
  `attr` with `sudo apt install attr` (Ubuntu) or `sudo dnf install attr` (Rocky)
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

:::caution[Future improvement]
There is currently no `curl | sh` installer. Download + checksum verification
is the supported installation method.
:::
