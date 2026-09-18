---
title: Installation
description: Install Sinter from release tarballs or build from source.
---

Sinter runs on the **controller** — the machine you run `sinter` on. The
managed host only needs SSH access. One Linux x86_64 release binary is
published; it is built on the oldest supported baseline (Rocky Linux 9
x86_64, glibc 2.34) and runs on every supported Linux x86_64 target
(Ubuntu 24.04, Ubuntu 26.04, Rocky Linux 9, Rocky Linux 10). Controllers on
other operating systems, such as macOS, can build Sinter from source.

## From release tarballs (recommended on Linux)

The current release is **v0.2.1**. Release assets are published on the
[GitHub Releases](https://github.com/hagix9/sinter/releases) page. Each
archive contains the `sinter` binary, both READMEs, and the license files.

```sh
# Linux x86_64 controller (built on Rocky Linux 9, runs on any supported Linux x86_64 target)
curl -LO https://github.com/hagix9/sinter/releases/download/v0.2.1/sinter-v0.2.1-linux-x86_64.tar.gz
curl -LO https://github.com/hagix9/sinter/releases/download/v0.2.1/SHA256SUMS

sha256sum -c SHA256SUMS    # expect: ... OK

tar -xzf sinter-v0.2.1-linux-x86_64.tar.gz
sudo install -m 0755 sinter-v0.2.1-linux-x86_64/sinter /usr/local/bin/sinter
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
The release archive names the platform whose toolchain produced the binary.
The Linux x86_64 artifact is built once on Rocky Linux 9 and is verified by
extraction and a run on every supported Linux x86_64 target; the platform
label reflects where it was built and validated, not which targets it can
manage. Linux release binaries do not run on macOS.
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
  cannot prove safe. Stock Ubuntu cloud images ship without `attr`, so run
  `sudo apt install attr` once; Rocky Linux images include it
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
