---
title: Installation
description: Install Sinter from release tarballs or build from source.
---

Sinter runs on the **controller** — the machine you run `sinter` on. The
managed host only needs SSH access. The controller can be macOS, Ubuntu 24.04
LTS, or any environment where the binary builds.

## From release tarballs (recommended)

Release assets are published on the
[GitHub Releases](https://github.com/hagix9/sinter/releases) page. Each
archive contains the `sinter` binary, both READMEs, and the license files.

```sh
# Example: Ubuntu 24.04 amd64 controller
curl -LO https://github.com/hagix9/sinter/releases/download/v0.2.0/sinter-v0.2.0-ubuntu24.04-amd64.tar.gz
curl -LO https://github.com/hagix9/sinter/releases/download/v0.2.0/SHA256SUMS

sha256sum -c SHA256SUMS    # expect: ... OK

tar -xzf sinter-v0.2.0-ubuntu24.04-amd64.tar.gz
./sinter-v0.2.0-ubuntu24.04-amd64/sinter --version   # sinter 0.2.0
```

For a Rocky Linux 9 x86_64 controller, use
`sinter-v0.2.0-rocky9-x86_64.tar.gz` instead.

:::note
The release archive names the platform whose toolchain produced the binary.
The same binary also works as a controller for other targets — the platform
label reflects where it was built and validated, not which targets it can
manage.
:::

## Build from source

Requires a Rust toolchain (rustup or your distribution's packages):

```sh
git clone https://github.com/hagix9/sinter.git
cd sinter
cargo build --locked --release
./target/release/sinter --version
```

## Managed host requirements

The target does not need Sinter installed. It needs:

- an OpenSSH server reachable with a key already in your `known_hosts`
- systemd
- `/bin/sh`
- passwordless `sudo -n` if you use `--sudo`

Sinter refuses unknown or changed SSH host keys. Non-default SSH ports require
an explicit `[host]:port` entry in `known_hosts`.

:::caution[Future improvement]
There is currently no `curl | sh` installer. Download + checksum verification
is the supported installation method.
:::
