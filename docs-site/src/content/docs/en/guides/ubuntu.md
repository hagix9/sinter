---
title: Ubuntu
description: Ubuntu 24.04 and 26.04 LTS amd64 managed-target guide — apt backend.
---

Ubuntu 24.04 LTS amd64 is the original Sinter reference target, and Ubuntu
26.04 LTS amd64 is supported with the same `apt` backend. The repository
support policy covers both version lines; both are acceptance-tested.

## Unified Linux x86_64 distribution

Sinter v0.5.1 uses one `sinter-v<VERSION>-linux-x86_64.tar.gz` for all
supported x86_64 version lines. The executable is unified; runtime platform
detection still selects APT on Ubuntu and DNF on RHEL-family targets. This
is not a claim of support for arbitrary Linux systems or architectures.

Sinter v0.4.1 passed eight-real-host acceptance on Ubuntu 24.04.5 LTS,
Ubuntu 26.04.1 LTS, Rocky Linux 9.8, Rocky Linux 10.2, RHEL 9.8, RHEL 10.2,
AlmaLinux 9.8, and AlmaLinux 10.2 — all x86_64, 344/344 checks.
Other and future point releases have not each been independently validated.
Historical v0.2.1 retains its distro-specific assets; see
[Installation](https://sinter.fulltrust.co.jp/en/getting-started/installation/)
for current downloads.


## Requirements

| Requirement | Notes |
|-------------|-------|
| Ubuntu 24.04 or 26.04 LTS | amd64 |
| OpenSSH server | Strict `known_hosts` verification; no auto-enrollment |
| systemd | Required for `service` resources and handlers |
| `/bin/sh` | Target-side shell |
| `attr` package | `/usr/bin/getfattr`; check on the target; run `sudo apt install attr` if missing |
| `sudo -n` | Passwordless sudo when using `--sudo` |

## Package management

`type: package` uses **apt** on Ubuntu. Package names must be valid Debian
package names; `state` is `present` or `absent`.

```yaml
resources:
  - id: nginx
    type: package
    with:
      name: nginx
      state: present
```

## Platform detection

Sinter reads the target's `/etc/os-release` and selects the `apt` backend for
`ID=ubuntu` / Debian-family systems. There is no recipe-level backend switch —
recipes stay platform-neutral.

## Example session

```sh
sinter plan --host web01 --sudo recipe.yaml
sinter apply --host web01 --sudo recipe.yaml
```

If `known_hosts` lacks the host key (or the port is non-default without a
`[host]:port` entry), the connection fails closed.

## Testing note

The repository's SSH integration test suite targets disposable Ubuntu hosts
via `SINTER_TEST_SSH_*` environment variables — see
[Contributing](/en/contributing/).
