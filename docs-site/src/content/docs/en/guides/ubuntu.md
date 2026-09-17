---
title: Ubuntu
description: Ubuntu 24.04 LTS amd64 managed-target guide — apt backend.
---

Ubuntu 24.04 LTS amd64 is the original Sinter reference target and remains
fully supported in v0.2.1.

## Requirements

| Requirement | Notes |
|-------------|-------|
| Ubuntu 24.04 LTS | amd64 |
| OpenSSH server | Strict `known_hosts` verification; no auto-enrollment |
| systemd | Required for `service` resources and handlers |
| `/bin/sh` | Target-side shell |
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
[Contributing](/sinter/en/contributing/).
