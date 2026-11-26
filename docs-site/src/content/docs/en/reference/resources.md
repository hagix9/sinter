---
title: Resource Reference
description: All built-in Sinter resource types implemented in v1.15.0.
---

Sinter v1.15.0 implements twelve built-in resource types (`postgresql_role` is new in v1.5.1; `systemd_timer` and `nm_connection` are new in v1.15.0). Six more are added after v1.15.0 and are **not in a release yet**: `file_merge`, `dnf_repository`, `dnf_module`, `crypto_policy`, `sysctl` and `hostname`; [Resource Plugins](/en/reference/resource-plugins/) can add more. Parameters below are the
complete supported set — unknown `with` fields are schema errors.

| Type | Purpose | Key parameters |
|------|---------|----------------|
| [file](/en/reference/resources/file/) | Regular file content + metadata | `path`, `state`, `content`/`source`, `owner`, `group`, `mode` |
| [directory](/en/reference/resources/directory/) | Directory presence + metadata | `path`, `state`, `owner`, `group`, `mode`, `parents` |
| [link](/en/reference/resources/link/) | Symbolic links | `path`, `target`, `state` |
| [template](/en/reference/resources/template/) | Rendered controller-side templates | `path`, `source`, `vars`, `mode` |
| [command](/en/reference/resources/command/) | Exact-argv program execution | `program`, `args`, `creates`/`removes`, `changed_when`, `register` |
| [package](/en/reference/resources/package/) | Package install/remove (apt/dnf) | `name`, `state` |
| [service](/en/reference/resources/service/) | systemd state + enablement | `name`, `state`, `enabled` |
| [systemd_timer](/en/reference/resources/systemd_timer/) | systemd timer unit + enablement | `name`, `on_calendar`, `on_boot_sec`, `state`, `enabled` |
| [nm_connection](/en/reference/resources/nm_connection/) | NetworkManager Ethernet profile (since v1.15.0) | `name`, `ifname`, `autoconnect`, `ipv4`, `ipv6`, `state`, `active` |
| [group](/en/reference/resources/group/) | Local Linux group | `name`, `state`, `gid`, `system` |
| [user](/en/reference/resources/user/) | Local Linux user | `name`, `state`, `uid`, `group`, `groups`, `shell`, `home`, `create_home`, `system`, `password_hash` |
| [file_merge](/en/reference/resources/file_merge/) | One part of an existing text file: a line, a marked block or a `key = value` (unreleased) | `path`, `merge`, `line` / `marker`+`content` / `key`+`value`, `state`, `create` |
| [dnf_repository](/en/reference/resources/dnf_repository/) | One repository section in `/etc/yum.repos.d` (unreleased) | `name`, `file`, `enabled`, `baseurl`, `gpgcheck`, `gpgkey`, `state` |
| [dnf_module](/en/reference/resources/dnf_module/) | DNF 4 module stream state (unreleased) | `name`, `stream`, `state` |
| [crypto_policy](/en/reference/resources/crypto_policy/) | System-wide cryptographic policy, RHEL family (unreleased) | `policy`, `allow_weaker` |
| [sysctl](/en/reference/resources/sysctl/) | One kernel parameter: running value and persistent setting (unreleased) | `name`, `value`, `state`, `runtime`, `persist` |
| [hostname](/en/reference/resources/hostname/) | The static host name (unreleased) | `name` |
| [postgresql_role](/en/reference/resources/postgresql_role/) | Role of a local PostgreSQL server (since v1.5.1) | `name`, `state`, `login`, `superuser`, …, `connection_limit`, `password_verifier` |

## Shared conventions

- `path`-type parameters are absolute paths; parent paths must already exist
  and pass the trust-boundary check (no unexpected symlinks; sticky, root-owned
  shared directories such as `/tmp` and `/var/tmp` are accepted, and when
  running as root a path inside an unprivileged account's own directory is
  accepted — see [file § Trust boundary](/en/reference/resources/file/#trust-boundary)).
- `mode` is always a quoted four-digit octal string (`"0644"`).
- `state` defaults to `present` for filesystem resources; `package` requires
  it explicitly.
- Content publication is atomic (rename); existing metadata is preserved when
  omitted.
- All types are idempotent — a converged resource mutates nothing on re-apply.
