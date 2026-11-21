---
title: nm_connection
description: Declare one NetworkManager Ethernet connection profile, with management-path protection and a NetworkManager checkpoint.
---

:::caution[Not released]
`nm_connection` is implemented for v1.15.0 but not released. A first
real-host measurement (Rocky Linux 9.8 and 10.2) found two defects, now
fixed: checkpoint creation was refused by NetworkManager, and profiles with
IPv6 values could not be read. Activation, deactivation, the checkpoint and
its rollback with the fixed code are not yet measured on real hosts; until
they are, anything Sinter cannot read exactly is refused, never assumed.
:::

**Purpose:** declare one NetworkManager connection profile (`connection.id`)
of type Ethernet: its interface, autoconnect, IPv4/IPv6 settings, whether it
exists and, optionally, whether it is active.

## Synopsis

```yaml
- id: lan
  type: nm_connection
  with:
    name: lan
    ifname: eth1
    autoconnect: true
    ipv4:
      method: manual
      addresses: [198.51.100.10/24]
      dns: [198.51.100.53]
      dns_search: [lab.example.net]
    ipv6:
      method: ignore
    active: true
```

## Parameters

| Parameter | Required | Type | Default | Description |
|-----------|----------|------|---------|-------------|
| `name` | yes | static string | — | `connection.id`: 1–64 bytes of printable ASCII without `\`, not starting with `-`, no leading or trailing space. Exactly one profile may have it. |
| `type` | no | string | `ethernet` | Only `ethernet` in v1.15.0. |
| `ifname` | no | string | — | `connection.interface-name` (1–15 bytes, `[A-Za-z0-9_.-]`). |
| `autoconnect` | no | boolean | — | `connection.autoconnect`. |
| `ipv4.method` | no | string | — | `auto`, `manual` or `disabled`. |
| `ipv4.addresses` | no | list | — | IPv4 addresses with prefix (`192.0.2.10/24`), order kept. |
| `ipv4.gateway` | no | string | — | IPv4 address; `""` for none. |
| `ipv4.dns` | no | list | — | IPv4 addresses; order is significant. |
| `ipv4.dns_search` | no | list | — | DNS names (RFC 1123 labels, lower case, at most 253 bytes). |
| `ipv6.method` | no | string | — | `auto`, `manual`, `ignore`, `disabled` or `link-local`. |
| `ipv6.addresses`, `ipv6.gateway`, `ipv6.dns` | no | — | — | As for IPv4, canonical IPv6 text (RFC 5952). |
| `state` | no | string | `present` | `present` or `absent`. |
| `active` | no | boolean | — | Whether the profile is active. |
| `checkpoint_timeout` | no | integer | `90` | Rollback timeout of the checkpoint in seconds, 30–600. |

- Only declared fields are compared and changed; every other setting of the
  profile stays as it is.
- `method: manual` needs at least one address. Addresses or a gateway are
  allowed only with `manual` (other combinations are not measured yet).
- `state: absent` allows only `name`.
- 802.1X, Wi-Fi, VLAN, bond, bridge and every setting with a secret are not
  supported; unknown fields are a validation error.
- Two `nm_connection` resources with the same `name` are a validation error.
- An existing profile of another type is never changed or removed.

## Expected behavior

- Precheck: `NetworkManager.service` is active and `/usr/bin/nmcli` exists;
  otherwise the resource fails naming the missing component. Sinter never
  installs or starts NetworkManager.
- Observation uses terse `nmcli` output with fixed field lists and is
  parsed strictly: a missing, repeated or unknown field, an unknown value
  or a profile in transition is an error, never drift. A settings line is
  read as the field name up to the first colon and the value after it (as
  NetworkManager prints IPv6 values, without escaping their colons); a value
  with a backslash or a control character is refused. Two profiles with the
  name are an error.
- Changes use fixed argv (`nmcli connection add|modify|up|down|delete`),
  never a shell, and the UUID Sinter observed, so a profile renamed or
  replaced in between is never the one changed. Afterwards the profile is
  observed again and every declared field verified.
- `active: true` activates the profile when it changed or is inactive;
  `active: false` deactivates it. Without `active`, a changed profile that is
  active is **not** re-activated: the device keeps its running settings until
  NetworkManager activates the profile again (for example at boot); plan and
  apply say so.
- A second apply of the same recipe changes nothing.
- Audit is read-only and reports drift per declared field, presence and (when
  declared) the active state.
- Not available through MCP.

## Management connection and checkpoint

Every change is connection-risk class C (see
[connection-risk control](/en/reference/cli/)). With the management
interfaces and client address of the SSH connection Sinter uses, a change
**affects** the management connection when the profile's interface (before
or after) is a management interface, the profile is active on one, it would
autoconnect or be activated without an interface (NetworkManager then picks
the device), it is deactivated or deleted while active
on one, or it can change routing for the client address: automatic
addressing (DHCP or router advertisements), a gateway, or an address whose
prefix contains the client address (for a created profile, or a changed
inactive profile that autoconnects, NetworkManager may activate it by itself,
so its addressing counts too). Only a change that is none of these is
**clear** (for example DNS settings on a non-management profile). A port
profile (of a bridge, bond or team) is **unknown**, and so is every change
when a management interface is not a plain Ethernet device (a bridge, bond,
team or VLAN). If the
path cannot be read the result is **unknown** and the change is refused; a
local target has no visible management connection, so every change there is
refused.

An `affects` change needs an approval and runs only inside a
NetworkManager checkpoint:

1. The checkpoint API (`CheckpointCreate`, `CheckpointDestroy`,
   `CheckpointRollback`) and its permission are checked with `busctl`;
   unavailable or refused (for example by polkit) fails the resource before
   any change.
2. A checkpoint is created for the management devices and the profile's
   device (never for all devices) with the rollback timeout
   `checkpoint_timeout`; a profile created inside it is removed by its
   rollback.
3. The change is applied, then a new SSH connection (full host-key check,
   `/usr/bin/true`) is opened.
4. Success destroys the checkpoint (the change stays) and verifies it.
   Failure rolls back explicitly when the original connection answers, or
   waits the timeout plus 15 seconds and reconnects; a verified rollback
   fails the resource (exit 5), anything else is indeterminate (exit 6).

A checkpoint is available only when the change takes effect now (the
profile is activated, or an active profile is deactivated or deleted) and
the devices are known. A change that would take effect only at a later
activation or boot, or a profile that autoconnects without an interface, is
refused even with an approval, because nothing can test it now.

Checkpoint creation, destruction and rollback are written to the approval
ledger. If Sinter is interrupted after creating a checkpoint, NetworkManager
rolls back at the timeout even a change that worked, and the ledger shows the
run as interrupted.

**Limits:** the checkpoint can restore NetworkManager's configuration while
NetworkManager keeps running. It does not cover a NetworkManager restart, a
reboot, routes or filters outside NetworkManager, or another session than
Sinter's own. Recovery is never guaranteed.
