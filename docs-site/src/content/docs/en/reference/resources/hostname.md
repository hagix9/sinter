---
title: hostname
description: Set the static host name of a host with hostnamectl.
---

**Purpose:** declare the static host name of a host (`hostnamectl`), the name
stored in `/etc/hostname`.

## Synopsis

```yaml
- id: name
  type: hostname
  with:
    name: web01.example.invalid
```

```toml
[[resources]]
id = "name"
type = "hostname"

[resources.with]
name = "web01.example.invalid"
```

## Parameters

| Parameter | Required | Type | Default | Description |
|-----------|----------|------|---------|-------------|
| `name` | yes | string | — | The host name: labels of `a-z`, `0-9` and `-` (1 to 63 bytes each, not starting or ending with `-`) separated by single dots; 1 to 64 bytes in total; lower case only. |

- `name` may use variables but not facts, registers or sensitive values; it
  is resolved and checked when the recipe is loaded.
- A name with upper-case letters is a validation error that asks you to write
  it in lower case. Sinter does not change the case for you.
- One `hostname` per recipe; a second one is a validation error.

## Expected behavior

- **Observation.** Sinter runs `/usr/bin/hostnamectl --static` and
  `/usr/bin/hostnamectl --transient` (read-only). Only an exit of zero with at
  most one line on standard output is accepted. An empty answer for the
  static name means "not set". Any other exit, a second line, truncated
  output, a signal or a timeout is an error; Sinter does not guess the name.
- **Plan** compares the static name with `name`. If they differ, plan shows
  the current and the declared name and runs nothing else.
- **Apply** runs `/usr/bin/hostnamectl set-hostname <name>` as root, with no
  shell. A non-zero exit is a failure. An exit of zero is not trusted on its
  own: the static name is observed again and must equal `name`, otherwise
  the resource fails. If the tool is killed, times out or the connection is
  lost, the result says the name may or may not have been changed; Sinter
  does not report success.
- A second apply changes nothing and does not run `set-hostname`.
- **The transient name is reported, not managed.** The transient name is the
  one the running kernel uses. If it is not `name` after the change (or when
  nothing had to change, or in audit), the result carries a note: another
  source such as DHCP sets the running name. That is neither drift nor a
  failure.
- **Audit** compares the static name with `name` and reports a difference as
  drift in `static`. An observation that fails, and a host without
  `hostnamectl`, are errors.

## What Sinter does not do

- It does not edit `/etc/hosts`. If the host needs an entry for its own
  name, declare it with [`file_merge`](/en/reference/resources/file_merge/).
- It restarts nothing. Programs that read the host name when they start keep
  the previous name until they are restarted. Every plan and apply result
  that changes the name says so.
- It does not set the pretty name, the transient name alone, or any other
  `hostnamectl` property.
- `facts.hostname` in the same run stays the name Sinter observed when it
  connected; a later run sees the new name.

A change notifies handlers like any other resource, so a recipe can restart
a service with a `service` handler.

The SSH connection Sinter uses does not depend on the host name, so this
resource has no connection-risk handling.

## Privilege

Changing the host name needs root: connect as root or use `--sudo`. Plan
says so when the connection is not root. A run that has nothing to change
needs no root.

## Unsupported cases

- Hosts without `/usr/bin/hostnamectl`: plan and apply fail with "hostname
  is not supported on this host (hostnamectl was not found)"; audit reports
  an error.
- Upper-case letters, underscores, a trailing dot, and names longer than 64
  bytes.
- Containers and other systems where `systemd-hostnamed` is not available:
  `hostnamectl` fails there, and Sinter reports that as an observation
  error.

## Supported OS

Ubuntu 24.04 and 26.04, and Rocky Linux, RHEL and AlmaLinux 9 and 10.

This resource is tested against Sinter's scripted target only. It is **not
verified on real hosts**: the output and exit codes of `hostnamectl --static`,
`--transient` and `set-hostname`, and what happens to the transient name.
