---
title: timezone
description: Set the system time zone of a host with timedatectl.
---

**Purpose:** declare the system time zone of a host: the zone the symbolic
link `/etc/localtime` names below `/usr/share/zoneinfo`.

## Synopsis

```yaml
- id: zone
  type: timezone
  with:
    name: Asia/Tokyo
```

```toml
[[resources]]
id = "zone"
type = "timezone"

[resources.with]
name = "Asia/Tokyo"
```

## Parameters

| Parameter | Required | Type | Default | Description |
|-----------|----------|------|---------|-------------|
| `name` | yes | string | — | An IANA zone name such as `Asia/Tokyo`, `UTC` or `America/Argentina/Buenos_Aires`: 1 to 3 components of `A-Z`, `a-z`, `0-9`, `_`, `+` and `-` separated by `/`, no component starting with `-`, at most 64 bytes. |

- `name` may use variables but not facts, registers or sensitive values; it
  is resolved and checked when the recipe is loaded.
- A leading `/`, `.` and `..` are refused. The `posix/` and `right/` trees
  and the names `posixrules` and `localtime` are refused: declare the zone
  itself.
- One `timezone` per recipe; a second one is a validation error.
- `/etc/localtime` belongs to this resource: a `file`, `template`, `link` or
  `file_merge` on that path in the same recipe is a validation error.

## Expected behavior

- **Observation (read-only).** Sinter looks at `/etc/localtime` without
  following it. It must be a symbolic link whose target is
  `/usr/share/zoneinfo/<zone>` or `../usr/share/zoneinfo/<zone>`. A regular
  file (a copied zone file), a missing `/etc/localtime` and any other target
  are errors: Sinter does not guess a zone from a copied file.
- **Plan** compares the zone with `name`. If they differ, it checks that
  `/usr/share/zoneinfo/<name>` exists as a regular file and that
  `/usr/bin/timedatectl` exists, and shows the current and the declared
  zone. A zone that is not installed is an error naming the zone, unless an
  earlier resource in the run (for example a `tzdata` package) may provide
  it; then the check is repeated in apply.
- **Apply** runs `/usr/bin/timedatectl set-timezone <name>` as root, with no
  shell. A non-zero exit is a failure. An exit of zero is not trusted on its
  own: `/etc/localtime` is observed again and must name `name`, otherwise
  the resource fails. If the tool is killed, times out or the connection is
  lost, the result says the zone may or may not have been changed; Sinter
  does not report success.
- A second apply changes nothing and does not run `timedatectl`. A host
  already in the declared zone does not need `timedatectl` at all.
- **Audit** compares the zone with `name` and reports a difference as drift
  in `timezone`. A copied zone file, a missing link and every failed
  observation are errors, never drift.

## What Sinter does not do

- It does not set the clock, NTP synchronization (`set-ntp`), the RTC mode
  (`set-local-rtc`) or any other `timedatectl` setting.
- It restarts nothing. Programs that are already running keep the time zone
  they started with until they are restarted. Every plan and apply result
  that changes the zone says so.
- It does not write `/etc/localtime` itself, does not install time zone
  data, and does not edit `/etc/timezone` (Debian, Ubuntu) directly.

A change notifies handlers like any other resource.

## Privilege

Changing the zone needs root: connect as root or use `--sudo`. Plan says so
when the connection is not root. A run that has nothing to change needs no
root.

## Sensitive resources

With `sensitive: true` the zone is withheld from diffs, notes, reasons and
audit details. The record of read-only commands still names the zone file
Sinter checks (`/usr/share/zoneinfo/<name>`), as it names the path of a
sensitive `file`.

## Unsupported cases

- `/etc/localtime` as a regular file (a copied zone file), or as a link that
  does not point into `/usr/share/zoneinfo`.
- Hosts without `/usr/bin/timedatectl` (containers and other systems without
  `systemd-timedated`): plan and apply fail with "timezone is not supported
  on this host (/usr/bin/timedatectl was not found)" when a change is
  needed; audit reads the link only.
- Zone names that are symbolic links below `/usr/share/zoneinfo` on some
  systems: the zone file must be a regular file.

## Supported OS

Ubuntu 24.04 and 26.04, and Rocky Linux, RHEL and AlmaLinux 9 and 10.

This resource is tested against Sinter's scripted target only. A read-only
look at Rocky Linux 10.2 showed `/etc/localtime` as a symbolic link to
`/usr/share/zoneinfo/Asia/Tokyo`. **Not verified on real hosts:** what
`timedatectl set-timezone` writes and prints and its exit codes on every
OS, the link form on Ubuntu, EL 9, RHEL and AlmaLinux, whether every zone
file is a regular file on each OS, and the behavior inside containers.
