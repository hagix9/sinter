---
title: kernel_module
description: Load a kernel module now and at boot, or blacklist it, with files of Sinter's own and modprobe.
---

**Purpose:** declare one kernel module: loaded now and at every boot, not
loaded at boot by Sinter any more, or kept out of alias-based autoloading
(blacklisted).

## Synopsis

```yaml
- id: br-netfilter
  type: kernel_module
  with:
    name: br_netfilter

- id: no-pcspkr
  type: kernel_module
  with:
    name: pcspkr
    state: blacklisted
```

```toml
[[resources]]
id = "br-netfilter"
type = "kernel_module"

[resources.with]
name = "br_netfilter"

[[resources]]
id = "no-pcspkr"
type = "kernel_module"

[resources.with]
name = "pcspkr"
state = "blacklisted"
```

## Parameters

| Parameter | Required | Type | Default | Description |
|-----------|----------|------|---------|-------------|
| `name` | yes | string | — | The module name: `A-Z`, `a-z`, `0-9`, `_` and `-`, 1 to 64 bytes. `-` and `_` name the same module; Sinter uses the form with `_`. |
| `state` | no | string | `present` | `present`, `absent` or `blacklisted` (a literal, not a variable). |
| `runtime` | no | boolean | `true` | With `present`: load the module now. |
| `persist` | no | boolean | `true` | With `present`: load it at every boot (Sinter's file in `/etc/modules-load.d`). |

- `name` may use variables but not facts, registers or sensitive values; it
  is resolved and checked when the recipe is loaded.
- With `present`, at least one of `runtime` and `persist` is true. With
  `absent` and `blacklisted`, `runtime` and `persist` are refused.
- One `kernel_module` per module (`br-netfilter` and `br_netfilter` are the
  same); a second one is a validation error.
- Sinter's two files for the module belong to this resource: a `file`,
  `template` or `file_merge` on either path in the same recipe is a
  validation error.

## The files Sinter owns

| File | Content | Used by |
|------|---------|---------|
| `/etc/modules-load.d/sinter-<name>.conf` | `# Managed by Sinter (kernel_module). Local changes are replaced.` and `<name>` | `present` with `persist` |
| `/etc/modprobe.d/sinter-blacklist-<name>.conf` | the same comment line and `blacklist <name>` | `blacklisted` |

Both are `root:root`, mode `0644`, written whole through the `file`
resource (atomic replacement, parent checks, refusal of a symbolic link,
diff). Sinter never edits any other file in these directories.

## Expected behavior

- **present**
  - Whether the module is loaded is read from `/sys/module/<name>` (a
    directory there means loaded; a built-in module that appears there
    counts as loaded). `/sys/module` itself must exist.
  - Only when a load is needed: `/usr/sbin/modprobe -n -v -- <name>`
    (modprobe's dry run) must exit 0. Exit 1 is the error "module … is not
    available for the running kernel", before any file is written. Any
    other answer is an observation error. If an earlier resource in the run
    (for example a package) may provide the module, plan says it is checked
    again in apply.
  - Apply writes Sinter's files first (the blacklist file is removed, the
    boot-time file written), then runs `/usr/sbin/modprobe -- <name>` as
    root and observes `/sys/module/<name>` again. A non-zero exit, or a
    module that still does not appear, is a failure. If a file was already
    changed, the failure reports that change. A signal, a timeout or a lost
    connection is reported as "may or may not have been loaded", never as
    success.
  - A loaded module needs neither the dry run nor `modprobe`.
- **absent**: Sinter's boot-time file is removed. The module is **not
  unloaded**; it stays loaded until a reboot.
- **blacklisted**: Sinter's blacklist file is written and its boot-time file
  removed. The module is **not unloaded**. After a reboot it can still be
  loaded explicitly or as a dependency of another module: `blacklist` only
  stops alias-based autoloading.
- **Audit** reports differences of the boot-time file as `persistent`, of
  the blacklist file as `blacklist`, and a module that is not loaded (with
  `present` and `runtime`) as `loaded`. Every observation failure is an
  error, never drift. Audit never runs `modprobe`.

## What Sinter does not do

- It never unloads a module (`modprobe -r` is not run by any state).
  Unloading a module in use and dependency handling need their own design.
- It does not evaluate other files in `/etc/modules-load.d`,
  `/usr/lib/modules-load.d` or `/etc/modprobe.d`: a `blacklist` or `install`
  line elsewhere can still change what happens at boot. The state after a
  reboot is not verified.
- It does not set module parameters and does not touch the kernel command
  line (`modprobe.blacklist=`, `module.param=`); that belongs to a later
  `kernel_args` type.
- It does not install module packages and does not rebuild the initramfs.

## Privilege

Writing the files and loading a module need root: connect as root or use
`--sudo`. Plan says so when the connection is not root.

## Sensitive resources

The module name is not treated as secret: like a `sysctl` name or a file
path it appears in notes and in the record of commands; file diffs follow
the `file` resource's redaction.

## Unsupported cases

- Hosts without `/sys/module` (no sysfs), and hosts without
  `/usr/sbin/modprobe` when a load is needed ("kernel_module is not
  supported on this host").
- A built-in module that does not appear in `/sys/module` (one without
  parameters): `modprobe` succeeds but the module is not observed, so the
  resource fails; use `persist` only (`runtime: false`) for it.

## Supported OS

Ubuntu 24.04 and 26.04, and Rocky Linux, RHEL and AlmaLinux 9 and 10.

This resource is tested against Sinter's scripted target only. A read-only
look at Rocky Linux 10.2 showed `/etc/modules-load.d` (empty),
`/sys/module/loop` present, `/sys/module/<unknown>` missing, and
`modprobe -n -v` exiting 0 with an `insmod …` line for an available module
and 1 with `FATAL: Module … not found` for an unknown one. **Not verified on
real hosts:** that `modprobe -n` changes nothing on every OS; the loading
itself and its exit codes; how built-in modules appear in `/sys/module` on
each OS and kernel; that systemd-modules-load and modprobe read Sinter's
files at boot; Ubuntu, EL 9, RHEL and AlmaLinux at all.
