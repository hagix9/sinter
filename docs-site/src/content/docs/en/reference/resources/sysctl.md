---
title: sysctl
description: Set one kernel parameter, as the running value and as a persistent setting in a file of its own.
---

**Purpose:** declare one kernel parameter (`sysctl`): the value the running
kernel uses now, and a persistent setting that is read at boot.

## Synopsis

```yaml
- id: swappiness
  type: sysctl
  with:
    name: vm.swappiness
    value: 10
```

```toml
[[resources]]
id = "swappiness"
type = "sysctl"

[resources.with]
name = "vm.swappiness"
value = 10
```

A parameter with several fields is written as one string:

```yaml
- id: tcp-rmem
  type: sysctl
  with:
    name: net.ipv4.tcp_rmem
    value: "4096 131072 6291456"
```

```toml
[[resources]]
id = "tcp-rmem"
type = "sysctl"

[resources.with]
name = "net.ipv4.tcp_rmem"
value = "4096 131072 6291456"
```

## Parameters

| Parameter | Required | Type | Default | Description |
|-----------|----------|------|---------|-------------|
| `name` | yes | string | — | The parameter in dotted form: `[a-z0-9_]+(\.[A-Za-z0-9_-]+)+`, at most 128 bytes. No `/`, no `*`. |
| `value` | with `present` | string or integer | — | One line of printable ASCII, at most 1024 bytes, not empty, without `{{`. |
| `state` | no | string | `present` | `present` or `absent`, written literally. |
| `runtime` | no | boolean | `true` | Manage the running value. A literal `true` or `false`. |
| `persist` | no | boolean | `true` | Manage the persistent file. A literal `true` or `false`. |

- `name` may use variables but not facts, registers or sensitive values; it
  is resolved and checked when the recipe is loaded.
- `value` is compared after trimming it and collapsing every run of spaces
  and tabs to one space, so `4096 131072 6291456` equals the tab-separated
  form the kernel prints. The file and the change command use that
  normalized form.
- `state`, `runtime` and `persist` cannot come from a variable.
- At least one of `runtime` and `persist` must be `true`.
- With `state: absent`, `value`, `runtime` and `persist` are not accepted.
- One `sysctl` per parameter in a recipe; a second one with the same `name`
  is a validation error.

## The persistent setting

Sinter owns one whole file per parameter:

```
/etc/sysctl.d/90-sinter-<name>.conf
```

Its content is exactly

```
# Managed by Sinter (sysctl). Local changes are replaced.
<name> = <value>
```

owned by `root:root` with mode `0644`. The file is written the way a
[`file`](/en/reference/resources/file/) resource writes it: atomically, after
the same checks of the parent directories, with a diff in plan. A `file`,
`template` or `file_merge` resource on the same path in the same recipe is a
validation error.

Sinter never edits `/etc/sysctl.conf` or any other file. A file that sorts
later in `/etc/sysctl.d`, or `/etc/sysctl.conf`, can still set another value
at boot. Sinter does not evaluate that order, and the value after a reboot
is **not verified** by this resource.

## Expected behavior

- **Observation of the running value.** Sinter runs
  `/usr/sbin/sysctl -n -- <name>` (read-only). Only an exit of zero with
  exactly one line on standard output and nothing on standard error is
  accepted. A non-zero exit is reported as "unknown kernel parameter" and
  stops the resource; it is never treated as "absent" or as a difference.
  Truncated output, a second line, a signal or a timeout is an error.
- **Plan** shows the difference of the file and, in a note, the running
  value (`"60" -> "10"`). It runs nothing but the observation.
- **Apply** works in this order:
  1. observe the running value (so an unknown parameter is refused before
     anything is written);
  2. write the file, if `persist` is `true` and it differs;
  3. if `runtime` is `true` and the running value differs, run
     `/usr/sbin/sysctl -w -- <name>=<value>` as root, with no shell, then
     observe again.

  The change succeeds only if `sysctl -w` exits zero **and** the value
  observed afterwards equals `value`. Otherwise the resource fails. If the
  file was already written, the failed result still reports that change. If
  the file cannot be written, the running value is not touched. If
  `sysctl -w` is killed, times out or the connection is lost, the result says
  the running value may or may not have been changed; Sinter does not report
  success.
- A second apply changes nothing, does not rewrite the file and does not run
  `sysctl -w`.
- With `runtime: false` Sinter does not run `sysctl` at all: only the file is
  managed, the parameter is not checked against the running kernel, and the
  setting takes effect at the next boot or when you run `sysctl --system`.
- With `persist: false` only the running value is managed. A file Sinter
  wrote earlier is left as it is; use `state: absent` to remove it.
- **`state: absent`** removes Sinter's file and nothing else. The running
  value is **not** reset: there is no previous value to restore. It keeps its
  current value until a reboot or another change. `sysctl` is not run.
- **Audit** reports a difference of the file under the dimension
  `persistent` (content, owner, group, mode or presence, as the `file` audit
  reports it) and a difference of the running value under `runtime`, each
  only when the resource manages it. An unknown parameter and a failed
  observation are errors, not drift.

A change notifies handlers like any other resource. Sinter restarts nothing.

## Privilege

Changing a kernel parameter and writing under `/etc/sysctl.d` need root:
connect as root or use `--sudo`. Plan says so when the connection is not
root. A run that has nothing to change needs no root.

## Limits and unsupported cases

- A host without `/usr/sbin/sysctl`: with `runtime: true`, plan and apply
  fail with "sysctl cannot manage the running value on this host
  (/usr/sbin/sysctl was not found)" and audit reports an error.
- Names with `/` (the alternative separator) or `*` (patterns), and
  interface names that contain a dot, cannot be declared.
- The value must be written the way the kernel reports it. If the kernel
  rounds or clamps what is written, or the parameter is read-only, the
  resource fails after `sysctl -w` and every later run fails the same way.
- A parameter that prints more than one line cannot be managed.
- An empty value cannot be declared.
- A parameter that exists only after a kernel module is loaded is an
  "unknown kernel parameter" while the module is not loaded. Use
  `runtime: false` to manage only the file.
- Sinter does not evaluate which file wins at boot and does not run
  `sysctl --system`.
- With `sensitive: true` on the resource, values are withheld from plan,
  apply and audit output. The parameter name and the file path are still
  shown.

## Supported OS

Ubuntu 24.04 and 26.04, and Rocky Linux, RHEL and AlmaLinux 9 and 10.

This resource is tested against Sinter's scripted target only. It is **not
verified on real hosts**: the output and exit codes of `sysctl -n` and
`sysctl -w`, how the kernel stores written values, and what is read at boot.
