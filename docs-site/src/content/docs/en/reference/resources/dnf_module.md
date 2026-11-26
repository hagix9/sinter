---
title: dnf_module
description: Enable a DNF module stream, disable a module or reset it to the distribution default.
---

**Purpose:** declare the state of one DNF module on a DNF 4 host: enabled with
one stream, disabled, or reset to the distribution default. It decides which
packages later [`package`](/en/reference/resources/package/) resources resolve.

## Synopsis

```yaml
- id: nodejs-stream
  type: dnf_module
  with:
    name: nodejs
    stream: "20"
    state: enabled
```

```toml
[[resources]]
id = "nodejs-stream"
type = "dnf_module"

[resources.with]
name = "nodejs"
stream = "20"
state = "enabled"
```

## Parameters

| Parameter | Required | Type | Default | Description |
|-----------|----------|------|---------|-------------|
| `name` | yes | string | — | Module name: `[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}`. |
| `stream` | with `state: enabled` | string | — | Stream name, same characters as `name`. Required when `state` is `enabled`, not allowed otherwise. Quote it in YAML (`"20"`); a bare number is rejected. |
| `state` | yes | string | — | `enabled`, `disabled` or `reset`. |
| `env` | no | map of strings | — | Environment for the `dnf module` command only (for example a proxy). The recipe-wide `env` is the base, as for `package`. |

- `name`, `stream` and `state` may use variables but not facts, registers or
  sensitive values; they are resolved and checked when the recipe is loaded.
- One `dnf_module` per module name in a recipe; a second one is a validation
  error.
- There is no field for module profiles. Installing or removing the packages
  of a profile is a package transaction; use
  [`package`](/en/reference/resources/package/) resources for the packages you
  want.

## Expected behavior

- **Observation.** Sinter reads DNF's own record of the module,
  `/etc/dnf/modules.d/<name>.module`, without running `dnf` and without
  following a symlink. No file means the module is in its default state.
  The file must be exactly what DNF writes: one section `[<name>]` with the
  keys `name`, `stream`, `profiles` and `state`. Anything else (another
  section, an unknown or repeated key, a comment, CRLF line ends, a `state`
  other than `enabled`, `disabled` or empty) is an error, in plan, apply and
  audit alike. Sinter does not guess a state.
- **Comparison.** `enabled` is satisfied when the recorded state is `enabled`
  with the declared stream; `disabled` when it is `disabled`; `reset` when
  there is no file or the recorded state is empty.
- **Plan** reports the change (`state=default` → `state=enabled stream=20`).
  It does not read repository metadata, so it cannot tell whether
  `<name>:<stream>` exists in the enabled repositories: a note says that dnf
  checks this at apply.
- **Apply** runs one fixed command as root, with no shell:
  `/usr/bin/dnf -y module enable <name>:<stream>`,
  `/usr/bin/dnf -y module disable <name>` or
  `/usr/bin/dnf -y module reset <name>`.
  A non-zero exit is a failure. An exit of zero is not trusted on its own:
  the state file is read again and must show the declared state, otherwise
  the resource fails. If dnf is killed, times out or the connection is lost,
  the result says the module state may or may not have changed; Sinter does
  not report success and sends nothing more for that resource.
- dnf's own output is not copied into the result on failure (it can contain
  repository URLs with credentials); the reason gives the exit code and tells
  you to run `dnf module list <name>` on the host.
- dnf may refresh repository metadata over the network for this command; a
  proxy from `env` applies.
- `-y` and `env` are handled as for [`package`](/en/reference/resources/package/).
  `-y` answers every question dnf asks with yes; that includes importing the
  signing key of a repository that has `repo_gpgcheck=1` when its metadata
  is first read. `env` is added to Sinter's baseline environment for this
  one command and can replace a baseline variable; the variable names are
  not restricted.
- **Enabling a module can enable other modules it depends on.** dnf does
  that in the same command, and Sinter does not report it: only the declared
  module's state file is read again, and the result names that module only.
  Run `dnf module list --enabled` on the host to see everything that is
  enabled, and declare the modules you rely on as their own `dnf_module`
  resources.
- The state file must have one name only: a state file with more than one
  hard link is refused (plan, apply and audit).
- A change notifies handlers like any other resource. A second apply changes
  nothing and does not run dnf.
- **Audit** compares the recorded state with the declared one and reports
  `state` and/or `stream` as drift. An unreadable or unexpected state file, a
  symlink and an unsupported host are errors, never drift. Audit runs no dnf
  command.

## What Sinter refuses

All of these stop plan and apply before any command changes the host.

- **Switching streams.** If the module is enabled with a different stream,
  Sinter does not switch it. Review the packages installed from the current
  stream, reset the module explicitly (a `dnf_module` with `state: reset`, in
  an earlier run), then enable the new stream. There is no override option.
- **Installed profiles.** If the state file lists installed profiles,
  `disabled` and `reset` are refused: what happens to those packages is a
  package decision.
- **Hosts without DNF 4.** On Debian and Ubuntu: "dnf_module is not supported
  on this host". With DNF 5 (`/usr/bin/dnf` is a link to `dnf5`): not
  supported in this release. If `/usr/bin/dnf` is not a symbolic link to a
  DNF 4 program (`dnf-3`), the resource stops rather than run an unidentified
  dnf. The check is the one [`dnf_repository`](/en/reference/resources/dnf_repository/)
  uses.
- **A state that changed meanwhile.** Right before it runs dnf, apply reads
  the state file once more. If it no longer shows what the decision was based
  on, nothing is changed and the resource fails; run again.
- **No root.** Changing a module needs root (connect as root or use
  `--sudo`). Plan adds a note; apply fails before dnf is run.
- Not available through MCP: the observation is not measured on real hosts
  yet.

## Supported systems

- DNF 4 on Rocky Linux, RHEL and AlmaLinux 9.
- EL 10 distributions ship no module streams in their repositories. Sinter
  does not special-case the OS version: `state: enabled` there fails at apply
  when dnf finds no such module, and is not a supported use. `disabled` and
  `reset` of a module that has no state file report no change.
- Debian, Ubuntu and DNF 5 hosts are refused as described above.

## Not yet verified on real hosts

The behaviour above is tested against a scripted target. The following has
not been measured on a real Rocky Linux, RHEL or AlmaLinux host yet:

- the exact content of `/etc/dnf/modules.d/<name>.module` after `dnf module
  enable`, `disable` and `reset` (in particular whether `reset` leaves a file
  with an empty `state=` or removes it; both are accepted), and whether any
  DNF 4 version writes other keys;
- that `/usr/bin/dnf` is a symbolic link to `dnf-3` on every supported
  release;
- the exit codes and messages of `dnf module` for a missing module or stream,
  and for a module on EL 10;
- the order in one run: enabling a stream and installing a package from it.

## Example

Enable a stream and install a package from it:

```yaml
version: 1
resources:
  - id: nodejs-stream
    type: dnf_module
    with:
      name: nodejs
      stream: "20"
      state: enabled
  - id: nodejs
    type: package
    depends_on: [nodejs-stream]
    with:
      name: nodejs
      state: present
```

```toml
version = 1

[[resources]]
id = "nodejs-stream"
type = "dnf_module"

[resources.with]
name = "nodejs"
stream = "20"
state = "enabled"

[[resources]]
id = "nodejs"
type = "package"
depends_on = ["nodejs-stream"]

[resources.with]
name = "nodejs"
state = "present"
```

Return a module to the distribution default (for example before choosing
another stream in a later run):

```yaml
- id: nodejs-reset
  type: dnf_module
  with:
    name: nodejs
    state: reset
```
