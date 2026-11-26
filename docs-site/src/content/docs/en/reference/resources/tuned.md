---
title: tuned
description: Select the TuneD profile of a host with tuned-adm.
---

**Purpose:** declare which TuneD profile is
selected on a host (`tuned-adm profile`), or that no profile is selected
(`tuned-adm off`).

## Synopsis

```yaml
- id: profile
  type: tuned
  with:
    profile: throughput-performance
```

```toml
[[resources]]
id = "profile"
type = "tuned"

[resources.with]
profile = "throughput-performance"
```

## Parameters

| Parameter | Required | Type | Default | Description |
|-----------|----------|------|---------|-------------|
| `profile` | one of three | string | — | The profile to select: `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`. |
| `recommended` | one of three | boolean (literal) | `false` | `true`: select the profile that `tuned-adm recommend` names for this host. |
| `state` | one of three | `active` or `off` (literal) | `active` | `off`: no profile is selected. |
| `verify` | no | boolean (literal) | `false` | `true`: also check with `tuned-adm verify` that the selected profile is applied (in apply after a change, and in audit). |

- Write **exactly one** of `profile`, `recommended: true` and `state: off`.
  None of them, or more than one, is a validation error.
- `profile` may use variables but not facts, registers or sensitive values;
  it is resolved and checked when the recipe is loaded. `recommended`,
  `state` and `verify` must be written literally.
- `verify: true` with `state: off` is a validation error: there is nothing
  to verify.
- One `tuned` per recipe; a second one is a validation error.

## Selected and applied are two things

TuneD keeps the name of the selected profile in `/etc/tuned/active_profile`.
That file says which profile is **selected**. The profile's settings are
**applied** only while `tuned.service` runs. Sinter reports the two
separately:

- The selection is what plan, apply and audit compare with your declaration.
- If the profile is selected but `tuned.service` is not active, an unchanged
  result carries a note, and audit reports a difference in `service`.
- Whether the settings really are in effect is checked only when you ask for
  it with `verify: true`.

## Examples

Select the profile TuneD recommends for the host:

```yaml
- id: profile
  type: tuned
  with:
    recommended: true
```

```toml
[[resources]]
id = "profile"
type = "tuned"

[resources.with]
recommended = true
```

Switch tuning off (no profile selected):

```yaml
- id: profile
  type: tuned
  with:
    state: off
```

```toml
[[resources]]
id = "profile"
type = "tuned"

[resources.with]
state = "off"
```

Select a profile and check that it is applied:

```yaml
- id: profile
  type: tuned
  with:
    profile: throughput-performance
    verify: true
```

```toml
[[resources]]
id = "profile"
type = "tuned"

[resources.with]
profile = "throughput-performance"
verify = true
```

### The full order: package, service, custom profile, selection

Sinter does not install TuneD and does not start it. Declare both, and a
custom profile if you need one, before the `tuned` resource:

```yaml
version: 1
resources:
  - id: tuned-package
    type: package
    with:
      name: tuned
      state: present

  - id: tuned-service
    type: service
    depends_on: [tuned-package]
    with:
      name: tuned.service
      state: running
      enabled: true

  - id: site-db-dir
    type: directory
    depends_on: [tuned-package]
    with:
      path: /etc/tuned/profiles/site-db
      parents: true

  - id: site-db-conf
    type: file
    depends_on: [site-db-dir]
    with:
      path: /etc/tuned/profiles/site-db/tuned.conf
      content: |
        [main]
        include=throughput-performance

  - id: profile
    type: tuned
    depends_on: [tuned-service, site-db-conf]
    with:
      profile: site-db
```

```toml
version = 1

[[resources]]
id = "tuned-package"
type = "package"

[resources.with]
name = "tuned"
state = "present"

[[resources]]
id = "tuned-service"
type = "service"
depends_on = ["tuned-package"]

[resources.with]
name = "tuned.service"
state = "running"
enabled = true

[[resources]]
id = "site-db-dir"
type = "directory"
depends_on = ["tuned-package"]

[resources.with]
path = "/etc/tuned/profiles/site-db"
parents = true

[[resources]]
id = "site-db-conf"
type = "file"
depends_on = ["site-db-dir"]

[resources.with]
path = "/etc/tuned/profiles/site-db/tuned.conf"
content = "[main]\ninclude=throughput-performance\n"

[[resources]]
id = "profile"
type = "tuned"
depends_on = ["tuned-service", "site-db-conf"]

[resources.with]
profile = "site-db"
```

- Older TuneD releases keep custom profiles in `/etc/tuned/<name>/` instead
  of `/etc/tuned/profiles/<name>/`. Sinter looks in both; write the file
  where the TuneD of your release reads it.
- On a host where TuneD is not installed yet, plan does not fail for this
  recipe: the `tuned` resource is shown as unknown until apply, because the
  earlier package may bring the tool.
- **Bundles:** keep the same order across recipes. Put the recipe that
  installs the package and starts the service before the recipe that holds
  the `tuned` resource. Plan of the later recipe then defers in the same
  way.

## Expected behavior

- **Observation (read-only).**
  - TuneD is installed when `/usr/sbin/tuned-adm` is executable.
  - The selected profile is read from `/etc/tuned/active_profile`. A missing
    or empty file means "no profile selected". Exactly one line that is one
    profile name is that profile. Anything else is an error; Sinter does not
    guess. A symlink is not followed.
  - `tuned.service` is observed the same way the `service` resource observes
    a unit.
  - With `recommended: true`, Sinter runs `/usr/sbin/tuned-adm recommend`.
    Only an exit of zero with exactly one line that is one profile name is
    accepted.
- **Plan** compares the selection with the declaration. If they differ, it
  checks that the profile exists and that `tuned.service` is active, shows
  the current and the declared selection, and runs nothing else. Plan never
  runs `tuned-adm verify`.
- **A profile exists** when `<dir>/<name>/tuned.conf` is a regular file in
  `/etc/tuned/profiles`, `/etc/tuned`, `/usr/lib/tuned/profiles` or
  `/usr/lib/tuned`. If it does not, plan fails and names the profile and the
  four directories. If an earlier resource of the plan may still create it,
  plan adds a note instead and apply checks again.
- **Apply** runs `/usr/sbin/tuned-adm profile <name>` or
  `/usr/sbin/tuned-adm off` as root, with no shell. Right before the command
  the state file is read again; if the selection changed in the meantime,
  nothing is run. A non-zero exit is a failure. An exit of zero is not
  trusted on its own: the state file is read again and must hold the
  declared selection, otherwise the resource fails. If the tool is killed,
  times out or the connection is lost, the result says the selection may or
  may not have been changed; Sinter does not report success.
- **When the selection is already as declared, no command is run** — also
  when the service is stopped. In that case the result carries a note: the
  profile is selected but not applied while the service is stopped.
- **`verify: true`.** After a successful change, apply runs
  `/usr/sbin/tuned-adm verify`. Exit 0 means applied. Exit 1 means the
  system differs from the profile: the resource **fails and reports the
  change** (the selection changed, the tuning did not verify). Any other
  exit, a signal, a timeout or truncated output is a failure too, and
  Sinter says that it does not know whether the profile is applied.
  Verify is not run in plan and not for an unchanged selection: it is not
  measured whether `tuned-adm verify` is free of side effects, which is also
  why it is opt-in.
- **Audit** reports up to three dimensions:
  - `profile`: the selection differs from the declaration (with
    `recommended: true`, from the recommendation observed during the audit);
  - `service`: a profile is declared and `tuned.service` is not active (or
    the unit was not found), so the selected profile is not applied;
  - `applied` (only with `verify: true`, and only when the two above are
    fine): `tuned-adm verify` exited 1.

  A host without `tuned-adm`, an unreadable or malformed state file and a
  failed command are errors, never drift.

Every plan and apply result that selects a profile carries a note: a TuneD
profile sets kernel parameters and other tunables. A value that a
[`sysctl`](/en/reference/resources/sysctl/) resource or a file in
`/etc/sysctl.d` sets can be overridden by the profile, and the other way
round (TuneD's `reapply_sysctl` setting decides the order). Sinter does not
resolve that. Declare each setting in one place.

## When Sinter cannot change the selection

The four cases have different messages:

| Case | What Sinter says |
|------|------------------|
| TuneD is not installed (`tuned-adm` not found) | "tuned is not supported on this host (tuned-adm was not found); install it with a package resource" |
| `tuned-adm` is there, the unit `tuned.service` is not | "tuned-adm is installed but the unit tuned.service was not found …" |
| The unit exists and is not active | "TuneD is installed but its service is not running (tuned.service is inactive); start it with a service resource (Sinter does not start it)" |
| The profile does not exist | "the profile NAME is not defined on this host (no NAME/tuned.conf in …)" |

In plan, the first case is deferred to apply when an earlier resource (for
example the package) may bring the tool, the second and third become a note
when an earlier resource such as a `service` may start TuneD, and the fourth
becomes a note when an earlier resource may create the profile.

## What Sinter does not do

- It does not install the `tuned` package. Use
  [`package`](/en/reference/resources/package/).
- It does not start, restart, enable or stop `tuned.service`. Use
  [`service`](/en/reference/resources/service/).
- It does not write profiles. Use [`file`](/en/reference/resources/file/)
  or [`template`](/en/reference/resources/template/).
- It does not change anything unless `tuned.service` is observed active.
- It does not read or change `/etc/tuned/tuned-main.conf` or TuneD's
  automatic profile mode, and it does not resolve conflicts between a
  profile and `sysctl` settings.
- It does not select several profiles at once (TuneD's merged profiles).
  A host whose state file names several profiles is reported as an
  observation error.

## Privilege

Changing the selection needs root: connect as root or use `--sudo`. Plan
says so when the connection is not root. A run that has nothing to change
needs no root.

## Unsupported cases

- Hosts without `/usr/sbin/tuned-adm`: plan and apply fail with the message
  above; audit reports an error.
- Several profiles selected at once.
- Profile names outside `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`.
- Use over MCP: `tuned` is refused in MCP manifests.

## Supported OS

RHEL, Rocky Linux and AlmaLinux 9 and 10, and Ubuntu 24.04 and 26.04 when
the `tuned` package is installed. The type decides by the presence of
`tuned-adm`, not by the OS name.

## Limits

- When `plan` cannot decide because an earlier resource may start TuneD or
  write the profile, the result is reported as decided at apply (unknown).
- Sinter checks that `tuned.service` is active right before it runs
  `tuned-adm`. If the service stops in that short window, TuneD's own tool may
  try to start it; Sinter itself never starts it.
- The state file `/etc/tuned/active_profile` is refused if it has more than
  one hard link.
- One `tuned` per recipe. Two recipes of a bundle that select different
  profiles for the same host are not detected: each apply would switch it.

## Not verified on a real host

This resource is tested against Sinter's scripted target only. No host with
TuneD was available, so **none of the following is verified**:

- that TuneD writes the selected profile to `/etc/tuned/active_profile` as
  one line with one name, and leaves the file empty (or absent) after
  `tuned-adm off`;
- the path `/usr/sbin/tuned-adm` on every supported OS;
- the four profile directories and the file name `tuned.conf` in each
  TuneD release;
- the output of `tuned-adm recommend` (assumed: one line, the profile name
  only) and whether it works while the service is stopped;
- the exit codes of `tuned-adm verify` (assumed: 0 applied, 1 not applied)
  and whether it changes anything on the host or only writes to TuneD's log;
- the exit codes of `tuned-adm profile` and `tuned-adm off`, and how long
  they take (Sinter allows 300 seconds);
- that `tuned-adm profile` switches TuneD to its manual profile mode;
- the unit name `tuned.service` on Ubuntu.
