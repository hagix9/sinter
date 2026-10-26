---
title: package
description: Install or remove a package via the target's package backend.
---

**Purpose:** ensure a package is installed (`present`) or removed (`absent`)
using the target's native package backend — `apt` on Ubuntu, `dnf` on
RHEL-family targets.

## Synopsis

```yaml
- id: tree
  type: package
  with:
    name: tree
    state: present
```

An operation may provide environment variables explicitly. They are passed only
to this package operation (including its privileged apt/dnf execution); they do
not configure a persistent host-wide environment.

```yaml
- id: install-tools
  type: package
  with:
    name: curl
    state: present
    env:
      HTTP_PROXY: "http://proxy.example.com:3128"
      HTTPS_PROXY: "http://proxy.example.com:3128"
      NO_PROXY: "localhost,127.0.0.1,.example.internal"
```

## Parameters

| Parameter | Required | Type | Default | Description |
|-----------|----------|------|---------|-------------|
| `name` | yes | string | — | Package name (validated). |
| `state` | yes | string | — | `present` or `absent`. Required. |
| `env` | no | map of strings | empty | Environment variables for this package operation. |

## Expected behavior

- Backend is chosen automatically from the target's `/etc/os-release`
  identity — recipes stay platform-neutral.
- `present` on Ubuntu → `apt`; on RHEL-family targets (Rocky Linux, RHEL,
  AlmaLinux, Oracle Linux) → `dnf`.
- No version pinning.
- On dnf targets, installs run through a private cache snapshot — see
  [Execution Model](/en/concepts/execution-model/) and the
  [Rocky guide](/en/guides/rocky-linux/).
- On apt targets Sinter never runs `apt-get update`: the package lists must
  already be present. On a fresh image without them an install fails
  (`E: Unable to locate package`, reported as a possible change because apt's
  output is not trusted); refresh the lists first, for example with a
  `command` resource that runs `/usr/bin/apt-get update` (with
  `changed_when: "false"`) declared before the package.
- Broken package states (half-configured etc.) fail rather than auto-repair.

## Removal (`state: absent`) on apt and dnf targets

> **Not yet released.** This section describes the removal implemented after
> v1.7.0 (WP-PKG-CORE-REPAIR). v1.7.0 and earlier asked the package manager to
> remove the package (`apt-get remove`, `dnf remove`), which can remove reverse
> dependencies too.

Sinter removes **exactly the named, installed package** and nothing else.

| Backend | Removal | Dry run before it |
|---------|---------|-------------------|
| apt (Ubuntu) | `dpkg --remove NAME` | `dpkg --dry-run --remove NAME` |
| dnf (RHEL family) | `rpm -e NEVRA`, while holding dnf's own process lock | `rpm -e --test NEVRA` |

- The package manager's resolver is never asked for a removal set: no
  `apt-get remove`, no `dnf remove`, no autoremove, no purge, and never
  `--force-depends` / `--nodeps`.
- **If other installed packages depend on the package, nothing is removed**
  and the resource fails, naming the dependents (for a sensitive resource only
  their number). Remove or replace the dependents first, in the same recipe or
  another one.
- **Dependencies the package pulled in stay installed** (they become unneeded
  but are not removed). Declare them with their own `state: absent` resources
  if you want them gone.
- Sinter also refuses, before removing anything, when the package is
  essential or protected (dpkg), is protected by dnf (`dnf` itself,
  `/etc/dnf/protected.d`, `protected_packages` in `dnf.conf`), is the package
  that owns the running kernel's image, is installed more than once
  (another architecture or version; a leftover of another architecture that
  only keeps configuration files, or is not installed, does not count), is not
  in a clean installed state, or when
  the DNF configuration or the package database cannot be read or understood.
- After the removal Sinter reads the package database back: the package must
  be gone, **no other package may be gone**, and no new dependency or
  half-configured-package problem may have appeared compared with before.
  Otherwise the resource fails and says so; Sinter never repairs the host.
  The plan (what was checked) and the outcome (what was found) are reported
  separately.
- Only `DEBIAN_FRONTEND`, `DEBIAN_PRIORITY`, `NEEDRESTART_MODE` and
  `NEEDRESTART_SUSPEND` of `with.env` reach the removal commands; other names
  are dropped (the result says how many).

### What is recorded, and what is left behind

- A removal done this way is **not** recorded by the package manager's own
  history (`dnf history`, `/var/log/apt/history.log`), and apt/dnf hooks
  (needrestart, etckeeper, …) do not run. dpkg keeps configuration files, as
  `apt-get remove` does.
- **dpkg records the request to remove before it checks dependencies and runs
  the pre-removal script.** If dpkg then refuses or the script fails, the
  package stays installed but in the state `deinstall ok installed` (or
  `half-installed` after a failing post-removal script). Sinter does not read
  these states: the resource reports a possible change with an unknown
  verification, and later resources that observe the package fail until the
  state is repaired (for example `dpkg --set-selections` with `<name> install`,
  `dpkg --configure -a`). A normal reverse-dependency refusal does not leave this
  behind, because the dry run runs first and does not write to the database.

### Locking and what it does not cover

| Concurrent activity | apt targets | dnf targets |
|---------------------|-------------|-------------|
| `apt`, `dpkg`, unattended-upgrades | the removal fails at once (dpkg's locks); nothing is changed | – |
| `dnf`, `dnf-automatic`, `yum` | – | a running transaction makes the removal fail before `rpm` starts; one that starts meanwhile waits until `rpm` is done (Sinter holds dnf's process lock) |
| another `rpm` transaction | – | `rpm` fails at once instead of waiting (no terminal) |
| PackageKit, `microdnf`, a hand-run `rpm -U` | – | **not excluded** |

dpkg checks dependencies while holding its lock. rpm checks them just before it
takes its transaction lock, so a dependent installed by a process that does not
use dnf's lock, in that instant, can be missed. Sinter's check afterwards
reports a broken dependency as a failure **if the other process has committed
by the time Sinter reads the database**; if its commit comes later the removal is
reported as successful. Sinter cannot undo such a removal.

If dnf's `persistdir` is not the default (in `dnf.conf` or `automatic.conf`),
the removal is refused, because dnf's lock is somewhere else.

Other cases that refuse or fail instead of removing:

- `dnf` is not installed, or `/var/lib/dnf` does not exist, on a dnf target (the
  lock wrapper cannot run): the removal is refused with no change.
- A `dpkg.cfg` line `ignore-depends=NAME` cannot be cancelled from the command
  line: dpkg then removes the package although a dependent needs it, and only
  the check afterwards (`apt-get -s check`) reports the broken dependency.
- A maintainer script of the removed package that itself runs `dnf` or `yum`
  waits for the lock Sinter holds while `rpm` runs; after 300 seconds Sinter
  kills the whole command, which can leave a half-finished rpm transaction.
- If the Sinter process itself is killed (SIGTERM or SIGKILL) while the removal
  runs, the `dpkg` / `rpm` command is not stopped: it runs to the end and the
  package database stays consistent, but nobody reports the result. Run the
  audit afterwards. (Tested with packages whose scripts do not write to the
  closed connection; a script that keeps writing to it was not tested.)
- If another process removed the package first, the resource reports no change
  and fails ("the package was already gone"), on both apt and dnf targets.
  On apt this is recognised from dpkg's own "ignoring request to remove NAME"
  warnings (the plain "which isn't installed" one and the "only the config files
  ... are on the system" one, with the name optionally followed by `:arch`) when
  they name this package and dpkg did not print a "Removing" line; the
  post-removal checks run in every case.
- On apt, "nothing was changed" after a failed `dpkg --remove` is only reported
  when dpkg printed no "Removing" line and its own refusal is on stderr as a
  whole line (a dependency problem for this package, a lock held by another
  process, missing privilege, an ambiguous name, an essential package). Words a
  maintainer script prints do not count. If dpkg had started, or the output does
  not show how far it got, the result is a (possible) change, never "no change";
  if the package is gone but nothing shows who removed it, it is reported as a
  possible change. The post-removal checks run in every case.
- On apt, a package that has another architecture's instance left with only its
  configuration files (or not installed) is handled like a package without it:
  its state is read per architecture. Two installed architectures, or an
  instance in any other state, are still refused.

### Time

On dnf targets Sinter lists the installed packages and verifies their
dependencies before and after the removal (`rpm -qa`, `rpm -Va --nofiles`).
This is CPU-bound and grows with the number of installed packages and the speed
of the host: about 7 s per removal on a lightly loaded 2-vCPU Rocky Linux 9 VM
with 412 packages, and 1–2 minutes on a small Rocky Linux 10 VM with 450
packages (rpm 4.19 is much slower here). apt targets take about 5 s. The time grows with the
number of installed packages; each of the two dependency verifications is limited to
300 seconds (before the removal this refuses it, after it the result is
`verification: unknown`).

### Verified on real hosts

Ubuntu 24.04, Rocky Linux 9.8 and Rocky Linux 10.2 were exercised on real
hosts with throw-away packages (removal, dependency refusal, lock contention,
script failure, cancellation). Ubuntu 26.04, RHEL 9/10 and AlmaLinux 9/10 use
the same tools and are expected to behave the same, but removal has **not**
been verified on them; neither has Rocky Linux 8 or Oracle Linux. Fedora is
not a supported target.

## Idempotency

Fully idempotent — already-installed `present` and already-absent `absent`
produce no mutation and no package transaction. A removal that was refused leaves
the host as it was (see the dpkg note above for the one exception).

## Failure behavior

- Unsupported platform / missing backend → capability error.
- Unresolvable package, repository errors, or ambiguous observation → failure
  or indeterminate, never a false change report.
- Observation failure before mutation is never reported as a change.
- A removal that cannot be proven safe — dependents, protected package, unreadable
  configuration, a lock held by another process — fails with `change: none` and
  `nothing was changed` in the reason. A removal that removed another package, or
  left a new broken dependency, is reported as failed with `verification: failed`.

## Metadata snapshot (dnf)

On RHEL-family targets an install runs cache-only against a private snapshot of
the target's dnf metadata. The snapshot must be complete for every enabled
repository. If an enabled repository has no cached metadata — a fresh image, or
a repository added since the last refresh — Sinter refreshes the target's own
dnf metadata cache once, exactly as `dnf makecache` does, then rebuilds and
re-verifies the snapshot; no manual preparation is needed. Only absent metadata
is fetched (`metadata_expire=-1`), so a warm host does no extra network
traffic, and only repository metadata is fetched — no package payload is
downloaded by that step. If the metadata cannot be established the resource
fails closed before any package mutation. The snapshot no longer treats packages
already downloaded in the live cache as the transaction payloads, and it never
removes or copies the live cache. The
package identity query (`rpm -qp`) ignores an untrusted-signature warning;
whether a signature is trusted is still decided by dnf and the payload digest.

## Package names and provides (dnf)

Declare a package by its **own name**. dnf also accepts a name that some other
package only *provides* (on RHEL-family 8, `python3` is provided by
`python36`, and `python311` by `python3.11`), but Sinter verifies the result by
that exact name, so it could never confirm such an install. Before installing
anything, Sinter checks that the dry-run transaction installs the requested
name itself. When dnf resolved it to another package — or reports nothing to do
because an installed package already provides it — the resource fails with
**no change** and names the real package:

```text
python3 is not a package name: dnf resolves it through a provides match to
package python36; nothing was changed. Declare the package by its own name
(name: python36) so the result can be verified
```

`plan` does not run dnf's resolver, so it reports such a name as an install;
`apply` then refuses it without changing the host.

## Why dnf refused (dnf)

When dnf refuses an install, the reason names the cause dnf reported,
measured on dnf 4.7 (EL8), 4.14 (EL9) and 4.20 (EL10). Nothing is installed in
any of these cases:

| Cause | Reason starts with |
|-------|--------------------|
| No package of that name (or providing it) in the enabled repositories | `dnf found no package named …` |
| The name is only a provides match | `… is not a package name: dnf resolves it …` / `no package named … is installed, but dnf reports …` |
| A dependency is missing (often a repository such as CRB/PowerTools is not enabled) | `dnf cannot resolve the dependencies of …: nothing provides <capability>` |
| A package is unsigned or signed by a key its repository does not trust | `dnf refused a package signature … (GPG check FAILED …)` |
| An enabled repository cannot be reached | `dnf could not download the metadata of repository <id> …` |
| The package download failed for another reason | `dnf could not download the packages required for …` |
| Repository metadata is not usable from the local cache after the bounded refresh | `dnf repository metadata not locally complete (…)` |

Only fixed text and validated tokens (package names, repository ids,
capabilities) are shown — never dnf's raw output, which can contain repository
URLs. Output Sinter does not recognize is reported by size only
(`… bytes of unrecognized dnf error output withheld`) and still fails closed.
For a sensitive resource every name is redacted.

## Platform notes

| Platform | Backend |
|----------|---------|
| Ubuntu 24.04 / 26.04 LTS | apt |
| Rocky Linux 8 (SSH target only) | dnf |
| Rocky Linux 9 / 10 | dnf |
| RHEL 9 / 10 | dnf |
| AlmaLinux 9 / 10 | dnf |
| Oracle Linux | dnf (expected compatible — not acceptance-tested) |

## Related

[service](/en/reference/resources/service/) ·
[Execution Model](/en/concepts/execution-model/)
