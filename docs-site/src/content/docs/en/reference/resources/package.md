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
- Broken package states (half-configured etc.) fail rather than auto-repair.

## Idempotency

Fully idempotent — already-installed `present` and already-absent `absent`
produce no mutation and no package transaction.

## Failure behavior

- Unsupported platform / missing backend → capability error.
- Unresolvable package, repository errors, or ambiguous observation → failure
  or indeterminate, never a false change report.
- Observation failure before mutation is never reported as a change.

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
