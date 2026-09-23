---
title: Quick Start
description: Validate, plan, apply, and audit a recipe against a target host.
---

This walkthrough installs the `tree` package on a managed host. The same
recipe works on Ubuntu (apt) and RHEL-family targets such as Rocky Linux,
RHEL, and AlmaLinux (dnf) — Sinter picks the backend from the detected
platform.

## 1. Write a recipe

```yaml title="recipe.yaml"
version: 1

resources:
  - id: tree
    type: package
    with:
      name: tree
      state: present
```

## 2. Validate

```sh
sinter validate recipe.yaml
# ok: 1 resource(s), 0 handler(s), 0 var(s)
```

`validate` checks structure and semantics without connecting to anything.

## 3. Plan

```sh
sinter plan --host web01.example.com recipe.yaml
```

`plan` performs observation only. If `tree` is missing, the plan reports the
package as a pending change — but installs nothing.

## 4. Apply

```sh
sinter apply --host web01.example.com --sudo recipe.yaml
```

`apply` re-observes the package state, installs `tree` if absent, then
verifies the result.

## 5. Apply again

```sh
sinter apply --host web01.example.com --sudo recipe.yaml
```

The second run performs zero mutations — the desired state is already
satisfied.

## 6. Audit

```sh
sinter audit --host web01.example.com --sudo recipe.yaml
```

`audit` is read-only like `plan`, but answers a different question: does the
target already match the recipe? After a successful apply it reports `PASS`
for auditable resources that now conform and exits `0`; drift exits `7` and
observation errors exit `6`. `command` resources always report
`NOT_AUDITABLE` — audit never executes them — and `when`-skipped resources
report `NOT_APPLICABLE`, so an exit-0 audit can still contain unverified
resources. Check the `summary:` line for the full picture.

## SSH options

```sh
sinter plan \
  --host web01.example.com \
  --port 2222 \
  --user ops \
  --identity ~/.ssh/ops_key \
  --known-hosts ~/.ssh/known_hosts \
  recipe.yaml
```

| Flag | Meaning |
|------|---------|
| `--host` | SSH target. Omit for localhost. |
| `--port` | SSH port (default 22). Non-default ports need a `[host]:port` `known_hosts` entry. |
| `--user` | SSH user (default: `$USER`). |
| `--identity` | Identity file; may be repeated. |
| `--known-hosts` | `known_hosts` file (default `~/.ssh/known_hosts`). |
| `--sudo` | Run all target-side operations via `sudo -n`. |
| `--format` | `text` (default) or `json`. |
| `--verbose` | Verbose output. |

Next: [First Recipe](/en/getting-started/first-recipe/) adds files,
directories, links, and services.
