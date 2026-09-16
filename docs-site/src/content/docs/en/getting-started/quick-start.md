---
title: Quick Start
description: Validate, plan, and apply a recipe against a target host.
---

This walkthrough installs the `tree` package on a managed host. The same
recipe works on Ubuntu (apt) and Rocky Linux (dnf) — Sinter picks the backend
from the detected platform.

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

Next: [First Recipe](/sinter/en/getting-started/first-recipe/) adds files,
services, and handlers.
