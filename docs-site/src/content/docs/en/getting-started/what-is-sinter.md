---
title: What is Sinter?
description: Product overview — agentless configuration management for Linux, built in Rust.
---

Sinter is a lightweight, agentless configuration-management tool, inspired by
Itamae. It describes and applies operating-system configuration from a single
Rust binary. Managed hosts require no Sinter agent and no Ruby or Python
runtime — only an SSH server, `/bin/sh`, systemd, and passwordless `sudo -n`
where privilege escalation is needed.

## Design goals

- **Small enough to understand.** A deliberately narrow scope: no inventory,
  roles, plugins, orchestration, or embedded scripting.
- **Strong enough to trust.** Observation-only plans, re-observation before
  every mutation, strict SSH host-key checking, fail-closed parsing, and
  truthful result reporting.
- **Idempotent.** Re-applying a recipe that already matches performs zero
  mutations.

## What a run looks like

```sh
sinter validate recipe.yaml                          # schema check, no target contact
sinter plan --host web01.example.com recipe.yaml     # observe only
sinter apply --host web01.example.com --sudo recipe.yaml
```

`plan` produces a non-authoritative preview. `apply` re-observes every
stateful resource immediately before deciding whether to mutate it — a
previous plan is never reused as current state.

## Supported managed targets

| Platform | Architecture | Package backend |
|----------|--------------|-----------------|
| Ubuntu 24.04 LTS | amd64 | apt |
| Rocky Linux 9 | x86_64 | dnf |

See [Compatibility](/sinter/en/compatibility/platforms/) for requirements and the
acceptance reference.

## What Sinter is not

Sinter does not aim to replace general-purpose orchestration systems. It has
no inventory, no agent daemon, no templating programming language, and no
cluster-wide coordination. It is a small tool for describing and applying
configuration on individual Linux hosts.
