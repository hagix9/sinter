---
title: Idempotency
description: Repeat applies perform zero mutations once desired state is reached.
---

Sinter resources are idempotent: when the target already matches the desired
state, `apply` performs no mutation for that resource.

## What this means in practice

```sh
sinter apply --host web01 --sudo recipe.yaml   # changes applied
sinter apply --host web01 --sudo recipe.yaml   # ok — zero mutations
```

- A `package` resource does not reinstall an installed package or re-remove an
  absent one.
- A `file` resource that already has the desired content, mode, and ownership
  is not rewritten.
- A `service` already `running` and `enabled` is left untouched.
- Handlers run only when something changed — an idempotent second apply
  triggers none.

## Re-observation, not replanning

`apply` does not trust an earlier `plan`. Every stateful resource is observed
again immediately before the mutation decision, so drift between plan and
apply is handled correctly.

## Command resources and guards

`command` is not inherently idempotent — it runs when reached. Use `creates`
or `removes` guards to make it idempotent:

```yaml
- id: update_index
  type: command
  with:
    program: /usr/bin/touch
    args: ["/var/lib/myapp/indexed"]
    creates: /var/lib/myapp/indexed
```

When `/var/lib/myapp/indexed` exists, the command is not executed; the
resource reports success with no change and dependencies stay satisfied.

## Truthful reporting

A resource that mutated successfully but failed a later step still reports
that it changed. Verification failures are never flattened into "success".
