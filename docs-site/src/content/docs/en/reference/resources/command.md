---
title: command
description: Execute a program on the target with exact argv and a fixed environment.
---

**Purpose:** run a program on the target. Not inherently idempotent — use
`creates`/`removes` guards or `changed_when` to control change reporting.

## Synopsis

```yaml
- id: update_index
  type: command
  with:
    program: /usr/bin/touch
    args: ["/var/lib/myapp/indexed"]
    creates: /var/lib/myapp/indexed
```

## Parameters

| Parameter | Required | Type | Default | Description |
|-----------|----------|------|---------|-------------|
| `program` | yes | string (absolute path) | — | Executable path. |
| `args` | no | list of strings | `[]` | Exact argv — no shell evaluation, NUL rejected. |
| `cwd` | no | string (absolute path) | — | Working directory. |
| `env` | no | map of strings | `{}` | Extra env vars. `PATH`, `LANG`, `LC_ALL`, `HOME` are reserved. |
| `timeout_seconds` | no | integer 1..86400 | `300` | Execution timeout. |
| `success_codes` | no | list of integers 0..255 | `[0]` | Exit codes counted as success. |
| `creates` | no | string (absolute path) | — | Guard: skip when this path exists. Mutually exclusive with `removes`. |
| `removes` | no | string (absolute path) | — | Guard: skip when this path does **not** exist. |
| `changed_when` | no | string (expression) | — | Decides change from `result.<field>` after successful execution. |
| `register` | no | string (identifier) | — | Stores the structured result as `registers.<name>`. |

## Expected behavior

- The program runs directly with the given argv — there is no shell, so no
  quoting or expansion surprises.
- Environment: a fixed baseline (`PATH`, `LANG`, `LC_ALL`, `HOME`) plus your
  `env` map. Controller, SSH-session, sudo, and login-shell variables are not
  inherited.
- Exit code in `success_codes` → success; anything else → failure, classified
  conservatively as `possible` change unless Sinter can prove the command
  never began.
- `register` captures `result` fields (e.g. `exit_code`, stdout/stderr) for
  later `when`/`changed_when` expressions.

## Guards

- `creates`: if the path exists, the command is not executed; the result is
  success / no change / `guard_satisfied`, and `register` receives a
  not-executed result.
- `removes`: if the path does not exist, the same skip semantics apply.
- This differs from `when: false`, which blocks dependents.

## Failure behavior

- Timeout after dispatch, lost response, or signal uncertainty →
  **indeterminate**; never auto-retried.
- Non-success exit code → failed resource; remaining resources blocked
  (fail-fast).

## Platform notes

Applies to all supported targets. `program` must be an absolute path on the
target.

## Related

[Idempotency](/sinter/en/concepts/idempotency/) ·
[Recipes — expressions](/sinter/en/concepts/recipes/)
