# Reading results

Source of truth: Sinter v1.0.0 `docs-site/src/content/docs/en/reference/cli.md`
(Reading plan / apply output, Reading audit output, JSON output contract).

## Plan and apply

Output starts with `== Sinter PLAN ==` or `== Sinter APPLY ==` and a
`target facts:` line (hostname, OS, family, version, architecture).

| Text status | Meaning |
|---|---|
| `ok` | Already in the desired state; nothing mutated. |
| `CHANGED` | Mutated, or in a plan, would be mutated. Not an error. |
| `POSSIBLE` | A change may have happened but could not be confirmed. |
| `FAILED` | Failed; later resources are blocked (fail-fast). |
| `INDET` | Mutation outcome unknown (e.g. timeout after dispatch). Never retried automatically. |
| `skip` | The resource's `when` was false. |
| `guard` | A `creates`/`removes` guard was already satisfied; command not run. |
| `blocked` | Not run because of an earlier failure, indeterminate result, or unmet dependency. |
| `?` | Unknown, e.g. a `command` resource in a plan. |

`known/` or `unknown/` before the disposition shows whether current state was
fully observed. Handlers that ran appear under `handlers:`; queued but not run
under `pending handlers` (a plan lists every notified handler as pending).

JSON resource fields: `execution` (`not_run`, `succeeded`, `failed`,
`indeterminate`), `change` (`none`, `changed`, `possible`), `verification`
(`not_applicable`, `not_performed`, `verified`, `failed`, `unknown`),
`disposition` (`normal`, `skipped_by_condition`, `guard_satisfied`,
`blocked_by_dependency`, `blocked_by_fail_fast`), plus `id`, `loop_index`,
`unknown`, `sensitive`, `reason`, `diff`, `notes`. Identify a resource by
`id` together with `loop_index`.

A plan is a preview from the moment it ran. Apply observes again before each
decision, so do not promise that apply will match the plan exactly.

## Audit

Output starts with `== Sinter AUDIT ==`; resources are listed in dependency
order.

| Text | JSON | Meaning |
|---|---|---|
| `PASS` | `compliant` | Observed state satisfies the recipe. |
| `DRIFT` | `drift` | Observation shows the recipe is not satisfied. |
| `NOT_AUDITABLE` | `not_auditable` | Cannot be verified without acting; every `command` resource, never executed. |
| `NOT_APPLICABLE` | `not_applicable` | The resource's `when` was false. |
| `ERROR` | `error` | A required observation failed. Never counted as drift. |

The run ends with `summary:` (total, compliant, drifted, not_auditable,
not_applicable, errors) and `status:` (`no_drift` exit 0, `drift` exit 7,
`indeterminate` exit 6; errors dominate drift). Exit 0 does not mean every
resource was verified: always mention `NOT_AUDITABLE` resources. Content
drift details are redacted by design.

## Unknown, possible, and indeterminate are different

- **Plan-side unknown** (text `unknown/` or `?`, JSON `unknown: true`): the
  resource's current state was not fully observed, so the preview is
  incomplete for it. A plan never executes `command` resources, so they
  appear this way (`execution: not_run`), as does a resource whose `when`
  condition evaluates to unknown in a plan. A plan mutates nothing, so this
  is neither an apply failure nor an uncertain mutation. It is also not a
  clean result: the effect of that resource is only known after apply, so
  name it when presenting the plan.
- **Possible change** (JSON `change: possible`; text `POSSIBLE` when the
  execution itself succeeded): a change may have happened but could not be
  confirmed. It also accompanies failures: a command that ran and exited with
  a code outside `success_codes` shows `FAILED` in text and
  `change: possible` in JSON. Check the target's state before applying
  again.
- **Apply-side indeterminate** (text `INDET`, JSON `execution:
  indeterminate`, apply `status: indeterminate`, exit 6): Sinter attempted a
  mutation and cannot establish whether it took effect (for example a
  timeout after dispatch, a lost response, or signal uncertainty). Sinter
  never retries it automatically. Report it as unknown, never as success or
  failure. Next step: audit or plan the same target to observe the actual
  state, then decide with the user. Do not re-run apply just to "clear" it.

Audit exit 6 is a different case: it means some observations failed
(`ERROR` results), not that a mutation is in doubt.

## Evidence versus inference

In every report, separate:

- **Observed**: what a command or tool actually returned (quote the status,
  exit code, and relevant lines or JSON fields).
- **Inferred or proposed**: your interpretation, likely causes, and next
  steps, labeled as such.

If nothing was run, say so plainly (for example: "Not validated: no Sinter
CLI or MCP was available; this is a manual review.").
