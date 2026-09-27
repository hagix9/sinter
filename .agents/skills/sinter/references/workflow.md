# Commands, JSON output, and exit codes

Source of truth: Sinter v1.0.0 `sinter --help` and subcommand help,
`docs-site/src/content/docs/en/reference/cli.md`, and `tests/json_contract.rs`.

## Commands

```sh
sinter --version                         # e.g. "sinter 1.0.0"
sinter validate recipe.yaml [--format json]
sinter plan  recipe.yaml [target options] [--format json]
sinter apply recipe.yaml [target options] [--format json]
sinter audit recipe.yaml [target options] [--format json]
sinter mcp [--targets-file targets.toml]  # read-only MCP server on stdio
```

Target options for plan, apply, and audit:

| Flag | Default | Meaning |
|---|---|---|
| `--host <HOST>` | local machine | SSH target. Omitted: the machine running `sinter`. |
| `--port <PORT>` | `22` | SSH port. |
| `--user <USER>` | current user | SSH user. |
| `--known-hosts <PATH>` | `~/.ssh/known_hosts` | Strict host-key database; unknown or changed keys fail. |
| `--identity <PATH>` | — | Extra identity file; repeatable. |
| `--sudo` | off | Every target-side operation via non-interactive `sudo -n`. |
| `--verbose` | off | Verbose output. |

Relative `include:` and `source:` paths resolve against the directory of the
recipe file that contains them.

## What each command does

- **validate**: parses and checks the recipe. Never contacts a target.
- **plan**: connects, observes current state, prints a non-authoritative
  preview. Never mutates, never runs `command` resources or handlers.
- **apply**: re-observes each resource immediately before deciding, mutates,
  verifies, then runs notified handlers. A previous plan is never reused as
  current state, so apply can differ from the plan if the target changed.
- **audit**: read-only compliance check against the recipe. Uses the same
  observation paths as plan; never mutates, never runs `command` resources
  or handlers.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Completed. Plan differences still exit 0. Audit: no drift and no errors. |
| 2 | Validation or schema error. |
| 3 | Connection, capability, or security error (e.g. unknown host key). |
| 4 | Plan could not be completed safely. |
| 5 | Apply failed. |
| 6 | Indeterminate: an apply outcome is unknown, or an audit had `ERROR` results. |
| 7 | Audit found drift and no observation errors. |

The exit code is authoritative. Error text on stderr is not a stable
interface.

## JSON output (stable in 1.x)

`--format json` works on validate, plan, apply, and audit. stdout then holds
exactly one JSON object and a newline. A document is written only when the
command produced a report; when it fails earlier (for example exit 2 or 3),
stdout is empty and one `sinter: ...` line goes to stderr.

- validate: `{"command":"validate","status":"ok","resources","handlers","vars"}`.
- plan / apply: `mode`, `status` (`success` 0, `plan_error` 4,
  `apply_failed` 5, `indeterminate` 6), `facts`, `resources`, `handlers`,
  `handlers_pending`.
- audit: `mode`, `status` (`no_drift` 0, `drift` 7, `indeterminate` 6),
  `summary`, `resources`.

Field meanings are in [results.md](results.md). Value sets are closed, and
unknown extra fields must be ignored.

## Control flow

1. Validate after every recipe edit. Stop on exit 2 and fix the recipe.
2. For a requested mutation, establish the exact user-identified target;
   never infer it from an environment/role label or default to local. Plan
   against that target (same `--host`, `--user`, `--port`, `--sudo`,
   `--known-hosts`, and `--identity`) that a later apply would use. Stop on
   exit 3 or 4. A plan must actually run and its result must be observed;
   claims, expectations, examples, and hypothetical results are not evidence.
3. Present actual plan output and relevant effects, including destructive
   resources and command details/uncertainty, then obtain the user's
   confirmation. A command's `changed_when` does not guard execution. If any
   gate is missing, do not construct or invoke apply; see [safety.md](safety.md).
4. Apply only with the same options after all mutation gates pass. Exit 5:
   report the failure; fix and plan
   again. Exit 6: state unknown; audit or plan before anything else.
5. Audit the same target. Exit 7 or 6 after an apply needs investigation, not
   an automatic re-apply.

## Evidence

Keep, for each step you ran: the exact command line or tool call, the exit
code, and the output (prefer `--format json`). Summaries must point back to
that evidence. Never fabricate output, and never present an expected result
as an observed one.
