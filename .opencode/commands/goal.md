---
description: Work autonomously until the project goal is completed
agent: build
---

$ARGUMENTS

Treat this as the authoritative project goal.

Work autonomously toward completion.

Read all relevant project documentation and existing code before making changes.

Implement, test, inspect failures, fix them, and repeat until the requested goal and the project's acceptance criteria are satisfied.

Do not stop after producing a plan.
Do not stop merely because one implementation step succeeded.
Continue through implementation, testing, correction, and re-testing.

Do not fake completion with stubs, hardcoded outputs, weakened tests, skipped tests, or behavior that only appears compliant.

If the repository contains authoritative specification documents, follow them over implementation convenience.

Stop only if:
- the goal is completed and verified, or
- a genuine specification contradiction or external blocker prevents safe progress.

When finished, summarize:
- what was implemented
- tests executed
- remaining limitations, if any
