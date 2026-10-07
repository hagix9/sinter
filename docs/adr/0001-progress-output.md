# ADR 0001: Progress output for plan, apply and audit

- Status: Accepted (implemented on `main` after v1.2.0, unreleased)
- Date: 2026-10-07
- Scope: the CLI commands `plan`, `apply` and `audit`
- User-facing description:
  [CLI reference, "Progress output"](../../docs-site/src/content/docs/en/reference/cli.md)
  (Japanese: `docs-site/src/content/docs/ja/reference/cli.md`)

This record keeps the decisions, their reasons and the known residuals. It is not
a copy of the work-package audit reports; it states what the code does now and why.

## 1. Motivation

A long `plan`, `apply` or `audit` is silent until it prints its report. A user on a
terminal cannot tell whether Sinter is working, waiting for a slow connection, or
stuck on one item, and a CI log shows nothing for minutes. The goal is a small,
honest signal of where a run is, without changing any existing output contract.

Constraints that shaped every decision below:

- stdout, the report, the JSON documents and exit codes must be byte-identical
  with and without the feature.
- Output of non-interactive runs must not change unless the user asks.
- Progress is an observer. It must not be able to slow, block, abort or alter a
  run, and it must add no target command.
- It must not carry data that could be sensitive.

## 2. Decision

Two renderers consume one internal event stream:

- **Transient mode** (`progress_tty`): one line on stderr, overwritten in place,
  erased at the end of the run. Automatic on an eligible terminal.
- **Plain mode** (`progress_plain`): bounded, persistent ASCII lines on stderr,
  prefix `progress: `. Opt-in only, through `SINTER_PROGRESS=plain`.

The engine and the CLI layer emit closed events (`RunStarted`, `StageStarted`,
`Progress`, `StageEnded`, `RunEnded`) into a channel; one worker thread per
execution owns the renderer. The engine never reads anything back.

### 2.1 Mode selection

`decide_mode` is the only place the mode is decided, from facts known at the
command line:

| Input | Result |
|---|---|
| `--format json` | Disabled (always) |
| `SINTER_PROGRESS=plain` (exact value) | Plain |
| stderr not a terminal, or `TERM=dumb` | Disabled |
| otherwise | Tty (transient) |

A second, per-execution decision follows once the recipe model exists: a recipe
whose resources reference an encrypted secret gets the null consumer, for both
renderers, before any renderer or descriptor is created. So the effective
precedence, strongest first, is: JSON and secret references (no progress) over an
explicit `plain` request over the automatic terminal rule.

### 2.2 `SINTER_PROGRESS`

The opt-in is one environment variable and one value. The owner decided against a
`--progress` flag, a configuration setting, an alias or a hidden alternative, so
the CLI surface and help text did not grow. Parsing is exact string equality with
`plain`; unrecognised values (`PLAIN`, `1`, `off`, empty, trailing space,
non-UTF-8) are ignored silently and fall back to automatic selection. They are not
errors, warnings, plain or off: adding values would create surface that was not
asked for, and ignoring cannot panic or turn progress on by accident. A
consequence worth stating to users is that no value turns the transient line off;
`TERM=dumb` or redirected stderr does.

### 2.3 Explicit `plain` wins over the terminal rule (owner decision)

An explicit request is stronger than automatic selection. With
`SINTER_PROGRESS=plain` and an eligible terminal, plain lines replace the transient
line (the two are never combined), and `TERM=dumb` is irrelevant: plain lines need
no terminal capability. On a non-terminal stderr plain lines are written as well.
JSON and secret references still win. The alternative (keep the transient line on
terminals and apply plain only elsewhere) would make plain unreachable on a
terminal and was rejected. No existing default changes, because the behaviour is
reachable only through a new variable.

### 2.4 JSON

`--format json` never produces progress on any stream, whatever the terminal and
whatever `SINTER_PROGRESS` says. Stdout is the document; stderr keeps only its
existing error diagnostics. A progress line on stderr could not corrupt stdout, but
callers that merge streams through a pseudo-terminal (`docker run -t 2>&1`, `ssh
-t`, `script`) would see progress inside a JSON capture, and the one-stderr-line
failure contract would be weakened. A separate structured progress stream would be
new contract surface without demonstrated demand.

### 2.5 Secrets

If any resource of a recipe references an encrypted secret
(`content: { secret: ... }`, `password_hash: { secret: ... }`), no progress is
produced, not even with `SINTER_PROGRESS=plain`. Reason: such a run can write a
passphrase prompt to the terminal and secret-related notes to stderr in the middle
of the run, and nothing coordinates those writes with a renderer. The factory
returns before the stderr surface exists, so there is no renderer, no descriptor
and no byte. The research had suggested plain lines could stay on, because
persistent lines do not corrupt a prompt the way a transient line does; one rule
for both renderers was chosen instead, and relaxing it for plain is a separate
decision. For a bundle, the rule applies per execution, and the resolution scope
of the invocation is silent if any recipe in the bundle references secrets.

### 2.6 Streams

Progress is written to stderr only, never stdout, never with the `sinter:` prefix
(the red token that means an error), and never with colour. Only `plan`, `apply`
and `audit` build a session; `validate`, `secrets` and `mcp` do not.

## 3. What an event can carry

An event consists of closed enums, `u32` counters and at most one string: the
`kind` and `id` of an `ItemRef` (a resource or handler id from the recipe, which is
a static literal). There is no field for a target, host, address, user, port, key
path, command line, output, file content, diff, secret reference, error text or
reason. This is the data boundary, enforced by types, and a renderer receives only
`&ProgressEvent`. A closed-vocabulary canary test drives a real engine stream
through both renderers and asserts that every word is from the vocabulary, a
declared id, or numeric. The only dynamic text is the item id, reduced to printable
ASCII at render time (any other character becomes `?`, one per character, so a
newline cannot start a second line) and cut to 64 characters with `...` in plain
mode. The event itself is not modified, so a renderer can never become the secrecy
mechanism.

## 4. Plain mode in detail

### 4.1 Grammar

```text
progress: run: apply started
progress: connect: start
progress: connect: done (1s)
progress: apply: start 0/42
progress: apply: 5/42 (7s)
progress: apply: 5/42 on package:nginx, 30s since last progress
progress: apply: failed 6/42 (12s)
progress: run: apply completed (3m43s)
```

Stage labels are `resolve`, `connect`, `backup`, the command name for the resource
traversal, and `handlers`. `N/M` counts items that reached a terminal disposition
out of the items that exist; it is not a percentage, there is no ETA, and a stage
without an honest total (`connect`) has no counter. Outcome words are closed
(`done`/`failed`/`indeterminate`, `completed`/`failed`/`indeterminate`); the
renderer prints no failure text. `(T)` on a milestone or stage end is time since
the stage started; on the `run` end line, since the run started; both come from the
renderer's own monotonic clock, in whole seconds (a sub-second stage shows `0s`).

`run:` lines delimit one execution (or the resolution phase of a multi-execution
invocation). They are what tells sequential scopes of an inventory run apart.

### 4.2 Boundedness

Per stage and execution: a start line and an end line, and at most ten count
milestones (a line when `done` first reaches `ceil(k * total / 10)` for some
k = 1..10; one line even if a single step crosses several thresholds); plus two
`run:` lines per execution. Non-heartbeat output therefore does not depend on the
number of resources; this is asserted by a test with 10 000 resources and a
simulated 24 h wait.

### 4.3 Heartbeat

- **Trigger.** A heartbeat is written when nothing at all has been written for the
  current interval, measured from the last written line of any kind.
- **Schedule.** The interval is 30 s, doubles after every heartbeat (60, 120, 240)
  and is capped at 300 s.
- **Reset rule.** Writing a start, milestone or end line puts the interval back to
  30 s. An item event that does not write a line (a new item that crosses no
  milestone) does **not** reset it. With a per-item reset, steady progress between
  two milestones would print a heartbeat every 30 s and the line count would again
  depend on the run.
- **Message.** `T since last progress` is the time since the stage's last event
  (its start, or an item start; `Progress` is emitted when an item starts). It is
  not measured from the last line and not from the run start. Trigger and message
  therefore measure different things, and during healthy progress a heartbeat can
  report a small `T` (for example `5s`). It is truthful, never claims a stall, and
  reads like a stall notice; whether a heartbeat with a small `T` should be
  suppressed was left open (carried, see section 8).
- **No liveness claim.** The text states elapsed time only. It never says the
  engine or target is alive or hung.

### 4.4 Why a 300 s cap, and what the bound is

The research asked for backoff, a 300 s cap and a bound of "at most 12 + O(log t)
lines per stage" at once. A cap and a logarithmic bound cannot both hold: after
about 450 s of unbroken stall the schedule is one line per 300 s, which is linear in
time. The cap was kept because the property behind it is the one that matters: while
a stage is active, silence never exceeds 300 s, which is intended to stay under the
idle-output limits of CI systems (those limits are not verified here). The cost is
that a very long stall (up to the 24 h command timeout) adds about 290 lines, growing
with waiting time and never with the number of resources. The accurate statement of
the bound, and the one to use, is: at most 12 non-heartbeat lines per stage, plus one
line per heartbeat interval during a stall, with silence never longer than 300 s.

300 s also matches the engine's own scale: the default target-command deadline is
300 s and the SSH setup budget is 60 s, so a longer silence means the current item
is outside the normal bounds.

### 4.5 Panic and interrupt: the stream may not end

If a run is interrupted (Ctrl-C, SIGTERM; no signal handler is installed for these
commands) or panics, the plain stream ends without `run: ... completed` or `failed`.
The renderer does not synthesise an outcome it cannot know; a made-up success or
failure line would be a false claim. A log with no closing line means the run did
not finish normally, and the exit status remains the authority. This is separate
from the panic-mute fix below: that fix concerns late output after a panic, not a
missing final line.

## 5. Transient mode in detail

- Display: `label [done/total] [kind:id] [elapsed]`, ASCII, one line, no spinner, no
  percentage, no ETA, no colour. `NO_COLOR` is irrelevant: it affects colour, not
  whether a line may exist.
- Control sequences: the only one written is `CR ESC [ 2 K` (return to column 0 and
  erase the line). No newline, no cursor hiding or vertical movement, no alternate
  screen, no termios change: none of that could be restored after an unhandled
  interrupt. After Ctrl-C one stale transient line may remain.
- Elapsed is the time since the last progress event of any kind, shown after 3 s of
  quiet, whole seconds. It restarts with every event and is not the run's total
  elapsed time; a user-facing description must not call it that.
- Redraws are coalesced to one per 100 ms and an unchanged line is not rewritten.
  Consequence (accepted residual): a change arriving within 100 ms of the last write
  is held, and a run that ends first never shows it, so a failure inside that window
  never displays its outcome word on the transient line. The persistent `sinter:`
  line, the report and the exit code still carry the failure, so no information is
  lost.
- Width: the line is bounded to the terminal width on stderr
  (`ioctl(TIOCGWINSZ)`, asked at every draw) minus one column, so the cursor never
  reaches the wrap position. A failing `ioctl`, or a reported width of 0, means
  unknown and uses a fallback of 60 columns. The `COLUMNS` environment variable is
  deliberately not consulted: one input fewer, and a small fallback is the
  conservative choice. When the line does not fit, the item is shortened first, then
  dropped, then the elapsed text, then the label and counter are cut. A terminal of
  width 1 has no room and nothing is drawn.
- Order at the end: the renderer is torn down (erased) before the run prints its
  report or error, so persistent output is unchanged and starts at column 0.

## 6. Isolation and teardown

### 6.1 Private descriptor, no stderr lock, not non-blocking

The renderer writes through its own descriptor, a `dup` of stderr (created with
`FD_CLOEXEC`, so `ssh` and local commands do not inherit it), owned by the surface
and used by one worker. It never goes through `std::io::stderr()`.

- **No shared stderr lock.** `Stderr` is one process-wide lock. A progress write
  that blocked while holding it (a terminal that is not being read) would block
  every `eprintln!` of the run, however short the teardown bound. That was the
  deadlock/teardown defect of the first TTY implementation. Holding no lock means a
  stalled terminal blocks only the progress worker.
- **Not non-blocking.** The `dup` shares one open file description with stderr, so
  `O_NONBLOCK` on it would silently make the process's own `eprintln!` non-blocking,
  and a second description cannot be obtained portably (`/dev/fd/N` duplicates on
  macOS). A non-blocking write may also stop half-way through a frame.
- **Repeated sessions** do not grow the descriptor table; ownership is single (no
  explicit `close`).

### 6.2 Bounded teardown and the abandon latch

The engine only calls an infallible, non-blocking channel send. At the end of an
execution the session asks the worker to stop and waits at most 500 ms; if the worker
is blocked in a write it is abandoned (detached) and the `AbandonLatch` is set. From
then on every renderer entry point (`on_event`, tick, wake-up, the final erase,
`Drop`) is muted. A stalled terminal therefore delays process exit by about half a
second at most, and an abandoned worker can neither hold the run up nor write after
the run has moved on.

### 6.3 Panic of the run itself

While the thread is panicking, `Drop` of the session emits nothing, waits for
nothing and joins nothing; it performs one atomic store that sets the latch, so the
detached worker, which may still have events queued, does not draw them after the
panic message and does not erase. It has no secondary-panic path. Without the latch
the detached worker drew its queued frames (and an erase) after the panic text.

### 6.4 Wording of the residual: an in-flight write cannot be recalled

A write (a frame, a plain line, or an erase) that is already blocked in the kernel
when the bound expires, or when the run panics, cannot be called back. It may still
land, once, after the run has printed more. The latch stops everything after that
write. Accordingly, "no late write is reachable" is **not** a claim this design
makes; the claim is: at most one write per abandoned scope or panic can be late,
only when the terminal has not drained for longer than the bound, and it cannot cut
into persistent text, because it refers to the same open file description as
stderr, so the terminal's own write queue orders it before any later persistent
write (it can prefix a line, not split one). A captured, non-terminal stderr has no
transient renderer. This corrects the earlier wording "clear-after-report:
eliminated", which over-stated the result for the erase write; the historical
reports are not edited.

## 7. Residuals accepted by this decision

- **Progress writes are not serialised with `eprintln!`.** Because the stderr lock
  was deliberately removed from the write path (6.1), a short write to a nearly full
  terminal buffer can be interleaved with persistent stderr text: persistent text can
  appear inside a transient frame, or a late plain line can precede a persistent one.
  Full serialisation is exactly what produced the stall defect. It needs a stalled or
  nearly full terminal, changes no persistent byte, leaves no effect on exit status or
  JSON, and for plain mode the exposure is smaller (lines are single short writes, and
  the session is joined before the report or error is printed).
- **A terminal narrowed to one column and widened again** shows no transient line
  until the next event. At width 1 nothing can be drawn, so the renderer asks for no
  wake-up, and nothing triggers a redraw until an event arrives (in practice
  milliseconds, since events come per resource). The alternative, polling for a state
  in which nothing can be drawn, was removed on purpose.
- **A failure within 100 ms of the previous redraw** does not show its outcome word
  on the transient line (section 5).
- **Elapsed is not total time** (sections 4.3 and 5), and it is in whole seconds.
- **A heartbeat can report a small `T`** (4.3).
- **An unterminated plain stream after a panic or interrupt** (4.5).
- **One late in-flight write** per abandoned scope or panic (6.4).
- **The heartbeat numbers are judgement calls.** The numbers (30/60/120/240/300 s)
  have no real-CI evidence; fitness against hosted-CI idle-output limits is
  unverified.

## 8. Open items and non-decisions

- **No target or recipe label (open question OQ-8).** Current behaviour: no progress
  line carries a target. `ItemRef` is `kind + id` and the event has no target, host,
  address, user or key field. In a multi-execution run the `run:` lines delimit
  executions and the following `sinter: [recipe @ host]` line identifies the host,
  but a reader of progress lines alone cannot tell which host a line belongs to. The
  omission is deliberate and is not a contract violation. Adding a label would be an
  event-contract change (the S1/S2 event model), with the rule that a label is an
  opaque name and never connection data (hostname, IP, SSH destination, user). It is
  not decided here.
- **Suppressing a heartbeat that reports a small `T`** was not decided.
- **`MAX_ID_CHARS` is a public constant** (`progress_plain::MAX_ID_CHARS`, 64) although
  only the crate uses it; its siblings are `pub(crate)`. This is API-surface hygiene
  with no runtime effect (the module states it is outside the 1.x CLI/JSON promise).
  Changing the visibility is a source change and was left out of the documentation
  closeout; the user-facing documents describe the observable 64-character limit and
  do not name the constant.
- **Relaxing the secret rule for plain lines**, a default-on plain mode for CI
  (for example keyed on `CI` being set), progress for MCP, cancellation, and a
  structured progress stream are all out of scope and would each be a new decision.

## 9. Compatibility

The feature adds no dependency, no thread beyond the session's single worker (the
heartbeat reuses the worker's wake-up, there is no timer thread), no command-line
option and no target command: the renderer cannot reach the engine, the executor or
the model, and a test compares the result and the target-command count of the S3
scenario matrix with and without it. The default behaviour is unchanged for every
non-interactive run, for `TERM=dumb`, for JSON, and for `validate`, `secrets` and
`mcp`. The progress modules are library API and, like the event model, are not part
of the 1.x CLI/JSON compatibility promise; progress text is stderr text and is
informational.

## 10. Validation status and deferred real-OS evidence

Evidence so far is from the test suite and from a macOS (arm64) real binary, on
pipes and real pseudo-terminals. For plain mode a real run produced
`progress: connect: 30s since last progress` during a genuine 60 s connect timeout,
which confirms the base interval, the wording, the elapsed value, and the order
against the persistent error line. **Not confirmed in a real run:** the doubling
(60/120/240) and the 300 s cap, which need a stall of at least 450 s; they are
asserted only on a driven clock.

Real-Linux validation is deferred to the full WP-PROGRESS gate and is **not** done:

1. Linux terminal detection on fd 2.
2. The `TIOCGWINSZ` ABI.
3. `TIOCSWINSZ`.
4. Linux pseudo-terminal behaviour for the pty tests.
5. `tests/cli.rs` behaviour on Linux.
6. Real SSH success and failure.
7. The backup path on a real host.
8. A successful `plan`/`apply`/`audit` through the real binary.
9. Real-host comparison of persistent output.
10. Real `QUIET_AFTER` timing.
11. Linux `dup` / `F_DUPFD_CLOEXEC`.
12. `ioctl` on the duplicated descriptor.
13. `ClosedPorts` refusal semantics in the test fixture.
14. `SINTER_PROGRESS=plain` on a real host with stderr redirected to a file and to a
    pipe: stdout and exit unchanged, bounded line count.
15. Heartbeat doubling and the 300 s cap in a real run, and CI idle-output fitness.
16. `SINTER_PROGRESS` unset in the gate environment for the pinned stderr suites.
