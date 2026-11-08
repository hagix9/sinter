Sinter Design

Status: Design Draft v4.2
Implementation language: Rust

GOALS.md defines project direction.
This document defines externally observable v0.1 semantics.

Implementation details may vary only where this document explicitly leaves them internal.

1. Design authority

Priority when requirements conflict:

safety

truthful behavior

GOALS.md

DESIGN.md

normative schema and semantic tables

acceptance tests

implementation convenience

Tests do not override the specification.

1.1 v4.2 closure note

v4.2 is a bounded specification-closure revision of v4.1.

It changes no v0.1 feature scope. It closes the remaining pre-implementation ambiguity around:

the effective target execution identity under --sudo

deterministic command environment construction

It also synchronizes stale examples/handler wording with already-normative v4.1 semantics.

1.2 Handler types note (after v4.2)

Handlers now have a type (§4.3, §18). The original handler is the type service and keeps every v4.2 semantic unchanged; a handler without a type is a service handler.

This revision separates three things, and a statement in §4.3 or §18 belongs to exactly one of them:

IMPLEMENTED: what this version of Sinter does today.

PLANNED: designed and accepted, not implemented. A planned feature is not available: a recipe that uses it is rejected at validation, never run and never ignored.

UNCHANGED LIMIT: a restriction that this revision keeps.

Planned features are listed so that their boundaries are fixed before they are built. They must not be read as available.

1.3 Resource Plugin note (v1.9.0, Owner decision 2026-11-01)

§38 adds restricted, data-only Resource Plugins (design E3-H). It uses the same three labels as §1.2. IMPLEMENTED: reading and verifying the plugin root (step 1) and, in step 2, recipe activation, the two execution channels, plan/apply/audit, results and the MCP refusal; in step 5 the release's registry of first-party catalogs lists its first catalog, firewalld 0.1.0, after it was confirmed on real hosts (§38.1, §38.4). No existing resource type, JSON key or exit code changes. The §36 prohibition on plugins is narrowed only as §36 states, and GOALS §16 records why.

1.4 Future directions note (non-normative)

Two possible future features are recorded outside this specification, in the project's future feature register: a common read-only Collector for configuration, diagnostics and forensic collection from selected inventory hosts (FR-025), and generating candidate Sinter recipes from what a Collector collected on existing hosts (FR-067). Neither is designed, accepted or implemented, and this note specifies nothing: no recipe, CLI, output or exit-code contract is changed by it, and validate, plan, apply and audit are unchanged. If either is taken up it needs its own design and Owner approval, and it must not change the observe and mutate contract of §38 or let audit run arbitrary commands.

2. Six v0.1 contracts

Sinter v0.1 is defined by:

Recipe Contract

Evaluation Contract

Planning Contract

Execution Contract

Operation Contract

Information Contract

3. Reference environment

The mandatory v0.1 integration target is:

Ubuntu 24.04 LTS amd64
systemd
apt
OpenSSH server
/bin/sh
sudo -n

Controller reference environments:

macOS Apple Silicon
Ubuntu 24.04 LTS amd64

Unknown or untested platforms must not be presented as verified v0.1 support.

4. Canonical recipe schema

v0.1 has one canonical recipe structure.

4.1 Top level

Canonical YAML shape:

version: 1

vars:
  app_name:
    value: nginx
    sensitive: false

include:
  - recipes/base.yaml

resources:
  - id: nginx_config
    type: template
    with:
      path: /etc/nginx/nginx.conf
      source: templates/nginx.conf
      mode: "0644"
    when: facts.os.family == "debian"
    depends_on:
      - nginx_package
    notify:
      - nginx_restart

handlers:
  - id: nginx_restart
    service: nginx
    action: restart

backup:
  paths:
    - /etc/nginx/nginx.conf

Top-level fields allowed:

version

vars

include

resources

handlers

backup (optional; §4.12)

targets (optional; §19.2)

All other top-level fields are validation errors.

4.2 Resource entry

Every resource entry has exactly these common fields:

id: required string

type: required string

with: required map, may be empty only if the resource schema permits

when: optional expression string

loop: optional static list

depends_on: optional list of resource IDs

notify: optional list of handler IDs

sensitive: optional boolean, default false

No resource-specific field may appear outside with.

Unknown fields are errors.

4.3 Handlers

A handler is a delayed action that runs once, after normal traversal, when a resource that definitely changed notified it (§18).

IMPLEMENTED: a handler has

id: required string

type: optional string, default service. The values are service, ca_trust and command; this version implements all three (see below)

sensitive: optional boolean, default false

for the type service,

service: required static string

action: required enum restart | reload

for the type ca_trust, nothing more: a ca_trust handler has only id, type and sensitive,

and for the type command,

with: required map with program (required static absolute path), args (optional static list of strings, default empty) and timeout_seconds (optional integer, default 300)

A handler that has no type is a service handler. type: service is the same handler as no type. A recipe written before handler types existed means exactly what it meant.

IMPLEMENTED: a type that is not one of the three values, or a type that is not a string, is rejected at validation with a plain error. Such a handler is never frozen, never queued by a notification and never reported as run. No type is skipped or treated as a success.

IMPLEMENTED: the fields a type does not define are rejected. In particular only a command handler has a with block, a command handler has no service and no action, a ca_trust handler has none of the three, and no handler has a privilege field.

UNCHANGED LIMIT: handlers do not support

when

loop

register

depends_on

notify

Handler IDs must be unique and must not collide with resource IDs. A notify that names an unknown handler is an error. Handlers never notify and never depend on each other, so handlers cannot form a cycle.

UNCHANGED LIMIT: a handler is never a general resource, and a handler never runs a shell. The programs a handler may run are the fixed tool of the type ca_trust and the one program of a command handler, both below, each run directly.

IMPLEMENTED: type ca_trust refreshes the system CA trust store with the operating system's own tool. The tool is chosen from the target's detected OS family (facts.os.family, the same identity that selects the package manager), never by checking which binary exists:

debian: /usr/sbin/update-ca-certificates, with no arguments. --fresh is not used; the existing store is not rebuilt.

redhat: /usr/bin/update-ca-trust extract.

The program and its arguments are fixed; nothing in the command line comes from the recipe, no shell is involved, and the run's executor, mutation permit and baseline environment are used. The timeout is 300 seconds and is not configurable. Output capture is bounded like every other command.

IMPLEMENTED: the placement, owner, mode and backup of the certificate files remain the duty of the file resources that notify the handler. The handler places nothing.

IMPLEMENTED: ca_trust is refused, never replaced by another command, in these cases. If a resource notifies a ca_trust handler and the target's OS family has no known tool (neither debian nor redhat), the run is rejected when the target is connected, before any resource runs (plan, apply and audit alike). If the run has no root (neither a root login nor --sudo) the handler fails without running anything. If the tool is not executable on the target the handler fails without running anything; the tool is checked when the handler runs, because an earlier resource may install it.

IMPLEMENTED: the result is the exit status of the tool. Exit status 0 is succeeded. It does not mean that any particular certificate is trusted; nothing is verified beyond the exit status. A non-zero status or a signal is failed, and an outcome that cannot be established (a timeout or a lost connection) is indeterminate and is not retried. A program that may have started is never reported as not run; nothing is rolled back. In output the handler has the type ca_trust, the action refresh, and no service: the service field is the empty string and no unit name is invented.

IMPLEMENTED: type command runs one program after a change. The program is an absolute path (the managed-path rule of §4.10: no . or .. component, no repeated or trailing separator, no NUL), never searched for in PATH. The arguments are an exact list: at most 64 entries of at most 4096 bytes each, no NUL. Every value is static text; a value that contains {{ is rejected, because the handler would run it literally. timeout_seconds is an integer from 1 to 3600, default 300; anything else (zero, a negative number, a non-integer, a string, more than 3600) is rejected. The program is run directly with those arguments, never through a shell, with the baseline environment of §10 and the run's executor and mutation permit. These limits belong to the command handler only: the command resource (§10) keeps its own and rejects no recipe it accepted before.

IMPLEMENTED: a command handler has no cwd, env or success_codes (they are rejected as unknown fields, so they can be added later without changing what a recipe means). It runs in the default working directory of a command, and exit status 0 is the only success.

IMPLEMENTED: the result of a command handler is the exit status of the program. Exit status 0 is succeeded. Any other status or a signal is failed, even if the program had begun to change something, and an outcome that cannot be established (a timeout or a lost connection) is indeterminate and is not retried. If the program is not an executable file on the target the handler fails and runs nothing; this is checked when the handler runs, because an earlier resource may install it. Nothing is rolled back. In output the handler has the type command, the action run, and no service (the service field is the empty string). The report never lists the arguments, and a failure reason names the program (not for a sensitive handler) and carries the first line of the program's standard error, which is withheld for a sensitive handler. A sensitive handler, or one notified by a sensitive resource, is redacted like every other.

IMPLEMENTED: ca_trust introduces no privilege escalation. Every handler runs with the privilege of the run (§21). A ca_trust handler requires root and fails when the run does not have it; it never escalates by itself, and a root login needs no --sudo.

IMPLEMENTED: a command handler follows the same rule as the command resource: it runs with the privilege of the run (a root login, or --sudo) and never escalates by itself. It does not require root in advance: a program that needs root and does not have it fails with its own exit status. There is no privilege field.

IMPLEMENTED: plan and audit never run any handler type. Output keeps the documented handler keys; the type is reported additively.

4.4 Variables

Canonical variable form:

vars:
  name:
    value: <Sinter value>
    sensitive: false

Allowed fields:

value: required

sensitive: optional boolean, default false

Variable names must be unique after include expansion.

Duplicate variable names are validation errors.
There is no override precedence in v0.1.

4.5 Includes

include is an ordered list of relative or absolute recipe paths.

Rules:

expansion is depth-first in declaration order

each canonicalized file may be included at most once per invocation

attempting to include the same canonical file twice is a validation error

include cycles are validation errors

relative paths are relative to the including recipe

included documents must use the same recipe version

all includes are expanded depth-first in declaration order before the including document's own resources and handlers

included variables join one global namespace

duplicate variable/resource/handler IDs are errors

no include parameters or namespaces exist in v0.1

4.6 YAML restrictions

v0.1 YAML rejects:

duplicate mapping keys

aliases

anchors

merge keys

custom tags

non-finite floats

4.7 TOML restrictions

TOML datetime values are rejected.

TOML values must map directly to the common Sinter value model.

4.8 Common value model

Supported semantic values:

null

boolean

signed 64-bit integer

finite IEEE-754 double

UTF-8 string

ordered list

string-keyed map

No implicit numeric/string coercion is performed by the expression system.

For v0.1, user-defined variable values may not be null. Null is reserved for schema-defined optional fields and internal/result values. This keeps YAML and TOML variable semantics equivalent.

4.9 Static target identifiers

The following fields must resolve from literal/static recipe values before target observation:

resource id

file/directory/template/link path

package name

service name

handler service

include path

loop input

dependency IDs

handler IDs

Facts and registered results may not be used to form these identifiers.

A variable used in one of these fields may take its value from a variables file (§19.5). That value is a literal fixed for each (recipe, host) execution before anything connects, so the identifier is still static for the execution; it may differ between hosts.

4.10 Canonical filesystem path syntax

Managed filesystem paths and command guard paths must be absolute UTF-8 paths.

v0.1 rejects paths containing:

. components

.. components

repeated / separators other than the leading root separator

a trailing / except for /

NUL

No lexical cleanup is performed to turn an ambiguous path into an accepted one.

Filesystem ownership-conflict checks use the validated canonical textual path.

4.11 Conflicting ownership

After static expansion, v0.1 rejects multiple stateful resources that manage the same exact filesystem path.

This applies across:

file

template

directory

link

No field-level ownership merging exists in v0.1.

4.12 Backup declaration

`backup` is an optional top-level map whose only field is `paths`, a non-empty list of target paths to copy before apply mutates anything:

backup:
  paths:
    - /etc/ssh/sshd_config
    - /etc/nginx

Each path is a static target identifier (§4.9): a literal canonical absolute path (§4.10), never interpolated. `/` is rejected. A path may appear only once across the include graph; declarations from included files are merged in include-expansion order.

Semantics:

validate checks the declaration only; it never contacts a target or checks path existence.

plan lists each declared path as planned; it observes nothing and creates nothing.

apply copies every declared path, in order, on the target before the first resource is evaluated. Any backup failure aborts the invocation before any resource runs (exit 5); a partially written run directory is left in place and named in the error.

audit ignores the declaration; backups are not desired state.

Store: with --sudo `/var/lib/sinter/backups/<run-id>/`, otherwise `<target-user-home>/.sinter/backups/<run-id>/`, on the target. Inside the run directory the original absolute path is reproduced. `<run-id>` is `<UTC YYYYMMDDTHHMMSSZ>-<8 hex>`, one per invocation and shared by all its targets; when several recipes run (§19.3) it is suffixed `-<NN>-<recipe>` per recipe. Backups run only for executions selected by target resolution (§19.2). Store directories created by Sinter are mode 0700; every ancestor of the run directory and of each source path must pass the §23 trust check. An existing run directory is a collision and fails. A declared path that contains, or lies inside, the store fails. `--backup-dir` or a project file can name another store on the target (§40.6); a recipe cannot.

Copy rules: a regular file in another account's tree is copied as §40.7 says, and nothing else in such a tree is copied. Elsewhere, regular files, directories (recursively) and symlinks (as links, never followed) are copied; mode (including POSIX ACLs), ownership and timestamps must be preserved or the backup fails; other extended attributes and SELinux labels are preserved on a best-effort basis. Other object types fail. An absent path is recorded as absent and is not a failure.

Backup content is never read by the controller and never appears in any output; only paths, object kinds and store locations do.

A backup is not a rollback. Sinter never restores, prunes, or reads back backups.

5. Ordering

Sinter uses one deterministic ordering rule.

includes expand depth-first in declaration order

resources retain declaration order after include expansion

loop instances retain list order

dependency edges may delay a resource until dependencies finish

among simultaneously eligible independent resources, original expanded declaration order wins

handlers execute in handler declaration order, but only if notified

No lexical sorting by ID is used.

6. Static loops

A loop is a literal/static ordered list.

Example:

- id: base_pkg
  type: package
  with:
    name: "{{ item }}"
    state: present
  loop:
    - curl
    - jq

Loop rules:

loop input must be statically known

empty list expands to zero resources

loop + register is forbidden in v0.1

resource ID for loop element N becomes <id>[N], with N zero-based

generated IDs participate in duplicate checks

dependency references to the unexpanded parent loop ID are forbidden

users reference generated IDs explicitly only where needed

facts and register values may not alter loop count or order

7. Expressions

v0.1 uses a deliberately small expression language.

The implementation may use a maintained Rust expression library only if configured to exactly satisfy these semantics.

7.1 Expression inputs

Expressions may read:

variables

facts

allowed registered results

item while expanding/evaluating a loop instance

the current command result in changed_when

7.2 Operators

Required operators only:

==

!=

<

<=

>

>=

&&

||

!

parentheses

No user-defined functions exist in v0.1.

7.3 Namespaces and variable evaluation

Names are resolved only through these explicit namespaces/symbols:

vars.<name>

facts.hostname

facts.os.name

facts.os.family

facts.os.version

facts.arch

registers.<name>.<field>

item inside a loop instance

result.<field> inside changed_when

Bare variable names are not allowed.

v0.1 variable values are literals only. Variable values are not expressions and do not interpolate other variables. Therefore variable forward references and variable cycles do not exist. A variables file (§19.5) may replace a declared variable's literal for a run, per host or group; the replacement is a literal of the same type and is fixed before anything connects.

Template-local values are exposed only as template.<name> and do not shadow vars, facts, registers, or item.

7.4 Comparison semantics

Equality/inequality are defined only for values of the same semantic type, except integer and finite float may be compared numerically.

Ordering operators < <= > >= are defined only for:

integer/float numeric pairs

UTF-8 strings using Unicode scalar-value lexicographic order

Ordering null, boolean, list, or map is an evaluation error.

Equality of null is supported only for schema/result values where null can occur.
Lists and maps are not comparable in v0.1 expressions.

Any comparison with Unknown produces Unknown.

7.5 Boolean strictness

when and changed_when must produce boolean.

No truthiness coercion exists.

7.6 Short-circuiting

Boolean operations short-circuit left to right.

Therefore:

false && X

returns false without evaluating X.

true || X

returns true without evaluating X.

An undefined value in an unevaluated branch does not cause an error.

7.7 Undefined versus Unknown

Undefined means a referenced name does not exist.
Evaluating an undefined name is an error.

Unknown means a known producer/value exists but cannot be known in the current mode.

Unknown is not null, false, skipped, or failure.

For boolean operations, evaluation is left-to-right and short-circuiting:

false && Unknown => false

true && Unknown => Unknown

Unknown && false => false

Unknown && true => Unknown

true || Unknown => true

false || Unknown => Unknown

Unknown || true => true

Unknown || false => Unknown

!Unknown => Unknown

When the left operand is Unknown, the right operand is evaluated only as needed to determine whether the result can be resolved by the table above. An error encountered in an operand that must be evaluated remains an error.

Comparisons involving Unknown => Unknown.

7.8 Interpolation

Strings may contain interpolation tokens:

"{{ vars.app_name }}"

If the entire string is one interpolation expression, the expression result retains its type.

If interpolation is embedded in surrounding text, inserted values must be scalar and are converted to strings using documented canonical formatting.

Literal {{ is written as \{{.

Sensitive values used in interpolation make the resulting value sensitive.

8. Evaluation phases

Phases:

A. parse and schema validation
B. include expansion
C. static variable assembly
D. static loop expansion
E. dependency/handler graph validation
F. target connection and capability detection
G. fact observation
H. per-resource runtime evaluation
I. per-resource observation/mutation/verification

Recipe structure is frozen after phase E.

9. Conditions

when is evaluated immediately before the resource would otherwise be considered.

Results:

true: continue

false: resource disposition = skipped_by_condition

Unknown in plan: resource remains unknown; no mutation occurs

Unknown in apply: fail before mutation

expression error: fail

Resource-specific values not needed for a false condition are not evaluated.

10. Command resource

Canonical shape:

- id: probe
  type: command
  with:
    program: /usr/bin/example
    args: ["--check"]
    cwd: /tmp
    env:
      MODE: check
    timeout_seconds: 30
    success_codes: [0]
    creates: /var/lib/example/ready
    removes: null
    changed_when: "result.exit_code == 0"
    register: probe_result

10.1 Required/optional fields

program: required static string

Optional:

args: list of strings, default []

cwd: static string or null, default null

env: string map, default {}

timeout_seconds: integer 1..86400, default 300

success_codes: non-empty list of integers 0..255, default [0]

creates: static absolute path or null

removes: static absolute path or null

changed_when: expression or null

register: identifier string or null

creates and removes are mutually exclusive in v0.1.

There is no failed_when in v0.1.

10.2 Guard semantics

If creates exists before execution:

command is not executed

execution = succeeded

change = none

disposition = guard_satisfied

dependencies are considered satisfied

register receives a structured not_executed result

If removes does not exist before execution, the same semantics apply.

This is distinct from when: false, which skips dependents under v0.1 dependency rules.

10.3 Exit status

After actual execution:

exit code in success_codes => execution succeeds

any other exit code => execution fails

A failing command is conservatively classified:

change = possible

unless Sinter can prove the command did not begin.

10.4 changed_when

changed_when is evaluated only after successful actual execution.

It may read only:

result.executed

result.exit_code

result.stdout

result.stderr

result.stdout_complete

result.stderr_complete

It may not read result.changed or result.execution, preventing self-referential change evaluation.

If absent:

successful executed command => change = changed

If present:

true => changed

false => none

Unknown/error => execution fails, change = possible

10.5 register

Register names are global and unique.

A register producer must not be inside a loop.

A consumer of a register must directly list the producing resource in depends_on.

Transitive dependency is insufficient.

Registered result fields:

executed: boolean

exit_code: integer or null

stdout: captured string or null

stderr: captured string or null

stdout_complete: boolean

stderr_complete: boolean

changed: boolean or null

execution: string enum

If output exceeds capture limits:

displayed output may be truncated

registered stdout/stderr become unavailable

corresponding complete flag is false

attempts to use incomplete output in expressions produce an error, not a truncated value

Guard-satisfied command registers:

executed = false

exit_code = null

stdout = null

stderr = null

complete flags = true

changed = false

execution = "succeeded"

10.6 OS-boundary semantics

If cwd is omitted, the command starts in the target login user's home directory for non-sudo execution and /root for invocation-level sudo execution.

Commands start from a clean environment. Controller environment variables, SSH session environment variables, login-shell initialization, and arbitrary target-user environment variables are not inherited.

The v0.1 baseline command environment is exactly:

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

LANG=C.UTF-8

LC_ALL=C.UTF-8

HOME=<effective target user's home>

For a non-sudo invocation, HOME is the connected/local target user's home as resolved by the reference platform account database.

For a --sudo invocation, HOME=/root.

The recipe env map is then added to this baseline.

The baseline names PATH, LANG, LC_ALL, and HOME are reserved in v0.1 and may not be supplied by recipe env; collision is a validation error. This avoids implementation-dependent precedence.

No other environment variable is implicitly supplied to a command resource.

Guard paths use non-following path inspection:

expected object present => present, including a dangling symlink as an object

confirmed ENOENT/ENOTDIR => absent

permission denied or otherwise uninspectable => error

stdout/stderr are captured as bytes first. A captured stream is usable as a string/register field only if it is valid UTF-8 and complete. Non-UTF-8 output makes that string field unavailable and its complete flag false; raw bytes are never silently replacement-decoded into a complete registered value.

If a process terminates by signal:

exit_code = null

execution = failed if termination is positively known

change = possible if execution began

11. Facts

Required v0.1 facts:

hostname

os.name

os.family

os.version

arch

Facts are immutable for one invocation after collection.

Facts may affect:

when

non-identity desired values

template content

They may not affect static target identifiers or recipe structure.

12. Plan contract

Plan is a preview, not an approved artifact.

Plan:

validates and freezes recipe structure

connects to target

validates required capabilities

gathers facts

walks resources in deterministic order

evaluates conditions

performs observation-safe resource inspection

calculates known ChangeSets

does not execute command resources

does not run systemctl daemon-reload or any other service/manager mutation (§28.6)

propagates Unknown from command registers

displays known, skipped, and unknown outcomes

Observation capabilities may not internally call mutation capabilities.

Acceptance tests must combine execution-interface instrumentation with external state observation.

13. Apply contract

Apply:

validates and freezes recipe structure

connects and validates capabilities

gathers facts

processes resources in deterministic dependency order

evaluates when

resolves required runtime values

observes current state immediately before mutation decision

computes ChangeSet

mutates only when required

verifies required state

records result

queues eligible handlers

synchronizes the systemd system manager at the consumer boundaries defined in §28.3

stops immediately on failed or indeterminate normal resource

if normal traversal contains no failed or indeterminate resource, enters the handler phase and executes legitimately notified handlers in handler declaration order; condition skips and condition-derived dependency blocks do not suppress this phase

stops on first failed or indeterminate handler

A previous plan is never reused as current state.

14. Dependency semantics

A dependency is satisfied by:

verified/successful stateful resource

successful command

command not executed because a creates/removes guard is already satisfied

A dependency is not satisfied by:

when condition false

failed resource

indeterminate resource

verification failure

If a dependency is not satisfied:

dependent resource is not executed

disposition records blocked_by_dependency

when: false on a producer therefore blocks its dependents in v0.1.

Plan and the accounts a resource uses (F-3). Order is declaration order plus depends_on; no dependency is ever added implicitly. Apply looks up an owner, group or primary group for real, after the resources that run before it have applied. Plan therefore defers (unknown until apply) a resource whose owner, group or primary group is created by a user/group resource that runs earlier in the execution order, whether or not it is listed in depends_on. An earlier resource counts only if its state is present and its when is true (or cannot be decided in plan); a resource that is absent, skipped, blocked because a resource it depends on (directly or through a chain) is skipped, or that runs later does not count, and the unknown-account error stays in plan and in apply. A user without group whose same-named group certainly runs earlier is refused in plan, as in apply. Deferral exists only in plan.

Dependencies also define order. Sinter never reorders resources. A resource that produces systemd manager input (§28.2) must be ordered before the service resource or handler that consumes it, by depends_on or declaration order. A producer declared after its consumer does not cause the consumer to be redone; only the end-of-run synchronization (§28.3) still happens.

Accounts and services created by a package are not inferred. A package resource is not treated as a producer of a user, group or unit: Sinter never guesses from a package name what accounts or units it creates, and it does not add an implicit dependency between a package and a user/group/service that happens to name a matching account or unit. A package creates what its own maintainer scripts create, which differs by package, version and distribution and cannot be proven before it runs; guessing would make plan optimistic and could order resources on a dependency that does not exist. Such a producer is therefore declared explicitly, as a user or group resource, or as a command whose effect is visible through a creates guard, and ordered with depends_on — see the accounts/paths example in examples/quick.

15. Result model

Every resource result contains independent dimensions.

Execution:

not_run

succeeded

failed

indeterminate

Change:

none

changed

possible

Verification:

not_applicable

not_performed

verified

failed

unknown

Disposition:

normal

skipped_by_condition

guard_satisfied

blocked_by_dependency

blocked_by_fail_fast

Reason/context fields must identify why execution did not occur or why certainty was lost.

Human labels are derived from these structured dimensions.

16. Retry contract

Sinter performs no automatic retry of mutation operations in v0.1 after:

timeout

SSH disconnect after dispatch

lost response after mutation dispatch

any other indeterminate completion

This rule applies to all mutation types, not only command resources.

Read-only observation may be retried internally only when doing so cannot transform an unknown mutation into an assumed success.

A new explicit sinter apply invocation is a new reconciliation attempt.

17. Fail-fast contract

v0.1 is fail-fast.

On the first failed or indeterminate normal resource:

no later normal resource executes

no delayed handler executes

no new systemd manager reload starts (§28.7)

pending handlers are reported

remaining resources are marked blocked_by_fail_fast

On the first failed or indeterminate handler:

no later handler executes

remaining pending handlers are reported

A killed Sinter process cannot guarantee reporting of in-memory pending notifications.

17.1 Invocation aggregate status

skipped_by_condition, guard_satisfied, and blocked_by_dependency caused solely by a condition-skipped producer do not by themselves make the invocation fail.

If no resource is failed or indeterminate, normal traversal completes and the handler phase runs for handlers legitimately queued by successful changed resources.

A successful invocation with such skips exits 0.

When fail-fast is triggered by a failed/indeterminate resource, all resources not yet processed are marked blocked_by_fail_fast, even if they would also have an unsatisfied dependency. Fail-fast reason takes presentation precedence.

18. Handler contract

IMPLEMENTED: the handler types this version runs are service, a delayed service action; ca_trust, a delayed refresh of the system CA trust store; and command, a delayed run of one program. The rules below apply to every handler type.

They execute only if notified by a resource that:

definitely changed

succeeded

passed required verification

Multiple notifications to the same handler are deduplicated.

Handlers run in handler declaration order, never in notification order, and the first failed or indeterminate handler stops the phase (§17).

The type service (IMPLEMENTED):

Allowed actions:

restart

reload

Handler execution order:

manager synchronization if pending (§28.3)

fresh observation of the handler's service (§28.4)

restart or reload action

verification

Handler verification:

restart: service must be active after action

reload: command/action must report success and service must still be active after action

The manager synchronization that may precede a handler (systemctl daemon-reload) is a separate operation from the handler's restart or reload action. It reloads unit definitions only and never restarts or reloads the service. To apply a changed unit definition to a running process, a restart handler (or a reload handler when the unit supports ExecReload) must be notified.

A failed or indeterminate manager synchronization before a handler makes that handler failed or indeterminate without running its action; later handlers do not run.

systemctl daemon-reload is not a handler type and none is planned: the manager synchronization of §28 already performs it. A ca_trust handler is unrelated to it: it neither causes nor needs a manager reload.

The types ca_trust and command (IMPLEMENTED): see §4.3. Each runs once, in handler declaration order, after the resources that notified it; a service handler that must see the refreshed trust store is declared after the ca_trust handler.

UNCHANGED LIMIT: a handler is not retried and is not recorded across runs. If a run stops before the handler phase, or a handler fails, the notification is lost: the next apply finds the resource already correct and notifies nobody. The run reports the handlers that did not run (handlers_pending); the operator must perform their action by hand. This holds for every handler type. For ca_trust it means a stale trust store until someone runs the refresh by hand (update-ca-certificates on debian, update-ca-trust extract on redhat). For a command handler it means running the program by hand with the arguments of the recipe.

IMPLEMENTED (ca_trust and command): the result is the exit status of the program, not a state observation; a failed or indeterminate result stops the phase like any other handler, a program that may have started is never reported as unchanged, and nothing is rolled back.

Handlers cannot notify anything else.

If a normal resource changes and then fails verification, no handler is enqueued.
This does not imply that manual recovery is unnecessary.

A subsequent apply does not guarantee replay of notifications lost in an earlier failed invocation.

19. SSH contract

v0.1 accepts only hosts whose keys are already present in the selected known_hosts file.

There is no interactive host-key enrollment UI.

Default known_hosts source:

~/.ssh/known_hosts

An explicit CLI option may select another file.

Unknown host key => connection failure.
Changed host key => connection failure.
No insecure fallback exists.

Host-key identity is selected by the connection port:

Default port 22 uses the portless `host` known_hosts identity.

A non-default port requires the explicit `[host]:port` known_hosts identity.

A portless `host` entry must not authorize a connection to a non-default port.

An explicit matching-identity mismatch must never be bypassed by another host form.

Hashed (`|1|...`) known_hosts entries are matched against the same exact identity.

A presented key listed on any `@revoked` line of the selected file is refused.

When known_hosts already records one or more key types for the identity, those host-key algorithms are negotiated first; the presented key must still match exactly.

19.1 OpenSSH client configuration (CLI only)

For a CLI SSH target, Sinter asks the installed OpenSSH client to evaluate its configuration (`ssh -G <host>`, no connection) and inherits HostName, User, Port, IdentityFile, IdentitiesOnly, IdentityAgent, HostKeyAlias and the first UserKnownHostsFile. When a HostKeyAlias is set it replaces `host` in the known_hosts identity.

Host-key policy settings are never inherited (StrictHostKeyChecking, UpdateHostKeys, CheckHostIP, GlobalKnownHostsFile); this section never weakens §19.

A ProxyJump or ProxyCommand for the host is a connection error; Sinter never silently connects directly instead.

`--no-ssh-config` disables inheritance. When no `ssh` client is installed, built-in defaults apply.

Precedence per field: explicit CLI option > inventory host field (§19.2) > OpenSSH configuration > built-in default ($USER, 22, ~/.ssh/known_hosts, ~/.ssh/id_ed25519, id_ecdsa, id_rsa).

Private keys are never decrypted by Sinter; an encrypted key is usable only through ssh-agent.

Key selection and authentication, as implemented. The list of key files is taken whole from the first source that names any: `--identity` (repeatable, also with `--host`) replaces the inventory host's `identity_files` (§19.2), which replace the OpenSSH `IdentityFile` list; lists are never merged. Each inventory host can therefore have its own keys. For a host without `IdentityFile` the OpenSSH client reports its own default key list, so the built-in list above applies only with `--no-ssh-config` or when no `ssh` client is installed. Authentication tries ssh-agent first: agent keys whose public key matches a selected key file's `.pub` are offered first, only those with IdentitiesOnly, and `IdentityAgent none` disables the agent. Then each selected key file that exists is tried without a passphrase. An unencrypted key file therefore works directly, and a passphrase-protected key only when it is loaded in ssh-agent; Sinter never asks for or accepts a passphrase. SSH password and keyboard-interactive authentication are not supported. With `--sudo`, sudo runs non-interactively and never asks for a password (§21).

MCP target profiles never consult the OpenSSH configuration.

19.2 Inventory, host groups, recipe targets (CLI)

An inventory defines which hosts exist. It never selects a host for execution.

Inventory file (YAML, or TOML by extension), passed to plan/apply/audit with `--inventory <path>` (alias `--hosts`):

hosts:
  web01:
    address: 10.0.0.11
    user: ubuntu
  db01:
    address: 10.0.0.21
    port: 2222
groups:
  web:
    hosts: [web01]

Host fields, all optional: address (default: the host name, which may be an OpenSSH `Host` alias), port, user, known_hosts, identity_files. `groups.<name>.hosts` is a non-empty list of defined hosts without repeats. Names match `[A-Za-z0-9._-]`, start alphanumeric, at most 64 characters. Unknown fields, undefined group members, an empty host set, and parse errors are validation errors (exit 2). There are no nested groups, variables, patterns, dynamic inventory, per-host sudo, or implicit "all" group. An inventory file never carries variables: per-group and per-host variable values come from a separate variables file (§19.5), which may only refer to hosts and groups the inventory defines and never selects, adds or removes a host.

A recipe names the hosts it may run on with a top-level `targets` map:

targets:
  groups: [web]
  hosts: [db01]

The selected set is the union of the named hosts and the members of the named groups. At least one name is required. `targets` may appear only in the recipe that is run, never in an included file. `targets` has no effect without an inventory; an explicit `--host` (or localhost) keeps the single-target behavior.

Target resolution fails closed. With `--inventory`, before anything connects:

a recipe without `targets` is an error (exit 2) — an inventory never implies "all hosts";

a target name the inventory does not define is an error (exit 2);

a selection that matches no host is an error (exit 2);

every selected host (and only selected hosts) is resolved per §19.1; two selected hosts resolving to the same address and port are an error (exit 2).

`--host` and `--inventory` are mutually exclusive (exit 2).

A selector argument (§39.2, not in v1.9.0) is the one exception to the first of these rules: one plain recipe without `targets` runs on exactly the hosts the selector names. Everything else in this section still holds for it, and an inventory alone, or `--limit`, never selects a host for such a recipe.

`--limit <ITEMS>` narrows a run with `--inventory` to some of the hosts the recipes' `targets` select. It never adds a host: the hosts that run are those a recipe targets and `--limit` names. `<ITEMS>` is a comma-separated list (at most 256 items of at most 64 characters, one `--limit` option only); each item is a host name, a group name, `host:<name>`, `group:<name>`, or a pattern. A bare name that is a host and also a group is ambiguous and an error — write `host:<name>` or `group:<name>`. A pattern uses `*` (any run of characters) and `?` (one character), matches host names only, and may be written with `host:`; quote it so the shell does not expand it. There is no exclusion (`!`). `--limit` needs `--inventory` and is exit 2 with a single target (`--host` or the local host).

`--limit` fails closed, with exit 2 and before any `ssh -G`, connection or command: an empty list or item, a character outside the name rules, a name that is neither a host nor a group of the inventory, a pattern that matches no host, and an item that reaches no host any recipe's `targets` select (it would run nothing). The hosts are chosen once, by evaluating `--limit` against the target resolution and before any host is resolved; the unfiltered selection is not passed on, and `ssh -G` (which may run local commands through an OpenSSH `Match exec`), the connection and the variables of a host left out by `--limit` are never evaluated. A recipe of a bundle that no host remains for is skipped: no value from the variables file or from a host is applied to it, no model is built for running it, no execution is planned for it and no `ssh -G` runs for its hosts. It is still held to what does not depend on a variable's value: it is parsed as a document when the bundle is loaded (syntax, schema, includes, declarations, its `targets` against the inventory) and `Prepared::check_structure` freezes it with its own defaults and keeps every failure except one that may depend on what a variable holds. A field that references a declared variable and fails its static check with the defaults is left out (the field is given no value), unless it fails whatever the variables hold: the check evaluates the field once more with a neutral value of its declared type for every non-sensitive variable, trying every combination of the boolean variables the field names because a boolean can decide which side of `||` or `&&` is evaluated (`Tolerance::may_depend_on_values`), so an undeclared variable, a fact or register, a sensitive value and a variable of another type are kept, and no message is inspected. The resource's other checks, and those of the other resources, go on. What is not judged, and is made when a host runs the recipe, is only what a variable's value decides: such a field, a conflict over a path or a name that such a field takes part in (`ownership_may_depend_on_values`), and a template file a variable chooses (its body is read only when the default resolves to a file, and a failure there is not judged). A field whose literal part is invalid whatever the variable holds (`rel/{{ vars.x }}`) is not refused either: only the evaluation is judged, not the checks that follow it. Known limits of the evaluation: at most 8 boolean variables named by one field are combined (a field naming more is left undecided), and only booleans are varied, so a comparison that decides which side of `||` or `&&` is evaluated (`vars.x == "a" || vars.x`) can still be refused although another value would make it valid. Unknown resource types and fields, duplicate ids, `depends_on`/`notify` references and cycles, secret references, undeclared variables, literal fields (`owner`, `group`, `mode`, `content` with `source`, `state`, `creates` with `removes`) and conflicts between literal paths or names are kept. A freeze that runs a recipe does not use this tolerance: there the first failing check fails, as before. It is listed as skipped (text `SKIP   recipe not run: --limit leaves no host for it`, JSON `excluded_by: "limit"` on its `resolution` entry and `null` counts in a `validate` bundle document). The ban on overriding a sensitive variable still covers the variables it declares. Text output prints a `limit:` line, marks the hosts left out `SKIP excluded by --limit (matched: …)` and counts them; JSON output adds the `limit` array and `excluded_by: "limit"` on those hosts, and keeps their `reasons`. Without `--limit` the output, the checks and the order are unchanged. By design `--limit` does not cover: the duplicate-address check among the hosts that run (hosts left out are not compared); a misspelled variable name in the layer of a host left out; and the drift of the hosts left out (an `audit` that exits 0 says nothing about them). `excluded_by` is an open set of values (`"limit"`, and `"selector"` for a selector, §39.2).

19.3 Recipe bundles

A bundle lists recipes to run as one invocation:

version: 1
name: web-stack
recipes:
  - common.yaml
  - nginx.yaml

A file whose top level has `recipes` is a bundle. Paths are relative to the bundle file. Each listed recipe must exist, load, and validate; a recipe may be listed once; bundles do not nest. A bundle adds no targets: with an inventory each recipe is resolved against its own `targets` (§19.2), and a recipe without `targets` fails the whole invocation before anything runs. Without an inventory, every recipe runs, in order, on the one explicit target.

19.4 Multi-target execution

Executions are (recipe, host) pairs: recipes in bundle order, hosts in name order within each recipe. They run one at a time.

plan and audit are read-only and attempt every execution.

apply fail-fast: during apply, an execution whose exit code is not 0 — for any reason: validation (2), connection or capability (3), plan (4), backup or apply failure (5), indeterminate outcome (6) — stops the sequence. The failed execution keeps its own result or error. Every later execution, whether a later host of the same recipe or any execution of a later recipe, is reported as not run with the name of the failed execution as its reason: it is never contacted, and neither its backups nor its resources run. Executions completed before the failure keep their results; nothing is rolled back.

The invocation exit code is the most severe exit code among executions that ran, in the order 6, 5, 4, 3, 2, 7, 8, 0 (8 only from a strict audit, §33); not-run executions contribute none. A partial failure never exits 0. The summary counts executions that exited 0, exited non-zero, and were not run.

Text output shows the target resolution (MATCH with reasons / SKIP per host and recipe) before running and an execution summary after. JSON output is one document for the invocation with the resolution and, per execution, the recipe, the target identity (inventory name, address, port, user), status, exit code, the single-target document or error, and an execution-level backup record (§4.12): null when the recipe declares no backup or in audit; otherwise its status (planned, completed, failed, not_started, not_run) with run id, run directory and per-path entries — never content.

`validate` accepts every target option and ignores it; it reads no inventory and no variables file — except with `--vars-file`, when it runs the static gate of §19.5 (and then reads the variables file and, with `--inventory`, the inventory) and still contacts no host. With `--vars-file` and `--inventory`, `--limit` narrows that check to the selected hosts exactly as it does for `plan`; the success output adds `limit` and `variables.targeted_executions` (JSON) or a line `ok: --limit … selects N of M execution(s)` (text). An explicit `--limit` is checked by `validate` with or without `--vars-file`: without a variables file `validate` reads the inventory, resolves each recipe's `targets` and evaluates `--limit` as `plan` does before it connects (a bad `--limit`, a broken inventory, a recipe without `targets` and `--host` with `--inventory` are exit 2), resolves no variable beyond loading the recipes some host runs, and contacts nothing. Without `--limit` or a selector (§39.2), `validate` reads no inventory and ignores the other target options.

19.5 Variables files (common, group and host variables)

A variables file gives recipe variables (§7.3) other values for a run, in common, per inventory group, and per host. It is passed to plan/apply/audit — and to validate, which then runs the static gate below without contacting any host — with `--vars-file <path>` (relative to the current directory, like `--inventory`). Without `--vars-file` nothing in this section applies and every behavior, output and error is exactly as before.

version: 1
vars:                 # common: every host
  app_port: 8080
groups:               # inventory group names
  web:
    app_port: 8081
hosts:                # inventory host names (--host: the --host string; local target: localhost)
  web01:
    app_root: /srv/web01

File. A regular file of at most 1 MiB, UTF-8, YAML (`.yaml`, `.yml`) or TOML (`.toml`) by extension; any other extension is an error. The top level allows exactly `version` (required, 1), `vars`, `groups` and `hosts`; each layer is a map of variable name to value; `groups` and `hosts` map a name (§19.2 name rules) to such a map. Variable names are `[A-Za-z0-9_]`, 1–128 characters. Values are literals (§7.3): never null, never interpolated (`{{ … }}` is plain text). Unknown keys are errors; nothing is ignored. There is one variables file per invocation.

Overrides. Every variable the file names must be declared by at least one recipe of the invocation (the recipe, or any recipe of the bundle, includes included). For every recipe that declares it, the value must have the type of the declared default (string, integer, float, boolean, list, map; integer and float are distinct), and a variable declared `sensitive: true` cannot be overridden at all. A recipe that does not declare a name is not affected by it; recipes of a bundle that declare the same name receive the same value. A bundle has no variables of its own, and there is no command-line variable layer.

Precedence, lowest to highest: the recipe default, `vars` (common), `groups`, `hosts.<name>`. The group layer of a host is every inventory group that contains the host, independent of which `targets` selected it. Group order never decides anything: when two of the host's groups give the same variable different values (type and value compared), it is an error for every host the run selects unless `hosts.<name>` sets that variable.

Modes. With `--inventory`, every `groups` key and every `hosts` key must name an inventory group or host (checked even for hosts no recipe selects), and a host's name is its inventory name. With `--host <H>` or on the local target there is no group membership: a non-empty `groups` layer is an error (a one-host inventory gives a single host its groups), `vars` applies, and `hosts.<H>` applies where `<H>` is the `--host` string (`localhost` for the local target); other `hosts` entries are ignored.

Scope of the checks with `--limit`. Without `--limit` every check above covers every layer, as before. With `--limit`, what is structure stays global and is checked for the whole file and inventory: the file's syntax and schema, the inventory, that every `groups` and `hosts` key names an inventory group or host, the common layer, the single-target `groups` rule, and the ban on overriding a sensitive variable in any layer (a value for a host that does not run is still a value in the file, so a sensitive variable is refused wherever it appears). What is specific to a host is checked only for the hosts that run: the types and names of that host's own layer and of the layers of the groups it belongs to, the group conflicts that affect it, and its frozen model. A wrong value that only an unselected host or a group of unselected hosts would receive does not stop the run, and nothing about those hosts is contacted either way.

Per-host models. Every (recipe, host) execution is frozen (static target identifiers §4.9, conflicting ownership §4.11, template and secret-reference checks, the recipe-wide env merge) with its own variable values, from the recipe as loaded; nothing evaluated for one host is reused for another, except that executions of one recipe with identical overrides may share one frozen model. With a variables file, a recipe's default values are frozen only for executions that override nothing, so a placeholder default that would fail static validation is accepted when every execution overrides it. Variables files resolve before anything connects; identifiers still never depend on facts or registers (§36).

Static gate. Before anything connects, in this order: every recipe is loaded; the inventory is loaded; the variables file is read; targets are resolved; the file is checked against the recipes, the inventory and the mode; every execution's model is frozen. The checks of the file run in stages, and a stage runs only when every earlier stage found nothing: (1) a file that cannot be read, is not a regular file of at most 1 MiB with a supported extension, is not UTF-8 or does not parse is one problem and stops at once; (2) every schema problem is collected and all are listed; (3) every override problem (names, types, sensitivity, layers against the inventory and the mode, group conflicts) is collected; (4) every execution is frozen and the first static failure of each is collected, identical messages being reported once with their hosts. Stages 3 and 4 each list at most 50 problems, then a count of the rest. One problem anywhere is exit 2 for plan, audit and apply alike, and then no `ssh -G` runs, no host is contacted and no local executor starts. Binding each frozen model to the (recipe, host) execution it was frozen for is an internal consistency check, not a check of the file: with an inventory it runs after the selected hosts are resolved (§19.1), which may run the local `ssh -G`, and before any execution connects; a mismatch is exit 2 and no host is contacted. Only when every execution of every host passes does target resolution (§19.1) and execution (§19.4) begin. Runtime failures — expressions over facts or registers, template rendering, secret decryption, connection, privilege, the target's own state — remain per execution, and apply stays fail-fast without rollback (§19.4). With `--vars-file`, a freeze-time error of a recipe (for example a duplicate resource id) is reported after every recipe, the inventory and the variables file have loaded, so it can follow a later recipe's parse error; without `--vars-file` the order is unchanged.

validate. `validate <recipe> --vars-file <path>` runs exactly the static gate above, by the same code: the recipes are loaded unfrozen, the inventory (only with `--inventory`) and the variables file are read, targets are resolved, and every (recipe, host) execution is checked and frozen with its own values. `--host` and `--inventory` stay mutually exclusive (exit 2) in this form; without `--vars-file` `validate` ignores every target option as before. Without an inventory the target is the `--host` string, or `localhost`. It then stops: no `ssh -G` runs, no host is contacted, nothing is written. The problems, their order and their exit code (2) are those of plan, apply and audit, and none carries a value from the file. What `validate` does not check, because it needs `ssh -G` or a connection or happens only while running, is: how OpenSSH resolves the `--host` address, two inventory hosts resolving to one address, ProxyJump/ProxyCommand, `USER` or `HOME` not being set (`--user is required when USER is not set`, `HOME is not set`), and the runtime failures listed above. On success it prints the usual document plus `ok: variables file <path> checked: N execution(s)` (text) or a `variables` object with `file` and `executions` (JSON); its warnings cover every checked execution, each listed once, at most 50 per recipe (`warnings_omitted` counts the rest). Because a recipe's default values are used only by executions that override nothing, a default that fails on its own is accepted by `validate --vars-file` when every execution overrides it, as in plan; `validate` without `--vars-file` still reports it.

Diagnostics never contain a value from the variables file, nor any part of one. A syntax error is reported with a fixed description, the file and, when the parser provides a position, the line and column (a TOML syntax error without one is reported without a position); invalid UTF-8 is reported with the line and column where it starts; a structural YAML problem found after parsing (duplicate key, anchor, alias, merge key, unsupported tag, out-of-range number, several documents) or a TOML datetime or non-finite number is reported with a fixed description and no position. A YAML core tag written with the default `!!` handle on a node of its kind is accepted (`!!str`, `!!int`, `!!float`, `!!bool` or `!!null` on a scalar, `!!seq` on a sequence, `!!map` on a mapping); any other tag, a core tag on another kind of node and a value its tag does not accept are unsupported. Schema and override errors name only the layer, group, host, variable, recipe and types, besides metadata that is never a value from the file: the variables file's path, the inventory's path (for a group or host it does not define) and, for a file that cannot be read, the operating system's error text; an unknown top-level key, and a key that is not a valid variable, group or host name, is never shown. Keys in name positions that are valid names are shown as names (for example an undeclared variable), so a value must never be written as a key. A static check that fails on a field whose value references a variable supplied by the file is reported by resource id and type, the field and check (with the other resource for an ownership conflict), and the variables with their layers, and states that the value is withheld; its original message is not used. Whether a check depends on such a variable is decided from the recipe (which fields reference which overridden variables) and from the stage of the check, never by reading the error text. A check that evaluates no value (field names, enumerations, literal syntax, references between resources) keeps its message; a check that is not attributed to a field is treated as depending on every overridden variable the resource references.

Secrets. A variables file is plaintext and is not a place for secrets; it cannot override a sensitive variable, and it never changes how encrypted secret references (`content: { secret: … }` and the like) are confined, opened or redacted. A value that passes the checks is an ordinary non-sensitive value: like any non-sensitive recipe variable it appears in plan diffs, run results, identifiers and runtime messages. `sensitive: false` declares that a value may be displayed; it does not make a value safe to display. Template bodies and secret files are read when each model is frozen and again at run time, as without a variables file.

20. Remote argv contract

command represents program + argv, not a shell command string.

Remote execution must preserve exact argv values without unintended shell evaluation.

Limited exception (FS-2, §23.5). The staging, publication and cleanup of a file or a link run as steps of one fixed shell script that is a constant of the Sinter binary (`src/fsstage.sh`, run as `sh -c <script> sh <operation> <arguments…>`). It is the only shell script Sinter sends to a target. The text is never built at run time, never extended, and is not a way to run a recipe's shell: every value reaches it as an argument, so no value can become shell syntax. A test pins the SHA-256 of the script, and the command log names it by that digest instead of repeating it. Nothing else in Sinter uses a shell string; this exception does not widen the argv contract anywhere else.

The implementation may choose its encoding mechanism internally.

Acceptance tests must include:

empty argument

spaces

single quote

double quote

newline

$()

semicolon

leading hyphen

Unicode

NUL bytes are rejected during validation/runtime value construction.

program must be an absolute path in v0.1.

21. sudo contract

v0.1 supports root escalation only.

Privilege escalation is enabled only by the invocation-level CLI flag:

--sudo

Without --sudo, every target-side resource observation, mutation, verification, command, and handler runs as the connected/local target execution user. Sinter never retries a permission failure with sudo.

With --sudo, every target-side resource observation, mutation, verification, command, and handler runs with effective UID 0 through the root privilege boundary using non-interactive sudo -n.

Sinter asks sudo for root explicitly: every wrapped command is sent as `sudo -n -u root -- …`, over SSH and locally alike (a target user that is already root is not wrapped; see below). Without -u root, sudo runs a command as the sudoers `runas_default` user, which is root only by default; a site that sets another user would make every command run as that user while Sinter treats the run as root. With -u root, sudo either runs the command as root or refuses it; a refusal is never turned into running the requested operation as another user, and nothing is retried through sudo (the only command that can follow a failed first command is the read-only diagnostic described below, run without sudo as the connected user only to word the error; the run still stops). A refusal of the first command (the connect probe) is reported at connect (see below) and nothing is applied. A rule that allows root for some commands only is refused at connect when it does not allow that first command; when it does, a later command that the rule does not allow fails like any other command failure. The user's sudoers rule must therefore allow running commands as root. Checked on real hosts (Ubuntu 24.04 with sudo 1.9.15p5, Rocky Linux 10.2 and 9.8 with sudo 1.9.17p2, Ubuntu 26.04 with sudo-rs 0.2.13; the sudo command line on all four, Sinter itself on all but Rocky Linux 9.8): a NOPASSWD rule with `(root)`, `(ALL)`, `(ALL:ALL)` or `(#0)`, or with no Runas_Spec when `runas_default` is root (its default), runs the command as root; `(ALL) NOPASSWD: ALL` did so also with `targetpw` or with `rootpw` set (the other forms were not combined with them). When `runas_default` is another user (sudo 1.9; the visudo of sudo-rs 0.2.13 rejects `runas_default` as an unknown setting), a rule with `(ALL)` is not refused and the command runs as root; a rule that allows only another user, or a rule with no Runas_Spec, is refused. Other sudo versions, other sudoers features (such as `!authenticate`, `requiretty` or LDAP sudoers) and other locales were not checked, and nothing is claimed for them. What Sinter guarantees is the request it makes (the argument vector); it does not measure the effective uid of a wrapped command, and the --sudo flag by itself is not a measurement of any uid. Only the connected user's uid is measured, without sudo, to learn whether there is anything for --sudo to add (next paragraphs).

This rule applies even when a particular operation would not otherwise require root privilege. For example, a command resource executing /usr/bin/id -u under --sudo must observe effective UID 0.

Controller-side work remains under the controller process identity. In particular, parsing, include loading, local source-file reading, template rendering, planning logic, and output rendering are not made root merely because the target invocation uses --sudo.

A target user that is already root (effective UID 0 on the target, learned from the target and never from the controller) is already the identity --sudo asks for. Sinter then runs every target-side operation directly, without sudo and without needing a sudo executable, under exactly the same environment and working directory contract, whether or not --sudo was given. --sudo is accepted there and changes nothing else; in particular the backup store location follows the flag as before. Conversely, whether an operation needs root (for example user password_hash) is decided by the effective identity of the target operations, not by the flag: it holds for a root login and for --sudo.

There is no per-resource sudo field, automatic privilege escalation, or permission-denied escalation in v0.1, and no mixed target execution identity except the one case of §23.2: for a managed filesystem path inside an unprivileged account's directory tree, Sinter's own file operations on that path run as that account (never commands, handlers, packages, services or any other resource kind), and never as anyone with more privilege than the invocation. The only thing Sinter reads about the target user's privilege is its effective user id, once per invocation, and only to know whether --sudo has anything to add; it never selects, probes for or changes a privilege.

When the first command through the sudo -n wrapper fails, Sinter names a cause only when sudo's own sentence names it: sudo not installed, sudo asking for a password, or sudoers refusing the user. On the hosts checked, sudo 1.9 under `-n` says "a password is required" for a rule that needs a password and also for a user without a rule, for a rule that allows only another user or only other commands, and for a rule without a Runas_Spec under a non-root `runas_default`; sudo-rs says "interactive authentication is required" for a rule that needs a password and words the cases tried (no rule, a rule for another user only, a rule for other commands only) as a refusal (`I'm sorry <user>. I'm afraid I can't do that`). The classic refusal wording (such as "is not allowed to execute" or "is not in the sudoers file") is recognized too but was not seen under `-n` on those hosts. The mere presence of stderr, or its absence, names nothing, because that command failing on its own looks the same as the wrapper failing. For any other failure that completed, Sinter runs one diagnostic without sudo, only on this failure path: the same read check as the plain target user. If the user can read the file, the failure lies in running through sudo and its cause is reported as not identified, with no statement about the operating system; if the user cannot read it either, it is reported as an unreadable /etc/os-release; any other answer is reported as not settled. A command that did not complete is reported as that. The diagnostic is not a retry through sudo: it uses no privilege and asks for no password. What a command wrote to stderr is never copied into a message; only the exit status or signal is. Sinter never asks for a password and never retries.

plan may note, on a planned change, that it needs root when the target user is not root and --sudo was not given (a package, user or group change; creating, replacing or removing an entry in a directory the target user cannot write). The note is information only: it adds no status, field or exit code, runs no command beyond the observations plan already makes, and is omitted whenever the fact is not certain.

Privileged target operations use non-interactive sudo, asked for root explicitly (sudo -n -u root).

No TTY-dependent password prompt is supported.

The environment contract is:

command resources use only the fixed baseline environment defined in §10.6 plus explicit non-reserved recipe env

controller, SSH-session, sudo, login-shell, and arbitrary target-user environment variables are not inherited

Sinter does not depend on caller PATH for privileged executable identity where a fixed absolute program is required

cwd follows the deterministic §10.6 rule

recipes must not assume arbitrary caller shell initialization

Failure to obtain root privilege is a hard error before privileged mutation.

22. Timeout contract

Every remote or command operation is bounded.

Command default timeout: 300 seconds.

If timeout occurs after remote dispatch and Sinter cannot prove the remote operation did not execute:

execution = indeterminate

Sinter stops and does not retry.

Terminating the local SSH client process is not treated as proof that the remote process stopped.

Captured stdout and stderr each have a fixed v0.1 maximum of 1 MiB.

23. Filesystem trust boundary

Sinter v0.1 applies a parent-path trust check to every managed filesystem mutation, privileged or unprivileged.

Trusted principals are:

root

for a non-sudo invocation, the target execution user

Every parent path component must be demonstrably non-writable by principals outside that trusted set under effective Unix permission/ACL semantics available on the reference platform.

For a --sudo invocation, root is the only trusted principal for privileged publication paths.

If Sinter cannot inspect effective writability or security metadata needed to establish this property, the operation is rejected before mutation. "Could not inspect" is never treated as "not present" or "safe".

Sinter does not claim safety against a hostile root administrator.

Parent symlinks are rejected for all managed filesystem mutation paths in v0.1.

One kind of directory that others can write is accepted as a parent: a shared directory (§23.4), the sticky directory owned by a trusted principal such as /tmp and /var/tmp. A directory that others can write without the sticky bit, or that another account owns, is still refused.

The final path component is inspected without following an unexpected symlink.

These checks apply to:

read

create

replace

chmod

chown

delete

link manipulation

23.2 Another account's directory tree

The rule above refuses a parent owned by an account that is neither root nor, for a non-sudo invocation, the target execution user. For an invocation that is root (a root login, or --sudo) Sinter supports exactly one extension, so that a recipe such as a directory /home/mogemoge/page owned by mogemoge needs no option and no --sudo:

The path is inside the tree of account U when the first untrusted ancestor D of the path is a directory owned by an unprivileged uid U (not 0), every ancestor above D is trusted by the rule of §23 (a shared directory of §23.4 above D counts as trusted: D may be an entry of /tmp, in which case the rule for such a D below applies), D is not group- or other-writable and carries no extended access metadata, no shared directory lies below D, and no ancestor below D is a symlink or is owned by a third uid.

Inside the tree of U, every file operation Sinter performs on the path after the parent walk (observing, creating, writing, renaming, chown, chmod, removing) runs as U: real, effective and saved uid and gid are U's, supplementary groups are U's, capabilities are dropped and no_new_privs is set (setpriv from util-linux; if it is missing the operation fails, nothing is done as root instead). U's primary group is taken from the account database, never from the group of D. A hostile U can therefore redirect Sinter only to what U can already write itself.

Because the operations run as U, only entries owned by U are supported in the tree: a new entry without a recipe owner belongs to U (except in a tree directly inside a shared directory, where an `owner` is required: see below) and its group is U's primary group; an owner other than U, or an existing entry owned by someone else that would have to be preserved, is refused in plan and in apply with the same reason, and nothing is handed to another uid. An account without an entry in the account database and a second foreign owner below D are refused; a backup of a path in such a tree is refused except for the regular file of §40.7. A non-root invocation is not changed: its trusted principals remain root and the target execution user.

A tree directly inside a shared directory (FS-3 C-1). When D is itself an entry of a shared directory (§23.4: /tmp, /var/tmp), any local account could have made D before the recipe's author did, and nothing says it is the directory the recipe means. What Sinter wrote there would belong to U, and U could read it and replace it afterwards; with `owner` left out the recipe gives nothing to compare U with. Sinter therefore manages an entry in such a tree only when the recipe sets `owner`: an entry that would be created, replaced or changed (a file or template, its content or its metadata; a directory, new or with changed metadata) without an `owner` is refused in plan and in apply with the same reason, before anything is written, even when the entry already exists and belongs to U (U may have made it too). An `owner` other than U is refused as above, so a squatted directory is refused for any owner but its own account's; with `owner` equal to U the operation runs as U as above. The check is made where a change is decided with the owner the recipe asked for: an entry that already matches is not a write and is not refused, and audit, which never writes and does not manage an owner that is not named, is unchanged. A link and `state: absent` carry no content and have no owner: they run as U as before. The refusal says how to proceed: make the directory with a directory resource (it is then root's, and a directory another account made first is refused as a directory by the entry gate, §23.4), or use a root-owned location such as /opt or /srv. A sensitive resource's refusal names neither the path nor a uid. Paths below /home/<user> and below any other directory that is not an entry of a shared directory are not affected.

Observation follows the same order in plan, apply and audit. The parent walk is the first thing done for a path and is always the invocation's own: it reads only the ancestors, never the path. A path is observed (its type and metadata, a link's target, a content digest) only through a parent chain the walk accepted, and inside the tree of U that observation is done as U like every other operation there. So nothing of a path that another account controls is ever read as the invocation, and nothing only the invocation could read can be reached through it. When the parent chain does not exist yet, the path is absent (nothing was read), so a directory planned earlier still lets a file below it plan as a creation. When the walk refuses the parent, nothing at the path is observed, whether or not a change would be needed: plan reports the refusal apply would give, or leaves the resource Unknown, with that reason, when an earlier planned change could alter what the walk saw; audit reports an observation error (never drift) and reads nothing behind the refused parent. Paths in one directory share one walk until something is mutated. Each resource starts as the invocation's own identity again. This does not apply to the guard paths (`creates`, `removes`) of a command resource, which are not managed paths and are still read as the invocation.

23.3 Explicit trust exception (DEFERRED / NOT IMPLEMENTED)

Status: DEFERRED / NOT IMPLEMENTED. Nothing in this section is part of the contract, the parser, the CLI or the engine, and no syntax is reserved.

Principle. Sinter does not ask for options to do what Linux lets an account do safely. Ordinary operations in an unprivileged account's tree (§23.2) and in sticky shared directories such as /tmp and /var/tmp are to work without any exception, apart from the owner a tree directly inside a shared directory needs (§23.2, FS-3 C-1). A future, explicit exception is considered only for a legitimate operation that Sinter's conservative safety decision still refuses on a host the operator administers.

Candidate notation (undecided, not a specification, not a YAML or parser form): a single line such as `trusted: on`.

Requirements for such a mechanism, if it is ever built:

- one line for the operator, without describing parent directories, owners or operation kinds; the detailed verification stays inside Sinter;
- not needed for ordinary operations;
- not an unconditional force: Linux permissions, symlink attack protection, time-of-check/time-of-use protection and path boundaries stay in force; which refusal conditions may be relaxed is decided when it is designed;
- independent of the authority to run a recipe and of authorization of external callers such as MCP.

Timing. Not now. FS-2 (§23.4) is done; first the dependency items are fixed. Only if refusals remain that ordinary fixes cannot resolve is the need reassessed; if there is no need, it is not implemented.

23.4 Shared directories

A shared directory is a directory that a trusted principal owns (root; for a non-sudo invocation also the target execution user), that has the sticky bit, and that group or others can write: /tmp, /var/tmp, /dev/shm. It is accepted as a parent without any option, and the properties are judged, not the path. It is not accepted inside another account's tree (§23.2), when another account owns it, or when the sticky bit is missing.

What the sticky bit guarantees is only that an account cannot remove or rename an entry it does not own. An entry owned by a trusted principal therefore cannot be replaced by anyone else. It does not restrict creation (any account can take a name first), it does not make the content of another account's entry safe to read, and it does not stop an account from linking a file it cannot read into the directory when the kernel allows that. Sinter relies on nothing else: not on protected_symlinks, protected_hardlinks or protected_regular.

Entry gate. When the direct parent of a managed path is a shared directory, the entry itself is judged first, by lstat (a final symlink is never followed), in plan, apply, audit and backup:

an absent entry passes;

an entry owned by anyone but a trusted principal is refused, whatever its type: it is not read, changed or removed, and a `state: absent` does not remove it;

a regular file with more than one hard link is refused: the other name may lead to a file nobody should read through this path.

The observation of the entry itself (type, owner, mode, size) is that gate lstat, not a second one: what plan and audit report about an entry directly in a shared directory is the metadata of the entry the gate judged, never of one that appeared after it. A read of its content or link text runs the gate again first, and is not made at all for an entry that was absent when the gate looked. Before a change or a removal, apply looks at the entry once more and refuses, as drift, if it is not the object that was observed (another inode, owner or type).

The refusal is the same in plan (exit 4, or Unknown when an earlier planned change could alter the path), apply (failed, nothing touched) and audit (an observation error, never drift); a sensitive resource names neither the path nor the uid. A file with more than one hard link stays refused, and the message says how to find the other names. The gate applies only to the entry directly in a shared directory: below a directory of another account the operations run as that account (§23.2) and the gate does not apply. The directory of another account itself, as the managed path, is refused by the gate; the paths below it can be managed when the recipe sets `owner` (§23.2, FS-3 C-1: the directory may be one that account made before the author did).

Ownership. In a shared directory Sinter manages only entries owned by a trusted principal. A recipe that asks for any other `owner` there is refused in plan and apply with the same reason, because the entry would be refused on the next run. (Below a directory of another account the rule of §23.2 applies instead.) `group` is not restricted.

Publication. A new file or template in a shared directory is published exclusively: the content, owner, mode and extended attributes are fixed on a private staging file, which is then hard-linked at the final path (`ln -T`, link(2)). The link fails with EEXIST if anything is there, and nothing is replaced, followed or fallen back to: a name another account took first leaves that entry untouched and the resource fails. The staging directory is made, proven, filled, published from and removed by the steps of the fixed staging script (§23.5), not by commands that name it again. An existing entry of a trusted principal is replaced by a rename, which is safe because nobody else can replace it. A new link is created with `ln -sT`, a new directory with mkdir, both of which fail on an existing name and never create anything inside a directory the name points to. A file system without hard links cannot create files in a shared directory.

SELinux and file systems. The staging directory is made inside the shared directory, so staging and final path are on the same file system (checked before anything is written) and link(2) needs nothing else. The security context of a new file is the one the policy gives a file created in that directory; the context of a file that is replaced is copied to the replacement as before (§24.3), and a hard link keeps the context of its inode. Sinter does not relabel anything. Whether that context is right for the final name under an enforcing policy is a matter for the real target and is not asserted here.

Backup. A file or a link directly in a shared directory is backed up after the gate, as any other path. A directory directly in a shared directory is refused before anything is read or made for it: the gate judges the directory only, and the recursive copy would read, as root, what other accounts put below it. A directory anywhere else is backed up as before.

Concurrency that this does not cover: a process with CAP_FOWNER (root) that removes the entry between a check and the operation, at the moment another account takes the name. Sinter does not defend against a hostile root.

23.5 Staging, publication and cleanup script (FS-2, I4/I5)

Why. Staging a file in a directory that others can write, with separate commands that each name the staging directory again (`mktemp`, `chown`, `chmod`, `dd`, `mv`, `rm`, `rmdir`), lets another account swap the name between two commands, so a later command works on something the first did not make. Measured on a real host this succeeds (a separate-command sequence redirected 114 of 1500 runs, `find -execdir` 161 of 1500). It is the same cause everywhere the staging name is used again, and it is closed only by one process that opens the directory once and keeps working on the open directory. That process is the fixed script of §20.

Steps. `stage <dir> <dir-id|-> <mode> <uid> <gid> [xattr-name xattr-value…]` (content on standard input) and `stagelink <dir> <dir-id|-> <target>` make the staging directory `.sinter-stage.XXXXXXXX` in `<dir>`, prove it is Sinter's own before anything is written, fill it, and leave it in place, answering `<name> <group> <dir-id> <payload-id>`. `publish <new|replace> <file|link> <dir> <dir-id|-> <name> <group> <dir-id> <payload-id> <base>` proves the directory again, gives the payload the final name `<base>` in the pinned `<dir>` (`new`: `ln -T`, which fails with EEXIST and replaces nothing; `replace`: `mv -T -f`), and removes the staging directory. `discard <dir> <dir-id|-> <name> <group> <dir-id>` proves the directory and removes it without publishing. `<dir>` is opened once as file descriptor 4 and the staging directory once as descriptor 5; the final name is `/proc/self/fd/4/<base>` and every other name is relative to the staging directory that was entered. No step resolves the staging name again as a path.

Identity of the staging directory. As root it is the random group G (3.0e9 to 4.0e9) the directory was created with (`setpriv --regid G --clear-groups mktemp -d`): the kernel gives it that group at creation and no other directory can be given it by anyone who is not root. The script enters the directory and checks owner, group G, mode 0700, that it is empty and that it is the directory the name leads to, before it writes. Later steps check owner, G and the recorded device:inode. As an unprivileged account (a non-sudo login, or the account of another user's tree, §23.2) there is no such attribute, so staging is refused unless the directory is one nobody else can rename entries in. The script refuses, before anything is written to it (exit 3, a `REJECT:` line on standard error; a refusal that comes after the staging directory was made leaves that empty directory behind and says so — nothing is removed on a refusal): a directory with the setgid bit (a directory made in it inherits its group, so G could not identify it — this refusal is of this staging only, not of setgid directories, which every other operation manages as before), a root run without `setpriv` (util-linux), and an unprivileged run in a directory others could change.

A directory nobody else can change (`trusted_dir`). Its owner is root or the account the script runs as — the owner of a directory can rename or unlink any entry in it, with or without the sticky bit, so a directory of any other account never qualifies — and either it has the sticky bit (another account then cannot rename or unlink an entry it does not own, and the staging directory is owned by the script's account) or neither group nor others can write to it (the group digit also covers an ACL mask). The mode is read as four octal digits; a mode that cannot be read is not trusted.

Cleanup. The payload name is removed first, and the staging directory is removed by name only if its parent is such a directory, by `find -P . -maxdepth 1 -name <name> -type d -user <me> (-gid G | -inum N) -empty -delete`, a single traversal that removes at most one empty directory and never follows a symlink. In any other parent the empty staging directory is left and reported. Whether the staging directory is gone is read from the directory the script holds open (its link count is 0 after removal), never from a name: a name can be missing because the directory was moved, and present because another account created one. The staging directory is held open, so its inode number cannot be reused while the script runs.

Answer. The exit code is the primary outcome only: 0 done, 3 refused (no existing entry changed or removed, nothing published; a `stage` refused after its directory was made leaves that empty directory), 4 the publication itself failed (nothing published), 5 the operation is done but a second name of the payload remains or the cleanup state is unknown; any other code means a step failed — for `publish` that is indeterminate, because only 3 and 4 prove that nothing was published. The directory argument must be an absolute path. The last line of standard output is the cleanup result: `CLEANUP:clean`, `CLEANUP:left:<path>` (an empty staging directory is still there, possibly under another name), `CLEANUP:link-remains:<path>` (the payload could not be removed: a second name of the file stays in the staging directory), or `CLEANUP:unknown`. Anything else is read as `unknown`.

Results. Sinter keeps the publication result and the cleanup result apart. `clean` and `left` never undo a publication: the resource succeeded, and `left` adds a note with the path. `link-remains` and `unknown` after a publication are a failed resource with `change: changed` that names the path (the file is published; a person has to look). A refusal, a failed staging step and a failed publication are failures with `change: none`, with the cleanup result in the reason. A step that was lost (signal, indeterminate completion) is indeterminate and is not followed by any cleanup that could destroy evidence. A staging directory that was left is never removed by a later run or by an automatic sweep: it is reported by path.

What this does not claim. Between the moment the script reads a candidate and the moment `find` removes it (microseconds inside one traversal) the name could in principle be swapped. This needs the ability to rename entries in the parent, which a trusted parent does not give another account; the reach of such a swap is one empty directory that matches owner, group or inode. A hostile root, and a hostile owner of a trusted parent, are outside the model (§23.4). The script's behavior was verified on Rocky Linux 10 (bash as `sh`, coreutils 9.5, findutils 4.10); dash, busybox, older coreutils, POSIX ACLs and network file systems were not exercised on a real host.

24. File metadata contract

24.1 Existing regular file

If owner/group/mode are omitted, Sinter must preserve the existing owner/group/mode across content replacement.

If explicitly specified, Sinter manages them.

24.2 New regular file

Defaults when omitted:

owner: effective target user for unprivileged path, root for privileged path

group: primary group of that owner

mode: "0644"

A recipe should specify more restrictive mode for sensitive files.

If the resource is sensitive, or its evaluated content/template output is sensitive, and mode is omitted for a new file, default mode is "0600".

This derived sensitivity rule applies even when the resource's explicit sensitive field is false.

24.3 Publication metadata

Before a new/replacement file becomes visible at the destination path, Sinter must establish the final access-control metadata necessary to prevent a temporarily over-permissive file.

At minimum this includes mode and ownership that are managed or required by the defaults above.

24.4 Unsupported security metadata

For v0.1, before replacing an existing file Sinter must determine whether security-relevant ACL/xattr/SELinux metadata that can affect access or labeling is present on the reference platform.

If such metadata is present and cannot be safely preserved, Sinter refuses content replacement.

If Sinter cannot perform the required inspection, it also refuses content replacement.

It must not silently treat inspection failure as absence or silently discard security-relevant metadata.

24.5 Atomic publication

Regular-file content replacement requires same-filesystem atomic rename semantics.

If Sinter cannot provide atomic publication, it fails.

There is no non-atomic fallback.

Atomic visibility is required.
Full power-loss crash durability is not guaranteed unless separately documented.

24.4 Pre-publication validation (file, template)

A file or template resource may declare an optional validate block:

program: required absolute path of the checking program
args: optional list of strings
timeout_seconds: optional integer, default 300

Apply runs `<program> <args...> <staged payload path>` as the operation's own identity, argv-only (no shell), against the staged file the fixation step produced in the private staging directory (§23.4). It is never run against the production path, and it runs after staging and before the publication step, so the destination cannot have been changed yet.

Exit 0 permits publication; the ordinary publication then proceeds unchanged. A non-zero exit, a signal, or a transport failure before completion refuses the content: the staged object is discarded and nothing is published (failed, change none). A timeout or lost response is unresolved: nothing is published and no cleanup runs that could destroy evidence (indeterminate, change none — the publication was provably not dispatched).

The command is a validator, not an apply step: Sinter never carries its stdout/stderr into the result for a sensitive resource, and the production path is never named in a sensitive resource's reason. No tool-specific adapter exists; the recipe names the program and its arguments. Without validate, behavior is unchanged.

25. Safe file replacement

Required conceptual sequence:

validate trusted parent path

lstat final object

capture state required for managed/unmanaged metadata preservation

create a protected staging object on the destination filesystem

write complete bytes

establish required publication metadata

revalidate protected parent/final-path assumptions

atomically rename into place

apply only metadata that is safe after publication

re-observe and verify desired state

clean staging artifacts

Failure to clean an unpublished staging artifact is reported as an apply failure without rolling back an already verified published destination. If publication and verification succeeded, the result must still truthfully record change=changed and the cleanup failure.

For SSH + sudo, Sinter must not use an unprivileged staging file that remains replaceable by that user and then ask root to trust it.

The exact safe staging protocol is an internal implementation choice, but the above property is mandatory.

26. Filesystem resource semantics

26.1 file

Fields in with:

path: required static absolute path

state: present | absent, default present

content: optional UTF-8 string

source: optional controller file path

owner: optional static user name or numeric ID

group: optional static group name or numeric ID

mode: optional quoted four-digit octal string

content and source are mutually exclusive.

If state=present and target is absent while neither content nor source is supplied:

Sinter creates an empty file using new-file metadata defaults.

If state=absent:

absent target => unchanged

regular file => remove

any other object type => fail

Relative source is relative to the declaring recipe file.

26.2 directory

Fields:

path: required static absolute path

state: present | absent, default present

owner/group/mode optional

If state=present:

absent => create exactly that directory, parent must already exist in v0.1

new-directory defaults when omitted: owner = effective target user (root under --sudo), group = that owner's primary group, mode = "0755"

directory => manage requested metadata

other type => fail

If state=absent:

absent => unchanged

empty directory => remove

non-empty directory => fail

other type => fail

No recursive creation/removal in v0.1.

26.3 link

Fields:

path: required static absolute path

target: required string when state=present

state: present | absent, default present

Parent must already exist.

If state=present:

absent => create symlink

symlink to same target => unchanged

symlink to different target => replace symlink atomically; if atomic replacement cannot be provided, fail with no non-atomic fallback

non-symlink => fail

Relative symlink targets are allowed and interpreted exactly as filesystem symlink targets, relative to the link's parent.

If state=absent:

absent => unchanged

symlink => remove

non-symlink => fail

26.4 template

Fields:

same managed destination fields as file

source: required

vars: optional map of literal values exposed under template.<name>

Template-local values do not shadow global namespaces.

Rendering happens on the controller.

Template functions are limited to interpolation and the small expression/value access model documented by Sinter.

Only {{ expression }} interpolation is rendered; \{{ is a literal {{. A Jinja statement tag ({% ... %}) or comment tag ({# ... #}) is not supported: an opener outside an interpolation that is followed by the closer of its own kind (%} for {%, #} for {#, outside any interpolation) before another opener of that kind is a validation error naming the resource, the source file and the line and column, and is never published verbatim. An opener with no such closer is plain text and is published as written; so is a {# directly after $ (a shell ${#var}). A literal {% is written {{ "{%" }}.
No arbitrary function execution exists.

Published output uses the file replacement contract.

27. Package resource

Reference implementation: Ubuntu 24.04 apt.

Fields:

name: required static package name

state: present | absent, required

v0.1 does not support version pinning.

Plan:

queries installed package state only

does not run apt update

Apply:

present: install only if absent

absent: remove package only if installed

package purge is not performed

apt never refreshes repository metadata. On dnf an install runs cache-only
against a private snapshot of the target's metadata cache (mode 0700, under
/var/tmp), and the snapshot is never the live cache. When an enabled
repository has no cached metadata (a host that has never run dnf, or a
repository added since the last refresh), Sinter populates the target's own
metadata cache once — the operator's `dnf makecache`, fetching only absent
metadata (metadata_expire=-1) and downloading no package payload — then
rebuilds and re-verifies the private snapshot; a repository that still
cannot be made complete fails closed before any package mutation. Whether a
payload's signature is trusted remains dnf's and the repository's business
(gpgcheck), and every transaction payload is identity-verified from its rpm
header before the cache-only install runs.

Package observation distinguishes cleanly installed, absent, and unsupported/inconsistent states.

If dpkg/apt reports a half-configured, unpacked-but-not-configured, broken, or otherwise non-clean state, v0.1 fails and does not attempt automatic repair.

Sinter does not run an explicit apt lock retry loop. Each apt mutation is bounded by the general operation timeout of 300 seconds; a lock-related non-success or timeout is reported according to normal failure/indeterminate rules.

Package maintainer scripts may have side effects outside Sinter's complete predictive control.

27.1 Recipe-wide default environment

A recipe may declare a top-level env map of strings. It is a base for the environment Sinter gives to package and command resources — the only resources that run an external process with an environment. It is never passed to a connection step, a package or service query, a file operation, or a service management command.

Precedence is per variable name: a name the resource sets in its own env overrides the recipe default; every other name of the default still applies. The default never replaces an explicit resource value. Merging happens when the resource is frozen, so the merged map is an ordinary env value: interpolation and sensitivity behave exactly as if the resource had written it (a value derived from a sensitive variable makes the inheriting resource sensitive and is redacted everywhere).

Names are case-sensitive, as on Linux; Sinter passes exactly the names given and does not fold case (HTTP_PROXY and http_proxy are distinct; dnf/apt honor both). The names PATH, LANG, LC_ALL and HOME are reserved and rejected, because Sinter always sets the baseline itself. env may be declared only in the recipe that is run, never in an included file. The inventory has no host variables (§19.2); a per-host or per-group env value is expressed by interpolating a variable whose value a variables file sets per host or group (§19.5), or with a separate recipe or include.

28. Service resource

Reference manager: systemd.

Fields:

name: required static unit name

state: optional running | stopped

enabled: optional boolean

At least one of state/enabled must be present.

Omitted fields are unmanaged.

Apply ordering when both are managed:

desired state

enabled

order

running

true

enable if needed, then start if needed

running

false

disable if needed, then start if needed

stopped

true

stop if needed, then enable if needed

stopped

false

stop if needed, then disable if needed

When only one field is managed, only that dimension is changed.

Verification checks every requested dimension after mutation.

Missing unit => fail, except in plan when the service has a direct dependency on a package resource whose planned state is present; in that one case plan reports the service as deferred/unknown until dependency apply. In apply, a missing unit after a changed package dependency is handled by the discovery reload of §28.5.

Masked unit when running requested => fail.
Static unit with enabled field requested => fail.

A systemd failed unit is not equivalent to clean stopped.

running requested: Sinter may issue one start operation; if not active afterward => verification failure

stopped requested: Sinter issues stop/reset only as required by the documented systemd adapter and must verify inactive and not failed; it does not silently report an existing failed state as satisfied.

28.1 Manager synchronization

Sinter synchronizes the systemd system manager automatically by running systemctl daemon-reload when required by §28.2. There is no resource type, handler action, or recipe option for it, and a manual daemon-reload command resource is normally unnecessary.

daemon-reload is not a restart. It reloads the manager's unit definitions; running processes keep their old configuration. Manager reload (daemon-reload), systemctl restart <unit>, and systemctl reload <unit> are three distinct operations.

Only the system manager is managed. The user manager (systemctl --user, ~/.config/systemd/user, /etc/systemd/user, user.conf) is never managed and Sinter never passes --user. Sinter does not run daemon-reexec.

28.2 Reload triggers

A reload is required when either holds:

(a) A file, template, or link resource really changes (content create/change/remove, symlink create/replace/remove) a systemd manager input:

a unit file (*.service, *.socket, *.target, *.timer, *.path, *.mount, *.automount, *.swap, *.slice, including template units such as foo@.service)

a drop-in (<unit>.d/*.conf, the type-wide service.d/*.conf form, or the prefix form such as foo-.service.d/*.conf)

an alias, mask, .wants, or .requires link

located directly in one of the manager's own unit load path roots, or the system manager configuration /etc/systemd/system.conf or system.conf.d/*.conf in the finite table /etc, /run, /usr/lib, /usr/local/lib under systemd/system.conf.d.

Sinter reads the load path roots read-only with systemctl show --property=UnitPath, parses the quoted-array output strictly, and compares paths lexically. It does not assume /etc/systemd/system. The query is made only when a managed path's file name has the shape of unit, drop-in, or link input. If it cannot be run or parsed, the resource fails before any mutation (plan: plan error). Sinter never guesses.

(b) A fresh observation (§28.4) reports NeedDaemonReload=yes for a unit the recipe uses: a service resource, the service of a notified handler, or a managed unit file or drop-in that names a single unit.

Metadata-only changes (chmod/chown), directories, ordinary application configuration, /etc/systemd/journald.conf, user.conf, and /etc/systemd/user/... never require a reload.

28.3 Enforcement points

Synchronization is enforced at three points:

before a service resource observes and decides, which is before its already-matches early return

before each notified handler runs

at the end of a successful apply, so that a unit update with no consumer is still synchronized

One reload covers every change pending at that moment. For the order unit A, service A, unit B, service B, two reloads occur, one per consumer boundary; there is no at-most-once-per-run rule. With nothing pending and NeedDaemonReload=no, zero reloads occur: a second unchanged apply issues none, and a notify restart caused by ordinary configuration issues none.

If NeedDaemonReload=yes remains after a reload, apply fails as unresolved. There is no retry loop, and at most one reload occurs per cause (pending input, observed staleness).

28.4 Observation

Service and handler observation requests exactly four properties, each exactly once: LoadState, ActiveState, UnitFileState, NeedDaemonReload (systemctl show --property=LoadState,ActiveState,UnitFileState,NeedDaemonReload -- <unit>). Missing, duplicate, invalid, or truncated properties, non-zero exit, and non-UTF-8 output are failures; NeedDaemonReload is never defaulted to no.

After a reload the service is re-observed, and only that fresh state decides start, stop, enable, and disable. enable and disable keep systemctl's own native implicit reload (Sinter does not use --no-reload), and Sinter observes again after them before deciding whether start is still needed.

28.5 Package boundary

Apply never reloads merely because a package changed. If a changed package that the service explicitly depends on (state present) leaves the unit not found, Sinter performs exactly one discovery reload and re-observes. If the unit is still not found, the service fails with no retry.

28.6 Plan and audit

plan is read-only. It never runs daemon-reload, enable, disable, start, stop, restart, or reload. If an earlier resource in the plan changes managed systemd input (§28.2 (a)), or the manager currently reports NeedDaemonReload=yes (observed only), later service resources are reported unknown/deferred (status ?, reason deferred/unknown until manager synchronization at apply), not unchanged and not failed. The reloads apply would perform are reported separately (§28.8) with phase planned, execution not_run, and unknown true. Pending handlers are listed as before; no handler IDs are invented.

audit is read-only and never reloads. Manager synchronization is an independent drift dimension, manager_reload (observed: daemon-reload pending (NeedDaemonReload=yes); desired: manager synchronized). It is reported on a service resource even when active and enabled match, and on a managed unit file or drop-in resource that names a single unit. It is separate from content/mode/owner drift and from state/enabled drift. NeedDaemonReload=yes is never treated as repaired. NeedDaemonReload=no is a limited observation, because systemd compares mtimes and paths, not content hashes; it is never presented as proof that the loaded definition equals the bytes on disk. A managed input that cannot be mapped to one unit (a template, a type-wide or prefix drop-in, system.conf) is reported with a note that manager consistency is not verified. An unobservable NeedDaemonReload or UnitPath is an observation error (aggregate indeterminate), never no_drift. link resources have no manager facet in audit.

The commands allowed in audit gain exactly two read-only shapes: systemctl show --property=LoadState,ActiveState,UnitFileState,NeedDaemonReload -- <unit> (replacing the former three-property shape) and systemctl show --property=UnitPath.

28.7 Failure semantics

daemon-reload exits non-zero => failure. The dependent service resource or notified handler does nothing (no start, enable, restart, or reload). Earlier successful file, template, and link results stay changed, nothing is rolled back, and the reload is never retried in the same run. Aggregate status is apply_failed.

Timeout, signal, or lost response => indeterminate. It is never reported as success nor as unchanged. Aggregate status is indeterminate.

Reload succeeded but the fresh observation failed => the reload is kept in the report as executed and changed, and the consumer fails (verification failed).

A run that stopped (earlier failed or indeterminate resource, or a failed handler) does not start a new reload. If managed input had changed, the report states that the reload was not run and the manager is unsynchronized; the operator re-applies or runs systemctl daemon-reload manually. Sinter keeps no persistent journal, so it cannot remember across runs that a previous apply stopped before its reload; a later run reloads only when it observes NeedDaemonReload=yes or makes a new change.

28.8 Reporting

plan and apply JSON documents carry a top-level manager_reloads list, always present and possibly empty. Each entry has: phase (resource, handler, final, planned), trigger (pending_input, observed_stale, package_discovery), causes (resource IDs), consumer (service resource ID, handler ID, or null), execution, change, verification (existing value sets of §15), unknown, sensitive, and reason. Text output has a manager reloads (systemd daemon-reload) section. For sensitive causes or consumers the reason is redacted; unit names, paths, and stderr never appear for sensitive resources.

The closed enumerations of §15 (execution, change, verification, disposition), the handler states, and the aggregate statuses are not extended. Exit codes are those of the existing statuses (apply_failed, indeterminate).

28.9 Limits

A reload acts on the whole system manager: it also loads other pending on-disk edits and re-runs generators, and it does not restart services.

systemd rate limits (ReloadLimit*) and authorization can make a reload fail.

NeedDaemonReload cannot see an external edit with the same or a backward mtime.

Path comparison with UnitPath roots is lexical. Aliases such as /lib versus /usr/lib are not equated, and an unrecognized path does not trigger a reload by itself. A unit file shadowed by a higher-priority root still triggers a reload. A fragment linked from outside the load path is noticed only through NeedDaemonReload.

Reloading system.conf does not guarantee that every directive takes effect.

Behavior on each supported distribution is validated separately; this section does not itself claim that validation.

29. Plan representation of future-created state

Plan describes current observations and intended Sinter operations, but does not pretend to know external side effects of dependencies.

Example:

package resource plans installation of nginx

dependent service unit is currently missing

The service plan is reported as:

current: missing
desired: running
status: deferred/unknown until dependency apply

A service resource is likewise reported unknown/deferred when an earlier resource in the plan changes managed systemd manager input, or when the manager currently reports NeedDaemonReload=yes for it (§28.6). Plan runs no daemon-reload.

This exception applies only when the service directly depends on a package resource whose desired state is present.
Otherwise a missing service unit is a plan error for a requested service state.

Apply re-observes the service after package application. A changed package dependency that leaves the unit not found causes exactly one discovery reload (§28.5).

29.1 Refusals plan can predict

For a file, directory, link or template change it plans, plan runs the same read-only checks apply runs before the mutation, with the same predicates: the parent path trust check (§23), for a content replacement the security metadata check of the replaced file (§24), and for directory state absent whether the directory has an entry (apply removes only an empty directory; observed with find <dir> -mindepth 1 -maxdepth 1 -print -quit). A refusal is a plan error (exit 4) carrying apply's reason when no earlier resource planned in the run can change what plan observed: no earlier file, directory, link or template planned to change or unknown whose path is this path or an ancestor of it (for the emptiness check, also a path below it), and no earlier package, command, service or user planned to change or unknown, whose effect on paths plan cannot know. A command skipped now because its creates or removes guard holds counts as one when an earlier planned change can alter the guard path, since apply may then run it. A guard path with a symlinked ancestor counts as alterable by any earlier planned change, because the guard is observed through the symlink while the change may name the resolved path. A group changes no path and no input of these checks, so it defers nothing. When the recipe declares backup paths, apply creates the backup store (/var/lib/sinter and /var/lib/sinter/backups with --sudo; $HOME/.sinter and $HOME/.sinter/backups otherwise) before the first resource: plan treats the first of those directories that does not exist as an earlier planned change, and the directories that exist, the other privilege mode's store and every other path as unaffected. Otherwise the change is reported with a note and apply decides. Apply still runs every check itself.

30. Verification requirements

Stateful resources require verification after mutation.

For any state=absent filesystem resource, verification requires confirmed non-existence using non-following inspection. Inaccessible/uninspectable is not absence.

For present state:

file: path type + managed content + managed/default metadata

directory: type + requested/default metadata

link: symlink target

package: installed/absent state

service: requested active/enabled state, observed after any manager synchronization (§28.3)

template: same as file

If no mutation was needed, execution=succeeded and verification may be represented as verified from the observation that established unchanged state.

Command verification is not applicable beyond exit/result semantics.

31. Information contract

31.1 Sensitive variables

A variable with sensitive: true produces a sensitive runtime value.

31.2 Sensitive resources

A resource with sensitive: true makes all resource-specific desired values, command output, diff content, and resource diagnostics sensitive unless a field is explicitly known safe by the implementation.

Conservative redaction wins.

31.3 Propagation

Derived values are sensitive if any evaluated input contributing to them is sensitive.

This applies to:

interpolation

list/map composition

template output

comparison and boolean-expression results

command args/env/cwd if derived from sensitive data

error context derived from sensitive values

If any evaluated command input is sensitive, including program, args, cwd, or env, the entire command execution becomes sensitive. Its stdout, stderr, register value, ChangeSet details, and diagnostics are sensitive regardless of whether the command itself was explicitly marked sensitive: true.

No external-program information-flow analysis is attempted; this conservative whole-command rule is the v0.1 boundary.

Identifiers required for operation such as resource IDs must be static and must not be built from sensitive values.

Managed paths may not be built from sensitive values in v0.1.

31.4 Runtime versus presentation

The execution engine may hold sensitive plaintext in memory when required to perform the requested operation.

Presentation/serialization must use separately sanitized representations.

No logger may receive raw sensitive values.

31.5 Sensitive diff

For sensitive content:

content: changed
diff: redacted

Hashes and sizes are redacted by default.

32. Diff contract

Text diff is allowed when:

both contents are valid UTF-8

neither value is sensitive

each side is <= 256 KiB

Otherwise content difference is summarized.

Terminal control characters are escaped/sanitized before display.

33. CLI exit codes

Stable v0.1 meanings:

0: invocation completed successfully

2: validation/schema error

3: target connection/capability/security error

4: plan could not be completed safely

5: apply failed

6: apply became indeterminate

7: audit detected drift, with no observation error

8: strict audit (`sinter audit --audit-policy strict`) found not-auditable resources, with no drift and no error

Plan finding desired-state differences still exits 0.

Exit 8 exists only for `audit --audit-policy strict`. The observed audit statuses are unchanged (a not-auditable resource stays not auditable), command resources and handlers are still never run, and without the option, or with `--audit-policy default`, the exit codes are as before. Error (6) and drift (7) take precedence over 8.

With an inventory or a bundle (§19.4) the exit code is the most severe execution exit code (6 > 5 > 4 > 3 > 2 > 7 > 8 > 0).

34. Acceptance tests

Tests must include normative fixtures rather than only round-tripping two frontends.

34.1 Schema fixtures

A table of YAML/TOML fixtures must define expected typed IR for:

all common value types

omitted fields/defaults

invalid duplicate fields

invalid YAML aliases/merge

invalid TOML datetime

invalid mode

conflicting ownership

static-identifier violations

34.2 Ordering/evaluation

Tests must verify:

include depth-first declaration order

loop list order

independent resource declaration order

direct register dependency requirement

false condition

guard_satisfied versus skipped_by_condition

Unknown short-circuit table

undefined behavior

loop + register rejection

34.3 Plan safety

Using both instrumented executor and external target observation, verify plan does not:

write

rename

chmod/chown

create/delete

install/remove package

change service state

run systemctl daemon-reload

upload staging file

execute command resource

Observation implementation must itself be audited/tested not to hide mutation.

34.4 Idempotency

For file, directory, link, package, and service:

Second apply against desired state must invoke zero corresponding mutation operations.

34.5 File safety

Tests must cover:

parent symlink rejection

untrusted writable parent rejection

final symlink conflict

staging replacement attempt

metadata preservation

sensitive new-file mode default, including sensitivity derived from content

unsupported security metadata refusal

inability to inspect required security metadata => refusal

failure before publication leaves old file

failure after atomic publication reports changed + failure if later verification/metadata fails

no non-atomic fallback

Controlled failure-injection points are required around publication.

34.6 SSH/sudo

Real disposable Ubuntu 24.04 SSH target tests must cover:

without --sudo, /usr/bin/id -u reports the target execution user's UID

with --sudo, /usr/bin/id -u reports 0

files created through target operations have the owner required by the invocation/resource contract

known host success

unknown host failure

changed key failure

sudo -n success

sudo denied

privileged file read/replace/verify

special argv exactness

non-UTF-8 stdout/stderr behavior

signal termination behavior

timeout after dispatch classified indeterminate

no automatic mutation retry

34.7 Command

Tests must cover:

controller/SSH/sudo sentinel environment variables are not implicitly inherited

baseline PATH, LANG, LC_ALL, and HOME have the exact specified values

recipe attempts to override reserved baseline environment names are rejected

explicit non-reserved env values are passed exactly

default success_codes

custom success_codes

creates guard

removes guard

guard producer dependency satisfaction

non-zero failure => possible change

changed_when true/false/error

output capture overflow and refusal to treat truncated output as complete register data

sensitive env echoed to stdout/stderr remains redacted in normal, verbose, register presentation, diagnostics, and structured output

34.8 Handlers

Tests must cover:

one source change -> one handler

multiple source changes -> one deduplicated handler

no source change -> no handler

source verification failure -> no handler

fail-fast before handler phase -> handlers not run, pending list reported

handler failure -> later handlers blocked

next apply does not promise replay of lost prior notification

unrelated condition-skipped resource does not suppress legitimately queued handler execution or successful exit

34.9 Package/service boundary

Tests must cover:

inconsistent/half-configured package state => failure without automatic repair

apt lock/non-success bounded by operation timeout

all four state/enabled service combinations

failed unit is not accepted as clean stopped

missing service is deferred in plan only for direct present-package dependency

package apply followed by service re-observation, with no stale service observation reused

unit file/drop-in/link/system.conf change followed by a service or handler => one reload before the consumer, fresh four-property observation, then the action

metadata-only, directory, ordinary-config, journald.conf, and user-manager changes => no reload

unchanged second apply => zero daemon-reload invocations

unit A, service A, unit B, service B => two reloads

failed, timed-out, or unresolved reload => consumer does nothing, earlier changes stay changed, no retry

stopped run with changed unit input => reload not run and reported as such

plan and audit never reload; plan defers dependent services as unknown; audit reports manager_reload drift independently of content and state drift

UnitPath or NeedDaemonReload unobservable => failure before mutation in apply/plan, ERROR in audit

34.10 Result truthfulness

Test:

unchanged verified state

successful change

failure without mutation

failure after mutation

indeterminate mutation

blocked dependency

fail-fast blocked resource

35. Implementation stages

Stage 0:

canonical schema

YAML/TOML parsers

normative IR fixtures

static validation

expression semantics tests

Stage 1:

execution capability boundary

LocalExecutor

SshExecutor

known_hosts policy

sudo -n

disposable Ubuntu 24.04 target

Stage 2:

file resource

path trust checks

safe staging/publication

metadata preservation/defaults

sensitive model

ChangeSet

validate/plan/apply vertical slice

Stage 3:

directory

link

template

Stage 4:

apt package

systemd service

sequential re-observation

Stage 5:

variables

facts

when

static loops

includes

Stage 6:

command

guards

register

Unknown

Stage 7:

dependency hardening

delayed service handlers

fail-fast/indeterminate integration

Stage 8:

CLI polish

full acceptance matrix

documentation

v0.1 release audit

36. Implementation-agent prohibitions

An autonomous implementation agent must not:

invent alternate schema

keep legacy recipe syntax

silently ignore fields

use YAML/TOML-specific semantics

make target identifiers dynamic

execute commands during plan

run systemctl daemon-reload, or any other service/manager mutation, during plan or audit

use systemctl --user or manage the user manager

guess systemd unit load paths instead of reading UnitPath

treat NeedDaemonReload=no as proof that the loaded definition equals the file on disk

treat Unknown as false, skipped, or unchanged

reuse stale plan observations during apply

infer success from SSH client termination

retry indeterminate mutations

use interactive sudo

enroll unknown SSH keys automatically

disable host-key verification

truncate managed files in place

use non-atomic fallback for file publication

trust an unprivileged staging file during root publication

follow privileged parent symlinks

discard unsupported security metadata silently

change omitted owner/group/mode on existing files

make recursive directory deletion implicit

add shell as a separate v0.1 resource

add generic handlers, roles, plugins, orchestration, or scripting (amended 2026-11-01: the restricted, data-only Resource Plugins of §38 are the one exception to "plugins"; everything else in this line is unchanged)

let a plugin definition name a program, argv, environment, working directory or standard input (§38.3)

run a plugin operation through any channel other than the two of §38.8, or a mutate operation without the mutation permit

accept a capability catalog that is not a reviewed first-party catalog of the release (§38.4)

present an attested observe operation as technically proven read-only (§38.13)

add inventory features beyond §19.2–19.5 (no variables in the inventory file, nested groups, patterns, implicit all-hosts selection, dynamic inventory, or parallel execution; host and group variables exist only as the variables file of §19.5)

add automatic rollback or restore of §4.12 backups

introduce Rhai

classify implementation stubs as completed behavior

weaken acceptance tests to fit incomplete implementation

37. Definition of done

A v0.1 feature is complete only when:

canonical syntax exists

externally observable semantics are defined

local behavior is tested where applicable

SSH behavior is tested where applicable

plan behavior is tested

mutation behavior is tested

verification behavior is tested

failure and indeterminate behavior are tested

second-apply mutation absence is tested for stateful resources

sensitive output behavior is tested where applicable

The v0.1 release is complete only when the mandatory acceptance matrix passes on the documented reference environment.

38. Resource Plugins (E3-H)

38.1 Status

Adopted by the Owner on 2026-11-01 for v1.9.0 (GOALS §16).

IMPLEMENTED (step 1): §38.3–§38.6 and the value check of §38.9.

IMPLEMENTED (step 2): activation (§38.7), the execution channels (§38.8), result classification (§38.10), plan/apply/audit with the existing results and exit codes (§38.11) and the MCP refusal (§38.12). Verified against a scripted target only.

IMPLEMENTED (step 5): the first first-party catalog in the release registry, firewalld 0.1.0 (SHA-256 `27741bcc6b72dfbf69d918282fb454c324e7229b764873334a5c6c0af04707ff`), with its plugin definition firewalld 0.1.0 (`firewalld.service`, present only, runtime and permanent, no reload, no removal, no zone or interface change; SHA-256 `47f33f171d239103cbb97450d17b57c857ce22436620ddf809fdd2be94948544`). Both files are kept under `plugins/first-party/`. Its seven operations and their exit codes were measured directly with `firewall-cmd`, and the plugin was run through Sinter, on Rocky Linux 9.8 (firewalld 1.3.4), Rocky Linux 10.2 (firewalld 2.4.3) and Ubuntu 24.04 (firewalld 2.1.1) on 2026-11-01; the trust-file checks of §38.5 were confirmed on the same three as Linux controllers. It is not yet in a published release.

NOT VERIFIED: other OS or firewalld versions (Sinter does not check the version); the release acceptance with this registry on its other five target labels; a mutation whose outcome is unknown because Sinter's own timeout expired, on a real host (covered by tests only: with the daemon stopped, `firewall-cmd` gave up by itself and the result was a failure that may have changed something); POSIX ACLs on a macOS controller (§38.5).

UNCHANGED LIMIT: no code runs from a plugin; third-party catalogs are not supported; plugin types are not offered through MCP (§38.12); Command Audit expectations cannot use plugin types in v1.9.0.

38.2 Layers

Core: the engine, the Core-fixed rules of §38.6, the two execution channels, the mutation permit, result classification, sensitivity, provenance and exit codes. Code, reviewed and released with Sinter.

Capability catalog (data): the operations a plugin may use. Each has a program, an argv template with typed operand slots, a timeout, a closed exit-code map and, for observations, an optional closed standard-output map, and a class: observe or mutate.

Resource plugin (data): resource types made of fields, prechecks and facets that name catalog operations. A plugin is never the basis of safety.

Trust file (data, Owner): the root of trust, on the controller.

Recipe: enables plugins and uses their types.

38.3 File formats

All three files are TOML with `format = 1`; any other format number is refused before anything else is read, and unknown keys are refused.

trust.toml: `[[catalog]]` entries with `id`, `version`, `sha256`, `attested_observe` (observe operations the Owner attests are read-only) and `allowed_mutate` (mutate operations apply may run); `[[plugin]]` entries with `id`, `version`, `sha256`.

catalogs/<id>-<version>.catalog.toml: `id`, `version`, and `[[op]]` entries with `id`, `class` (`observe` or `mutate`), `program`, `argv`, `timeout_secs`, `slots` (`{ name = { class = "ident", max_len = N } }`), `exit` (exit code -> state) and, for observe only, `stdout_map` (trimmed output template -> state).

plugins/<id>-<version>.plugin.toml: `id`, `version`, `catalog = { id, version }`, and `[[type]]` entries with `name` (`<plugin id>.<name>`), `fields` (`ident`, or `enum` with `values`), `precheck` (`{ op, expect }`) and `[[type.facet]]` with `name`, `observe`, `want` (a state, or `field:<enum field>`) and `ensure` (state -> mutate operation).

A plugin file has no key for a program, argv, environment, working directory or standard input. Files must not contain secrets.

38.4 Versions, digests and first-party catalogs

Identifiers are `[a-z][a-z0-9_]*` (at most 32 bytes); versions are `MAJOR.MINOR.PATCH` without leading zeros. A plugin is used only when the trust file has an entry with its exact id and version and the SHA-256 of the exact bytes read equals that entry. A catalog is used only when, in addition, the same id, version and SHA-256 appear in the release's registry of reviewed first-party catalogs, which is compiled into Sinter. A catalog that the trust file pins but the registry does not list is refused: third-party catalogs need a separate safety review and Owner approval and are not supported in v1.9.0. The digest of a catalog is checked against the trust file and the registry before the catalog is parsed. In v1.9.0 the registry has one entry, firewalld 0.1.0 (§38.1); its file is kept in the repository and a test checks that the file's digest and the entry agree. A new catalog, or a new version of one, needs its own measurements on real hosts and its own entry.

An operation is usable only when the trust file lists it under the list of its own class (`attested_observe` for observe, `allowed_mutate` for mutate). An operation listed under the other class, listed twice, or not defined by the catalog is an error; an operation the catalog defines but the trust file does not list loads and stays disabled.

38.5 Plugin root and file protection

The plugin root is a controller directory holding trust.toml, catalogs/ and plugins/. Its location comes only from the operator's configuration (§38.7), never from a recipe, a plugin file or MCP input.

The configured path is resolved once (it may contain symbolic links) and then walked again from / one component at a time without following symbolic links, so a link introduced after resolution is refused. Each check is made on the opened descriptor:

every ancestor of the root: owned by root or the invoking user, and not writable by group or others unless sticky

the root, catalogs/ and plugins/: directories owned by root or the invoking user, not writable by group or others

each file: a regular file opened without following a final symbolic link (and without blocking on a FIFO), owned by root or the invoking user, not writable by group or others, at most 64 KiB

A file is read from the checked descriptor. Its device, inode, size, modification time and change time must be identical before and after the read, otherwise the file is refused as changed while it was being read; a replacement by rename is therefore either invisible (the original bytes are used) or refused, and the replacement's bytes are never used. The digest is computed over exactly the bytes that are parsed. Every failure is a refusal (exit 2); nothing falls back. ACLs are not inspected directly. On Linux a POSIX ACL entry that grants write to another user or group shows in the group bits of the mode through the ACL mask, so the mode check refuses it (confirmed on Rocky Linux 9.8 and 10.2 and Ubuntu 24.04, 2026-11-01); on macOS ACLs do not show in the mode and are not detected. On a non-Unix controller plugins are refused.

Root ownership is not required: a root owned by the user (for example under the user's configuration directory) is accepted.

38.6 Verification rules (Core-fixed)

A data file can tighten these rules (shorter limits, fewer operations) but not loosen them.

programs: directly under /usr/bin or /usr/sbin; shells, interpreters, privilege tools (sudo, su, setpriv, pkexec, ...), remote and transfer tools (ssh, scp, curl, ...), and general file tools (cp, mv, rm, tee, dd, ...) are refused

argv: at most 16 tokens; a literal is 1–128 printable ASCII characters without spaces or braces; a whole-token slot `{name}` only after a literal `--` (which may appear once); otherwise a slot only as `--option={name}`; every slot used exactly once and declared

slots: at most 4, class `ident`, `max_len` 1–64

timeout: 1–120 seconds

exit map: 1–16 entries, codes 0–255 in canonical decimal, states `[a-z][a-z0-9_]*`; a mutate operation maps only to `ok` and has no output map; an observation with an output map maps its exit codes only to `ok`

observe lint: an observe operation whose literal tokens look like a change (`--add…`, `--remove…`, `--set…`, `reload`, `start`, ...) is refused. The lint is a denylist and supplementary; it is not the safety argument

types: `<plugin id>.<name>`, never a built-in type name; 1–16 types, 1–8 fields, at most 8 prechecks, 1–8 facets; a precheck uses an enabled observe operation and expects a state it can report; a facet observes through an enabled observe operation, wants a state that operation can report (or an enum field whose every value it can report), and has an enabled mutate `ensure` operation for every wanted state; every slot of every operation a type uses is filled by the field of the same name; enum values must fit the shortest slot they fill

enabling: each plugin at most once per run

38.7 Activation

A recipe enables plugins explicitly with `plugins: [{ id, version }]` (a non-empty list, each id once, an exact `MAJOR.MINOR.PATCH` version), in the top-level recipe only: an included file that declares `plugins` is refused. Without it nothing in §38 applies, no plugin file is opened, and every behavior is exactly as before; a type named like a plugin type is an unknown resource type. With it, the plugins are loaded and verified once, before any resource is expanded, and a resource type `<plugin>.<name>` is accepted only when an enabled plugin provides it; its fields must be exactly the type's and each literal value a valid value (a value with `{{ }}` is checked when it is evaluated, before any command for that resource runs).

The plugin root is `--plugin-root <dir>` (validate, plan, apply, audit) or, when absent, `$XDG_CONFIG_HOME/sinter/plugins` when that variable is an absolute path, else `$HOME/.config/sinter/plugins`. It is opened only when the recipe enables a plugin. Nothing in a recipe, a variables file, a plugin file or MCP input can choose it. Only the CLI provides a plugin root; every other loader (MCP, `secrets list --recipe`, library callers) refuses a recipe that enables plugins.

Controller identity: the files and directories must be owned by root or by the invoking user (§38.5). When the controller runs as root (for example through sudo), only root-owned plugin files are accepted, whatever HOME points to.

38.8 Execution channels and the mutation permit

Two channels run plugin operations: an observe channel, used by plan, audit and apply, and a mutate channel that requires the existing `&MutationPermit`. Neither accepts a program or argv: each takes a call value only the plugin module builds, from a verified operation of the matching class that the trust file enabled, with every operand checked again. There is no generic execution channel for plugins, audit never obtains a permit (unchanged), and audit refuses a mutation-capable target. Requests use the baseline environment, never a tree identity, and the run's executor (so `--sudo` applies as for every other command). The mutation permit's construction is unchanged.

38.9 Operands and sensitivity

An operand (implemented check) is 1 to the slot's `max_len` bytes (at most 64), starts with an ASCII letter or digit and continues with letters, digits, `_`, `.` or `-`; it is checked when a resource is validated and again before dispatch. It can never be an option, a list, a path, an assignment or shell syntax. A resource's values must be exactly the type's fields. Error messages name the field and never show the value. A plugin resource marked sensitive follows §31 (redacted command records, no values in output). Parser messages about data files drop quoted values.

38.10 Result classification

An observation maps an exit code listed in the operation's exit map to its state, and, with an output map, maps the trimmed output to a state only when it equals one template exactly. Anything else (an unlisted exit code, unrecognized or truncated output, a signal, an unknown completion) is an error for observations. For a mutate operation, an unlisted exit code is a failure that may have changed the target (change `possible`); a signal, a timeout, a lost connection or any transport failure after dispatch is Indeterminate (change `possible`, never `none`): the run stops (fail-fast, §17), nothing is retried, and the next run observes first. When an earlier facet of the same resource definitely changed, the change is `changed`. After a successful mutation the facet is observed again and must have the wanted state; otherwise the resource fails (or is Indeterminate when it cannot be observed). A failed precondition or observation before any mutation is a failure with no change. Standard error is never shown, and standard output only through the closed map.

38.11 plan, apply, audit, JSON and exit codes

plan and audit run prechecks and observe operations only; apply runs a facet's mutate operation only when its observed state differs from the wanted state. plan reports a pending facet as a change with a summary diff (`facet=state`) and lists the operations apply would run; an observation that fails in plan is a plan error. audit reports each differing facet as drift (dimension = facet name), and a failed precondition or observation as an error. The existing statuses and exit codes are used (§33): validation and plugin verification errors 2, plan errors 4, apply failures 5, Indeterminate 6, audit drift 7, audit errors 6, strict audit unchanged (plugin types are auditable). No JSON key is added or changed: the provenance is carried in the existing `notes` of plan/apply results and `reason` of audit results, as one line `plugin=<id>@<version> plugin_sha256=<hex> catalog=<id>@<version> catalog_sha256=<hex> registry=first-party`, followed by `observed=`, `would_run=`, `ran=` and `verified=` lists of operation or facet names. A sensitive resource keeps every §31 redaction. In plan's change analysis (§23) a plugin change counts as an opaque change.

38.12 MCP boundary

Resource Plugins and connection providers (Tunnel, Gateway, MCP) are separate layers. In v1.9.0 MCP refuses plugin types: a manifest that declares `plugins` is refused by every manifest tool before anything is loaded, and MCP's loader has no plugin root, so a plugin type is an unknown resource type there. The MCP tool list is unchanged. MCP can never select the plugin root or the trust file. Exposing plugin types through MCP is decided with v2.0 (caller identity, target authorization, approval-based apply that includes plugin provenance in the approved digest).

38.13 Limits of the non-mutation guarantee

Sinter enforces which operations can run: only operations of reviewed first-party catalogs, pinned and attested by the Owner, and in plan and audit only observe operations. It cannot prove that an attested observe operation is read-only on the host: a misclassified operation would change the host during audit. For daemon-based tools (firewalld, NetworkManager) the change is made by the daemon, so isolating the client process would not prevent it. Digests, signatures and argv rules do not prove non-mutation. This is a documented residual risk; it must not be described as a technical guarantee.

38.14 Change history

2026-11-01: section added (Owner decision adopting E3-H; GOALS §16). §1.3 added; §36 prohibition on plugins narrowed to the data-only Resource Plugins of this section and four related prohibitions added.

2026-11-01 (step 2): §38.7, §38.8, §38.10–§38.12 implemented and made precise (activation in the top-level recipe only, the CLI-only plugin root, root-run controllers, the change states of failed and unknown mutations, provenance in existing `notes`/`reason`, the MCP refusal). The release registry stays empty.

2026-11-01 (step 4, real hosts): §38.5 ACL sentence made precise from measurements on Linux controllers.

2026-11-01 (step 5): firewalld 0.1.0 added to the release registry from the step 4 measurements (§38.1, §38.4); what is not verified listed in §38.1.

39. CLI usability: selector, inventory detection, short options

Status: IMPLEMENTED IN THE NEXT VERSION, NOT RELEASED; live Linux acceptance not yet run. Sinter v1.9.0 does not contain it. The version is undecided. It is not a completion condition of the v2.0 Secure MCP Tunnel and does not change that roadmap. Register entries (local work register): FR-072 selector (§39.2), FR-073 inventory detection (§39.3, §39.4), FR-074 short options (§39.5). Owner decisions D-1 to D-5 of 2026-11-04 settled what were open questions U-1 to U-10 of the earlier proposal.

39.1 What does not change

With no selector, every existing command behaves as in v1.9.0: same targets, same output byte for byte, same exit codes. With neither `--host` nor `--inventory` the target is the local host, and a file named `hosts.yaml` next to the recipe has no effect. `--limit` still needs `--inventory`, and still narrows only. `mcp` has no selector and no detection.

39.2 Selector argument (FR-072)

`validate`, `plan`, `apply` and `audit` take an optional second positional argument:

sinter validate nginx.yaml web01
sinter plan nginx.yaml web01
sinter apply nginx.yaml web01
sinter audit nginx.yaml web01
sinter apply nginx.yaml @web
sinter apply nginx.yaml web01,web02
sinter audit nginx.yaml @web,@db

Grammar: one or more arguments, each a comma-separated list; together at most 256 items. `NAME` and `host:NAME` are an inventory host and only a host. `@NAME` and `group:NAME` are an inventory group and only a group. A `NAME` that is both a host and a group of the inventory is refused with the two forms that settle it: what a command means does not depend on how the inventory happens to be named, and a host and a group may still share a name when written with a prefix. Names follow §19.2, so a name has no `:`. A repeated item, and a host reached twice, runs once. There are no patterns, exclusions or implicit "all"; those are refused, and patterns stay with `--limit`.

Meaning, by recipe:

A recipe with `targets`, alone or in a bundle: the selector works as `--limit` does in §19.2. It narrows and never widens: a name outside `targets` is exit 2, a host of `@group` outside `targets` does not run, and a recipe of a bundle left with no host is skipped.

One plain recipe without `targets`: the selector names the hosts it runs on, and no others. This gives an explicit name the authority `--host` already has; an inventory still selects nothing by itself.

A recipe of a bundle without `targets`: exit 2, as with any inventory. A one-recipe bundle is a bundle.

Failures, all exit 2 before any `ssh -G`, connection or command: an empty selector or item, a character outside the name rules, a name the inventory does not define as that kind (the message points out a group written without a prefix and a host written with one), a bare name that is both a host and a group, an item that reaches no host any recipe's `targets` select, a selection of no host, a selector with `--host` (`-H`) or with `--limit`, and no inventory (§39.3). A name never falls back to an `~/.ssh/config` alias or to `--host` behaviour. `localhost` has no special meaning: it works only if the inventory defines it.

Implementation: the selector is parsed into the same `ParsedLimit` as `--limit` and evaluated by the same `match_limit`, `Resolution` and `Limited`, so there is one selection path. For a recipe without `targets` its names become the `TargetSelector` passed to the same `resolve`. A selector that was not applied stops the run as a `--limit` that was not applied does (§19.2).

`validate` with a selector reads the inventory, evaluates the selection as `plan` does, checks the variables of the selected hosts with `--vars-file`, and contacts nothing and runs no `ssh -G`. `--vars-file` otherwise works as with `--limit` (§19.5), with the inventory the selector found.

Output, only with a selector. Text: an `inventory: <path> (auto-detected)` or `(--inventory)` line first, a `selector:` line instead of `limit:`, hosts left out marked `excluded by the selector`, and for a recipe without `targets` the line `targets: none declared; running on the hosts the selector names`. JSON: always the aggregate document of §19.4, with `selector` (the items) instead of `limit`, `inventory`, `inventory_source` (`detected` or `explicit`), `targets_declared` on each `resolution` entry and `excluded_by: "selector"`. A `validate` document gains `selector`, `inventory`, `inventory_source`, `selected_executions` and `targeted_executions`. With JSON the `inventory:` line goes to stderr. Exit codes are those of §33.

39.3 Inventory auto-detection (FR-073)

Detection runs only with a selector and without `--inventory`. `--inventory PATH` always wins, keeps every rule it has today (no new check), and a broken or missing named file is an error that never falls through to detection.

The names are `hosts.yaml`, `hosts.yml` and `hosts.toml`, and the places are the current directory and the directory of the recipe or bundle as named on the command line (a symbolic link to a recipe does not move it). Parent directories and the home directory are not searched, and there is no environment variable or per-user default.

Exactly one file may be found. Two names in one directory, or files in both places, are exit 2 listing the candidates: Sinter never picks by priority. Two hard links of one file are two candidates, since their format can differ. The same directory reached twice counts once.

A candidate that exists and cannot be used is an error, never a miss: nothing falls back to another file, another host or the local host. Refused, with exit 2 before any `ssh -G`:

a symbolic link, also a dangling one, and also when another candidate exists;

a recipe directory reached through a symbolic link, except, for an invoking user other than root, one owned by root anywhere but the last component (the system's own layout, such as `/var` on macOS). A root run gets no exception, because everything it clones or unpacks is root's too;

anything but a regular file, without blocking on a FIFO;

a file not owned by the invoking user or root, or writable by group or others;

a directory holding the file that is not owned by the invoking user or root, or is writable by group or others (a sticky bit does not excuse it);

a file larger than 1 MiB, not valid UTF-8, or invalid under §19.2;

`known_hosts` on any host: it could satisfy strict verification for a host of the file's choosing, so only `--inventory` may set it;

a relative `identity_files` entry on any host, including `~other/...`, whose meaning would depend on the current directory. Absolute and `~/` entries stay allowed (§39.4).

Time of check and time of use: a candidate is opened with `openat` and `O_NOFOLLOW`, every check is made on that descriptor, and the bytes parsed are read from it; a change to its size, times or link count during the read is refused. The file is read once, so replacing it later changes nothing about the run.

The path used is absolute and shown before the hosts are evaluated (§39.2).

Known limits. A cloned repository's `hosts.yaml` is owned by whoever cloned it, so the owner checks do not stop it. It can aim `address` at any host, and the protection left is strict verification against the user's own known_hosts (it reaches only hosts already trusted), `targets`, the path shown, and `plan` first. ACLs the mode bits do not show (macOS extended ACLs) are not inspected. Ancestors of the directory are checked for symbolic links only, not for modes: replacing one can bring in only directories and files this user or root already owns, because the owner checks apply to what is opened, and a stricter rule would refuse ordinary group-writable parents. Automation should name `--inventory`.

39.4 SSH authentication (no new mechanism)

Host management and key management stay separate; §19.1 is unchanged. The key file list is taken whole from the first source that names any: `--identity` > inventory `identity_files` > OpenSSH `IdentityFile` > standard keys. ssh-agent is a separate path tried first, as §19.1 describes. The usual way to use the operating system's keys is to omit `identity_files`; a host that needs its own key sets it, and `--identity` overrides for one run. Strict known_hosts verification (§19) is unchanged, and `--known-hosts` on the command line still applies.

39.5 Short options (FR-074)

`-H` is `--host`, `-p` is `--port`, `-u` is `--user` and `-i` is `--identity`, on `validate`, `plan`, `apply` and `audit`. Long options all stay, and a short option means exactly its long option, including where `validate` ignores it. `--inventory`, `--limit`, `--sudo` and `--format` have no short form. `secrets decrypt -i` and `secrets encrypt -r`, `-o`, `-f` are separate subcommands and keep their meanings. `-H` with a selector is exit 2, as `--host` is.

39.6 Verification status

Tests: `tests/cli_selector.rs` and the unit tests of `src/inventory.rs`, `src/inventory_detect.rs` and `src/main.rs`, with a scripted `ssh` and counting listeners. Not verified by them: real SSH hosts and Linux controllers, whose acceptance is a separate step; and a file really owned by another user, which needs root while the release gate runs as a non-root user: that refusal is proven on real descriptors judged as a stand-in user, and the same goes for its directory.

39.7 Change history

2026-11-04: section added as a proposal after the v1.9.0 publication (Owner direction). No implementation, test, or earlier section changed.

2026-11-04: implemented under Owner decisions D-1 to D-5 (FR-072 to FR-074), replacing the proposal text and the open questions. §19.2 gained the exception for one plain recipe without `targets`; §19.4 and the value set of `excluded_by` were extended. Nothing released.

40. Project configuration, recipe search, layered variables, backup store, partial runs

Status: IMPLEMENTED, NOT RELEASED; live Linux acceptance not yet run. Without a project file and without the new options, every command behaves as in §39, with one stated exception (§40.5, unknown variables).

40.1 The project file

A project file holds what an operator would otherwise repeat on every command line. It has its own name so that no recipe, inventory or variables file is ever taken for one.

```yaml
version: 1
recipe_paths:              # directories searched for a bare recipe name
  - /opt/sinter/recipes
  - ./recipes
inventory: ./hosts.yaml
vars_files:                # lowest precedence first
  - ./vars/common.yaml
  - ./vars/production.yaml
backup:
  directory: /var/backups/sinter    # a path on each target
default_target: "@web"     # optional, see §40.4
allow_implicit_apply: false
strict_vars: false
```

Every field but `version` is optional; an unknown field, a wrong type or a duplicate entry in a list is exit 2. A relative path in the file is relative to the directory holding the file, never to the current directory. `~` and environment variables are not expanded: a path means what it says wherever the command is run.

Discovery. `--config PATH` names the file (it must exist; nothing is searched). `--no-config` ignores any project file, and the two exclude each other. Otherwise the current directory only is looked at for `sinter.yaml`, `sinter.yml` and `sinter.toml`. Parent directories, the recipe's directory and the home directory are never searched: a file in a directory above, or next to a shared recipe, says nothing about what the person running the command wants. A project file up to 8 directories above, not past the home directory or a repository's top, is only named in a note on stderr (`exists but is not used`), never opened, so a command run from a subdirectory does not look as if it had its project's settings. A recipe called `sinter.yaml` in the current directory is read as the project file and refused with that explanation: rename it, or use `--no-config`. Applies to `validate`, `plan`, `apply` and `audit`; `mcp` and `secrets` never read a project file. No file found means no project: the command is what it was before.

A discovered file arrives without having been named, so it is held to the §39.3 rules: exactly one candidate (Sinter never picks by priority), not a symbolic link, a regular file, at most 1 MiB, file and directory owned by this user or root and not writable by group or others, checked on the open descriptor that is then read. Any failure is exit 2, and nothing falls back to "no project file". A file named with `--config` is what the operator asked for: it must be a regular file of at most 1 MiB, as `--inventory` is taken at its word.

A file a project file names (a recipe found through `recipe_paths`, `inventory`, `vars_files`) is held to the same ownership and mode rules, whichever way the project file was found, since it was not named on the command line. The rule is checked immediately before the file is read by path; it holds as long as the directories above it are, which the same limit of §39.3 states. The inventory a project file names is also held to the field rules of a detected inventory, whichever way the project file was found: no `known_hosts` and no relative `identity_files` on any host (§39.3). Otherwise a cloned repository's project file could bring the host keys that strict verification checks against; `--known-hosts` or `--inventory` on the command line can still name them. A path named on the command line is taken at its word.

The project file, the recipe, the inventory, the variables files and the project's backup store are shown before anything runs (`config:`, `recipe:`, `inventory:`, `vars:`, `backup store:` in text; `resolved` in JSON). A run without a project file prints nothing new.

40.2 Which recipe

The first positional argument is, in order:

1. a path when it contains `/`: used as given, relative to the current directory, never searched for;
2. with no project file or no `recipe_paths`: used as given (the behaviour before this section);
3. otherwise a *search name*: `<dir>/<name>` is looked at for every directory of `recipe_paths`, and `./<name>` in the current directory. Exactly one existing file (the same file reached twice counts once) is the recipe. Two different files are exit 2, listing both: Sinter never picks one, and writing `./name` or a full path settles it. None is exit 2, listing the places searched: no other recipe is tried and no extension is added. A file found only in the current directory is the path the command line would have meant and is taken as given; one found through `recipe_paths` is held to the §40.1 file rules.

A `recipes:` entry of a bundle stays relative to the bundle file (§19.3), and a recipe's `include` to the recipe.

40.3 Which inventory

`--inventory` (never falls back), else the project file's `inventory`, else, for a selector only, detection as in §39.3, except that a recipe found through `recipe_paths` adds no place to look: a shared recipe directory's `hosts.yaml` is not this project's. `--host` turns the project file's `inventory` and `default_target` off for that command.

40.4 Which hosts

From strongest to weakest; the first that applies decides, and nothing below it is consulted:

1. `--host H`: that host alone.
2. A selector: the named inventory hosts, as §39.2.
3. `--inventory`, or the project file's `inventory`, with `--limit` if given: the recipes' `targets`, as §19.2.
4. `default_target` of the project file as if it were the selector. `plan`, `audit` and `validate` use it. `apply` refuses it unless allowed, as below: an `apply` that names no host must not reach machines because of a file nobody on this command line mentioned. No prompt is added, so unattended runs stay unattended.
5. Local target, as before §39: only when no project file names an inventory or a default target.

An `apply` that names no host on its command line (no `--host`, selector, `--limit` or `--inventory`) and would reach hosts through the project file's `inventory` or `default_target` is refused (exit 2) unless the file also says `allow_implicit_apply: true`. Between 3 and 4: with a project `inventory` and `default_target` both set, the default target applies. A recipe without `targets` in an inventory run is refused as §19.2 says, never run locally. A name that does not resolve, an empty selection or an unreachable host is an error at its own step and never reaches a lower step: in particular no failure ever falls back to the local target. To run locally in a project directory, use `--no-config`.

40.5 Variables files in layers

`--vars-file` may be repeated. The files in effect are the project's `vars_files`, in order, then the command line's, in order; a later file wins. `--no-config` drops the former.

Merging is by variable name inside each layer: `vars`, `groups.<g>`, `hosts.<h>` of all files are merged separately, then the precedence of §19.5 (recipe default, `vars`, `groups`, `hosts`) applies to the merged layers. A host value of an earlier file therefore beats a common value of a later one. A variable's value is replaced whole: a map or list value is never merged with an earlier one, so what a file says is what the variable holds. A missing file, invalid YAML or TOML, a wrong type of the final value and an attempt to override a sensitive variable are exit 2 before anything is contacted, in any file, shadowed or not for the last one. Every message names variables and files, never a value.

Unknown variables. A file shared between recipes normally holds names a given recipe does not declare, so such a name must not stop the run on a guess (exit 2 in v1.9.0). A name the recipes of this run do not declare is judged in this order:

1. `--strict-vars` or `strict_vars: true`: exit 2, whatever else is true of it. Every name in the files must be used by this run.
2. Another recipe's variable: a top-level `vars` key of a file directly in a directory of the project file's `recipe_paths`: nothing is said. Only the names are read: `include` is not followed, nothing is run and no value is kept, the files are held to the §40.1 rules, and a file that is unreadable, not trusted or not understood adds nothing and never fails the run. Without `recipe_paths` nothing is read.
3. A certain typo: it differs from a variable the recipes declare only in case, or by two neighbouring letters swapped (at least 4 characters, not only digits): exit 2 naming the likely variable. Nothing else plausibly explains such a name, and a silent default is the failure a warning would not stop. A `-` is not valid in a variable name and is refused as such.
4. Otherwise a warning, naming the variable and the file. A name one or two edits from a declared one gets `did you mean`. It stays a warning because `db_port` and `db_host`, `web_port` and `web_host`, `app_url` and `api_url` are that close and are real variables. Mark what must be set `required: true`: a required variable left without a value is exit 2 whatever the file's other names are.

Required variables. A declaration `required: true` (with `value` still giving the type) must be given a value by a variables file for every execution that runs the recipe; otherwise exit 2 naming the variable. A recipe no host runs is not asked (§19.2). `required` with `sensitive` is refused: a variables file cannot set a sensitive variable.

40.6 The backup store

A recipe declares what to keep and may say where. For each path the first that applies decides, and nothing lower ever overrides it:

1. the path's own `directory`: `paths: [{ path: /var/lib/pgsql/.pgpass, directory: /var/backups/pg }]`;
2. the `backup.directory` of the document that declares the path (an `include` does not inherit it);
3. the project file's `backup.directory`;
4. the store of §4 (§ Store above).

A string in `paths` means the same as before. Declaring a path twice stays an error, whichever store each names. There is no command line option: the pairing of a path and its store is read in the recipe. The store is a path on each target, literal (no `{{`), absolute and normalized (no `.`, `..`, `//`, trailing `/`, control characters), and not `/`; the owner and mode of a store cannot be chosen.

Refused before anything is contacted, in every phase: a declared path that contains or lies inside any declared store (whichever path names it), and a store inside another. Refused at run time, by `plan` (read-only) and by `apply`, for every store in use: the same overlaps with the project file's and the default store; and, as for the default store, every ancestor by the strict §23 walk (no symbolic link, no account's tree, no ACL, nothing others can write), an existing store that is not a directory owned by a trusted principal or that group or others can write, a symbolic link, and a store whose direct parent is a shared directory (§23.4), since anyone can make a name there first.

`apply` checks and makes every store, and its run directory, before the first copy, in the order the paths name them. Only the store itself is created (mode 0700, never `-p`); its parent must exist. A run directory that exists is a collision. Any failure stops the apply before any resource runs, and run directories already made are left and named. `plan` lists each path with its store and makes nothing; `audit` does not touch stores. A copy lies at `<store>/<run-id>/<original absolute path>`, and each entry reports its destination; JSON has `store` per entry and `directories`, while `directory` is set only when there is one. Sinter still does not restore anything.

A recipe that names a store gains nothing it did not have: it can already write any file on the target. What it does decide is where the invocation writes copies, so `plan` shows it: read it before running someone else's recipe. No path list is refused, because what a directory means belongs to the services on the target, and nothing already there is replaced: the only new name directly in a store is the run directory, named by the run id, mode 0700, and a run directory that exists stops the apply. Still, do not point a store at a directory a service reads: a service that includes every entry of a directory (`include sites-enabled/*`) can fail on a directory it finds there, and one that walks a tree recursively can find the copies.

40.7 Backing up a file in another account's tree

A path in another account's directory tree (§23.2), such as `/var/lib/pgsql/.pgpass` (owner `postgres`, mode 0600, directory mode 0700), is copied without root reading through a tree that account controls. This is one exception to the sentence of §23.2 that refuses such a backup, and it keeps the rule of §23.2: nothing of a path another account controls is read as the invocation.

The read and the write are two identities in one fixed script (`src/fsbackup.sh`, pinned by digest, §20's limited exception as §23.4; every value is an argument):

- Everything about the source runs as the account U through `setpriv` (real, effective and saved ids, supplementary groups, no_new_privs): `lstat`, the read with `dd iflag=nofollow`, the second `lstat`, `getfacl`. U can therefore make it read only what U can read.
- Everything about the destination runs as root in the private run directory: the file is created exclusively, filled from the pipe, then given owner, mode, times and ACL.
- What crosses from U to root is treated as hostile, since U may tamper with a process of its own: the content is bytes written to a file and never interpreted, its length is capped, and the metadata lines must match a strict grammar before use. No archive format is unpacked as root, because a stream U can write would then decide what root creates.

Accepted: exactly a regular file, owned by U, one hard link, no setuid or setgid bit, at most 1 GiB, whose metadata is unchanged between the two `lstat`s (device, inode, mode, owner, group, links, size, mtime, ctime), and whose written size equals its `lstat` size. Owner, group, mode and access and modification times are preserved; an ACL is preserved with `getfacl`/`setfacl`, and a file with an ACL on a target without them fails. Other extended attributes and SELinux labels are not copied here. The metadata of the copy is what the account reports (its group and ACL can name anyone, within what the grammar allows), which the private run directory contains; whoever restores a copy by hand should read it first.

Overlap. A copy of a directory can leave anything its owner put there in the run directory, a symbolic link included, and a second copy into the same place would write through it as the invocation. So declared paths that overlap are refused, in every phase and whichever comes first (exit 2; accepted until v1.9.0). The top of another account's tree (a declared directory with trusted parents and an untrusted owner) is refused for the same reason as a directory inside it; this also changes a declaration that `cp -a` accepted until v1.9.0. A directory a trusted principal owns is still copied with `cp -a`, including what other accounts own below it: links are not followed and the copy stays in the private run directory, but that walk is the invocation's, as it always was.

Refused, each before anything is read: a directory (a tree U controls is not walked as root, and a live PostgreSQL data directory copied file by file would not be a consistent backup anyway: use the database's own tools, and name files here), a symbolic link, any other type, a file owned by another account, a file with more than one link, a tree directly inside a shared directory (§23.2 C-1: no `owner` to compare with), a non-root invocation (§23.2 unchanged), and a target without `setpriv`. The account's processes run in their own session with no terminal on stdin, and what root reads from them into memory is capped. Any failure aborts the apply before any resource runs, as every backup failure does, and removes the partial destination file. Nothing about a path under a store's run directory is readable by U: the run directory is root's, mode 0700, even though the copy keeps U as its owner. A copy of a file is not a database backup, and Sinter does not claim consistency between files.

40.8 Partial runs

`--skip-recipe NAME` and `--skip-resource ID` may be repeated, on `validate`, `plan`, `apply` and `audit`, with one meaning: what is excluded is not observed, changed or reported as passed. `NAME` is a recipe's label (its file stem). `ID` is a resource id, the base id of a loop (all its instances) or one instance (`id[2]`), or `recipe/id` to say which recipe.

Refused with exit 2 before `ssh -G` or any connection, in all commands:

- a name that matches nothing, in any recipe of the run (never ignored);
- a recipe label two recipes of a bundle share, an id several recipes have without a `recipe/` prefix, and a string that reads both ways;
- a handler id: a handler is not a resource, and skipping one would leave a change without its restart;
- an included resource whose `depends_on` names an excluded one, directly. A `register` reference is always also a `depends_on` (§ recipe rules), so it is covered. Nothing is excluded automatically: the message lists each edge, and the operator decides;
- everything excluded: nothing would run;
- `--audit-policy strict` with an exclusion: a strict audit answers for the whole recipe.

An excluded recipe is still loaded and validated, and its hosts are not resolved unless another recipe needs them. A declared backup of a recipe that runs is taken in full, also of paths only an excluded resource would change. A handler runs only if an included resource notified it.

Exit codes do not change, so an exclusion must be visible instead: text output always shows `Included`, `Excluded` (`SKIPPED_BY_USER`) and `Blocked dependencies` first and a final `PARTIAL_APPLY`, `PARTIAL_PLAN` or `PARTIAL_AUDIT` line; JSON has `skips` with `partial: true`, the requests and every excluded resource with its reason. There is no `--show-skips`, because `plan` always shows this.

40.9 Parallel execution: not added

Executions run one at a time, recipe-major (§19.3); resources run in dependency order inside one thread; nothing in the engine runs concurrently except I/O helpers of one command. Host-level parallelism would need each execution's output and progress buffered, an answer for apply's stop-at-first-failure, and a review of the per-target `ssh -G` resolution; none of it is local to one module. It is deferred, not refused, as a separate work package with its own acceptance.

40.10 Verification status

Tests: `tests/cli_project.rs`, `tests/cli_skips.rs`, `tests/backup_store_dir.rs`, `tests/backup_tree.rs`, `tests/backup_tree_script.rs` and unit tests. Scripted targets run the production engine. `tests/backup_tree_script.rs` runs the real script text under `/bin/sh` with stand-in tools, so its logic is tested on any Unix, but the stand-ins are not util-linux or coreutils. `tests/backup_tree_real.rs` runs it for real and needs Linux and root. No real target has run any of §40 yet.
