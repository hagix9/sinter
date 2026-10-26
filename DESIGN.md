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

type: optional string, default service. The values are service, ca_trust and command; this version implements service only (see below)

sensitive: optional boolean, default false

and, for the type service,

service: required static string

action: required enum restart | reload

A handler that has no type is a service handler. type: service is the same handler as no type. A recipe written before handler types existed means exactly what it meant.

IMPLEMENTED: a recipe that declares a type this version does not implement (ca_trust, command) is rejected at validation with a plain error. A type that is not one of the three values, or a type that is not a string, is rejected. Such a handler is never frozen, never queued by a notification and never reported as run. No type is skipped or treated as a success.

IMPLEMENTED: the fields a type does not define are rejected. In particular a service handler has no with block and no privilege field.

UNCHANGED LIMIT: handlers do not support

when

loop

register

depends_on

notify

Handler IDs must be unique and must not collide with resource IDs. A notify that names an unknown handler is an error. Handlers never notify and never depend on each other, so handlers cannot form a cycle.

UNCHANGED LIMIT: a handler is never a general resource, and a handler never runs a shell. The only way a handler may run a program is the planned type command below.

PLANNED, not implemented (H2): type ca_trust refreshes the system CA trust store with the operating system's own tool, chosen by the target's OS family: update-ca-certificates on debian, update-ca-trust extract on redhat. It has no parameters. It needs root. On any other OS family it is refused rather than replaced by another command.

PLANNED, not implemented (H3): type command runs one program after a change. It reuses the validation of the command resource (§10): a static absolute program path, an exact argument list with no shell, a fixed baseline environment plus a restricted env map, an absolute cwd, success_codes, and timeout_seconds. Differences fixed in advance: every value is a static string (no expression), the argument list has at most 64 entries of at most 4096 bytes each, timeout_seconds is 1 to 3600 with default 300, and an optional privilege: root states that root is required. The command resource itself keeps its existing limits.

PLANNED: neither ca_trust nor command introduces implicit privilege escalation. Every handler runs with the privilege of the run (§21); privilege: root only requires it and fails the handler when the run does not have it. A handler never escalates by itself.

PLANNED: plan and audit never run any handler type. Output keeps the documented handler keys; the type is reported additively.

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

Store: with --sudo `/var/lib/sinter/backups/<run-id>/`, otherwise `<target-user-home>/.sinter/backups/<run-id>/`, on the target. Inside the run directory the original absolute path is reproduced. `<run-id>` is `<UTC YYYYMMDDTHHMMSSZ>-<8 hex>`, one per invocation and shared by all its targets; when several recipes run (§19.3) it is suffixed `-<NN>-<recipe>` per recipe. Backups run only for executions selected by target resolution (§19.2). Store directories created by Sinter are mode 0700; every ancestor of the run directory and of each source path must pass the §23 trust check. An existing run directory is a collision and fails. A declared path that contains, or lies inside, the store fails.

Copy rules: regular files, directories (recursively) and symlinks (as links, never followed) are copied; mode (including POSIX ACLs), ownership and timestamps must be preserved or the backup fails; other extended attributes and SELinux labels are preserved on a best-effort basis. Other object types fail. An absent path is recorded as absent and is not a failure.

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

IMPLEMENTED: the only handler type this version runs is service, a delayed service action. The rules below apply to every handler type, present and planned.

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

systemctl daemon-reload is not a handler type and none is planned: the manager synchronization of §28 already performs it.

UNCHANGED LIMIT: a handler is not retried and is not recorded across runs. If a run stops before the handler phase, or a handler fails, the notification is lost: the next apply finds the resource already correct and notifies nobody. The run reports the handlers that did not run (handlers_pending); the operator must perform their action by hand. This holds for every handler type, and for a planned type such as ca_trust it means a stale trust store until someone runs the refresh.

PLANNED (types ca_trust and command): their result is the exit status of the program, not a state observation; a failed or indeterminate result stops the phase like any other handler, a program that may have started is never reported as unchanged, and nothing is rolled back.

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

`--limit <ITEMS>` narrows a run with `--inventory` to some of the hosts the recipes' `targets` select. It never adds a host: the hosts that run are those a recipe targets and `--limit` names. `<ITEMS>` is a comma-separated list (at most 256 items of at most 64 characters, one `--limit` option only); each item is a host name, a group name, `host:<name>`, `group:<name>`, or a pattern. A bare name that is a host and also a group is ambiguous and an error — write `host:<name>` or `group:<name>`. A pattern uses `*` (any run of characters) and `?` (one character), matches host names only, and may be written with `host:`; quote it so the shell does not expand it. There is no exclusion (`!`). `--limit` needs `--inventory` and is exit 2 with a single target (`--host` or the local host).

`--limit` fails closed, with exit 2 and before any `ssh -G`, connection or command: an empty list or item, a character outside the name rules, a name that is neither a host nor a group of the inventory, a pattern that matches no host, and an item that reaches no host any recipe's `targets` select (it would run nothing). The hosts are chosen once, by evaluating `--limit` against the target resolution and before any host is resolved; the unfiltered selection is not passed on, and `ssh -G` (which may run local commands through an OpenSSH `Match exec`), the connection and the variables of a host left out by `--limit` are never evaluated. A recipe of a bundle that no host remains for is skipped: no value from the variables file or from a host is applied to it, no model is built for running it, no execution is planned for it and no `ssh -G` runs for its hosts. It is still held to what does not depend on a variable's value: it is parsed as a document when the bundle is loaded (syntax, schema, includes, declarations, its `targets` against the inventory) and `Prepared::check_structure` freezes it with its own defaults and keeps every failure except one that may depend on what a variable holds. A field that references a declared variable and fails its static check with the defaults is left out (the field is given no value), unless it fails whatever the variables hold: the check evaluates the field once more with a neutral value of its declared type for every non-sensitive variable, trying every combination of the boolean variables the field names because a boolean can decide which side of `||` or `&&` is evaluated (`Tolerance::may_depend_on_values`), so an undeclared variable, a fact or register, a sensitive value and a variable of another type are kept, and no message is inspected. The resource's other checks, and those of the other resources, go on. What is not judged, and is made when a host runs the recipe, is only what a variable's value decides: such a field, a conflict over a path or a name that such a field takes part in (`ownership_may_depend_on_values`), and a template file a variable chooses (its body is read only when the default resolves to a file, and a failure there is not judged). A field whose literal part is invalid whatever the variable holds (`rel/{{ vars.x }}`) is not refused either: only the evaluation is judged, not the checks that follow it. Known limits of the evaluation: at most 8 boolean variables named by one field are combined (a field naming more is left undecided), and only booleans are varied, so a comparison that decides which side of `||` or `&&` is evaluated (`vars.x == "a" || vars.x`) can still be refused although another value would make it valid. Unknown resource types and fields, duplicate ids, `depends_on`/`notify` references and cycles, secret references, undeclared variables, literal fields (`owner`, `group`, `mode`, `content` with `source`, `state`, `creates` with `removes`) and conflicts between literal paths or names are kept. A freeze that runs a recipe does not use this tolerance: there the first failing check fails, as before. It is listed as skipped (text `SKIP   recipe not run: --limit leaves no host for it`, JSON `excluded_by: "limit"` on its `resolution` entry and `null` counts in a `validate` bundle document). The ban on overriding a sensitive variable still covers the variables it declares. Text output prints a `limit:` line, marks the hosts left out `SKIP excluded by --limit (matched: …)` and counts them; JSON output adds the `limit` array and `excluded_by: "limit"` on those hosts, and keeps their `reasons`. Without `--limit` the output, the checks and the order are unchanged. By design `--limit` does not cover: the duplicate-address check among the hosts that run (hosts left out are not compared); a misspelled variable name in the layer of a host left out; and the drift of the hosts left out (an `audit` that exits 0 says nothing about them). `excluded_by` is an open set of values (today only `"limit"`).

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

The invocation exit code is the most severe exit code among executions that ran, in the order 6, 5, 4, 3, 2, 7, 0; not-run executions contribute none. A partial failure never exits 0. The summary counts executions that exited 0, exited non-zero, and were not run.

Text output shows the target resolution (MATCH with reasons / SKIP per host and recipe) before running and an execution summary after. JSON output is one document for the invocation with the resolution and, per execution, the recipe, the target identity (inventory name, address, port, user), status, exit code, the single-target document or error, and an execution-level backup record (§4.12): null when the recipe declares no backup or in audit; otherwise its status (planned, completed, failed, not_started, not_run) with run id, run directory and per-path entries — never content.

`validate` accepts every target option and ignores it; it reads no inventory and no variables file — except with `--vars-file`, when it runs the static gate of §19.5 (and then reads the variables file and, with `--inventory`, the inventory) and still contacts no host. With `--vars-file` and `--inventory`, `--limit` narrows that check to the selected hosts exactly as it does for `plan`; the success output adds `limit` and `variables.targeted_executions` (JSON) or a line `ok: --limit … selects N of M execution(s)` (text). An explicit `--limit` is checked by `validate` with or without `--vars-file`: without a variables file `validate` reads the inventory, resolves each recipe's `targets` and evaluates `--limit` as `plan` does before it connects (a bad `--limit`, a broken inventory, a recipe without `targets` and `--host` with `--inventory` are exit 2), resolves no variable beyond loading the recipes some host runs, and contacts nothing. Without `--limit`, `validate` reads no inventory and ignores the other target options.

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

Because the operations run as U, only entries owned by U are supported in the tree: a new entry without a recipe owner belongs to U (except in a tree directly inside a shared directory, where an `owner` is required: see below) and its group is U's primary group; an owner other than U, or an existing entry owned by someone else that would have to be preserved, is refused in plan and in apply with the same reason, and nothing is handed to another uid. An account without an entry in the account database, a second foreign owner below D, and a backup of a path in such a tree are refused. A non-root invocation is not changed: its trusted principals remain root and the target execution user.

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

Plan finding desired-state differences still exits 0.

With an inventory or a bundle (§19.4) the exit code is the most severe execution exit code (6 > 5 > 4 > 3 > 2 > 7 > 0).

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

add generic handlers, roles, plugins, orchestration, or scripting

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
