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

Top-level fields allowed in v0.1:

version

vars

include

resources

handlers

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

v0.1 handlers are not generic resources.

A handler has exactly:

id: required string

service: required static string

action: required enum restart | reload

sensitive: optional boolean, default false

Handlers do not support:

when

loop

register

depends_on

notify

arbitrary command execution

Handler IDs must be unique and must not collide with resource IDs.

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

v0.1 variable values are literals only. Variable values are not expressions and do not interpolate other variables. Therefore variable forward references and variable cycles do not exist.

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

Handlers are delayed service actions only.

They execute only if notified by a resource that:

definitely changed

succeeded

passed required verification

Multiple notifications to the same handler are deduplicated.

Allowed actions:

restart

reload

Handler verification:

restart: service must be active after action

reload: command/action must report success and service must still be active after action

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

20. Remote argv contract

command represents program + argv, not a shell command string.

Remote execution must preserve exact argv values without unintended shell evaluation.

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

This rule applies even when a particular operation would not otherwise require root privilege. For example, a command resource executing /usr/bin/id -u under --sudo must observe effective UID 0.

Controller-side work remains under the controller process identity. In particular, parsing, include loading, local source-file reading, template rendering, planning logic, and output rendering are not made root merely because the target invocation uses --sudo.

There is no per-resource sudo field, automatic privilege detection, permission-denied escalation, or mixed target execution identity in v0.1.

Privileged target operations use non-interactive sudo -n.

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

The final path component is inspected without following an unexpected symlink.

These checks apply to:

read

create

replace

chmod

chown

delete

link manipulation

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

automatic repository metadata refresh is not performed by Sinter

Package observation distinguishes cleanly installed, absent, and unsupported/inconsistent states.

If dpkg/apt reports a half-configured, unpacked-but-not-configured, broken, or otherwise non-clean state, v0.1 fails and does not attempt automatic repair.

Sinter does not run an explicit apt lock retry loop. Each apt mutation is bounded by the general operation timeout of 300 seconds; a lock-related non-success or timeout is reported according to normal failure/indeterminate rules.

Package maintainer scripts may have side effects outside Sinter's complete predictive control.

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

Missing unit => fail, except in plan when the service has a direct dependency on a package resource whose planned state is present; in that one case plan reports the service as deferred/unknown until dependency apply.

Masked unit when running requested => fail.
Static unit with enabled field requested => fail.

A systemd failed unit is not equivalent to clean stopped.

running requested: Sinter may issue one start operation; if not active afterward => verification failure

stopped requested: Sinter issues stop/reset only as required by the documented systemd adapter and must verify inactive and not failed; it does not silently report an existing failed state as satisfied.

Sinter does not perform daemon-reload implicitly in v0.1.

29. Plan representation of future-created state

Plan describes current observations and intended Sinter operations, but does not pretend to know external side effects of dependencies.

Example:

package resource plans installation of nginx

dependent service unit is currently missing

The service plan is reported as:

current: missing
desired: running
status: deferred/unknown until dependency apply

This exception applies only when the service directly depends on a package resource whose desired state is present.
Otherwise a missing service unit is a plan error for a requested service state.

Apply re-observes the service after package application.

30. Verification requirements

Stateful resources require verification after mutation.

For any state=absent filesystem resource, verification requires confirmed non-existence using non-following inspection. Inaccessible/uninspectable is not absence.

For present state:

file: path type + managed content + managed/default metadata

directory: type + requested/default metadata

link: symlink target

package: installed/absent state

service: requested active/enabled state

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

add generic handlers, roles, plugins, inventory, orchestration, or scripting

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
