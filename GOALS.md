Sinter Goals

Status: Design Draft v4.2
Project: Sinter
Implementation language: Rust

1. Vision

Sinter is a lightweight, agentless configuration-management tool inspired by Itamae.

Its purpose is to provide a small and trustworthy way to describe and apply operating-system configuration without requiring Ruby, Python, an agent, or a Sinter runtime on managed hosts.

Sinter favors a narrow, understandable core over becoming a general-purpose automation platform.

The intended character is:

Rust single binary

agentless

YAML and TOML recipes

one common semantic model

local and SSH execution

passwordless sudo

validate / plan / apply workflow

useful current -> desired differences by default

strong idempotency for stateful resources

explicit failure and uncertainty semantics

conservative behavior when safety cannot be proven

conservative sensitive-data propagation, including command outputs derived from sensitive inputs

Guiding phrase:

Small enough to understand, strong enough to trust.

2. Non-goal: becoming Ansible

Sinter is not intended to become an everything-platform.

v0.1 intentionally does not include:

roles

collections

plugin SDK (a general SDK for plugins that run code; the restricted, data-only Resource Plugins of §16 are not an SDK)

dynamic inventory

multi-host orchestration

parallel execution

workflow orchestration

embedded general-purpose scripting

agent deployment

central management server

compatibility layers for Ansible or Itamae DSLs

Capabilities are added only when a real configuration-management requirement cannot be expressed safely by the small core.

3. Declarative first

Normal configuration should be expressible directly in YAML or TOML.

v0.1 may use:

variables

facts

conditions

static loops

includes

templates

dependencies

registered command results

delayed service handlers

These mechanisms are deliberately bounded.

They must not allow recipe structure to become dependent on arbitrary runtime code.

4. One semantic model

YAML and TOML are frontends for one Sinter recipe model.

Equivalent recipes must produce equivalent:

typed values

resource identities

ordering

desired state

ChangeSets

execution behavior

Format-specific semantics are prohibited.

5. Primary workflow

The primary workflow is:

sinter validate recipe.yaml
sinter plan recipe.yaml --host host.example
sinter apply recipe.yaml --host host.example

validate checks recipe structure and semantics without connecting to the target.

plan performs observation only and produces a non-authoritative preview.

apply re-observes every stateful resource immediately before deciding whether to mutate it.

A v0.1 plan is not an approved or replayable execution artifact.

6. Plan safety

Plan may perform observation operations only.

It must not intentionally:

write files

upload staging files

chmod or chown

create or delete filesystem objects

install or remove packages

update package metadata

start, stop, restart, reload, enable, or disable services

execute arbitrary user commands

perform configuration-changing sudo operations

Incidental observation effects such as atime, audit logs, SSH logs, and service-manager query logs are outside the managed-state non-mutation guarantee.

Unknown runtime values must be displayed as unknown, never silently converted to unchanged or skipped.

7. Idempotency

For stateful resources, a second apply against already-satisfied state must perform no unnecessary mutation operations.

Sinter does not claim automatic idempotency for arbitrary commands.

Idempotency tests must verify actual mutation calls, not only reported labels.

8. Fail safely

v0.1 is fail-fast.

The first:

failed mutation

failed required verification

indeterminate mutation

failed delayed handler

stops further execution.

Resources that were not executed must retain a structured reason.

Sinter must not automatically retry any mutation whose completion is indeterminate.

A new explicit user invocation is required.

9. Static target identity

The identity of a managed target must be statically known before execution.

In v0.1, the following may not be derived from facts or registered command results:

resource id

file/directory/link path

package name

service name

loop cardinality

include path

dependency graph

notification graph

Dynamic content and ordinary desired values may still use facts and allowed registered values where the specification permits.

10. Conservative filesystem behavior

Filesystem mutation is permitted only when Sinter can preserve its safety contract.

v0.1 rejects operations when:

a parent path required for a privileged mutation is writable by an untrusted non-root user and Sinter cannot establish a stable safe path

an unexpected symlink or object type is encountered

an existing file carries unsupported security metadata that cannot be safely preserved

atomic same-filesystem publication is unavailable for a content replacement

target drift is detected between protected observation and publication

Sinter does not attempt to solve races against a hostile root administrator.

11. Sensitive information

Sinter does not claim automatic secret detection.

Recipes explicitly mark sensitive variables or resources.

Sensitivity propagates conservatively into derived values and presentation.

Sensitive values must not appear in:

normal output

verbose output

diff output

registered-result presentation

diagnostics

structured serialization

For sensitive content, hashes and sizes are hidden by default.

Runtime values and redacted presentation values are distinct representations.

12. v0.1 mandatory scope

Frontends:

YAML

TOML

one canonical schema

one common IR

Commands:

validate

plan

apply

Execution:

localhost

SSH

passwordless sudo using non-interactive sudo, enabled only by an explicit invocation-level --sudo; when enabled, all target-side resource observation, mutation, verification, commands, and handlers run with effective UID 0

pre-registered SSH host keys only

Recipe features:

variables

basic facts

when

static loop

include-once composition

dependencies

command register

delayed service handlers

Resources:

file

directory

template

link

command

package for the reference platform

systemd service

Behavior:

structured ChangeSet

useful default diff

sensitive redaction

fail-fast execution

explicit Unknown

explicit indeterminate completion

apply verification

real SSH integration tests

mutation-free plan tests

strong idempotency tests

13. Explicitly deferred

Not required for v0.1:

user

group

git

http_request

remote_directory synchronization

dynamic inventory, host and group variables, nested groups, and host patterns (a static inventory with flat host groups and explicit recipe targets exists; DESIGN §19.2)

parallel or orchestrated execution across multiple targets

parallelism

shell as a separate resource

immediate notifications

generic handlers

notification chaining

handler dependencies

loop + register combinations

dynamic resource generation

saved plans

interactive sudo

secret-provider integrations

YAML aliases and merge keys

TOML datetime semantics

plugin system (a general one: plugins that run code, scripts, separate plugin processes or WASM; only the restricted, data-only Resource Plugins of §16 exist)

Rhai or another embedded scripting language

14. Reference environment

The v0.1 reference managed target is:

Ubuntu 24.04 LTS

amd64

systemd

apt

OpenSSH server

/bin/sh

GNU/Linux core utilities used by the documented implementation

passwordless sudo -n for privileged integration tests

The controller reference environments are:

macOS on Apple Silicon

Ubuntu 24.04 LTS amd64

Other environments may work, but are not claimed as verified v0.1 support unless added to the documented test matrix.

15. Success criteria

Sinter v0.1 succeeds when a user can:

obtain one binary

write an equivalent YAML or TOML recipe

validate it

preview one local or remote target safely

understand current -> desired differences without debug flags

apply configuration

use passwordless sudo for privileged resources

run apply again with no unnecessary stateful mutations

receive explicit failure or indeterminate results when certainty is lost

do all of this without installing a Sinter-specific runtime on the target

16. Restricted Resource Plugins (Owner decision, 2026-11-01)

Status: adopted for v1.9.0 as design E3-H. Foundation step 1 (reading and verifying plugin data) is implemented; nothing is executed yet. DESIGN §38 is normative.

Why this changes §2 and §13. Adding every new resource type to the core makes the core, its review and its releases grow with each type. The Owner asked for resource types that can be added later without rebuilding or changing the core. §2 and §13 rejected a plugin SDK and a plugin system meaning code loaded into Sinter; that rejection stands. What is added is narrower: a plugin is data that the core verifies, and it can only use operations from a capability catalog that the Owner pinned.

What is allowed:

a resource plugin made only of data (types, fields, prechecks, facets), which names catalog operations and nothing else

capability catalogs reviewed by the Sinter project and shipped with the release (first-party), each operation classed observe or mutate

an Owner-managed trust file on the controller that pins every plugin and catalog by id, version and SHA-256 and lists, per operation, what the Owner attests (observe) or allows (mutate)

What stays prohibited or deferred:

running arbitrary code from a plugin (Rust, scripts, separate processes, WASM)

arbitrary scripts or shell in a plugin or catalog

a plugin connecting to a target itself (SSH or otherwise)

registering capabilities without limit; third-party capability catalogs need a separate safety review and Owner approval, and are not supported in v1.9.0

a general plugin SDK

automatic distribution, marketplaces and automatic updates

a plugin bypassing authorization: the trust file, the mutation permit, plan/audit read-only operation, and (in v2.0) MCP authorization

Known limit. Sinter can enforce that only operations the Owner pinned and attested are run, and that audit and plan run only observe operations. It cannot prove that an operation attested as observe is really read-only on the host; a misclassified operation would change the host during audit. This is a documented residual risk (DESIGN §38.13), not a guarantee.

History: 2026-11-01, Owner decision adopting E3-H with the conditions above, after a design comparison and a limited proof of concept (a prototype engine gained two resource types from data alone while its binary stayed byte-identical).
