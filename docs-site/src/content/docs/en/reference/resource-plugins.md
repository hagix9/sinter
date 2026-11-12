---
title: Resource Plugins
description: Data-only Resource Plugins, the plugin root, the sinter plugin commands and the first-party firewalld plugin.
---

*Available from v1.9.0. The `sinter plugin` commands, firewalld 0.2.0 and partial
mutate permission are new in v1.12.0.*

A Resource Plugin adds resource types named `<plugin>.<name>`, as data. No code
from a plugin runs in Sinter. Every program a plugin can run comes from a
capability catalog that lists fixed programs, argument templates with checked
operands, and the meaning of each exit status.

Sinter v1.12.0 carries two first-party plugins, each with its catalog:

| Plugin | Resource types | Releases |
|--------|----------------|----------|
| `firewalld` 0.1.0 | `firewalld.service` (present only) | v1.9.0 and later |
| `firewalld` 0.2.0 | `firewalld.service`, `firewalld.port`, `firewalld.port_range`, `firewalld.protocol` | v1.12.0 and later |

Catalogs from anyone else are not supported: a catalog is used only when it is one
of the reviewed first-party catalogs compiled into this Sinter, and any other
catalog is refused, even when it is pinned. A release before v1.12.0 refuses
firewalld 0.2.0.

A recipe without `plugins:` behaves as before, and the plugin root is not read.

## The plugin root

The plugin root is a directory on the controller:

```text
<plugin-root>/
  trust.toml                              (mode 0600)
  catalogs/firewalld-0.2.0.catalog.toml
  plugins/firewalld-0.2.0.plugin.toml
```

Give it with `--plugin-root DIR` on `validate`, `plan`, `apply`, `audit` and the
`sinter plugin` commands. The default is `$XDG_CONFIG_HOME/sinter/plugins`, else
`~/.config/sinter/plugins`. A recipe, a variables file or MCP input can never
choose it.

The root and every file in it must be owned by root or by the invoking user and
not writable by group or others. The same applies to the directories above it,
which may also be sticky. Symbolic links are refused. Any problem refuses the
recipe with exit 2 before anything runs.

- When Sinter runs as root (for example through `sudo`), only root-owned plugin
  files are accepted, whatever `HOME` points to.
- On Linux, a POSIX ACL entry that grants write to someone else is refused
  through the ACL mask. On macOS, ACLs are not detected.
- Plugins are refused on non-Unix controllers.

## Install a plugin

*From v1.12.0.* Sinter carries the exact bytes of its first-party plugins and
catalogs. `sinter plugin install` writes them into the plugin root and adds their
entries to `trust.toml`; nothing is downloaded.

```sh
sinter plugin list                               # what this Sinter carries and what is installed
sinter plugin install firewalld@0.2.0 --dry-run  # show the plan, change nothing
sinter plugin install firewalld@0.2.0            # type "yes" to confirm
sinter plugin verify firewalld@0.2.0
```

The plan lists the files and trust entries it would write, every observe
operation of the catalog, and the mutate operations that would stay not allowed.

- **Your confirmation is an attestation.** Typing `yes` (or passing `--yes` when
  there is no terminal) states that you accept the catalog's observe operations
  as read-only. Sinter cannot prove that on the host; the classification rests on
  the catalog review.
- **No mutate operation is allowed by default.** `--yes` never allows one. Allow
  them by name with `--allow-mutate OP[,OP...]`, or every change operation of a
  resource type with `--allow-mutate-for TYPE[,TYPE...]`. There is no option that
  allows everything.
- Files are created with mode 0600 and directories with mode 0700. An existing
  file is never replaced, and an existing trust entry is never widened or
  narrowed: to change a permission, edit `trust.toml` yourself.
- One writer at a time: a second install or remove on the same root is refused.

`sinter plugin remove firewalld@0.2.0` takes the plugin out again. It removes only
files that still have the pinned first-party bytes, keeps a catalog another
trusted plugin uses, and keeps the previous trust file as `trust.toml.prev`. A
changed file is refused and nothing changes.

Exit codes: 0 done, nothing to do, or a dry run; 2 refused, with no change left;
5 a failure after a change began (the report lists what was changed). `--json`
prints one JSON document; the plan and messages go to standard error.

`sinter plugin list` and `sinter plugin verify` only read. `verify` exits 2 when
there is nothing to verify (no root, no trust file, or nothing pinned), when a
file differs from its pin, or when the loader refuses the plugin. None of the
`sinter plugin` commands reads a recipe or contacts a target, and MCP has no
plugin tool.

A plugin root set up by hand, as before v1.12.0, keeps working: copy the files
from [`plugins/first-party/`](https://github.com/hagix9/sinter/tree/main/plugins/first-party)
without changing a byte and pin them in `trust.toml`:

```toml
format = 1

[[catalog]]
id = "firewalld"
version = "0.2.0"
sha256 = "d32ac3947279ec2581a7049f9fa931d29c904c91ea2484cafaa6759fe09c3641"
attested_observe = ["state", "zone_defined", "service_defined", "query_service_runtime", "query_service_permanent", "query_port_runtime", "query_port_permanent", "query_protocol_runtime", "query_protocol_permanent"]
allowed_mutate = ["add_port_runtime", "add_port_permanent"]

[[plugin]]
id = "firewalld"
version = "0.2.0"
sha256 = "e5819cfe0e2c017648f628a27d0ed6e4a18ed402f3ff6de072e61a724f0aa99a"
```

## Partial mutate permission

*From v1.12.0.* Observe and mutate permissions are separate. Every observe
operation a plugin's types use must be attested, or the whole plugin is refused.
A mutate operation that `allowed_mutate` leaves out does not refuse the plugin:

- `audit` works, since it runs observe operations only.
- `plan` and `apply` refuse a run with exit 2 before contacting any target (no
  `ssh -G`, connection, backup or observation) when a resource could need a
  mutate operation that is not allowed. The message names the operations.

Allowing some mutate operations never allows the others, another type's, or the
plugin as a whole.

## Enable a plugin in a recipe

Declare the plugin at the top level of the recipe:

```yaml
plugins:
  - { id: firewalld, version: 0.2.0 }
```

Then use its types under `resources`:

```yaml
- id: allow_https
  type: firewalld.port
  with: { zone: public, port: 443/tcp, state: present }
```

`plugins` is allowed only in the top-level recipe. An included file that declares
it is rejected.

## How a plugin resource runs

- `plan` and `audit` run only the observe operations.
- `apply` runs a mutate operation only for a part whose observed state differs,
  and observes it again afterwards.
- Results use the existing statuses and exit codes, and no JSON key is added. Each
  plugin resource carries one provenance line (plugin, catalog and their SHA-256)
  in its existing `notes` or `reason`.
- `sinter mcp` refuses every manifest that declares `plugins`.

Sinter cannot prove that an operation a catalog classes as observe is read-only
on the host. That classification rests on the catalog review.

## firewalld types

Each type works separately on the runtime and the permanent configuration.
Before it observes anything, the plugin checks that the daemon runs and that the
zone (and, for a service, the service) exists. It never reloads, and never
changes a zone or an interface. The operations need root on the target: log in
as root or use `--sudo`.

| Type (version) | Fields | `state` |
|----------------|--------|---------|
| `firewalld.service` (0.1.0, 0.2.0) | `zone`, `service`, `state` | 0.1.0: `present`; 0.2.0: `present` or `absent` |
| `firewalld.port` (0.2.0) | `zone`, `port` (one port with its protocol, such as `8443/tcp`), `state` | `present` or `absent` |
| `firewalld.port_range` (0.2.0) | `zone`, `port` (a range such as `8000-8099/udp`), `state` | `present` only |
| `firewalld.protocol` (0.2.0) | `zone`, `protocol` (such as `gre`), `state` | `present` or `absent` |

Removing the `ssh` service and removing `22/tcp` are refused, since they could cut
the connection Sinter itself uses. A port range has no `absent`: firewalld answers
"no" for a range that is only partly allowed, so close ports one by one with
`firewalld.port`.

## Verification

firewalld 0.1.0 and 0.2.0 were measured on real hosts, and run through Sinter, on
these systems:

| OS | firewalld |
|----|-----------|
| Rocky Linux 9.8 | 1.3.4 |
| Rocky Linux 10.2 | 2.4.3 |
| Ubuntu 24.04 | 2.1.1 |

Not verified:

- Other OS and firewalld versions. Sinter does not check the version.
- The eight-label [release acceptance](/en/compatibility/platforms/) does not change
  a firewall. From v1.12.0 it checks the `sinter plugin` commands and the refusal
  of `plan` and `apply` without a mutate permission, not firewalld changes.
- Sinter's own timeout on a real host (a mutation whose outcome is unknown, reported
  as indeterminate). It is covered by tests only.
- Installing plugins on controllers whose file systems have no hard links (install
  then refuses).
