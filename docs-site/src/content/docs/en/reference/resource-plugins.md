---
title: Resource Plugins
description: Data-only Resource Plugins, the plugin root, and the first-party firewalld plugin in v1.9.0.
---

*Available from v1.9.0.*

A Resource Plugin adds resource types named `<plugin>.<name>`, as data. No code
from a plugin runs in Sinter. Every program a plugin can run comes from a
capability catalog that lists fixed programs, argument templates with checked
operands, and the meaning of each exit status.

v1.9.0 provides one plugin: **`firewalld` 0.1.0**, with the resource type
`firewalld.service`. Catalogs from anyone else are not supported: a catalog is
used only when it is one of the reviewed first-party catalogs compiled into this
Sinter, and any other catalog is refused, even when it is pinned.

A recipe without `plugins:` behaves as before, and the plugin root is not read.

## Set up a plugin root

The plugin files are kept in the source repository, in
[`plugins/first-party/` at v1.9.0](https://github.com/hagix9/sinter/tree/v1.9.0/plugins/first-party).
They are not part of the release archive. Copy them to the controller without
editing them: one changed byte changes the digest, and Sinter refuses the file.

```text
<plugin-root>/
  trust.toml                              (mode 0600)
  catalogs/firewalld-0.1.0.catalog.toml
  plugins/firewalld-0.1.0.plugin.toml
```

`trust.toml` pins every plugin and catalog by the SHA-256 of its exact bytes and
lists which operations may be used:

```toml
format = 1

[[catalog]]
id = "firewalld"
version = "0.1.0"
sha256 = "27741bcc6b72dfbf69d918282fb454c324e7229b764873334a5c6c0af04707ff"
attested_observe = ["state", "zone_defined", "service_defined", "query_service_runtime", "query_service_permanent"]
allowed_mutate = ["add_service_runtime", "add_service_permanent"]

[[plugin]]
id = "firewalld"
version = "0.1.0"
sha256 = "47f33f171d239103cbb97450d17b57c857ce22436620ddf809fdd2be94948544"
```

Give the root with `--plugin-root DIR` on `validate`, `plan`, `apply` or `audit`.
The default is `$XDG_CONFIG_HOME/sinter/plugins`, else `~/.config/sinter/plugins`.

The root and every file in it must be owned by root or by the invoking user and
not writable by group or others. The same applies to the directories above it,
which may also be sticky. Symbolic links are refused. Any problem refuses the
recipe with exit 2 before anything runs.

- On Linux, a POSIX ACL entry that grants write to someone else is refused
  through the ACL mask. On macOS, ACLs are not detected.
- Plugins are refused on non-Unix controllers.

## Enable a plugin in a recipe

```yaml
version: 1
plugins:
  - { id: firewalld, version: 0.1.0 }
resources:
  - id: allow_http
    type: firewalld.service
    with: { zone: public, service: http, state: present }
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

## `firewalld.service`

Makes a service present in a firewalld zone, separately in the runtime and the
permanent configuration.

| Field | Required | Description |
|-------|----------|-------------|
| `zone` | yes | Zone name. |
| `service` | yes | firewalld service name. |
| `state` | yes | `present`. No other value is accepted. |

Before it observes anything, the plugin checks that the daemon runs and that the
zone and the service exist. It never reloads, removes a service, or changes a
zone or an interface.

The operations need root on the target: log in as root or use `--sudo`.

## Verification

Measured on real hosts, and run through Sinter, on these systems:

| OS | firewalld |
|----|-----------|
| Rocky Linux 9.8 | 1.3.4 |
| Rocky Linux 10.2 | 2.4.3 |
| Ubuntu 24.04 | 2.1.1 |

Not verified:

- Other OS and firewalld versions. Sinter does not check the version.
- The eight-label [release acceptance](/en/compatibility/platforms/) does not run
  plugins, so its result says nothing about them.
- Sinter's own timeout on a real host (a mutation whose outcome is unknown, reported
  as indeterminate). It is covered by tests only.
