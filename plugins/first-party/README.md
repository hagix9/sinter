# First-party Resource Plugin files

These are the capability catalogs and plugin definitions that the Sinter
project has reviewed and confirmed on real hosts (DESIGN §38). A catalog is
usable only when the release's registry (`FIRST_PARTY_CATALOGS` in
`src/plugin/mod.rs`) lists its id, version and the SHA-256 of its exact
bytes. A test checks that every catalog file here is listed, with the same
digest, and that the registry lists nothing else.

Do not edit these files. Changing one byte changes the digest, and Sinter
then refuses the catalog. A change is a new version with new measurements
and a new registry entry.

| File | SHA-256 |
|---|---|
| `catalogs/firewalld-0.1.0.catalog.toml` | `27741bcc6b72dfbf69d918282fb454c324e7229b764873334a5c6c0af04707ff` |
| `plugins/firewalld-0.1.0.plugin.toml` | `47f33f171d239103cbb97450d17b57c857ce22436620ddf809fdd2be94948544` |
| `catalogs/firewalld-0.2.0.catalog.toml` | `d32ac3947279ec2581a7049f9fa931d29c904c91ea2484cafaa6759fe09c3641` |
| `plugins/firewalld-0.2.0.plugin.toml` | `e5819cfe0e2c017648f628a27d0ed6e4a18ed402f3ff6de072e61a724f0aa99a` |

The registry has two entries, firewalld 0.1.0 and firewalld 0.2.0. Both can
be pinned in the same trust file; a recipe enables one of them (each plugin
id at most once per run). firewalld 0.1.0 is registered in the source tree for
v1.9.0 and available from that release (published 2026-11-04). firewalld
0.2.0 is registered in the source tree and not yet in a published release.
These files are kept in the source repository. Their exact bytes are also
embedded in the `sinter` executable, which `sinter plugin list` and
`sinter plugin verify` compare with a plugin root; they are not separate
files in the release archive. Embedding trusts or enables nothing.

## firewalld 0.2.0

Four resource types, each with a runtime and a permanent facet:

| Type | Fields | States |
|---|---|---|
| `firewalld.service` | `zone`, `service` | `present`, `absent` |
| `firewalld.port` | `zone`, `port` (one port: `80/tcp`) | `present`, `absent` |
| `firewalld.port_range` | `zone`, `port` (`8000-8099/udp`, or one port) | `present` only |
| `firewalld.protocol` | `zone`, `protocol` (`gre`, `icmp`, `ipv6-icmp`, ...) | `present`, `absent` |

`firewalld.service` with `state: present` behaves exactly as in firewalld
0.1.0, whose seven operations are carried over unchanged. `state: absent`
removes only the named service (or port, or protocol) from the named zone;
nothing else is touched, and nothing is reloaded.

`port` is checked by the Core operand class `port_spec`: a port 1–65535 or a
range LOW-HIGH with LOW < HIGH, in canonical decimal, then `/` and one of
`tcp`, `udp`, `sctp`, `dccp`. `firewalld.port` uses the field kind
`port_single`, which refuses a range.

### Ranges are present only

A range has no `absent`. Measured on real hosts, firewalld answers a query
for a range that is only partly allowed with "no", and removing such a range
succeeds without removing anything. `absent` for a range could therefore
report compliance while ports of the range stay open. To close ports, use
`firewalld.port` with `state: absent` for each port: firewalld splits a range
when one port inside it is removed, and the query for that port then answers
"no". firewalld merges overlapping ranges (not adjacent ones); a query for a
port inside an allowed range answers "yes".

### Refused combinations (SSH protection and its limits)

The plugin refuses, before anything runs:

- `firewalld.service` with `service: ssh` and `state: absent`
- `firewalld.port` with `port: 22/tcp` and `state: absent`

These would most likely cut the SSH connection Sinter itself uses. They are
exact matches and do not cover every way to lose access: an SSH server on
another port, the ssh service in another zone, a rich rule, a source or an
interface binding. Check what the target's management connection depends on
before removing anything.

### Operations

All through `/usr/bin/firewall-cmd`, and all need root (run Sinter as root on
the target or with `--sudo`).

| Operation | Class | Exit codes (anything else is an error) |
|---|---|---|
| `state`, `zone_defined`, `service_defined`, `query_service_runtime`, `query_service_permanent`, `add_service_runtime`, `add_service_permanent` | as in 0.1.0 | as in 0.1.0 |
| `remove_service_runtime`, `remove_service_permanent` | mutate | 0 ok |
| `query_port_runtime`, `query_port_permanent` | observe | 0 present, 1 absent |
| `add_port_runtime`, `add_port_permanent`, `remove_port_runtime`, `remove_port_permanent` | mutate | 0 ok |
| `query_protocol_runtime`, `query_protocol_permanent` | observe | 0 present, 1 absent |
| `add_protocol_runtime`, `add_protocol_permanent`, `remove_protocol_runtime`, `remove_protocol_permanent` | mutate | 0 ok |

A query answers 0 for yes and 1 for no; a change answers 0, including adding
an entry that is there and removing one that is not (both a warning). The
errors measured were 102 (invalid port), 103 (invalid protocol), 112 (unknown
zone), 101 (unknown service, runtime), 252 (not running) and 253 (not root).
They are not listed, so Sinter treats them as errors: an observation fails
before any change, and a change is reported as a failure that may have
changed something, never as success. firewalld accepts `0/tcp` and
`90-80/tcp`; Sinter refuses both. A permanent query of an unknown protocol
answers 1, but the runtime query answers 103, so the runtime facet stops such
a resource.

### Confirmed on real hosts (2026-11-09)

| OS | firewalld |
|---|---|
| Rocky Linux 9.8 | 1.3.4 |
| Rocky Linux 10.2 | 2.4.3 |
| Ubuntu 24.04.5 | 2.1.1 |

On each of them, in a test zone with no interface and no source:

- The 14 new operations were measured directly with `firewall-cmd` (158
  steps), with identical exit codes on all three. The observe operations left
  the other zones, `/etc/firewalld`, the nftables ruleset and the test zone
  unchanged (40 of 40).
- Through Sinter, with these plugin bytes: plan, apply, a second apply (no
  change) and audit for services, single ports, port ranges and protocols;
  runtime/permanent drift in both directions; removal; a port inside a range;
  the refused combinations and invalid input (refused before any command, the
  firewall state unchanged); a range with `absent` refused for both port
  types; an unknown zone or protocol and a stopped daemon never reported as
  success; firewalld 0.1.0 through the same build (37 of 37 checks passed on
  each OS).

### Not confirmed

- Other OS or firewalld versions. Sinter does not check the version.
- Sinter's own timeout on a real host (a mutation whose outcome is unknown).
- The release acceptance on its eight target labels.

### Not covered

Rich rules, sources, interfaces, masquerade, forward ports, zones, ipsets,
policies, ICMP blocks, helpers, the direct interface, lockdown and panic mode.

## firewalld 0.1.0

The resource type `firewalld.service` makes a service present in a zone,
separately in the runtime and the permanent configuration. It has seven
operations, all through `/usr/bin/firewall-cmd`:

| Operation | Class | Exit codes (anything else is an error) |
|---|---|---|
| `state` | observe | 0 running, 252 not running |
| `zone_defined` | observe | 0 defined, 112 undefined |
| `service_defined` | observe | 0 defined, 101 undefined |
| `query_service_runtime` | observe | 0 present, 1 absent |
| `query_service_permanent` | observe | 0 present, 1 absent |
| `add_service_runtime` | mutate | 0 ok |
| `add_service_permanent` | mutate | 0 ok |

It cannot reload, remove a service, or change a zone or an interface. The
plugin checks that the daemon runs, the zone exists and the service exists
before it observes anything. The service check is required: on a real host,
a permanent query of a service that does not exist answers 1 ("absent").

The operations need root. Run Sinter as root on the target or with `--sudo`.
As another user, `firewall-cmd` exits 253, which is an error.

### Confirmed on real hosts (2026-11-01)

| OS | firewalld |
|---|---|
| Rocky Linux 9.8 | 1.3.4 |
| Rocky Linux 10.2 | 2.4.3 |
| Ubuntu 24.04 | 2.1.1 |

On each of them:

- The exit codes above were measured directly with `firewall-cmd`. The
  observe operations left the runtime and permanent configuration and the
  nftables ruleset unchanged.
- Through Sinter: plan and audit made no change; apply observed again and
  reached the wanted state; a second apply changed nothing; a difference
  between runtime and permanent showed as drift; a stopped daemon, an unknown
  zone or service, and an unlisted exit code were never reported as success.
- With the daemon stopped by a signal during a mutation, `firewall-cmd`
  itself gave up (exit 254). Sinter reported a failure that may have changed
  something, did not retry, and stopped the run.
- The plugin root checks (owner, mode, symbolic links, POSIX ACLs) refused
  every unsafe root.

### Not confirmed

- Other OS or firewalld versions. Sinter does not check the version.
- Sinter's own timeout on a real host (a mutation whose outcome is unknown,
  reported as indeterminate). It is covered by tests only.
- The release acceptance on its other five target labels.
- POSIX ACLs on a macOS controller (they are not detected there).

## Using it

Copy the files of the version you use into a plugin root on the controller
and pin them in the root's `trust.toml` (DESIGN §38.5). The root and
everything in it must be owned by you or by root and not writable by others,
and so must every directory above it.

```text
<plugin-root>/
  trust.toml                              (mode 0600)
  catalogs/firewalld-0.2.0.catalog.toml
  plugins/firewalld-0.2.0.plugin.toml
```

```toml
format = 1

[[catalog]]
id = "firewalld"
version = "0.2.0"
sha256 = "d32ac3947279ec2581a7049f9fa931d29c904c91ea2484cafaa6759fe09c3641"
attested_observe = ["state", "zone_defined", "service_defined", "query_service_runtime", "query_service_permanent", "query_port_runtime", "query_port_permanent", "query_protocol_runtime", "query_protocol_permanent"]
allowed_mutate = ["add_service_runtime", "add_service_permanent", "remove_service_runtime", "remove_service_permanent", "add_port_runtime", "add_port_permanent", "remove_port_runtime", "remove_port_permanent", "add_protocol_runtime", "add_protocol_permanent", "remove_protocol_runtime", "remove_protocol_permanent"]

[[plugin]]
id = "firewalld"
version = "0.2.0"
sha256 = "e5819cfe0e2c017648f628a27d0ed6e4a18ed402f3ff6de072e61a724f0aa99a"
```

For firewalld 0.1.0, pin `27741bcc…` (catalog) and `47f33f17…` (plugin) with
the five observe and two mutate operations of its table. Every observe
operation a resource type uses must be attested, or the plugin fails to load
as a whole. Mutate operations are separate (not yet in a published release:
Sinter v1.9.0 to v1.11.0 refuse the whole plugin instead): leave out the ones
you do not want run, for example the removal operations, or all of them for
audit only. The plugin still loads, `audit` works, and `plan` and `apply`
refuse, before contacting any host, every run with a resource that could need
an operation that is not allowed (a computed `state` counts as every value).
Allowing some operations never allows the others.

A recipe enables the plugin explicitly:

```yaml
version: 1
plugins:
  - { id: firewalld, version: 0.2.0 }
resources:
  - id: allow_https
    type: firewalld.service
    with: { zone: public, service: https, state: present }
  - id: close_8080
    type: firewalld.port
    with: { zone: public, port: 8080/tcp, state: absent }
  - id: app_ports
    type: firewalld.port_range
    with: { zone: public, port: 8000-8099/tcp, state: present }
  - id: allow_gre
    type: firewalld.protocol
    with: { zone: public, protocol: gre, state: present }
```

## Checking a plugin root

Not yet in a published release: `sinter plugin list` and `sinter plugin verify`
are in the source tree only; Sinter v1.9.0 to v1.11.0 do not have them.

Both commands only read: they change no file, read no recipe and contact no
host. `--plugin-root` and the default root are as for `plan`.

```text
sinter plugin list            # embedded plugins and what the root holds
sinter plugin verify          # every plugin the trust file pins
sinter plugin verify firewalld@0.2.0 --json
```

`list` shows, per plugin, whether this Sinter carries it, whether it is
installed (pinned in the trust file, file present), a status (`available`,
`installed`, `trust-incomplete`, `missing-file`, `digest-mismatch`,
`not-trusted`, `refused`, `unsupported-by-this-sinter`) and how many observe
and mutate operations the trust file enables. `verify` checks the root's
protection, the trust file, each file against its pin, the first-party
registry and the embedded file, and loads the plugin with the loader; it
lists the observe operations the plugin uses that the trust file does not
attest (`required_not_enabled`; while any is listed the loader refuses the
whole plugin) and the mutate operations it uses that the trust file does not
allow (`mutate_not_allowed`; the plugin loads, plan and apply refuse the
resources that could need them). Exit 0 when at least one
plugin was verified and everything passes, otherwise 2: nothing to verify (no
plugin root, an absent root, no `trust.toml`, nothing pinned) is exit 2, with
the reason in `nothing_verified` and on standard error. `list` with nothing
installed is exit 0. With `--json` stdout is one JSON document and messages
go to standard error. Neither command installs or trusts anything: copy the
files and write `trust.toml` as above.

Sinter cannot prove that an observe operation is read-only on the host; the
classification above rests on the measurements listed here (DESIGN §38.13).
Catalogs from anyone else are not supported.
