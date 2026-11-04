# First-party Resource Plugin files

These are the capability catalogs and plugin definitions that the Sinter
project has reviewed and confirmed on real hosts (DESIGN §38). A catalog is
usable only when the release's registry (`FIRST_PARTY_CATALOGS` in
`src/plugin/mod.rs`) lists its id, version and the SHA-256 of its exact
bytes. A test checks that every file here and its registry entry agree.

Do not edit these files. Changing one byte changes the digest, and Sinter
then refuses the catalog. A change is a new version with new measurements
and a new registry entry.

| File | SHA-256 |
|---|---|
| `catalogs/firewalld-0.1.0.catalog.toml` | `27741bcc6b72dfbf69d918282fb454c324e7229b764873334a5c6c0af04707ff` |
| `plugins/firewalld-0.1.0.plugin.toml` | `47f33f171d239103cbb97450d17b57c857ce22436620ddf809fdd2be94948544` |

Status: registered in the source tree for v1.9.0 and available from that release
(published 2026-11-04). These files stay in the source repository and are not part
of the release archive.

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

Copy the two files into a plugin root on the controller and pin them in the
root's `trust.toml` (DESIGN §38.5). The root and everything in it must be
owned by you or by root and not writable by others, and so must every
directory above it.

```text
<plugin-root>/
  trust.toml                              (mode 0600)
  catalogs/firewalld-0.1.0.catalog.toml
  plugins/firewalld-0.1.0.plugin.toml
```

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

A recipe enables the plugin explicitly:

```yaml
version: 1
plugins:
  - { id: firewalld, version: 0.1.0 }
resources:
  - id: allow_http
    type: firewalld.service
    with: { zone: public, service: http, state: present }
```

Sinter cannot prove that an observe operation is read-only on the host; the
classification above rests on the measurements listed here (DESIGN §38.13).
Catalogs from anyone else are not supported.
