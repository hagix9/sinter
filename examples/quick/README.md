# Quick recipes

Small, fast recipes for checking one behaviour at a time. Each is a single
short file, so when something fails the cause is obvious. They are meant to be
run against a disposable RHEL-family or Debian/Ubuntu host (some need root /
`--sudo`).

| File | Exercises |
|------|-----------|
| `packages.yaml` | `package` `state: present`, and dnf metadata auto-acquisition (no manual `dnf makecache`) |
| `package-proxy.yaml` | one recipe-wide `env` proxy for every `package`/`command` (`NO_PROXY`, per-resource override) |
| `dnf-module.yaml` | installing a package from a DNF module stream (`command` + `depends_on`) |
| `accounts-and-paths.yaml` | group → user → directory → file with explicit `depends_on` (package-created accounts are not inferred) |
| `httpd-service.yaml` | package → dedicated user → service with explicit `depends_on` (a failed producer blocks its dependents) |
| `validate-sshd-config.yaml` | `validate`: check the staged file before it is published |

`depends_on` is ordering and gating, not inference: a resource runs only after
the ids it lists have succeeded, and if a producer fails its dependents are
**blocked and never run** (see `httpd-service.yaml`, `dnf-module.yaml`,
`accounts-and-paths.yaml`). Sinter never adds a dependency on its own — a
package is not assumed to create an account or a unit.

Validate syntax without a target:

```sh
sinter validate examples/quick/packages.yaml
```

Apply to a target (read the output; a second apply should report no change):

```sh
sinter apply examples/quick/packages.yaml --host host.example.com --user admin --sudo
sinter apply examples/quick/packages.yaml --host host.example.com --user admin --sudo   # idempotent
```

The larger, multi-role example lives in [`examples/multihost/`](../multihost/). Complete
RHEL-family recipes (Python, PostgreSQL, EPEL/CRB, signed repositories, Apache)
live in [`examples/recipes/`](../recipes/).
