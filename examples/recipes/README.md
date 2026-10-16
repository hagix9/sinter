# RHEL-family recipes (v1.5.1)

Complete recipes for Rocky Linux / RHEL 8, 9 and 10. Each file starts with a
comment that explains what it does and why; `facts.os.version_major` selects
per-release steps. EL8 is an SSH **target** only (run Sinter from EL9/EL10 or
Ubuntu). File resources need the `attr` package on the target.

| File | What it sets up |
|------|-----------------|
| `python-el8.yaml` | Python 3.6, 3.11 (+ pip), 3.12 on EL8 by their real package names |
| `postgresql-os.yaml` | PostgreSQL 16 from the OS, validated config, SCRAM `pg_hba.conf`, a role |
| `postgresql-pgdg17.yaml` | PostgreSQL 17 from PGDG with a pinned key and repository files |
| `epel-crb.yaml` | EPEL + CRB/PowerTools and packages from each |
| `signed-repo.yaml` | Any signed RPM repository (replace the key and URL first) |
| `apache-htpasswd.yaml` | httpd with Basic authentication from a secret htpasswd file |

Secrets are not shipped. Create them before applying:

- `secrets/app-verifier.age` — the SCRAM-SHA-256 verifier of the PostgreSQL
  role `app` (see the `postgresql_role` reference for a one-line generator),
  encrypted with `sinter secrets encrypt`.
- `secrets/htpasswd.age` — an htpasswd file (`htpasswd -niB <user>`), encrypted
  the same way.

```sh
sinter validate examples/recipes/postgresql-os.yaml
sinter apply examples/recipes/postgresql-os.yaml --host <host> --sudo
sinter apply examples/recipes/postgresql-os.yaml --host <host> --sudo   # no change
sinter audit examples/recipes/postgresql-os.yaml --host <host> --sudo
```
