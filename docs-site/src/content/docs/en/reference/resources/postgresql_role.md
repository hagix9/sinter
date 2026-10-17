---
title: postgresql_role
description: Manage one role of a local PostgreSQL server, with a SCRAM-SHA-256 verifier from an encrypted secret.
---

**Purpose:** declare one **role** of a PostgreSQL server running on the
target: present or absent, the attributes you name, and optionally its
password as a **SCRAM-SHA-256 verifier** kept in an encrypted secret. It is
planned, applied and audited like any other resource. New in v1.5.1, which
is not yet released; v1.5.0 rejects this resource type.

## Synopsis

```yaml
- id: app_role
  type: postgresql_role
  depends_on: [pg_service]
  with:
    name: app
    login: true
    connection_limit: 20
    password_verifier: { secret: secrets/app-verifier.age }
```

## Parameters

| Parameter | Required | Type | Default | Description |
|-----------|----------|------|---------|-------------|
| `name` | yes | string | — | Role name. Static. `[a-z_][a-z0-9_]*`, at most 63 bytes, not `pg_*`. |
| `state` | no | string | `present` | `present` or `absent`. |
| `login`, `superuser`, `createdb`, `createrole`, `inherit`, `replication`, `bypassrls` | no | boolean | unmanaged | Each declared attribute is managed; an undeclared one is never changed (a new role gets PostgreSQL's default for it). |
| `connection_limit` | no | integer | unmanaged | `-1` (no limit) or more. |
| `password_verifier` | no | `{ secret: <path> }` | unmanaged | An encrypted secret holding exactly one SCRAM-SHA-256 verifier. Never a literal. |
| `os_user` | no | string | `postgres` | The operating system account that owns the cluster; `psql` runs as it (peer authentication). |
| `psql` | no | string | `/usr/bin/psql` | `/usr/bin/psql` or a PGDG `/usr/pgsql-<major>/bin/psql` (e.g. `/usr/pgsql-17/bin/psql`); no other path is accepted, because plan and audit run it. |
| `port` | no | integer | server default | Server port, for a cluster on a non-default port. |
| `database` | no | string | `postgres` | Database to connect to. |

Unknown fields are schema errors. There is no plaintext `password` field.

## Expected behavior

- **Local server, peer authentication.** Sinter runs `psql` on the target as
  `os_user` through `setpriv` (no password is used to connect), so the
  resource needs root: connect as root or use `--sudo`.
- **Observation** is one read-only `SELECT` on `pg_catalog.pg_authid`, passed
  on the command line, that names only the role. When a verifier is declared,
  the stored password field is read and compared **in memory** (constant
  time); it is never shown.
- `present`, role missing → `CREATE ROLE "name" WITH <declared attributes>
  [PASSWORD '<verifier>']`. Undeclared attributes get PostgreSQL's defaults
  (`NOSUPERUSER`, `NOLOGIN`, `INHERIT`, ...). Nothing is granted implicitly.
- `present`, role exists → `ALTER ROLE` of exactly the differing declared
  attributes, and `ALTER ROLE ... PASSWORD` only when the stored verifier
  differs (an `md5` hash or no password counts as different).
- `absent` → `DROP ROLE "name"` without `CASCADE`. PostgreSQL refuses to drop a
  role that still owns objects or holds privileges; that refusal is the result.
- The role Sinter connects as (`os_user`) is never dropped and never loses
  `superuser` or `login`.
- **plan** predicts from the observation. If the server cannot be observed yet
  because an earlier resource still has to install or start it, the role is
  reported **Unknown** in plan; apply never guesses.
- **audit** reports drift per dimension (`login`, `connection_limit`,
  `password_verifier`, ...). A password dimension never carries a value.

## The verifier is secret material

A SCRAM verifier is not the password, but it allows offline guessing and is
treated like a password hash:

- It is accepted only from an encrypted secret (`password_verifier: { secret:
  ... }`, see [sinter secrets](/en/reference/secrets/)) and must be exactly
  `SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>` with at least
  4096 iterations and 32-byte keys (one trailing newline is allowed). A value
  PostgreSQL would not parse as a verifier is refused, because PostgreSQL
  would store it as a plaintext password. A plaintext password or an
  `md5…` hash is refused with fixed text before anything runs.
- It reaches the server only on `psql`'s **standard input**, never in argv, an
  environment variable or a temporary file, and never in plan, apply or audit
  output.
- **Server-side logging.** Before any change, the session sets
  `log_min_messages`, `log_min_error_statement` and `log_statement` and the
  duration, sampling and debug logging (`log_min_duration_statement`,
  `log_duration`, `log_*_sample*`, `debug_print_*`), `track_activities`,
  `pg_stat_statements.track`/`track_utility` and `pgaudit.log` to silent
  values, then **reads every one back** with `current_setting`. Only when all
  of them are verified does the change run (in one transaction); otherwise
  nothing carrying the verifier is sent and the resource fails. A failed
  statement is therefore not logged with its text either, and `psql`'s own
  output for the change is withheld from the result.
- PostgreSQL itself stores the verifier in `pg_authid` (and its WAL), exactly
  as given — whatever `password_encryption` says.

Produce a verifier on a machine you trust, from a password typed on standard
input (Python standard library only; nothing is sent anywhere):

```sh
python3 -c 'import base64,hashlib,hmac,os,sys
pw=sys.stdin.buffer.read().rstrip(b"\n"); s=os.urandom(16); i=4096
k=hashlib.pbkdf2_hmac("sha256",pw,s,i); c=hmac.new(k,b"Client Key","sha256").digest()
v=hmac.new(k,b"Server Key","sha256").digest(); b=lambda x: base64.b64encode(x).decode()
print("SCRAM-SHA-256$%d:%s$%s:%s"%(i,b(s),b(hashlib.sha256(c).digest()),b(v)))' > app.verifier
sinter secrets encrypt app.verifier -o secrets/app-verifier.age
```

Do not use `psql`'s `\password` to set a password on a server that logs
statements: it sends `ALTER ROLE ... PASSWORD` like any other statement.

## Idempotency

Fully idempotent: a role that matches every declared dimension produces no
statement and no change.

## Failure behavior

- Not root, `psql` missing, the server not running, or `os_user` not able to
  connect → the resource fails (in plan: an error, or Unknown after an earlier
  planned change). `psql`'s output is not shown.
- Log suppression not verified → fails, nothing sent.
- A refused change (PostgreSQL error) → fails; the role is observed again, and
  the result says no change when it is unchanged.
- An `os_user` that is not a superuser cannot read `pg_authid` or set the
  logging parameters → fails before any change.

## Platform notes

Measured in v1.5.1 development on PostgreSQL 10.23 (Rocky Linux 8 default
stream), 13.23 (Rocky Linux 9 default), 16.15 (Rocky Linux 8/9 stream 16 and
Rocky Linux 10) and 17.11 (PGDG on Rocky Linux 9). PostgreSQL 10 or later is
required. `pg_hba.conf` is not managed by this resource; manage it as a file
(see the [PostgreSQL recipes](/en/recipes/overview/)).

## Related

[user](/en/reference/resources/user/) ·
[sinter secrets](/en/reference/secrets/) ·
[file](/en/reference/resources/file/)
