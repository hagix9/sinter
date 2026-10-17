---
title: Recipe Overview
description: Recipe examples built from functionality supported by Sinter v1.5.1.
---

All examples below use only resource types and fields implemented in v1.5.1.
The resource types are platform-neutral: Sinter picks `apt` or `dnf` from the
target. Package and service names are not always the same on Ubuntu and
RHEL-family targets (for example `apache2` / `httpd`); select such resources
with `when` on `facts.os.family`, as in the platform-conditional example.

## Package + service baseline

```yaml
version: 1

resources:
  - id: nginx
    type: package
    with:
      name: nginx
      state: present

  - id: nginx_service
    type: service
    with:
      name: nginx
      state: running
      enabled: true
    depends_on: [nginx]
```

## Managed config file with handler

```yaml
version: 1

resources:
  - id: app_conf
    type: file
    with:
      path: /etc/myapp/config.ini
      content: |
        [server]
        listen = 8080
      mode: "0640"
      owner: root
      group: root
    notify: [restart_app]

  - id: app_service
    type: service
    with:
      name: myapp
      state: running
      enabled: true

handlers:
  - id: restart_app
    service: myapp
    action: restart
```

The handler restarts `myapp` once, at the end of the apply, and only when the
file actually changed.

## systemd unit file with handler

```yaml
version: 1

resources:
  - id: app_unit
    type: file
    with:
      path: /etc/systemd/system/myapp.service
      content: |
        [Unit]
        Description=My app

        [Service]
        ExecStart=/opt/myapp/bin/myapp

        [Install]
        WantedBy=multi-user.target
      mode: "0644"
      owner: root
      group: root
    notify: [restart_app]

  - id: app_service
    type: service
    with:
      name: myapp.service
      state: running
      enabled: true
    depends_on: [app_unit]

handlers:
  - id: restart_app
    service: myapp.service
    action: restart
```

Sinter runs `systemctl daemon-reload` for you — no `command` resource is
needed. Because the unit file changed, the manager is reloaded before the
`service` resource decides. The manager is checked again before the handler
runs, but it is reloaded again only if new changes or a stale manager state
require it; the same already-synchronized change causes no second reload.
`depends_on` puts the unit file before the service: Sinter does not reorder
resources. A
reload only re-reads unit definitions; the `restart` handler is what applies a
changed unit file to an already-running process. When nothing changed, a
second apply performs no reload and no restart. See
[service](/en/reference/resources/service/#automatic-manager-synchronization).

## Guarded one-shot command

```yaml
version: 1

resources:
  - id: mark_provisioned
    type: command
    with:
      program: /usr/bin/touch
      args: ["/var/lib/myapp/provisioned"]
      creates: /var/lib/myapp/provisioned
```

`creates` makes the command idempotent — it runs only when the marker is
absent.

## Platform-conditional resource

```yaml
version: 1

resources:
  - id: debian_only
    type: package
    when: "facts.os.family == 'debian'"
    with:
      name: unattended-upgrades
      state: present
```

## Registered command results

```yaml
version: 1

resources:
  - id: probe
    type: command
    with:
      program: /usr/bin/test
      args: ["-f", "/etc/myapp/ready"]
      success_codes: [0, 1]
      changed_when: "false"
      register: probe_result

  - id: follow_up
    type: file
    depends_on: [probe]   # a register is read only by a direct dependent
    when: "registers.probe_result.exit_code == 0"
    with:
      path: /etc/myapp/confirmed
      content: "ready\n"
```

See the [Recipe Format reference](/en/reference/recipe-format/) and the
[Resource Reference](/en/reference/resources/) for the full schema.

## RHEL-family recipes (v1.5.1)

Complete recipes for Rocky Linux / RHEL 8, 9 and 10 live in
[`examples/recipes/`](https://github.com/hagix9/sinter/tree/main/examples/recipes) of the repository; each file explains itself. They use
`facts.os.version_major` to branch per release and were measured on Rocky Linux
8.10, 9.8 and 10.2 for v1.5.1.

| File | What it sets up |
|------|-----------------|
| `python-el8.yaml` | Python 3.6, 3.11 (+ pip) and 3.12 on EL8 by their real package names |
| `postgresql-os.yaml` | PostgreSQL 16 from the OS (stream `postgresql:16` on EL8/EL9), validated `postgresql.conf` / drop-in (`--config-file={{ staged }}`), `pg_hba.conf` with SCRAM, a `postgresql_role` |
| `postgresql-pgdg17.yaml` | PostgreSQL 17 from PGDG with a pinned, fingerprint-checked key and repository files (`gpgcheck`/`repo_gpgcheck` on) |
| `epel-crb.yaml` | EPEL + CRB/PowerTools and packages from each, with a second apply reporting no change |
| `signed-repo.yaml` | Any signed RPM repository: key file, repository file, package |
| `apache-htpasswd.yaml` | httpd with Basic authentication: the package-created `apache` account declared first, a secret htpasswd file, a config file validated by `httpd -t` |

:::note[Official recipe collections]
Curated recipe collections (for example a `linux-baseline` set) are a future
product improvement and do not exist yet — this page documents only what
v1.5.1 implements.
:::
