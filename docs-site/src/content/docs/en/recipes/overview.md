---
title: Recipe Overview
description: Recipe examples built from functionality supported by Sinter v1.3.0.
---

All examples below use only resource types and fields implemented in v1.3.0.
Every recipe is platform-neutral — the same YAML applies to Ubuntu and RHEL-family
targets.

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
    when: "registers.probe_result.exit_code == 0"
    with:
      path: /etc/myapp/confirmed
      content: "ready\n"
```

See the [Recipe Format reference](/en/reference/recipe-format/) and the
[Resource Reference](/en/reference/resources/) for the full schema.

:::note[Official recipe collections]
Curated recipe collections (for example a `linux-baseline` set) are a future
product improvement and do not exist yet — this page documents only what
v1.3.0 implements.
:::
