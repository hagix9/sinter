---
title: Recipe Overview
description: Recipe examples built from functionality supported by Sinter v0.2.1.
---

All examples below use only resource types and fields implemented in v0.2.1.
Every recipe is platform-neutral — the same YAML applies to Ubuntu and Rocky
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

See the [Recipe Format reference](/sinter/en/reference/recipe-format/) and the
[Resource Reference](/sinter/en/reference/resources/) for the full schema.

:::note[Official recipe collections]
Curated recipe collections (for example a `linux-baseline` set) are a future
product improvement and do not exist yet — this page documents only what
v0.2.1 implements.
:::
