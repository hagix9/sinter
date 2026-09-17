---
title: First Recipe
description: A first substantial recipe — variables and a rendered template.
---

This recipe renders a controller-side template onto the target. It uses
variables and a rendered template — core building blocks of Sinter recipes.

```yaml title="recipe.yaml"
version: 1

vars:
  greeting:
    value: hello
    sensitive: false

resources:
  - id: greeting
    type: template
    with:
      path: /etc/sinter-motd
      source: templates/greeting
      mode: "0644"
```

The example deliberately writes to `/etc/sinter-motd` — a path that does not
exist by default on either supported target — rather than `/etc/motd`, which
Rocky ships as a package-owned file and Ubuntu manages dynamically through
`/etc/update-motd.d`.

## What each piece does

- `version: 1` — the recipe format version (required).
- `vars` — literal values referenced as `{{ vars.greeting }}` in fields and
  templates. `sensitive: true` values are redacted from all output.
- `resources` — ordered list of desired state. Each has `id`, `type`,
  `with` (parameters), and optional `when`, `loop`, `depends_on`, `notify`,
  `sensitive`.
- `id: greeting` — the resource id, a label used by `depends_on` and
  `notify`. It is unrelated to the unit names of any `service` resources.

## The template

```text title="templates/greeting"
{{ vars.greeting }} — managed by sinter
```

Template sources are resolved relative to the recipe file. Template-local
values may also be passed via `with.vars` and referenced as
`{{ template.name }}`.

## Run it

```sh
sinter validate recipe.yaml
sinter plan --host web01.example.com recipe.yaml
sinter apply --host web01.example.com --sudo recipe.yaml
```

## Expected behavior

- `validate` reports the recipe as ok without contacting any target.
- `plan` observes the target and previews the file Sinter would write. It
  creates or changes nothing.
- First apply: the template is rendered on the controller and the result is
  published atomically at `/etc/sinter-motd` as `root:root`, mode `0644`.
- Second apply: every resource is unchanged — zero mutations.
- If any resource fails, execution stops (fail-fast); remaining resources are
  reported as blocked.

## Adding a service

A service resource is included in the [Quick Start](/sinter/en/getting-started/quick-start/)
basics. Keep one rule in mind: a `service` resource and a handler `service:`
both name the **systemd unit on the target**, and unit names differ between
distributions — the SSH daemon is `ssh.service` on Ubuntu but `sshd.service`
on Rocky Linux. You can scope such a resource to one platform with the
documented `when` expression:

```yaml
  - id: ssh_service
    type: service
    with:
      name: ssh          # sshd on RHEL-family targets
      state: running
    when: "facts.os.family == 'debian'"
```

To restart a service only when a resource changes, add a handler — see
[Recipes](/sinter/en/concepts/recipes/) for the full handler model.

Continue to [Recipes](/sinter/en/concepts/recipes/) for the full model, or jump
to the [Resource Reference](/sinter/en/reference/resources/).
