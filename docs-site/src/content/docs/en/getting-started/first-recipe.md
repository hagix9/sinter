---
title: First Recipe
description: A complete recipe touching a file, a service, and a handler.
---

This recipe writes a config file and ensures a service is running. It uses
variables, a dependency, and a delayed handler — the core building blocks of
Sinter recipes.

```yaml title="recipe.yaml"
version: 1

vars:
  greeting:
    value: hello
    sensitive: false

resources:
  - id: motd
    type: template
    with:
      path: /etc/motd
      source: templates/motd
      mode: "0644"
    notify:
      - restart_motd

  - id: sshd
    type: service
    with:
      name: sshd
      state: running
      enabled: true

handlers:
  - id: restart_motd
    service: motd
    action: restart
```

## What each piece does

- `version: 1` — the recipe format version (required).
- `vars` — literal values referenced as `{{ vars.greeting }}` in fields and
  templates. `sensitive: true` values are redacted from all output.
- `resources` — ordered list of desired state. Each has `id`, `type`,
  `with` (parameters), and optional `when`, `loop`, `depends_on`, `notify`,
  `sensitive`.
- `notify` — after `motd` changes, the handler `restart_motd` runs once at
  the end of the apply (delayed, deduplicated).
- `handlers` — delayed `restart`/`reload` service actions.

## The template

```text title="templates/motd"
{{ vars.greeting }} — managed by sinter
```

Template sources are resolved relative to the recipe file. Template-local
values may also be passed via `with.vars` and referenced as
`{{ template.name }}`.

## Run it

```sh
sinter validate recipe.yaml
sinter plan --host web01.example.com --sudo recipe.yaml
sinter apply --host web01.example.com --sudo recipe.yaml
```

## Expected behavior

- First apply: file written atomically, service ensured running/enabled,
  handler restarts `motd` once.
- Second apply: every resource unchanged — zero mutations, handler does not
  run.
- If any resource fails, execution stops (fail-fast); remaining resources are
  reported as blocked.

Continue to [Recipes](/sinter/en/concepts/recipes/) for the full model, or jump
to the [Resource Reference](/sinter/en/reference/resources/).
