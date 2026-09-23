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

## Running against a target

`plan` and `apply` need a target — a machine whose state they observe. This
example uses a remote host, which Sinter reaches over SSH:

- `--host web01.example.com` — the SSH hostname (or address) of the target
  machine. Sinter connects to it over SSH and runs every observation and
  change there; nothing is installed on the target. Omit `--host` to target
  the machine you are running `sinter` on instead.
- `--sudo` — run every target-side operation as root via non-interactive
  `sudo -n`. It is needed here because writing under `/etc` normally
  requires root privileges for a non-root user.
  The target account must have passwordless sudo configured; without
  `--sudo`, permission failures are reported, not retried with elevation.

`validate` takes no `--host`: it checks only the recipe's structure and
semantics on the controller and never connects to any target. `plan` and
`apply` do need a target in this example because they observe (and `apply`
also changes) the actual state of `/etc/sinter-motd` on a specific machine.

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

A service resource is included in the [Quick Start](/en/getting-started/quick-start/)
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
[Recipes](/en/concepts/recipes/) for the full handler model.

## Two more resources to try

Sinter implements seven resource types — the
[Resource Reference](/en/reference/resources/) lists them all. Two
small variations on this recipe exercise two more of them.

### Inline content with `file`

A `file` resource writes inline content without a template file. This is a
complete recipe — copy it exactly as shown:

```yaml
version: 1

resources:
  - id: motd
    type: file
    with:
      path: /etc/sinter-motd
      content: "managed by sinter\n"
      mode: "0644"
```

Like the template version, the content is published atomically and re-applies
mutate nothing. Inline `content` is interpolated too — for example
`content: "token={{ vars.token }}"` works. The difference is the source:
`file` writes a literal string (or copies a `source` file verbatim), while
`template` renders an external template file and can also use template-local
values from `with.vars` as `{{ template.name }}`.

### A directory and a symbolic link

```yaml
version: 1

resources:
  - id: appdir
    type: directory
    with:
      path: /etc/myapp
      mode: "0755"

  - id: current_config
    type: link
    with:
      path: /etc/myapp/config
      target: /etc/sinter-motd
    depends_on: [appdir]
```

A `directory` creates exactly one directory — the parent (`/etc`) must
already exist; there is no recursive creation. A `link` ensures the symlink
at `path` points to `target`. `depends_on` orders the link after the
directory.

All of these run with the same commands shown above. For larger building
blocks — guarded `command` resources, `package`/`service` baselines, and
handlers — see [Recipe Overview](/en/recipes/overview/).

Continue to [Recipes](/en/concepts/recipes/) for the full model, or jump
to the [Resource Reference](/en/reference/resources/).
