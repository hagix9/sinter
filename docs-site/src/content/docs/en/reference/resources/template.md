---
title: template
description: Render a controller-side template file to a managed path.
---

**Purpose:** render a template file stored next to the recipe and publish the
result at `path` on the target.

## Synopsis

```yaml
- id: app_conf
  type: template
  with:
    path: /etc/myapp/config.ini
    source: templates/config.ini
    mode: "0640"
    vars:
      listen_port: 8080
```

```text title="templates/config.ini"
[server]
listen = {{ template.listen_port }}
hostname = {{ facts.hostname }}
```

## Parameters

| Parameter | Required | Type | Default | Description |
|-----------|----------|------|---------|-------------|
| `path` | yes | string (absolute path) | — | Destination on the target. |
| `source` | yes | string | — | Controller-side template, resolved relative to the recipe file. |
| `state` | no | string | `present` | `present` or `absent`. |
| `vars` | no | map | — | Template-local values, exposed as `template.<name>`. |
| `owner` | no | string | — | Owner name. |
| `group` | no | string | — | Group name. |
| `mode` | no | string | — | Quoted four-digit octal. |

## Expected behavior

- The template is rendered on the controller and published atomically like
  [`file`](/en/reference/resources/file/).
- Template expressions may read `vars.*`, `facts.*`, `registers.*`, and
  `template.*`. `template.*` names never shadow the other namespaces.
- `content` is **not** supported — template resources always use `source`.
- Only `{{ expression }}` is rendered. Write `\{{` for a literal `{{`, and
  `{{ "{%" }}` for a literal `{%`. Jinja statement (`{% ... %}`) and comment
  (`{# ... #}`) tags are not supported and are an error (see below), never
  copied silently. Only an opener followed by its own closer (`%}` for `{%`,
  `#}` for `{#`) is a tag. An opener with no closer, and a `{#` right after `$`
  (shell `${#var}`), are plain text and are published as written.
- A template output that really changes a systemd manager input (a unit file, drop-in,
  alias/mask/`.wants`/`.requires` link, or `system.conf`) makes Sinter run
  `systemctl daemon-reload` automatically before the next service or handler
  that needs it, and at the end of a successful apply. See
  [service](/en/reference/resources/service/#automatic-manager-synchronization).

## Idempotency

Fully idempotent — unchanged rendered output produces no mutation and triggers
no handler notification.

## Failure behavior

- Missing `source` file or template evaluation errors (e.g. undefined
  variables) fail at validation/apply with a descriptive error — sensitive
  values are redacted from the message.
- A Jinja tag (`{% if ... %}`, `{% for ... %}`, `{# ... #}`) fails validation
  (exit 2) with the resource, the source file, and the line and column of the
  tag. To publish such a file unchanged, use a [`file`](/en/reference/resources/file/)
  resource with `source` instead.
- Same filesystem safety rules as `file` (trust boundary, symlink rejection,
  atomic publication).

## Platform notes

Applies to all supported targets.

## Related

[file](/en/reference/resources/file/) ·
[Recipes — expressions](/en/concepts/recipes/)
