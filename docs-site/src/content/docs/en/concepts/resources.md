---
title: Resources
description: The resource model — common fields, ordering, dependencies, notifications.
---

Resources are the unit of desired state. v0.4.1 implements seven types:
`file`, `directory`, `link`, `template`, `command`, `package`, `service`.

## Common fields

Every resource accepts:

| Field | Purpose |
|-------|---------|
| `id` | Unique identifier (required). |
| `type` | Resource type (required). |
| `with` | Type-specific parameters. |
| `when` | Boolean expression; false blocks the resource and its dependents. |
| `loop` | Expand the resource once per item (`{{ item }}`). |
| `depends_on` | List of resource ids that must succeed first. |

## Loops

A resource with `loop` is expanded once per item, with `{{ item }}` available
in its fields:

```yaml
resources:
  - id: tool
    type: package
    with:
      name: "{{ item }}"
      state: present
    loop: [jq, curl]
```

Each expansion gets an instance id — `tool[0]`, `tool[1]`, … — which is how
other resources must address it in `depends_on` (e.g.
`depends_on: [tool[0]]`). Depending on the bare loop id (`tool`) or on the
loop declaration from a resource outside the loop is a validation error, as
is `register` inside a loop.
| `notify` | Handler ids triggered when the resource changes. |
| `sensitive` | Redact this resource's values and derived values in all output. |

## Ordering and dependencies

Resources run in declaration order subject to `depends_on`. A failed or
indeterminate resource stops execution — remaining resources are reported as
blocked (fail-fast).

`when: false` is different from a failed dependency: it skips the resource and
blocks dependents under the dependency rules.

## Notification

`notify` names handlers that run once, at the end of a successful apply, only
if the notifying resource actually changed. Notifications are deduplicated —
several changed resources may trigger the same handler once.

## Sensitive resources

Mark a resource `sensitive: true` when its parameters, content, or results may
carry secrets. Sinter then redacts the values in every output channel —
including error messages — and hides content hashes and sizes. Values derived
from sensitive variables are automatically treated as sensitive.

## Observation contract

Stateful resources are observed twice in an apply: once for planning and once
immediately before mutation. Observation failures are reported as failures or
indeterminate — never as changes.
