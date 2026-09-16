---
title: Resource Reference
description: All Sinter resource types implemented in v0.2.0.
---

Sinter v0.2.0 implements seven resource types. Parameters below are the
complete supported set — unknown `with` fields are schema errors.

| Type | Purpose | Key parameters |
|------|---------|----------------|
| [file](/sinter/en/reference/resources/file/) | Regular file content + metadata | `path`, `state`, `content`/`source`, `owner`, `group`, `mode` |
| [directory](/sinter/en/reference/resources/directory/) | Directory presence + metadata | `path`, `state`, `owner`, `group`, `mode` |
| [link](/sinter/en/reference/resources/link/) | Symbolic links | `path`, `target`, `state` |
| [template](/sinter/en/reference/resources/template/) | Rendered controller-side templates | `path`, `source`, `vars`, `mode` |
| [command](/sinter/en/reference/resources/command/) | Exact-argv program execution | `program`, `args`, `creates`/`removes`, `changed_when`, `register` |
| [package](/sinter/en/reference/resources/package/) | Package install/remove (apt/dnf) | `name`, `state` |
| [service](/sinter/en/reference/resources/service/) | systemd state + enablement | `name`, `state`, `enabled` |

## Shared conventions

- `path`-type parameters are absolute paths; parent paths must already exist
  and pass the trust-boundary check (no unexpected symlinks).
- `mode` is always a quoted four-digit octal string (`"0644"`).
- `state` defaults to `present` for filesystem resources; `package` requires
  it explicitly.
- Content publication is atomic (rename); existing metadata is preserved when
  omitted.
- All types are idempotent — a converged resource mutates nothing on re-apply.
