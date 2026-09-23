---
title: Resource Reference
description: All Sinter resource types implemented in v0.5.0.
---

Sinter v0.5.0 implements seven resource types. Parameters below are the
complete supported set — unknown `with` fields are schema errors.

| Type | Purpose | Key parameters |
|------|---------|----------------|
| [file](/en/reference/resources/file/) | Regular file content + metadata | `path`, `state`, `content`/`source`, `owner`, `group`, `mode` |
| [directory](/en/reference/resources/directory/) | Directory presence + metadata | `path`, `state`, `owner`, `group`, `mode` |
| [link](/en/reference/resources/link/) | Symbolic links | `path`, `target`, `state` |
| [template](/en/reference/resources/template/) | Rendered controller-side templates | `path`, `source`, `vars`, `mode` |
| [command](/en/reference/resources/command/) | Exact-argv program execution | `program`, `args`, `creates`/`removes`, `changed_when`, `register` |
| [package](/en/reference/resources/package/) | Package install/remove (apt/dnf) | `name`, `state` |
| [service](/en/reference/resources/service/) | systemd state + enablement | `name`, `state`, `enabled` |

## Shared conventions

- `path`-type parameters are absolute paths; parent paths must already exist
  and pass the trust-boundary check (no unexpected symlinks).
- `mode` is always a quoted four-digit octal string (`"0644"`).
- `state` defaults to `present` for filesystem resources; `package` requires
  it explicitly.
- Content publication is atomic (rename); existing metadata is preserved when
  omitted.
- All types are idempotent — a converged resource mutates nothing on re-apply.
