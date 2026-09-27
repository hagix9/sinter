# Sinter surfaces and capability selection

Source of truth: Sinter v1.0.0 `docs-site/public/webmcp.js`,
`docs-site/src/content/docs/en/reference/webmcp.md`, `src/mcp.rs`,
`docs-site/src/content/docs/en/reference/mcp.md`, and `sinter --help`.

There are three different surfaces. Their tool names share the `sinter_`
prefix but they are unrelated; do not mix them up.

## 1. Documentation WebMCP (reference only)

Browser-side tools registered by https://sinter.fulltrust.co.jp/ pages, only
in browsers or agents that support WebMCP (`navigator.modelContext` or
`document.modelContext`). They look up documentation. They never run Sinter,
never contact a target, and change nothing.

| Tool | Returns |
|---|---|
| `sinter_search_docs` | Matching documentation pages (title, URL, summary). |
| `sinter_list_resources` | Resource types of the current release, with summaries. |
| `sinter_get_resource` | Full parameter reference and example for one resource type. |
| `sinter_get_compatibility` | Supported platforms and managed-target requirements. |
| `sinter_get_installation` | Installation steps (`linux-x86_64` or `source`). |

All accept an optional `locale` (`en` or `ja`). Without WebMCP, the same data
is plain HTTPS: https://sinter.fulltrust.co.jp/webmcp/en.json (or `ja.json`),
https://sinter.fulltrust.co.jp/llms.txt, and the reference pages.

## 2. Core MCP: `sinter mcp` (read-only operations)

A local stdio MCP server started from the Sinter binary, for example
`{"mcpServers": {"sinter": {"command": "sinter", "args": ["mcp"]}}}`. Every
tool is annotated `readOnlyHint: true`, `destructiveHint: false`,
`openWorldHint: false`. There is no apply, exec, or shell tool.

| Tool | Input | Does |
|---|---|---|
| `sinter_get_version` | — | Version and read-only capability statement. |
| `sinter_classify_platform` | `os_release`, optional `arch`, `hostname` | Platform family and package backend. |
| `sinter_validate_manifest` | `manifest` (recipe text) | Validate with the real parser; structured diagnostics. |
| `sinter_inspect_manifest` | `manifest` | Structure: ids, types, dependencies, sensitivity. No values. |
| `sinter_plan` | `manifest`, `target`, optional `sudo` | Plan against a built-in snapshot (`ubuntu2404`, `ubuntu2604`, `rocky9`, `rocky10`). No SSH, no real host. |
| `sinter_list_targets` | — | Names of administrator-configured SSH targets. |
| `sinter_plan_host` | `manifest`, `target` | Real read-only plan of a named target. |
| `sinter_audit_host` | `manifest`, `target` | Real read-only audit of a named target. |

Limits:

- Host tools reach only names from `sinter mcp --targets-file`. Without that
  file, `sinter_list_targets` is empty and host calls fail as unknown target.
  Connection details and sudo come from the file and cannot be passed as
  arguments.
- Manifests are inline text only: `include:` and `source:` are rejected. For
  recipes that use them, use the CLI.
- Manifest text is limited to 4 MiB. File and template content diffs are
  redacted in host plans.

## 3. CLI: `sinter`

The complete surface: `validate`, `plan`, `apply`, `audit`, `mcp`. It is the
only way to apply. Check it with `sinter --version`. Installing Sinter changes
the user's machine: offer the official instructions (installation page or
`sinter_get_installation`) and let the user decide.

## Choosing a surface

| Task | Prefer | Otherwise |
|---|---|---|
| Look up fields, platforms, installation | Documentation WebMCP | Docs over HTTPS, then [recipe.md](recipe.md) |
| Validate or inspect a recipe | CLI `validate`, or Core MCP `sinter_validate_manifest` / `sinter_inspect_manifest` | Manual review, labeled as not validated |
| Preview a real host | CLI `plan` with the confirmed target, or `sinter_plan_host` for a configured name | Explain how to run it; do not invent output |
| Check compliance of a real host | CLI `audit`, or `sinter_audit_host` | Same as above |
| Apply | CLI `apply` only, after confirmation ([safety.md](safety.md)) | Never through MCP; never simulated |

`sinter_plan` (built-in snapshots) is useful for trying a recipe against a
supported platform without any host; say that it is a simulation.

If no surface is available, stay in guidance-only mode: draft, review, and
explain, and state that nothing was validated, planned, applied, or audited.
