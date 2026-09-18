---
title: Documentation WebMCP
description: Read-only documentation lookup tools exposed by this site via WebMCP.
---

This documentation site optionally exposes a small set of **read-only
documentation lookup tools** over [WebMCP](https://webmcp.org/) — a browser
API that lets AI agents and agent-enabled browsers call tools hosted by a web
page. These tools are for **documentation only**: they look up reference
material and never execute Sinter, never connect to targets, and never change
anything.

## Availability

The tools are registered only when the browsing environment supports WebMCP
(the `document.modelContext` / `navigator.modelContext` API). In browsers or
clients without it, nothing is registered and the site works as plain
documentation — no action is needed. Agent-enabled clients discover the tools
automatically when viewing the site.

## Tools

| Tool | Purpose |
|------|---------|
| `sinter_search_docs` | Free-text search over the documentation index; returns page titles, URLs, and summaries. |
| `sinter_list_resources` | Lists all recipe resource types of the current release with one-line summaries and doc URLs. |
| `sinter_get_resource` | Full parameter reference for one resource type (`file`, `directory`, `link`, `template`, `command`, `package`, `service`). |
| `sinter_get_compatibility` | Supported-platform matrix, acceptance reference, and managed-target requirements. |
| `sinter_get_installation` | Installation steps for a platform (`linux-x86_64` or `source`; old Ubuntu/Rocky identifiers remain aliases). |

The same machine-readable data is also served directly as JSON at
`/sinter/webmcp/en.json` and `/sinter/webmcp/ja.json`.

## Locales

Every tool accepts an optional `locale` input: `en` or `ja`. When omitted,
the locale is detected from the page currently being viewed
(`/sinter/ja/...` → `ja`, otherwise `en`). An invalid locale fails cleanly
with the supported locales listed, and if a localized payload is unavailable
the tools fall back to the English data rather than failing.

## Scope

This is a **documentation-site feature only**. Sinter itself does not
currently expose any runtime or execution MCP tools; if that ever changes, it
will be a separate, explicitly documented feature.
