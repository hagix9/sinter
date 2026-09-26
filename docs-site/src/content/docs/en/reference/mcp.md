---
title: Core MCP
description: sinter mcp — a read-only Model Context Protocol endpoint for inspecting Sinter operations over stdio.
---

Core MCP is Sinter's operational MCP surface: `sinter mcp` serves a minimal,
strictly **read-only** MCP (Model Context Protocol) endpoint over stdio, so
MCP-capable clients and agents can validate recipes, inspect structure, plan
against supplied-facts targets, and observe real named hosts — without ever
mutating anything.

It is unrelated to this site's **Documentation WebMCP**, which is a
browser-side feature that only looks up documentation pages. Core MCP
exposes Sinter's own operations.

## Running the server

```sh
sinter mcp                          # no targets; host tools fail closed
sinter mcp --targets-file targets.toml
```

Transport is newline-delimited JSON-RPC 2.0 on stdin/stdout (protocol
revision `2025-03-26`). stdout carries protocol frames only; diagnostics go
to stderr. Supported methods: `initialize`, `ping`, `tools/list`,
`tools/call`, JSON-RPC batches, and `notifications/*`.

Client configuration example (stdio servers):

```json
{ "mcpServers": { "sinter": { "command": "sinter", "args": ["mcp"] } } }
```

## Tools

All eight tools are read-only. There is intentionally no apply, exec, or
shell tool. Every tool carries the MCP annotations `readOnlyHint: true`,
`destructiveHint: false`, and `openWorldHint: false`.

| Tool | Purpose |
|------|---------|
| `sinter_get_version` | Crate version and read-only capability statement. |
| `sinter_classify_platform` | Classify a platform from `/etc/os-release` content (family, package backend) via the real platform model. |
| `sinter_validate_manifest` | Validate recipe text with the real `load_model` parser; structured diagnostics. |
| `sinter_inspect_manifest` | Structural recipe summary: resource identities, types, dependencies, sensitivity flags. Values are never returned. |
| `sinter_plan` | Plan a recipe against a **supplied-facts** target snapshot (`ubuntu2404`, `ubuntu2604`, `rocky9`, `rocky10`) using the in-process scripted target — production planning code, no SSH, no real host, `Mode::Plan` only. |
| `sinter_list_targets` | List the opaque names of administrator-configured SSH target profiles (names only — never connection details). |
| `sinter_plan_host` | Plan a recipe against a **named** SSH target profile: real-host read-only observation via the production `Mode::Plan` path. |
| `sinter_audit_host` | Audit whether a named SSH target satisfies a recipe via the production `run_audit` path. Reports `no_drift`/`drift` with per-resource `PASS`/`DRIFT`/`NOT_AUDITABLE`/`NOT_APPLICABLE`/`ERROR` detail. |

## Named targets (`--targets-file`)

`--targets-file` points at an administrator-owned TOML registry of SSH
profiles, loaded once at startup and immutable while serving:

```toml
[targets.web01]
host = "web01.example.com"
port = 22                                        # optional, default 22
user = "deploy"
known_hosts = "/secure/path/known_hosts"
identity_files = ["/secure/path/id_ed25519"]     # optional
sudo = false                                     # optional privilege policy

[targets.db01]
host = "10.0.0.20"
user = "ops"
known_hosts = "/secure/path/known_hosts"
sudo = true
```

- Profile names: `[A-Za-z0-9_-]`, start alphanumeric, max 64 chars.
- A missing, unreadable, malformed, or structurally invalid file aborts
  `sinter mcp` startup — the server never runs with a partial registry.
- Without `--targets-file`, host tools stay registered but fail closed:
  `sinter_list_targets` returns an empty list and host calls report
  `unknown target`.
- An omitted or empty `identity_files` follows the existing Sinter SSH
  authentication behavior and may use default identity resolution; it does
  not disable authentication.

## Plan vs audit

- `sinter_plan_host` answers "what would change" — a non-authoritative
  preview, observation only.
- `sinter_audit_host` answers "does the target currently satisfy the
  recipe" — per-resource compliance/drift classification, observation only.

Both are real SSH observations of the named target, read-only end to end.

## Security model

- **Read-only is structural.** Host tools construct the engine in
  `Mode::Plan` on a `TargetFs` that cannot produce a mutation permit; every
  mutating operation requires that permit. `run_audit` additionally refuses
  any engine that could produce one. Command resources are never executed
  and audit as `NOT_AUDITABLE`.
- **Connection authority stays server-side.** Callers reference targets by
  opaque name only; host, port, user, known_hosts, identity files, and sudo
  cannot be supplied or overridden through tool arguments — unexpected
  parameters are rejected outright.
- **Strict host-key verification.** The profile's `known_hosts` is
  mandatory; unknown or changed host keys fail the connection. No automatic
  enrollment, no insecure fallback.
- **Manifest authority is constrained.** MCP manifests accept inline content
  only: `include:` and `source:` are rejected on the parsed structure before
  loading, so an MCP manifest grants no controller-local filesystem read
  authority. Staging uses a private 0700 directory and a `create_new` 0600
  file. Ordinary CLI recipes keep full `include:`/`source:` support.
- **Bounded input.** Manifest text is limited to 4 MiB; SSH setup, socket,
  and per-command operations are all time-bounded.
- **Redaction.** Profile internals and staged paths are removed from
  tool-facing diagnostics, and host-plan file/template content diffs are
  always redacted regardless of manifest sensitivity flags.

## What MCP deliberately cannot do

- Apply or remediate — no mutation tool exists.
- Execute arbitrary commands or shells.
- Reach arbitrary hosts — only administrator-named profiles are reachable.
- Read controller files — `include:`/`source:` are rejected for MCP
  manifests.
- Return remote file or template bodies — content diffs are redacted at the
  MCP boundary.

## Limitations

- stdio transport only; there is no built-in network listener. Exposing it
  to remote clients requires a separate transport bridge operated outside
  Sinter.
- Sequential request handling; the server is a single stdio process.
- Sinter distributes Linux x86_64 artifacts only; `sinter mcp` on other
  platforms is a build-from-source capability, not a shipped artifact.
