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

## Tool arguments

Every tool's input schema declares `additionalProperties: false`. The server
enforces that only for the two host tools; the other six ignore an argument
they do not know, as they always have (compatibility).

| Tool | Arguments | Unknown argument |
|------|-----------|------------------|
| `sinter_get_version` | none | ignored |
| `sinter_classify_platform` | `os_release` (required), `arch`, `hostname` | ignored |
| `sinter_validate_manifest` | `manifest` (required) | ignored |
| `sinter_inspect_manifest` | `manifest` (required) | ignored |
| `sinter_plan` | `manifest`, `target` (one of the four snapshots; required), `sudo` (models sudo on the snapshot; no SSH) | ignored |
| `sinter_list_targets` | none | ignored |
| `sinter_plan_host` | `manifest`, `target` (a profile name; both required) | **rejected** before anything is read or contacted |
| `sinter_audit_host` | `manifest`, `target` (a profile name; both required) | **rejected** before anything is read or contacted |

A tool name that is not one of the eight is refused before anything runs.

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

Neither ever runs `systemctl daemon-reload`. The plan output (`sinter_plan` and
`sinter_plan_host`) gains an additive top-level `manager_reloads` list — the
reloads an apply would perform, each with phase `planned`, execution `not_run`
and `unknown: true` — and a service whose unit depends on a pending systemd
input change is reported as unknown (deferred until manager synchronization at
apply) rather than unchanged. `sinter_audit_host` reports a pending manager
reload as an independent `manager_reload` drift dimension. See
[service](/en/reference/resources/service/#automatic-manager-synchronization)
and the [JSON output contract](/en/reference/cli/#json-output-contract).

## Security model

- **Read-only tools, enforced at run time.** The tool surface has no
  mutating tool. Beyond that, the host tools construct the engine in
  `Mode::Plan` on a `TargetFs` that cannot produce a mutation permit, and
  every mutating operation requires that permit: this run-time check is what
  stops a change. `run_audit` additionally refuses any engine that could
  produce one. Command resources are never executed and audit as
  `NOT_AUDITABLE`. Tests check the commands the host tools actually send
  (observations only).
- **What a host tool can see.** It observes what the profile's SSH account
  (with the profile's sudo setting) can read on the target; Sinter adds no
  further limit to that.
- **Connection authority stays server-side.** Callers reference targets by
  opaque name only; host, port, user, known_hosts, identity files, and sudo
  cannot be supplied or overridden through tool arguments. The two host
  tools reject any parameter other than `manifest` and `target`; see
  [Tool arguments](#tool-arguments) for the other tools.
- **Strict host-key verification.** The profile's `known_hosts` is
  mandatory; unknown or changed host keys fail the connection. No automatic
  enrollment, no insecure fallback.
- **Manifest authority is constrained.** MCP manifests accept inline content
  only: `include:` and `source:` are rejected on the parsed structure before
  loading, so an MCP manifest grants no controller-local filesystem read
  authority. Staging uses a private 0700 directory and a `create_new` 0600
  file. Ordinary CLI recipes keep full `include:`/`source:` support.
- **No encrypted secrets over MCP.** A manifest that references an encrypted
  secret — `content`, `password_hash` or (v1.5.1) `password_verifier` written
  as a map such as `{ secret: … }` (see [sinter secrets](/en/reference/secrets/)) — is refused
  on the parsed structure before loading, with a message saying that
  decryption is not permitted over MCP; the reference text is not echoed.
  Every manifest-consuming tool passes through this one boundary. The MCP
  server never opens an identity and never decrypts a file, so recipes that
  use secrets are planned, applied and audited with the CLI, not through MCP.
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
- Decrypt or handle secrets — encrypted-secret references are rejected for
  MCP manifests.
- Return remote file or template bodies — content diffs are redacted at the
  MCP boundary.

## Limitations

- stdio transport only; there is no built-in network listener. Exposing it
  to remote clients requires a separate transport bridge operated outside
  Sinter.
- Sequential request handling; the server is a single stdio process.
- Sinter distributes Linux x86_64 artifacts only; `sinter mcp` on other
  platforms is a build-from-source capability, not a shipped artifact.
