---
title: ChatGPT via the Secure MCP Tunnel
description: Connect ChatGPT to your own read-only sinter mcp through the OpenAI Secure MCP Tunnel, with sinter serve or the documented systemd unit.
---

This guide connects ChatGPT to **your own** [`sinter mcp`](/en/reference/mcp/)
through the OpenAI **Secure MCP Tunnel**, using the official OpenAI
`tunnel-client`. `sinter serve` and its setup commands were released in
Sinter v1.14.0.

```text
ChatGPT (custom MCP app: Connection = Tunnel)
  → OpenAI Secure MCP Tunnel   (outbound HTTPS from your controller only)
  → official tunnel-client     (started by sinter serve, or by systemd)
  → sinter mcp                 (stdio child; the eight read-only tools)
  → named SSH targets          (only those in your targets file)
```

## What this is, and what it is not

- **Core MCP** (`sinter mcp`) is the read-only tool server: eight tools, no
  apply, no command execution, targets only from the administrator's targets
  file. See the [MCP reference](/en/reference/mcp/).
- **`sinter serve`** only starts the official `tunnel-client` in the
  foreground, which runs `sinter mcp` as its child. It opens no listener, has
  no HTTP client, implements no part of the tunnel, restarts nothing, and is
  not a central server or an agent. Starting it grants a connection to the
  read-only tools, nothing else.
- **WebMCP** is the documentation site's own read-only lookup tools in your
  browser ([WebMCP reference](/en/reference/webmcp/)); it has nothing to do
  with your hosts or this tunnel.
- **Applying changes through ChatGPT does not exist.** A "tunnel apply" is
  only a future design topic (threat model in ADR 0003); nothing in this guide
  can change a host.

Nothing in the path is operated by the Sinter project: there is no Sinter
gateway, relay, OAuth server or account database.

## Before you start

- Linux controller (`sinter serve` exits 3 on other systems).
- The official `tunnel-client` installed by you (Sinter does not bundle,
  patch or download it).
- An existing tunnel and a Restricted API key with the Tunnels Read and Use
  permissions, created by you in the OpenAI Platform. Sinter cannot create
  either.
- A [targets file](/en/reference/mcp/#named-targets---targets-file) naming the
  hosts ChatGPT may plan and audit, each with a `known_hosts` file.
- In ChatGPT, a custom MCP app whose connection is the tunnel, added by you.

## Who can use it

A stdio server receives no user, workspace or connection identity. Anyone who
can use the tunnel from ChatGPT gets the same read-only authority over the
same targets file; Sinter adds no authentication or authorization of ChatGPT
users. The boundary is OpenAI's (the organization's Tunnels Use permission and
the tunnel's workspace). Where people need different access, use separate
tunnels, separate targets files and separate OS users.

## Set up and run

1. Write the configuration and the key file (on a terminal; the key is read
   with echo off and stored in a 0600 file, the configuration holds no key;
   nothing existing is replaced):

   ```bash
   sinter serve init --client /usr/local/bin/tunnel-client --targets-file /etc/sinter/targets.toml
   ```

   It asks for the tunnel ID (an identifier, not a secret) and the key, then
   runs the checks and `tunnel-client doctor`. `--check-online` also asks the
   official client whether the key can read the tunnel.

2. Check the setup at any time without starting or writing anything:

   ```bash
   sinter serve check --online
   ```

3. Start the connection in the foreground, for as long as you want it:

   ```bash
   sinter serve --max-duration 1h
   ```

   Ctrl+C, `SIGTERM`, `SIGHUP` or the end of `--max-duration` stop it
   (`SIGKILL` follows after 10 seconds). Exit 0: stopped on request or at the
   time limit; 2: configuration invalid, nothing started; 3: the client could
   not start or ended by itself.

4. Replace the key when needed: `sinter serve rotate-key`.

Before anything starts, `sinter serve` checks the configuration, the key file
(regular file, private, owned by you; its content is never read), the client
executable and the targets file, and gives the client a cleared environment
with an allowlist only, so no key reaches the client or `sinter mcp` through
the environment.

## Under systemd

`contrib/systemd/sinter-tunnel.service` runs the official client directly
(without `sinter serve`), with the key handed over as a systemd credential.
It has no `[Install]` section, so it is never started at boot; start and stop
it explicitly (`systemctl start sinter-tunnel`, `systemctl stop
sinter-tunnel`). `sinter serve init --systemd` (as root) stores the key
root-owned for `LoadCredential=` and prints the filled unit; it installs
nothing. Replace every placeholder named in the unit's header before
installing it.

## Verified and not verified

From the v1.14.0 entry of `CHANGELOG.md`:

- Verified once, with a development build before the v1.14.0 release, on one
  temporary Ubuntu 24.04 x86_64 controller with `tunnel-client` v0.0.21:
  ChatGPT called `sinter_get_version`, `sinter_list_targets`,
  `sinter_validate_manifest`, `sinter_inspect_manifest`, `sinter_plan_host`
  and `sinter_audit_host` against one real target, and Ctrl+C stopped it with
  exit 0 and no remaining process.
- The setup commands were checked once with a real Restricted key
  (`init --check-online`, `check --online`, `rotate-key --check-online`).
- Not verified: the released build itself on a real host, other controller
  distributions, a ChatGPT call with a configuration written by `init`, the
  corrected HTTP-status reading of a failed client check against the live
  service, and the systemd unit with `tunnel-client` v0.0.21 (it was verified
  earlier with Sinter v1.5.2 and `tunnel-client` v0.0.16).

## Limits

- No guarantee that every process ends after an abnormal end; no lock per
  tunnel ID (run one instance per tunnel); no per-user authorization.
- The read-only tool list, the named-target model, the mandatory
  `known_hosts` and the refusal of secret references are those of
  `sinter mcp`, unchanged.
- This guide is not an enterprise security review; your organization's
  review is a separate decision.
