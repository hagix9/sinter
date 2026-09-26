---
title: ChatGPT Plugin
description: Use Sinter from ChatGPT through the public Sinter Gateway and your own sinter-bridge (read-only).
---

The Sinter ChatGPT plugin lets ChatGPT call Sinter's **read-only** MCP tools
(validate, inspect and plan recipes; plan or audit your named SSH targets)
on **your own** Sinter installation.

:::caution[Preview]
Sinter for ChatGPT is currently available by invitation, and the plugin is
not yet listed in the ChatGPT plugin directory. To request access, contact
us through the [Fulltrust contact form](https://fulltrust.co.jp/contact/index.html) and mention "Sinter" in your
inquiry. Do not include server details, credentials, or tokens in the
form. After approval, the Gateway operator sets up your sign-in account
and sends you a one-time registration token (see [Quick start](#quick-start)).
:::

## How it works

```text
ChatGPT
  → Sinter plugin (MCP over HTTPS, OAuth sign-in)
  → public Sinter Gateway  https://gateway.fulltrust.co.jp/mcp
  → your account's controller (matched by the account in your sign-in token)
  → your sinter-bridge      (runs on your machine, outbound HTTPS only)
  → your local `sinter mcp` (read-only tools; SSH to your named targets)
```

- The **Gateway** is a shared, public relay operated by Fulltrust. It
  authenticates ChatGPT requests (OAuth access tokens), and forwards MCP
  requests to the controller registered for your account. It is **not**
  your Sinter host: it never runs Sinter, never holds your SSH
  configuration, and never connects to your servers.
- **sinter-bridge** runs on your machine. It long-polls the Gateway over
  outbound HTTPS (no listener, no inbound firewall change), passes each
  request to a local `sinter mcp` child process, and returns the result.
- **`sinter mcp`** runs locally with your permissions. Host access is only
  through the named targets in your own targets file.

## Prerequisites

| Requirement | Detail |
|---|---|
| Sinter | v0.5.0 or later (`sinter mcp`); see [Installation](/en/getting-started/installation/) |
| sinter-bridge | Built from this repository's `gateway/` crate (not yet in release archives); needs a Rust toolchain |
| Bridge host | Linux x86_64 (release archive) or another Unix-like machine where you build Sinter from source (for example macOS); it must reach `https://gateway.fulltrust.co.jp` over outbound HTTPS (443) and stay online while you use the plugin |
| ChatGPT | A ChatGPT plan that can use apps/plugins; developer mode to add the app while the plugin is in preview |
| Sign-in account | A Sinter sign-in account whose account mapping has been set by the operator |
| Optional | A targets file (`--targets-file` format) if you want `sinter_plan_host` / `sinter_audit_host` |

## Quick start

1. **Install Sinter** (v0.5.0+). On Linux x86_64:

   ```sh
   curl -fsSL https://sinter.fulltrust.co.jp/install.sh | sh
   $HOME/.local/bin/sinter --version
   ```

   The installer supports Linux x86_64 only. On other systems (for
   example macOS), build Sinter from source in step 2 with
   `cargo build --release` in the repository root (binary:
   `target/release/sinter`).

2. **Build sinter-bridge**:

   ```sh
   git clone https://github.com/hagix9/sinter.git
   cd sinter/gateway
   cargo build --release --bin sinter-bridge
   # binary: gateway/target/release/sinter-bridge (the commands below run from sinter/gateway)
   ```

3. **Request access.** Use the [Fulltrust contact form](https://fulltrust.co.jp/contact/index.html) and mention
   "Sinter" in your inquiry (no server details, credentials, or tokens).
   The operator creates your sign-in account and sends you its sign-in
   details and, separately, a **one-time registration token**. The token is
   valid for 15 minutes and can be used once; if it expires, ask for a new
   one.

4. **Register the bridge** (run `register` once — it consumes the token).
   The token is read from stdin, never from the command line; standard
   output contains only the credential:

   ```sh
   mkdir -p ~/.config/sinter && umask 077
   SINTER_BRIDGE_GATEWAY_URL=https://gateway.fulltrust.co.jp \
     ./target/release/sinter-bridge register > ~/.config/sinter/bridge.cred
   # paste the registration token at the prompt
   chmod 600 ~/.config/sinter/bridge.cred
   ```

5. **Start the bridge**:

   ```sh
   export SINTER_BRIDGE_GATEWAY_URL=https://gateway.fulltrust.co.jp
   export SINTER_BRIDGE_CREDENTIAL_FILE=~/.config/sinter/bridge.cred
   # optional: export SINTER_BRIDGE_SINTER_BIN=/path/to/sinter   (default: sinter on PATH)
   # optional: export SINTER_BRIDGE_TARGETS_FILE=~/.config/sinter/targets.toml
   ./target/release/sinter-bridge --check   # validates config and child start, prints "ok"
   ./target/release/sinter-bridge           # logs "bridge polling https://gateway.fulltrust.co.jp/"
   ```

6. **Add the app in ChatGPT** (developer mode while in preview): create a
   new app with
   - MCP server URL: `https://gateway.fulltrust.co.jp/mcp`
   - Authentication: OAuth

7. **Sign in** when ChatGPT opens the sign-in page, and approve access.

8. **Test**: in a new chat, ask the Sinter app for its version (see
   [Example](#example)).

## Example

> Ask Sinter which version it is running.

ChatGPT calls `sinter_get_version`; your bridge answers from your local
Sinter, for example `{"name":"sinter","readOnly":true,"version":"0.5.0"}`.

Other read-only prompts:

- "Validate this Sinter recipe" (paste YAML/TOML) → `sinter_validate_manifest`
- "Plan this recipe for rocky9" → `sinter_plan` (supplied-facts snapshot, no host)
- "List my Sinter targets" → `sinter_list_targets`
- "Audit web01 against this recipe" → `sinter_audit_host` (named target from your targets file)

## Tools and permissions

All tools are read-only: there is no apply, install or command-execution
tool. Every tool is annotated `readOnlyHint: true`,
`destructiveHint: false`, `openWorldHint: false`.

| Tool | What it does |
|---|---|
| `sinter_get_version` | Sinter version and read-only statement |
| `sinter_classify_platform` | Classify `/etc/os-release` content |
| `sinter_validate_manifest` | Validate recipe text |
| `sinter_inspect_manifest` | Structural recipe summary (values never returned) |
| `sinter_plan` | Plan against a built-in supplied-facts snapshot (no SSH) |
| `sinter_list_targets` | Names of your configured targets (no connection details) |
| `sinter_plan_host` | Read-only plan against a named target |
| `sinter_audit_host` | Read-only audit of a named target |
| `sinter_get_profile` | Added by the Gateway: returns your account id (and name/email if present in your sign-in token) so ChatGPT can label the connection |

MCP recipes accept inline content only (`include:` / `source:` are
rejected), so a request cannot read files from your machine through a
recipe. See [Core MCP](/en/reference/mcp/).

## Keeping the bridge running

The bridge must be running whenever you use the plugin. If it stops, tool
calls fail with `controller_offline` about 130 seconds after its last poll.

- **Foreground**: run `sinter-bridge` in a terminal. It reconnects with
  backoff (1 s doubling, up to 60 s) if the Gateway is unreachable, and
  restarts the `sinter mcp` child up to 5 times in 5 minutes.
- **systemd (Linux)**: the repository ships a user unit and an environment
  template in `gateway/contrib/systemd/`. From the `sinter/gateway`
  directory:

  ```sh
  install -D -m 755 target/release/sinter-bridge ~/.local/bin/sinter-bridge
  install -D -m 644 contrib/systemd/sinter-bridge.service ~/.config/systemd/user/sinter-bridge.service
  install -D -m 600 contrib/systemd/bridge.env.example ~/.config/sinter/bridge.env
  # edit ~/.config/sinter/bridge.env: replace /home/USER with your home directory
  systemctl --user daemon-reload
  systemctl --user enable --now sinter-bridge
  loginctl enable-linger "$USER"             # keep running after logout / at boot
  journalctl --user -u sinter-bridge -f      # expect "bridge polling …"
  ```

  `bridge.env` must use absolute paths: systemd does not expand `~` there,
  and the user service `PATH` does not include `~/.local/bin`, so
  `SINTER_BRIDGE_SINTER_BIN` points at the `sinter` binary explicitly.
  `systemctl --user stop sinter-bridge` stops it cleanly; failures are
  restarted after 10 seconds.

- **launchd (macOS)**: no launchd definition is provided. Run the bridge in
  the foreground; note that sleep, logout or reboot stops it.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Tool call fails with `controller_offline` / "no controller for account" | Your bridge is not running or has not polled for ~130 s. Start it and check its log for `bridge polling …`. |
| Bridge logs `controller authentication failed — retrying every 300s` | The credential was revoked or is wrong. Ask the operator for a new registration token and register again. |
| `register rejected: HTTP 410` / `409` / `401` | 410: the registration token expired (15 min). 409: it was already used, or your account already has an active bridge (the operator must revoke the old one first). 401: the token is not valid. Request a new token from the operator. |
| Sign-in fails in ChatGPT (OAuth error / access denied) | Your sign-in account has no Sinter account mapping yet. Ask the operator. |
| "Authentication succeeded, action discovery failed" | ChatGPT signed in but could not list tools: usually the bridge is offline (see above) or the Gateway is unreachable. |
| Tools worked earlier, now ChatGPT asks to sign in again or cannot refresh tools | The access token expired and could not be renewed. Disconnect and reconnect the app in ChatGPT, then sign in again. |
| Tool call returns `account_unbound` (HTTP 403) | Your sign-in token has no Sinter account mapping. Ask the operator. |
| Gateway unreachable, DNS or TLS errors | Check `curl -sS https://gateway.fulltrust.co.jp/healthz` returns HTTP 200 from the bridge host. Corporate proxies must allow outbound HTTPS to this host. |
| `sinter_plan_host` / `sinter_audit_host`: target not found | The target name is not in `SINTER_BRIDGE_TARGETS_FILE`. List names with `sinter_list_targets`. |
| Permission denied on a host | SSH from your bridge host to the target failed with your own credentials; test the same target with the `sinter` CLI. |
| Credential file warning "group/world-accessible" | Run `chmod 600 ~/.config/sinter/bridge.cred`. |

## Security and privacy

- **Transport**: ChatGPT ↔ Gateway uses HTTPS (TLS certificate from Let's
  Encrypt). Bridge ↔ Gateway uses HTTPS only; redirects are disabled, so
  the bridge credential can only reach the configured Gateway origin.
- **Authentication**: every MCP request must carry an OAuth access token.
  The Gateway checks the signature (pinned JWKS, RS256/ES256), issuer,
  audience, expiry and the Sinter account claim; requests without a
  valid token get HTTP 401, and tokens without an account mapping get 403.
- **Account isolation**: requests are delivered only to the controller
  registered for the account in your token. One active controller per
  account.
- **What the Gateway stores**: account ids, controller ids, SHA-256
  hashes of registration tokens and controller credentials, and
  registration/revocation audit events. It does not store OAuth tokens,
  bridge credentials in clear, or MCP request/response content.
- **What passes through the Gateway**: the MCP requests from ChatGPT and
  the results from your Sinter (for example recipe text you paste, plan
  and audit results about your targets). These are relayed in memory and
  also reach ChatGPT. Do not paste secrets into recipes you send.
- **Logs**: the public Gateway's access log records method, path (without
  query), status, size and duration; headers and client IPs are removed.
  The Gateway service log records account, controller and request ids and
  status codes, not tokens or payloads.
- **Your credential**: the bridge credential stays on your machine; keep
  it `chmod 600`. The operator can revoke it at any time.
- **Read-only**: no tool changes your systems. Sinter's own safety rules
  (inline-only MCP recipes, named targets only) still apply.
