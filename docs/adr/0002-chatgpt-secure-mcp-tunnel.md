# ADR 0002: ChatGPT access through the OpenAI Secure MCP Tunnel

- Status: **Accepted** (r5, 2026-11-15). Revision r4 (2026-10-19) records the
  real-host verification of Option A and the Owner decisions that make Option A,
  with the unit template `contrib/systemd/sinter-tunnel.service`, the supported
  configuration. Revision r5 records the Owner's decision to implement Option B
  (`sinter serve`), against Sinter v1.13.0 and `tunnel-client` v0.0.21, and what
  the implementation does beyond §6 (§17). Neither is released yet, and Option B
  has not been run with the real client. Revision r6 adds the setup commands
  `sinter serve init`, `check` and `rotate-key` (§18). Text from r3 and r4 is kept where it
  still describes a decision; where a later revision changes a decision, a
  **Changed in r4** note (§16) or the §17 table says what, why and where.
- Date: 2026-10-18
- Scope: how an administrator lets ChatGPT use the existing read-only
  [`sinter mcp`](../../docs-site/src/content/docs/en/reference/mcp.md) through
  the OpenAI Secure MCP Tunnel, and whether a `sinter serve` command is needed
- Baseline: Sinter v1.5.2 (`sinter mcp`, stdio, protocol `2025-03-26`, eight
  read-only tools); OpenAI `tunnel-client` v0.0.16 (latest release on
  2026-10-18). Facts about `tunnel-client` internals come from its public
  source. The key precedence, the tunnel ID validation, the signal handling and
  the stdio child handling cited here were read at tag `v0.0.16`. Source-confirmed
  is not runtime-verified: §14 lists what still has to be observed.
- Platform: **Linux only.** Sinter ships Linux artifacts, and this design and
  its verification target Linux (with or without systemd). macOS is out of
  scope: there are no macOS-specific requirements, termination guarantees or
  process monitoring in this record. Revisit if macOS becomes a supported
  platform.
- Revision: r3 (2026-10-18), after a second review. r2 introduced: Linux-only
  scope; `sinter serve` reduced to a launcher (§6.7 lists what was removed and
  what that costs); the precise effect and limits of `PDEATHSIG`; a manual
  procedure for leftover processes (§7.1); a reduced and explicitly unverified
  systemd example; no claim that an interrupted observation leaves nothing on a
  target. r3 adds: the distinction between "ChatGPT can no longer send requests"
  and "every process has ended" (§7); what `Restart=no` and a missing
  `[Install]` section do and do not prevent (§5); and which signal reaches which
  process on Ctrl+C, on `kill`, and when an SSH session closes, with systemd as
  the session-independent way to run (§7). A final r3 alignment makes the tunnel
  ID form (§6.3) and the key precedence (§5) match the `v0.0.16` source.
- Revision r4 (2026-10-19), after the real-host verification of 2026-10-18/19
  (Ubuntu 24.04, systemd 255.4, Sinter v1.5.2, `tunnel-client` v0.0.16). r4
  records: the restart policy of the supported unit (`Restart=always`, not
  `Restart=no`), the decision not to start at boot, what the verification did and
  did not cover (§14.1), and why the two known limitations of the read-only MCP
  surface are not changed for the first release (§16). It does not change the
  read-only boundary, the named-target model, the secret refusal or the absence of
  per-user authorization.

This record states the decision, its reasons, and what is and is not known. It
does not describe shipped behaviour. r4: the user-facing guide
(`guides/chatgpt-tunnel`), the Core MCP reference and the unit template
`contrib/systemd/sinter-tunnel.service` now describe Option A; they are not yet
released.

## 1. Goal

An administrator wants ChatGPT to use Sinter's read-only tools on the
administrator's own controller, with these properties:

- The administrator explicitly starts the connection with a command, and once it
  is stopped ChatGPT can no longer reach Sinter.
- Each user signs in to ChatGPT with their own account. The Sinter provider
  operates no login, account database, OAuth server or relay.
- No public listener, no Sinter-operated service, no new ChatGPT plugin code.

## 2. Status of each element

| Class | Element |
|---|---|
| **Demonstrated** (earlier Sinter release) | Browser ChatGPT → Secure MCP Tunnel → official `tunnel-client` (stdio mode) → unmodified `sinter mcp` → `get_version`, `list_targets` (empty), `validate`, `inspect`, supplied-facts `plan`. Demonstrated on 2026-10-05 with Sinter v1.1.3 and `tunnel-client` v0.0.15, no Sinter change, connector set to "No authentication". Reconnect with the same tunnel and app worked. |
| **Adopted policy** (this record) | Official Secure MCP Tunnel; the official `tunnel-client` as an external process; no own implementation of the tunnel protocol; no third-party tunnel code reused; the existing `sinter mcp` over stdio; no new HTTP MCP server; the administrator registers the ChatGPT custom MCP app; the provider manages no OpenAI account or authentication; only the eight existing read-only tools are exposed. |
| **To implement** (only if accepted) | Option A: documentation (a `tunnel-client` invocation, a systemd unit and a foreground procedure), published as supported examples only after the real-host verification of §14. Option B: a `sinter serve` command (§6). |
| **Unverified OpenAI-side behaviour** | The ChatGPT plans that may use Tunnel-backed custom MCP apps; use from ChatGPT mobile and desktop apps; billing of tunnels; the expiry policy of runtime keys; whether other workspace members can attach their own app to the same tunnel; whether any per-user identity reaches a stdio backend (none is documented). |
| **Unverified on Sinter's side** | Sinter v1.5.2 with `tunnel-client` v0.0.16 end to end; `sinter_plan_host` / `sinter_audit_host` on a real named target through the tunnel; ChatGPT app refresh and new app creation with v1.5.2. |
| **Future candidates** | apply over MCP, approvals, per-call audit log, per-user authorization, multi-user or multi-organization service. All are out of scope (§12). |

**r4 note.** The "To implement" and "Unverified on Sinter's side" rows describe
the state at r3. After the verification of 2026-10-18/19, Option A is
documented and its unit template is provided; what was and was not verified is
in §14.1.

## 3. Decision

1. ChatGPT reaches Sinter only through the OpenAI Secure MCP Tunnel, using the
   official `tunnel-client`, which starts `sinter mcp` as its stdio child.
2. The ChatGPT app is created by the administrator: Connection **Tunnel**,
   Authentication **No authentication**. There is no Sinter-side credential for
   ChatGPT to hold, because a stdio child has no HTTP hop to authenticate.
3. Who can attach to the tunnel is decided by OpenAI's controls (the
   organization's Tunnels Read + Use permission and the tunnel's association
   with the ChatGPT workspace). Sinter adds no authentication of its own and
   cannot distinguish callers (§8.4).
4. **First step: Option A** (§5), which needs no Sinter code. It is verified on a
   real host with v1.5.2 before anything else is built.
5. **Option B, `sinter serve`** (§6), is the target design for a single Sinter
   command that starts and stops the connection. It is implemented only after
   Option A has been verified and the Owner confirms the need (§10).

**r4 note.** Item 4 says Option A needs no Sinter code. That still holds for
the tunnel itself: the documentation and the unit template change no Rust code.
Two limitations of the existing read-only MCP surface (F-L1, F-L2) are
independent of the tunnel and are not changed for the first release (§16).

## 4. Architecture and network

```text
ChatGPT (web)  user signed in with their own ChatGPT account
   │  custom MCP app: Connection = Tunnel, Authentication = No authentication
   ▼
OpenAI control plane (api.openai.com)
   ▲  outbound HTTPS long-poll from the controller, TCP 443; no inbound port
   │
official tunnel-client          (unprivileged OS user on the controller)
   │  stdin/stdout: newline-delimited JSON-RPC (MCP stdio)
   ▼
sinter mcp --targets-file …     (same user; child of tunnel-client)
   │  SSH (separate traffic, controller → named targets only)
   ▼
named targets from the administrator's targets file
```

Traffic classes, kept separate in configuration and in firewall rules:

| Traffic | Direction | Notes |
|---|---|---|
| Tunnel control plane | controller → `api.openai.com:443` (and `mtls.api.openai.com:443` only if control-plane mTLS is configured) | The only external traffic of the tunnel. `tunnel-client` honours a control-plane proxy (`--control-plane.http-proxy`), a global proxy, `HTTP(S)_PROXY`/`NO_PROXY`, and an additive CA bundle (`--ca-bundle`). |
| MCP | local pipe between `tunnel-client` and `sinter mcp` | No socket, no listener. |
| `tunnel-client` health/UI | loopback listener, default `127.0.0.1:8080` | Serves `/healthz`, `/readyz`, `/metrics` and an embedded web UI with logs and a live log-level switch, answering loopback clients only by default. See §8.6. |
| Target SSH | controller → targets, as configured in the targets file | Unrelated to the tunnel. Host keys are verified against the profile's `known_hosts`. |

Conditions for corporate networks (to be stated in the user documentation):

- Outbound HTTPS to the OpenAI control plane must be permitted for the
  controller, either directly or through a proxy.
- TLS inspection works only if the inspecting CA is supplied with `--ca-bundle`
  (or `CA_BUNDLE`). If the organization forbids adding a CA, the tunnel cannot
  be used through that proxy.
- A browser that reaches ChatGPT does not prove that the controller's process
  reaches the control plane: proxy, DNS and IPv6 routes can differ. `tunnel-client
  doctor` is the check.

Data that leaves the controller: every tool result is returned to the ChatGPT
conversation and is then subject to OpenAI's and the workspace's data handling.
This includes recipe text supplied by ChatGPT, validation diagnostics, target
profile **names**, and for host tools the observed facts (hostname, OS name,
family, version, architecture), resource identities and types, change labels,
metadata summaries (for example mode, owner, group: current and desired) and
audit observations per dimension. File and template content diffs are always
redacted by `sinter mcp`, and profile host, user, `known_hosts` and identity
paths are removed from diagnostics. Secrets cannot be referenced by MCP
manifests. The administrator decides which targets are named in the targets
file with this in mind.

## 5. Option A: the official `tunnel-client` started directly

Sinter is unchanged. The administrator writes three things.

**A `tunnel-client` invocation.** The relevant official options:

```text
env -u OPENAI_API_KEY -u OPENAI_ADMIN_KEY -u CONTROL_PLANE_API_KEY \
  tunnel-client run \
  --control-plane.tunnel-id tunnel_<id> \
  --control-plane.api-key file:/etc/sinter/tunnel/runtime-key \
  --mcp.command "/usr/local/bin/sinter mcp --targets-file /etc/sinter/targets.toml" \
  --health.listen-addr 127.0.0.1:0
```

- The runtime key is a **Restricted** OpenAI Platform organization key with
  Tunnels **Read + Use** only. It lives in a file readable only by the OS user
  that runs the client (or by root, when systemd delivers it as a credential)
  and is passed by `file:` reference, so it is in neither argv nor the
  environment. It is never written into a configuration file or a unit file.
  Sinter adds no encryption or secret store of its own.
- Key precedence in v0.0.16 (**source-confirmed**, `getControlPlaneAPIKey` in
  `pkg/runtimeconfig/config.go`; **not yet runtime-verified**, U-S3):
  1. `--control-plane.api-key` (`file:` or `env:` reference; any other value is
     rejected), and nothing else is consulted when it is set;
  2. `CONTROL_PLANE_API_KEY`;
  3. `OPENAI_API_KEY`, only when neither of the above is set.

  With the flag, an `OPENAI_API_KEY` in the environment is therefore not used.
  The foreground procedure still removes these variables, as above, so that a
  mistake in the flag cannot fall through to another key, and because the stdio
  child inherits the client's environment (next point). A systemd service does
  not inherit a login shell's environment, so the unit needs no such step.
- `tunnel-client` starts `sinter mcp` with its own complete environment (in its
  source, `exec.Command` without an explicit `Env`). Any secret in the client's
  environment therefore also reaches `sinter mcp`. This is another reason for
  passing the key by file rather than by `CONTROL_PLANE_API_KEY`.
- `--mcp.command` is parsed as a shell-like string; a path with spaces must be
  quoted (observed with an earlier client).
- `tunnel-client doctor` with the same options checks the key, the tunnel and the
  local MCP command before the first `run`, and whenever a connection fails.
- `--health.listen-addr 127.0.0.1:0` picks a free loopback port instead of the
  default `8080` (§8.6).

**A systemd unit.** This is the recommended way to run the connection, because
it does not depend on a login session or terminal (§7.2). It differs from the
official example on purpose: the official example uses `Restart=always` and an
inline key, which contradicts "explicitly started". The unit below is an
**illustration for verification**, not a supported example; it is published as
one only after §14 has passed.

```ini
[Unit]
Description=Sinter read-only MCP over OpenAI Secure MCP Tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=sinter-tunnel
LoadCredential=runtime-key:/etc/sinter/tunnel/runtime-key
ExecStart=/opt/tunnel-client/tunnel-client run \
  --control-plane.tunnel-id tunnel_<id> \
  --control-plane.api-key file:%d/runtime-key \
  --mcp.command "/usr/local/bin/sinter mcp --targets-file /etc/sinter/targets.toml" \
  --health.listen-addr 127.0.0.1:0 \
  --health.url-file %t/sinter-tunnel/health-url
RuntimeDirectory=sinter-tunnel
Restart=no
KillMode=control-group
TimeoutStopSec=15
# Optional connection time limit:
# RuntimeMaxSec=8h
NoNewPrivileges=yes
PrivateTmp=yes
# No [Install] section: the unit cannot be enabled for start at boot.
```

**Changed in r4 (§5, restart policy).** The unit above is the r3 text and is
kept as the history of a decision. r3 chose `Restart=no` and rejected the
official example's `Restart=always` because it contradicts "explicitly
started". The verification showed that with `Restart=on-failure` a death of
only the `sinter mcp` child is not recovered: `tunnel-client` then ends with exit
status 0, which systemd treats as a clean end, and the connection stays down
until an administrator starts it again (an unmet operational requirement).
After a one-line change to `Restart=always`, the same fault was followed by an
automatic restart 10.05 seconds later, and `systemctl stop` was still honoured.
The Owner decided (2026-10-19) that the **standard unit template** is
`Restart=always`, `RestartSec=10`, `StartLimitIntervalSec=300`,
`StartLimitBurst=5`, with no `[Install]` section (no start at boot), and that `Restart=no`
with an optional `RuntimeMaxSec=` is documented as a difference (the
"explicit-start variant"), marked unverified. The supported template is
`contrib/systemd/sinter-tunnel.service`; §16 lists every change. In the table
below, the `Restart=no`, `RuntimeMaxSec=` and "Neither setting" statements
describe r3's intent and now apply to the explicit-start variant only.

Start: `systemctl start sinter-tunnel`. Stop: `systemctl stop sinter-tunnel`.
Each setting and what is not yet verified:

| Setting | Purpose | Not verified |
|---|---|---|
| `LoadCredential=` with `file:%d/runtime-key` | The key file can stay root-owned; systemd hands a copy to the service. `%d` is systemd's specifier for the credentials directory, so the key never appears in the unit | The minimum systemd version on the supported distributions, and that `tunnel-client` reads the credential file |
| `RuntimeDirectory=` with `%t/sinter-tunnel/health-url` | A private, automatically removed directory for the health URL file (`%t` is `/run` for system units) | Nothing beyond normal systemd behaviour |
| No `[Install]` section | The unit itself configures no automatic start: `systemctl enable` has nothing to install, so it is not started at boot through this unit | — |
| `Restart=no` | After the process ends, for whatever reason, systemd does not start it again | — |
| `KillMode=control-group` (the default, stated explicitly) | On stop, every process of the unit is killed, including `sinter mcp` | That no process survives (§14) |
| `TimeoutStopSec=15` | systemd sends `SIGKILL` after 15 seconds | — |
| `RuntimeMaxSec=` (optional) | Ends the connection after a fixed time. systemd treats this as a timeout, so the unit ends up in the failed state; with `Restart=no` it stays off | The resulting unit state on the supported systemd versions |
| `NoNewPrivileges=yes`, `PrivateTmp=yes` | Low-cost hardening; `sinter mcp` stages manifests in its own temporary directory, which `PrivateTmp` keeps private | That `tunnel-client` runs unaffected |

Neither setting forbids every other start. Another unit's `Wants=` or
`Requires=`, a timer, socket or path unit, or a `systemctl start` by any
administrator still starts it. Operation relies on the rule that only the
responsible administrator starts and stops the unit explicitly, and that nothing
else refers to it. No further mechanism against automatic start is added.

Stricter sandboxing (`ProtectSystem=`, `ProtectHome=` and similar) is not part of
the example. It can break the client's or Sinter's file access (state files, the
targets file, `known_hosts`, identity files), and the benefit is not established.
It may be evaluated after the basic unit has been verified.

**A foreground procedure** for short interactive use: run the invocation above
in a terminal, stop with Ctrl+C. A time limit, if wanted, uses `timeout` from GNU
coreutils (for example `timeout --signal=TERM 1h tunnel-client run …`). What
happens when the terminal's SSH session closes depends on the session (§7.2); the
foreground procedure is not relied on to stop the connection in that case.

What Option A already gives:

- Explicit start and stop: `systemctl start|stop`, or Ctrl+C in the foreground.
  When `tunnel-client` has ended, nothing polls the tunnel, so ChatGPT can send
  no new request.
- Under systemd, stop by control group: every process of the unit is signalled,
  then killed after the timeout. That this leaves no process is to be verified (§14).
- A time limit: `RuntimeMaxSec=` under systemd, `timeout` in the foreground.

What Option A does not give: a Sinter command; a check of Sinter's own inputs
before connecting; and, in the foreground, protection against an operator who
forgets to remove `OPENAI_API_KEY` from the environment.

## 6. Option B: `sinter serve`

`sinter serve` is a thin foreground launcher for one official `tunnel-client`
process, for interactive use. It is not a web server, not a supervisor, not a
daemon framework and not an approval of any future apply operation; starting it
grants a connection, nothing else. Everything the official client or systemd
already does (checking the key and tunnel, connecting to and polling the control
plane, health endpoints, stopping a unit's processes, time limits for units) is
left to them.

```text
sinter serve                       # connect until Ctrl+C
sinter serve --max-duration 1h     # connect for at most one hour
```

### 6.1 Command line

```text
sinter serve [--config <path>] [--max-duration <duration>]
```

- `--config`: a TOML file (§6.2). Default `$XDG_CONFIG_HOME/sinter/serve.toml`
  (when `XDG_CONFIG_HOME` is absolute), else `~/.config/sinter/serve.toml`, the
  same rule as the existing default identity path of `sinter secrets`.
- `--max-duration`: optional. No limit by default.
- Exit codes, reusing the existing classes: `0` stopped on request or at the
  time limit; `2` configuration invalid; `3` `tunnel-client` could not be started
  or exited without being asked to.
- Under systemd, the Option A unit is used instead of `sinter serve`: there,
  `serve` would add nothing that the unit does not already do (§7, row 9).

### 6.2 Configuration file

```toml
[tunnel]
id = "tunnel_<id>"                    # an identifier, not a secret
api_key_file = "/etc/sinter/tunnel/runtime-key"
client = "/opt/tunnel-client/tunnel-client"

[mcp]
targets_file = "/etc/sinter/targets.toml" # optional; same as sinter mcp --targets-file
```

- Unknown keys are rejected, as for the targets file.
- There is no field that can hold a key value; only the path of the key file.
- `client` is an absolute path; `serve` does not search `PATH` and never
  downloads `tunnel-client`.
- A proxy or CA bundle is configured through the client's own environment
  variables, which `serve` passes through (§6.4); `serve` has no settings of its
  own for them.

### 6.3 Checks before starting (fail closed; no network traffic)

1. Parse the configuration; every path must be absolute. The tunnel ID is
   checked only loosely: it must start with `tunnel_` and contain only lowercase
   ASCII letters, digits and `_`. The exact form is left to `tunnel-client`,
   which rejects an invalid ID at start. v0.0.16 accepts
   `^tunnel_[a-z0-9]{32}$` (source-confirmed). Newer client documentation also
   allows `tunnel_<4-character namespace>_<32 characters>`. A stricter check in
   Sinter would reject valid IDs, for example any ID with letters beyond `f`.
2. Key file: a regular file, non-empty, of bounded size, with no group or other
   permission bits. Its content is never printed or logged.
3. Load the targets file with the same loader as `sinter mcp`, so a broken file
   fails here instead of inside `tunnel-client`.
4. `client` is an executable regular file.
5. Paths placed into `--mcp.command` (the Sinter executable and the targets file)
   must not contain whitespace, quotes or backslashes; otherwise refuse, rather
   than depend on `tunnel-client`'s shell-like parsing.

Whether the key and tunnel are valid is checked by `tunnel-client` itself: it
fails at start, and the administrator runs `tunnel-client doctor` to diagnose (§5).

### 6.4 Starting `tunnel-client`

- Arguments: `run`, the tunnel ID, `--control-plane.api-key file:<key file>`,
  `--mcp.command "<absolute path of this sinter> mcp [--targets-file <path>]"`,
  and `--health.listen-addr 127.0.0.1:0`.
- Environment: cleared, then an allowlist only: `PATH`, `HOME`, `USER`,
  `LOGNAME`, `LANG`, `LC_*`, `TMPDIR`, `SSH_AUTH_SOCK` (target SSH keys may be
  agent-only), and the client's documented network variables `HTTPS_PROXY`,
  `HTTP_PROXY`, `NO_PROXY` (and their lowercase forms), `CONTROL_PLANE_HTTP_PROXY`
  and `CA_BUNDLE`. `OPENAI_API_KEY`, `OPENAI_ADMIN_KEY`, `CONTROL_PLANE_API_KEY`
  and every other variable are absent. This is the one safety function of
  `serve` that the official client does not provide: the client would fall back
  to `OPENAI_API_KEY`, and it gives its stdio child its own complete environment.
  With the key passed by file and the environment cleared, neither process
  carries the key in its environment.
- Process group: `tunnel-client` stays in the process group of `serve`, so
  Ctrl+C in the terminal reaches all three processes (§7.2), and `serve` needs no
  group handling of its own. A signal sent to the PID of `serve` reaches only
  `serve`; that case is handled by §6.6.
- `PR_SET_PDEATHSIG(SIGTERM)` is set for the `tunnel-client` child (§6.6).
- `stdin` is null. `tunnel-client`'s stdout and stderr, which also carry
  `sinter mcp` diagnostics, are passed through unchanged.

### 6.5 Output

`serve` prints one line when it starts the client and one line when it ends,
with the reason (requested stop, time limit, client exited) and the exit code.
Connection progress is what `tunnel-client` itself logs (for example, tunnel
metadata fetched and polling started). `serve` does not poll the health endpoint
and has no HTTP client. Neither `serve` nor the client's log shows ChatGPT's use
of the connection. No key or tool payload is printed by `serve`.

### 6.6 Stopping

1. On `SIGINT`, `SIGTERM` or `SIGHUP` to `serve`, or when `--max-duration`
   expires, `serve` sends `SIGTERM` to `tunnel-client`. The client may already
   have received the terminal's signal directly; a second `SIGTERM` is harmless.
   From its source, `tunnel-client` handles `SIGINT`/`SIGTERM`, closes the
   stdio child's stdin, sends it `SIGTERM` and waits for it.
2. If `tunnel-client` has not exited after 10 seconds, `serve` sends it
   `SIGKILL`. Once `tunnel-client` is gone, nothing polls the tunnel, so ChatGPT
   can send no new request (outcome 1 of §7). `sinter mcp` may still be running:
   it reads end-of-file on stdin only after its current request, if any, has
   ended, and then exits (outcome 2 is expected, not guaranteed).
3. `serve` exits with the code of §6.1. A client that exits after `serve` has
   received a stop request counts as a requested stop.

`PR_SET_PDEATHSIG(SIGTERM)` covers the case where `serve` itself dies without
running this routine, including `SIGKILL`:

- **Effect.** When the thread of `serve` that started `tunnel-client` ends, the
  Linux kernel sends `SIGTERM` to `tunnel-client`, which then performs the
  normal stop of step 1 on its own. `SIGTERM` rather than `SIGKILL` is chosen so
  that the client also stops `sinter mcp`.
- **Limits.** It is tied to the thread that spawned the child, so the client must
  be started from the thread that lives for the whole run. If `serve` dies after
  the fork but before the setting takes effect, the signal is not sent. The usual
  remedy is to check the parent process ID right after setting it and exit if it
  has changed. The setting is cleared if the child executes a set-user-ID or
  set-group-ID program, or one with file capabilities; `tunnel-client` is
  installed as neither. Unlike step 2, it has no `SIGKILL` escalation: a
  `tunnel-client` that does not stop on `SIGTERM` stays. It acts only on
  `tunnel-client`; `sinter mcp` depends on the client's stop or on end-of-file
  on stdin.
- That `tunnel-client` and `sinter mcp` both end after `serve` is killed is **to
  be verified** (§14). `serve` is a launcher and does **not** guarantee that every
  child process ends after an abnormal end. A remaining process is not assumed
  to be harmless either: a remaining `tunnel-client` may keep the connection
  open. §7.1 gives the manual check.

### 6.7 What was removed, and what that costs

| Removed | What is lost | Risk, and what covers it |
|---|---|---|
| `--check` and an automatic `tunnel-client doctor` | An explicit check of key and tunnel before the client starts | Low: the client fails at start with its own message, and the administrator runs `doctor` directly |
| Single-instance lock per tunnel ID | Refusal of a second `serve` for the same tunnel on the same host | No security impact. A duplicate makes calls fail unpredictably (§8.5). §7.1 shows how to see a duplicate. Under systemd, the unit name prevents one |
| Own process group and group kill | Killing a stuck `sinter mcp` together with the client in step 2 | Once the client is gone, ChatGPT can send no new request. A `sinter mcp` that is still running may continue its current host observation until it ends, and is found with §7.1 |
| Readiness polling of `/readyz` and a "ready" line | An explicit "locally ready" message from Sinter | Low: the client logs its own progress. Readiness never meant that ChatGPT had connected |
| `client_sha256` pin and recording `--version` | Detection of a replaced client executable by Sinter | Same as any installed executable: install it root-owned and not writable by the service user |
| A systemd-credential key option | Running `serve` under systemd with `LoadCredential` | None: under systemd the Option A unit is used |
| Proxy and CA fields in the configuration | Configuration in one file | None: the client's own variables are passed through |
| A time limit in the configuration file | A per-host default limit | The limit is set on the command line, or with `RuntimeMaxSec=` under systemd |

## 7. Lifecycle

`tunnel-client` facts below come from its source (`cmd/client/main.go`,
`pkg/mcpclient/stdio_command.go`). `sinter mcp` facts come from v1.5.2: it reads
stdin until EOF and then exits, and installs no signal handler, so `SIGTERM`
ends it immediately.

Two outcomes are kept apart throughout:

1. **The connection has ended**: `tunnel-client` has exited, so nothing polls
   the tunnel and ChatGPT can send no new request to Sinter. This is what "stop"
   must achieve.
2. **Every process has ended**: `tunnel-client` and `sinter mcp` are both gone.
   Under systemd, `KillMode=control-group` stops every process of the unit. In
   the foreground and with `sinter serve`, this is expected but not guaranteed
   after an abnormal end. A process that remains is not assumed to be harmless:
   a remaining `tunnel-client` means outcome 1 has not been reached, and a
   remaining `sinter mcp` may still be observing a target.

| # | Event | Option A (official client directly) | Option B (`sinter serve`) |
|---|---|---|---|
| 1 | Normal start / stop | `run` or `systemctl start`; Ctrl+C or `systemctl stop` | `sinter serve`; Ctrl+C. The checks of §6.3 run before the client starts |
| 2a | Ctrl+C in the terminal | The terminal sends `SIGINT` to its foreground process group, normally both processes. The client stops gracefully, forwards the signal and closes the child's stdin | `SIGINT` normally reaches all three processes (same process group); `serve` runs §6.6 |
| 2b | `SIGTERM` to one PID (`kill <pid>`) | Only that process receives it. Sent to `tunnel-client`, the client stops itself and its child. Sent to `sinter mcp` only, that process ends and the client then shuts itself down (row 6) | Sent to `serve`: `serve` passes `SIGTERM` to `tunnel-client` (§6.6). Sent to another PID: as in Option A |
| 3 | SSH session closed | Depends on the session (§7.2). Whether every process ends is **not guaranteed** before verification. If the client receives `SIGHUP`: it does not handle it, so the Go runtime's default ends it (inference from Go's documented default) | Same; if `serve` receives `SIGHUP`, it runs §6.6. Not guaranteed either. For a connection that must not depend on a session, use the systemd unit |
| 4 | Tunnel cannot be established (key, permission, network, proxy) | `doctor` reports the cause; `run` fails or keeps retrying, depending on the client's retry policy (not verified) | If the client exits, `serve` exits `3` and the client's own log shows the cause. If the client keeps retrying, `serve` keeps running until stopped |
| 5 | `tunnel-client` crashes | Outcome 1 is reached. `sinter mcp` gets end-of-file on stdin and is expected to exit after its current request. Under systemd: `Restart=no`, so the connection stays off | Same, then `serve` exits `3`. No automatic restart |
| 6 | `sinter mcp` exits unexpectedly | The client shuts itself down when its stdio child exits or closes stdout | Same, then `serve` exits `3` |
| 6b | `serve` itself dies without stopping the client (for example `SIGKILL`) | Not applicable | The death signal sends `SIGTERM` to `tunnel-client`, which is expected to stop itself and `sinter mcp`. The limits of §6.6 apply, neither outcome is guaranteed, and the result is to be verified. A remaining process is found with §7.1 |
| 7 | Reconnect | The tunnel ID and ChatGPT app are reused. A new process gets a new child, and ChatGPT initializes again (observed before) | Same; `serve` has no reconnect loop |
| 8 | Time limit reached | systemd: `RuntimeMaxSec=` ends the unit. Foreground: `timeout` sends `SIGTERM` | `serve` runs §6.6 and exits `0` |
| 9 | systemd start / stop | Unit of §5; the control group is stopped as a whole | Not used: under systemd the Option A unit is used, so that `serve` and systemd do not do the same job twice |
| 10 | A tool call is running when stop is requested | `sinter mcp` is sequential and synchronous, and has no signal handler: `SIGTERM` ends it at once. The call in progress is interrupted and fails or times out in ChatGPT (the tunnel's own deadline is 120 seconds). The process's SSH connection (made in-process with libssh2, so no local `ssh` process exists) is cut. What happens on the target is **not verified**: whether the commands of that observation are ended by the SSH server, and whether temporary state can remain (Sinter's source contains remote helpers that create a private temporary directory with `mktemp -d`). The tools never apply a change, but an interrupted call is not claimed to leave nothing behind | Same; the 10-second wait does not let the call finish. No rollback, cleanup or job mechanism is added |

**Changed in r4 (§7, rows 5 and 6 under systemd).** Those rows say that with
`Restart=no` the connection stays off after a crash. With the r4 template
(`Restart=always`) systemd restarts the unit after either process ends, unless
the unit was stopped with `systemctl stop`: an observed `SIGKILL` of the
`sinter mcp` child (under `Restart=always`), and of `tunnel-client` (under
`Restart=on-failure`), were each followed by a new pair of processes about 10
seconds later. Row 8 (a time limit with `RuntimeMaxSec=`)
no longer gives a guaranteed limit with the standard unit; see §16. The
statements for the foreground and for `sinter serve` are unchanged.

**Changed in r5 (§7, row 6 and the stop rows).** With `tunnel-client` v0.0.19
or later, row 6 changes for both options: by default the client restarts a
`sinter mcp` child that exits, instead of ending itself, so `serve` keeps
running and does not exit `3` (§17). For rows 2a and 8, `serve` reports a stop
that it was asked for as a requested stop (exit `0`) even when the client has
already ended on the same Ctrl+C, which the terminal also delivers to it.

The design adds no watchdog, no process search, no automatic kill, no restart
policy, no daemon manager, no lock and no automatic cleanup. The only mechanisms
`serve` adds are the cleared environment, the Linux death signal and the
10-second escalation.

### 7.1 Checking for leftover processes

Sinter does not search for or kill old processes when it starts. After a crash,
a killed `serve`, or any doubt, the administrator checks by hand:

```sh
# systemd (Option A unit)
systemctl status sinter-tunnel        # lists every process still in the unit
systemctl stop sinter-tunnel

# foreground or sinter serve
pgrep -u sinter-tunnel -a tunnel-client
pgrep -u sinter-tunnel -af 'sinter mcp'
kill <pid>          # SIGTERM first; kill -KILL <pid> only if it does not exit
```

This matters for two reasons. A `tunnel-client` that is still running keeps the
tunnel served, so ChatGPT can still reach Sinter. A new instance started next to
it is an unsupported duplicate (§8.5). The user documentation therefore tells the
administrator to check after an abnormal end. The user name above is the
dedicated user of §8.1.

Revoking or rotating the runtime key in the OpenAI Platform is the remote way to
end a connection whose process cannot be reached. That a running client then
stops serving is expected but **not verified**.

### 7.2 Which signal reaches which process

- **Ctrl+C** makes the terminal send `SIGINT` to its foreground process group.
  A command started normally from an interactive shell runs in that group, with
  its children unless they move to another group. `tunnel-client` does not move
  its stdio child.
- **`kill <pid>`** (`SIGTERM` by default) reaches only that process. Nothing
  passes it on automatically, except what the receiving program does itself
  (`tunnel-client` forwards `SIGINT`/`SIGTERM` to its stdio child; `serve` passes
  them to `tunnel-client`).
- **An SSH session that closes** first affects the session's controlling process,
  usually the login shell. Whether and to which processes `SIGHUP` is then
  delivered depends on the shell and its settings (job control, `huponexit`),
  and on whether the command was started with `nohup`, `setsid` or `disown`, or
  inside tmux or screen. A network failure can also delay the moment the session
  is seen as closed. Sinter therefore does **not** claim that closing an SSH
  session ends the connection, or that it ends every process. This is checked
  on the real host for the shell actually used (§14).
- **systemd** does not depend on any of this. `systemctl stop` signals every
  process in the unit's control group, so the systemd unit is the recommended
  way to run a connection that must not depend on a login session.

## 8. Permissions and exposure

### 8.1 Operating system

- `tunnel-client` and `sinter mcp` run as one dedicated, unprivileged OS user
  (for example `sinter-tunnel`). Root is neither needed nor recommended.
- That user can read the targets file and the SSH material the targets file
  references, and nothing else that matters. The runtime key file is owned by
  that user with mode `0600`, or is delivered by systemd credentials.
- The read-only boundary of `sinter mcp` is unchanged: there is no apply, exec or
  shell tool. Manifests cannot use `include:`, `source:` or secret references.

### 8.2 Host tools

`sinter_plan_host` and `sinter_audit_host` make real SSH observations. While the
connection is up, the caller can make any registered target run Sinter's fixed
read-only observation commands for any recipe that validates. The tunnel allows
600 requests per minute by default. Therefore:

- Start with a targets file that names only the hosts meant for ChatGPT, or none
  at all. Without `--targets-file`, the host tools fail closed.
- Prefer profiles with `sudo = false` and a dedicated read-only remote account.
  With `sudo = true`, observation runs as root on the target, and results such
  as metadata of root-only files reach the conversation. Using `sudo = true`
  through the tunnel is an explicit administrator decision.
- The explicit, time-limited connection window is itself a control: the targets
  are reachable only while the connection is up.

**Changed in r4 (§8.2, connection window).** With the standard unit, the window
is no longer bounded by the life of the process: after an explicit start, the
service returns by itself after a crash or a `kill`, and only `systemctl stop`
(or anything else that stops the unit) ends the connection. The control moves
from "the process ends" to "the administrator stops the unit". The unit still
has no `[Install]` section, so it never starts at boot. A fast restart loop is
stopped by the start limit (five starts in 300 seconds), but a process that dies
only after running for about a minute would be restarted indefinitely and
silently (an analysis, not measured). **What does not change:** the eight
read-only tools, the named targets, the mandatory `known_hosts`, the refusal of
secret references, and the absence of per-user authorization. Anyone who can use
the tunnel gets the same read-only authority whether or not the unit restarts
itself. Administrators who want the stricter window use the explicit-start
variant (`Restart=no`, optional `RuntimeMaxSec=`), which is unverified.

### 8.3 Tunnel ID and runtime key

| Item | Nature | Where it lives | Who creates it |
|---|---|---|---|
| Tunnel ID | Identifier, not a secret | Configuration file, unit file | A Platform user with Tunnels Read + Manage, using an admin key that **never** goes on the controller |
| Runtime key | Secret; a Restricted organization key with Tunnels Read + Use | `0600` file or systemd credential, passed by `file:` reference | The administrator, in the Platform UI |

Rotation: a revoked or expired key surfaces as a control-plane authentication
failure: `doctor` fails, and `serve` exits `3` if the client exits on it (§7,
row 4). Sinter cannot tell from the key itself whether it is Restricted, so
using a Restricted key remains an operator responsibility.

### 8.4 No per-user authorization

A stdio child receives only JSON-RPC bytes: no user, workspace, tunnel or
connection identity. Anyone who can use the tunnel from ChatGPT gets the same
read-only authority over the same targets file. The coarse boundary is OpenAI's:
the Platform organization's Tunnels Use permission and the tunnel's workspace
association. One administrator, one tunnel and one targets file is the supported
model. Where people need different access, they need separate tunnels, separate
targets files and separate OS users. Real per-user authorization needs an
HTTP MCP surface with OAuth, which is out of scope.

### 8.5 One instance per tunnel ID

The official documentation states that more than one active `tunnel-client`
with a stdio binding on the same tunnel ID is not supported, because requests
are not pinned to the instance that handled `initialize`. A duplicate is not a
security problem, but calls then fail or time out unpredictably. Sinter adds no
lock for this. Under systemd, the unit name prevents a second instance on one
host. In the foreground, the administrator does not start a second one, and
checks with §7.1 after an abnormal end. A duplicate on another host or in another
user account cannot be detected by Sinter in any case.

### 8.6 Local listener

`tunnel-client` serves health, metrics and an embedded UI with logs and a
log-level switch on a loopback port, without authentication, answering loopback
clients only by default. On a controller shared with other local users, those
users can reach it. Mitigations: a dedicated controller; the port set to `0`
(ephemeral) with the URL file in a private run directory; never
`--allow-remote-ui`; and the documented `--health.unix-socket` in a `0700`
directory, if v0.0.16 supports it for `run` (to be verified). Debug logging can
record more of the traffic; it stays at `info`.

## 9. Comparison

| Aspect | A: official client directly | B: `sinter serve` |
|---|---|---|
| Setup and operation | One `tunnel-client` command line and an optional unit; every option comes from `tunnel-client`'s documentation | One short TOML file and one Sinter command; Sinter checks its own inputs first |
| Explicit manual start in an organization | Yes: `systemctl start` (no `[Install]`) or a foreground command | Yes, with a Sinter command, plus an optional `--max-duration` |
| Stop certainty | systemd: by control group, independent of sessions (to be verified). Foreground: Ctrl+C normally reaches every process; SSH disconnect depends on the session (§7.2) | Foreground: the same, plus `SIGTERM` passing and the 10-second escalation; the Linux death signal when `serve` itself dies, with the limits of §6.6. No guarantee that every child ends after an abnormal end. Not used under systemd |
| Secrets | Safe when the documented `file:` reference is used and, in the foreground, the OpenAI variables are removed; that step depends on the operator | Enforced: no key field, key file permission check, cleared environment, no key in argv or environment of either process |
| Platform | Linux; systemd optional | Linux; foreground use |
| Implementation and maintenance | None in Sinter; documentation only; follows the client's options | A small module (configuration, checks, spawn, signal passing, time limit) plus tests, and tracking the client's command-line interface |
| Consistency with the Sinter CLI | Not a Sinter command | A new subcommand (naming in §11) |

**Equivalence:** on Linux with systemd, Option A already provides explicit start
and stop, a stop of every process of the unit and a time limit, through
`systemctl start|stop` and `RuntimeMaxSec=`. It lacks only a Sinter-named command
and Sinter's own checks. Option B adds something only in interactive use outside
systemd: one Sinter command, and secrets handling that does not depend on the
operator following a procedure. It is therefore not used under systemd.

## 10. Recommended minimal configuration and sequence

1. **Minimal configuration: Option A**, with a dedicated OS user, a `file:`
   runtime key, a clean environment, `Restart=no`, no `[Install]`, an optional
   `RuntimeMaxSec=`, `sudo = false` profiles, and a minimal targets file.
2. Verify it on a real host with v1.5.2 and `tunnel-client` v0.0.16 (§14). This
   verification is needed for Option B as well, because B relies on the same
   client behaviour.
3. Then decide on **`sinter serve`**. It is not required for function or for
   safety under systemd. It is justified by the requirement "a Sinter command
   starts the connection, and stopping it makes ChatGPT unable to use Sinter",
   and by enforced secrets handling in interactive use. If the Owner keeps that
   requirement, implement §6 as specified, with no additional features.

**Changed in r4 (§10, item 1).** The minimal configuration now uses
`Restart=always` (with `RestartSec=10` and a start limit) instead of
`Restart=no`, and `RuntimeMaxSec=` is not part of it; no `[Install]` section,
`sudo = false` profiles and a minimal targets file are unchanged. The
verification required by item 2 has been done within the limits of §14.1.
Item 3 is not decided by r4: `sinter serve` stays a design, and it is not
needed for function or safety under systemd.

## 11. Naming and CLI consistency

- Existing subcommands: `validate`, `plan`, `apply`, `audit`, `mcp`, `secrets`.
  `serve` does not collide with any of them.
  *Later note (2026-11-20, v1.15.0 development, P6):* this list is the state when this section was written. Since then `plugin` (released in v1.12.0) and `serve` itself (released in v1.14.0) were added. The v1.15.0 development adds `approve`, `approvals` and `discover` (not released). None of them is an MCP tool.
- Two points to settle before implementing:
  - The `mcp` help text already reads "Serve a read-only MCP … endpoint on stdio".
    With a `serve` command, that text should say "Run" instead, so that "serve"
    has one meaning.
  - GOALS.md excludes a "central management server" and "agent deployment".
    `serve` is neither (it opens no listener and runs on the administrator's
    controller), and its help text must say so.
- Alternative names considered: `sinter mcp tunnel` (puts it next to `mcp`, but
  turns `mcp` into a command with an optional subcommand) and `sinter connect`
  (not requested). **`sinter serve` remains the first candidate.**
- The configuration follows existing conventions: TOML, unknown keys rejected,
  explicit paths, a default under `~/.config/sinter/` as for the identity file.

## 12. Out of scope

apply, remediation or any mutating tool over MCP; approvals and approval digests;
a per-call audit log; asynchronous jobs beyond the tunnel's 120-second deadline;
per-user authorization, OAuth or an HTTP MCP server; a public plugin or directory
listing; MCP Events; bundling or downloading `tunnel-client`; a web UI; restarting
the tunnel on failure; automatic search for or cleanup of leftover processes;
rollback or cleanup on targets after an interrupted call; a secret store or
encryption of the runtime key; macOS and its termination behaviour. Any of these
needs its own design and decision. A running `serve` is never an approval for
them.

**Changed in r4 (§12, "restarting the tunnel on failure").** r3 listed it as
out of scope. The design and decision it asked for are now recorded here (§16,
Owner decision of 2026-10-19): within Option A, systemd's `Restart=always` in
the standard unit restarts the tunnel after it has been explicitly started.
Sinter itself still restarts nothing: there is no restart code in Sinter, and
`sinter serve` would have no restart loop. The remaining items of this section
stay out of scope.

## 13. Unresolved security points

| ID | Point |
|---|---|
| U-S1 | Processes left after an abnormal end in foreground use, with or without `serve` (§6.6 limits, §7.2). A remaining `tunnel-client` may keep the connection open (outcome 1 not reached); a remaining `sinter mcp` may still observe a target. Neither is assumed to be harmless. There is no automatic search or kill; §7.1 is the manual check. Whether revoking the runtime key stops a remaining client is not verified. Under systemd, `KillMode=control-group` is relied on (to be verified). **r4:** in the single stop tests of the systemd unit, no process of the unit was left (§14.1, row 3); abnormal ends of a foreground run remain unverified. |
| U-S2 | The unauthenticated loopback health/UI listener on shared controllers (§8.6). |
| U-S3 | Key precedence at run time. Source-confirmed for v0.0.16 (§5: the flag, then `CONTROL_PLANE_API_KEY`, then `OPENAI_API_KEY`); not yet observed. The cleared environment makes this moot for B, but it matters for a careless foreground A. |
| U-S4 | Whether other members of the workspace or organization can attach their own ChatGPT app to the same tunnel. This decides who, beyond the administrator, can call Sinter. |
| U-S5 | Whether any user identity (for example the `openai/subject` value documented for Apps SDK tool calls) ever reaches a tunnel backend. It must not be used for authorization in any case. |
| U-S6 | What `tunnel-client` logs at `info` (and at `debug`) about tool payloads. |
| U-S7 | No per-user authorization (§8.4): accepted as a constraint, not solved. |
| U-S8 | The state of a target after a host-tool call is interrupted (§7, row 10): remote commands, and any temporary directory a remote helper creates. |
| U-S9 (r4) | Information a recipe can probe. A recipe is chosen by whoever writes the conversation; through a host tool it can make Sinter observe arbitrary paths on a named target as the SSH user (existence, type, owner and mode, a symlink's target, and whether content matches a given value, one bit per check). File contents are not returned. Sinter does not restrict which paths a recipe may name, and no code mitigation is designed. Mitigation is operational: a low-privilege SSH user, `sudo = false`, one named target (§8.2). |
| U-S10 (r4) | The connection window under `Restart=always` (§8.2, r4): the connection is ended by an administrator's `systemctl stop`, not by a process ending. A silent, slow restart loop is possible and not alerted. |

## 14. Verification required on a real host (not yet authorized)

*r4: this list is the r3 plan. The verification was carried out in part; §14.1 gives the status of each item.*

1. v1.5.2 `sinter mcp` with `tunnel-client` v0.0.16: initialize, tool list, and
   the eight tools, with an empty targets file and with one disposable target.
2. ChatGPT web: new app creation and Refresh with a v1.5.2 backend.
3. The systemd unit of §5, on the supported distributions' systemd versions:
   `LoadCredential` with `file:%d/…`, `RuntimeDirectory`, `NoNewPrivileges`,
   `PrivateTmp`, `Restart=no`, the unit state after `RuntimeMaxSec=`, and that
   `systemctl stop` leaves no process and ends the tunnel's availability (a
   ChatGPT call fails afterwards).
4. Foreground: whether Ctrl+C, `kill <pid>` of each process, and closing the SSH
   session (with the shell actually used) end the connection and every process.
   Record what happens; do not assume it.
5. `tunnel-client` crash and `sinter mcp` crash (each killed separately): the
   other process ends.
6. A host-tool call in progress during stop: how the call fails in ChatGPT; that
   the SSH connection is closed; and what is left on the target (remote
   processes, temporary directories) (U-S8).
7. Two instances with the same tunnel ID: confirm the documented failure, so
   that the user documentation can describe its symptoms.
8. `OPENAI_API_KEY` set and `--control-plane.api-key file:` given: which key the
   client uses (U-S3).
9. Proxy and CA bundle through a test proxy, if corporate use is targeted.
10. ChatGPT mobile and desktop apps, and plan eligibility, only as observations;
    they are not claimed in documentation until observed.
11. For Option B only: after `kill -KILL` of `serve`, the death signal ends
    `tunnel-client` and `sinter mcp`; and the procedure of §7.1 finds a deliberately
    left process.

### 14.1 Status after the verification of 2026-10-18/19 (r4)

Environment of the verification: one temporary VM (Ubuntu 24.04, systemd
255.4), Sinter v1.5.2, `tunnel-client` v0.0.16, a targets file with no targets.
ChatGPT-side results were reported by the person operating ChatGPT and were
matched with the VM's logs by time and count. Single runs unless noted.

| # | Item | Status |
|---|---|---|
| 1 | Eight tools with `tunnel-client` v0.0.16 | **Partial.** ChatGPT called four tools (`sinter_get_version`, `sinter_list_targets`, `sinter_validate_manifest`, `sinter_plan`) with an empty targets file; its list of eight tools came from the app's stored definition (no `tools/list` was observed through the tunnel). **Not verified:** the host tools through the tunnel, and a disposable target. |
| 2 | ChatGPT web: new app and Refresh with a v1.5.2 backend | **Not verified.** An existing app was used and no Refresh was performed. |
| 3 | systemd unit | **Verified:** `LoadCredential=` with `file:%d/…`, `RuntimeDirectory=`, `NoNewPrivileges=`, `PrivateTmp=`; `systemctl stop` leaves no process, is not restarted, and ends the tunnel's availability (a later ChatGPT call failed with `Session terminated`). **Not verified:** `Restart=no`, `RuntimeMaxSec=` (with or without `Restart=always`), a root-owned key file, other systemd versions and distributions. |
| 4 | Foreground and SSH disconnect | **Partial.** A `SIGINT` to one PID stopped the connection and it reconnected with the same key, tunnel and app; a normal SSH logout did not stop the systemd unit. **Not tested:** foreground use with an SSH session that drops. |
| 5 | Crash of `tunnel-client` and of `sinter mcp`, each killed separately | **Verified in single runs:** the `sinter` child killed under `Restart=on-failure` leaves the unit stopped with exit status 0; under `Restart=always` it was restarted 10.05 s later; `tunnel-client` killed under `Restart=on-failure` was restarted 10.05 s later. ChatGPT worked again after each recovery (checked about 19 minutes after the restart; the recovery time was not measured). Why the `sinter` child ended when `tunnel-client` was killed was not established. |
| 6 | A host-tool call in progress during stop | **Not verified.** |
| 7 | Two instances with the same tunnel ID | **Not verified.** A repeated `systemctl start` on a running unit does nothing (verified); a second client was not tried. |
| 8 | `OPENAI_API_KEY` set with `--control-plane.api-key file:` | **Not verified.** Neither variable was present. |
| 9 | Proxy and CA bundle | **Not verified.** |
| 10 | ChatGPT mobile and desktop apps; plan eligibility | **Not verified.** |
| 11 | Option B | Not applicable: not built. |

Also not covered: start failure and `start-limit-hit`, a reboot of the
controller, `systemctl restart`, a manual `SIGTERM`, rotating or revoking the
key while the client runs, and the real-host use of the host tools (the
"verification F" that was planned).

## 15. Sources

- `openai/tunnel-client` (public, Apache-2.0): `README.md`,
  `docs/configuration.md` (API key precedence and `OPENAI_API_KEY` fallback,
  `--mcp.command`, stdio deployment limits, health listener and embedded UI,
  proxy and CA bundle), `docs/permissions.md`,
  `docs/deployment/systemd-vm.md`, `cmd/client/main.go`,
  `pkg/mcpclient/stdio_command.go`, `pkg/runtimeconfig/config.go` (key
  precedence, tunnel ID pattern) at tag `v0.0.16`; release v0.0.16 (2026-10-06).
- OpenAI developer documentation: Secure MCP Tunnels guide (limits: 600
  requests/min, 10 MiB, 120-second deadline, 1,000 pending), "Connect from
  ChatGPT", "Custom MCP server", "Plugins authentication", "Apps SDK reference".
- Sinter v1.5.2: `src/main.rs` (CLI), `src/mcp.rs` (tools, stdio loop, manifest
  authority, redaction), `src/targets.rs` (targets file),
  `docs-site/src/content/docs/en/reference/mcp.md`.
- r4: the real-host verification of 2026-10-18/19 (summarized in §14.1 and §16), `guides/chatgpt-tunnel`, and
  `contrib/systemd/sinter-tunnel.service`.

## 16. Revision r4: decisions after the verification (2026-10-19)

This section records what r4 changes, why, and what it leaves alone, so that no
earlier decision is rewritten silently. The decisions are the Owner's
(2026-10-19). The evidence is the real-host verification of §14.1.

| Topic | r3 | r4 | Reason and evidence | Effect |
|---|---|---|---|---|
| Restart policy (§5) | `Restart=no`; the official example's `Restart=always` was rejected | Standard template: `Restart=always`, `RestartSec=10`, `StartLimitIntervalSec=300`, `StartLimitBurst=5` (Owner decision, 2026-10-19) | With `Restart=on-failure`, a death of only the `sinter` child was not recovered (exit status 0, unit stopped; an unmet operational requirement). `Restart=always` gave an automatic restart 10.05 s later and still honoured `systemctl stop`. | Automatic recovery after an explicit start. The connection window changes (below). |
| Start at boot (§5) | No `[Install]` section | Unchanged (Owner decision, 2026-10-19): no `[Install]`, no `systemctl enable` | Keeps start as an explicit administrator act. | The restart policy applies only after an explicit start. After a reboot the unit is not running. |
| Explicit-start variant | The only unit | Documented as a difference: `Restart=no`, optional `RuntimeMaxSec=` | Some administrators prefer a stricter window. It was **never run** (the verification went from `on-failure` to `always`), so it is documented as unverified. | `RuntimeMaxSec=` together with `Restart=always` gives **no guaranteed time limit** (the systemd manual does not say whether its expiry triggers a restart). |
| Connection window (§8.2) | The window is itself a control: targets are reachable only while the connection is up | The window is bounded by the administrator's `systemctl stop`, not by the life of the process | A consequence of the restart policy above. | Weaker time control. **Unchanged:** the authorization boundary (no per-user authorization, OpenAI's controls decide who can attach), the read-only boundary, the named-target limit, the mandatory `known_hosts`, the refusal of secret references. |
| "Restarting the tunnel on failure" (§12) | Out of scope; needs its own design and decision | In scope as systemd's `Restart=` in the Option A unit | This record is that design and decision. | No restart code in Sinter; `sinter serve` unchanged and not built. The other items of §12 stay out of scope. |
| Unit template and documentation | Illustration only, "published after §14 has passed" | `contrib/systemd/sinter-tunnel.service`, `guides/chatgpt-tunnel` (en, ja) and an updated Core MCP reference | The verification of §14.1 covers the configuration within its stated limits. | Published as the supported configuration only within the verified scope; the unverified items are stated in the guide. |
| F-L1: `sinter_plan` cannot plan `file` / `directory` resources | Not recorded | **Not changed** for the first release; documented as a known limitation | A comment in the existing test suite states that the snapshots intentionally do not model filesystem helpers and fail honestly, but no test asserts the failure. The first verification of this configuration classified it as a medium-severity failure and inferred, without tracing it, that a later release introduced it; but the 2026-10-05 experiment with Sinter v1.1.3 had already recorded the same failure for a `file` recipe as baseline behaviour (low severity), while `package` recipes planned. It does not affect the tunnel, and such resources can be planned with `sinter_plan_host`. The Owner decided to keep the current behaviour for the first release. | None to the read-only boundary. A change would alter the documented behaviour of the snapshots and is a separate decision. |
| F-L2: extra arguments | Not recorded | **Not changed** for the first release; documented | Only `sinter_plan_host` and `sinter_audit_host` reject unexpected arguments; the other tools accept and ignore extra keys (observed). Low severity, no effect on the boundary; rejecting them would change what is accepted today and would need a client-compatibility check. | None. |
| A regression test for the refusal of `password_verifier` secret references | Not recorded | **Not added** | The refusal exists in `src/mcp.rs` and was confirmed by running the built binary with a synthetic manifest; no dedicated test exists. It does not block tunnel support. | A future refactor could drop the refusal without a test noticing; this is recorded as a risk. |

*Later correction (2026-11-20, v1.15.0 development, P6; the r4 row above is kept as recorded):* the row was already out of date when written. `tests/password_hash.rs` (`mcp_refuses_a_password_hash_secret_in_manifest_text`) sends a `postgresql_role` manifest with `password_verifier: { secret: … }` (and a `user` manifest with `password_hash`) to every manifest tool of the built binary and asserts the refusal; the P6 boundary tests (`src/mcp_boundary_tests.rs`) add that the host tools refuse it before connecting. The recorded risk does not apply.

**Unchanged by r4:** the eight read-only tools and their exact-allowlist test;
no apply, exec or shell tool; named targets only, with the connection details
never supplied by the caller; the refusal of `include:`, `source:` and secret
references; the absence of per-user authorization (§8.4); one instance per
tunnel ID (§8.5); the status of Option B as a design that is not built.

**Public tree.** The file name `0002-chatgpt-secure-mcp-tunnel.md` does not
collide with an existing tracked ADR (`0001-progress-output.md`). The public-tree
guard lists `docs/adr/0002-future.md` among paths that must not be ignored; it
checks only that the path is not ignored, and does not require the file to exist.

## 17. Revision r5: `sinter serve` implemented (2026-11-15)

The Owner asked on 2026-11-15 for Option B to be implemented, which is the
confirmation of the need that §3 item 5 and §10 item 3 waited for. r5 records
the implementation and every point where it differs from, or adds to, §6. It
does not change the read-only boundary, the eight tools, the named-target model,
the refusal of secret references or the absence of per-user authorization, and
it does not make `serve` an approval of any future apply operation (§12).

**Baseline.** Sinter v1.13.0 (`main` at the post-release docs commit
`cc9547cb`). `tunnel-client` v0.0.21 (2026-11-14), read in its public source at
that tag; no binary was downloaded or run. Points that changed after v0.0.16 and
matter here:

| Point | v0.0.16 (§5–§7) | v0.0.21 | Effect on `serve` |
|---|---|---|---|
| Flags `run`, `--control-plane.tunnel-id`, `--control-plane.api-key file:`, `--mcp.command`, `--health.listen-addr` | as described | unchanged | none |
| Key precedence | flag, then `CONTROL_PLANE_API_KEY`, then `OPENAI_API_KEY` | unchanged; v0.0.18 adds an AWS workload-identity path (`CONTROL_PLANE_AWS_*`) | the AWS variables are not passed |
| Tunnel ID | `^tunnel_[a-z0-9]{32}$` | `^tunnel_([a-z0-9]{4}_)?[a-z0-9]{32}$` (v0.0.17) | the loose check of §6.3 accepts both; unchanged |
| `--mcp.command` parsing | shell-like | the client's own argv splitter; the child shares the client's process group and inherits its full environment | the stricter path allowlist below |
| Child death (§7 row 6) | the client exits (status 0) | v0.0.19: by default the client restarts its stdio child with a backoff (`--mcp.stdio-failure-policy=restart`); `exit` makes the client end with status 1 | `serve` does not pass the policy flag (older clients reject it) and does not pass `MCP_STDIO_FAILURE_POLICY`: with v0.0.19+, a dying `sinter mcp` is restarted by the official client and `serve` keeps running; with older clients `serve` exits 3. Sinter itself still restarts nothing |
| Signals | SIGINT/SIGTERM handled, SIGHUP not | unchanged; the client forwards the received signal to the child and then sends it SIGTERM | none |
| Network variables | `HTTP(S)_PROXY`, `NO_PROXY`, `CONTROL_PLANE_HTTP_PROXY`, `CA_BUNDLE` | adds `TUNNEL_CLIENT_HTTP_PROXY`, `CONTROL_PLANE_RESIDENCY`; a YAML configuration is read only with `--config`/`--profile` or `TUNNEL_CLIENT_CONFIG`/`TUNNEL_CLIENT_PROFILE*` | the two new network variables are allowlisted; the configuration variables are not |

**Implemented as §6, with these additions (each stricter, none a new feature):**

| § | §6 text | Implementation | Reason |
|---|---|---|---|
| 6.2 / 6.3 item 1 | unknown keys rejected | messages name keys and line numbers only, never a value from the file | a value in the wrong place may be a pasted key |
| 6.3 item 2 | key file: regular, non-empty, bounded, no group/other bits | also: not a symbolic link, owned by the effective user, at most 4096 bytes, and opened (not read) to prove it is readable | a key file another user owns or replaces through a link is refused |
| 6.3 item 4 | client is an executable regular file | also: not writable by group or others | a replaceable client would run with the key |
| 6.3 item 5 | paths in `--mcp.command` without whitespace, quotes or backslashes | an allowlist: `A-Z a-z 0-9 / . _ - + , @ = :` | independent of the client's splitting rules (`$`, `*`, `~`, `;` and the like are refused too) |
| 6.4 | environment allowlist | as listed, plus `TUNNEL_CLIENT_HTTP_PROXY` and `CONTROL_PLANE_RESIDENCY` (above) | documented network settings of the newer client |
| 6.1 | Linux only | the configuration is checked on every system; on a system other than Linux `serve` then exits 3 without starting anything | the checks can be exercised everywhere; nothing runs where the death signal is unavailable |
| 6.1 | `--max-duration` | `<n>h`, `<n>m`, `<n>s` and combinations, 1 s to 720 h | a bounded, unambiguous form |
| 6.6 | stop | the signal handlers are installed before the client starts, so a stop requested during the start is acted on as soon as the client runs | no window in which a signal would end `serve` without stopping the client |

**Unchanged by r5:** §6.7 (nothing removed there is added back: no `doctor`
call, no lock, no own process group, no readiness polling, no client hash pin,
no systemd-credential option, no proxy fields); §7.1 (manual check for leftover
processes); §8; §12.

**Verification of r5.** Automated tests with a scripted stand-in for
`tunnel-client` (no OpenAI contact): the checks of §6.3 on macOS and Linux; on
Linux (Rocky Linux 10.2, aarch64, in a local VM) the exact arguments, the cleared
environment, SIGINT/SIGTERM/SIGHUP passed on as SIGTERM, `--max-duration`,
SIGKILL after 10 seconds, the death signal after `kill -KILL` of `serve` (no
client left), start failures (exit 3), a client that exits by itself (exit 3),
and the unchanged eight read-only tools through `--mcp.command` (an unlisted
tool is refused). §14 item 11 is therefore covered with a stand-in only. **Not
verified:** `serve` with the real `tunnel-client` and ChatGPT, Linux x86_64,
and every item of §14.1 that was not verified for Option A.

## 18. Revision r6: setup commands for an existing tunnel (2026-11-15)

After the live acceptance of r5 passed (L-1 to L-7), the Owner asked for the
first-time setup to be simpler. The design record is the project report of
2026-11-15 on the setup simplification; r6 records the decision and what was
built (Phase 1A). It does not change `sinter serve` itself, `tunnel-client`'s
invocation, the MCP tools or any boundary of §8.

**Facts the decision rests on** (OpenAI's Secure MCP Tunnel guide and
`tunnel-client` v0.0.21 source and documentation):

- Connecting needs only a Restricted key with Tunnels **Read + Use** and the
  tunnel ID; an admin key or an "All" key must not be used by the long-running
  client.
- A Restricted key can read one tunnel (`admin tunnels get`), but cannot list
  or create tunnels. Creating, listing and deleting need an admin key whose
  owner has Tunnels **Manage**; that API appears in `tunnel-client`'s source,
  not in OpenAI's published API reference.
- No API was found that creates a Restricted (tunnel) key, or that registers a
  custom MCP app in ChatGPT; both are manual.

**Decision.**

- **Phase 1A (built):** `sinter serve init`, `sinter serve check` and
  `sinter serve rotate-key`, subcommands of `serve` (no new command group, no
  `start`/`stop`/`status`: stopping is Ctrl+C or systemd, and a status would
  need a process search, which §7 excludes).
- **Phase 1B (not built):** automatic tunnel creation. It would need an
  Owner-level admin key on or near the controller and an API that is not
  published; the operator can run `tunnel-client admin tunnels create` once on
  an administrator's machine instead.

**What the commands do.**

- `init`:
  - Refuses without a terminal, and refuses before asking anything if the
    configuration or the key file exists (a symbolic link counts).
  - Asks for the tunnel ID (shown). An ID outside `tunnel-client`'s current
    form is accepted only after a confirmation.
  - Asks for the key on `/dev/tty` with echo off, using the existing
    `TtyPrompter` of `sinter secrets`. The key must be printable ASCII without
    whitespace, 20 to 1024 bytes; a key not starting with `sk-` is accepted
    with a warning.
  - Creates a missing parent directory with mode `0700`. An existing parent
    must be a real directory owned by the user (or root) and not writable by
    group or others.
  - Writes the key file, then the configuration (both `0600`), with
    `securefile::publish_new`: a temporary file plus a hard link, so no
    existing file is ever replaced.
  - If anything fails, removes exactly what this run created. Otherwise runs
    the `serve` preflight, then `tunnel-client doctor` with the arguments and
    the cleared environment of `serve`.
  - With `--check-online`, also runs
    `tunnel-client admin --admin-key file:<key file> tunnels get <id>`. Its
    output carries organization identifiers, so only the outcome is shown.
  - `--systemd` (root only) leaves the key `root:root 0600` for
    `LoadCredential=` and prints the shipped unit with every placeholder
    filled. It installs nothing.
- `check`: the same diagnosis for an existing configuration; writes nothing.
- `rotate-key`: replaces the key file atomically (`securefile::replace`). The
  file must pass the `serve` key check first. No copy of the old key is kept.
- Exit codes of the three: `0` OK; `2` invalid input or configuration (for
  `init`: nothing written); `3` written or valid, but a client check failed.

**Secret handling.** Sinter holds the key only between reading it and writing
it, in a zeroized buffer. When a client check fails, Sinter shows the exit
status, an HTTP status read only at a status position of the client's output
(after `failed:`, `status`, `HTTP` and the like; numbers in a URL, a tunnel ID
or a request ID are never read; 401, 403, 404 explained)
and the names and verdicts of doctor's checks, never the client's text: an API
error message can quote part of a key. The key is asked for only after every
check that can refuse has passed, and a missing directory is created only after
the key was read, so interrupting the prompt (Ctrl-C) leaves nothing. It never prints the key, never passes it as an
argument or an environment variable, and never reads the key file afterwards.
Sinter makes no network connection; the optional online lookup is made by the
official client.

**Shared code.** `full_sync` and `create_exclusive` moved from `secrets_cli`
into the new `securefile` module, which adds `publish_new` and `replace`.
`sinter secrets` behaves as before.

**Verification.**

- Unit tests of the setup logic, with a scripted prompter, on macOS and Linux.
- End-to-end tests that type into a real pseudo-terminal: the key never
  appears on the terminal, the doctor and the online lookup receive the key
  only as a `file:` reference, there is no terminal, there is an existing
  setup, Ctrl-D at the key prompt, the doctor fails, and `check` and
  `rotate-key` work.
- `--systemd` run as root on Linux.

**Not verified:** the online lookup against the real control plane with a
real key (it needs the Owner's key and approval).

**Unchanged by r6:** §6 and §17 (`serve` itself), §7, §8, §12.

