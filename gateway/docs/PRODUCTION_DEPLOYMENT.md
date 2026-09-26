# Sinter Gateway — Production Deployment (P7.5)

This document is the deployment contract for the production assembly:

```
ChatGPT ──HTTPS+OAuth──▶ TLS terminator ──▶ sinter-gateway ──▶ SQLite
                                                  ▲
sinter-bridge ──outbound HTTPS long-poll──────────┘
      │ stdio (fixed argv, no shell)
      ▼
sinter mcp ──SSH──▶ managed hosts
```

All binaries are thin assembly over the P1–P7 library; no security logic
lives in the executables.

## 1. Artifacts

| Binary | Role | Built by |
|---|---|---|
| `sinter-gateway` | central HTTPS ingress + work broker | `cargo build --release --bin sinter-gateway` (in `gateway/`) |
| `sinter-bridge` | customer-side controller | `cargo build --release --bin sinter-bridge` |
| `sinter` | MCP/tool authority on the controller | repo-root `cargo build --release` |

`sinter-gateway --version` prints version + whether the `test-auth`
feature is compiled in. Production artifacts must report `test-auth:
off` — never ship `--features test-auth` builds.

## 2. `sinter-gateway` configuration

Environment only; the binary fails closed on any missing/invalid
required value.

| Variable | Required | Secret | Meaning |
|---|---|---|---|
| `SINTER_GW_BIND` | yes | no | Listener bind, e.g. `127.0.0.1:8443` (behind proxy) or a private NIC address |
| `SINTER_GW_SQLITE` | yes | no | Path to the identity store; operator-owned directory, `0600`/`0700` |
| `SINTER_GW_PUBLIC_URL` | yes | no | External public base URL; becomes the RFC 9728 `resource` |
| `SINTER_GW_OAUTH_ISSUER` | yes | no | Token `iss` — exact-match trusted issuer |
| `SINTER_GW_OAUTH_AUDIENCE` | yes | no | Expected `aud` (RFC 8707 resource indicator) |
| `SINTER_GW_OAUTH_JWKS_URI` | yes | no | Pinned JWKS document URI (https) |
| `SINTER_GW_OAUTH_ACCOUNT_CLAIM` | no | no | Account-binding claim [default `sinter_account`] |
| `SINTER_GW_ALLOWED_ORIGINS` | no | no | CSV Origin allowlist (e.g. `https://chatgpt.com`) |
| `SINTER_GW_LOG` | no | no | tracing filter [default `info`] |
| `SINTER_GW_RATE_*` | no | no | P7 rate-limit knobs (RFC §M; defaults ratified) |
| `SINTER_GW_METRICS_*` | no | no | Optional loopback metrics listener |
| `SINTER_GW_CLEANUP_*` | no | no | P7 cleanup interval knobs |

No OAuth client secrets, tokens, or keys are configured on the Gateway —
it is a pure resource server (JWKS + issuer/audience pinning only).

### Operator commands

```
sinter-gateway --issue-registration-token <account>   # prints token once
sinter-gateway --revoke-controller <controller-id>
```

Both open `SINTER_GW_SQLITE` directly; run as the service user.
`scripts/sinter-gw-admin` wraps them for day-to-day onboarding: it validates
the account, checks for an existing controller, asks for confirmation, and
supports `--dry-run` and read-only `list`/`status`. See
[`OPERATOR_ONBOARDING.md`](OPERATOR_ONBOARDING.md).

## 3. External Authorization Server contract

The Gateway implements the RFC 9728 protected-resource side only. An
external OAuth 2.1 AS must provide:

| Requirement | Detail |
|---|---|
| JWT access tokens | RS256/ES256 (JWKS-published keys) |
| `iss` | exactly `SINTER_GW_OAUTH_ISSUER` |
| `aud` | exactly `SINTER_GW_OAUTH_AUDIENCE` (RFC 8707 resource indicator) |
| Account claim | a stable claim (default `sinter_account`) identifying the customer account; must match the account used at controller registration |
| JWKS | served at `SINTER_GW_OAUTH_JWKS_URI` over HTTPS |
| `exp`/`nbf`/`iat` | enforced by the validator with bounded leeway |
| Client registration | whatever the ChatGPT connector requires (DCR or console-issued client_id) — AS-side concern, not Gateway |

The Gateway never sees the authorization code, client secret, refresh
tokens, or login flows.

## 4. TLS model

Recommended: **TLS termination at a trusted reverse proxy or managed
ingress** (nginx, Caddy, cloud LB), forwarding to `sinter-gateway` on a
loopback/private bind. The public endpoint is HTTPS; the Gateway itself
serves HTTP on its bind.

Preserve the P7 invariant: **forwarded headers are never trusted** for
security identity or rate keys. Behind a proxy, pre-auth IP rate limits
see the proxy's peer address — deploy accordingly (this is the ratified
P7 semantic, unchanged).

## 5. `sinter-bridge` configuration (customer side)

| Variable | Required | Secret | Meaning |
|---|---|---|---|
| `SINTER_BRIDGE_GATEWAY_URL` | yes | no | `https://<gateway>` — no path/query/userinfo |
| `SINTER_BRIDGE_CREDENTIAL_FILE` | yes¹ | yes | File holding the controller credential (`chmod 600`) |
| `SINTER_BRIDGE_CREDENTIAL` | yes¹ | yes | Alternative env injection (secret-manager style) |
| `SINTER_BRIDGE_SINTER_BIN` | no | no | `sinter` executable [default `sinter` via PATH] |
| `SINTER_BRIDGE_TARGETS_FILE` | no | no | Local targets file passed to the child as `--targets-file` |
| `SINTER_BRIDGE_LOG` | no | no | tracing filter |

¹ exactly one of the two credential sources.

The bridge is **outbound-only**: no listener, no inbound NAT/firewall
change. Redirects are disabled — the controller credential can only ever
reach the configured origin. Plain `http://` is rejected unless the host
is loopback AND `SINTER_BRIDGE_ALLOW_HTTP=1` is set (dev only — never
production).

### Bootstrap

```
# operator, on the gateway host:
sinter-gateway --issue-registration-token acme-corp
#  → prints registration token (single-use, bounded TTL)

# customer, on the controller host:
export SINTER_BRIDGE_GATEWAY_URL=https://gw.example.com
umask 077
# run register ONCE: it consumes the single-use token. It prompts for the
# token on stderr (or reads SINTER_BRIDGE_REG_TOKEN) — never argv — and
# prints only the credential on stdout.
sinter-bridge register > ~/.config/sinter/controller.cred
export SINTER_BRIDGE_CREDENTIAL_FILE=~/.config/sinter/controller.cred
sinter-bridge                     # runs
```

## 6. systemd example

```ini
# /etc/systemd/system/sinter-gateway.service
[Unit]
Description=Sinter Gateway
After=network.target

[Service]
User=sinter-gw
Group=sinter-gw
EnvironmentFile=/etc/sinter/gateway.env   # chmod 640 root:sinter-gw
ExecStart=/usr/local/bin/sinter-gateway
Restart=on-failure
RestartSec=5
# Writable state is the SQLite directory only
ReadWritePaths=/var/lib/sinter-gateway
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

```ini
# ~/.config/systemd/user/sinter-bridge.service  (or system unit)
[Service]
EnvironmentFile=%h/.config/sinter/bridge.env
ExecStart=/usr/local/bin/sinter-bridge
Restart=on-failure
RestartSec=10
```

A complete bridge user unit and environment template (absolute paths —
systemd does not expand `~` in `EnvironmentFile`) are in
`gateway/contrib/systemd/`.

SIGTERM/SIGINT trigger graceful shutdown on both binaries (bounded;
parked polls are woken, the SQLite store is closed cleanly).

## 7. What the bridge never does

- no shell (`sh -c`/`bash -c`) — the child is spawned directly with fixed
  argv `mcp [--targets-file <local-path>]`
- no Gateway-supplied executable/argv — transport payloads are opaque MCP
  frames only
- no durable work queue — memory-only; nothing replays after restart
- no inbound listener
- credential never in argv, child env, child stdio, or logs (env is
  whitelisted: PATH/HOME/SSH_AUTH_SOCK etc.)
