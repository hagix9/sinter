# Public ChatGPT MCP / Plugin lane — FROZEN

Status: **FROZEN on 2026-09-27.** This is a pause, not a cancellation.

The work is preserved so that it can resume if OpenAI's MCP, plugin, authentication or tunnel mechanisms become simpler.

## Why it is frozen

Public ChatGPT MCP was shown to be feasible. It is frozen because the authentication, publication and operational complexity is currently too large for its purpose, which is to make Sinter easier to use. The pause is not caused by any technical impossibility.

## What was being built

A public ChatGPT plugin. It would let ChatGPT inspect a user's servers over the internet through that user's own Sinter installation:

```text
ChatGPT (MCP client, OAuth)
  → Authorization Server (Logto Cloud; Rauthy evaluated as a replacement)
  → Sinter Gateway (public HTTPS, OAuth resource server, per-account dispatch)
  → sinter-bridge (user-run, outbound long-poll, registered per account)
  → local `sinter mcp` (8 read-only tools)
  → the user's named SSH targets
```

## Out of scope for this freeze

The following continue as normal Sinter work:

- the Sinter CLI and engine (recipes, targets, plan, apply, audit);
- `sinter mcp`, the reusable read-only stdio MCP server in `src/mcp.rs`;
- WebMCP and the docs-site WebMCP;
- the curl installer;
- future local, LAN, VPN or SSH-tunnel HTTP interfaces (a possible `sinter serve`);
- agent and Codex use of Sinter;
- the recipe roadmap.

**No code is deleted by this freeze.**

## What was proven (evidence retained)

| Area | Result | Where |
|---|---|---|
| Gateway P1–P7 | Implemented and audited: transport, sessions, OAuth resource server, rate limits, cleanup, telemetry | `gateway/SINTER_GATEWAY_P*_REPORT.md`, `gateway/docs/SINTER_PRODUCTION_GATEWAY_SECURITY_RFC.md` |
| Production assembly | `sinter-gateway` and `sinter-bridge` executables; deployment contract; operator tooling (`sinter-gw-admin`); systemd user unit | `gateway/docs/PRODUCTION_DEPLOYMENT.md`, `gateway/docs/OPERATOR_ONBOARDING.md`, `gateway/contrib/systemd/` |
| Real ChatGPT end-to-end (2026-09-26) | Worked end to end: OAuth through Logto (CIMD client), then `tools/list`, then read-only tool calls through Gateway → bridge → `sinter mcp` | local report `SINTER_CHATGPT_ACTION_DISCOVERY_REMEDIATION_REPORT.md` (untracked) |
| Tool annotations | Every tool is `readOnlyHint: true`, `destructiveHint: false`, `openWorldHint: false`; shipped in v0.5.1 | `src/mcp.rs`, `tests/mcp.rs`, CHANGELOG 0.5.1 |
| Account isolation | Automated tests pass: 56/56 on the committed Gateway (`isolation`, `abuse`, `http`, `mcp_http`, `oauth_http`) | `gateway/tests/` |
| Token expiry (T1) | Without a refresh token, ChatGPT asks the user to reconnect about once per access-token lifetime (3600 s) | remediation report |
| Hosting hardening | IAP-only SSH, deletion protection, snapshot schedule, uptime check with Slack alert | `gateway/docs/PRODUCTION_DEPLOYMENT.md` §2 |

## Findings about the authorization server

### Route classification at freeze time

| Route | Classification | Summary |
|---|---|---|
| **ChatGPT → Logto → Gateway → sinter-bridge → `sinter mcp`** | **PROVEN; the known production candidate.** Not put into production. | A real ChatGPT OAuth connection, `tools/list` and read-only tool calls worked end to end on 2026-09-26. Keeping this route requires Logto Production **Pro**; see the next section. **This route did not fail.** It is paused only because of cost and operational load. |
| Rauthy (CIMD / ephemeral client) | **NOT USABLE** (as Rauthy v0.36.2 ships) | Summarized below. |
| Rauthy (static confidential client) | **Passed at protocol level. ChatGPT end-to-end: INCONCLUSIVE.** | An exploratory spike for a Logto alternative. **These results say nothing about the Logto route.** |

### Logto route — production recovery path

**Current state.**
- The Logto Cloud tenant is still a **Development** tenant. It was deliberately **not** converted to Production, because the conversion cannot be undone.
- A Development tenant has these limits:
  - users older than 90 days are deleted automatically;
  - the sign-in page shows a development-mode banner;
  - it is not intended for production.

**How the account binding works.**
1. An administrator sets `customData.sinter_account` on the Logto user.
2. A Logto **Custom JWT** script copies it into the access token as the `sinter_account` claim.
3. The script denies token issuance when the value is missing.
4. The Gateway binds each request to that account.
5. The Gateway also fails closed on its own: a token without the claim gets 403 `Unbound`.

**Which plan.**
- Production **Free** does not include Custom JWT. On a Free tenant, Logto skips the script silently, so tokens would have no `sinter_account` and the Gateway would reject every request.
- The production candidate that keeps the current design is **Logto Production Pro**.
- The Pro base price checked at freeze time (2026-09-27) was **USD 24/month**, plus usage-based and add-on charges. Features carried over from the Development tenant can also appear at checkout.
- The Convert/checkout screen was never opened, so the exact first charge is unknown. **Re-check prices, add-ons and the plan feature matrix before resuming; do not assume these figures still hold.**

**Why it is not in production.**
- The route works technically.
- Running OAuth/IdP, a reviewer environment, the Gateway and bridges only for a public plugin is too complex and too costly for the current demand.

**Re-verify all of the following before converting to Pro:**
- issuer and the OIDC / OAuth discovery documents;
- JWKS and the RSA signing key;
- the API resource and the audience;
- Authorization Code flow with PKCE S256;
- CIMD / ChatGPT client-registration compatibility, including the dynamic-app permissions for `profile` and `email`;
- the `sinter_account` Custom JWT claim, and that issuance is denied when it is missing;
- Gateway authentication, account isolation, and existing users;
- that self-registration is still disabled;
- the access-token lifetime and refresh-token behaviour (T2);
- OpenAI's MCP / plugin authentication requirements at that time;
- Logto's pricing and plan feature matrix at that time.

**T2 — no refresh token today.**
- Logto removes `offline_access` when the request has no `prompt=consent`, and ChatGPT does not send it. Users therefore reconnect about once per access-token lifetime (3600 s).
- An upstream fix (logto-io/logto #9656, #9657, #9659) was merged on 2026-09-24. Whether Logto Cloud has rolled it out is unknown.
- **This is a Logto version/rollout issue, not a plan issue.**

### Rauthy v0.36.2 spike (Phase 2A/2B, isolated, commit `dd61ac3c`) — an exploratory Logto alternative

These results describe Rauthy only. They do not change the classification of the Logto route.

**CIMD path — not usable:**
- The default token algorithm is EdDSA, which the Gateway does not accept.
- `resource` is rejected unless `danger_allow_unvalidated_resource` is set, and that flag allows any audience.
- The advertised token-endpoint auth methods do not overlap with ChatGPT's (`none`, `private_key_jwt`).
- `private_key_jwt` assertions are ignored.
- Fetching the metadata document has weak SSRF protection.

**Static (predefined) client path — passed at protocol level, `GATEWAY SOURCE CHANGE: NONE`:**
- RS256 tokens; the audience is pinned with `allowed_resources` and `default_aud`, and unlisted resources are rejected.
- `sinter_account` comes from an admin-only attribute (`user_editable=false`) through the client's default scope, at the token root.
- Refresh tokens are issued without `prompt=consent`, and they rotate.
- The unmodified HEAD Gateway accepted these tokens and served `tools/list` and tool calls through public test tunnels.
- The negative tests failed closed:
  - wrong PKCE verifier;
  - reused authorization code;
  - redirect URI variants;
  - missing or `plain` PKCE;
  - tampered token;
  - wrong issuer or audience;
  - user without a mapping (rejected with 403 `Unbound`);
  - a user editing their own mapping.

**Remaining gaps:**
- RFC 9207 `iss` is not returned.
- Refresh-token reuse does not revoke the whole token family.
- A user without a mapping still gets a token; the Gateway rejects it.
- The metadata still advertises CIMD after the ephemeral-client feature is disabled.
- Login uses email, not a username.

**Measured details (the raw logs are summarized here):**
- Token-endpoint client authentication with the static confidential client:
  - `client_secret_basic` → 200;
  - `client_secret_post` → 200;
  - no secret (`none`) → 400.
- A dry run through public test tunnels against the unmodified HEAD Gateway:
  - `initialize` → 200;
  - `tools/list` → 9 tools (8 Sinter tools and `sinter_get_profile`);
  - `sinter_get_version` → 0.5.1;
  - `sinter_get_profile` → id = test account.
- Unadvertised scopes that ChatGPT may request (`groups`, `address`, `phone`) were dropped silently, not rejected.
- The refresh token's `nbf` is roughly access-token lifetime minus 60 s, so refresh works only near expiry. Rotation works, and a used refresh token is rejected after a 5 s grace period.

**To reproduce the static-client setup (no secrets here):**
1. Build Rauthy `v0.36.2` from source. The repository ships a prebuilt UI archive (`assets/static_html`).
2. Configuration:
   - `[ephemeral_clients] enable = false`;
   - `[dynamic_clients] enable = false`;
   - `[user_registration] enable = false`;
   - `[mfa] admin_force_mfa = false`;
   - listen on loopback only (set `HQL_LISTEN_ADDR_API` and `HQL_LISTEN_ADDR_RAFT` too);
   - behind a proxy, set `proxy_mode = true` and `trusted_proxies`.
3. Create a user attribute `sinter_account` with `user_editable = false`.
4. Create a scope `sinter` with `attr_include_access = ["sinter_account"]` and `claims_at_root = true`.
5. Create a confidential client:
   - `flows_enabled = [authorization_code, refresh_token]`;
   - `access_token_alg = RS256`;
   - `challenges = ["S256"]`;
   - `default_scopes = ["openid", "sinter"]`;
   - `allowed_resources = default_aud = [<MCP resource URL>]`;
   - `redirect_uris = [<exact ChatGPT callback URL>]`.
6. Configure the Gateway: set `SINTER_GW_OAUTH_ISSUER` to Rauthy's issuer (**with** the trailing slash, `https://<host>/auth/v1/`) and `SINTER_GW_OAUTH_JWKS_URI` to `https://<host>/auth/v1/oidc/certs`. No source change is needed.

### ChatGPT User-Defined OAuth Client (2026-09-27)

- ChatGPT offers static credentials in developer mode. The callback URL has the form `https://chatgpt.com/connector/oauth/{callback_id}`.
- The first create attempt failed inside ChatGPT ("MCP アプリを作成できませんでした"). Tunnel request counters prove it sent **no** request to the test endpoints.
- A later attempt ran discovery (`POST /mcp` 401 → protected-resource metadata → RFC 8414 metadata → OIDC discovery) but never sent an authorization request.
- **Result: INCONCLUSIVE.** Whether ChatGPT can complete OAuth with a static client against Rauthy was not established.

## Not completed

- A ChatGPT authorization request with a static client against Rauthy (Phase 2B).
- Privacy policy and terms pages (drafts only, awaiting owner and legal input).
- The reviewer environment (runbook only; no VM was created).
- The demo recording.
- Domain verification (the challenge path returns 404).
- OpenAI submission. Nothing was submitted.
- A production decision on the authorization server (Logto Pro or Rauthy).
- Committing the owner's uncommitted diagnostic logging in `gateway/src/oauth.rs`; the production Gateway binary was built with it.

## Standing decisions while frozen

- **Do not** convert Logto to Production or Pro, and do not start Logto billing. Pro remains the known production candidate, to be converted only when the lane resumes, with owner approval, after the re-verification above.
- **Do not** create the reviewer VM or any Rauthy infrastructure.
- **Do not** submit the plugin, request review, or set up domain verification.
- **Do not** delete the Gateway, bridge or MCP code, tests, or documents.
- **Do not** start the production Gateway VM, or its `sinter-gateway` service, with the binary it holds. See [Restart guard (CVE-2026-25537)](#restart-guard-cve-2026-25537).

## Security boundary to keep if work resumes

- Signed JWT access tokens (RS256 or ES256 P-256, `kid` required) checked against a pinned JWKS; `iss` and `aud` must match exactly; `exp`/`nbf`/`iat` are checked.
- An account binding (`sinter_account`) that only an administrator can set, carried in the signed token.
- Deny by default: a token without an account binding gets 403.
- One active controller per account.
- Per-account dispatch and session ownership.
- PKCE S256 and exact redirect-URI matching at the authorization server.
- Never widen the Gateway's algorithm allowlist, and never accept an unvalidated audience, just to fit a provider.

## Restart guard (CVE-2026-25537)

**The frozen Gateway deployment must not be restarted with its existing binary.** Before the production Gateway VM or its public Gateway service returns to service, the binary must be replaced with a patched, validated build.

**Why.** From `22edea2` (the production executables) through `c88d646`, `gateway/Cargo.lock` pins `jsonwebtoken` 9.3.1. That version is affected by CVE-2026-25537 (type confusion, CWE-843): an `nbf` claim of the wrong JSON type, such as the string `"99999999999"`, is not enforced, so a token that is not yet valid can be accepted. The Gateway's OAuth validator reaches this path. `525a23d` moves to a patched `jsonwebtoken` and adds regression tests.

**The existing binary is unverified.** It was built from uncommitted source (see [Not completed](#not-completed)), and the VM has been stopped since 2026-09-27, so its dependency versions have not been checked. Treat it as potentially affected. Nothing has patched it, and having been stopped does not make it safe to reuse.

**Booting is itself exposure.** The VM boots with `caddy` and `sinter-gateway` enabled, and its public HTTPS firewall rule and DNS record are still in place. Booting it unchanged starts the existing binary on the public endpoint, so replacing the binary after boot is too late.

Before the Gateway returns to service, in this order:

1. Use Sinter source at `525a23d` or a later commit on `main`; the CVE-2026-25537 fix must be included.
2. Build with the committed lockfile: `cargo build --release --locked --bin sinter-gateway` in `gateway/`. Do not build without `--locked`, and do not run `cargo update` as part of the restart.
3. Confirm that the production dependency set uses a patched `jsonwebtoken`: in `gateway/`, `cargo tree --locked -e normal,build -i jsonwebtoken` must show a patched version (upstream first patched: 10.3.0). The currently approved and tested candidate is `jsonwebtoken` 10.4.0 with the `aws_lc_rs` backend. A later patched version is acceptable only if it meets the backend requirement below and passes step 6.
4. Confirm that `jsonwebtoken` 9.3.1 is absent: `cargo tree --locked --target all -i jsonwebtoken@9.3.1` must match no package.
5. Confirm that the `rsa` crate (RUSTSEC-2023-0071) is absent from the production graph: `cargo tree --locked --target all -e normal,build -i rsa` must print nothing. It may appear only as a test dev-dependency.
6. Validate the replacement before any public exposure:
   - `cargo test --locked --test oauth_reason` in `gateway/` passes from the same source and lockfile, including `valid_token_accepted`, `nbf_temporal_contract` and `rsa_keys_below_2048_bits_are_rejected`.
   - The replacement binary itself, run in a production-equivalent setup that is not publicly reachable, accepts a valid token and rejects:
     - a token whose numeric `nbf` is in the future, beyond the 60 s leeway;
     - a token whose `nbf` is malformed or of the wrong type, including at least the string `"99999999999"`.
   - A rejected token must not authenticate. Expect 401, never success.
7. Install the replacement at `/usr/local/bin/sinter-gateway`, and record its SHA-256 and `--version` output (`test-auth: off`). This must happen before `sinter-gateway` is started and before the public route serves traffic. If the VM has to be booted to do this, first make sure, through an owner-approved change, that the existing binary can neither start nor be reached publicly.
8. Only after steps 1–7 pass may the service be started and exposed.

**Backend requirement.** The JWT backend must preserve the existing cryptographic contract; it is not pinned to a particular library:

- The accepted algorithms stay exactly RS256 and ES256 (`ALLOWED_ALGS` in `gateway/src/oauth.rs`).
- RSA keys below 2048 bits stay rejected (`rsa_keys_below_2048_bits_are_rejected`).

`aws_lc_rs` is selected today because it meets both requirements. The `rust_crypto` backend of `jsonwebtoken` 10.4.0 accepted a 1024-bit RSA key, so it does not meet them.

## Conditions for resuming

Resume only if at least one of these holds:

1. OpenAI simplifies MCP or plugin authentication or tunnelling, for example a supported private/tunnel connection for published plugins, or a first-party identity option.
2. There is a concrete user need that justifies running an authorization server and a reviewer environment.
3. A low-cost authorization-server path is verified end to end with real ChatGPT. The candidate is Rauthy with a static client; Phase 2B has to be finished first.

## OpenAI documents to re-read first

`developers.openai.com/plugins/`:
- `build/auth` — CIMD, DCR, predefined clients, RFC 9207, refresh, the profile tool;
- `deploy/submission` and `deploy/submission-errors` — required fields, demo recording, reviewer credentials, domain verification;
- `deploy/app-review` — versioning, origin immutability, re-review;
- `app-guidelines` — test credentials, response minimization.

Also the platform "developer mode" guide on static credentials.

## Resources left running (owner decision)

| Resource | State | Note |
|---|---|---|
| Production Gateway VM and its static IP, disk, firewall rules, uptime check and alert | stopped since 2026-09-27 | Not stopped by this freeze itself. Its resources still cost money. **Do not restart it with its existing binary**; see [Restart guard (CVE-2026-25537)](#restart-guard-cve-2026-25537). Deleting it needs an explicit owner decision. |
| Developer-machine `sinter-bridge` (test account) connected to the production Gateway | running | Not a spike artifact. Stop it when you no longer need the connection. |
| Logto Cloud development tenant | active (free) | Users older than 90 days are deleted automatically. |
| Acceptance-test VMs (8, stopped) | not part of this lane | They are Sinter release infrastructure. Their disks and daily snapshots still cost money. |

## Evidence

**In the repository (committed):**
- this document, which summarizes all spike results with measured values and reproduction settings;
- the Gateway and bridge source and tests;
- `gateway/docs/` and the `gateway/SINTER_GATEWAY_*` reports;
- `src/mcp.rs` and `tests/mcp.rs`;
- the docs-site guides (`guides/chatgpt-plugin`, `reference/mcp`).

The 56/56 account-isolation result can be reproduced with `cargo test --features test-auth` in `gateway/`.

**Local only (untracked, not for Git):**
- `SINTER_CHATGPT_*.md` and `gateway/SINTER_GATEWAY_P8_*.md`: the detailed investigation reports, including production host details.
- `SINTER_PLUGIN_*.md`: publication readiness, metadata, legal drafts and the reviewer runbook, each marked FROZEN.
- `SINTER_PUBLIC_MCP_FREEZE_EVIDENCE/`: the ChatGPT-side proof for the INCONCLUSIVE result. It holds:
  - the evidence-proxy log (parameter names and non-secret values);
  - the tunnel request counters.

  These files contain temporary tunnel hostnames and a ChatGPT callback identifier, so they are kept out of Git.

**Removed:**
- the temporary spike processes, tunnels, test credentials and secrets, test Rauthy databases, and the test Gateway identity store;
- raw spike logs whose results are summarized above (Rauthy Phase 2A test outputs, the dry run, the auth-method check, the test Gateway log, the isolation-test log).

None of these were production resources.

## Public documentation

At freeze time, the README (EN/JA) and the docs-site guide `guides/chatgpt-plugin` (EN/JA) carry a "paused" notice. The notice says that the public ChatGPT plugin / remote MCP publication path is paused while the project focuses on the core Sinter experience, and that the CLI, `sinter mcp` and WebMCP are unaffected. The rest of the guide still documents the architecture as built.

When the lane resumes, update or remove the notice.
