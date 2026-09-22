# SINTER PRODUCTION GATEWAY SECURITY RFC

**Document type:** **AUTHORITATIVE** production Gateway security/design RFC (Git-managed)
**Supersedes:** the lost historical RFC (unrecoverable outside Git)
**Date:** 2026-09-22
**Base HEAD at ratification:** `7bd878eecc6746a6b88fb9f84e8752d03a49b57f`
**Status:** authoritative specification for P7+ implementation

> **Authoritative status:** This Git-managed file is the current production
> Gateway security/design RFC. P7 implementation must use this path only
> (`gateway/docs/SINTER_PRODUCTION_GATEWAY_SECURITY_RFC.md`), not external
> recovery/ratification copies.

---

## A. Provenance notice

```text
The original RFC artifact was lost.

Sections marked RECOVERED are reconstructed from surviving direct
or corroborated evidence.

Sections marked RATIFIED 2026-09-22 are new owner-approved decisions
made to resolve gaps that could not be recovered from surviving evidence.

RATIFIED sections are not claimed to reproduce the lost original text.
```

| Marker | Meaning |
|---|---|
| **RECOVERED** | From Tier-1/2 evidence (session-history RFC quotes, accepted reports) |
| **RATIFIED 2026-09-22** | New decision filling a recovery gap |
| **ARCHITECTURAL INVARIANT** | Preserved from accepted P1–P6 architecture |

Lost original path: `~/sinter-public-plugin-research/SINTER_PRODUCTION_GATEWAY_SECURITY_RFC.md`
Recovery inputs: `SINTER_PRODUCTION_GATEWAY_SECURITY_RFC_RECOVERED.md`, `SINTER_GATEWAY_RFC_RECOVERY_REPORT.md`

---

## B. Architecture

**RECOVERED / ARCHITECTURAL INVARIANT**

```text
ChatGPT / Public Plugin
        │ HTTPS + OAuth (P6 RS)
        ▼
Central Sinter Gateway          (public MCP server)
        │ account mapping (validated claims only)
        ▼
GatewayCore                     (memory-only work)
        ▲ outbound HTTPS long-poll
        │ controller bearer (separate trust domain)
sinter-bridge → sinter mcp → managed hosts
```

v1: **single Gateway node**. No second instance.
If horizontal scaling is introduced later: rate-limit and session state would need a shared design (sticky sessions or shared store) — **out of v1**.

---

## C. Threat model

**RECOVERED (from accepted audits + invariants)**

Assume: Internet-facing `/mcp` and controller endpoints; arbitrary HTTP/JSON; stolen/revoked controller credentials; restart at adversarial moments; proxy retries; malformed input as normal.

Out of scope: malicious AS (trusted by config); Sinter tool semantics inside `sinter mcp`; TLS termination implementation (deployment).

---

## D. Security boundaries

**ARCHITECTURAL INVARIANT**

- Gateway is not an SSH bastion; never receives SSH keys or target SSH config (I-1).
- No broker; no durable active work; SQLite = identity/security lifecycle only.
- One controller per account; controller-initiated connectivity only (I-9).
- `sinter mcp` is sole tool authority; only `tools/list` + `tools/call` forwarded (I-10/I-11).
- Public OAuth identity and controller credential remain separate domains.

---

## E. Authentication model

**RECOVERED (P6)**

- Public: OAuth 2.1 RS — JWT RS256/ES256, `iss`/`aud` exact, `exp`/`nbf`/`iat`, JWKS from pinned `jwks_uri`, PRM per RFC 9728, RFC 6750 challenges. Missing account claim → `account_unbound` (403).
- Controller: `Bearer ctrlk_…` SHA-256 verifier lookup; register/rotate/revoke lifecycle.
- `TestPublicAuth` compile-gated (F-01 CLOSED). Fail-closed if no `PublicAuth` (503).

---

## F. Persistence model

**RECOVERED**

Durable (SQLite): controller identity + verifier + status, registration token verifiers, `audit_events` metadata (ts/kind/account_id/controller_id).
Memory-only: sessions, MCP work, queues, rate-limit state (**RATIFIED 2026-09-22**), metrics counters.

Retention (RECOVERED): spent registration tokens 24h; revoked controllers retain +90d then purgeable — **scheduler is P7** (E-09).

---

## G. Public MCP model

**RECOVERED**

Edge: `initialize`, `ping`, `notifications/*`, `tools/call` name==profile.
Forwarded: `tools/list`, `tools/call`. Unknown → −32601; batches → −32600. Session is routing context, never auth.

---

## H. Controller protocol

**RECOVERED**

`POST /v1/register|rotate|poll|respond`; one poll per controller; ownership-checked respond; revocation rechecked before delivery and respond (F-07 CLOSED).

---

## I. Recovered P1–P8 plan

| Phase | Purpose | Status |
|---|---|---|
| P1 | core/state machine/limits, memory-only | DONE |
| P2 | controller identity lifecycle | DONE |
| P3 | SQLite identity + audit | DONE |
| P4 | poll/respond HTTP | DONE |
| P5 | public `/mcp` | DONE |
| P6 | OAuth RS + profile | DONE |
| **P7** | **production hardening** (see §J) | **THIS SPEC** |
| **P8** | **ChatGPT e2e acceptance + zero-mutation re-proof** | NOT YET |

---

## J. Ratified P7 specification

### P7.1 Rate limiting
- provenance: **RECOVERED** (E-01 “rate limits”, E-04 §11 “incl. rates”) + **RATIFIED 2026-09-22** (concrete values in §K)

### P7.2 Telemetry
- provenance: **RECOVERED** (E-01 “telemetry”) + **RATIFIED 2026-09-22** (shape in §L)

### P7.3 Log redaction / I-7 full coverage
- provenance: **RECOVERED** (E-01 “log redaction”, I-7, E-10)

### P7.4 Production hardening umbrella
- provenance: **RECOVERED** (E-01 “hardening”) + **RATIFIED 2026-09-22** (closed set below)

**Hardening closed set (RATIFIED 2026-09-22):**
1. F-03 `core.cancel` ownership parameter (defense-in-depth)
2. Identity/registration **cleanup scheduler** (24h spent tokens; revoked+90d)
3. Rate-limit + concurrency enforcement
4. Structured operational logs with prohibited-field list
5. Abuse-test suite + log-grep contract
6. Config validation + config-revert rollback
7. Ignore untrusted forwarding headers (no trusted-proxy in v1)

### P7.5 Abuse tests
- provenance: **RECOVERED** (E-01)

### P7.6 Log grep
- provenance: **RECOVERED** (E-01)

### P7.7 Rollback = configuration revert
- provenance: **RECOVERED** (E-01)

### P7 explicit non-goals (this P7)
- P8 ChatGPT acceptance run
- OAuth redesign
- multi-controller (Q-4)
- broker / PostgreSQL / durable work
- managed mTLS / connector IP allowlist (deployment)

---

## K. P7 rate-limit contract

**RATIFIED 2026-09-22** — workload model: one ChatGPT conversation turn may burst `initialize`/`tools/list`/several `tools/call`; `tools/call` may hold up to the 120s work deadline; controller long-poll is one-at-a-time and mostly idle-holding.

### Algorithms
| Problem | Mechanism | State |
|---|---|---|
| Request rate | token bucket | memory-only |
| Concurrency | semaphore / existing inflight+queue caps | memory-only |
| Pre-auth flood | token bucket keyed by **socket peer IP** | memory-only |

**Never key security identity on** `X-Forwarded-For` / `Forwarded` / `X-Real-IP` (v1: **ignore entirely**).
**Trusted proxy:** none in v1.

### Concrete limits (defaults)

| Operation | Key | Steady | Burst | Concurrency | Failure |
|---|---|---|---|---|---|
| `POST /mcp` | account (post-auth) | 30/s | 60 | 64 inflight/account (existing) | 429 |
| `POST /mcp` global | gateway | 300/s | 600 | 256 concurrent | 429 |
| `/mcp` pre-auth attempts | socket IP | 60/s | 120 | — | 429 |
| `POST /v1/poll` | controller | 2/s | 5 | 1 (existing) | 429 |
| `POST /v1/respond` | controller | 20/s | 40 | 32 | 429 |
| `POST /v1/register` | socket IP | 5/min | 10 | 4 | 429 |
| `POST /v1/rotate` | controller | 10/min | 20 | 4 | 429 |
| Invalid auth (401/403) | socket IP | 30/min | 60 | — | 429 after bucket empty |
| JWKS refresh | global | 1/min unknown-kid + 1h TTL (existing) | — | 1 fetch | fail-closed auth |

**Health:** `/healthz`, `/readyz`, PRM `/.well-known/oauth-protected-resource*` — **no app rate limit** (cheap, needed by LB/AS discovery). Optional reverse-proxy limit is deployment.

**Response:** `429` + `Retry-After: 1` (seconds, bucket-dependent). Uniform body `{"error":{"code":"rate_limited","message":"rate limit exceeded"}}` — identical for account vs IP buckets (no existence oracle). Never echo credentials/payloads.

### Bounds / cleanup / restart
- Bucket map capped (e.g. 50k keys); LRU/expiry sweep ≤ 5 min idle.
- State **memory-only**; restart = empty buckets (safe).
- **Not** written to SQLite.

---

## L. P7 telemetry contract

**RATIFIED 2026-09-22**

### Separation
| Channel | Contents | Durability |
|---|---|---|
| **Metrics** | counters/histograms, low cardinality | memory (+ optional scrape) |
| **Structured logs** | categorical ops events | stdout/journald (ephemeral) |
| **Security audit** | identity lifecycle only | SQLite `audit_events` |

### Metrics (minimal set)
`http_requests_total{route,method,status_class}` · `http_request_duration_seconds` · `mcp_active_requests` · `controller_active_polls` · `work_queued` · `rate_limited_total{bucket_class}` · `auth_failures_total{reason_class}` · `controller_online` · `deadline_exceeded_total` · `jwks_refresh_total{result}` · `sqlite_errors_total{op}`

**Prohibited metric labels:** `account_id`, `controller_id`, `request_id`, `subject`, `email`, `target`, any secret, any payload.

**Prohibited metric/log/audit fields:** OAuth bearer, JWT, controller credential, registration token, manifest, tool arguments, tool results, SSH target/user/key, raw MCP payload.

### Structured logs
Allowed: `event`, `route`, `method`, `status_class`, `error_category`, `duration_ms` (or bucket), optional **opaque** `corr` id (random, not a secret).
Preserve marker-secret tests (zero prohibited markers).

### Durable `audit_events` (allowed kinds only)
`registration_token_issued` · `registration_token_consumed` · `controller_registered` · `credential_rotated` · `controller_revoked`
**Never** store per-request `/mcp` traffic or payloads (not a request warehouse).

### Export mechanism
**v1: structured logs + in-process counters.**
Optional `GET /metrics` on a **separate** admin bind (default **off**); if enabled, loopback-only default.
OpenTelemetry: **FUTURE/OPTIONAL** — not required for P7 correctness.

---

## M. P7 configuration contract

**RATIFIED 2026-09-22** — env vars, applied at process start (restart to change). Invalid values: **fail closed** (refuse start) except documented clamps.

| Name | Purpose | Type | Default | Min | Max | Reload | Security effect |
|---|---|---|---|---|---|---|---|
| `SINTER_GW_RATE_MCP_RPS` | /mcp per-account steady | float | `30` | 1 | 1000 | restart | abuse bound |
| `SINTER_GW_RATE_MCP_BURST` | /mcp burst | int | `60` | 1 | 10000 | restart | burst bound |
| `SINTER_GW_RATE_MCP_GLOBAL_RPS` | global /mcp | float | `300` | 1 | 10000 | restart | node ceiling |
| `SINTER_GW_RATE_POLL_RPS` | poll per controller | float | `2` | 0.1 | 100 | restart | poll abuse |
| `SINTER_GW_RATE_RESPOND_RPS` | respond per controller | float | `20` | 1 | 1000 | restart | respond abuse |
| `SINTER_GW_RATE_REGISTER_PER_MIN` | register per IP | float | `5` | 0.1 | 100 | restart | token farming |
| `SINTER_GW_RATE_ROTATE_PER_MIN` | rotate per controller | float | `10` | 0.1 | 100 | restart | rotate abuse |
| `SINTER_GW_RATE_AUTHFAIL_PER_MIN` | invalid auth per IP | float | `30` | 1 | 10000 | restart | cred stuffing |
| `SINTER_GW_RATE_ENABLED` | master switch | bool | `true` | — | — | restart | rollback lever |
| `SINTER_GW_METRICS_ENABLED` | metrics endpoint | bool | `false` | — | — | restart | exposure |
| `SINTER_GW_METRICS_BIND` | metrics bind | addr | `127.0.0.1:9091` | — | — | restart | exposure |
| `SINTER_GW_CLEANUP_INTERVAL_SECS` | identity GC period | int | `3600` | 60 | 86400 | restart | retention |
| `SINTER_GW_TRUSTED_PROXY` | proxy trust | string | empty | — | — | restart | identity spoofing (**v1: must stay empty**) |

Existing caps (body, sessions, inflight, queue, poll hold, deadlines) remain as code defaults; not duplicated as dozens of knobs.

---

## N. P7 abuse / log-grep test contract

**RECOVERED** (abuse tests, log grep) + **RATIFIED 2026-09-22** (exact plan)

### Abuse tests (deterministic; barrier/channel sync; no `sleep` as proof)
1. Burst `/mcp` (limit+burst+1) → 429 after bucket empty
2. Sustained `/mcp` at steady rate → no 429 below limit
3. Cross-account rate isolation (A flood does not starve B)
4. Controller poll abuse (2nd concurrent poll still 409; rate 429)
5. Registration abuse (per-IP)
6. Rotation abuse
7. Invalid-auth flood → 429 after bucket
8. Oversized body (limit−1 / limit / limit+1)
9. Concurrency exhaustion (global 256)
10. Slow controller (deadline expiry)
11. Offline controller
12. Deadline race (respond after expire)
13. Revocation race (F-07; multiple runs, barriers)
14. Shutdown under load (parked poll wake; no new work)
15. Rate-bucket cleanup (idle key reclaim)
16. Config boundary values (min/max/invalid fail-closed)
17. Log-secret grep (see below)
18. Telemetry cardinality (labels stay bounded; no account_id labels)
19. Forwarded-header ignore (`X-Forwarded-For` cannot move identity/rate key)
20. F-03: cancel of foreign rid rejected when ownership required

### Log-grep contract
Scan: stdout structured logs, `audit_events` rows, metrics label dumps.
Markers (must be **zero** occurrences):
- OAuth bearer (`Bearer <token>` full string + token body)
- JWT body/claim marker (synthetic `sub`/`email` marker)
- Controller credential (`ctrlk_` + secret)
- Registration token (`reg_` + secret)
- Manifest marker
- Tool-result marker
- SSH-looking secret marker (`BEGIN OPENSSH PRIVATE KEY` / `BEGIN RSA PRIVATE KEY`)

---

## O. P7 rollback contract

**RECOVERED:** rollback = **configuration revert**.

| Control | Disable/relax | Mandatory? | Restart? |
|---|---|---|---|
| Rate limits | `SINTER_GW_RATE_ENABLED=false` or raise RPS/burst env | Optional (safe default on) | yes |
| Telemetry metrics | `SINTER_GW_METRICS_ENABLED=false` | Optional | yes |
| Structured logs | level filter only (never disable redaction) | Redaction **mandatory** | level: yes |
| I-7 prohibited fields | **cannot disable** | **MANDATORY** | — |
| Auth / ownership / revocation recheck | **cannot disable** | **MANDATORY** | — |
| Body caps | code defaults; tighten via future config only | Mandatory minimums stay | — |

Mis-sized production rate limit → change env + restart; **no code rollback**.

---

## P. P8 acceptance boundary

**RECOVERED (E-02/E-20)**

P8 (not P7): real ChatGPT dev-mode → gateway → bridge → official `sinter` → target; zero-mutation re-proof; acceptance report; all invariants.
P7 **prepares**; P8 **proves**.

---

## Q. Security invariants

**RECOVERED (E-03)** I-1…I-11 as previously listed.

**I-7 focus for P7:**
```text
original identifier: I-7
recovered semantic meaning: No credential/token/Authorization-header value
  appears in any log at any level (across endpoints including failure paths).
exact historical wording: RECOVERED as quoted in recovery E-03
  ("No credential/token/Authorization-header value appears in any log at
   any level (test: log grep across all endpoints incl. failure paths).")
```
P7 tests: §N log-grep contract over logs + audit + metrics labels.

---

## R. Open questions after ratification

| ID | Status after ratification |
|---|---|
| Q-1 | RESOLVED (P6) |
| Q-2 | RESOLVED (P1) |
| Q-4 | DEFERRED (post-v1) |
| Q-5 payload AEAD | **FUTURE** — not required for v1 P7 |
| Q-6 cancellation | Addressed operationally by F-03 hardening; formal Q text unrecovered |
| Horizontal scaling | FUTURE (would change rate/session design) |
| OTel export | FUTURE/OPTIONAL |
| Trusted reverse-proxy identity | FUTURE (v1 ignores forwarded headers) |

---

## S. Historical provenance map

| Section | Provenance |
|---|---|
| B Architecture | RECOVERED + INVARIANT |
| C Threat model | RECOVERED |
| D Boundaries | INVARIANT |
| E Auth | RECOVERED (P6) |
| F Persistence | RECOVERED + RATIFIED (RL state memory-only) |
| G/H MCP/controller | RECOVERED |
| I P1–P8 | RECOVERED |
| J P7.1–.3,.5–.7 | RECOVERED backbone |
| J P7.4 closed set | RATIFIED 2026-09-22 |
| K Rate values | RATIFIED 2026-09-22 |
| L Telemetry shape | RATIFIED 2026-09-22 |
| M Config names | RATIFIED 2026-09-22 |
| N Test plan detail | RATIFIED 2026-09-22 (plan for RECOVERED abuse/log-grep) |
| O Rollback | RECOVERED principle + RATIFIED mechanics |
| P P8 boundary | RECOVERED |
| Q Invariants | RECOVERED |
