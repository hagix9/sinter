# Sinter Gateway P7 Scope Ratification Report

**Date:** 2026-09-22
**Type:** design / ratification only — **no P7 implementation, no code/test changes, no commit/push**

---

## A. Starting identity

```text
HEAD:    7bd878eecc6746a6b88fb9f84e8752d03a49b57f
branch:  main
worktree:
  D opencode.json
  ?? gateway/SINTER_GATEWAY_P1_P5_GATE_REEVALUATION_REPORT.md
diff:    opencode.json deletion only (owner-controlled, untouched)
```

---

## B. Inputs / evidence

- `SINTER_PRODUCTION_GATEWAY_SECURITY_RFC_RECOVERED.md` (full)
- `SINTER_GATEWAY_RFC_RECOVERY_REPORT.md` (full)
- Accepted P1–P6 implementation/audit reports (targeted re-read)
- Source constants at HEAD (existing caps, `audit_events`, retention comments)
- External: MCP authorization / RFC 6750 / RFC 9728 / RFC 9207 — **already satisfied by P6**; no redesign

---

## C. External requirement verification

| Requirement | Class | P7 impact |
|---|---|---|
| MCP Streamable HTTP `/mcp` semantics | MANDATORY | already implemented (P5) |
| OAuth 2.1 RS + PRM + WWW-Authenticate | MANDATORY | already implemented (P6) |
| Token lifetime / offline JWT (no instant revoke) | MANDATORY (protocol) | F-10 INFO — accepted |
| Rate limiting | RECOMMENDED (ops/security) | **P7 implements** |
| Metrics/telemetry export (OTel etc.) | OPTIONAL | logs+counters v1; OTel FUTURE |
| mTLS / connector IP allowlists | OPTIONAL / deployment | not P7 code |
| CIMD/DCR/PKCE | NOT APPLICABLE (client↔AS) | unchanged |

No mandatory external requirement forces architecture change.

---

## D. Rate-limit decision

**RATIFIED 2026-09-22** — token bucket (rate) + existing/semaphore concurrency; memory-only; identity = account/controller post-auth, socket peer IP pre-auth; **ignore** all forwarding headers in v1.

Defaults (summary): `/mcp` 30/s burst 60 per account (global 300/s burst 600); poll 2/s; respond 20/s; register 5/min/IP; rotate 10/min; auth-fail 30/min/IP. Health/PRM unlimited at app layer. Response `429` + `Retry-After`, uniform `rate_limited` body.

Rationale: ChatGPT turns burst a handful of MCP calls; 30/s steady + burst 60 is headroom without allowing floods; poll is inherently ≤1 in flight so 2/s is reconnect budget only.

---

## E. Telemetry decision

**RATIFIED 2026-09-22** — three separated channels (metrics / structured logs / durable security audit). v1 export = logs + in-process counters; optional loopback metrics endpoint default-off. No OTel, no external collector, no request archive in SQLite.

---

## F. F-06 decision

| Field | Value |
|---|---|
| Original finding | Duplicate JSON-RPC ids overwrite `Session.live`; earlier request un-cancelable via public id |
| Severity | LOW |
| Exploitability | Same-session lifecycle only; not cross-account; no response misroute |
| Mitigation today | `public_key` canonicalization; ownership on respond; deadlines finalize |
| vs P7 recovered reqs | Not required by rate/telemetry/I-7/abuse backbone |
| vs P8 | Does not block e2e acceptance |
| Cost/risk of fix | Small map change; medium blast on cancel semantics |

**Classification: `ACCEPTED RESIDUAL RISK`**

---

## G. F-08 decision

| Field | Value |
|---|---|
| Original finding | `active_polls` explicit release; panic could leak one controller’s poll slot |
| Severity | LOW |
| Exploitability | Requires panic (not attacker-reachable from HTTP/JSON) |
| Mitigation today | Normal paths release; one-controller blast radius |
| vs P7 | Covered by VERIFY in shutdown/abuse tests |
| vs P8 | Non-blocking |
| Cost/risk of fix | Tiny RAII; low risk |

**Classification: `P7 VERIFY ONLY`** (RAII implementation = FUTURE if desired)

---

## H. Optional-hardening decisions

| Item | Classification | Reason |
|---|---|---|
| managed mTLS | POST-v1 / deployment | E-15 transport concern |
| connector IP allowlist | POST-v1 / deployment | E-15 edge concern |
| payload AEAD | FUTURE | deferred; not needed for v1 confidentiality model (TLS) |
| ignore forwarded headers | **P7 REQUIRED** | identity spoofing defense (small) |
| JWKS lock optimization (F-12) | P7 OPTIONAL | bounded stall already; optimize only if cheap |
| extra DoS beyond rate limits | P7 OPTIONAL | rate+body+concurrency sufficient for v1 |
| deployment sandboxing | POST-v1 | ops |
| extra HTTP parser limits | P7 OPTIONAL | axum/hyper bounds + body caps enough unless audit demands |

---

## I. I-7 recovery

```text
original identifier: I-7
recovered semantic meaning: no credential/token/Authorization values in logs
  at any level, including failure paths
exact historical wording: recovered via E-03 (quoted in RFC_RATIFIED §Q)
```
Testable via §N log-grep markers (bearer, JWT claims, ctrlk_, reg_, manifest, tool-result, SSH PEM).

---

## J. Exact P7 scope

| ID | Item | Provenance | Action |
|---|---|---|---|
| P7.1 | Rate limiting (§K values) | RECOVERED + RATIFIED values | IMPLEMENT |
| P7.2 | Telemetry (3 channels, §L) | RECOVERED + RATIFIED shape | IMPLEMENT |
| P7.3 | Log redaction / I-7 full coverage | RECOVERED | IMPLEMENT |
| P7.4a | F-03 cancel ownership | RECOVERED (E-07/E-08) | IMPLEMENT |
| P7.4b | Cleanup scheduler (24h / +90d) | RECOVERED (E-09) | IMPLEMENT |
| P7.4c | Ignore forwarding headers | RATIFIED | IMPLEMENT |
| P7.4d | Config validation + env contract | RATIFIED (backbone “config revert”) | IMPLEMENT |
| P7.5 | Abuse tests | RECOVERED | IMPLEMENT (tests) |
| P7.6 | Log grep | RECOVERED | IMPLEMENT (tests) |
| P7.7 | Rollback via config revert | RECOVERED | VERIFY |
| — | F-06 | RATIFIED | ACCEPTED RESIDUAL |
| — | F-08 | RATIFIED | VERIFY ONLY |
| — | P8 e2e acceptance | RECOVERED boundary | DEFER to P8 |

No unresolved implementation-affecting question remains in this table.

---

## K. P7 / P8 boundary

```text
P7 = production hardening (rate limits, telemetry, log redaction, hardening,
     abuse tests, log grep, config-revert rollback)

P8 = ChatGPT e2e acceptance + zero-mutation re-proof
```

Unchanged from DIRECT recovery.

---

## L. Configuration contract

See `SINTER_PRODUCTION_GATEWAY_SECURITY_RFC_RATIFIED.md` §M.
Summary: `SINTER_GW_RATE_*`, `SINTER_GW_METRICS_*`, `SINTER_GW_CLEANUP_INTERVAL_SECS`, `SINTER_GW_TRUSTED_PROXY` (must stay empty in v1). Fail closed on invalid. Restart to apply.

---

## M. Abuse-test plan

See RFC_RATIFIED §N (20 deterministic cases). No sleep-as-proof; barrier/channel races repeated.

---

## N. Log-grep contract

See RFC_RATIFIED §N (markers listed; zero-occurrence over logs + `audit_events` + metric labels).

---

## O. Remaining unknowns

**None that block P7 implementation.**
FUTURE-only: OTel, trusted-proxy mode, payload AEAD, multi-controller, horizontal scaling, F-08 RAII (optional), F-12 lock split (optional).

---

## P. Repository integrity

```text
 D opencode.json
?? gateway/SINTER_GATEWAY_P1_P5_GATE_REEVALUATION_REPORT.md
```
No source/test/dependency changes. Artifacts written outside the repository only.

---

## Q. Recommendation

Proceed to **P7 implementation** against `SINTER_PRODUCTION_GATEWAY_SECURITY_RFC_RATIFIED.md` after owner review of the decision matrix. Do not start P8 until P7 gates pass.

---

## Ratification decision matrix

| Topic | Historical status | New decision | Provenance | Reason |
|---|---|---|---|---|
| Rate limiting | partial recovery (§11 “incl. rates”) | Token bucket + concurrency caps; concrete defaults in §K | RATIFIED 2026-09-22 | §11 numbers unrecoverable; workload-based safe defaults |
| Telemetry | partial (“telemetry”) | Metrics + structured logs + durable security audit; logs/counters v1 | RATIFIED 2026-09-22 | smallest operable shape; no warehouse |
| F-06 | open LOW | ACCEPTED RESIDUAL RISK | RATIFIED 2026-09-22 | not a security boundary |
| F-08 | open LOW | P7 VERIFY ONLY | RATIFIED 2026-09-22 | panic-only; verify in tests |
| Optional hardening | mixed deferrals | See §H | RATIFIED 2026-09-22 | deployment vs code split |
| F-03 | open MEDIUM → P7 hardening | IMPLEMENT ownership check | RECOVERED (E-07/E-08) | explicit P7 assignment |
| Cleanup scheduler | P3 unresolved | IMPLEMENT | RECOVERED (E-09) | explicit P7 ops hardening |
| P8 boundary | recovered | unchanged | RECOVERED | E-01/E-02 |

---

## Ratification gate

| # | Question | Answer |
|---|---|---|
| 1 | Every implementation-affecting P7 requirement explicit? | **YES** |
| 2 | Concrete rate limits defined? | **YES** |
| 3 | Rate limits configurable with safe defaults? | **YES** |
| 4 | Rate-limit state bounded and memory-only? | **YES** |
| 5 | Telemetry shape explicit? | **YES** |
| 6 | Prohibited telemetry fields explicit? | **YES** |
| 7 | Telemetry cardinality bounded? | **YES** |
| 8 | Durable audit separated from request telemetry? | **YES** |
| 9 | F-06 disposition explicit? | **YES** (`ACCEPTED RESIDUAL RISK`) |
| 10 | F-08 disposition explicit? | **YES** (`P7 VERIFY ONLY`) |
| 11 | Optional hardening classified? | **YES** |
| 12 | I-7 sufficiently recovered to test? | **YES** |
| 13 | P7/P8 boundary explicit? | **YES** |
| 14 | Rollback possible by configuration revert? | **YES** |
| 15 | P7 avoids new infrastructure? | **YES** |
| 16 | P7 preserves no-broker model? | **YES** |
| 17 | P7 preserves memory-only active work? | **YES** |
| 18 | P7 preserves single-node v1 + one controller/account? | **YES** |
| 19 | No historical text forged as original RFC? | **YES** (provenance markers throughout) |
| 20 | Repository unmodified? | **YES** |

---

## Verdict

```text
SINTER GATEWAY P7 SCOPE RATIFICATION: PASS
```
