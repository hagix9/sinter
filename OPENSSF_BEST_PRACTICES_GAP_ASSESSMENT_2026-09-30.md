# OpenSSF Best Practices: read-only gap assessment for Sinter

- **Date baseline:** 2026-09-30 (JST).
- **Status:** RESEARCH / ASSESSMENT ONLY.
- No repository file, GitHub setting or external service was changed. No enrollment, login, badge or submission was made. This report is the only file created (untracked).

Evidence labels:
- **[REPO]** repository at `543b238`;
- **[GH]** read-only GitHub API, 2026-09-30;
- **[ART]** published v1.1.1 release assets, downloaded read-only and checksum-verified;
- **[SRC]** official OpenSSF source;
- **[INF]** my reasoning.

---

## A. Executive summary

- Sinter already meets most of the **Passing** level of the OpenSSF Best Practices *metal* series (67 criteria).
  - **46 SATISFIED**, **10 LIKELY SATISFIED** (a small human confirmation or judgement remains), **5 NOT APPLICABLE**.
  - Only **2 MUST criteria are not met**: `crypto_working` and `crypto_keylength`. Both come from **one real engineering finding**, described next.
  - The remaining unmet items are SHOULD/SUGGESTED, which the rules allow to be answered "unmet".
- **The finding.**
  - The SSH client stack's **default** algorithm offer still includes legacy fallbacks: MD5 and SHA-1 MACs, RC4/blowfish/CAST/3DES/CBC ciphers, and **1024-bit `diffie-hellman-group1-sha1`**.
  - Sinter provides **no way to disable them**. It sets only the host-key preference.
  - This is present in the **published v1.1.1 binary** [ART].
  - Against Sinter's supported (modern OpenSSH) targets the negotiated algorithms are strong, so this is a **hardening** gap, not an observed exploit. But it is exactly what the two MUST criteria prohibit by default, and it is worth fixing regardless of any badge.
- **Recommendation: WAIT** (§Z).
  - Do the small SSH-defaults hardening as its own WP and ship it in the next release.
  - Then enrollment is mostly evidence entry.
  - Nothing else needs building. No new workflows, no Scorecard, no CodeQL.

## B. Repository baseline

| Item | Value |
|---|---|
| HEAD = main = origin/main = `ls-remote` main | `543b238c64ac8def52aabf25d3f8c11a3ed53709` |
| branch; ahead/behind; tracked changes | `main`; 0/0; none |
| untracked | 16 pre-existing reports (+ this report) |
| latest tag / Release | `v1.1.1` → `cf0339e`; Release "Sinter v1.1.1", 2026-09-29T06:48:38Z; 11 Releases total |
| visibility / license | public. GitHub license detection shows `Apache-2.0` only, although the repo is dual `MIT OR Apache-2.0` (`Cargo.toml`, `LICENSE-APACHE`, `LICENSE-MIT`, README §License) |
| workflows | `ci.yml`, `advisories.yml`, `docs.yml`, `start.yml` |
| WP-N | Treated as CLOSED per the task statement. The closure re-audit report is not present locally; nothing found here reopens WP-N |

Not present:
- **`CONTRIBUTING*`** at the repo root (contribution docs live on the docs site);
- **`CODE_OF_CONDUCT*`**, **`GOVERNANCE*`**, issue/PR templates.

Present: `SECURITY.md`, `CHANGELOG.md`, `RELEASE.md`, `DESIGN.md`, `GOALS.md`, `README.md`/`README.ja.md`, and the docs site `https://sinter.fulltrust.co.jp`.

WebCodex procedure (task §1): not applicable. This assessment ran in Claude Code with direct filesystem access, so no Runner `client_id` was involved.

## C. Official sources and retrieval (2026-09-30)

| Source | Identity |
|---|---|
| Best Practices badge repository (official; `coreinfrastructure/…` now redirects to it) | `github.com/ossf/best-practices-badge`, main `e1b85623fd6c` (2026-09-24) |
| Criteria definitions | `criteria/criteria.yml` (last change `880f1cb`, 2026-06-25) |
| Criteria text and details | `config/locales/en.yml` (last change `5ea0f48`, 2026-09-13) |
| Badge rules, terminology, implied criterion | `docs/criteria.md` (`2fc9ac1`, 2026-06-26) |
| Baseline series | `criteria/baseline_criteria.yml` (`368d894`, 2026-09-03; source `baseline.openssf.org/versions/2026-08-28`, 64 controls) |
| Live site | `https://www.bestpractices.dev/en/criteria` (six levels listed); badge image, JSON and API behaviour from `docs/api.md`, `docs/baseline_plan.md`, `docs/implementation.md`, `app/models/project.rb` |
| Scorecard relation | `docs/badge-vs-scorecards.md` |

The criteria header states that the website is now the authoritative presentation, rendered from `criteria.yml` + `en.yml`. The criterion wording below comes from those pinned files.

## D. Current program structure

- **Two independent badge series** [SRC README, `baseline_plan.md`]:
  - **Metal:** Passing, Silver, Gold.
  - **Baseline:** Baseline Level 1/2/3, from OSPS Baseline v2026.08.28.
- "A given project can use one set of criteria, or the other, or both." They use **separate badge images**: `/projects/<id>/badge` (metal) and `/projects/<id>/baseline`.
- **The first metal level is "Passing"** (level 0), with **67 active criteria: 43 MUST, 10 SHOULD, 14 SUGGESTED**, none marked future.
  - Silver adds 55 (44/10/1) and requires `achieve_passing`.
  - Gold adds 23 (21/2/0) and requires `achieve_silver`.
- **Rule to obtain a badge** [SRC `docs/criteria.md`]:
  > all MUST and MUST NOT criteria must be met, all SHOULD criteria must be met OR the rationale for not implementing the criterion must be documented, and all SUGGESTED criteria have to be considered (rated as met or unmet).
- **Implied criterion:** `homepage_url`, "a public website with a stable URL".
- **Evidence flags** per criterion: `{Met URL}`, `{Met justification}`, `{N/A allowed}`, N/A justification.
- **Progress** [SRC `project.rb` via research agent]:
  - Each active criterion counts equally.
  - These count toward the percentage: Met; SUGGESTED "Unmet"; SHOULD "Unmet" with a justification.
  - `?` (unknown) does not count.
- **Self-attested, partly automated.** "Detectives" auto-fill some answers for GitHub projects: license, sites_https, repo_*, contribution, discussion, license_location, release_notes, build, documentation_basics and others. Results with confidence ≥ 4 override user input.
- **Recent change:** Baseline support was added from late 2025. No 2025–2026 change to the metal Passing criteria was found (UNVERIFIED beyond the file history above).
- No expiry or re-attestation is documented. **A badge can be lost** when updated criteria take effect (`lost_passing_at`).

## E. Methodology

- Every Passing criterion was taken verbatim from the pinned `en.yml` (description + details) with its category and flags from `criteria.yml`.
- Each was mapped to concrete repository, GitHub or artifact evidence.
- Statuses use exactly the requested taxonomy, and uncertainty was never upgraded.
- Where a criterion's details settle an interpretation, that is cited:
  - `vulnerability_report_response` → N/A when there are no reports;
  - `release_notes_vulns` → N/A when there are no publicly known vulnerabilities in project results;
  - `dynamic_analysis` needs a fuzzer or ≥ 80% branch coverage;
  - `static_analysis` excludes compiler warnings.
- The Gateway (`gateway/`) is in the repository but is not a released artifact (the CLI release is CLI-only; the Gateway lane is frozen). It is treated as project source where criteria concern "software produced by the project".

## F. Complete Passing-level matrix (67 criteria)

Legend: M = MUST, S = SHOULD, G = SUGGESTED; `u` = Met URL required, `j` = justification required, `N` = N/A allowed.

| # | Criterion | Req | Status | Evidence / note | Action |
|---|---|---|---|---|---|
| 1 | description_good | M | SATISFIED | README opening ("lightweight, agentless configuration-management tool…"); docs site home | — |
| 2 | interact | M | SATISFIED | README §Install, §Reporting bugs and vulnerabilities, contributing link; docs site Getting started + Contributing | — |
| 3 | contribution | M u | SATISFIED | docs site `/en/contributing/` §Proposing changes: issue first, PR against `main` | optional root `CONTRIBUTING.md` pointer (helps autofill) |
| 4 | contribution_requirements | S u | SATISFIED | same page: quality gates (fmt/clippy/test), "include tests for any change in behavior", docs checks | — |
| 5 | floss_license | M | SATISFIED | `MIT OR Apache-2.0` (`Cargo.toml`, both license files, README §License) | — |
| 6 | floss_license_osi | G | SATISFIED | MIT and Apache-2.0 are OSI-approved | — |
| 7 | license_location | M u | LIKELY SATISFIED | top-level `LICENSE-APACHE` + `LICENSE-MIT`, the Rust dual-license convention. The details name `LICENSE`/`COPYING` (+ext) or a REUSE `LICENSES/` directory as conventions; GitHub detects only Apache-2.0 | reviewer judgement; optional top-level `LICENSE` stating the dual choice |
| 8 | documentation_basics | M N | SATISFIED | README; docs site (getting started, concepts, guides, recipes) | — |
| 9 | documentation_interface | M N | SATISFIED | docs site reference: `cli.md`, `recipe-format.md`, `resources/`, `mcp.md`, `webmcp.md`; README §CLI exit codes, §MCP interface | — |
| 10 | sites_https | M | SATISFIED | `http://sinter.fulltrust.co.jp/` → 301 to https; https 200 with valid TLS; GitHub https; downloads from GitHub Releases over https | — |
| 11 | discussion | M | SATISFIED | GitHub issues + pull requests: public, searchable, URL-addressable, no proprietary client | — |
| 12 | english | S | SATISFIED | EN docs primary (JA in addition) | — |
| 13 | maintained | M | SATISFIED | 114 commits in the last 30 days; 11 Releases since 2026-09-13 | — |
| 14 | repo_public | M | SATISFIED | `github.com/hagix9/sinter`, public | — |
| 15 | repo_track | M | SATISFIED | git history (author, date, diff) | — |
| 16 | repo_interim | M | SATISFIED | many commits between tags (e.g. `cf0339e..543b238`) | — |
| 17 | repo_distributed | G | SATISFIED | git | — |
| 18 | version_unique | M | SATISFIED | `v0.1.0`…`v1.1.1`, one version per release | — |
| 19 | version_semver | G | SATISFIED | SemVer | — |
| 20 | version_tags | G | SATISFIED | annotated git tags per release | — |
| 21 | release_notes | M N u | SATISFIED | curated GitHub Release notes (e.g. v1.1.1 "Highlights") + `CHANGELOG.md` per version; not raw git log | — |
| 22 | release_notes_vulns | M N | NOT APPLICABLE | no publicly known (CVE) vulnerability in project results was fixed in a release. Dependency CVEs are excluded by the criterion ("applies only to the project results"), e.g. CVE-2026-25537 in the Gateway's jsonwebtoken dependency, source-only. Details: "If there … have been no publicly known vulnerabilities, choose N/A" | — |
| 23 | report_process | M u | SATISFIED | GitHub issue tracker; contributing §Reporting bugs; README | — |
| 24 | report_tracker | S | SATISFIED | GitHub Issues enabled | — |
| 25 | report_responses | M | LIKELY SATISFIED | **0 issues ever** [GH], so there is nothing to acknowledge. N/A is not allowed for this criterion; "Met" with justification "no bug reports received" | human attestation |
| 26 | enhancement_responses | S | LIKELY SATISFIED | 0 enhancement requests (vacuous) | human attestation |
| 27 | report_archive | M u | SATISFIED | public GitHub issue/PR archive | — |
| 28 | vulnerability_report_process | M u | SATISFIED | `SECURITY.md` (GitHub private vulnerability reporting); README + contributing link it | — |
| 29 | vulnerability_report_private | M N u | SATISFIED | `SECURITY.md` steps to `…/security/advisories/new`; PVR `enabled: true` [GH] | — |
| 30 | vulnerability_report_response | M N | NOT APPLICABLE | 0 repository security advisories/reports [GH]. Details: "If there have been no vulnerabilities reported in the last 6 months, choose N/A" | — |
| 31 | build | M N | SATISFIED | `cargo build` (README §Build; RELEASE.md steps 5–6) | — |
| 32 | build_common_tools | G N | SATISFIED | Cargo | — |
| 33 | build_floss_tools | S N | SATISFIED | Rust toolchain, OpenSSL, libssh2: all FLOSS | — |
| 34 | test | M | SATISFIED | Rust test suites (root + gateway) and Python installer/checker tests; how to run: contributing §Quality gates, README §Testing, RELEASE.md step 4, `ci.yml` | — |
| 35 | test_invocation | S | SATISFIED | `cargo test` | — |
| 36 | test_most | G | UNVERIFIED | coverage is not measured | consider (answer "unmet" is allowed) |
| 37 | test_continuous_integration | G | SATISFIED | `ci.yml` on every push/PR runs automated tests (gateway 198, installer 18, checker 72), builds all root test binaries, and runs fmt/clippy. The root runtime suite runs at the release gate (Option C). The criterion asks for CI running automated tests, not every test (§M) | — |
| 38 | test_policy | M | SATISFIED | contributing: "include tests for any change in behavior" | — |
| 39 | tests_are_added | M | SATISFIED | recent behaviour-changing commits all added or changed tests (`a0f9d98`, `bd1783d`, `9ec4d1c`, `54b242b`, `543b238`, …) | — |
| 40 | tests_documented_added | G | SATISFIED | same contributing sentence, in the change-proposal instructions | — |
| 41 | warnings | M N | SATISFIED | `cargo clippy --locked --all-targets --all-features -- -D warnings` (root + gateway) in `ci.yml` and the pinned release gate | — |
| 42 | warnings_fixed | M N | SATISFIED | `-D warnings` makes any warning fail CI and the gate; the latest runs are green | — |
| 43 | warnings_strict | G N | LIKELY SATISFIED | all warnings denied; no `pedantic`/`nursery` groups, no `[lints]` table | maintainer judgement |
| 44 | know_secure_design | M | LIKELY SATISFIED | human attestation. Evidence of practice: README §Security and safety properties, DESIGN.md, the fail-closed trust boundary (`check_trusted_parents`), plan/apply separation, known_hosts-only SSH, WP-S | maintainer attests |
| 45 | know_common_errors | M | LIKELY SATISFIED | human attestation. Evidence: exact argv without shell, NUL rejection, symlink/parent trust checks, sensitive redaction, OAuth/JWT hardening | maintainer attests |
| 46 | crypto_published | M N | SATISFIED | only standard published algorithms: SSH via libssh2/OpenSSL, SHA-256, JWT RS256/ES256 via aws-lc-rs, TLS via rustls | — |
| 47 | crypto_call | S N | SATISFIED | uses crypto libraries (libssh2/OpenSSL, sha2, aws-lc-rs, rustls); implements none | — |
| 48 | crypto_floss | M N | SATISFIED | all crypto dependencies are FLOSS | — |
| 49 | **crypto_keylength** | **M N** | **PARTIAL** | Against supported modern targets the negotiated default is strong (curve25519/ECDH first). But the default offer still includes **`diffie-hellman-group1-sha1` (1024-bit)** [ART strings, bundled libssh2 1.11.1 `kex.c`], and **no option exists to disable smaller key lengths** (only `MethodType::HostKey` is set, `src/executor.rs:1407-1415`). The criterion's second MUST ("possible to configure … completely disabled") is unmet | **SMALL CODE/TEST** (§X) |
| 50 | **crypto_working** | **M N** | **PARTIAL** | Defaults do not *need* broken algorithms (strong ones are preferred and negotiated with supported targets). But broken ones are **enabled by default** as fallbacks: `hmac-md5`, `arcfour`/`arcfour128` (RC4), blowfish/cast/3des-cbc [ART strings; libssh2 `crypt.c`/`mac.c`]. RC4/blowfish/CAST likely fail at runtime under OpenSSL 3's default provider (UNVERIFIED); MD5-HMAC is usable. The details allow broken mechanisms only when users opt in through configuration | **SMALL CODE/TEST** (§X) |
| 51 | crypto_weaknesses | S N | NOT SATISFIED | SHA-1 (`hmac-sha1`, `*-sha1` kex) and **CBC in SSH** are in the default offer, the criterion's own examples. As a SHOULD it could be answered "unmet with rationale", but the same fix resolves it | fix with #49/#50 |
| 52 | crypto_pfs | S N | SATISFIED | every SSH kex method is ephemeral (EC)DH; rustls TLS 1.2/1.3 uses ECDHE | — |
| 53 | crypto_password_storage | M N | NOT APPLICABLE | no inbound password authentication. The CLI uses SSH keys/agent and passwordless `sudo -n`. The Gateway delegates user auth to an external OAuth AS; its controller credentials are 256-bit CSPRNG secrets stored as SHA-256 verifiers (`gateway/src/auth.rs:30,43`), not passwords | — |
| 54 | crypto_random | M N | SATISFIED | SSH session keys and nonces come from libssh2/OpenSSL CSPRNG. Gateway secrets use `getrandom` (OS CSPRNG, `auth.rs:30`, `mcp.rs:241`); the one ignored `getrandom` result is backoff jitter only (`bridge.rs:579`). The CLI generates no keys itself | — |
| 55 | delivery_mitm | M | SATISFIED | GitHub Releases over HTTPS; `install.sh` forces `--proto '=https' --proto-redir '=https'`; SSH host keys are verified strictly against known_hosts | — |
| 56 | delivery_unsigned | M | SATISFIED | the installer fetches `SHA256SUMS` over **HTTPS only** and verifies the archive and the installed executable (`install.sh:22,35,45,59,95,98`). No hash is fetched over http | — |
| 57 | vulnerabilities_fixed_60_days | M | LIKELY SATISFIED | Today, OSV (GHSA + RustSec) over both lockfiles finds only RUSTSEC-2023-0071 (`rsa`), which is test-only, outside every built artifact and guarded by CI. Dependabot: 0 alerts. **History:** CVE-2026-25537 (medium; public 2026-02-03) sat in the Gateway's dependency until the source fix `525a23d` (2026-09-29). The Gateway is source-only and not released; its only deployment is stopped and guarded. "Patched **and released**" is ambiguous for a source-only component | maintainer justification |
| 58 | vulnerabilities_critical_fixed | S | SATISFIED | no critical vulnerabilities known | — |
| 59 | no_leaked_credentials | M | LIKELY SATISFIED | secret scanning (full history) **0 alerts**; push protection enabled [GH]. Absence cannot be proven outright | — |
| 60 | static_analysis | M N j | LIKELY SATISFIED | clippy (a separate FLOSS lint/analysis tool) runs before every release: pinned `root-clippy`/`gateway-clippy` steps, required by the acceptance checker; also on every push. The details exclude only compiler warnings and "safe" modes, and list linters such as `lintr` among the examples. Whether clippy counts is a **reviewer judgement** | justification text |
| 61 | static_analysis_common_vulnerabilities | G N | NOT SATISFIED | clippy has few security-focused rules; no security SAST | consider; "unmet" allowed |
| 62 | static_analysis_fixed | M N | SATISFIED | clippy findings cannot land (`-D warnings`); no exploitable static-analysis finding is open | — |
| 63 | static_analysis_often | G N | SATISFIED | clippy on every push and PR (`ci.yml`) | — |
| 64 | dynamic_analysis | G | NOT SATISFIED | no fuzzing and no measured branch coverage (the details require a fuzzer or an 80% branch-coverage suite) | consider; "unmet" allowed |
| 65 | dynamic_analysis_unsafe | G N | NOT APPLICABLE | the project's code is Rust (memory-safe; `unsafe` only in 8 small libc call sites); C dependencies are not the project's software | — |
| 66 | dynamic_analysis_enable_assertions | G | LIKELY SATISFIED | tests run in the dev profile (debug assertions and overflow checks on) | maintainer judgement |
| 67 | dynamic_analysis_fixed | M N | NOT APPLICABLE | no dynamic-analysis tool in the criterion's sense is applied, so there are no findings | — |
| — | homepage_url (implied) | M | SATISFIED | `https://sinter.fulltrust.co.jp/` (README line 5). The GitHub repo "homepage" field is empty (cosmetic) | optional: set the field |

**Counts: 46 SATISFIED · 10 LIKELY SATISFIED · 2 PARTIAL · 3 NOT SATISFIED · 5 NOT APPLICABLE · 1 UNVERIFIED = 67.** The implied `homepage_url` is not counted.

## G. Already satisfied / free wins

Without any new engineering, Sinter already meets:
- basics, licensing, documentation and HTTPS: 1–14;
- repository and versioning: 14–21;
- the reporting process, including the WP-M private reporting (`SECURITY.md` + PVR): 23–30;
- build and tests: 31–42;
- secure delivery (the installer's HTTPS-only fetch and SHA256SUMS verification): 55–56;
- most crypto: 46–48, 52–54;
- static-analysis cadence: 62–63.

Contributions of recent work:
- **WP-N** supplies the CI evidence: tests, warnings, static-analysis cadence, and dependency monitoring (the latter is a Silver criterion; see §W).
- **WP-S** supplies the vulnerability-handling record.
- **WP-M** supplies the security policy.

About 56 of 67 criteria are met or likely met today.

## H. Partial criteria

- `crypto_keylength` (M): the 1024-bit DH fallback is enabled by default, and nothing can disable it.
- `crypto_working` (M): MD5-HMAC and RC4 (plus blowfish/CAST) are enabled by default as fallbacks.

Both come from libssh2's default method lists, which Sinter does not restrict. See §T for the mechanism and §X for the fix.

## I. Not satisfied

| Criterion | Req | Blocker? |
|---|---|---|
| crypto_weaknesses | SHOULD | No: may be "unmet" with rationale. The §X fix removes it anyway |
| static_analysis_common_vulnerabilities | SUGGESTED | No |
| dynamic_analysis | SUGGESTED | No |

## J. Not applicable

`release_notes_vulns`, `vulnerability_report_response`, `crypto_password_storage`, `dynamic_analysis_unsafe`, `dynamic_analysis_fixed`. Each is justified in §F from the criterion's own details.

## K. Unverified

`test_most` (SUGGESTED): coverage has never been measured. Answering "unmet" is allowed.

## L. GitHub settings evidence (read-only)

| Setting | State |
|---|---|
| visibility, issues | public; issues on; discussions off; wiki/projects on |
| Private vulnerability reporting | enabled |
| Secret scanning / push protection | enabled / enabled; 0 alerts |
| Dependency graph / Dependabot alerts | on / on (0 open alerts) |
| Dependabot security updates / version updates | off / not configured |
| CodeQL | default setup `not-configured` |
| Ruleset 24173917 | active on main: `deletion`, `non_fast_forward`, no bypass; no branch protection (direct pushes allowed by policy) |
| Actions | default token `read`; `sha_pinning_required: false` |
| Repository advisories | 0 |
| description / topics / homepage field | set / set / **empty** |

## M. CI / testing assessment

- **Per commit** (`ci.yml`, GitHub-hosted, runner guard):
  - root fmt and clippy;
  - **all 24 root test binaries built, not run**;
  - installer tests (18) and release-checker tests (72);
  - gateway fmt and clippy;
  - explicit root build, then gateway tests (198).
- **Also per commit** (`advisories.yml`): the OSV scan and the rsa graph guard.
- **Release acceptance** (RELEASE.md step 4, checker-enforced since `543b238`): the **full root runtime suite** on a dedicated, disposable Linux x86_64 host, with complete per-harness evidence.
- **Passing's testing criteria** (`test`, `test_invocation`, `test_policy`, `tests_are_added`, `tests_documented_added`) are met.
- `test_continuous_integration` (SUGGESTED) is met in its own terms: CI with automated tests. It does not claim every test runs per commit.
- Silver's `automated_integration_testing` ("an automated test suite … on each check-in") is plausibly met by the per-commit gateway, installer and checker suites. This is a preview judgement only.

## N. Security reporting assessment

`SECURITY.md` covers what the criteria need:
- a published process (28);
- a private channel with how-to (29, PVR, no email needed; the criteria do not require an email address);
- a disclosure expectation;
- best-effort response ("without a fixed response time").

Passing only requires the actual first response in the last 6 months to be ≤ 14 days, which is N/A with zero reports. A documented response process becomes a Silver MUST (`vulnerability_response_process`); the current text partially covers it. The Gateway's release/supported-version gap noted during WP-S is not a Passing criterion.

## O. Dependency / vulnerability monitoring assessment

- **Mechanisms:**
  - OSV Scanner 2.6.0 (pinned, digest-verified) over both lockfiles on push, PR, dispatch and weekly;
  - a documented, expiring RUSTSEC-2023-0071 exception with an independent production-graph guard;
  - Dependabot alerts (GHSA; Cargo, npm, Actions);
  - committed `Cargo.lock` files.
- No cargo-audit, and none is needed.
- At Passing this supports `vulnerabilities_fixed_60_days` (current state LIKELY SATISFIED; see the history note) and `vulnerabilities_critical_fixed`.
- `dependency_monitoring` is a **Silver** MUST and would already be met.

## P. Release-process assessment

RELEASE.md provides:
- a pinned-command Linux gate (now with complete root-test evidence);
- build-once / freeze;
- 8-target acceptance;
- SHA-256 checksums and an acceptance evidence bundle;
- a checker and human review.

Releases carry curated notes. Passing's release criteria (18–22) are met.

- **Reproducible builds:** not claimed for the CLI. WP-S demonstrated bit-identical Gateway Linux builds across two runs only.
- **Signed releases:** none (a Silver MUST).

## Q. Licensing assessment

- `MIT OR Apache-2.0`; OSI-approved; license texts at the top level.
- **Passing does not require per-file headers**; those are Gold only.
- The one question is `license_location`'s naming convention (LIKELY SATISFIED).
- GitHub's detector reports only Apache-2.0. This is cosmetic, but a top-level `LICENSE` pointer would also improve how the dual license is shown.

## R. Contribution / governance assessment

- Passing needs the contribution process and requirements (3–4), both met on the docs site.
- A root `CONTRIBUTING.md` pointer is optional. It helps the autofill detective and GitHub's UI.
- No governance, code-of-conduct or roles criteria apply at Passing. They are **Silver** MUSTs (`governance`, `code_of_conduct`, `roles_responsibilities`).

## S. Documentation assessment

User documentation (README, docs site, CLI/recipe/MCP references, security properties, install guide) meets 1–2 and 8–9. Internal audit reports are untracked and are **not** relied on as public documentation.

## T. Secure-development criteria assessment

**Secure design is demonstrable from source and docs:**
- plan/apply/audit separation (plan cannot mutate);
- strict known_hosts-only SSH;
- exact argv with no shell;
- a fail-closed parent-path trust boundary (it correctly refused GitHub's ACL'd `/home` during WP-N);
- sensitive-value redaction;
- Gateway OAuth resource-server hardening.

**SSH crypto defaults (the one real gap)** [REPO + ART]:
- `src/executor.rs` sets `method_pref` only for `MethodType::HostKey`, to the key types in known_hosts.
- Key exchange, ciphers and MACs are libssh2's built-in defaults. The bundled libssh2-sys 0.3.3 is libssh2 1.11.1_DEV.
- Its client offer, strongest first:
  - **kex**: curve25519, ECDH, DH-SHA2 groups, then `group14-sha1`, **`group1-sha1`**, `gex-sha1`;
  - **ciphers**: chacha20-poly1305, AES-GCM, AES-CTR, then AES-CBC, **blowfish-cbc, arcfour, arcfour128, cast128-cbc, 3des-cbc**;
  - **MACs**: HMAC-SHA2(-etm), then **hmac-sha1**, hmac-sha1-96, **hmac-md5**, hmac-md5-96, ripemd160.
- The published v1.1.1 binary contains these names and links the target's `libssl.so.3`/`libcrypto.so.3` dynamically.
- Against supported targets (modern OpenSSH on Ubuntu 24.04/26.04 and RHEL-family 9/10) strong algorithms are negotiated.
- However, a server offering only legacy algorithms would be accepted, and an operator cannot turn the legacy ones off.

## U. Badge / enrollment mechanics

- **What Sinter could display once qualified:** the OpenSSF Best Practices **"passing"** metal badge, `https://www.bestpractices.dev/projects/<ID>/badge` (JSON at `…/<ID>/badge.json`, field `badge_level`).
- **Before qualifying**, the same image shows **"in progress NN%"**, and entries and percentages are **public**.
- The Baseline series is a separate image (`/projects/<ID>/baseline`) and optional.
- Silver requires the passing badge first; gold requires silver.
- No expiry exists, but a badge can be lost after criteria updates.

## V. Privacy / account implications (human decision required)

Creating an entry needs a **login via GitHub OAuth or a local account** (sign-up is automatic with GitHub). Once created:
- **the entry is public**;
- the badge-entry **owner's name (as provided to GitHub) and GitHub nickname are shown publicly**, along with the username of whoever last edited it;
- **email is kept private** (administrators only).

Other points:
- Anyone with commit access to the GitHub repo can edit the entry.
- Entries can be deleted, with a written rationale.
- Content is under CDLA-Permissive-2.0.
- The privacy policy and terms are the Linux Foundation's (`linuxfoundation.org/privacy`, `/terms`).
- **Enrollment itself is an owner action.** It exposes the maintainer identity and an in-progress percentage, so do it only when ready.

## W. Higher-level preview (lightweight)

**Silver (55)**
- **Already met or close:**
  - `dependency_monitoring`, `external_dependencies` (lockfiles);
  - `automated_integration_testing` (plausibly);
  - `coding_standards_enforced` (rustfmt/clippy in CI);
  - `documentation_security` (README security properties + SECURITY.md);
  - `documentation_quick_start`, `documentation_architecture` (DESIGN.md), `documentation_roadmap` (GOALS.md; unconfirmed);
  - `report_tracker`, `installation_common` (installer).
  - After the §X fix: `crypto_weaknesses` (a Silver MUST), `crypto_certificate_verification` (rustls/reqwest defaults, unverified).
- **Obvious gaps:**
  - `governance`, `code_of_conduct`, `roles_responsibilities` (docs);
  - `access_continuity` / `bus_factor` (a single maintainer: a real organisational gap);
  - `signed_releases` (process);
  - `test_statement_coverage80` (unmeasured);
  - `static_analysis_common_vulnerabilities` (MUST at Silver; would need a security-rule SAST);
  - `assurance_case`, `dco`, `vulnerability_report_credit`/`vulnerability_response_process` wording;
  - `build_repeatable`.

**Gold (23): expensive for a single-maintainer project.** `two_person_review`, `contributors_unassociated`, `bus_factor` ≥ 2, `require_2FA` evidence, per-file copyright/license headers, 90% statement / 80% branch coverage, `build_reproducible`, `security_review`, `hardened_site`, and mandatory `dynamic_analysis`.

**Baseline series:** not assessed here. The WP-N research found that OSPS-AC-03.01 (baseline-1: prevent direct commits to the primary branch) conflicts with Sinter's deliberate direct-push policy. Re-verify before choosing that series.

## X. Minimal truthful remediation path to Passing

1. **SSH algorithm hardening** (SMALL CODE/TEST; WORTH DOING ANYWAY).
   - In the SSH session setup, set libssh2 `method_pref` for `Kex`, `CryptCs`/`CryptSc` and `MacCs`/`MacSc` to a modern allowlist:
     - kex: curve25519-sha256, ecdh-sha2-nistp256/384/521, DH group16/18-sha512 and group14-sha256;
     - ciphers: chacha20-poly1305, aes256/128-gcm, aes256/192/128-ctr;
     - MACs: hmac-sha2-256/512 (+etm).
   - Review whether the host-key preference can still select SHA-1 `ssh-rsa` for RSA known_hosts entries; prefer rsa-sha2-256/512.
   - Add tests.
   - Supported targets (OpenSSH on Ubuntu 24.04/26.04, RHEL-family 9/10) support this set. Confirm through the existing 8-target acceptance.
   - This closes `crypto_working`, `crypto_keylength` (legacy groups become completely disabled) and `crypto_weaknesses`.
2. **Ship it in the next release** (PROCESS: the existing release gate and acceptance; no new process). Until a release carries it, the claim does not hold for released software.
3. **Evidence entry at enrollment** (EVIDENCE ONLY), using §F's evidence and URLs:
   - justifications for `static_analysis` (clippy before release), `vulnerabilities_fixed_60_days` (current state + history), `license_location`, `report_responses` (no reports yet);
   - human attestations for `know_secure_design` / `know_common_errors`;
   - honest "unmet" answers for the SUGGESTED items (`test_most`, `dynamic_analysis`, `static_analysis_common_vulnerabilities`).
4. **Optional cheap improvements** (DOCS/SETTINGS; LOW-to-MODERATE value):
   - a root `CONTRIBUTING.md` pointer to the docs page (helps autofill and GitHub UI);
   - a top-level `LICENSE` stating the dual license (fixes GitHub's single-license display);
   - set the repository "homepage" field.

   None of these is required.
5. **Owner action:** create the bestpractices.dev entry (GitHub login; public identity) only when ready.

## Y. Cost / value classification

| Gap | Cost class | Value |
|---|---|---|
| crypto_working / crypto_keylength / crypto_weaknesses (SSH defaults) | SMALL CODE/TEST + PROCESS (next release) | **WORTH DOING ANYWAY** (removes MD5/RC4/1024-bit-DH fallbacks from a root-capable SSH tool) |
| static_analysis justification | EVIDENCE ONLY | badge-only |
| license_location / GitHub license display | DOCS ONLY (optional `LICENSE`) | UNCLEAR (small user value) |
| root CONTRIBUTING.md pointer | DOCS ONLY | BADGE-ONLY / LOW |
| repo homepage field | GITHUB SETTING | LOW |
| test_most / dynamic_analysis (fuzzing, coverage) | CI CHANGE / SMALL CODE | UNCLEAR (useful later; not needed for Passing) |
| static_analysis_common_vulnerabilities (security SAST) | CI CHANGE | UNCLEAR; not needed for Passing |
| know_* attestations, report_responses | EVIDENCE ONLY | badge-only |

## Z. Recommendation and next step

**WAIT.** There is exactly one engineering prerequisite, and it is worth doing without any badge.

1. **Next step:** a small, separately scoped WP to harden Sinter's SSH algorithm defaults (§X-1), with tests.
2. Ship it through the existing release gate and 8-target acceptance, as v1.1.2 or with the next planned release.
3. Then the Passing badge is mostly evidence entry. Enrollment needs the owner's GitHub login and public identity.

Scheduling relative to the MCP / ChatGPT plugin investigation:
- The SSH hardening is small in code (one function plus tests), but it needs a release cycle to count.
- The badge itself does not block MCP research, and MCP research does not block the badge.
- Suggested order:
  - run the hardening WP before or alongside the MCP research;
  - let the next release carry it;
  - enroll afterwards.
- No new workflows, Scorecard or CodeQL are needed for Passing.

---

OPENSSF FIRST-BADGE ASSESSMENT:
WAIT

CURRENT POSITION:
Of the 67 Passing criteria: 46 SATISFIED, 10 LIKELY SATISFIED, 5 NOT APPLICABLE, 1 UNVERIFIED (SUGGESTED), 3 NOT SATISFIED (1 SHOULD, 2 SUGGESTED, all answerable as "unmet"), and 2 PARTIAL MUST criteria from one SSH-defaults finding.

FIRST-BADGE BLOCKERS:
2: crypto_working (MUST), crypto_keylength (MUST). Both come from libssh2's default kex/cipher/MAC offer (MD5, RC4, 1024-bit DH fallbacks), which cannot be disabled.

ESTIMATED REMEDIATION:
SMALL CODE/TEST (SSH method allowlist + tests) + PROCESS (ship in the next release via the existing gate) + EVIDENCE ONLY (justifications and attestations at enrollment). Optional DOCS/SETTINGS polish.

REPOSITORY MUTATED:
NO

REPORT:
OPENSSF_BEST_PRACTICES_GAP_ASSESSMENT_2026-09-30.md
