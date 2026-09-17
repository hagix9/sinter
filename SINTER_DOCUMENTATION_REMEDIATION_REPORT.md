# Sinter Documentation Remediation Report

## Executive Summary

**Verdict: COMPLETE.**

All 13 findings (F-01 … F-13) from `SINTER_DOCUMENTATION_CONTENT_AUDIT.md` have been
remediated in both the English and Japanese documentation trees. Validation is green:

- Astro build + `astro check`: 0 errors / 0 warnings / 0 hints
- 52 built documentation pages (51 baseline + 1 new WebMCP page per locale)
- 1,764 internal links checked, 0 missing
- Pagefind indexes built for `en` and `ja`
- WebMCP payloads (`en`/`ja`) internally consistent at v0.2.1 with correct v0.2.1 artifact names
- Rust suite: **270 passed / 0 failed** (`cargo test --release --locked`), no regression

**The F-01 First Recipe has now passed live acceptance on BOTH supported targets** —
a real Ubuntu 24.04 LTS target and a real Rocky Linux 9.8 target — each executing the
exact documented recipe through the documented CLI sequence
validate → plan → apply → apply → final plan, with the documented outcomes (first
apply creates/changes `/etc/sinter-motd`; second apply and final plan are idempotent
with `0 changed`; plan never mutates). Raw transcripts of the Rocky 9 run are
preserved in `/tmp/f01_rocky9_acceptance/`.

Caveat (recorded honestly, non-blocking): both live targets were aarch64, and the
controller used a locally built v0.2.1 binary from the release tag (`sinter 0.2.1`,
commit `26720b6`) rather than the published x86_64 artifacts, which cannot execute on
aarch64 targets. The exercised code paths are the release's; see Remaining Risks.

## Findings Status

| ID | Severity | Status | Explanation |
|----|----------|--------|-------------|
| F-01 | BLOCKER | **FIXED** | First Recipe rewritten (EN+JA): template to `/etc/sinter-motd` (absent by default on both supported targets), no systemd unit dependency, no handlers in the walkthrough. Executed successfully on real Ubuntu 24.04 and Rocky Linux 9.8 targets through the documented CLI. The optional "Adding a service" snippet uses `when: "facts.os.family == 'debian'"` with `name: ssh` (valid on Ubuntu) and points Rocky users at `sshd`, with the cross-distribution unit-name caveat stated explicitly. The snippet was assembled and validated with the v0.2.1 binary (`validate` exit 0). |
| F-02 | HIGH | **FIXED** | All current-release installation references updated v0.2.0 → v0.2.1: download URLs, tarball names, `SHA256SUMS` step, expected `sinter --version` output (`sinter 0.2.1`), WebMCP installation metadata. Remaining `v0.2.0` occurrences are historical (see Version Alignment). |
| F-03 | HIGH | **FIXED** | Handler `service:` documented as the **systemd unit name on the target** (EN+JA Concepts/Recipes). Re-verified against v0.2.1 first: `handler_service()` passes the field verbatim to `systemctl`; the audit's "resource id or unit name" claim was confirmed wrong and the false rule removed. |
| F-04 | MEDIUM | **FIXED** | New "Reading plan / apply output" section in CLI Reference (EN+JA): header lines, `target facts:` line, one status line per resource, and a status legend (`ok`, `CHANGED`, `POSSIBLE`, `FAILED`, `INDET`, `skip`, `guard`, `blocked`, `?`) plus `known/unknown` prefix, handlers/pending-handlers trailers, and quick answers. Every legend entry was cross-checked against the actual v0.2.1 output code (`src/output.rs`) **and** against live output captured during the F-01 run (headers, `target facts:`, `CHANGED`, `ok`, summary, `status:` all match verbatim). No invented sample output: the sample shown is the format of real captured output. |
| F-05 | MEDIUM | **FIXED** | Installation pages now state the controller/target distinction explicitly: released tarballs are Linux artifacts covering the supported managed targets; macOS controller use means building from source; Linux artifacts must not be expected to run natively on macOS. No support-contract expansion. |
| F-06 | MEDIUM | **FIXED** | SSH behavior documented (EN+JA): `--host/--port/--user/--known-hosts/--identity` flags (verified against `src/main.rs`), user-authentication vs host-identity (known_hosts) distinction, public key must already be authorized on the target, and a new Troubleshooting entry for authentication failures. The documented flow was exercised live during F-01 (identity file + known_hosts + host-key verification succeeded against a real target). |
| F-07 | MEDIUM | **FIXED** | Version stamping aligned to v0.2.1 everywhere current-release semantics are intended; every remaining `v0.2.0` string triaged and documented below. |
| F-08 | MEDIUM | **FIXED** | "Targeting model" section added to What is Sinter? (EN+JA): one `plan`/`apply` invocation targets **one host**; omit `--host` for local execution; `--host` selects a remote target; v0.2.1 has **no** inventory/multi-host orchestration layer; orchestrate externally if needed. Flag names match the actual CLI (`--host` singular; no `--hosts` invented). Linked from the SSH/CLI documentation. |
| F-09 | MEDIUM | **FIXED** | (a) `build-webmcp.ts` now emits the v0.2.1 artifact names, so the payload no longer mixes v0.2.0 artifacts with a v0.2.1 version (verified in built `dist/webmcp/{en,ja}.json`). (b) New "Documentation WebMCP" reference page (EN+JA) added to the Reference sidebar: what it is, read-only docs-lookup tools (`sinter_search_docs`, `sinter_list_resources`, `sinter_get_resource`, `sinter_get_compatibility`, `sinter_get_installation`), EN/JA locale behavior, browser/client requirement, fallback to the normal site, and an explicit statement that it does **not** execute Sinter (future runtime WebMCP labeled as future, one sentence). |
| F-10 | LOW | **FIXED** | Loop instance addressing documented (EN+JA Concepts/Resources): loop-expanded instances are addressable by dependencies using the documented `id[index]` form (verified against v0.2.1 engine/IR handling before documenting), with a small example. |
| F-11 | LOW | **FIXED** | `file.source` resolution documented as **recipe-relative** (EN+JA file resource page and First Recipe). Verified live: the controller resolved `templates/greeting` relative to the recipe file during the F-01 acceptance run. |
| F-12 | LOW | **FIXED** | Installation polish (EN+JA): where to place the binary for PATH access, curl availability note for the documented commands. No installer invented; no package-manager method invented. |
| F-13 | LOW | **FIXED** | Include resolution semantics documented concisely (EN+JA Concepts/Recipes): relative-to-including-file and absolute path behavior as implemented in v0.2.1. Duplicate/cycle behavior not documented (not verified as useful/user-facing in v0.2.1). |

No finding was reclassified as INVALID: every runtime semantic asserted by the audit
was re-verified against the v0.2.1 checkout (HEAD == tag `v0.2.1`) before documenting.

## Files Changed

All paths relative to repository root. 30 documentation files modified, 2 added;
`opencode.json` was **not** touched by this task (its working-tree change pre-dates it).

Modified (EN — 12):
- `docs-site/src/content/docs/en/getting-started/what-is-sinter.md` — F-08 targeting-model section
- `docs-site/src/content/docs/en/getting-started/installation.md` — F-02/F-05/F-07/F-12
- `docs-site/src/content/docs/en/getting-started/first-recipe.md` — F-01 rewrite
- `docs-site/src/content/docs/en/concepts/recipes.md` — F-03 handler semantics, F-13 includes
- `docs-site/src/content/docs/en/concepts/resources.md` — F-10 loops, version stamp
- `docs-site/src/content/docs/en/reference/cli.md` — F-04 output legend
- `docs-site/src/content/docs/en/reference/resources.md` — F-07 version stamp
- `docs-site/src/content/docs/en/reference/resources/file.md` — F-11 `file.source` resolution
- `docs-site/src/content/docs/en/troubleshooting.md` — F-06 SSH auth entry
- `docs-site/src/content/docs/en/compatibility/platforms.md` — F-07 version stamp
- `docs-site/src/content/docs/en/guides/ubuntu.md` — F-07 version stamp
- `docs-site/src/content/docs/en/recipes/overview.md` — F-07 version stamp

Modified (JA — 12): exact mirrors of the EN pages above under
`docs-site/src/content/docs/ja/…`.

Modified (build/data — 4):
- `docs-site/astro.config.mjs` — sidebar entry for the new WebMCP page (both locales)
- `docs-site/src/data/build-webmcp.ts` — v0.2.1 artifact names (F-09a)
- `docs-site/src/data/doc-index.json` / `doc-index.ja.json` — WebMCP page registration + version stamp

Added (2):
- `docs-site/src/content/docs/en/reference/webmcp.md`
- `docs-site/src/content/docs/ja/reference/webmcp.md`

Not modified (confirmed by diff): `src/**`, `tests/**`, `Cargo.*`, CI, release files,
`opencode.json` (pre-existing unrelated change left untouched), release artifacts.

## F-01 First Recipe Evidence

### Old failure mechanism
The audited recipe ran a `service` handler with `service: motd` —
`handler_service()` in v0.2.1 passes that string verbatim to
`systemctl restart motd`, a unit that exists on neither supported target — and its
`file` resource targeted `/etc/motd`, which stock Ubuntu 24.04 does not ship as a
regular file (base-files 13ubuntu10 does not contain it; Ubuntu's update-motd(5)
describes it as typically a symlink to `/run/motd.dynamic`) and Sinter refuses to
manage symlinked paths. Every documented run failed on both targets despite the page
promising success.

### Corrected recipe design
One `template` resource rendering `{{ vars.greeting }}` into `/etc/sinter-motd`
(mode 0644), with `vars` and a controller-side template source. Deliberately:

- `/etc/sinter-motd` exists in **no** package on either target (checked against the
  Ubuntu noble base-files data.tar and the Rocky 9 `setup` rpm contents), so the
  first apply is deterministic and the path is free of platform-specific semantics.
- No systemd unit, no handler, no package, no distro-conditional logic in the
  walkthrough itself — nothing unit-named to diverge between Ubuntu/Rocky.
- The optional "Adding a service" snippet keeps pedagogical coverage of services and
  handles the ssh/sshd split with the documented `when` fact expression instead of a
  fake unit.

### Why it is valid on Ubuntu 24.04
**Proven by live execution.** Target: Lima VM, `Ubuntu 24.04.3 LTS (Noble Numbat)`,
aarch64, passwordless sudo, SSH key auth. The recipe touches only a template file at
a path with no Ubuntu package ownership and no symlink semantics.

### Why it is valid on Rocky Linux 9
**Proven by live execution.** Target: a Lima VM created from the official
Rocky-9-GenericCloud-Base-9.8 (20260525.0) aarch64 cloud image, passwordless sudo,
SSH key auth with strict host-key verification. Observed facts line:
`os=Rocky Linux family=redhat version=9.8 arch=aarch64`. The earlier (pre-live)
archive evidence also remains true: `/etc/sinter-motd` is absent from the Rocky 9
package set (`setup-2.13.7-10.el9.noarch.rpm` content list) and `/etc` is a trusted
parent on both families per the v0.2.1 target-filesystem trust rules; the recipe
uses no unit names, package managers, or platform conditionals.

### Validation performed
Using the locally built v0.2.1 binary (`sinter 0.2.1`), the exact documented recipe
(controller at `/tmp/f01_live`, target over SSH with `--known-hosts` and `--identity`):

| Step | Command form | Result |
|------|--------------|--------|
| validate | `sinter validate recipe.yaml` | `ok: 1 resource(s), 0 handler(s), 1 var(s)`, exit 0 |
| plan | `sinter plan --host … recipe.yaml` | facts line `os=Ubuntu family=debian version=24.04`; `CHANGED greeting [template] known/normal`, `current: absent`, `desired: 28 bytes`; `summary: 1 changed …`; `status: success`; exit 0; nothing created |
| apply #1 | `sinter apply --host … --sudo recipe.yaml` | `CHANGED greeting [template]`; `summary: 1 changed`; `status: success`; exit 0 |
| target state | `stat` on target | `regular file 644 root:root 28 bytes`; content exactly `hello — managed by sinter` |
| apply #2 | `sinter apply --host … --sudo recipe.yaml` | `ok greeting [template] … file already matches desired state`; `summary: 0 changed`; exit 0 |
| plan after | `sinter plan --host … recipe.yaml` | `0 changed` |

**Rocky Linux 9.8 run** (same documented recipe, extracted verbatim from the
documented page into `/tmp/f01_rocky9_acceptance/recipe`; target `127.0.0.1:62412`,
user `a0000`, Lima VM from the official Rocky 9.8 aarch64 cloud image; raw transcript
`/tmp/f01_rocky9_acceptance/02-acceptance-run.txt`):

| Step | Result |
|------|--------|
| validate | `ok: 1 resource(s), 0 handler(s), 1 var(s)`, exit 0 |
| plan before apply | facts `os=Rocky Linux family=redhat version=9.8 arch=aarch64`; `CHANGED greeting [template] known/normal`, `current: absent`, `desired: 28 bytes`; `summary: 1 changed …`; `status: success`; exit 0; `/etc/sinter-motd` verified still absent after plan (plan did not mutate) |
| apply #1 | `CHANGED greeting [template]`; `summary: 1 changed`; `status: success`; exit 0 |
| target state | `regular file 644 root:root 28 bytes`; content exactly `hello — managed by sinter` |
| apply #2 | `ok greeting [template] … file already matches desired state`; `summary: 0 changed`; `status: success`; exit 0 |
| final plan | `ok … file already matches desired state`; `summary: 0 changed`; `status: success`; exit 0 |

These outputs also directly validate the F-04 legend and F-06/F-08 documentation
(actual flags, actual status vocabulary, one-host-per-invocation model in use).

### Live cross-platform acceptance status
- **Ubuntu 24.04 LTS: live acceptance PERFORMED and PASSED** (validate/plan/apply/apply/plan).
- **Rocky Linux 9.8: live acceptance PERFORMED and PASSED** (validate/plan/apply/
  apply/final plan) on 2026-09-17, on a Lima VM built from the official Rocky 9.8
  aarch64 cloud image. (Earlier in the remediation, before that VM existed, no Rocky
  host was reachable and no container could be built; that gap is now closed.)

## v0.2.1 Version Alignment

Verified against the public GitHub release (v0.2.1 assets enumerated via the GitHub
API in the audit phase) and the built payloads:

- **Installation URLs / artifact names** (EN+JA Installation, WebMCP payloads):
  - `sinter-v0.2.1-ubuntu24.04-amd64.tar.gz`
  - `sinter-v0.2.1-rocky9-x86_64.tar.gz`
  - `SHA256SUMS`
- **Expected version output**: `sinter 0.2.1` (matches the local release build used for acceptance).
- **WebMCP installation release metadata**: both `dist/webmcp/en.json` and `dist/webmcp/ja.json`
  emit version `0.2.1` and the two v0.2.1 artifact names; no v0.2.0 artifact strings remain.
- **Remaining `v0.2.0` occurrences** (4, all legitimate history — classification B):
  - `en/guides/rocky-linux.md:6` + JA mirror: "Rocky Linux 9 x86_64 is supported **as of v0.2.0**" — historical support-contract statement.
  - `en/compatibility/platforms.md:14` + JA mirror: the reference acceptance environment used for **v0.2.0** target testing — historical record.
- `doc-index.json` / `doc-index.ja.json` no longer contain any `0.2.0` strings.

## SSH / Targeting / Output Documentation (F-04, F-06, F-08)

- **F-04**: compact output-format section with status legend in CLI Reference (EN+JA);
  every status verified against `src/output.rs` and live captured output. A reader can
  now answer: did anything change (`CHANGED` count in summary), did plan only observe
  (plan never mutates), did something fail (`FAILED`/`INDET`/exit status), was
  something skipped/blocked (`skip`/`guard`/`blocked`), and what a second idempotent
  apply looks like (`ok … already matches`, `0 changed`).
- **F-06**: credential selection and the host-identity vs user-authentication
  distinction documented with the real flags; "public key must already be authorized
  on the target" stated; Troubleshooting gained an SSH authentication-failure entry.
  Behavior verified against the v0.2.1 SSH implementation and exercised live.
- **F-08**: one-host-per-invocation model documented up front in What is Sinter?
  (EN+JA) with the real `--host` semantics; no inventory, groups, or `--hosts` invented.

## Documentation WebMCP

- New page location: `en/reference/webmcp.md` and `ja/reference/webmcp.md`; sidebar
  entry added under Reference for both locales.
- Tool list documented: `sinter_search_docs`, `sinter_list_resources`,
  `sinter_get_resource`, `sinter_get_compatibility`, `sinter_get_installation`.
- EN/JA behavior explained (locale-specific payload endpoints and page language).
- States explicitly: read-only documentation lookup only; does not execute Sinter;
  requires a compatible browser/client environment; unsupported environments should
  use the normal site. Future runtime WebMCP mentioned only as explicitly future.
- Release metadata consistency: payloads emit v0.2.1 artifacts matching the
  installation docs (verified in built output).
- Docs-only WebMCP confirmed: no runtime/core WebMCP implemented; no
  `docs-site/public/webmcp.js` behavior changed.

## EN / JA Parity

Modified page pairs (12 content pairs + WebMCP pair): all reviewed.

Automated structural comparison of every modified pair: fenced code-block counts
equal, recipe YAML key sequences equal, heading structure equal. The only textual
differences inside code blocks are translated inline comments (e.g. `# observe only`
/ `# 観測のみ`); every command, flag, URL, artifact name, YAML value, and warning is
byte-identical between EN and JA. Semantic parity: **no defects found**; prose was
written idiomatically in each language rather than translated literally.

## Validation Results

| Check | Command | Result |
|-------|---------|--------|
| Rust regression | `cargo test --release --locked` | **270 passed, 0 failed** (baseline 266; HEAD adds tests; Linux-gated suites run 0 on this macOS controller by design) |
| Docs build | `npm run build` (docs-site) | success, exit 0 (124 pre-existing legacy-redirect warnings, identical before/after) |
| Type/diagnostic check | `npx astro check` | 0 errors / 0 warnings / 0 hints |
| Page count | `find dist/{en,ja} -name index.html \| wc -l` | 52 (51 + new WebMCP page, consistent) |
| Internal links | script over built HTML (`/sinter/…` hrefs vs dist tree) | 1,764 checked, **0 missing** |
| Search index | `dist/pagefind/pagefind-entry.json` | languages `en`, `ja` indexed |
| WebMCP payload | inspection of `dist/webmcp/{en,ja}.json` | version 0.2.1; artifacts `sinter-v0.2.1-ubuntu24.04-amd64.tar.gz`, `sinter-v0.2.1-rocky9-x86_64.tar.gz` |
| Stale-version search | `rg -n 'v?0\.2\.0' docs-site/src` | only the 4 documented historical occurrences |
| F-01 recipe validate | `sinter validate recipe.yaml` | ok, exit 0 |
| F-01 recipe "when" snippet | assembled + `sinter validate` | ok, exit 0 |
| F-01 live acceptance (Ubuntu) | validate/plan/apply/apply/plan vs Ubuntu 24.04.3 target | all passed as documented (see F-01 table) |
| F-01 live acceptance (Rocky) | validate/plan/apply/apply/final plan vs Rocky Linux 9.8 target | all passed as documented; raw transcript in `/tmp/f01_rocky9_acceptance/` |

## Scope Integrity

- Runtime source changed: **NO**
- Runtime behavior changed: **NO**
- Ubuntu 26.04 support added/claimed: **NO**
- Rocky Linux 10 support added/claimed: **NO**
- curl installer implemented: **NO**
- Sinter runtime/core WebMCP implemented: **NO**
- opencode.json changed by this task: **NO** (pre-existing working-tree change left untouched; diff reviewed)
- Commit created: **NO**
- Push performed: **NO**
- Deployment performed: **NO**

Diff contains only `docs-site/**` changes plus the two new WebMCP pages. No
accidental `--hosts` flag, no invented installer, no unrelated cleanup or visual
redesign. Temporary validation artifacts live outside the repo (`/tmp/f01*`,
`/tmp/f01_harness`); nothing spurious was added to the tree.

## Remaining Risks / Validation Gaps

1. ~~Rocky Linux 9 live acceptance of the First Recipe is outstanding~~ **Closed on
   2026-09-17**: live validate/plan/apply/apply/final-plan passed on a real Rocky 9.8
   target (official 9.8 cloud image); see F-01 evidence.
2. Both live targets were aarch64; the released artifacts are x86_64 (ubuntu amd64,
   rocky x86_64). The recipe/doc claims exercised (recipe schema, SSH flow, template
   publish, idempotency, output format) are architecture-independent, but an x86_64
   run would remove even that caveat.
3. The acceptance controller used a locally built binary from the v0.2.1 tag
   (version string `sinter 0.2.1`, commit `26720b6`), not the published release
   artifact byte-for-byte. The published x86_64 artifacts cannot execute on aarch64
   targets, so the published-artifact path was not exercisable in this environment.

## Final Recommendation

The diff is **ready for human review and publication**. All documentation defects
from the audit are remediated with EN/JA parity, all available validations pass, and
the First Recipe is proven live on both supported targets (Ubuntu 24.04 LTS and
Rocky Linux 9.8). No known documentation BLOCKER remains. No commit, push, tag,
release, or deployment was performed while producing this report; work stops here
for human review.
