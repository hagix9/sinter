# Sinter Release Runbook

Operational procedure for cutting a Sinter release. Written so a human or a
coding agent can execute it top to bottom. Placeholders used throughout:

```sh
VERSION=0.4.0            # version being released (no "v" prefix)
TAG=v${VERSION}          # release tag
RC_COMMIT=<full hash>    # exact release-candidate commit
```

`RC_COMMIT` must always be a full 40-character commit hash, never a branch
name or short ref.

## Release state machine

```text
Development
    ↓
Implementation Complete
    ↓
Independent Audit / Remediation   (as needed)
    ↓
Phase A: Target Acceptance        → GO / NO-GO
    ↓
Phase B: Release Preparation      → metadata/docs-only commit
    ↓
Phase C: Final Release Check      → read-only GO / NO-GO
    ↓
Phase D: Artifact Staging         → human review package
    ↓
Human Review                      → explicit authorization
    ↓
Publish                           → tag + GitHub Release + assets
    ↓
Post-Publish Verification         → read-back checks
```

| Gate | Purpose | Allowed changes | Required evidence | GO condition | STOP / rollback |
|------|---------|-----------------|-------------------|--------------|-----------------|
| A. Target Acceptance | Prove the implementation works on each supported target | None — repository read-only | Real-target run log: platform detection, package/file/service/command, idempotency, failure truth, sensitive redaction, cleanup | All matrix rows PASS on every supported target | Any FAIL → NO-GO, fix in a new remediation round |
| B. Release Preparation | Package accepted code as a versioned candidate | Version fields, `Cargo.lock`, `CHANGELOG.md`, README platform docs — nothing else | Diff shows only release files; gates clean | All prep checks pass, single preparation commit | Unexpected diff → STOP, redo from accepted commit |
| C. Final Release Check | Verify RC = accepted code + correct metadata | None | Fresh build, `--version`, gates, lineage proof | All §C checks pass | Any failure → NO-GO back to B or remediation |
| D. Artifact Staging | Produce the exact publishable files | Nothing in repo; artifacts outside it | Baseline native build + source provenance, ABI inspection, exact artifact verification per target, checksums, manifest | All artifacts verified | Missing/incorrect artifact → NOT READY |
| Human Review | Human signs off | None | Reviewer checks manifest, notes, sums, tarballs | Explicit human approval | Any doubt → hold |
| Publish | Make it public | Remote refs + GitHub Release only | Read-back verification | §Publish checks pass | Partial failure → §Partial publish failure |
| Post-publish | Confirm what the world sees | None | Downloaded assets match staged checksums | All read-backs pass | Mismatch → incident, do not force-fix |

## Golden rule

**Acceptance evidence is only valid while production behavior is frozen.**

- `accepted commit → metadata/docs-only release prep → RC`: evidence
  inherited, no re-acceptance needed.
- `accepted commit → any src/ change → RC`: **re-acceptance required.** Never
  inherit old acceptance evidence across a production diff.

Release candidate commits that change `src/` or `tests/` after acceptance
void the previous GO.

## Phase A — Target Acceptance

Run once per supported target, on real machines (real OS, real architecture,
real SSH where applicable). FakeTarget/FakeExecutor coverage does not
substitute for target acceptance.

Minimum matrix per target:

- [ ] `cat /etc/os-release`, `uname -m`, toolchain/runtime versions recorded
- [ ] SSH connect + command exec + stdout/stderr/exit status
- [ ] `sudo -n` works
- [ ] Platform detected correctly (family, distro, backend — no fall-through)
- [ ] `type: package` `state: present` → install → independent verification
      (`rpm -q` / `dpkg -s`)
- [ ] Second present apply: no new mutation (idempotent)
- [ ] `state: absent` → remove → independent verification
- [ ] Second absent apply: idempotent
- [ ] Native package-manager output handled by production parsers
- [ ] file resource: create/update/mode/owner + idempotency
- [ ] service resource: enable/start, disable/stop + idempotency
- [ ] command resource: guard (`creates`) honored
- [ ] Pre-mutation failure reports failed, no false Changed, no mutation
- [ ] Sensitive values redacted in output/diffs/errors
- [ ] No residue after operations (temp dirs, snapshots)

Report ends with an explicit `GO` or `NO-GO`. Do not remediate during
acceptance — reproduce, preserve evidence, report, stop.

## Phase B — Release Preparation

After acceptance GO, prepare the candidate. Allowed changes **only**:

- `Cargo.toml` version → `${VERSION}`
- `Cargo.lock` regenerated consistently (`cargo check`)
- `CHANGELOG.md` new version entry (follow existing section conventions;
  keep claims inside implemented + accepted scope)
- `README.md` / `README.ja.md` supported-platform and version statements
- Other strictly necessary release metadata

Forbidden: production logic, tests (unless a metadata check truly requires
it), unrelated refactors, unrelated dirty files.

Preparation commit must be a direct/traceable descendant of the accepted
commit. Recommended message:

```text
Prepare Sinter v${VERSION} release
```

Stage explicitly (`git add CHANGELOG.md Cargo.toml Cargo.lock README.md
README.ja.md`), never `git add .` / `-A`; verify with
`git diff --cached --name-only` before committing.

## Phase C — Final Release Check

Read-only verification of the RC. Fix nothing in this phase — failures go
back to Phase B or remediation.

```sh
# Fixed state
git rev-parse HEAD                 # == RC_COMMIT
git status --short                 # only pre-existing unrelated dirty files
git tag --list                     # TAG must NOT exist yet

# Lineage
git merge-base --is-ancestor <ACCEPTED_COMMIT> HEAD
git diff --name-status <ACCEPTED_COMMIT>..HEAD    # release files only
git diff <ACCEPTED_COMMIT>..HEAD -- src/ tests/   # MUST be empty

# Version consistency
grep '^version' Cargo.toml                        # ${VERSION}
grep -A1 'name = "sinter"' Cargo.lock
cargo metadata --locked | jq '.packages[] | select(.name=="sinter") | .version'

# Fresh build outside the repo
CARGO_TARGET_DIR=/tmp/sinter-${TAG}-check/target cargo build --locked --release
/tmp/sinter-${TAG}-check/target/release/sinter --version   # sinter ${VERSION}

# Gates
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked
git diff --check
```

Also review: `CHANGELOG.md` accuracy vs evidence, `README.md` /
`README.ja.md` consistency, supported-platform claims scoped to actual
acceptance references, no stale current-version references
(`rg -n 'v0\.\d|0\.\d\.\d' --glob '!target/**'`), no unexpected release
infrastructure claims. Distinguish fresh check evidence from inherited
acceptance evidence in the report.

GO only when every check passes; otherwise NO-GO.

## Phase D — Artifact Staging

### Build environments and provenance

Linux x86_64 publishes **one** artifact, built on the oldest supported
baseline (Rocky Linux 9 x86_64, glibc 2.34) and then extracted and executed,
byte-identical, on every supported Linux x86_64 target before release. This
is justified — not assumed — by evidence: the Rocky-9-built binary requires
no glibc symbol newer than `GLIBC_2.34`, needs only
`libssl.so.3`/`libcrypto.so.3`/`libgcc_s.so.1`/`libc.so.6` (no RPATH), and
the exact same bytes were verified to run on Ubuntu 24.04, Ubuntu 26.04,
Rocky Linux 9, and Rocky Linux 10. Never substitute: no macOS binary shipped
as a Linux artifact, no rename-based target spoofing, no stale or
unknown-provenance binaries.

A build on a newer baseline (Ubuntu 26.04 or Rocky 10) is **not** an
acceptable substitute for this artifact: those builds require `GLIBC_2.39`
and will not run on Rocky Linux 9 (glibc 2.34).

Preferred source transport:

```sh
git archive ${RC_COMMIT} -o sinter-${RC_COMMIT}.tar   # exact commit, tracked files only
```

Ship to the build host, extract, and prove identity by comparing per-file
SHA-256s against a local extraction (sort with `LC_ALL=C` — locale collation
differs across hosts):

```sh
find . -type f | sort | xargs sha256sum > sums.txt   # on each side, then diff
```

A real `git worktree`/clone at `RC_COMMIT` is equally acceptable. Uncertain
provenance → do not publish.

Builder prerequisites: a fresh Rocky Linux 9 image needs explicit
provisioning before the build — `gcc`, `openssl-devel`, `pkgconf`
(`sudo dnf install -y gcc openssl-devel pkgconf`) and a Rust toolchain
(rustup or equivalent). Do not assume these are present.

Record on the build host:

```sh
cat /etc/os-release; uname -m; rustc --version; cargo --version
cargo build --locked --release        # -j1 on low-memory hosts
file target/release/sinter
readelf -d target/release/sinter | grep -E 'NEEDED|RPATH|RUNPATH'
readelf -V target/release/sinter | grep -oE 'GLIBC_[0-9.]+' | sort -uV | tail -1
ldd target/release/sinter
target/release/sinter --version       # sinter ${VERSION}
sha256sum target/release/sinter
```

Then, on **every** supported Linux x86_64 target, extract that exact binary
and re-verify `sha256sum` (must be identical), `ldd`, `--version`, and a
safe non-mutating `plan` before publishing. Record the per-target results.

### Build, freeze, package, and accept — mandatory identity gate

Build exactly once on **Rocky Linux 9 x86_64** with
`cargo build --locked --release` (`-j1` is permitted). Record source HEAD,
per-file build-input comparison, OS/version, architecture, rustc/cargo,
`ldd --version` (glibc), and `openssl version`. A different build baseline,
architecture, or maximum required GLIBC above **GLIBC_2.34** is a **STOP**.
Do not substitute Ubuntu 24/26 or Rocky 10 builds.

Immediately freeze the executable SHA-256. Record ELF headers/interpreter,
all symbol-version requirements, DT_NEEDED, and RPATH/RUNPATH. Expected native
interfaces are `libssl.so.3`, `libcrypto.so.3`, `libgcc_s.so.1`, `libc.so.6`,
and `ld-linux-x86-64.so.2`, with `OPENSSL_3.0.0` and no RPATH/RUNPATH.
Unexpected dependencies or unresolved linkage are a STOP pending review.
Do not strip, patch, or otherwise alter the frozen bytes.

Package one canonical archive, record its SHA-256, and prove a fresh
extraction has the frozen executable SHA. Build validation (source/ABI/hash/
smoke) is distinct from runtime acceptance: execute that exact extracted
artifact on every supported target and retain the Phase A matrix evidence
and independent OS-state checks tied to the source/hash. Source or test
changes invalidate acceptance under the golden rule; no release without
final production lineage. Record exact tested point releases separately
from supported version lines. No claim that future point releases were tested.

### Artifact naming

```text
sinter-v${VERSION}-linux-x86_64.tar.gz
SHA256SUMS
```

The name records Linux and the architecture class, not a managed-target
distribution. The manifest records the build baseline: the same binary manages all supported Linux
x86_64 targets. New targets that keep the same dependency interface extend
the verification matrix, not the artifact list; a target needing a different
interface gets its own artifact.

### Archive layout

Each tarball contains a single same-named top-level directory:

```text
sinter-v${VERSION}-<platform>-<arch>/
  sinter            # executable, mode 755
  README.md
  README.ja.md
  LICENSE-MIT
  LICENSE-APACHE
```

Never include: `.git`, source tree, `target/`, credentials, SSH keys, tokens,
`opencode.json`, internal audit/remediation/acceptance reports, agent logs,
temporary files.

**macOS packaging warning:** macOS `bsdtar` embeds extended-attribute headers
(`LIBARCHIVE.xattr.com.apple.*`) into archives. When packing on macOS use
`COPYFILE_DISABLE=1 tar --no-xattrs -czf …` (equivalent flags differ across
tools/platforms — always finish by inspecting the archive contents on the
target side; the first v0.2.0 pack needed a repack for exactly this reason).

### Archive verification

For every tarball:

- [ ] `tar tzvf` lists expected files only
- [ ] No absolute paths, no `..` traversal
- [ ] Executable bit preserved on `sinter`
- [ ] Fresh extraction on the **intended target** succeeds
- [ ] Extracted `./sinter --version` → `sinter ${VERSION}` on that target
- [ ] `file`/`ldd` confirm architecture and resolvable linkage

### Checksums

Generate `SHA256SUMS` **only after the artifacts are final**:

```sh
shasum -a 256 sinter-v${VERSION}-*.tar.gz > SHA256SUMS   # or sha256sum
shasum -a 256 -c SHA256SUMS                              # verify
```

Repacking an artifact invalidates its checksum — regenerate `SHA256SUMS`
whenever any tarball changes.

### Human review package

Assemble outside the repository:

```text
~/Downloads/Sinter-v${VERSION}-release-staging/
  sinter-v${VERSION}-*.tar.gz     # → release assets
  SHA256SUMS                      # → release asset
  RELEASE_NOTES.md                # → GitHub Release body source
  RELEASE_MANIFEST.md             # internal review evidence
  evidence/                       # provenance logs, file-hash lists, build envs
```

GitHub Release assets are the tarballs + `SHA256SUMS` only. The manifest and
`evidence/` are for human review, not publication.

### RELEASE_MANIFEST.md required fields

Per artifact: filename, size, SHA-256, build OS, architecture, rustc/cargo
version, source commit, binary type, linkage summary, extraction-verification
result, `--version` result. Overall: release version, RC commit, checksum
verification result, staging timestamp, supported-target matrix.

### RELEASE_NOTES.md structure

```markdown
# Sinter vX.Y.Z
## Highlights
## Supported platforms      (matrix + acceptance reference scoping)
## Downloads                (artifacts + SHA256SUMS + verify command)
## Validation               (concise, evidence-based)
## Known limitations
```

Must not contradict `CHANGELOG.md`/`README.md`/acceptance evidence. No
internal finding IDs, no agent internals, no overstated security guarantees.

### Human review gate

Publishing requires explicit human review of, in order:

1. `RELEASE_MANIFEST.md`
2. `RELEASE_NOTES.md`
3. `SHA256SUMS`
4. tarball contents (`tar tzvf`, spot-run `--version`)

No publish until the human confirms all four.

## Publish

Only after human authorization. All steps use read-back verification.

```sh
# 1. Recheck fixed state
git rev-parse HEAD                       # still RC_COMMIT's descendant; tag targets RC_COMMIT
git status --short
git remote -v

# 2. Recheck staging
cd ~/Downloads/Sinter-v${VERSION}-release-staging
shasum -a 256 -c SHA256SUMS              # all OK

# 3. Recheck remote — TAG must not exist; no unexpected divergence
git ls-remote --tags <remote> | grep ${TAG}   # expect empty
git fetch <remote> && git status -sb

# 4. Push main
git push <remote> main

# 5–7. Annotated tag at the exact RC, verify target, push tag
git tag -a ${TAG} ${RC_COMMIT} -m "Sinter ${TAG}"
git rev-parse ${TAG}^{commit}            # MUST equal RC_COMMIT
git push <remote> ${TAG}
git ls-remote --tags <remote> | grep ${TAG}   # confirm points at RC_COMMIT

# 8–10. GitHub Release with reviewed notes and intended assets only
gh release create ${TAG} \
  --title "Sinter ${TAG}" \
  --notes-file RELEASE_NOTES.md \
  sinter-v${VERSION}-*.tar.gz SHA256SUMS

# 11. Read back
gh release view ${TAG}                   # tag, title, asset names/sizes
```

Rules:

- Release tags are **annotated** and must point at the exact `RC_COMMIT`.
  Verify before and after pushing.
- If the tag already exists remotely → STOP. Never force-update a release tag.
- Never `--force` / `--force-with-lease` anywhere in this workflow.
- A v0.2.0-style docs commit after the RC does **not** move the tag target —
  the tag always names the commit the staged artifacts were built from.
- CLI exit codes are not proof; verify §Post-publish verification.

## Post-publish verification

Read the release back from GitHub:

```sh
gh release view ${TAG} --json tagName,name,assets
git ls-remote --tags <remote> | grep ${TAG}    # tag → RC_COMMIT
```

- [ ] Tag exists and points at `RC_COMMIT`
- [ ] Release exists with correct title
- [ ] Exactly the intended assets, no extras
- [ ] `SHA256SUMS` downloadable and matches staged copy
- [ ] Fresh-download each asset and check against `SHA256SUMS`:

```sh
gh release download ${TAG} -D /tmp/verify-${TAG} --clobber
(cd /tmp/verify-${TAG} && sha256sum -c SHA256SUMS)
```

## Partial publish failure

Steps 4–11 can partially succeed (e.g. tag pushed but release creation fails).

- **Do not blindly retry the whole workflow.**
- Read back remote state first: `git ls-remote`, `gh release view`.
- Resume only the unfinished steps.
- Do not delete or force-update an existing tag to "fix" bookkeeping — treat
  tag existence as ground truth and reconcile forward.

## Abort rules

Do not begin publishing when any of these hold:

- unexpected dirty files, or RC/version mismatch
- any production diff after acceptance
- missing/wrong-OS/wrong-arch artifact, extraction or `--version` failure
- checksum mismatch or uncertain provenance
- inaccurate release notes
- remote tag already exists unexpectedly

Abnormalities *after* publish has started → partial-publish procedure above.

## Secrets

- Never log or report GitHub tokens, SSH private keys, or environment secrets
- Never place credentials inside artifacts, manifests, or release notes
- Do not dump credential-bearing command output into reports

## Evidence retention

Keep (no secrets): `RELEASE_MANIFEST.md`, `RELEASE_NOTES.md`, `SHA256SUMS`,
final RC hash, tag, release URL, build-environment summary, and the
acceptance/check reports that authorized the release.

## Future fast path (conditional)

When the process proves stable, a release may compress to:

```text
Final Release Check GO → Artifact Staging → automatic staging verification
→ tag → push → GitHub Release → post-publish verification
```

Prerequisites — all required:

- zero production diff after acceptance
- exact RC fixed
- baseline build environment available and exact-artifact verification complete on all targets
- extraction/run and checksum verification green
- release notes generated and validated
- clean repository state; no unexpected remote tag/release
- **explicit human authorization to publish** — a coding agent must never
  publish on its own judgment

## Reference example — v0.2.0 (do not copy/paste as commands)

Historical proven values, for orientation only:

- Version `0.2.0`, RC `031f09a5507383afd246c98b0994b750f911e64e`
  (accepted implementation `cb4b5d9f96745f09541cc1f799907cb0ad19dee5`)
- Artifacts: `sinter-v0.2.0-ubuntu24.04-amd64.tar.gz`,
  `sinter-v0.2.0-rocky9-x86_64.tar.gz`, `SHA256SUMS`
- Final Release Check: GO; Artifact Staging: READY FOR HUMAN REVIEW
- Rocky acceptance reference: Rocky Linux 9.8 x86_64, DNF 4.14.0

## Future candidates (not part of this runbook)

Release CI/GitHub Actions, signing infrastructure, curl installer, Homebrew /
package repositories, documentation site. Evaluate separately; do not assume
existence.
