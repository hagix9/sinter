# Sinter Release Runbook

Operational procedure for cutting a Sinter release. Written so a human or a
coding agent can execute it top to bottom. Placeholders used throughout:

```sh
VERSION=0.4.0            # version being released (no "v" prefix)
TAG=v${VERSION}          # release tag
SOURCE_CANDIDATE=<full hash>  # reviewed implementation commit (step 1)
RC_COMMIT=<full hash>    # exact release-candidate commit (step 2)
```

`SOURCE_CANDIDATE` and `RC_COMMIT` must always be full 40-character commit
hashes, never a branch name or short ref.

## Release state machine

A release moves through these steps strictly in order. Each step consumes
only the outputs of earlier steps; no step feeds back into an earlier one.
A failed gate never "retries in place": it returns to the step named in its
STOP column, and every later output is discarded.

```text
 1. Source candidate fixed        SOURCE_CANDIDATE (clean, reviewed commit)
 2. Version / metadata prepared   RC_COMMIT = SOURCE_CANDIDATE + metadata-only commit
 3. Source validation             read-only checks on RC_COMMIT
 4. Linux validation gate         fmt / clippy / all tests / installer / checker on Linux x86_64
 5. Build artifact                one build from RC_COMMIT on Rocky Linux 9 x86_64
 6. Freeze artifact identity      filename, size, tarball SHA-256, executable SHA-256, SHA256SUMS
 7. Target acceptance             the same frozen artifact on all 8 supported targets
 8. Per-target hash re-check      tarball + executable SHA-256 observed on each target
 9. Raw logs                      one sanitized raw log per target
10. Evidence Manifest             generated from the recorded values
11. Evidence bundle               bundle archive + acceptance SHA256SUMS
12. Checker PASS                  release/check_acceptance_manifest.py (full mode)
13. Human review                  staged assets, notes, manifests, checker output
14. Tag                           annotated tag → RC_COMMIT
15. GitHub Release                release created from the reviewed notes
16. Assets                        exactly the reviewed, staged files
17. Post-publish verification     download + checksum read-back, manifest copy commit
```

| Step | Allowed changes | Output | GO condition | STOP / return to |
|------|-----------------|--------|--------------|------------------|
| 1 | None (select commit) | `SOURCE_CANDIDATE` | Clean tree, reviewed, pushed | — |
| 2 | Version fields, `Cargo.lock`, `CHANGELOG.md`, README platform/version text only | `RC_COMMIT` | Diff `SOURCE_CANDIDATE..RC_COMMIT` touches release metadata only | Unexpected diff → redo 2 |
| 3 | None | Source validation report | All §3 checks pass | Any failure → 1 (remediation) or 2 |
| 4 | None | Linux gate log + recorded results | Every step PASS on supported Linux x86_64 | Any FAIL → 1; **no build, no acceptance** |
| 5 | Nothing in repo | Built executable | Baseline, ABI and provenance checks pass | Failure → 5, or 1 if source is wrong |
| 6 | Nothing in repo | Tarball, `SHA256SUMS`, frozen hashes | Fresh extraction reproduces the frozen executable hash | Mismatch → 5 |
| 7–9 | None (repository and artifact read-only) | Per-target results and raw logs | All 8 targets PASS with identical hashes | Any target FAIL or hash mismatch → NO-GO, return to 1 |
| 10–11 | Nothing in repo | Manifest, bundle, acceptance `SHA256SUMS` | Built only from recorded values | Missing value → 7 (re-run), never reconstruct |
| 12 | None | Checker output `OK … (verdict GO)` | Exit 0 | FAIL → fix sanitization/assembly (10–11) or return to 7; **no tag** |
| 13 | None | Explicit human approval | Reviewer approves the exact staged files | Any doubt → hold |
| 14–16 | Remote refs + GitHub Release only | Tag, release, assets | §Publish read-backs pass | Partial failure → §Partial publish failure |
| 17 | Docs-only manifest-copy commit | Read-back record | All read-backs match staging | Mismatch → incident, do not force-fix |

## Invalidation rules

These rules are absolute. They define when an output of the state machine
stops being valid.

- **No tag before acceptance.** Steps 14–16 require steps 7–13 to be
  complete for the same `RC_COMMIT` and the same frozen artifact.
- **No rebuild after freeze or tag.** The artifact frozen in step 6 is the
  only artifact that may be accepted and published. A rebuild — even from
  the same commit — produces a new candidate and restarts at step 5 with
  fresh acceptance.
- **Source, test, or build-input change invalidates the candidate.** Any
  change to `src/`, `tests/`, `Cargo.toml` dependencies, `Cargo.lock`
  (beyond the step-2 version line), the toolchain, or the build baseline
  after step 2 voids every later output. Restart at step 1.
- **Artifact hash change → redo acceptance.** If the tarball or executable
  SHA-256 differs from the step-6 values anywhere, all acceptance evidence
  for that candidate is void. Restart at step 5.
- **Linux gate FAIL → no build, no acceptance.** A macOS (or any non-Linux)
  PASS is never a substitute: Linux-only test suites are compiled out there
  and the installer tests need GNU userland.
- **Any target FAIL → no tag.** The verdict must be `GO` on all 8 targets.
- **Checker FAIL → no tag.** Steps 13–16 require the full-mode checker to
  pass on the exact staged manifest, bundle archive, artifact, and
  acceptance `SHA256SUMS`.
- **Evidence is complete before human review.** Manifest, bundle, and both
  checksum files exist and verify before step 13 begins.
- **Only reviewed bytes are published.** Steps 14–16 upload exactly the
  files the reviewer approved; their checksums are re-verified immediately
  before upload.
- **Never reconstruct evidence.** Missing or lost evidence means re-running
  the step that produces it, never recreating it from memory or summaries.

Real-target testing before step 1 (development or remediation acceptance)
is useful but is not release evidence: release evidence is always produced
in steps 7–12 from the frozen artifact of the current `RC_COMMIT`.

## Steps 1–2 — Source candidate and release preparation

Fix `SOURCE_CANDIDATE`: a clean, reviewed, pushed commit whose remediation
and audits are complete. Then prepare the candidate on top of it. Allowed
changes **only**:

- `Cargo.toml` version → `${VERSION}`
- `Cargo.lock` regenerated consistently (`cargo check`)
- `CHANGELOG.md` new version entry (follow existing section conventions;
  keep claims inside implemented + accepted scope)
- `README.md` / `README.ja.md` supported-platform and version statements
- Other strictly necessary release metadata

Forbidden: production logic, tests (unless a metadata check truly requires
it), unrelated refactors, unrelated dirty files.

The preparation commit must be the direct child of `SOURCE_CANDIDATE`; it
becomes `RC_COMMIT`. Recommended message:

```text
Prepare Sinter v${VERSION} release
```

Stage explicitly (`git add CHANGELOG.md Cargo.toml Cargo.lock README.md
README.ja.md`), never `git add .` / `-A`; verify with
`git diff --cached --name-only` before committing.

## Step 3 — Source validation

Read-only verification of `RC_COMMIT`. Fix nothing in this step — failures
go back to step 2 or to remediation (step 1).

```sh
# Fixed state
git rev-parse HEAD                 # == RC_COMMIT
git status --short                 # only pre-existing unrelated dirty files
git tag --list                     # TAG must NOT exist yet

# Lineage
git merge-base --is-ancestor ${SOURCE_CANDIDATE} HEAD
git diff --name-status ${SOURCE_CANDIDATE}..HEAD  # release files only
git diff ${SOURCE_CANDIDATE}..HEAD -- src/ tests/ # MUST be empty

# Version consistency
grep '^version' Cargo.toml                        # ${VERSION}
grep -A1 'name = "sinter"' Cargo.lock
cargo metadata --locked | jq '.packages[] | select(.name=="sinter") | .version'

# Fresh build outside the repo
CARGO_TARGET_DIR=/tmp/sinter-${TAG}-check/target cargo build --locked --release
/tmp/sinter-${TAG}-check/target/release/sinter --version   # sinter ${VERSION}

# Gates (any host; step 4 is still mandatory on Linux)
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
python3 release/check_acceptance_manifest.py --template release/acceptance-manifest.template.json
git diff --check
```

Also review: `CHANGELOG.md` accuracy vs evidence, `README.md` /
`README.ja.md` consistency, supported-platform claims scoped to actual
acceptance references, no stale current-version references
(`rg -n 'v0\.\d|0\.\d\.\d' --glob '!target/**'`), no unexpected release
infrastructure claims.

GO only when every check passes; otherwise NO-GO.

## Step 4 — Linux validation gate (mandatory, before any build)

Run on a supported Linux x86_64 host (one of the eight supported
distributions; Rocky Linux 9 x86_64 is the reference) from a clean checkout
of exactly `RC_COMMIT`. Use a checkout path outside any home directory (for
example `/work/sinter`) so the log contains no user paths.

A macOS or other non-Linux PASS is **not** a substitute. On macOS the
Linux-only suites (`#![cfg(target_os = "linux")]`) compile to zero tests
and the installer tests need GNU `tar`, `stat`, and `sha256sum`.

```sh
git rev-parse HEAD                    # == RC_COMMIT
git status --short                    # empty
cat /etc/os-release; uname -m; rustc --version; cargo --version
grep -l '^#!\[cfg(target_os = "linux")\]' tests/*.rs   # → linux_only_suites

# The commands are pinned; the checker rejects any other spelling.
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
env SINTER_TEST_LOCAL_SSHD=1 cargo test --locked --all-targets --all-features
python3 tests/installer/test_install.py
python3 -m unittest discover -s release/tests
cargo fmt --manifest-path gateway/Cargo.toml --check
cargo clippy --manifest-path gateway/Cargo.toml --locked --all-targets --all-features -- -D warnings
cargo test --manifest-path gateway/Cargo.toml --locked --all-targets --all-features
```

`SINTER_TEST_LOCAL_SSHD=1` is part of the pinned `root-test` command. It
enables the suites that start a throwaway unprivileged `sshd` on loopback:
`tests/ssh_keys.rs` (key formats, host-key verification, and the SSH
algorithm policy negotiated against a real server) and
`tests/multihost_lab.rs`. Without it those tests return early and still
count as passed, so a green run would not show that SSH negotiation was
exercised. The gate host needs `sshd`, `ssh-keygen`, `ssh-agent` and
`ssh-add`. Record and log the command exactly as written, including
`env`, which keeps it a single command whether it is typed into a shell or
run by a harness as an argument vector. The checker rejects `root-test`
evidence recorded without the variable for every release after v1.1.1.

The gateway crate (`gateway/`) is not part of the release artifact. It is
validated here anyway so that a release never ships from a commit whose
workspace fails on the reference platform.

Gate host: the host's own SSH service is its control plane and, in strict
mode, the SSH reference target. After preparing the host, reboot it and,
before the first gate command, confirm that `ssh.service` is active, no
`ssh.socket` is active, and ports 22 and 2222 are owned by the
`ssh.service` main process (a stray sshd from an earlier socket activation
makes later SSH tests fail). Service and handler lifecycle tests use a
dedicated fixture unit, but some tests act on the host's own SSH service:
`tests/package_service.rs` ensures `openssh-server` is installed and the SSH
unit is running and enabled, and `tests/remediation.rs` restarts that unit
through a handler. Run the gate only on a dedicated, disposable Linux host.
The per-commit CI builds the root test binaries but does not run them; this
gate is where the root test suite runs. A gate failure
that disturbs the host's SSH control plane is still a STOP: diagnose it on
the evidence, never retry in place.

Capture the full output of all of the above into one log
(`validation/linux-gate.log` in the evidence bundle), delimiting each step
with `== step <name> start <time>`, `$ <command>` and
`== step <name> rc=<rc> end <time>` lines as the gate harness does, and
record, as they are produced, the `linux_validation` fields of the Evidence
Manifest:
OS name/version/architecture, `RC_COMMIT`, `rustc`/`cargo` versions, start
and finish times, the Linux-only suites, and for each step its name, pinned
command, result, and passed/failed/ignored counts.

GO only when every step PASSes, every Linux-only suite ran at least one
test, and nothing failed. **Any FAIL is a STOP:** no build, no acceptance,
no tag; return to step 1. The checker enforces this record at step 12
(`linux_validation`: pinned commands, all PASS, x86_64, same commit,
finished before acceptance started, Linux-only suites executed). A partial
root test run is not valid evidence: the log's `root-test` section must show
every test harness of the root crate at `RC_COMMIT`, their pass counts must
add up to the recorded `root-test` counts, and `linux_only_suites` must name
exactly the Linux-only suites at `RC_COMMIT`. The checker derives both lists
from the repository with git and cargo, so run it from a clone that contains
`RC_COMMIT`.

## Steps 5–6 — Build once and freeze the artifact

Only after the step-4 gate PASSes.

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

In steps 7–8, every supported Linux x86_64 target extracts that exact
binary and re-verifies `sha256sum` (must be identical), `ldd`, `--version`,
and a safe non-mutating `plan`. Record the per-target results.

### Build, freeze, and package — mandatory identity gate

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
smoke) is distinct from runtime acceptance: steps 7–9 execute that exact
extracted artifact on every supported target and retain the matrix evidence
and independent OS-state checks tied to the source/hash. Source or test
changes invalidate the candidate (§Invalidation rules); no release without
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

### Checksums (step 6)

Generate `SHA256SUMS` **only after the artifacts are final**, then record
the frozen identity: artifact filename, size, tarball SHA-256, and the
SHA-256 of the extracted `sinter` executable.

```sh
shasum -a 256 sinter-v${VERSION}-linux-*.tar.gz > SHA256SUMS   # or sha256sum
shasum -a 256 -c SHA256SUMS                                    # verify
```

Repacking an artifact creates a new candidate: its checksum and any
acceptance evidence are void (§Invalidation rules). Only the installable
`linux-*` artifacts go into `SHA256SUMS`; the acceptance evidence bundle
never does.

## Steps 7–9 — Target acceptance of the frozen artifact

Only after step 6. Run once per supported target (the eight labels
`ubuntu2404`, `ubuntu2604`, `rocky9`, `rocky10`, `rhel9`, `rhel10`, `alma9`,
`alma10`), on real machines (real OS, real architecture, real SSH where
applicable), against the **exact** tarball frozen in step 6. FakeTarget/
FakeExecutor coverage does not substitute for target acceptance.

Step 8 on every target, before any check: copy the tarball, record its
observed SHA-256 and the SHA-256 of the extracted `sinter`, and compare them
with the step-6 values. A mismatch is a STOP (§Invalidation rules).

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

Step 9: keep one raw, sanitized log per target, named by its label.

Report ends with an explicit `GO` or `NO-GO`. Do not remediate during
acceptance — reproduce, preserve evidence, report, stop. Any target FAIL
ends this candidate; a fix is a new candidate from step 1.

## Steps 10–12 — Evidence Manifest, bundle, and checker

Follow `release/ACCEPTANCE_EVIDENCE.md`.

- Step 10: generate the Evidence Manifest from the values recorded in steps
  4 and 6–9 only — never from memory or summaries.
- Step 11: assemble the bundle directory (manifest copy, `harness/`,
  `logs/<label>.log`, `validation/linux-gate.log`), pack it, and write the
  acceptance checksums:

```sh
tar -czf sinter-v${VERSION}-acceptance-evidence.tar.gz sinter-v${VERSION}-acceptance-evidence
shasum -a 256 sinter-v${VERSION}-acceptance-manifest.json \
  sinter-v${VERSION}-acceptance-evidence.tar.gz > sinter-v${VERSION}-acceptance-SHA256SUMS
shasum -a 256 -c sinter-v${VERSION}-acceptance-SHA256SUMS
```

- Step 12: run the checker in full mode on the exact files that will be
  staged. It must print `OK … (verdict GO)` and exit 0:

```sh
python3 release/check_acceptance_manifest.py \
  sinter-v${VERSION}-acceptance-manifest.json \
  --bundle-archive sinter-v${VERSION}-acceptance-evidence.tar.gz \
  --artifact sinter-v${VERSION}-linux-x86_64.tar.gz \
  --sums sinter-v${VERSION}-acceptance-SHA256SUMS
```

A checker FAIL is a STOP: **no human review, no tag.** A sensitive-content
finding means sanitizing the logs and rebuilding the bundle (steps 9–11); a
hash, target, or gate finding means the evidence does not support this
candidate (return to step 7, or to step 1).

## Step 13 — Staging and human review

Only after the step-12 checker PASS. Assemble outside the repository:

```text
~/Downloads/Sinter-v${VERSION}-release-staging/
  sinter-v${VERSION}-linux-*.tar.gz  # → release assets
  SHA256SUMS                      # → release asset
  RELEASE_NOTES.md                # → GitHub Release body source
  RELEASE_MANIFEST.md             # internal review evidence
  evidence/                       # provenance logs, file-hash lists, build envs
  sinter-v${VERSION}-acceptance-manifest.json   # → release asset
  sinter-v${VERSION}-acceptance-evidence.tar.gz # → release asset
  sinter-v${VERSION}-acceptance-SHA256SUMS      # → release asset
```

GitHub Release assets are the tarballs, `SHA256SUMS`, and the three
acceptance assets (manifest, evidence bundle, acceptance checksums; see
`release/ACCEPTANCE_EVIDENCE.md`). `SHA256SUMS` lists the tarballs only, so
the installer and the documented checksum command are unaffected.
`RELEASE_MANIFEST.md` and the build `evidence/` directory remain internal
review material and are not published.

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
5. the acceptance manifest, the Linux gate record in it, its full-mode
   checker output, and `sinter-v${VERSION}-acceptance-SHA256SUMS`

No publish until the human confirms all five. The approval covers exactly
the staged bytes; any change to a staged file voids it.

## Steps 14–16 — Publish (tag, GitHub Release, assets)

Only after step-13 human authorization. All steps use read-back verification.

```sh
# 1. Recheck fixed state
git rev-parse HEAD                       # still RC_COMMIT's descendant; tag targets RC_COMMIT
git status --short
git remote -v

# 2. Recheck staging — the exact reviewed bytes
cd ~/Downloads/Sinter-v${VERSION}-release-staging
shasum -a 256 -c SHA256SUMS              # all OK
shasum -a 256 -c sinter-v${VERSION}-acceptance-SHA256SUMS
python3 <repo>/release/check_acceptance_manifest.py \
  sinter-v${VERSION}-acceptance-manifest.json \
  --bundle-archive sinter-v${VERSION}-acceptance-evidence.tar.gz \
  --artifact sinter-v${VERSION}-linux-x86_64.tar.gz \
  --sums sinter-v${VERSION}-acceptance-SHA256SUMS   # OK … (verdict GO)

# 3. Recheck remote — TAG must not exist; no unexpected divergence
git ls-remote --tags <remote> | grep ${TAG}   # expect empty
git fetch <remote> && git status -sb

# 4. Push main
git push <remote> main

# 5–7. Step 14: annotated tag at the exact RC, verify target, push tag
git tag -a ${TAG} ${RC_COMMIT} -m "Sinter ${TAG}"
git rev-parse ${TAG}^{commit}            # MUST equal RC_COMMIT
git push <remote> ${TAG}
git ls-remote --tags <remote> | grep ${TAG}   # confirm points at RC_COMMIT

# 8–10. Steps 15–16: GitHub Release with reviewed notes and the reviewed assets only
gh release create ${TAG} \
  --title "Sinter ${TAG}" \
  --notes-file RELEASE_NOTES.md \
  sinter-v${VERSION}-linux-*.tar.gz SHA256SUMS \
  sinter-v${VERSION}-acceptance-manifest.json \
  sinter-v${VERSION}-acceptance-evidence.tar.gz \
  sinter-v${VERSION}-acceptance-SHA256SUMS

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

## Step 17 — Post-publish verification

Read the release back from GitHub:

```sh
gh release view ${TAG} --json tagName,name,assets
git ls-remote --tags <remote> | grep ${TAG}    # tag → RC_COMMIT
```

- [ ] Tag exists and points at `RC_COMMIT`
- [ ] Release exists with correct title
- [ ] Exactly the intended assets, no extras
- [ ] `SHA256SUMS` downloadable and matches staged copy
- [ ] Fresh-download each asset and check against `SHA256SUMS` and the
      acceptance checksums:

```sh
gh release download ${TAG} -D /tmp/verify-${TAG} --clobber
(cd /tmp/verify-${TAG} && sha256sum -c SHA256SUMS \
  && sha256sum -c sinter-v${VERSION}-acceptance-SHA256SUMS \
  && python3 <repo>/release/check_acceptance_manifest.py \
       sinter-v${VERSION}-acceptance-manifest.json \
       --bundle-archive sinter-v${VERSION}-acceptance-evidence.tar.gz \
       --artifact sinter-v${VERSION}-linux-x86_64.tar.gz \
       --sums sinter-v${VERSION}-acceptance-SHA256SUMS)
```

- [ ] Commit the manifest copy to
      `release/evidence/v${VERSION}/acceptance-manifest.json` (byte-identical
      to the published asset) in a docs-only commit.

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
- any source, test, or build-input change after step 2
- Linux validation gate (step 4) not PASS, or run only on a non-Linux host
- any target FAIL, or any artifact/executable hash that differs from step 6
- full-mode checker (step 12) not PASS on the staged files
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

From v1.0.0 candidates on, the acceptance evidence itself is retained
publicly and permanently as release assets (manifest, evidence bundle,
acceptance checksums), with a tracked manifest copy under
`release/evidence/v${VERSION}/`. See `release/ACCEPTANCE_EVIDENCE.md`.

## Future fast path (conditional)

When the process proves stable, a release may compress to:

```text
source validation + Linux gate → build/freeze → acceptance → checker
→ automatic staging verification → human authorization → tag → GitHub Release
→ post-publish verification
```

The fast path may automate steps, never skip or reorder them.

Prerequisites — all required:

- zero source/test/build-input diff after step 2
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
  (v0.2.0 predates the current step order)
- Rocky acceptance reference: Rocky Linux 9.8 x86_64, DNF 4.14.0

## Future candidates (not part of this runbook)

Release CI/GitHub Actions, signing infrastructure, curl installer, Homebrew /
package repositories, documentation site. Evaluate separately; do not assume
existence.
