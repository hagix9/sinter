# Release acceptance harness

The scripts that run RELEASE.md steps 7–9 (target acceptance of the frozen
artifact) on real cloud machines. They are a minimal, fail-closed driver, not
a provisioning system: the target instances must already exist, and nothing
here creates, deletes or modifies them beyond start/stop and an optional
temporary external IP that is removed again.

## Configuration

Everything environment- or release-specific comes from the environment;
nothing is hardcoded and nothing has a default. Copy `harness.env.example`
to a place **outside the repository**, fill it in and load it with
`set -a; . <file>; set +a`. A missing or malformed value (including an
instance name or label that is not a plain name) stops the run with exit 64
before any cloud call.

| Variable | Meaning |
|----------|---------|
| `SINTER_PROJECT`, `SINTER_ZONE` | cloud project and zone of the targets |
| `SINTER_SPECS` | one `<instance>:<label>:<need_ip>:<make_cache>` per line |
| `SINTER_ARTIFACT` | the frozen tarball `sinter-v<version>-linux-x86_64.tar.gz` |
| `SINTER_RC_COMMIT` | full 40-hex release-candidate commit |
| `SINTER_EXP_ART`, `SINTER_EXP_EXE` | step-6 tarball / executable SHA-256 |
| `SINTER_EXP_VER` | expected `sinter --version` line |
| `SINTER_SANITIZE_PATTERNS` | optional: a local, untracked `<regex><TAB><replacement>` file with extra identifiers to mask in published logs |

`GCLOUD` may name a different `gcloud` executable (the tests use a fake one).

## Flow

`run-all.sh <out>` runs `run-target.sh` once per spec, sequentially and
fail-fast (no retry). For one target, `run-target.sh`:

1. verifies the local tarball against `SINTER_EXP_ART` (refuses to start on a
   mismatch);
2. records the boot disk's source image and image id (`source_image`,
   `source_image_id` in `run.json`); no provenance → `ERROR`;
3. starts the instance, uploads the harness and the tarball, and re-checks
   the tarball hash on the target;
4. runs `target-prep.sh` after removing any earlier `/tmp/prep.rc`; a stale,
   missing or non-zero result → `ERROR`;
5. optionally refreshes dnf metadata; a non-zero `dnf makecache` → `ERROR`;
6. runs the frozen `acceptance-target.sh` in a private per-run directory,
   hashes the raw log on the target, fetches it, and stops with
   `RAW_SHA_MISMATCH` unless the fetched copy has the same SHA-256;
7. derives the verdict with `raw-verdict.py`, cleans up only its own per-run
   directory, and stops the instance on every path.

Every run writes `runs/<run-id>/` (`driver.log`, `run.json`, `result`, the
raw log and a `scripts/` copy with its SHA-256 sums) and appends to
`INDEX.tsv`; a used run directory is never reused. `collect-evidence.py`
gathers the PASS runs; GO requires a verified PASS for all eight release
labels (the matrix cannot be narrowed) and an Owner approval signed with
`approve.py`. `sanitize.py <label> <raw> <out>` writes the publishable log: it
masks the project, the zone and the instance names from `SINTER_SPECS` as
literals, plus generic hosts, users, paths and addresses, and writes nothing
if any of the run's identifiers would remain.

Tests: `python3 -m unittest discover -s release/tests`
(`test_acceptance_harness.py` drives these scripts against a fake `gcloud`).
