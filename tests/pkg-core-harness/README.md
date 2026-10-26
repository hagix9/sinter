# WP-PKG-CORE real-host safety harness

A fail-closed harness that exercises Sinter's package-removal path on a real
Debian-family host (real `dpkg`) using **synthetic test packages only**
(`sinter-t-*`). It is a test asset, not part of the Sinter binary, and it is
not run by CI (it needs a disposable host).

Everything destructive goes through one library path (`lib/safe-lib.sh`): a
package is purged only if the run registered it, it is in the scenario's
static allow-list, and its identity (name, architecture, version, Maintainer,
not Essential) was re-verified immediately before. No `--force-*` option
exists anywhere (`lint-harness.sh` enforces it).

## Layout

| Path | Purpose |
|---|---|
| `lib/` | the safety library, the namespace gate, the wrapper shims, the capture layer |
| `init/body.sh` | `init-state.sh`: the **explicit** initialisation of the persistent state |
| `recovery/body.sh` | `recover-synthetic.sh`: fail-closed recovery of a failed or killed run |
| `stageb1/`, `stageb2/` | scenarios that do not run Sinter (1 package; 3 packages with a dependency) |
| `sa3/`, `multiarch/` | scenarios that run a Sinter binary (`ARTIFACT_PATH`) |
| `build-debs.py` | builds the synthetic `.deb` payloads |
| `assemble.sh` | lints, then assembles the self-contained scripts (see below) |
| `lint-harness.sh` | static safety lint |
| `tests/` | the harness's own failure-injection tests (mock `dpkg`, 185 cases) and the mutation runner |

## Build

```sh
ASSEMBLE_BUILD=production ./assemble.sh OUTDIR     # production (default)
ASSEMBLE_BUILD=test       ./assemble.sh OUTDIR     # test build (fault hooks; used by the tests)
```

It writes `init-state.sh`, `recover-synthetic.sh` and four `scenario-*.sh`
files. `init-state.sh` and `recover-synthetic.sh` are byte-for-byte
reproducible. The `scenario-*.sh` files embed a packaged payload (gzip/tar/ar
timestamps), so their **code part (everything before `__PAYLOAD__`) is
reproducible, the whole file is not**.

## Tests

```sh
export TMPDIR=<a directory on a disk with room to spare>
tests/run-tests.sh                 # all cases (mock dpkg; no package manager is touched)
tests/run-tests.sh "t173 t150"     # selected cases (globs allowed)
```

The mutation runner (`tests/run-mutants.py OUT.tsv [PREFIX...]`, needs
`MUT_WORK`) is slow and **leaves large work directories** because some cases
make directories read-only: run `chmod -R u+rwx "$MUT_WORK"` and delete them
afterwards.

## Operating rules

The run exclusion is an `flock(2)` on a stable file plus an atomically
replaced state record, in a persistent state directory
(`/var/lib/sinter-harness`, mode 700, yours). Runs and recoveries start only
in an environment that was **initialised explicitly**; a missing or damaged
record is `UNKNOWN` and stops everything; nothing is repaired automatically.

1. Initialise once per host, as the **same user** that will run the scenarios
   and the recovery tool:
   `init-state.sh --evidence-dir DIR --confirm-clean-host`.
   `--confirm-clean-host` is the operator's statement that the host carries no
   unrecovered change of an earlier run; the tool additionally refuses if it
   finds an old-format lock, a leftover run directory, a synthetic package or
   a harness wrapper.
2. The tool performs the privileged steps itself (`sudo -n mkdir -m 700` and
   `chown` of the state directory). **Do not run the whole tool as root**: the
   records would belong to root and every run by the ordinary user would then
   be refused.
3. **Never work around a refusal** by changing the owner or mode of the state
   directory or records, or by recreating a record by hand. A refusal
   (`UNKNOWN`, `INIT_INCOMPLETE`, `LEGACY_LOCK`, `UNINITIALIZED`,
   `FAILED_LOCKED`, `RECOVERY_IN_PROGRESS`, `PACKAGES_RECOVERED_LOCK_PENDING`)
   asks a human to review the host. A failed run is recovered with
   `recover-synthetic.sh` (a run that was killed needs `--allow-orphan`).
4. Re-running the initialisation is idempotent and never clears a failed run.

Symbolic links and wrong owners or modes are refused by an explicit link test
and by a mode test. Note that GNU `stat` does **not** follow symbolic links by
default (it reports the link's own mode); `stat -L` follows them.

## Verification status

This tree was verified on a disposable Ubuntu 24.04.5 host (x86_64, real
`dpkg` 1.22.6): the production build, the `init-state.sh` `sudo` branch
(only `mkdir -m 700` and `chown` were run with `sudo`), stages B1 and B2, a
SIGKILLed run and a real cleanup failure with recovery, refusal of another UID
and of root, and refusal after the state record was removed. The
OS-independent layer (flock, stat, permissions, state directory) was also
verified on Rocky Linux 10.2 (aarch64) with the mock `dpkg`.

**Not covered:** Rocky Linux 9 (the harness needs `dpkg`; not applicable),
the `sa3` and `multiarch` scenarios (they need a Sinter binary) on the final
tree, other architectures, and production use of the mutation runner.

## Provenance - which copy is the source

This directory is the single source. Earlier copies of this harness exist in
local audit-record directories outside this tree (names starting with
`wp-pkg-core-gce-followup-safety-` and `wp-pkg-core-r4-minimal-fix-`). They are
evidence, not sources, and the later ones contain a defect that makes the
production build refuse to start on Linux (`lib/nscheck.sh` tested
`/proc/self/mountinfo` with `[ -s ]`, which is always false because procfs
files report size 0). Do not build from them.
