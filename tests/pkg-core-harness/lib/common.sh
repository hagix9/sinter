#!/usr/bin/env bash
# common.sh -- shared header of the SA-3 and the Multi-Arch scenarios (APT hosts only).
# Executed ON the target by `gce.sh run` (login user with passwordless sudo): ARTIFACT_PATH, RUN_ID and WORKSPACE are
# provided.  Everything installed is a synthetic sinter-t-* package carried in the payload appended to the assembled
# scenario.  All package removal goes through safe-lib.sh; there is no other purge in these scenarios.
set -uo pipefail

# The gate (lib/nscheck.sh): environment guard, entry into a PRIVATE mount namespace (root: unshare --mount --propagation
# private, then back to the login user) and the verification of that namespace from the kernel state.  Nothing else of this
# file, and no package operation, runs unless it passes.  H_NS_ENTERED / H_TEST_MODE never skip it (audit finding F-2).
h_gate || exit 70

SINTER="${ARTIFACT_PATH:?ARTIFACT_PATH required}"
RID="${RUN_ID:?RUN_ID required}"
OUT="${WORKSPACE:?WORKSPACE required}/out"
mkdir -p "$OUT/logs" || exit 70
RESULTS="$OUT/results.tsv"
: > "$RESULTS" || exit 70
FAILED=0
RC=0

record() {
    local step="$1" want="$2" got="$3" st=PASS
    [ "$want" = "$got" ] || { st=FAIL; FAILED=1; }
    printf '%s\t%s\t%s\t%s\n' "$step" "$want" "$got" "$st" | tee -a "$RESULTS"
}
note() { printf 'NOTE\t%s\n' "$*" | tee -a "$OUT/notes.txt"; }

ACC="$HOME/sinter-h-$RID"
PK="$ACC/pkgs"
mkdir -p "$ACC" "$PK" || exit 70
H_PK="$PK"
if [ "${H_SUDO_NONE:-0}" = 1 ]; then H_SUDO=(); else H_SUDO=(sudo -n); fi   # H_SUDO_NONE=1 only in the isolated tests

H_OS_RELEASE="${H_OS_RELEASE:-/etc/os-release}"
OS_ID="$(. "$H_OS_RELEASE"; echo "${ID:-}")"
OS_LIKE="$(. "$H_OS_RELEASE"; echo "${ID_LIKE:-}")"
case " $OS_ID $OS_LIKE " in
    *" debian "*|*" ubuntu "*) ;;
    *) record "distro:family" "debian" "unsupported($OS_ID)"; exit 0 ;;
esac
record "distro:family" debian debian
cp "$H_OS_RELEASE" "$OUT/os-release.txt"; uname -a > "$OUT/uname.txt"

# payload (synthetic packages): extracted next to the scenario, verified against the embedded manifest
sed -n '/^__PAYLOAD__$/,$p' "$0" | tail -n +2 | base64 -d | tar xz -C "$PK" || { record "payload:extracted" yes no; exit 70; }
( cd "$PK" && ${H_SHA256SUM:-sha256sum} -c MANIFEST.sha256 > "$OUT/payload-check.txt" 2>&1 ) && record "payload:sha256-verified" yes yes || { record "payload:sha256-verified" yes no; exit 70; }

jf() {  # jf LABEL FIELD -> a field of the first resource of a Sinter JSON report
    python3 -I -c 'import json,sys
try:
    r = json.load(open(sys.argv[1]))["resources"][0]
    v = r.get(sys.argv[2])
    print("" if v is None else v)
except Exception:
    print("JSON-ERROR")' "$OUT/logs/$1.json" "$2"
}
recipe() {  # recipe FILE NAME STATE [sensitive]
    local f="$ACC/$1" sens=""
    [ "${4:-}" = sensitive ] && sens="    sensitive: true"
    { echo "version: 1"; echo "resources:"; echo "  - id: p"; echo "    type: package"
      [ -n "$sens" ] && echo "$sens"
      echo "    with:"; echo "      name: $2"; echo "      state: $3"; } > "$f" || { h_fail "recipe:$1" "cannot write the recipe"; return 1; }
}
WRAPPED=0   # 1 while the dpkg wrapper is mounted (sinj/sint then reset and collect its logs)
sinj() {  # sinj LABEL RECIPE [sinter args] -> JSON run
    local label="$1" rec="$2"; shift 2
    [ "$WRAPPED" = 1 ] && { h_shim_reset_logs || { h_fail "sinj:$label" "cannot reset the wrapper logs"; return 1; }; }
    "$SINTER" apply --format json "$@" "$ACC/$rec" > "$OUT/logs/$label.json" 2> "$OUT/logs/$label.err"
    RC=$?
    [ "$WRAPPED" = 1 ] && h_shim_collect "$label"
    return 0
}
sint() {  # sint LABEL RECIPE [sinter args] -> text run
    local label="$1" rec="$2"; shift 2
    [ "$WRAPPED" = 1 ] && { h_shim_reset_logs || { h_fail "sint:$label" "cannot reset the wrapper logs"; return 1; }; }
    "$SINTER" apply "$@" "$ACC/$rec" > "$OUT/logs/$label.txt" 2>&1
    RC=$?
    return 0
}
report() { note "$1: rc=$RC change=$(jf "$1" change) execution=$(jf "$1" execution) verification=$(jf "$1" verification) reason=[$(jf "$1" reason | tr '\n' ' ' | cut -c1-260)]"; }
cons() {  # the text summary agrees with the JSON change
    local ch want s
    ch="$(jf "$1" change)"; s="$(grep -E '^summary:' "$OUT/logs/$2.txt" | head -1)"
    case "$ch" in changed) want="1 changed, 0 possible" ;; possible) want="0 changed, 1 possible" ;; none) want="0 changed, 0 possible" ;; *) want="?" ;; esac
    case "$s" in *"$want"*) record "$2:text-agrees-with-json($ch)" yes yes ;; *) record "$2:text-agrees-with-json($ch)" yes "no: [$s]" ;; esac
}
inv() {  # invariants between the JSON result and what the real removing dpkg wrote (needs the dpkg wrapper)
    local l="$1" ch removing proof
    ch="$(jf "$l" change)"
    [ -e "$OUT/logs/$l.shim.real.err" ] || { note "$l: no real removing dpkg ran (Sinter refused earlier)"; return 0; }
    removing="$(grep -q '^Removing ' "$OUT/logs/$l.shim.real.out" && echo yes || echo no)"
    record "$l:INV1-a-Removing-line-never-with-change-none" yes "$([ "$removing" = yes ] && [ "$ch" = none ] && echo no || echo yes)"
    if [ "$ch" = none ]; then
        grep -qE '^dpkg: (dependency problems prevent removal of |error: |warning: ignoring request to remove )' "$OUT/logs/$l.shim.real.err" && proof=yes || proof=no
        record "$l:INV2-change-none-has-a-dpkg-refusal-or-warning-line" yes "$proof"
    fi
}
snapc() {  # snapc LABEL -> a validated snapshot of the whole host; failure stops the scenario
    h_snapshot "$1" || { h_abort "snapshot $1 failed"; exit 70; }
    cp "$H_RUNDIR/snap.$1" "$OUT/snap-$1.tsv" 2> /dev/null || h_fail "evidence:snap-$1" "cannot save the snapshot"
}
nonreg_same() {  # nonreg_same STEP A B -> every package this run did not register is unchanged between two snapshots
    if h_compare_nonreg "$2" "$3"; then record "$1" unchanged unchanged; else record "$1" unchanged "changed: ${H_DIFF:-?}"; fi
}
state_of() { h_query_pkg "$1" "$2" > /dev/null 2>&1 && echo "$H_PSTATE" || echo "unknown"; }
cleanup_case() {  # the purge of everything this run registered; a failure stops the scenario (the EXIT trap reports)
    h_cleanup || { note "cleanup failed: the scenario stops here (nothing more is installed or purged)"; exit 70; }
}
