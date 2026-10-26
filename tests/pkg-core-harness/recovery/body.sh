# =====================================================================================
# recover-synthetic.sh -- fail-closed recovery of the SYNTHETIC packages a FAILED harness run left behind.
# (R3: independent re-audit blocker R3-1 "lock exclusion"; before: R2-1 "lock release", R2-2 "pre-recovery dpkg --audit".)
#
#   recover-synthetic.sh --run-id ID --run-dir DIR --evidence-dir DIR --target NAME:ARCH:VERSION [--target ...] [--allow-orphan]
#
# Contract (details and the state machine: 03-lock-state-machine.md):
#   * EXCLUSION: the tool enters through the SAME function the scenarios use (h_env_enter): the persistent state directory must
#     exist and be safe, the environment must have been initialised explicitly and be consistent (a vanished record is UNKNOWN,
#     never "fresh"), and it takes flock(2) on the SAME stable file (sinter-h-mutex) BEFORE it trusts anything, and
#     holds it until it exits.  The file is never removed or renamed, so a new run can not start at any moment of the recovery,
#     including the moments between the state transitions.  A busy exclusion (a running scenario or another recovery) is refused.
#   * STATE: the state record (sinter-h-state) decides.  Only FAILED_LOCKED (or, with --allow-orphan, RUNNING = a killed run) of
#     THE RUN NAMED ON THE COMMAND LINE is recoverable.  UNKNOWN, RECOVERY_IN_PROGRESS, PACKAGES_RECOVERED_LOCK_PENDING, old-format
#     locks (LEGACY_LOCK), UNLOCKED and RECOVERED are refused; nothing is repaired or taken over automatically.
#   * Nothing is changed until EVERY pre-check passed.  The pre-checks include the pre-recovery `dpkg --audit` (R2-2).
#   * Removal goes through the library's single removal path (h_purge_one: plain `dpkg --purge`, no force option).  The FIRST
#     failure stops everything.  After the purges ALL post-checks must hold.
#   * Transitions (each ONE atomic compare-and-set of the state record, by the holder of the exclusion):
#       FAILED_LOCKED|RUNNING -> RECOVERY_IN_PROGRESS (just before the first purge; a graceful failure before the packages are
#       recovered puts the ORIGINAL state back) -> PACKAGES_RECOVERED_LOCK_PENDING (all post-checks passed) -> [final evidence
#       saved and read back] -> RECOVERED (sealed: only now a new run is allowed).  A kill at any point leaves a state that
#       refuses new runs; the owner record is in the state file and in the evidence copy.
#     "Packages recovered" and "recovered including the seal" are different results and are recorded as such.
# Exit status: 0 recovered, 1 failed (state and evidence kept), 2 usage, 70 environment gate.
# =====================================================================================
set -uo pipefail
h_gate_env || exit 70
RF_ME="$(id -u)"
if [ "$RF_ME" = 0 ]; then H_SUDO=()
elif declare -F h_production > /dev/null && h_production; then H_SUDO=(/usr/bin/sudo -n)
elif [ "${H_SUDO_NONE:-0}" = 1 ]; then H_SUDO=()
else echo "no privilege path (a test build needs H_SUDO_NONE=1)" >&2; exit 70; fi
RF_WHY=""

RF_RUN_ID=""; RF_RUN_DIR=""; RF_EVID=""; RF_TARGETS=(); RF_EV=""; RF_STATUS_WRITTEN=0; RF_PURGES=0; RF_LOCK_STATE=not-read
RF_PKG_RECOVERED=no; RF_ORDER=(); RF_LOCK_FP=""; RF_LOCK_CONTENT=""; RF_ALLOW_ORPHAN=0
RF_ORIG_STATE=""; RF_REC_NOW=""; RF_SEQ=0
RF_TNAMES=(); RF_TSTATES=()

record() { [ -n "$RF_EV" ] && printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$RF_EV/steps.tsv" 2> /dev/null; return 0; }
note() { printf 'NOTE\t%s\n' "$*" >&2; [ -n "$RF_EV" ] && printf 'NOTE\t%s\n' "$*" >> "$RF_EV/notes.txt" 2> /dev/null; return 0; }
rf_usage() { echo "usage: recover-synthetic.sh --run-id ID --run-dir DIR --evidence-dir DIR --target NAME:ARCH:VERSION [--target ...] [--allow-orphan]" >&2; exit 2; }
rf_sha() { if command -v sha256sum > /dev/null 2>&1; then sha256sum | cut -d' ' -f1; else shasum -a 256 | cut -d' ' -f1; fi; }
rf_fault() { [ "${H_RF_FAULT:-}" = "$1" ] && ! h_production; }     # fault injection exists in TEST builds only
rf_phase() {  # rf_phase NAME -> one append-only line: the last line says how far a (killed) recovery got
    [ -n "$RF_EV" ] && printf '%s\n' "$1" >> "$RF_EV/phases.tsv" 2> /dev/null
}
rf_write_status() {  # rf_write_status RESULT REASON -> recovery-status.tsv, written to a temp file, renamed, read back
    local res="$1" why="$2" f want got tmp
    if [ "$res" = PACKAGES_RECOVERED_LOCK_PENDING ] && rf_fault interim-save; then echo "RECOVERY $res: $why (the status could not be written)" >&2; return 1; fi     # test builds only
    [ -n "$RF_EV" ] && [ -d "$RF_EV" ] || { echo "RECOVERY $res: $why (no evidence directory to record it)" >&2; return 1; }
    f="$RF_EV/recovery-status.tsv"; tmp="$RF_EV/.status.tmp"
    want="$(printf 'result\t%s\nreason\t%s\npackages_recovered\t%s\nlock\t%s\npurge_commands\t%s\ntargets\t%s\n' "$res" "$why" "$RF_PKG_RECOVERED" "$RF_LOCK_STATE" "$RF_PURGES" "${RF_TARGETS[*]-}")"
    printf '%s\n' "$want" > "$tmp" 2> /dev/null && h_rename_path "$tmp" "$f" || { echo "RECOVERY $res: $why (the status could not be written)" >&2; return 1; }
    got="$(cat "$f" 2> /dev/null)"
    [ "$got" = "$want" ] || { echo "RECOVERY $res: $why (the status read back differently)" >&2; return 1; }
    RF_STATUS_WRITTEN=1
    return 0
}
rf_hold() {  # test builds only: wait until the test says go, so that it can act while the recovery holds the exclusion
    rf_fault "hold-$1" || return 0
    local i=0
    : > "${H_RF_HOLD_DIR:?}/held-$1"
    while [ ! -e "$H_RF_HOLD_DIR/go-$1" ] && [ "$i" -lt 600 ]; do sleep 0.1; i=$((i + 1)); done
}
rf_state_set() {  # rf_state_set NEW_STATE -> ONE compare-and-set of the state record (the run's identity is kept)
    local new
    new="$(h_state_record "$1" recovery $((RF_SEQ + 1)) "$$" "$H_ST_RUN_ID" "$H_ST_UID" "$H_ST_RUN_DIR" "$H_ST_NONCE" "$H_INIT_ID")"
    h_state_cas "$RF_REC_NOW" "$new" || return 1
    RF_REC_NOW="$new"; RF_SEQ=$((RF_SEQ + 1)); RF_LOCK_STATE="$1"
    return 0
}
rf_fail() {  # rf_fail REASON -> FAILED: the state and the evidence are kept; nothing further is done
    note "FAILED: $1"
    rf_phase failed
    # a graceful failure BEFORE any purge command was issued puts the original state back (so the failed run can be recovered
    # again).  Once a purge was issued the outcome on the host is not known by this tool: RECOVERY_IN_PROGRESS stays, which refuses
    # every new run and every automatic recovery until a human has reviewed the evidence (pre/post snapshots, steps, phases).
    if [ "$RF_LOCK_STATE" = RECOVERY_IN_PROGRESS ] && [ "$RF_PKG_RECOVERED" = no ] && [ "$RF_PURGES" = 0 ]; then
        rf_state_set "$RF_ORIG_STATE" || note "the original state $RF_ORIG_STATE could not be put back: the state stays RECOVERY_IN_PROGRESS (a human must review it)"
    fi
    rf_write_status FAILED "$1" || true
    echo "RECOVERY FAILED: $1 (state: $RF_LOCK_STATE; packages recovered: $RF_PKG_RECOVERED; evidence: ${RF_EV:-none})" >&2
    exit 1
}

# ---- arguments ------------------------------------------------------------------------------
tre='^(sinter-t-[a-z0-9]+(-[a-z0-9]+)*):(all|amd64|i386):([0-9][0-9.]*)$'
while [ $# -gt 0 ]; do
    case "$1" in
        --run-id) [ $# -ge 2 ] || rf_usage; RF_RUN_ID="$2"; shift 2 ;;
        --run-dir) [ $# -ge 2 ] || rf_usage; RF_RUN_DIR="$2"; shift 2 ;;
        --evidence-dir) [ $# -ge 2 ] || rf_usage; RF_EVID="$2"; shift 2 ;;
        --target) [ $# -ge 2 ] || rf_usage; RF_TARGETS[${#RF_TARGETS[@]}]="$2"; shift 2 ;;
        --allow-orphan) RF_ALLOW_ORPHAN=1; shift ;;
        *) rf_usage ;;
    esac
done
[[ "$RF_RUN_ID" =~ ^[a-z0-9][a-z0-9-]{2,40}$ ]] || { echo "bad --run-id" >&2; rf_usage; }
[ -n "$RF_RUN_DIR" ] && [ -n "$RF_EVID" ] && [ "${#RF_TARGETS[@]}" -ge 1 ] || rf_usage
[ "${#RF_TARGETS[@]}" -le "$H_MAX_PKGS" ] || { echo "too many targets" >&2; rf_usage; }
RF_NAMES=()
for t in "${RF_TARGETS[@]}"; do
    [[ "$t" =~ $tre ]] && [ "${#BASH_REMATCH[1]}" -le 48 ] || { echo "bad --target [$t] (expected NAME:ARCH:VERSION of a synthetic package)" >&2; rf_usage; }
    for e in "${RF_NAMES[@]+"${RF_NAMES[@]}"}"; do [ "$e" = "${BASH_REMATCH[1]}:${BASH_REMATCH[3]}" ] && { echo "duplicate --target" >&2; rf_usage; }; done
    RF_NAMES[${#RF_NAMES[@]}]="${BASH_REMATCH[1]}:${BASH_REMATCH[3]}"
done
case "$RF_RUN_DIR" in "$H_BASE"/sinter-h-*) ;; *) echo "the run directory must be under $H_BASE and named sinter-h-*" >&2; rf_usage ;; esac
case "$RF_RUN_DIR" in *..*|*$'\n'*|*';'*) echo "bad --run-dir" >&2; rf_usage ;; esac
case "$RF_EVID" in /*) ;; *) echo "--evidence-dir must be absolute" >&2; rf_usage ;; esac
h_assert_test_isolation || exit 70
h_check_dir "$H_BASE" || { echo "unsafe base directory" >&2; exit 1; }

# ---- private evidence directory (nothing else is touched before this exists) ------------------
[ -d "$RF_EVID" ] && [ ! -L "$RF_EVID" ] && [ -O "$RF_EVID" ] && [ -w "$RF_EVID" ] || { echo "RECOVERY FAILED: the evidence directory is not usable (must exist, not a symlink, owned by you, writable)" >&2; exit 1; }
RF_EV="$(mktemp -d "$RF_EVID/recovery.XXXXXX")" && [ -d "$RF_EV" ] && [ ! -L "$RF_EV" ] && chmod 700 "$RF_EV" || { echo "RECOVERY FAILED: cannot create the private evidence directory" >&2; exit 1; }
H_RUNDIR="$RF_EV"; H_REGFILE="$RF_EV/registry"
: > "$RF_EV/steps.tsv" && printf 'run_id\t%s\n' "$RF_RUN_ID" > "$RF_EV/phases.tsv" || { echo "RECOVERY FAILED: cannot write the evidence" >&2; exit 1; }
trap 'rc=$?; if [ "$RF_STATUS_WRITTEN" != 1 ] && [ "$rc" != 0 ]; then echo "RECOVERY ABORTED (exit $rc): the state is kept" >&2; fi' EXIT
note "recovery of run $RF_RUN_ID; targets: ${RF_TARGETS[*]}; evidence $RF_EV"
rf_phase start

# a previous recovery of this run that did not reach `final` is reported (never completed automatically)
for pd in "$RF_EVID"/recovery.*/phases.tsv; do
    [ -f "$pd" ] && [ "$pd" != "$RF_EV/phases.tsv" ] || continue
    if [ "$(sed -n 1p "$pd")" = "$(printf 'run_id\t%s' "$RF_RUN_ID")" ] && [ "$(tail -1 "$pd")" != final ]; then
        note "an earlier recovery of this run (${pd%/phases.tsv}) stopped at the phase [$(tail -1 "$pd")]: it is NOT completed automatically"
    fi
done

# ---- exclusion (the same stable file and functions as the scenarios) and the state of THAT run ----
if rf_fault lock-foreign-owner; then h_my_uid() { echo 4242; }; fi     # test builds only: a file of another user needs root to create
h_env_paths
if h_legacy_lock_present; then
    rf_fail "LEGACY_LOCK: an old-format lock exists [$(h_clip "$H_LEGACY_PATH" 120)] (old format, contract v1-v3): it is not interpreted, released or taken over; a human must review it"
fi
h_env_enter; rc=$?
case "$rc" in
    0) ;;
    1) rf_fail "BUSY: a running scenario or another recovery holds the exclusion: it is not taken over" ;;
    *) rf_fail "$H_ENV_MSG" ;;
esac
rf_phase exclusion-held
rf_lock_verify() {  # 0 only if the state record, the run directory and the failed status all belong together; sets RF_LOCK_FP / RF_LOCK_CONTENT
    local content pid rid uid rd nonce fs
    h_state_read; RF_LOCK_STATE="$H_ST_STATE"
    case "$H_ST_STATE" in
        UNKNOWN) RF_WHY="UNKNOWN: the state record is unreadable, malformed or not a plain file: it is NOT repaired automatically"; return 1 ;;
        UNLOCKED|RECOVERED)
            RF_WHY="the state is $H_ST_STATE: nothing to recover"
            return 1 ;;
        ABSENT) RF_WHY="UNKNOWN: there is no state record (it was lost): the environment is not trusted, nothing is recovered or re-initialised automatically"; return 1 ;;
        RECOVERY_IN_PROGRESS) RF_WHY="the state is RECOVERY_IN_PROGRESS: an earlier recovery was interrupted; a human must review it, it is NOT continued automatically"; return 1 ;;
        PACKAGES_RECOVERED_LOCK_PENDING) RF_WHY="the state is PACKAGES_RECOVERED_LOCK_PENDING: an earlier recovery removed the packages but did not seal the state; a human must review the evidence, it is NOT completed automatically"; return 1 ;;
        RUNNING) [ "$RF_ALLOW_ORPHAN" = 1 ] || { RF_WHY="the state is RUNNING and nobody holds the exclusion (the run was killed): recovering it needs --allow-orphan"; return 1; } ;;
        FAILED_LOCKED) ;;
        *) RF_WHY="UNKNOWN state [$H_ST_STATE]"; return 1 ;;
    esac
    content="$H_ST_RAW"; rid="$H_ST_RUN_ID"; uid="$H_ST_UID"; rd="$H_ST_RUN_DIR"; nonce="$H_ST_NONCE"
    [ "$rid" = "$RF_RUN_ID" ] || { RF_WHY="the state record belongs to run [$rid], not [$RF_RUN_ID]"; return 1; }
    [ "$uid" = "$RF_ME" ] || { RF_WHY="the state record was written by uid $uid, you are $RF_ME"; return 1; }
    [ "$rd" = "$RF_RUN_DIR" ] || { RF_WHY="the state record names another run directory"; return 1; }
    [ -d "$rd" ] && [ ! -L "$rd" ] && [ -O "$rd" ] && [ "$(h_stat_mode "$rd")" = 700 ] || { RF_WHY="the run directory is not usable (missing / symlink / not yours / not mode 700)"; return 1; }
    [ -f "$rd/lock-nonce" ] && [ ! -L "$rd/lock-nonce" ] && [ "$(cat "$rd/lock-nonce")" = "$nonce" ] || { RF_WHY="the run directory does not carry this state record's nonce: the record and the run directory do not belong together"; return 1; }
    fs="$rd/final-status.tsv"
    if [ "$H_ST_STATE" = FAILED_LOCKED ]; then
        [ -f "$fs" ] && [ ! -L "$fs" ] && grep -qx $'cleanup\tfailed' "$fs" || { RF_WHY="the run did not end with 'cleanup failed' (final-status.tsv missing or different)"; return 1; }
    fi
    [ -f "$rd/registry" ] && [ ! -L "$rd/registry" ] && [ -f "$rd/snap.base" ] && [ ! -L "$rd/snap.base" ] || { RF_WHY="the run directory lacks its registry or baseline snapshot"; return 1; }
    RF_LOCK_CONTENT="$content"; RF_REC_NOW="$content"; RF_SEQ="$H_ST_SEQ"; RF_ORIG_STATE="$H_ST_STATE"
    RF_LOCK_FP="$(printf '%s' "$content" | rf_sha)"
    return 0
}

rf_foreign_arch_same() {  # the foreign architectures equal the failed run's baseline (the tool changes packages only, never architectures)
    [ -f "$RF_RUN_DIR/foreign.base" ] && [ ! -L "$RF_RUN_DIR/foreign.base" ] || { RF_WHY="the failed run has no foreign-architecture baseline"; return 1; }
    h_run "foreign-arch" "$H_DPKG" --print-foreign-architectures || { RF_WHY="cannot read the foreign architectures"; return 1; }
    [ "$H_RC" = 0 ] && [ ! -s "$H_ERRF" ] && h_text_ok "$H_OUTF" || { RF_WHY="the foreign architectures could not be read cleanly"; return 1; }
    cmp -s "$H_OUTF" "$RF_RUN_DIR/foreign.base" || { RF_WHY="the foreign architectures differ from the failed run's baseline (architecture changes are outside this tool: needs a reviewed plan)"; return 1; }
    return 0
}

rf_mounts_clear() {  # no wrapper mount / marker on the dpkg programs
    local p
    for p in "$H_DPKG_TARGET" "$H_DPKGQ_TARGET"; do
        if "$H_FINDMNT" -n -M "$p" > /dev/null 2>&1; then RF_WHY="$p is a mount point (a wrapper mount remains)"; return 1; fi
        if h_is_shim "$p"; then RF_WHY="$p is a harness wrapper"; return 1; fi
    done
    return 0
}

# ---- R2-2: the pre-recovery `dpkg --audit` ------------------------------------------------------
# A  the command itself failed (could not run, no output captured, exit status != 0, anything on stderr, output not saved or not
#    read back identically)                                         -> stop, no purge
# C  it ran, exit 0, nothing on stderr, EMPTY output                 -> normal, saved
# B  it ran, exit 0, nothing on stderr, output = exactly the one report this tool knows ("only half installed", observed once on
#    dpkg 1.22.6: see 04-audit-format.md) listing only explicit targets whose state is half-installed, and listing ALL of them
#                                                                   -> saved, diagnostics matched with the targets' states
#    any other report, header, package or state                     -> stop (not guessed)
# NOT VERIFIED on a real host: whether dpkg --audit exits 0 when it reports half-installed packages.  If it exits non-zero the
# tool stops (A): the safe direction.
RF_AUDIT_H1='The following packages are only half installed, due to problems during'
RF_AUDIT_H2='installation.  The installation can probably be completed by retrying it;'
RF_AUDIT_H3='the packages can be removed using dselect or dpkg --remove:'
rf_audit_pre() {
    local rc line n=0 stage=0 listed=() name desc i expect=() ok
    if rf_fault audit-nocapture; then h_run() { H_RC=125; H_OUTF=""; H_ERRF=""; return 1; }; fi
    h_run "audit-pre" h_sudo_run "$H_DPKG" --audit || { RF_WHY="dpkg --audit could not be executed (no capture files could be created): purge refused"; return 1; }
    rc="$H_RC"
    if rf_fault audit-stdout-missing; then rm -f "$H_OUTF"; fi
    if rf_fault audit-stderr-missing; then rm -f "$H_ERRF"; fi
    [ -f "$H_OUTF" ] && [ ! -L "$H_OUTF" ] || { RF_WHY="the standard output of dpkg --audit was not obtained: purge refused"; return 1; }
    [ -f "$H_ERRF" ] && [ ! -L "$H_ERRF" ] || { RF_WHY="the standard error of dpkg --audit was not obtained: purge refused"; return 1; }
    if rf_fault audit-save; then RF_SAVE_FAIL=1; else RF_SAVE_FAIL=0; fi
    if [ "$RF_SAVE_FAIL" = 1 ] || ! { cp "$H_OUTF" "$RF_EV/audit-pre.out" && cp "$H_ERRF" "$RF_EV/audit-pre.err" && printf '%s\n' "$rc" > "$RF_EV/audit-pre.rc"; } 2> /dev/null; then
        RF_WHY="the output of dpkg --audit could not be saved to the evidence: purge refused"; return 1
    fi
    if rf_fault audit-readback; then printf x >> "$RF_EV/audit-pre.out"; fi
    cmp -s "$H_OUTF" "$RF_EV/audit-pre.out" && cmp -s "$H_ERRF" "$RF_EV/audit-pre.err" && [ "$(cat "$RF_EV/audit-pre.rc" 2> /dev/null)" = "$rc" ] || { RF_WHY="the saved output of dpkg --audit reads back differently: purge refused"; return 1; }
    [ "$rc" = 0 ] || { RF_WHY="dpkg --audit exited with status $rc (the command failed; this is not interpreted as a diagnostic): purge refused"; return 1; }
    [ ! -s "$H_ERRF" ] || { RF_WHY="dpkg --audit wrote to stderr [$(h_err_summary "$H_ERRF")]: purge refused"; return 1; }
    h_text_ok "$H_OUTF" || { RF_WHY="the output of dpkg --audit is not clean text: purge refused"; return 1; }
    if [ ! -s "$H_OUTF" ]; then record "pre:dpkg-audit" ok "C: ran, exit 0, empty (normal)"; return 0; fi
    # B: only the one known report
    while IFS= read -r line; do
        case "$stage" in
            0) [ "$line" = "$RF_AUDIT_H1" ] || { RF_WHY="dpkg --audit reports something this tool does not know (first line [$(h_clip "$line" 60)]): purge refused"; return 1; }; stage=1 ;;
            1) [ "$line" = "$RF_AUDIT_H2" ] || { RF_WHY="dpkg --audit: the report header differs from the known one: purge refused"; return 1; }; stage=2 ;;
            2) [ "$line" = "$RF_AUDIT_H3" ] || { RF_WHY="dpkg --audit: the report header differs from the known one: purge refused"; return 1; }; stage=3 ;;
            3) if [[ "$line" =~ ^\ ([a-z0-9][a-z0-9+.-]*)\ +(.*)$ ]]; then
                   name="${BASH_REMATCH[1]}"; desc="${BASH_REMATCH[2]}"
                   [ "$desc" = "synthetic package for Sinter removal tests" ] || { RF_WHY="dpkg --audit lists [$name] with an unexpected description: purge refused"; return 1; }
                   listed[${#listed[@]}]="$name"
               elif [ -z "$line" ]; then stage=4
               else RF_WHY="dpkg --audit: an unexpected line inside the package list: purge refused"; return 1; fi ;;
            4) RF_WHY="dpkg --audit: more than the one known report (text after the list): purge refused"; return 1 ;;
        esac
    done < "$H_OUTF"
    [ "$stage" -ge 3 ] && [ "${#listed[@]}" -ge 1 ] || { RF_WHY="dpkg --audit: the known report is incomplete: purge refused"; return 1; }
    # every listed package is an explicit target in a half-installed state; every half-installed target is listed
    for name in "${listed[@]}"; do
        ok=0
        for i in "${!RF_TNAMES[@]}"; do
            if [ "${RF_TNAMES[$i]}" = "$name" ]; then
                case "${RF_TSTATES[$i]}" in ?H?) ok=1 ;; esac
            fi
        done
        [ "$ok" = 1 ] || { RF_WHY="dpkg --audit lists [$name], which is not an explicit target in a half-installed state: purge refused"; return 1; }
    done
    for i in "${!RF_TNAMES[@]}"; do
        case "${RF_TSTATES[$i]}" in
            ?H?) ok=0; for name in "${listed[@]}"; do [ "$name" = "${RF_TNAMES[$i]}" ] && ok=1; done
                 [ "$ok" = 1 ] || { RF_WHY="the target ${RF_TNAMES[$i]} is half-installed but dpkg --audit does not list it: inconsistent, purge refused"; return 1; } ;;
        esac
    done
    record "pre:dpkg-audit" ok "B: ran, exit 0, the known half-installed report for explicit targets only (${listed[*]})"
    return 0
}

# ======================= pre-checks (nothing is changed) =======================
rf_lock_verify || rf_fail "$RF_WHY"
record "pre:lock" ok "state $RF_LOCK_STATE verified (fingerprint $RF_LOCK_FP)"
if rf_fault owner-save; then mkdir "$RF_EV/lock-owner.copy"; fi     # test builds only: the copy of the owner record can not be written
cp /dev/null "$RF_EV/lock-owner.copy" && printf '%s\n' "$RF_LOCK_CONTENT" > "$RF_EV/lock-owner.copy" 2> /dev/null && [ "$(cat "$RF_EV/lock-owner.copy")" = "$RF_LOCK_CONTENT" ] || rf_fail "the state record could not be saved to the evidence"
rf_mounts_clear || rf_fail "$RF_WHY"
record "pre:no-wrapper-mounts" ok ok
rf_foreign_arch_same || rf_fail "$RF_WHY"
record "pre:foreign-architectures-equal-baseline" ok ok
h_wrappers_clear || rf_fail "a wrapper is installed"

# the targets must be in the failed run's registry (name, arch, version)
RF_REG="$RF_RUN_DIR/registry"
for t in "${RF_TARGETS[@]}"; do
    IFS=: read -r n a v <<< "$t"
    grep -qxF "$(printf '%s\t%s\t%s' "$n" "$a" "$v")" "$RF_REG" || rf_fail "target $t is not in the registry of run $RF_RUN_ID (name, arch and version must all match)"
done
# order: the reverse of the failed run's registration order
RF_ORDER=()
while IFS=$'\t' read -r n a v; do
    for t in "${RF_TARGETS[@]}"; do [ "$t" = "$n:$a:$v" ] && RF_ORDER=("$n:$a:$v" "${RF_ORDER[@]+"${RF_ORDER[@]}"}"); done
done < "$RF_REG"
[ "${#RF_ORDER[@]}" -eq "${#RF_TARGETS[@]}" ] || rf_fail "the targets could not be ordered from the registry (duplicates?)"
# the library's own registry/allowlist state, built from the VERIFIED explicit targets only
H_REG=(); H_REG_VER=(); H_PAYLOAD_ALLOW=(); : > "$H_REGFILE"
for t in "${RF_ORDER[@]}"; do
    IFS=: read -r n a v <<< "$t"
    H_PAYLOAD_ALLOW[${#H_PAYLOAD_ALLOW[@]}]="$n:$a"
done
for t in $(printf '%s\n' "${RF_ORDER[@]}" | awk '{a[NR]=$0} END{for(i=NR;i>=1;i--) print a[i]}'); do   # registration order = reverse of the purge order
    IFS=: read -r n a v <<< "$t"
    H_REG[${#H_REG[@]}]="$n:$a"; H_REG_VER[${#H_REG_VER[@]}]="$v"
    printf '%s\t%s\t%s\n' "$n" "$a" "$v" >> "$H_REGFILE"
done

h_snapshot pre || rf_fail "the package listing could not be read and validated"
cp "$H_RUNDIR/snap.pre" "$RF_EV/snap-pre.tsv" 2> /dev/null || rf_fail "cannot save the pre-state"
# no other synthetic package may exist
others="$(awk -F'\t' '$2 ~ /^sinter-t-/ {print $2 ":" $3 ":" $4}' "$H_RUNDIR/snap.pre" | LC_ALL=C sort)"
want_t="$(printf '%s\n' "${RF_TARGETS[@]}" | LC_ALL=C sort)"
[ "$others" = "$want_t" ] || rf_fail "the synthetic packages present [$(printf '%s' "$others" | tr '\n' ' ')] are not exactly the explicit targets [$(printf '%s' "$want_t" | tr '\n' ' ')]"
record "pre:only-the-targets-exist" ok ok
# the rest of the database equals the failed run's baseline
h_nonreg pre > "$RF_EV/nonreg-pre.tsv" 2> /dev/null || rf_fail "cannot compute the non-target records"
LC_ALL=C sort "$RF_RUN_DIR/snap.base" > "$RF_EV/base-sorted.tsv" 2> /dev/null || rf_fail "cannot read the baseline of the failed run"
cmp -s "$RF_EV/nonreg-pre.tsv" "$RF_EV/base-sorted.tsv" || rf_fail "the package database (without the targets) differs from the failed run's baseline: something else changed"
record "pre:database-equals-baseline-without-targets" ok ok
# every target: identity, Maintainer, Essential, state (the purge itself re-verifies version / Essential / state / dry-run)
for t in "${RF_ORDER[@]}"; do
    IFS=: read -r n a v <<< "$t"
    h_query_pkg "$n" "$a" || rf_fail "cannot establish the state of $n:$a"
    [ "$H_PSTATE" != absent ] || rf_fail "$n:$a is already absent: nothing to recover for it (the explicit targets must all exist)"
    [ "$H_PVER" = "$v" ] || rf_fail "$n:$a has the version [$H_PVER], not [$v]"
    [ "$H_PESS" != yes ] || rf_fail "$n:$a is Essential"
    case "$H_PSTATE" in "ii "|"ri "|"pi "|"rH "|"pH "|"iH "|?c?) ;; *) rf_fail "$n:$a is in the state [$H_PSTATE]: it needs a reviewed plan" ;; esac
    RF_TNAMES[${#RF_TNAMES[@]}]="$n"; RF_TSTATES[${#RF_TSTATES[@]}]="$H_PSTATE"
    h_run "maintainer:$n" "$H_DPKG_QUERY" -W -f='${Maintainer}\n' -- "$n" || rf_fail "cannot read the Maintainer of $n"
    [ "$H_RC" = 0 ] && [ ! -s "$H_ERRF" ] && [ "$(cat "$H_OUTF")" = 'Sinter Test <test@example.invalid>' ] || rf_fail "$n is not a synthetic package of the harness (Maintainer differs)"
    record "pre:target:$t" ok "state [$H_PSTATE]"
done
rf_audit_pre || rf_fail "$RF_WHY"
rf_phase prechecks-passed
rf_hold before-enter
if rf_fault kill-before-enter; then kill -9 $$; fi
if rf_fault chmod-base-before-enter; then chmod 500 "$H_STATE_DIR"; fi     # test builds only: the state record can not be replaced
rf_state_set RECOVERY_IN_PROGRESS || rf_fail "the state RECOVERY_IN_PROGRESS could not be recorded (compare-and-set failed: the state changed, or the exclusion file was replaced): nothing was purged"
rf_phase state-entered
record "state:RECOVERY_IN_PROGRESS" ok "seq $RF_SEQ"
if rf_fault fail-after-enter-readonly; then chmod 500 "$H_STATE_DIR"; fi     # test builds only: the original state can not be put back
if rf_fault fail-after-enter || rf_fault fail-after-enter-readonly; then rf_fail "injected failure after the first transition (test build)"; fi
rf_hold after-enter
if rf_fault kill-after-enter; then kill -9 $$; fi

# ======================= removal: the library's single path, first failure stops =======================
rf_phase purge-started
for t in "${RF_ORDER[@]}"; do
    IFS=: read -r n a v <<< "$t"
    RF_PURGES=$((RF_PURGES + 1))
    h_purge_one "$n:$a" || rf_fail "the purge of $n:$a failed or did not complete (no further purge was attempted)"
    record "purge:$t" ok removed
done
rf_phase purges-done
if rf_fault kill-after-purge; then kill -9 $$; fi

# ======================= post-checks: ALL must hold =======================
for t in "${RF_ORDER[@]}"; do
    IFS=: read -r n a v <<< "$t"
    h_query_pkg "$n" "$a" || rf_fail "cannot establish the state of $n:$a after the purge"
    if [ "$H_PSTATE" != absent ] && ! h_state_gone "$H_PSTATE"; then rf_fail "$n:$a is still there after the purge (state [$H_PSTATE])"; fi
done
record "post:targets-gone" ok ok
h_snapshot post || rf_fail "the package listing after the purge could not be read and validated"
cp "$H_RUNDIR/snap.post" "$RF_EV/snap-post.tsv" 2> /dev/null || rf_fail "cannot save the post-state"
h_compare_nonreg pre post || rf_fail "a package other than the targets changed during the recovery: ${H_DIFF:-?}"
record "post:no-other-package-changed" ok ok
h_run "audit-post" h_sudo_run "$H_DPKG" --audit || rf_fail "cannot run dpkg --audit"
cp "$H_OUTF" "$RF_EV/audit-post.out" 2> /dev/null; cp "$H_ERRF" "$RF_EV/audit-post.err" 2> /dev/null
[ "$H_RC" = 0 ] && [ ! -s "$H_OUTF" ] && [ ! -s "$H_ERRF" ] || rf_fail "dpkg --audit failed or reports problems (exit $H_RC)"
record "post:dpkg-audit-clean" ok ok
cmp -s "$H_RUNDIR/snap.post" "$RF_EV/base-sorted.tsv" || rf_fail "the package database does not equal the failed run's baseline"
record "post:database-equals-baseline" ok ok
rf_mounts_clear || rf_fail "$RF_WHY"
[ -z "$H_MOUNT_RESIDUE" ] || rf_fail "a recorded wrapper mount remains"
record "post:no-wrapper-mounts" ok ok
rf_foreign_arch_same || rf_fail "$RF_WHY"
record "post:foreign-architectures-equal-baseline" ok ok
# evidence: the report is written, read back and compared before the lock is touched
rep="$(printf 'run_id\t%s\nrun_dir\t%s\ntargets\t%s\npurge_commands\t%s\npre_snapshot_sha256\t%s\npost_snapshot_sha256\t%s\n' "$RF_RUN_ID" "$RF_RUN_DIR" "${RF_TARGETS[*]}" "$RF_PURGES" "$(rf_sha < "$RF_EV/snap-pre.tsv")" "$(rf_sha < "$RF_EV/snap-post.tsv")")"
printf '%s\n' "$rep" > "$RF_EV/recovery-report.tsv" 2> /dev/null && [ "$(cat "$RF_EV/recovery-report.tsv" 2> /dev/null)" = "$rep" ] || rf_fail "the evidence could not be saved (the report was not written or not read back identically)"
record "post:evidence-saved" ok ok

# ======================= packages are recovered; the exclusion is still held, the state is not yet sealed =======================
RF_PKG_RECOVERED=yes
rf_phase postchecks-passed
rf_state_set PACKAGES_RECOVERED_LOCK_PENDING || rf_fail "the state PACKAGES_RECOVERED_LOCK_PENDING could not be recorded (compare-and-set failed): the state stays as it is, new runs stay refused"
rf_phase state-pending
rf_write_status PACKAGES_RECOVERED_LOCK_PENDING "all post-checks passed; the state is not sealed yet (no new run is allowed)" || rf_fail "the interim status (packages recovered, state not sealed) could not be saved: the state stays PACKAGES_RECOVERED_LOCK_PENDING and new runs stay refused"
rf_hold before-seal
if rf_fault kill-before-seal; then kill -9 $$; fi
if rf_fault chmod-before-seal; then chmod 500 "$RF_EV"; fi
if rf_fault chmod-base-before-seal; then chmod 500 "$H_STATE_DIR"; fi     # test builds only: the state record can not be replaced
# the final evidence is saved and read back BEFORE the state is sealed: RECOVERED always implies it exists
fin="$(printf 'result\tPACKAGES_RECOVERED_SEALING\nrun_id\t%s\nrun_dir\t%s\ntargets\t%s\npurge_commands\t%s\nstate_before_seal\tPACKAGES_RECOVERED_LOCK_PENDING\nstate_record_seq\t%s\n' "$RF_RUN_ID" "$RF_RUN_DIR" "${RF_TARGETS[*]}" "$RF_PURGES" "$RF_SEQ")"
printf '%s\n' "$fin" > "$RF_EV/recovery-final.tsv" 2> /dev/null && [ "$(cat "$RF_EV/recovery-final.tsv" 2> /dev/null)" = "$fin" ] || rf_fail "the final evidence could not be saved and read back: the state is NOT sealed (it stays PACKAGES_RECOVERED_LOCK_PENDING, new runs stay refused)"
record "post:final-evidence-saved" ok ok
if rf_fault seal-fail; then h_state_cas() { return 1; }; fi
rf_state_set RECOVERED || rf_fail "the state could not be sealed as RECOVERED (compare-and-set failed): it stays PACKAGES_RECOVERED_LOCK_PENDING, new runs stay refused"
rf_phase sealed
if rf_fault kill-after-seal; then kill -9 $$; fi
if rf_fault chmod-after-seal; then chmod 500 "$RF_EV"; fi
rf_write_status RECOVERED "packages recovered and the state sealed as RECOVERED" || { echo "RECOVERY: the packages are recovered and the state is sealed (new runs are allowed), but the FINAL status could not be saved (recovery-final.tsv and the interim status PACKAGES_RECOVERED_LOCK_PENDING remain in $RF_EV)" >&2; exit 1; }
rf_phase final
echo "RECOVERY OK: ${RF_TARGETS[*]} removed; state sealed as RECOVERED; final status saved; evidence $RF_EV"
exit 0
