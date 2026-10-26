#!/bin/bash
# safe-lib.sh -- safety layer for the destructive steps of the Sinter real-host scenarios.
#
# Written after the 2026-10-24 ubuntu24 incident (a harness cleanup purged real packages).
# Contract: 03-safety-contract.md.  Every rule below has a test in tests/ (failure injection).
#
#  * A package is purged only if THIS run registered it (h_install_deb) AND it is in the scenario's
#    static allowlist (H_PAYLOAD_ALLOW).  Nothing is ever derived from a package listing.
#  * No --force-* option appears in this file or in any scenario (lint-harness.sh enforces it).
#    If a package cannot be removed normally the cleanup STOPS and reports; there is no escalation.
#  * Every query is validated (exit status, empty stderr, clean ASCII text, complete lines, strict
#    record syntax).  An empty answer is only accepted where "empty" is the documented success answer.
#  * Every call gets its own private files (mktemp inside a 0700 run directory); a stale file can
#    never be read back.
#  * A failed cleanup is a failed run: it is recorded separately from the scenario result, it keeps
#    the state record FAILED_LOCKED (the next run refuses to start) and it changes the exit status.
#
# Compatible with bash 3.2 and bash 5.  No `set -e`: every failure is handled explicitly.

H_LIB_VERSION=2
H_ABORTED=0          # 1 = no further mutation is allowed
H_FAILED=0           # 1 = at least one harness-level failure was recorded
H_CLEANUP_STATUS="not-run"   # not-run | ok | failed
H_FINISHED=0
H_LOCK_HELD=0
H_STATE_REC=""        # the state record this process wrote last (the expected value of the next compare-and-set)
H_MUTEX_HELD=0       # 1 = this process holds flock(2) on the exclusion file (descriptor 200)
H_ST_SEQ=0
H_RC=125
H_OUTF=""
H_ERRF=""
H_PSTATE=""
H_PESS=""
H_REG=()             # registered "name:arch", in install order
H_REG_VER=()         # the version registered for the same index (from the payload file name, checked against the .deb)
H_PVER=""            # version of the record found by the last h_query_pkg
H_MOUNT_RESIDUE=""   # non-empty: a wrapper mount could not be removed; every mutation and the cleanup are refused
H_ARMED=()           # package names whose failure flag is armed
H_PAYLOAD_ALLOW=()   # the scenario's static allowlist ("name:arch")

: "${H_BASE:=/var/tmp}"
: "${H_STATE_DIR:=/var/lib/sinter-harness}"     # the persistent state of the run exclusion (NOT in /var/tmp: that is cleaned automatically)
: "${H_MAX_PKGS:=12}"
: "${H_MIN_PKGS:=50}"
: "${H_ARCHES:=all amd64 i386}"
: "${H_DPKG:=/usr/bin/dpkg}"
: "${H_DPKG_QUERY:=/usr/bin/dpkg-query}"
: "${H_DPKG_DEB:=/usr/bin/dpkg-deb}"
: "${H_FINDMNT:=findmnt}"
: "${H_FLAGDIR:=/var/tmp/sinter-h-flags}"
: "${H_SHRINK_PERCENT:=5}"
declare -p H_SUDO > /dev/null 2>&1 || H_SUDO=()

H_SNAP_FMT='${db:Status-Abbrev}\t${Package}\t${Architecture}\t${Version}\t${Essential}\n'

# ---- reporting ---------------------------------------------------------------------------------
h_note() { if declare -F note > /dev/null 2>&1; then note "$*"; else printf 'H_NOTE\t%s\n' "$*" >&2; fi; }
h_clip() { printf '%s' "$1" | head -c "${2:-80}" | LC_ALL=C tr -c '[:print:]' '?'; }
h_fail() {  # h_fail STEP DETAIL -> records a failure (does not stop by itself)
    H_FAILED=1
    if declare -F record > /dev/null 2>&1; then record "$1" "ok" "FAILED: $2"; else printf 'H_FAIL\t%s\t%s\n' "$1" "$2" >&2; fi
}
h_abort() {  # h_abort REASON -> no further mutation is allowed
    H_ABORTED=1
    h_fail "ABORT" "$1"
}
h_guard() {  # h_guard STEP -> refuse to mutate after an abort or while a wrapper mount could not be removed
    if [ "$H_ABORTED" = 1 ]; then h_fail "$1" "refused: the harness is aborted"; return 1; fi
    if [ -n "$H_MOUNT_RESIDUE" ]; then h_fail "$1" "refused: a wrapper mount remains [$(h_clip "$H_MOUNT_RESIDUE" 120)]"; return 1; fi
    return 0
}
h_sudo_run() { if [ "${#H_SUDO[@]}" -gt 0 ]; then "${H_SUDO[@]}" "$@"; else "$@"; fi; }

# ---- validators --------------------------------------------------------------------------------
h_valid_name() {
    local re='^sinter-t-[a-z0-9]+(-[a-z0-9]+)*$'
    [[ "$1" =~ $re ]] && [ "${#1}" -le 48 ]
}
h_valid_arch() {
    local a
    for a in $H_ARCHES; do [ "$1" = "$a" ] && return 0; done
    return 1
}
h_valid_spec() {  # exactly name:arch
    local s="$1" n a
    case "$s" in *:*:*|:*|*:|"") return 1 ;; esac
    case "$s" in *:*) ;; *) return 1 ;; esac
    n="${s%%:*}"; a="${s#*:}"
    h_valid_name "$n" && h_valid_arch "$a"
}
h_in_allowlist() {
    local x
    for x in "${H_PAYLOAD_ALLOW[@]+"${H_PAYLOAD_ALLOW[@]}"}"; do [ "$x" = "$1" ] && return 0; done
    return 1
}
h_is_registered() {
    local x
    for x in "${H_REG[@]+"${H_REG[@]}"}"; do [ "$x" = "$1" ] && return 0; done
    return 1
}
h_reg_ver() {  # h_reg_ver name:arch -> prints the version registered for it
    local i=0 x
    for x in "${H_REG[@]+"${H_REG[@]}"}"; do
        if [ "$x" = "$1" ] && [ -n "${H_REG_VER[$i]:-}" ]; then printf '%s\n' "${H_REG_VER[$i]}"; return 0; fi
        i=$((i + 1))
    done
    return 1
}

# ---- file-system checks ------------------------------------------------------------------------
h_stat_mode() {
    local m
    m="$(stat -c %a "$1" 2> /dev/null)" && [ -n "$m" ] && { printf '%s\n' "$m"; return 0; }
    m="$(stat -f %Lp "$1" 2> /dev/null)" && [ -n "$m" ] && { printf '%s\n' "$m"; return 0; }
    return 1
}
h_stat_uid() {
    local u
    u="$(stat -c %u "$1" 2> /dev/null)" && [ -n "$u" ] && { printf '%s\n' "$u"; return 0; }
    u="$(stat -f %u "$1" 2> /dev/null)" && [ -n "$u" ] && { printf '%s\n' "$u"; return 0; }
    return 1
}
h_check_dir() {  # exists, not a symlink, owned by root or me, group/world-writable only with the sticky bit
    local d="$1" m u me last g o first
    me="$(id -u)" || return 1
    [ -n "$d" ] && [ -d "$d" ] && [ ! -L "$d" ] || return 1
    m="$(h_stat_mode "$d")" || return 1
    u="$(h_stat_uid "$d")" || return 1
    [ "$u" = "$me" ] || [ "$u" = 0 ] || return 1
    last="${m: -3}"; g="${last:1:1}"; o="${last:2:1}"; first=0
    [ "${#m}" -ge 4 ] && first="${m:0:1}"
    if [ $((g & 2)) -ne 0 ] || [ $((o & 2)) -ne 0 ]; then
        case "$first" in 1|3|5|7) ;; *) return 1 ;; esac
    fi
    return 0
}
h_text_ok() {  # clean ASCII text only (printable, tab, newline), no NUL/CR/VT/FF, complete last line
    local f="$1" a b
    [ -n "$f" ] && [ -f "$f" ] && [ ! -L "$f" ] || return 1
    [ -s "$f" ] || return 0
    a="$(LC_ALL=C tr -d '\000' < "$f" | wc -c)"; b="$(wc -c < "$f")"
    [ $((a)) -eq $((b)) ] || return 1
    if LC_ALL=C grep -q '[^[:print:][:space:]]' "$f"; then return 1; fi
    if LC_ALL=C grep -q "$(printf '[\r\v\f]')" "$f"; then return 1; fi
    [ "$(tail -c 1 "$f" | od -An -tx1 | tr -d ' \n')" = "0a" ] || return 1
    return 0
}

# ---- run directory, lock, isolation ------------------------------------------------------------
h_assert_test_isolation() {  # H_TEST_MODE=1: no command and no directory may live outside H_TEST_ROOT
    [ "${H_TEST_MODE:-0}" = 1 ] || return 0
    local v p
    [ -n "${H_TEST_ROOT:-}" ] || { h_abort "test mode without H_TEST_ROOT"; return 1; }
    for v in H_DPKG H_DPKG_QUERY H_DPKG_DEB H_BASE H_STATE_DIR H_FLAGDIR H_DPKG_TARGET H_DPKGQ_TARGET H_MOUNT H_UMOUNT H_STDBUF H_FINDMNT H_NS_SELF_LINK H_NS_PID1_LINK H_MOUNTINFO H_PID1_ROOT H_SUDO_BIN H_UNSHARE_BIN H_ENV_BIN; do
        p="${!v:-}"
        case "$p" in "$H_TEST_ROOT"/*) ;; *) h_abort "test mode: $v=$(h_clip "$p") is outside the test root"; return 1 ;; esac
    done
    return 0
}
h_init() {  # h_init RUN_ID -> private run directory + exclusive lock
    local re='^[a-z0-9][a-z0-9-]{2,40}$' rc
    H_RUN_ID="$1"
    [[ "$H_RUN_ID" =~ $re ]] || { h_abort "invalid run id"; return 1; }
    # the namespace gate again, before the lock, the baseline or any package operation (audit F-2: not only at wrapper time)
    declare -F h_ns_require > /dev/null 2>&1 || { h_abort "the namespace gate is not loaded"; return 1; }
    if declare -F h_production > /dev/null 2>&1 && h_production && [ -n "${H_TEST_MODE:-}" ]; then h_abort "H_TEST_MODE is set in a production run"; return 1; fi
    h_ns_require 2> /dev/null || { h_abort "the private mount namespace could not be verified"; return 1; }
    h_assert_test_isolation || return 1
    h_check_dir "$H_BASE" || { h_abort "unsafe base directory"; return 1; }
    # ---- exclusion + state record, contract v4/v5 (R3-1 exclusion, R4-1 persistent state) ------------------------------------
    # See the "persistent environment" block below.  Run AND recovery enter through the same function, h_env_enter: the state
    # directory must exist and be safe, the exclusion file must exist (only the explicit initialisation creates it), flock must
    # be free, the init record and the state record must agree.  A MISSING record is never "fresh": it is UNKNOWN.
    if [ "$H_MUTEX_HELD" = 1 ]; then h_abort "this process already holds the exclusion"; return 1; fi
    if h_legacy_lock_present; then
        h_abort "LEGACY_LOCK: an old-format lock or an old state file exists [$(h_clip "$H_LEGACY_PATH" 120)] (contract v1-v4 in the base directory): it is not interpreted, removed or taken over; a human must review it"
        return 1
    fi
    h_env_enter; rc=$?
    case "$rc" in
        0) ;;
        *) h_abort "$H_ENV_MSG"; return 1 ;;
    esac
    case "$H_ST_STATE" in
        UNLOCKED|RECOVERED) ;;
        RUNNING) h_mutex_drop; h_abort "UNKNOWN: a previous run did not finish (state RUNNING, but nobody holds the exclusion: it was killed); it must be recovered (recover-synthetic.sh --allow-orphan) or reviewed by a human"; return 1 ;;
        FAILED_LOCKED) h_mutex_drop; h_abort "FAILED_LOCKED: a previous run failed and left its state; it must be recovered with recover-synthetic.sh"; return 1 ;;
        RECOVERY_IN_PROGRESS) h_mutex_drop; h_abort "RECOVERY_IN_PROGRESS: a recovery was interrupted; a human must review it, it is not continued automatically"; return 1 ;;
        PACKAGES_RECOVERED_LOCK_PENDING) h_mutex_drop; h_abort "PACKAGES_RECOVERED_LOCK_PENDING: the packages were recovered but the state was not sealed; a human must review the evidence"; return 1 ;;
        *) h_mutex_drop; h_abort "UNKNOWN state [$(h_clip "$H_ST_STATE" 40)]"; return 1 ;;
    esac
    h_new_run_dir || { h_mutex_drop; return 1; }
    H_STATE_REC="$H_ST_RAW"
    if ! h_state_transition RUNNING scenario; then
        # nothing was recorded: remove only what THIS call created, keep nothing half-made
        unlink "$H_RUNDIR/lock-nonce" 2> /dev/null; unlink "$H_REGFILE" 2> /dev/null; rmdir "$H_RUNDIR" 2> /dev/null
        H_RUNDIR=""; H_REGFILE=""; h_mutex_drop
        h_abort "the state record RUNNING could not be written (compare-and-set failed); nothing was changed"
        return 1
    fi
    H_LOCK_HELD=1
    return 0
}
h_new_run_dir() {
    H_RUNDIR="$(mktemp -d "$H_BASE/sinter-h-$H_RUN_ID.XXXXXX")" || { h_abort "cannot create the run directory"; return 1; }
    [ -d "$H_RUNDIR" ] && [ ! -L "$H_RUNDIR" ] && [ -O "$H_RUNDIR" ] || { h_abort "run directory is not private"; return 1; }
    chmod 700 "$H_RUNDIR" || { h_abort "cannot restrict the run directory"; return 1; }
    [ "$(h_stat_mode "$H_RUNDIR")" = 700 ] || { h_abort "run directory mode is not 700"; return 1; }
    H_REGFILE="$H_RUNDIR/registry"
    ( set -C; : > "$H_REGFILE" ) 2> /dev/null || { h_abort "cannot create the registry"; return 1; }
    H_LOCK_NONCE="$(od -An -N16 -tx1 /dev/urandom 2> /dev/null | tr -d ' \n')"
    [[ "$H_LOCK_NONCE" =~ ^[0-9a-f]{32}$ ]] || { h_abort "cannot create a lock nonce"; return 1; }
    ( set -C; printf '%s\n' "$H_LOCK_NONCE" > "$H_RUNDIR/lock-nonce" ) 2> /dev/null || { h_abort "cannot write the lock nonce"; return 1; }
    return 0
}
h_rename_path() {  # h_rename_path SRC DST -> rename(2) of the path itself (a symlink is not followed)
    python3 -I -c 'import os, sys
try:
    os.rename(sys.argv[1], sys.argv[2])
except OSError:
    sys.exit(1)' "$1" "$2"
}
h_my_uid() { id -u; }
# ---- (0) the persistent environment: state directory, init record, "was it initialised?" (R4-1) ---------------------------------
# Nothing that is missing is ever taken for "fresh": a run/recovery starts only in an environment that was initialised
# EXPLICITLY (init-state.sh) and whose three records agree.  A vanished record (an automatic clean-up of /var/tmp, a manual
# delete, a corruption) is UNKNOWN and stops everything; it is never repaired and never re-initialised automatically.
#   $H_STATE_DIR/sinter-h-mutex  the stable flock file (created only by the initialisation)
#   $H_STATE_DIR/sinter-h-init   sinter-init-v5;id=HEX32;phase=started|complete;uid=U;state_dir=DIR;created=UTC
#   $H_STATE_DIR/sinter-h-state  the state record (carries the same init id)
h_env_paths() { H_MUTEX_PATH="$H_STATE_DIR/sinter-h-mutex"; H_STATE_PATH="$H_STATE_DIR/sinter-h-state"; H_INIT_PATH="$H_STATE_DIR/sinter-h-init"; }
h_state_dir_check() {  # 0 usable | 1 absent | 2 unsafe (a symlink, not a directory, not yours, not mode 700, or an unsafe parent)
    local d="$H_STATE_DIR"
    [ -e "$d" ] || [ -L "$d" ] || return 1
    [ -d "$d" ] && [ ! -L "$d" ] && [ -O "$d" ] || return 2
    [ "$(h_stat_mode "$d")" = 700 ] || return 2
    h_check_dir "$(dirname "$d")" || return 2
    return 0
}
H_INIT_RE='^sinter-init-v5;id=([0-9a-f]{32});phase=(started|complete);uid=([0-9]+);state_dir=(/[^;]+);created=([0-9TZ:-]+)$'
h_init_read() {  # sets H_INIT_FILE (ABSENT | CORRUPT | VALID), H_INIT_RAW, H_INIT_ID, H_INIT_PHASE, H_INIT_CREATED
    local p="$H_INIT_PATH" raw
    H_INIT_FILE="ABSENT"; H_INIT_RAW="ABSENT"; H_INIT_ID=""; H_INIT_PHASE=""; H_INIT_CREATED=""
    if [ -L "$p" ] || { [ -e "$p" ] && [ ! -f "$p" ]; }; then H_INIT_FILE="CORRUPT"; return 1; fi
    [ -e "$p" ] || return 0
    { [ -O "$p" ] && [ "$(h_stat_mode "$p")" = 600 ]; } || { H_INIT_FILE="CORRUPT"; return 1; }
    raw="$(head -c 600 "$p" 2> /dev/null)" || { H_INIT_FILE="CORRUPT"; return 1; }
    case "$raw" in *$'\n'*) H_INIT_FILE="CORRUPT"; return 1 ;; esac
    if [[ "$raw" =~ $H_INIT_RE ]] && [ "${BASH_REMATCH[3]}" = "$(h_my_uid)" ] && [ "${BASH_REMATCH[4]}" = "$H_STATE_DIR" ]; then
        H_INIT_FILE="VALID"; H_INIT_RAW="$raw"; H_INIT_ID="${BASH_REMATCH[1]}"; H_INIT_PHASE="${BASH_REMATCH[2]}"; H_INIT_CREATED="${BASH_REMATCH[5]}"
        return 0
    fi
    H_INIT_FILE="CORRUPT"; return 1
}
h_env_classify() {  # needs the exclusion; reads the init record and the state record; sets H_ENV_CLASS and H_ENV_MSG
    h_init_read; h_state_read
    H_ENV_MSG=""
    if [ "$H_INIT_FILE" = CORRUPT ]; then H_ENV_CLASS=UNKNOWN; H_ENV_MSG="UNKNOWN: the init record is unreadable, malformed, not yours or for another directory; it is not repaired automatically"; return 1; fi
    if [ "$H_INIT_FILE" = ABSENT ]; then
        if [ "$H_ST_STATE" = ABSENT ]; then H_ENV_CLASS=INIT_INCOMPLETE; H_ENV_MSG="INIT_INCOMPLETE: the exclusion file exists but there is neither an init record nor a state record (the initialisation was interrupted, or both records were lost): nothing is assumed, no run starts"; return 1; fi
        H_ENV_CLASS=UNKNOWN; H_ENV_MSG="UNKNOWN: a state record exists but the init record is missing (it was lost): the environment is not trusted"; return 1
    fi
    if [ "$H_INIT_PHASE" = started ]; then
        if [ "$H_ST_STATE" = ABSENT ] || { [ "$H_ST_STATE" = UNLOCKED ] && [ "$H_ST_SEQ" = 0 ] && [ "$H_ST_BY" = init ] && [ "$H_ST_INIT" = "$H_INIT_ID" ]; }; then
            H_ENV_CLASS=INIT_INCOMPLETE; H_ENV_MSG="INIT_INCOMPLETE: the initialisation was interrupted (phase started): it must be completed by init-state.sh, no run starts"; return 1
        fi
        H_ENV_CLASS=UNKNOWN; H_ENV_MSG="UNKNOWN: the initialisation was interrupted and the state record is not the initial one"; return 1
    fi
    # the initialisation is complete: the state record MUST exist and carry the same init id
    if [ "$H_ST_STATE" = ABSENT ]; then H_ENV_CLASS=UNKNOWN; H_ENV_MSG="UNKNOWN: the environment was initialised but its state record is MISSING (lost or deleted): it is NOT taken for a fresh environment, nothing is re-initialised automatically; a human must review the host"; return 1; fi
    if [ "$H_ST_STATE" = UNKNOWN ]; then H_ENV_CLASS=UNKNOWN; H_ENV_MSG="UNKNOWN: the state record is unreadable, malformed or not a plain file; it is not repaired automatically"; return 1; fi
    if [ "$H_ST_INIT" != "$H_INIT_ID" ]; then H_ENV_CLASS=UNKNOWN; H_ENV_MSG="UNKNOWN: the state record belongs to another initialisation (init id mismatch)"; return 1; fi
    H_ENV_CLASS=INITIALIZED
    return 0
}
h_env_enter() {  # the one entry for runs AND recoveries: 0 = exclusion held, environment INITIALIZED, state read | 1 = busy | 2 = refused (H_ENV_CLASS, H_ENV_MSG)
    local rc hi=0 hs=0 hm=0
    h_env_paths; H_ENV_CLASS=""; H_ENV_MSG=""
    h_state_dir_check; rc=$?
    case "$rc" in
        1) H_ENV_CLASS=UNINITIALIZED; H_ENV_MSG="UNINITIALIZED: the state directory [$(h_clip "$H_STATE_DIR" 100)] does not exist: the environment was never initialised, or the directory was lost; run init-state.sh (explicit, with the Owner's confirmation); nothing was changed"; return 2 ;;
        2) H_ENV_CLASS=UNKNOWN; H_ENV_MSG="UNKNOWN: the state directory is unsafe (a symbolic link, not a directory, not yours, not mode 700, or an unsafe parent); nothing was changed"; return 2 ;;
    esac
    { [ -e "$H_INIT_PATH" ] || [ -L "$H_INIT_PATH" ]; } && hi=1
    { [ -e "$H_STATE_PATH" ] || [ -L "$H_STATE_PATH" ]; } && hs=1
    { [ -e "$H_MUTEX_PATH" ] || [ -L "$H_MUTEX_PATH" ]; } && hm=1
    if [ "$hm" = 0 ]; then
        if [ "$hi" = 1 ] || [ "$hs" = 1 ]; then H_ENV_CLASS=UNKNOWN; H_ENV_MSG="UNKNOWN: the exclusion file is missing while an init or state record exists (it was removed); nothing is recreated automatically"
        else H_ENV_CLASS=UNINITIALIZED; H_ENV_MSG="UNINITIALIZED: the state directory is empty: the environment was never initialised, or all records were lost; run init-state.sh (explicit, with the Owner's confirmation); nothing was changed"; fi
        return 2
    fi
    h_mutex_acquire; rc=$?
    case "$rc" in
        0) ;;
        1) H_ENV_CLASS=BUSY; H_ENV_MSG="BUSY: another run or a recovery holds the exclusion; nothing was changed"; return 1 ;;
        *) H_ENV_CLASS=UNSAFE; H_ENV_MSG="the exclusion file is unsafe or unusable (not a private regular file of yours, replaced, or cannot be opened); nothing was changed"; return 2 ;;
    esac
    if h_env_classify; then return 0; fi
    h_mutex_drop
    return 2
}
h_env_fault() {  # test builds only: H_INIT_FAULT=NAME injects a failure (kill-* = SIGKILL right here); never active in a production build
    declare -F h_production > /dev/null 2>&1 && ! h_production && [ "${H_INIT_FAULT:-}" = "$1" ] || return 1
    case "$1" in kill-*) kill -9 $$ ;; esac
    return 0
}
h_env_hold() {  # test builds only: wait until the test says go, so that it can act while the initialisation holds the exclusion
    declare -F h_production > /dev/null 2>&1 && ! h_production && [ "${H_INIT_FAULT:-}" = "hold-$1" ] || return 0
    local i=0
    : > "${H_INIT_HOLD_DIR:?}/held-$1"
    while [ ! -e "$H_INIT_HOLD_DIR/go-$1" ] && [ "$i" -lt 600 ]; do sleep 0.1; i=$((i + 1)); done
}
h_mutex_create() {  # 0 created now | 3 existed already | 1 error: ONLY the initialisation creates the exclusion file
    python3 -I -c "$H_PY_MUTEX_CREATE" "$H_MUTEX_PATH"
}
h_env_initialize() {  # explicit, idempotent, never overwrites: 0 ok (H_INIT_RESULT=created|resumed|already) | 1 refused (H_ENV_MSG) | 2 failed
    local id started complete created existed=0 st rc
    h_env_paths; H_INIT_RESULT=""; H_ENV_MSG=""
    h_state_dir_check || { H_ENV_MSG="the state directory is missing or unsafe"; return 1; }
    { [ -e "$H_MUTEX_PATH" ] || [ -L "$H_MUTEX_PATH" ]; } && existed=1
    if h_env_fault fail-create-mutex; then H_ENV_MSG="injected failure: the exclusion file could not be created"; return 2; fi
    if [ "$existed" = 0 ]; then h_mutex_create || { H_ENV_MSG="the exclusion file could not be created"; return 2; }; fi
    h_env_fault kill-after-mutex
    h_mutex_acquire; rc=$?
    case "$rc" in 0) ;; 1) H_ENV_MSG="BUSY: a run, a recovery or another initialisation holds the exclusion"; return 1 ;; *) H_ENV_MSG="the exclusion file is unsafe or unusable"; return 1 ;; esac
    h_env_hold after-mutex
    h_env_classify
    case "$H_ENV_CLASS" in
        INITIALIZED) H_INIT_RESULT=already; h_mutex_drop; return 0 ;;
        INIT_INCOMPLETE) ;;
        *) h_mutex_drop; return 1 ;;
    esac
    if [ "$H_INIT_FILE" = VALID ]; then id="$H_INIT_ID"; created="$H_INIT_CREATED"
    else id="$(od -An -N16 -tx1 /dev/urandom 2> /dev/null | tr -d ' \n')"; created="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; fi
    [[ "$id" =~ ^[0-9a-f]{32}$ ]] || { H_ENV_MSG="cannot create an init id"; h_mutex_drop; return 2; }
    started="sinter-init-v5;id=$id;phase=started;uid=$(h_my_uid);state_dir=$H_STATE_DIR;created=$created"
    complete="sinter-init-v5;id=$id;phase=complete;uid=$(h_my_uid);state_dir=$H_STATE_DIR;created=$created"
    if [ "$H_INIT_FILE" = ABSENT ]; then
        if h_env_fault fail-init-record || ! h_file_cas "$H_INIT_PATH" ABSENT "$started"; then H_ENV_MSG="the init record (phase started) could not be written"; h_mutex_drop; return 2; fi
    fi
    h_env_fault kill-after-init-record
    h_env_hold after-init-record
    if [ "$H_ST_STATE" = ABSENT ]; then
        st="$(h_state_record UNLOCKED init 0 "$$" initial "$(h_my_uid)" "$H_STATE_DIR" "$id" "$id")"
        if h_env_fault fail-state-record || ! h_file_cas "$H_STATE_PATH" ABSENT "$st"; then H_ENV_MSG="the initial state record could not be written"; h_mutex_drop; return 2; fi
    fi
    h_env_fault kill-after-state-record
    if h_env_fault fail-complete || ! h_file_cas "$H_INIT_PATH" "$started" "$complete"; then H_ENV_MSG="the init record could not be completed"; h_mutex_drop; return 2; fi
    h_env_classify || { H_ENV_MSG="after the initialisation the environment is not consistent: $H_ENV_MSG"; h_mutex_drop; return 2; }
    if [ "$existed" = 1 ]; then H_INIT_RESULT=resumed; else H_INIT_RESULT=created; fi
    h_mutex_drop
    return 0
}
# ---- (1) the OS exclusion -------------------------------------------------------------------------------------------------
# A file of the OLD formats (v1 directory, v2 directory + owner, v3 symbolic link, its recovery mutex or tombstones) or the R3
# state files in the BASE directory (sinter-h-state / sinter-h-mutex, which now live in $H_STATE_DIR) means a lock of another
# contract: new work is refused, the old thing is never touched, nothing is migrated automatically.
h_legacy_lock_present() {
    local p
    H_LEGACY_PATH=""
    for p in "$H_BASE/sinter-h-lock" "$H_BASE/sinter-h-lock.recovery" "$H_BASE/sinter-h-state" "$H_BASE/sinter-h-mutex"; do
        if [ -e "$p" ] || [ -L "$p" ]; then H_LEGACY_PATH="$p"; return 0; fi
    done
    p="$(ls -d "$H_BASE"/sinter-h-lock.released.* "$H_BASE"/sinter-h-state.tmp.* 2> /dev/null | head -1)"
    if [ -n "$p" ]; then H_LEGACY_PATH="$p"; return 0; fi
    return 1
}
# Python helper 1: create the stable file if it does not exist (O_EXCL|O_NOFOLLOW, mode 0600); an existing file is left alone.
H_PY_MUTEX_CREATE='import os, sys
try:
    fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
except FileExistsError:
    sys.exit(0)
except OSError:
    sys.exit(3)
try:
    os.fchmod(fd, 0o600)
finally:
    os.close(fd)'
# Python helper 2: lock = flock(LOCK_EX|LOCK_NB) on the inherited descriptor, then verify that the descriptor IS the inode that
# is currently at the path (a regular file, mode 0600, one link, owned by the expected uid).  verify = only the identity check.
# exit: 0 ok | 1 busy | 2 identity mismatch | 3 error
H_PY_MUTEX='import fcntl, os, stat, sys
fd, path, uid, mode = int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), sys.argv[4]
code = 3
try:
    busy = False
    if mode == "lock":
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, PermissionError):
            busy = True
    if busy:
        code = 1
    else:
        a = os.fstat(fd)
        b = os.lstat(path)
        same = stat.S_ISREG(b.st_mode) and (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino) and b.st_uid == uid and b.st_nlink == 1 and stat.S_IMODE(b.st_mode) == 0o600
        code = 0 if same else 2
except OSError:
    code = 3
sys.exit(code)'
h_mutex_acquire() {  # 0 held | 1 busy (nothing changed) | 2 unsafe (nothing changed)
    local p="$H_MUTEX_PATH" rc
    [ -f "$p" ] && [ ! -L "$p" ] || return 2
    # A process that inherited descriptor 200 (a child of a holder) first closes ITS copy: opening onto an occupied descriptor
    # number (dup2) is not a clean "new open file description" on every kernel (observed on Darwin), a close-then-open is.
    { exec 200<&-; } 2> /dev/null
    { exec 200< "$p"; } 2> /dev/null || return 2
    python3 -I -c "$H_PY_MUTEX" 200 "$p" "$(h_my_uid)" lock; rc=$?
    case "$rc" in
        0) H_MUTEX_HELD=1; return 0 ;;
        1) { exec 200<&-; } 2> /dev/null; return 1 ;;
        *) { exec 200<&-; } 2> /dev/null; return 2 ;;
    esac
}
h_mutex_verify() {  # the held descriptor is still the inode at the path
    [ "$H_MUTEX_HELD" = 1 ] || return 1
    python3 -I -c "$H_PY_MUTEX" 200 "$H_MUTEX_PATH" "$(h_my_uid)" verify
}
h_mutex_drop() {  # give up the exclusion (the state record decides what happens next)
    if [ "$H_MUTEX_HELD" = 1 ]; then { exec 200<&-; } 2> /dev/null; fi
    H_MUTEX_HELD=0
}
# ---- (2) the state record -------------------------------------------------------------------------------------------------
#   sinter-state-v5;state=S;seq=N;by=scenario|recovery|init;pid=P;run_id=ID;uid=U;run_dir=DIR;nonce=HEX32;init=HEX32
H_STATE_RE='^sinter-state-v5;state=(RUNNING|FAILED_LOCKED|RECOVERY_IN_PROGRESS|PACKAGES_RECOVERED_LOCK_PENDING|RECOVERED|UNLOCKED);seq=([0-9]+);by=(scenario|recovery|init);pid=([0-9]+);run_id=([a-z0-9-]+);uid=([0-9]+);run_dir=(/[^;]+);nonce=([0-9a-f]{32});init=([0-9a-f]{32})$'
h_state_read() {  # sets H_ST_RAW and H_ST_STATE (ABSENT when there is no file, which is NEVER "fresh"; UNKNOWN when it is not a valid record) and the fields
    local p="$H_STATE_PATH" raw
    H_ST_RAW="ABSENT"; H_ST_STATE="ABSENT"; H_ST_SEQ=0; H_ST_BY=""; H_ST_PID=""; H_ST_RUN_ID=""; H_ST_UID=""; H_ST_RUN_DIR=""; H_ST_NONCE=""; H_ST_INIT=""
    if [ -L "$p" ] || { [ -e "$p" ] && [ ! -f "$p" ]; }; then H_ST_STATE="UNKNOWN"; return 1; fi
    [ -e "$p" ] || return 0
    { [ -O "$p" ] && [ "$(h_stat_mode "$p")" = 600 ]; } || { H_ST_STATE="UNKNOWN"; return 1; }
    raw="$(head -c 600 "$p" 2> /dev/null)" || { H_ST_STATE="UNKNOWN"; return 1; }
    case "$raw" in *$'\n'*) H_ST_STATE="UNKNOWN"; return 1 ;; esac
    if [[ "$raw" =~ $H_STATE_RE ]]; then
        H_ST_RAW="$raw"; H_ST_STATE="${BASH_REMATCH[1]}"; H_ST_SEQ="${BASH_REMATCH[2]}"; H_ST_BY="${BASH_REMATCH[3]}"; H_ST_PID="${BASH_REMATCH[4]}"
        H_ST_RUN_ID="${BASH_REMATCH[5]}"; H_ST_UID="${BASH_REMATCH[6]}"; H_ST_RUN_DIR="${BASH_REMATCH[7]}"; H_ST_NONCE="${BASH_REMATCH[8]}"; H_ST_INIT="${BASH_REMATCH[9]}"
        return 0
    fi
    H_ST_STATE="UNKNOWN"; return 1
}
# Python helper 3: compare-and-set of the state record.  It verifies the exclusion file's identity, compares the CURRENT content
# of the state file with the expected record (ABSENT = no file), writes the new record to a private temp file, fsyncs it and
# replaces the state file with ONE rename(2).  Any failure leaves the old record in place (and removes the own temp file).
# exit: 0 written | 2 exclusion file identity mismatch | 4 state file unusable | 5 compare failed | 6 write failed
H_PY_STATE_CAS='import os, stat, sys
fd, mp, uid, sp, expect, new = int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5], sys.argv[6]
try:
    a = os.fstat(fd)
    b = os.lstat(mp)
    if not (stat.S_ISREG(b.st_mode) and (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino) and b.st_uid == uid and b.st_nlink == 1):
        sys.exit(2)
except OSError:
    sys.exit(2)
try:
    st = os.lstat(sp)
except FileNotFoundError:
    cur = "ABSENT"
except OSError:
    sys.exit(4)
else:
    if not stat.S_ISREG(st.st_mode) or st.st_uid != uid or st.st_nlink != 1:
        sys.exit(4)
    try:
        with open(sp, "rb") as f:
            cur = f.read(600).decode("ascii").rstrip("\n")
    except (OSError, UnicodeDecodeError):
        sys.exit(4)
if cur != expect:
    sys.exit(5)
tmp = "%s.tmp.%d.%s" % (sp, os.getpid(), os.urandom(6).hex())
try:
    t = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(t, 0o600)
        os.write(t, (new + "\n").encode("ascii"))
        os.fsync(t)
    finally:
        os.close(t)
    os.replace(tmp, sp)
    d = os.open(os.path.dirname(sp), os.O_RDONLY)
    try:
        os.fsync(d)
    finally:
        os.close(d)
except OSError:
    try:
        os.unlink(tmp)
    except OSError:
        pass
    sys.exit(6)
sys.exit(0)'
h_file_cas() {  # h_file_cas PATH EXPECTED NEW -> the same compare-and-set for any record file of the state directory
    [ "$H_MUTEX_HELD" = 1 ] || return 1
    python3 -I -c "$H_PY_STATE_CAS" 200 "$H_MUTEX_PATH" "$(h_my_uid)" "$1" "$2" "$3"
}
h_state_cas() {  # h_state_cas EXPECTED_RECORD NEW_RECORD
    h_file_cas "$H_STATE_PATH" "$1" "$2"
}
h_state_record() {  # h_state_record STATE BY SEQ PID RUN_ID UID RUN_DIR NONCE INIT_ID
    printf 'sinter-state-v5;state=%s;seq=%s;by=%s;pid=%s;run_id=%s;uid=%s;run_dir=%s;nonce=%s;init=%s' "$1" "$3" "$2" "$4" "$5" "$6" "$7" "$8" "$9"
}
h_state_transition() {  # h_state_transition NEW_STATE BY -> CAS from the record this process wrote last; the run's identity is kept
    local new
    new="$(h_state_record "$1" "$2" $((H_ST_SEQ + 1)) "$$" "${H_ST_RUN_ID_NOW:-$H_RUN_ID}" "$(h_my_uid)" "${H_ST_RUN_DIR_NOW:-$H_RUNDIR}" "${H_ST_NONCE_NOW:-$H_LOCK_NONCE}" "$H_INIT_ID")"
    h_state_cas "$H_STATE_REC" "$new" || return 1
    H_STATE_REC="$new"; H_ST_SEQ=$((H_ST_SEQ + 1))
    return 0
}
h_lock_release() {  # the run ends cleanly: state UNLOCKED (one atomic replace), then the exclusion is dropped
    [ "$H_LOCK_HELD" = 1 ] || return 0
    h_state_transition UNLOCKED scenario || { h_fail "lock" "the state record could not be set to UNLOCKED (compare-and-set failed): the state stays as it was and the exclusion is kept"; return 1; }
    H_LOCK_HELD=0
    h_mutex_drop
    return 0
}
h_lock_fail() {  # the run failed: state FAILED_LOCKED (the next run is refused until the run is recovered), then the exclusion is dropped
    [ "$H_LOCK_HELD" = 1 ] || return 0
    h_state_transition FAILED_LOCKED scenario || { h_fail "lock" "the state record could not be set to FAILED_LOCKED (compare-and-set failed): the state stays RUNNING, which also refuses every new run"; return 1; }
    H_LOCK_HELD=0
    h_mutex_drop
    return 0
}

# ---- running and validating commands -----------------------------------------------------------
h_run() {  # h_run LABEL CMD ARGS... -> H_RC, H_OUTF, H_ERRF (fresh private files; argv only, no shell)
    local label="$1" o e
    shift
    H_RC=125; H_OUTF=""; H_ERRF=""
    [ -n "${H_RUNDIR:-}" ] && [ -d "$H_RUNDIR" ] || { h_fail "$label" "no run directory"; return 1; }
    o="$(mktemp "$H_RUNDIR/o.XXXXXX")" || { h_fail "$label" "cannot create a temp file"; return 1; }
    e="$(mktemp "$H_RUNDIR/e.XXXXXX")" || { h_fail "$label" "cannot create a temp file"; return 1; }
    if [ -L "$o" ] || [ -L "$e" ] || [ ! -f "$o" ] || [ ! -f "$e" ]; then h_fail "$label" "temp file is not a fresh regular file"; return 1; fi
    "$@" > "$o" 2> "$e"
    H_RC=$?
    H_OUTF="$o"; H_ERRF="$e"
    return 0
}
h_err_summary() { head -c 200 "$1" 2> /dev/null | LC_ALL=C tr -c '[:print:]' ' '; }

h_parse_record() {  # one dpkg-query record of H_SNAP_FMT -> H_R_ST H_R_NAME H_R_ARCH H_R_VER H_R_ESS
    local line="$1" T re
    T=$'\t'
    re="^([uihrp][ncHUFWti][ RHX])${T}([a-z0-9][a-z0-9+.-]+)${T}([a-z0-9-]+)${T}([A-Za-z0-9.+~:_-]+)${T}(yes|no)?\$"
    [[ "$line" =~ $re ]] || return 1
    H_R_ST="${BASH_REMATCH[1]}"; H_R_NAME="${BASH_REMATCH[2]}"; H_R_ARCH="${BASH_REMATCH[3]}"
    H_R_VER="${BASH_REMATCH[4]}"; H_R_ESS="${BASH_REMATCH[5]}"
    return 0
}
h_snapshot() {  # h_snapshot LABEL -> $H_RUNDIR/snap.LABEL (validated, sorted) ; the whole host listing
    local label="$1" f line n=0 tmp lre='^[a-z0-9_-]+$'
    [[ "$label" =~ $lre ]] || { h_fail "snapshot" "bad label"; return 1; }
    f="$H_RUNDIR/snap.$label"
    h_run "snapshot:$label" "$H_DPKG_QUERY" -W -f="$H_SNAP_FMT" || return 1
    [ "$H_RC" = 0 ] || { h_fail "snapshot:$label" "dpkg-query exited $H_RC"; return 1; }
    [ ! -s "$H_ERRF" ] || { h_fail "snapshot:$label" "dpkg-query wrote to stderr: $(h_err_summary "$H_ERRF")"; return 1; }
    h_text_ok "$H_OUTF" || { h_fail "snapshot:$label" "the listing is not clean, complete text"; return 1; }
    [ -s "$H_OUTF" ] || { h_fail "snapshot:$label" "the listing is empty (an empty package set is not a valid answer)"; return 1; }
    tmp="$H_OUTF"
    while IFS= read -r line; do
        h_parse_record "$line" || { h_fail "snapshot:$label" "unparseable record [$(h_clip "$line")]"; return 1; }
        n=$((n + 1))
    done < "$tmp"
    [ "$n" -ge "$H_MIN_PKGS" ] || { h_fail "snapshot:$label" "only $n records (minimum $H_MIN_PKGS)"; return 1; }
    rm -f "$f"
    ( set -C; LC_ALL=C sort "$tmp" > "$f" ) 2> /dev/null && [ -f "$f" ] && [ ! -L "$f" ] || { h_fail "snapshot:$label" "cannot write the snapshot"; return 1; }
    if [ -n "$(LC_ALL=C cut -f2,3 "$f" | LC_ALL=C uniq -d)" ]; then h_fail "snapshot:$label" "duplicate name:arch records"; return 1; fi
    return 0
}
h_query_pkg() {  # h_query_pkg NAME ARCH -> H_PSTATE (absent | 3-char status), H_PESS ; any doubt = failure
    local n="$1" a="$2" line found=0 st="" es="" ve="" msg
    H_PSTATE=""; H_PESS=""; H_PVER=""
    h_valid_name "$n" && h_valid_arch "$a" || { h_fail "query:pkg" "invalid package spec"; return 1; }
    h_run "query:$n" "$H_DPKG_QUERY" -W -f="$H_SNAP_FMT" -- "$n" || return 1
    if [ "$H_RC" = 1 ] && [ ! -s "$H_OUTF" ]; then
        msg="$(cat "$H_ERRF")"
        if [ "$msg" = "dpkg-query: no packages found matching $n" ]; then H_PSTATE=absent; return 0; fi
    fi
    [ "$H_RC" = 0 ] || { h_fail "query:$n" "dpkg-query exited $H_RC: $(h_err_summary "$H_ERRF")"; return 1; }
    [ ! -s "$H_ERRF" ] || { h_fail "query:$n" "dpkg-query wrote to stderr: $(h_err_summary "$H_ERRF")"; return 1; }
    h_text_ok "$H_OUTF" && [ -s "$H_OUTF" ] || { h_fail "query:$n" "the answer is empty or not clean text"; return 1; }
    while IFS= read -r line; do
        h_parse_record "$line" || { h_fail "query:$n" "unparseable record [$(h_clip "$line")]"; return 1; }
        [ "$H_R_NAME" = "$n" ] || { h_fail "query:$n" "the answer names another package [$(h_clip "$H_R_NAME")]"; return 1; }
        if [ "$H_R_ARCH" = "$a" ]; then found=$((found + 1)); st="$H_R_ST"; es="$H_R_ESS"; ve="$H_R_VER"; fi
    done < "$H_OUTF"
    if [ "$found" = 0 ]; then H_PSTATE=absent; return 0; fi   # only other architectures are known
    [ "$found" = 1 ] || { h_fail "query:$n" "more than one record for $n:$a"; return 1; }
    H_PSTATE="$st"; H_PESS="$es"; H_PVER="$ve"
    return 0
}
h_state_gone() {  # 3-char status: not installed (second character n)
    [ "${1:1:1}" = n ]
}

# ---- snapshots compared ------------------------------------------------------------------------
h_nonreg() {  # h_nonreg LABEL -> records of everything the harness did NOT register
    awk -F'\t' 'NR==FNR { reg[$1 ":" $2] = 1; next } !(($2 ":" $3) in reg)' "$H_REGFILE" "$H_RUNDIR/snap.$1" | LC_ALL=C sort
}
h_compare_nonreg() {  # h_compare_nonreg A B -> 0 only if every non-registered record is identical
    local a b
    [ -f "$H_RUNDIR/snap.$1" ] && [ -f "$H_RUNDIR/snap.$2" ] || { h_fail "compare" "missing snapshot"; return 1; }
    a="$H_RUNDIR/nr.$1.$2.a"; b="$H_RUNDIR/nr.$1.$2.b"
    h_nonreg "$1" > "$a" 2> /dev/null && h_nonreg "$2" > "$b" 2> /dev/null || { h_fail "compare" "cannot compute the comparison"; return 1; }
    if cmp -s "$a" "$b"; then return 0; fi
    H_DIFF="$(diff "$a" "$b" | head -6 | LC_ALL=C tr -c '[:print:]' ' ' | head -c 300)"
    return 1
}
h_compare_full() {  # identical including registered packages
    [ -f "$H_RUNDIR/snap.$1" ] && [ -f "$H_RUNDIR/snap.$2" ] || return 1
    if cmp -s "$H_RUNDIR/snap.$1" "$H_RUNDIR/snap.$2"; then return 0; fi
    H_DIFF="$(diff "$H_RUNDIR/snap.$1" "$H_RUNDIR/snap.$2" | head -6 | LC_ALL=C tr -c '[:print:]' ' ' | head -c 300)"
    return 1
}
h_snap_count() { wc -l < "$H_RUNDIR/snap.$1" | tr -d ' '; }

h_baseline() {  # take the baseline; leftover test packages are reported, never removed
    local left
    h_guard baseline || return 1
    h_snapshot base || { h_abort "baseline snapshot failed"; return 1; }
    left="$(awk -F'\t' '$2 ~ /^sinter-t-/ {print $2 ":" $3}' "$H_RUNDIR/snap.base" | tr '\n' ' ')"
    if [ -n "$left" ]; then h_abort "leftover test packages exist before the run (not removed): $(h_clip "$left" 160)"; return 1; fi
    h_run "foreign-arch:base" "$H_DPKG" --print-foreign-architectures || return 1
    [ "$H_RC" = 0 ] && [ ! -s "$H_ERRF" ] && h_text_ok "$H_OUTF" || { h_abort "cannot read the foreign architectures"; return 1; }
    cp "$H_OUTF" "$H_RUNDIR/foreign.base" || { h_abort "cannot save the foreign architectures"; return 1; }
    return 0
}

# ---- installing: verified identity first, registration second, install third ---------------------------
h_register() {  # kept only so that a direct call fails loudly: registration is not a public operation
    h_abort "direct registration is not allowed: a package is registered only by h_install_deb / h_install_deb_bg / h_shim_arm after its payload file was verified"
    return 1
}
_h_register() {  # _h_register name:arch version -- internal; only reached through h_prepare_install
    local s="$1" v="$2" old vre='^[0-9][0-9.]*$'
    h_guard register || return 1
    h_valid_spec "$s" || { h_abort "invalid package spec [$(h_clip "$s")]"; return 1; }
    h_in_allowlist "$s" || { h_abort "package is not in the scenario allowlist [$s]"; return 1; }
    [[ "$v" =~ $vre ]] || { h_abort "invalid version [$(h_clip "$v")]"; return 1; }
    if h_is_registered "$s"; then
        old="$(h_reg_ver "$s")" && [ "$old" = "$v" ] || { h_abort "$s is already registered with another version"; return 1; }
        return 0
    fi
    [ "${#H_REG[@]}" -lt "$H_MAX_PKGS" ] || { h_abort "more than $H_MAX_PKGS packages registered"; return 1; }
    printf '%s\t%s\t%s\n' "${s%%:*}" "${s#*:}" "$v" >> "$H_REGFILE" || { h_abort "cannot write the registry"; return 1; }
    H_REG[${#H_REG[@]}]="$s"
    H_REG_VER[${#H_REG_VER[@]}]="$v"
    return 0
}
h_payload_check() {  # h_payload_check FILE -> H_PN H_PA H_PV ; a regular payload file whose name and .deb fields agree, not Essential
    local f="$1" re want
    case "$f" in */*|*..*|"") h_abort "bad payload file name"; return 1 ;; esac
    re='^(sinter-t-[a-z0-9]+(-[a-z0-9]+)*)_([0-9][0-9.]*)_(all|amd64|i386)\.deb$'
    [[ "$f" =~ $re ]] || { h_abort "payload file name does not match the pattern [$(h_clip "$f")]"; return 1; }
    H_PN="${BASH_REMATCH[1]}"; H_PV="${BASH_REMATCH[3]}"; H_PA="${BASH_REMATCH[4]}"
    h_valid_spec "$H_PN:$H_PA" || { h_abort "invalid package spec in the payload file name"; return 1; }
    [ -n "${H_PK:-}" ] && [ -f "$H_PK/$f" ] && [ ! -L "$H_PK/$f" ] || { h_abort "payload file missing"; return 1; }
    h_run "deb-fields:$f" "$H_DPKG_DEB" -f "$H_PK/$f" Package Architecture Version || return 1
    want="$(printf 'Package: %s\nArchitecture: %s\nVersion: %s' "$H_PN" "$H_PA" "$H_PV")"
    if [ "$H_RC" != 0 ] || [ -s "$H_ERRF" ] || [ "$(cat "$H_OUTF")" != "$want" ]; then
        h_abort "the payload file does not contain the package its name says"; return 1
    fi
    # real dpkg-deb 1.22.6 (Stage B1, 2026-10-24): one requested field is printed WITHOUT its label; an absent Essential
    # prints "no"; an unknown field prints an empty line.  Only "no" or empty is accepted.
    h_run "deb-essential:$f" "$H_DPKG_DEB" -f "$H_PK/$f" Essential || return 1
    if [ "$H_RC" != 0 ] || [ -s "$H_ERRF" ] || ! h_text_ok "$H_OUTF"; then
        h_abort "the Essential field of the payload file could not be read"; return 1
    fi
    case "$(cat "$H_OUTF")" in no|"") ;; *) h_abort "the payload file declares Essential"; return 1 ;; esac
    return 0
}
h_verify_identity() {  # h_verify_identity name arch version -> 0 if the package is absent or exactly this version and not Essential
    h_query_pkg "$1" "$2" || return 1
    [ "$H_PSTATE" = absent ] && return 0
    if [ "$H_PVER" != "$3" ]; then h_abort "$1:$2 has the version [$(h_clip "$H_PVER")], this run registered [$3]"; return 1; fi
    if [ "$H_PESS" = yes ]; then h_abort "$1:$2 is Essential"; return 1; fi
    return 0
}
h_prepare_install() {  # h_prepare_install FILE -> payload verified, the package did not exist before (first time), registered
    local f="$1" s
    h_guard install || return 1
    [ -n "${H_RUNDIR:-}" ] && [ -f "$H_RUNDIR/snap.base" ] || { h_abort "install before the baseline snapshot exists"; return 1; }
    h_payload_check "$f" || return 1
    s="$H_PN:$H_PA"
    if ! h_is_registered "$s"; then
        h_query_pkg "$H_PN" "$H_PA" || { h_abort "cannot establish that $s is absent before the install"; return 1; }
        [ "$H_PSTATE" = absent ] || { h_abort "$s exists before this run installed it [$H_PSTATE]: not adopted"; return 1; }
    fi
    _h_register "$s" "$H_PV" || return 1
    return 0
}
h_install_deb() {  # h_install_deb FILE  (a file name inside $H_PK; installed with plain `dpkg -i`)
    local f="$1" n a v rc
    h_prepare_install "$f" || return 1
    n="$H_PN"; a="$H_PA"; v="$H_PV"
    h_run "install:$n:$a" h_sudo_run "$H_DPKG" -i "$H_PK/$f" || return 1
    rc="$H_RC"
    h_verify_identity "$n" "$a" "$v" || return 1
    if [ "$rc" = 0 ] && [ "$H_PSTATE" = absent ]; then h_abort "dpkg -i reported success but $n:$a is absent"; return 1; fi
    [ "$rc" = 0 ]
}

h_install_deb_bg() {  # h_install_deb_bg FILE -> H_BGPID : same checks as h_install_deb, installs in the background
    local f="$1"
    h_prepare_install "$f" || return 1
    ( h_sudo_run "$H_DPKG" -i "$H_PK/$f" > "$H_RUNDIR/bg.$H_PN.out" 2> "$H_RUNDIR/bg.$H_PN.err" ) &
    H_BGPID=$!
    return 0
}

# ---- failure flags (scripts of the synthetic packages fail only while their flag exists) ------------
h_flag_dir_ready() {
    h_sudo_run mkdir -p "$H_FLAGDIR" || return 1
    h_check_dir "$H_FLAGDIR"
}
h_valid_flag() {  # NAME or NAME.wait / NAME.seen / NAME.order, NAME a valid test package name
    local f="$1" base
    base="${f%.wait}"; base="${base%.seen}"; base="${base%.order}"
    h_valid_name "$base" || return 1
    case "$f" in "$base"|"$base.wait"|"$base.seen"|"$base.order") return 0 ;; esac
    return 1
}
h_arm() {  # h_arm NAME [wait] -> NAME (the scripts of the synthetic package fail) or NAME.wait (prerm waits for NAME.seen)
    local n="$1" f
    h_guard arm || return 1
    f="$n"; [ "${2:-}" = wait ] && f="$n.wait"
    h_valid_flag "$f" || { h_abort "invalid flag name"; return 1; }
    h_flag_dir_ready || { h_abort "the flag directory is not safe"; return 1; }
    h_sudo_run touch "$H_FLAGDIR/$f" || { h_fail "arm:$f" "cannot create the flag"; return 1; }
    H_ARMED[${#H_ARMED[@]}]="$f"
    return 0
}
h_flag_set() {  # h_flag_set NAME.seen -> used by the order reader (runs as root through the same sudo wrapper)
    h_valid_flag "$1" && h_check_dir "$H_FLAGDIR" || return 1
    h_sudo_run touch "$H_FLAGDIR/$1" || return 1
    H_ARMED[${#H_ARMED[@]}]="$1"
}
h_flag_read() {  # h_flag_read NAME.order -> prints the content or "missing"
    h_valid_flag "$1" && h_check_dir "$H_FLAGDIR" || { echo invalid; return 1; }
    if [ -f "$H_FLAGDIR/$1" ] && [ ! -L "$H_FLAGDIR/$1" ]; then h_sudo_run cat "$H_FLAGDIR/$1"; else echo missing; fi
}
h_disarm() {
    local n="$1"
    h_valid_flag "$n" || return 1
    h_check_dir "$H_FLAGDIR" || return 1
    h_sudo_run rm -f "$H_FLAGDIR/$n" || return 1
    [ ! -e "$H_FLAGDIR/$n" ]
}
h_disarm_all() {
    local n rc=0
    for n in "${H_ARMED[@]+"${H_ARMED[@]}"}"; do h_disarm "$n" || { h_fail "disarm:$n" "cannot remove the flag"; rc=1; }; done
    H_ARMED=()
    # flags the synthetic packages' own scripts create (.order, .seen) are not in H_ARMED: remove every flag of a REGISTERED package
    # (real host, Stage B/C: a root-owned NAME.order stayed in the flag directory after the run).  Nothing else is touched.
    if [ -d "$H_FLAGDIR" ]; then
        local s b sfx
        for s in "${H_REG[@]+"${H_REG[@]}"}"; do
            b="${s%%:*}"
            for sfx in "" .wait .seen .order; do h_disarm "$b$sfx" || { h_fail "disarm:$b$sfx" "cannot remove the flag"; rc=1; }; done
        done
    fi
    return $rc
}

# ---- selections (only registered names) --------------------------------------------------------
h_restore_selection() {  # h_restore_selection name:arch... -> `dpkg --set-selections` for registered packages only
    local s lines=""
    h_guard selection || return 1
    for s in "$@"; do
        h_valid_spec "$s" && h_is_registered "$s" || { h_abort "selection for a package this run did not register [$(h_clip "$s")]"; return 1; }
        lines="$lines${s%%:*} install
"
    done
    printf '%s' "$lines" | h_sudo_run "$H_DPKG" --set-selections > /dev/null 2>&1 || { h_fail "selection" "dpkg --set-selections failed"; return 1; }
}

# ---- wrappers must be gone before a cleanup ----------------------------------------------------
h_is_shim() { LC_ALL=C grep -q 'SINTER-HARNESS-SHIM' "$1" 2> /dev/null; }
h_wrappers_clear() {  # the programs the cleanup would call must be the real ones, never a test wrapper; no mount may remain
    local p
    if [ -n "$H_MOUNT_RESIDUE" ]; then h_fail "cleanup:wrapper" "a wrapper mount remains [$(h_clip "$H_MOUNT_RESIDUE" 120)]: the cleanup does not purge (review by hand)"; return 1; fi
    for p in "$H_DPKG" "$H_DPKG_QUERY"; do
        if h_is_shim "$p"; then h_fail "cleanup:wrapper" "$(h_clip "$p") is a test wrapper (not purging through a wrapper)"; return 1; fi
    done
    return 0
}

# ---- foreign architecture (Multi-Arch scenario): added by the run, removed again at the end ----------
H_ADDED_ARCH=""
h_add_arch() {  # h_add_arch ARCH -> `dpkg --add-architecture`; only if the baseline did not have it
    local a="$1"
    h_guard arch || return 1
    h_valid_arch "$a" && [ "$a" != all ] || { h_abort "invalid architecture [$(h_clip "$a")]"; return 1; }
    if grep -qx -- "$a" "$H_RUNDIR/foreign.base"; then h_note "architecture $a was already configured; it is left as it was"; return 0; fi
    h_run "add-arch:$a" h_sudo_run "$H_DPKG" --add-architecture "$a" || return 1
    [ "$H_RC" = 0 ] || { h_fail "add-arch:$a" "dpkg --add-architecture failed (exit $H_RC)"; return 1; }
    H_ADDED_ARCH="$a"
}
h_remove_added_arch() {  # only the architecture this run added, and only if no package of it remains
    [ -n "$H_ADDED_ARCH" ] || return 0
    h_snapshot arch || return 1
    if awk -F'\t' -v a="$H_ADDED_ARCH" '$3 == a { found = 1 } END { exit !found }' "$H_RUNDIR/snap.arch"; then
        h_fail "cleanup" "packages of the architecture $H_ADDED_ARCH remain; it is not removed"; return 1
    fi
    h_run "remove-arch:$H_ADDED_ARCH" h_sudo_run "$H_DPKG" --remove-architecture "$H_ADDED_ARCH" || return 1
    [ "$H_RC" = 0 ] || { h_fail "cleanup" "dpkg --remove-architecture failed (exit $H_RC)"; return 1; }
    H_ADDED_ARCH=""
}
h_purge_now() {  # h_purge_now name:arch -> purge one registered package in the middle of a scenario (state set-up)
    local s="$1" n a
    h_valid_spec "$s" && h_is_registered "$s" || { h_abort "refusing to purge [$(h_clip "$s")]"; return 1; }
    n="${s%%:*}"; a="${s#*:}"
    h_query_pkg "$n" "$a" || return 1
    if [ "$H_PSTATE" = absent ] || h_state_gone "$H_PSTATE"; then return 0; fi
    h_purge_one "$s"
}

# ---- cleanup: the only place that removes packages ---------------------------------------------
h_dry_run_exact() {  # h_dry_run_exact name arch version -> 0 only if the dry-run names exactly this one package, once
    # real dpkg 1.22.6 (Stage A, 2026-10-24):  "(Reading database ... N files and directories currently installed.)" and
    # "Would remove or purge NAME (VERSION) ..." on stdout; nothing on stderr.  An empty answer is NOT a success.
    local line seen=0 re_read re_would
    re_read='^\(Reading database \.\.\. [0-9]+ files and directories currently installed\.\)$'
    re_would='^Would remove or purge ([a-z0-9+.-]+)(:[a-z0-9-]+)? \(([^)]+)\) \.\.\.$'
    while IFS= read -r line; do
        if [[ "$line" =~ $re_read ]]; then continue; fi
        if [[ "$line" =~ $re_would ]]; then
            [ "${BASH_REMATCH[1]}" = "$1" ] || return 1
            if [ -n "${BASH_REMATCH[2]}" ]; then [ "${BASH_REMATCH[2]}" = ":$2" ] || return 1; fi
            [ "${BASH_REMATCH[3]}" = "$3" ] || return 1
            seen=$((seen + 1))
            continue
        fi
        return 1
    done < "$H_OUTF"
    [ "$seen" = 1 ]
}
h_configure_one() {  # a half-configured / unpacked registered package is configured normally before it is purged
    local s="$1" n a target
    h_guard configure || return 1
    h_valid_spec "$s" && h_is_registered "$s" && h_in_allowlist "$s" || { h_abort "refusing to configure [$(h_clip "$s")]"; return 1; }
    n="${s%%:*}"; a="${s#*:}"
    if [ "$a" = all ]; then target="$n"; else target="$n:$a"; fi
    h_run "configure:$s" h_sudo_run "$H_DPKG" --configure "$target" || return 1
    [ "$H_RC" = 0 ] || { h_fail "cleanup:$s" "configure failed (exit $H_RC); no escalation: $(h_err_summary "$H_ERRF")"; return 1; }
    h_query_pkg "$n" "$a" || return 1
    return 0
}
h_purge_one() {  # h_purge_one name:arch -> normal `dpkg --purge`, no force option exists; identity re-verified right before
    local s="$1" n a v target
    h_guard purge || return 1
    h_valid_spec "$s" && h_is_registered "$s" && h_in_allowlist "$s" || { h_abort "refusing to purge [$(h_clip "$s")]"; return 1; }
    n="${s%%:*}"; a="${s#*:}"
    v="$(h_reg_ver "$s")" || { h_abort "no registered version for $s"; return 1; }
    if [ "$a" = all ]; then target="$n"; else target="$n:$a"; fi
    # the state right now must be the state this run created: this name, this arch, this version, not Essential
    h_query_pkg "$n" "$a" || return 1
    if [ "$H_PSTATE" = absent ] || h_state_gone "$H_PSTATE"; then return 0; fi
    if [ "$H_PVER" != "$v" ]; then h_abort "refusing to purge $s: installed version [$(h_clip "$H_PVER")] is not the registered [$v]"; return 1; fi
    if [ "$H_PESS" = yes ]; then h_abort "refusing to purge $s: it is Essential"; return 1; fi
    # real dpkg 1.22.6: "ri " = a refused `dpkg --remove` leaves the package installed but selected for removal (Stage B2);
    # "rH " = a failing post-removal script leaves it half-installed (Stage C, SA-3 B6): with the failure flags disarmed a plain
    # `dpkg --purge` completes it (dpkg's own audit text says so); a REINSTREQ ("?? R") or hold state still needs a reviewed plan
    case "$H_PSTATE" in "ii "|"ri "|"pi "|"rH "|"pH "|"iH "|?c?) ;; *) h_abort "refusing to purge $s in the state [$H_PSTATE]: a reviewed plan is needed"; return 1 ;; esac
    if [ "${H_PSTATE:1:1}" != c ]; then   # an installed package: dpkg's own dry-run must name exactly the target
        h_run "purge-dry:$s" h_sudo_run "$H_DPKG" --dry-run --purge "$target" || return 1
        [ "$H_RC" = 0 ] || { h_fail "cleanup:$s" "dry-run refused (exit $H_RC): $(h_err_summary "$H_ERRF")"; return 1; }
        [ ! -s "$H_ERRF" ] || { h_abort "the purge dry-run wrote to stderr: $(h_err_summary "$H_ERRF")"; return 1; }
        h_text_ok "$H_OUTF" || { h_fail "cleanup:$s" "dry-run output is not clean text"; return 1; }
        h_dry_run_exact "$n" "$a" "$v" || { h_abort "the purge dry-run does not name exactly the target (empty, other packages, or another version)"; return 1; }
    fi
    h_run "purge:$s" h_sudo_run "$H_DPKG" --purge "$target" || return 1
    [ "$H_RC" = 0 ] || { h_fail "cleanup:$s" "purge failed (exit $H_RC); no escalation: $(h_err_summary "$H_ERRF")"; return 1; }
    h_query_pkg "$n" "$a" || return 1
    if [ "$H_PSTATE" = absent ] || h_state_gone "$H_PSTATE"; then return 0; fi
    h_fail "cleanup:$s" "still present after the purge (status [$H_PSTATE])"
    return 1
}
h_cleanup() {  # h_cleanup [final] -> 0 only if every registered package is gone and the host equals the baseline
    # Any failure aborts the harness: nothing is installed or purged afterwards, and a later retry is refused.
    if h_cleanup_inner "${1:-}"; then return 0; fi
    H_CLEANUP_STATUS=failed
    H_ABORTED=1
    return 1
}
h_cleanup_inner() {
    local i spec n a plan=() cnt_b cnt_c lim
    H_CLEANUP_STATUS=failed
    h_wrappers_clear || return 1     # a wrapper mount that could not be removed fails the cleanup before anything else
    # nothing was ever registered, armed or added: there is nothing to restore (the run never started to change the host)
    if [ "${#H_REG[@]}" -eq 0 ] && [ "${#H_ARMED[@]}" -eq 0 ] && [ -z "$H_ADDED_ARCH" ] && { [ -z "${H_RUNDIR:-}" ] || [ ! -f "$H_RUNDIR/snap.base" ]; }; then
        H_CLEANUP_STATUS=ok; return 0
    fi
    [ -n "${H_RUNDIR:-}" ] && [ -f "$H_RUNDIR/snap.base" ] || { h_fail "cleanup" "no baseline"; return 1; }
    h_disarm_all || return 1
    h_wrappers_clear || return 1
    h_snapshot cur || return 1
    cnt_b="$(h_snap_count base)"; cnt_c="$(h_snap_count cur)"
    lim=$((cnt_b - cnt_b * H_SHRINK_PERCENT / 100))
    if [ "$cnt_c" -lt "$lim" ]; then h_abort "the package set shrank from $cnt_b to $cnt_c records; nothing was purged"; return 1; fi
    if ! h_compare_nonreg base cur; then h_abort "non-test packages differ from the baseline; nothing was purged: ${H_DIFF:-}"; return 1; fi
    i=${#H_REG[@]}
    while [ "$i" -gt 0 ]; do
        i=$((i - 1)); spec="${H_REG[$i]}"; n="${spec%%:*}"; a="${spec#*:}"
        h_query_pkg "$n" "$a" || return 1
        if [ "$H_PSTATE" = absent ] || h_state_gone "$H_PSTATE"; then continue; fi
        if [ "$H_PESS" = yes ]; then h_abort "registered package $spec is Essential: removal needs a separate, reviewed plan"; return 1; fi
        case "${H_PSTATE:2:1}" in R|H|X) h_abort "registered package $spec is in an error state [$H_PSTATE]: removal needs a separate, reviewed plan"; return 1 ;; esac
        plan[${#plan[@]}]="$spec|$H_PSTATE"
        [ "$H_PVER" = "$(h_reg_ver "$spec")" ] || { h_abort "registered package $spec has the version [$(h_clip "$H_PVER")], not the registered one: it is not the package this run installed"; return 1; }
    done
    [ "${#plan[@]}" -le "$H_MAX_PKGS" ] || { h_abort "the cleanup plan exceeds $H_MAX_PKGS packages"; return 1; }
    for i in "${plan[@]+"${plan[@]}"}"; do
        spec="${i%%|*}"; H_PSTATE="${i#*|}"
        case "${H_PSTATE:1:1}" in F|U|W|t) h_configure_one "$spec" || return 1 ;; esac
        h_purge_one "$spec" || return 1     # re-verifies the identity and the state itself
    done
    if [ "${1:-}" = final ]; then h_remove_added_arch || return 1; fi
    h_snapshot final || return 1
    if ! h_compare_full base final; then h_fail "cleanup" "the host differs from the baseline after the cleanup: ${H_DIFF:-}"; return 1; fi
    if [ "${1:-}" = final ]; then
        h_run "foreign-arch:final" "$H_DPKG" --print-foreign-architectures || return 1
        if [ "$H_RC" != 0 ] || [ -s "$H_ERRF" ] || ! h_text_ok "$H_OUTF" || ! cmp -s "$H_OUTF" "$H_RUNDIR/foreign.base"; then
            h_fail "cleanup" "the foreign architectures differ from the baseline"; return 1
        fi
    fi
    H_CLEANUP_STATUS=ok
    return 0
}

# ---- finishing: cleanup result is separate from the scenario result ---------------------------------
h_write_status() {  # h_write_status FILE -> original scenario result and cleanup result, saved separately
    {
        printf 'scenario_failed\t%s\n' "${FAILED:-0}"
        printf 'harness_failed\t%s\n' "$H_FAILED"
        printf 'aborted\t%s\n' "$H_ABORTED"
        printf 'cleanup\t%s\n' "$H_CLEANUP_STATUS"
    } > "$1" 2> /dev/null || { h_fail "evidence:status" "cannot write $1"; return 1; }
}
h_finish() {
    [ "$H_FINISHED" = 1 ] && return 0
    H_FINISHED=1
    if declare -F h_shims_finish > /dev/null 2>&1; then h_shims_finish; fi
    h_cleanup final || true
    if [ "$H_CLEANUP_STATUS" != ok ]; then h_fail "CLEANUP" "the cleanup did not complete; the host may hold test packages or changes (the state becomes FAILED_LOCKED: the next run is refused)"; fi
    [ -n "${H_RUNDIR:-}" ] && h_write_status "$H_RUNDIR/final-status.tsv"
    [ -n "${OUT:-}" ] && [ -d "${OUT:-}" ] && h_write_status "$OUT/final-status.tsv"
    if [ "$H_LOCK_HELD" = 1 ]; then
        if [ "$H_CLEANUP_STATUS" = ok ]; then h_lock_release; else h_lock_fail; fi
    fi
    return 0
}
h_verdict() {  # prints the verdict; exit status 0 = PASS only if the scenario, the harness and the cleanup all passed
    if [ "${FAILED:-0}" = 0 ] && [ "$H_FAILED" = 0 ] && [ "$H_ABORTED" = 0 ] && [ "$H_CLEANUP_STATUS" = ok ]; then
        echo "SCENARIO: PASS"; return 0
    fi
    echo "SCENARIO: FAIL (scenario_failed=${FAILED:-0} harness_failed=$H_FAILED aborted=$H_ABORTED cleanup=$H_CLEANUP_STATUS)"
    return 1
}
h_install_traps() {  # the EXIT trap also runs when the scenario is interrupted or terminated
    trap h_on_exit EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'exit 129' HUP
}
h_on_exit() {  # EXIT trap: runs the finish if it did not run; a failed cleanup always changes the exit status
    local rc=$?
    if [ "$H_FINISHED" != 1 ]; then h_finish; fi
    if [ "$H_CLEANUP_STATUS" != ok ] || [ "$H_FAILED" = 1 ] || [ "$H_ABORTED" = 1 ]; then
        [ "$rc" = 0 ] && rc=70
    fi
    exit "$rc"
}
