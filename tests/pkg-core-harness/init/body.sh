# =====================================================================================
# init-state.sh -- the EXPLICIT, idempotent initialisation of the persistent state of the run exclusion (R4-1).
#
#   init-state.sh --evidence-dir DIR [--confirm-clean-host]
#
# Why: a missing state record must never be taken for "a fresh environment".  Runs and recoveries start only in an environment
# that this tool initialised and whose records agree; a vanished record is UNKNOWN.  This tool is the ONLY writer that creates
# them.  Contract (details: 02-init-contract.md):
#   * Already initialised and consistent  -> reports the state and changes NOTHING (idempotent; a FAILED_LOCKED run is not touched).
#   * Initialised before but a record is missing / corrupt / inconsistent (UNKNOWN), or old-format files exist (LEGACY_LOCK)
#     -> REFUSED.  Nothing is re-initialised over an unknown state; a human reviews the host and moves the directory away.
#   * Interrupted initialisation (INIT_INCOMPLETE: a prefix of the sequence) -> completed, with the same init id.
#   * Never initialised (no state directory, or an empty one) -> created, but ONLY with --confirm-clean-host (the Owner's
#     explicit statement that this host carries no unrecovered change of an earlier run) AND only if the automatic evidence
#     agrees: no old-format lock or state file, no leftover run directory, no synthetic package, no wrapper mount.
# Sequence (each step ONE atomic write; a kill leaves a recognisable prefix):
#   directory (mode 700, yours) -> exclusion file -> init record (phase started) -> initial state record (UNLOCKED, seq 0)
#   -> init record (phase complete).
# Exit status: 0 initialised or already initialised, 1 refused or failed, 2 usage, 70 environment gate.
#
# OPERATING RULES (final audit F-3; comments only, no behaviour):
#   * Run this tool as the SAME user that runs the scenarios and the recovery tool.  The init record and every state record carry
#     that user's uid, and the tools treat records of any other uid as UNKNOWN and refuse them (fail-closed).
#   * Only the privileged steps need sudo, and the tool performs them itself (through H_SUDO: mkdir -m 700 and chown of the state
#     directory).  Do NOT run the whole tool as root (no `sudo init-state.sh`): the records would belong to root and every run by
#     the ordinary user would then be refused.
#   * Never work around a refusal by changing the owner or the mode of the directory or of the records by hand (chown / chmod),
#     and never recreate a missing record by hand.  A refusal is a request for a human to review the host (see the contract above).
#   * This tool adds no privilege escalation and no automatic repair.
# =====================================================================================
set -uo pipefail
h_gate_env || exit 70
IS_ME="$(id -u)"
if [ "$IS_ME" = 0 ]; then H_SUDO=()
elif declare -F h_production > /dev/null && h_production; then H_SUDO=(/usr/bin/sudo -n)
elif [ "${H_SUDO_NONE:-0}" = 1 ]; then H_SUDO=()
else echo "no privilege path (a test build needs H_SUDO_NONE=1)" >&2; exit 70; fi
IS_EVID=""; IS_CONFIRM=0; IS_EV=""
is_usage() { echo "usage: init-state.sh --evidence-dir DIR [--confirm-clean-host]" >&2; exit 2; }
record() { [ -n "$IS_EV" ] && printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$IS_EV/steps.tsv" 2> /dev/null; return 0; }
note() { printf 'NOTE\t%s\n' "$*" >&2; [ -n "$IS_EV" ] && printf 'NOTE\t%s\n' "$*" >> "$IS_EV/notes.txt" 2> /dev/null; return 0; }
is_fail() { note "REFUSED/FAILED: $1"; echo "INIT FAILED: $1 (evidence: ${IS_EV:-none})" >&2; exit 1; }
while [ $# -gt 0 ]; do
    case "$1" in
        --evidence-dir) [ $# -ge 2 ] || is_usage; IS_EVID="$2"; shift 2 ;;
        --confirm-clean-host) IS_CONFIRM=1; shift ;;
        *) is_usage ;;
    esac
done
case "$IS_EVID" in /*) ;; *) echo "--evidence-dir must be absolute" >&2; is_usage ;; esac
h_assert_test_isolation || exit 70
h_check_dir "$H_BASE" || { echo "unsafe base directory" >&2; exit 1; }
[ -d "$IS_EVID" ] && [ ! -L "$IS_EVID" ] && [ -O "$IS_EVID" ] && [ -w "$IS_EVID" ] || { echo "INIT FAILED: the evidence directory is not usable (must exist, not a symlink, owned by you, writable)" >&2; exit 1; }
IS_EV="$(mktemp -d "$IS_EVID/init.XXXXXX")" && [ -d "$IS_EV" ] && [ ! -L "$IS_EV" ] && chmod 700 "$IS_EV" || { echo "INIT FAILED: cannot create the private evidence directory" >&2; exit 1; }
H_RUNDIR="$IS_EV"; H_REGFILE="$IS_EV/registry"
: > "$IS_EV/steps.tsv" || { echo "INIT FAILED: cannot write the evidence" >&2; exit 1; }
h_env_paths
note "initialisation of [$H_STATE_DIR]; evidence $IS_EV; confirmation of a clean host: $IS_CONFIRM"

# ---- 1. what is there? (nothing is changed) --------------------------------------------------------
if h_legacy_lock_present; then is_fail "LEGACY_LOCK: an old-format lock or an old state file exists [$(h_clip "$H_LEGACY_PATH" 120)] (old format): it is not interpreted or removed; a human must review it"; fi
need=""
h_state_dir_check; rc=$?
case "$rc" in
    2) is_fail "UNKNOWN: the state directory is unsafe (a symbolic link, not a directory, not yours, not mode 700, or an unsafe parent)" ;;
    1) need=create ;;
    0)
        h_env_enter; rc=$?
        case "$rc" in
            0) h_mutex_drop
               record "init:class" ok "INITIALIZED (state $H_ST_STATE)"
               echo "INIT OK: already initialised (state $H_ST_STATE, init id $H_INIT_ID): nothing was changed; evidence $IS_EV"
               exit 0 ;;
            1) is_fail "BUSY: a run, a recovery or another initialisation holds the exclusion" ;;
            *) case "$H_ENV_CLASS" in
                   UNINITIALIZED) need=create ;;
                   INIT_INCOMPLETE) need=resume ;;
                   *) is_fail "$H_ENV_MSG" ;;
               esac ;;
        esac ;;
esac
record "init:class" ok "needs $need"

# ---- 2. the explicit confirmation, and the automatic evidence that the host carries nothing of an earlier run ----------
if [ "$IS_CONFIRM" != 1 ]; then
    note "the initialisation needs the Owner's explicit confirmation: --confirm-clean-host"
    echo "INIT REFUSED: initialising ($need) needs --confirm-clean-host (the Owner's statement that this host carries no unrecovered change of an earlier run); nothing was changed" >&2
    exit 2
fi
leftover="$(for d in "$H_BASE"/sinter-h-*; do [ -d "$d" ] && [ ! -L "$d" ] && [[ "$(basename "$d")" =~ ^sinter-h-[a-z0-9-]+\.[A-Za-z0-9]{6}$ ]] && echo "$d"; done 2> /dev/null | head -1)"
[ -z "$leftover" ] || is_fail "a run directory of an earlier run exists [$(h_clip "$leftover" 120)]: the host was used; a human must review it"
record "init:no-leftover-run-directory" ok ok
h_snapshot pre || is_fail "the package listing could not be read and validated"
syn="$(awk -F'\t' '$2 ~ /^sinter-t-/ {print $2}' "$H_RUNDIR/snap.pre" | head -3 | tr '\n' ' ')"
[ -z "$syn" ] || is_fail "synthetic packages are installed [$syn]: an earlier run left changes; recover them first"
record "init:no-synthetic-package" ok ok
for p in "$H_DPKG_TARGET" "$H_DPKGQ_TARGET"; do
    if "$H_FINDMNT" -n -M "$p" > /dev/null 2>&1; then is_fail "$p is a mount point (a wrapper mount remains)"; fi
    if h_is_shim "$p"; then is_fail "$p is a harness wrapper"; fi
done
record "init:no-wrapper-mounts" ok ok
note "NOT checked automatically: foreign architectures and anything else the harness does not record (the confirmation covers it)"

# ---- 3. create / resume -----------------------------------------------------------------------------
if [ "$need" = create ] && [ ! -e "$H_STATE_DIR" ] && [ ! -L "$H_STATE_DIR" ]; then
    parent="$(dirname "$H_STATE_DIR")"
    h_check_dir "$parent" || is_fail "the parent directory [$parent] is unsafe"
    if [ -w "$parent" ]; then mkdir -m 700 "$H_STATE_DIR" 2> /dev/null
    else "${H_SUDO[@]+"${H_SUDO[@]}"}" mkdir -m 700 "$H_STATE_DIR" 2> /dev/null && "${H_SUDO[@]+"${H_SUDO[@]}"}" chown "$IS_ME" "$H_STATE_DIR" 2> /dev/null; fi
    if h_env_fault kill-after-dir; then :; fi
fi
h_state_dir_check || is_fail "the state directory could not be created safely (mode 700, yours)"
record "init:state-directory" ok "$H_STATE_DIR"
h_env_initialize; rc=$?
case "$rc" in
    0) ;;
    1) is_fail "${H_ENV_MSG:-refused}" ;;
    *) is_fail "${H_ENV_MSG:-failed} (the initialisation is incomplete; INIT_INCOMPLETE is recognised and it can be completed by running this tool again)" ;;
esac
record "init:result" ok "$H_INIT_RESULT"
cp "$H_INIT_PATH" "$IS_EV/init-record.copy" 2> /dev/null && cp "$H_STATE_PATH" "$IS_EV/state-record.copy" 2> /dev/null || is_fail "the records could not be copied to the evidence (the environment IS initialised)"
cmp -s "$H_INIT_PATH" "$IS_EV/init-record.copy" && cmp -s "$H_STATE_PATH" "$IS_EV/state-record.copy" || is_fail "the evidence copy of the records reads back differently (the environment IS initialised)"
echo "INIT OK: $H_INIT_RESULT [$H_STATE_DIR] (init id $(sed 's/^[^;]*;id=\([0-9a-f]*\);.*/\1/' "$H_INIT_PATH")); evidence $IS_EV"
exit 0
