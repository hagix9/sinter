#!/bin/bash
# shims.sh -- temporary wrappers over dpkg / dpkg-query for the real-host scenarios (bind mounts, not persistent).
#
# Differences to the wrappers of the 2026-10-24 run (which caused the incident):
#  * every call works in its own fresh `mktemp -d` directory; nothing is ever read back from a file the
#    call did not create, so a stale file can not be printed;
#  * if the call can not create its private directory (for example an unprivileged caller), the wrapper is a
#    pure pass-through (exec of the real program): same stdout, stderr and exit status, no capture;
#  * the wrapper directory is root-owned and 0755, not world-writable; logging is best effort and never
#    changes what the wrapped program printed;
#  * the harness itself never goes through the wrappers (it calls the real programs by their saved path);
#  * mount/umount failures are never ignored: a failed install rolls back, a failed removal fails the cleanup
#    (the lib refuses to purge while a wrapper is mounted).
# Requires safe-lib.sh.  H_MOUNT/H_UMOUNT/H_FINDMNT and the two target paths are variables so the tests can
# inject mocks (the tests never mount anything).

: "${H_MOUNT:=mount}"
: "${H_UMOUNT:=umount}"
: "${H_DPKG_TARGET:=/usr/bin/dpkg}"
: "${H_DPKGQ_TARGET:=/usr/bin/dpkg-query}"
H_SHIMS=""                                     # kinds currently installed
: "${H_PID1_ROOT:=/proc/1/root}"             # how the host's own view of the file system is reached
if declare -F h_production > /dev/null 2>&1 && h_production; then H_PID1_ROOT=/proc/1/root; fi   # never from the environment

h_tmpl_dpkg() {
    cat << 'TMPL_EOF'
#!/bin/bash
# SINTER-HARNESS-SHIM
# Sinter test wrapper over dpkg: transparent; for a real --remove/--purge it keeps what the real dpkg wrote;
# when armed ($D/arm, written by the harness) it first lets "another process" run one dpkg command.
REAL='@REAL@'
D='@D@'
log() { printf '%s\n' "$*" >> "$D/shim.log" 2> /dev/null || true; }
log "$(date +%s.%N 2> /dev/null) uid=$(id -u) argv: $*"
case " $* " in *" --dry-run "*) exec "$REAL" "$@" ;; esac
case " $* " in
    *" --remove "*|*" --purge "*)
        cap="$(mktemp -d "$D/c.XXXXXX" 2> /dev/null)" || exec "$REAL" "$@"
        { [ -d "$cap" ] && [ ! -L "$cap" ]; } || exec "$REAL" "$@"
        if [ -f "$D/arm" ] && [ ! -L "$D/arm" ]; then
            oargs=()
            while IFS= read -r line; do oargs[${#oargs[@]}]="$line"; done < "$D/arm"
            rm -f "$D/arm"
            log "other process: dpkg ${oargs[*]}"
            "$REAL" "${oargs[@]}" > "$cap/other.out" 2> "$cap/other.err"
            log "other rc=$?"
        fi
        "$REAL" "$@" > "$cap/real.out" 2> "$cap/real.err"
        rc=$?
        cat "$cap/real.out"
        cat "$cap/real.err" >&2
        log "real rc=$rc cap=$cap"
        exit "$rc"
        ;;
esac
exec "$REAL" "$@"
TMPL_EOF
}

h_tmpl_dpkg_query() {
    cat << 'TMPL_EOF'
#!/bin/bash
# SINTER-HARNESS-SHIM
# Sinter test wrapper over dpkg-query: transparent (byte-exact); logs calls; in a test mode ($D/qmode) it answers the
# per-instance query with a prepared, deliberately wrong answer.
REAL='@REAL@'
D='@D@'
log() { printf '%s\n' "$*" >> "$D/q.log" 2> /dev/null || true; }
log "$(date +%s.%N 2> /dev/null) uid=$(id -u) argv: $*"
instfmt='-f=${Status}\t${Package}\t${Architecture}\n'
if [ "$1" = -W ] && [ "$2" = "$instfmt" ] && [ -f "$D/qmode" ] && [ ! -L "$D/qmode" ]; then
    mode="$(cat "$D/qmode" 2> /dev/null)"
    name="$4"
    log "  instance query answered in test mode: $mode"
    case "$mode" in
        garbage)  printf 'not a record\n'; exit 0 ;;
        two)      printf 'install ok installed\t%s\tamd64\ninstall ok installed\t%s\ti386\n' "$name" "$name"; exit 0 ;;
        mismatch) printf 'install ok installed\tintruder\tamd64\n'; exit 0 ;;
        nonl)     printf 'install ok installed\t%s\tamd64' "$name"; exit 0 ;;
        exit1)    echo 'dpkg-query: error: simulated failure' >&2; exit 1 ;;
        empty)    exit 0 ;;
        broken)   printf 'install ok installed\t%s\tamd64\ninstall ok half-configured\t%s\ti386\n' "$name" "$name"; exit 0 ;;
        stderr)   "$REAL" "$@"; echo 'dpkg-query: warning: simulated diagnostic' >&2; exit 0 ;;
    esac
fi
cap="$(mktemp -d "$D/q.XXXXXX" 2> /dev/null)" || exec "$REAL" "$@"
{ [ -d "$cap" ] && [ ! -L "$cap" ]; } || exec "$REAL" "$@"
"$REAL" "$@" > "$cap/out" 2> "$cap/err"
rc=$?
case "$2" in
    -f=\$\{Status\}*) { echo "--- argv: $*"; cat "$cap/out"; echo "--- rc=$rc"; } >> "$D/q.out.log" 2> /dev/null || true ;;
esac
cat "$cap/out"
cat "$cap/err" >&2
rm -f "$cap/out" "$cap/err"
rmdir "$cap" 2> /dev/null
exit "$rc"
TMPL_EOF
}

h_shim_render() {  # h_shim_render dpkg|dpkg_query REAL D -> the wrapper text
    local kind="$1" real="$2" d="$3"
    case "$real$d" in *'|'*|*'&'*|*'\'*|*"'"*|*$'\n'*) return 1 ;; esac
    "h_tmpl_$kind" | sed -e "s|@REAL@|$real|" -e "s|@D@|$d|"
}

h_mount_residue() {  # h_mount_residue PATH -> a mount could not be removed: every later mutation and the cleanup are refused
    H_MOUNT_RESIDUE="$H_MOUNT_RESIDUE $1"
    h_abort "FAILED: the wrapper mount on $(h_clip "$1") could not be removed; nothing more is installed, removed or purged"
}
h_ns_check() {  # the wrappers may be mounted only in a PRIVATE mount namespace of this run (B-1): re-verified from the kernel state
    declare -F h_ns_require > /dev/null 2>&1 || { h_abort "the namespace gate is not loaded: wrappers are not mounted"; return 1; }
    if ! h_ns_require 2> "${H_RUNDIR:-/dev/null}/ns-check.err"; then
        h_abort "the private mount namespace could not be verified ($(h_err_summary "${H_RUNDIR:-/dev/null}/ns-check.err")): wrappers are not mounted"
        return 1
    fi
    h_note "mount namespace $H_NS_ID (init: $H_NS_HOST_ID), every mount private"
    return 0
}
h_leak_check() {  # h_leak_check TARGET -> 0 only if the host's own view of TARGET is NOT the wrapper
    local rc
    h_sudo_run grep -c SINTER-HARNESS-SHIM "$H_PID1_ROOT$1" > /dev/null 2>&1
    rc=$?
    [ "$rc" = 1 ]      # 0 = the wrapper is visible to the host, >=2 = could not verify: both are failures
}
h_shim_dir() {  # the wrapper directory: root-owned, 0755, inside the base directory
    H_SHIMDIR="$H_BASE/sinter-h-wrap.$H_RUN_ID"
    if [ ! -d "$H_SHIMDIR" ]; then h_sudo_run mkdir -m 755 "$H_SHIMDIR" || return 1; fi
    h_check_dir "$H_SHIMDIR" || return 1
    return 0
}

h_shim_install() {  # h_shim_install dpkg|dpkg_query
    local kind="$1" target real shim mounted=""
    h_guard "shim:$kind" || return 1
    case "$kind" in dpkg) target="$H_DPKG_TARGET" ;; dpkg_query) target="$H_DPKGQ_TARGET" ;; *) h_abort "unknown shim kind"; return 1 ;; esac
    h_ns_check || return 1
    h_shim_dir || { h_abort "the wrapper directory is not safe"; return 1; }
    real="$H_SHIMDIR/$kind-real"; shim="$H_SHIMDIR/$kind-shim.sh"
    if "$H_FINDMNT" -n -M "$target" > /dev/null 2>&1 || [ -e "$real" ]; then h_abort "a wrapper or a leftover is already present for $kind"; return 1; fi
    h_sudo_run touch "$real" || { h_fail "shim:$kind" "cannot create the bind target"; return 1; }
    if ! h_sudo_run "$H_MOUNT" --bind "$target" "$real"; then h_sudo_run rm -f "$real"; h_fail "shim:$kind" "bind mount of the real program failed"; return 1; fi
    # without this the second mount propagates into the first and the "real" program becomes the wrapper (endless exec loop)
    if ! h_sudo_run "$H_MOUNT" --make-private "$real"; then h_shim_rollback "$kind" "$target" "$real"; h_fail "shim:$kind" "make-private failed"; return 1; fi
    h_shim_render "$kind" "$real" "$H_SHIMDIR" | h_sudo_run tee "$shim" > /dev/null && h_sudo_run chmod 755 "$shim" || { h_shim_rollback "$kind" "$target" "$real"; h_fail "shim:$kind" "cannot write the wrapper"; return 1; }
    if ! h_sudo_run "$H_MOUNT" --bind "$shim" "$target"; then h_shim_rollback "$kind" "$target" "$real"; h_fail "shim:$kind" "bind mount of the wrapper failed"; return 1; fi
    if ! h_is_shim "$target" || h_is_shim "$real" || ! "$real" --version > /dev/null 2>&1 || ! "$target" --version > /dev/null 2>&1; then
        h_fail "shim:$kind" "the wrapper self-test failed"
        h_shim_remove "$kind" > /dev/null 2>&1 || h_fail "shim:$kind" "the wrapper could not be removed after the failed self-test"
        return 1
    fi
    # B-1: the host's own view (init's namespace) must still show the REAL program: the wrapper is private to this run
    if ! h_leak_check "$target"; then
        h_abort "the wrapper on $(h_clip "$target") is visible outside the private mount namespace (or the host view cannot be read)"
        h_shim_remove "$kind" > /dev/null 2>&1 || h_fail "shim:$kind" "the wrapper could not be removed after the leak was found"
        return 1
    fi
    # the harness itself never goes through a wrapper: its own calls use the saved real program
    case "$kind" in dpkg) H_DPKG_SAVED="$H_DPKG"; H_DPKG="$real" ;; dpkg_query) H_DPKGQ_SAVED="$H_DPKG_QUERY"; H_DPKG_QUERY="$real" ;; esac
    H_SHIMS="$H_SHIMS $kind"
    return 0
}
h_shim_rollback() {  # h_shim_rollback KIND TARGET REAL -- unmount what was mounted; files are removed only when nothing is mounted
    local kind="$1" real="$3"
    if "$H_FINDMNT" -n -M "$real" > /dev/null 2>&1; then
        h_sudo_run "$H_UMOUNT" "$real" > /dev/null 2>&1
        if "$H_FINDMNT" -n -M "$real" > /dev/null 2>&1; then h_mount_residue "$real"; return 1; fi
    fi
    h_sudo_run rm -f "$real" "$H_SHIMDIR/$kind-shim.sh" || { h_fail "shim:$kind" "the rollback could not remove its files"; return 1; }
    return 0
}
h_shim_remove() {  # h_shim_remove dpkg|dpkg_query -> 0 only if nothing is mounted any more
    local kind="$1" target real shim rc=0
    case "$kind" in dpkg) target="$H_DPKG_TARGET" ;; dpkg_query) target="$H_DPKGQ_TARGET" ;; *) return 1 ;; esac
    [ -n "${H_SHIMDIR:-}" ] || return 0
    real="$H_SHIMDIR/$kind-real"; shim="$H_SHIMDIR/$kind-shim.sh"
    if "$H_FINDMNT" -n -M "$target" > /dev/null 2>&1; then
        h_sudo_run "$H_UMOUNT" "$target" || rc=1
        if "$H_FINDMNT" -n -M "$target" > /dev/null 2>&1; then h_fail "shim:$kind" "$(h_clip "$target") is still mounted after umount"; h_mount_residue "$target"; return 1; fi
    fi
    if "$H_FINDMNT" -n -M "$real" > /dev/null 2>&1; then
        h_sudo_run "$H_UMOUNT" "$real" || rc=1
        if "$H_FINDMNT" -n -M "$real" > /dev/null 2>&1; then h_fail "shim:$kind" "the bind target is still mounted after umount"; h_mount_residue "$real"; return 1; fi
    fi
    case "$kind" in dpkg) [ -n "${H_DPKG_SAVED:-}" ] && H_DPKG="$H_DPKG_SAVED" ;; dpkg_query) [ -n "${H_DPKGQ_SAVED:-}" ] && H_DPKG_QUERY="$H_DPKGQ_SAVED" ;; esac
    # only now (nothing mounted) are the files removed
    h_sudo_run rm -f "$shim" "$real" || rc=1
    if [ "$rc" != 0 ]; then h_fail "shim:$kind" "unmount/removal reported an error"; return 1; fi
    local k keep=""; for k in $H_SHIMS; do [ "$k" = "$kind" ] || keep="$keep $k"; done; H_SHIMS="$keep"
    return 0
}
h_shims_finish() {  # called by h_finish BEFORE the cleanup: every wrapper still mounted is removed; a failure leaves a residue
    local k
    for k in $H_SHIMS; do h_shim_remove "$k" > /dev/null 2>&1 || h_fail "shim:$k" "the wrapper could not be removed at the end of the run"; done
    return 0
}
h_shim_arm() {  # h_shim_arm FILE-NAME -> "another process" installs this payload file right before the next real --remove
    local f="$1"
    h_guard arm || return 1
    # the package the "other process" will install is verified and registered HERE (the cleanup must know it; no direct registration exists)
    h_prepare_install "$f" || return 1
    printf '%s\n%s\n' "-i" "$H_PK/$f" | h_sudo_run tee "$H_SHIMDIR/arm" > /dev/null || { h_fail "shim:arm" "cannot write the arm file"; return 1; }
}
h_shim_unarm() { h_sudo_run rm -f "$H_SHIMDIR/arm"; }
h_shim_qmode() {  # h_shim_qmode MODE|"" -> answer mode of the dpkg-query wrapper
    case "$1" in garbage|two|mismatch|nonl|exit1|empty|broken|stderr) printf '%s' "$1" | h_sudo_run tee "$H_SHIMDIR/qmode" > /dev/null ;; "") h_sudo_run rm -f "$H_SHIMDIR/qmode" ;; *) h_abort "unknown query mode"; return 1 ;; esac
}
h_shim_collect() {  # h_shim_collect LABEL -> copies the wrapper logs and the last real --remove/--purge capture into $OUT/logs
    local label="$1" capdir f
    [ -n "${OUT:-}" ] && [ -d "$OUT/logs" ] || return 1
    for f in shim.log q.log q.out.log; do
        [ -f "$H_SHIMDIR/$f" ] && { h_sudo_run cp "$H_SHIMDIR/$f" "$OUT/logs/$label.$f" || h_fail "evidence:$label" "cannot copy $f"; }
    done
    capdir="$(h_sudo_run grep -h 'real rc=' "$H_SHIMDIR/shim.log" 2> /dev/null | tail -1 | sed -n 's/.*cap=//p')"
    if [ -n "$capdir" ]; then
        case "$capdir" in "$H_SHIMDIR"/c.*) ;; *) h_fail "evidence:$label" "unexpected capture path"; return 1 ;; esac
        for f in real.out real.err other.out other.err; do
            # the capture directory is created by the wrapper as root (mktemp, 0700): even the existence test needs root
            if h_sudo_run test -e "$capdir/$f"; then h_sudo_run cp "$capdir/$f" "$OUT/logs/$label.shim.$f" || h_fail "evidence:$label" "cannot copy $f"; fi
        done
    fi
    h_sudo_run chown "$(id -u):$(id -g)" "$OUT/logs/$label".* 2> /dev/null
    return 0
}
h_shim_reset_logs() {  # before each Sinter run: empty logs, so a run never sees the previous run's capture
    h_sudo_run rm -f "$H_SHIMDIR/shim.log" "$H_SHIMDIR/q.log" "$H_SHIMDIR/q.out.log" || return 1
}
