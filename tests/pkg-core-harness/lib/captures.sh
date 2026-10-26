#!/bin/bash
# captures.sh -- direct `dpkg --remove` captures: evidence about what dpkg itself writes (SA-3).
# Only packages this run registered (h_install_deb) can be targeted; the options are the safety options Sinter
# uses (--refuse-*), never a force option.  Requires safe-lib.sh.

: "${H_STDBUF:=stdbuf}"
H_REFUSE=(--refuse-depends --refuse-remove-essential --refuse-remove-protected)

h_capture_target() {  # h_capture_target name:arch -> H_TARGET (the argument dpkg gets)
    local s="$1" n a v
    h_valid_spec "$s" && h_is_registered "$s" && h_in_allowlist "$s" || { h_abort "capture of an unregistered package [$(h_clip "$s")]"; return 1; }
    n="${s%%:*}"; a="${s#*:}"
    # identity right before the command: if the package exists it must be the version this run registered, not Essential
    h_query_pkg "$n" "$a" || return 1
    if [ "$H_PSTATE" != absent ] && ! h_state_gone "$H_PSTATE"; then
        v="$(h_reg_ver "$s")" || { h_abort "no registered version for [$(h_clip "$s")]"; return 1; }
        if [ "$H_PVER" != "$v" ] || [ "$H_PESS" = yes ]; then h_abort "capture target $s is not the package this run installed (version [$(h_clip "$H_PVER")], essential [$H_PESS])"; return 1; fi
    fi
    if [ "$a" = all ]; then H_TARGET="$n"; else H_TARGET="$n:$a"; fi
}
h_capture_save() {  # h_capture_save LABEL -> copies H_OUTF/H_ERRF/H_RC into $OUT/logs
    local l="$1"
    [ -n "${OUT:-}" ] && [ -d "$OUT/logs" ] || { h_fail "evidence:$l" "no evidence directory"; return 1; }
    cp "$H_OUTF" "$OUT/logs/$l.out" && cp "$H_ERRF" "$OUT/logs/$l.err" && printf '%s\n' "$H_RC" > "$OUT/logs/$l.rc" || { h_fail "evidence:$l" "cannot save the capture"; return 1; }
}
h_capture_remove() {  # h_capture_remove LABEL name:arch [unpriv]
    local l="$1" s="$2"
    h_guard capture || return 1
    h_capture_target "$s" || return 1
    if [ "${3:-}" = unpriv ]; then h_run "capture:$l" "$H_DPKG" "${H_REFUSE[@]}" --remove "$H_TARGET" || return 1
    else h_run "capture:$l" h_sudo_run "$H_DPKG" "${H_REFUSE[@]}" --remove "$H_TARGET" || return 1; fi
    h_capture_save "$l"
}
h_capture_dry_purge() {  # h_capture_dry_purge LABEL name:arch -> dpkg's own dry-run text for a registered package (changes nothing)
    local l="$1" s="$2"
    h_guard capture || return 1
    h_capture_target "$s" || return 1
    h_run "capture:$l" h_sudo_run "$H_DPKG" --dry-run --purge "$H_TARGET" || return 1
    h_capture_save "$l"
}
h_reader_script() {
    cat << 'PY_EOF'
import os, sys, time
log = open(sys.argv[1], "w")
seen = sys.argv[2]
while True:
    chunk = os.read(0, 4096)
    if not chunk:
        break
    t = time.time()
    for line in chunk.splitlines(True):
        log.write("%.6f %s" % (t, line.decode("ascii", "replace")))
        log.flush()
        if line.startswith(b"Removing "):
            open(seen, "w").close()
PY_EOF
}
h_capture_remove_ordered() {  # h_capture_remove_ordered LABEL name:arch line|default
    local l="$1" s="$2" mode="$3" n py errf rcf
    h_guard capture || return 1
    h_capture_target "$s" || return 1
    n="${s%%:*}"
    case "$mode" in line|default) ;; *) h_abort "bad buffering mode"; return 1 ;; esac
    [ -n "${OUT:-}" ] && [ -d "$OUT/logs" ] || { h_fail "evidence:$l" "no evidence directory"; return 1; }
    py="$H_RUNDIR/reader.py"; h_reader_script > "$py" || { h_fail "capture:$l" "cannot write the reader"; return 1; }
    errf="$OUT/logs/$l.err"; rcf="$OUT/logs/$l.rc"
    h_sudo_run rm -f "$H_FLAGDIR/$n.seen"
    H_ARMED[${#H_ARMED[@]}]="$n.seen"
    {
        if [ "$mode" = line ]; then h_sudo_run "$H_STDBUF" -oL "$H_DPKG" "${H_REFUSE[@]}" --remove "$H_TARGET" 2> "$errf"
        else h_sudo_run "$H_DPKG" "${H_REFUSE[@]}" --remove "$H_TARGET" 2> "$errf"; fi
        printf '%s\n' "$?" > "$rcf"
    } | h_sudo_run python3 -I "$py" "$OUT/logs/$l.stdout.log" "$H_FLAGDIR/$n.seen"
    [ -s "$rcf" ] || { h_fail "capture:$l" "no exit status was recorded"; return 1; }
    return 0
}
