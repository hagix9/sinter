#!/usr/bin/env python3
"""Mutation check of the harness safety layer: each mutant weakens ONE safety rule in a private copy of the harness
(the original is never touched) and the test suite must fail.  Usage: run-mutants.py OUT.tsv [NAME-PREFIX...]
A mutant that survives is either a missing test or an equivalent mutation (classified by hand in 05-test-results.md)."""
import concurrent.futures, os, re, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(HERE)                      # harness/
WORK = os.environ.get("MUT_WORK") or sys.exit("set MUT_WORK to a scratch directory on the external SSD (<EXTERNAL_TMP>/...)")
JOBS = int(os.environ.get("MUT_JOBS", "4"))
# cases that exercise the library (the end-to-end smoke cases are run for the scenario-level mutants only)
LIB_CASES = "t0[0-9]* t1[0-9] t1[0-9][a-z] t2[0-9] t2[0-9][a-z] t30 t31 t32 t33 t34 t35 t36 t42 t43 t44 t45 t46 t47 t48 t49 t49b t50 t50b t50c t50d t50e t51 t52 t53 t54 t55a t55b t55c t55d t55e t56 t57 t58 t59 t60 t61 t62 t63 t64 t65 t66"   # library cases (no shim templates, lint, smoke)

SHIM_CASES = "t01 t27 t37 t39 t39b t39c t40 t48 t62"
LOCK_CASES = "t15 t16 t17 t17b t17c t17d t72 t90 t102 t104 t113 t124 t125 t126 t131 t132 t133 t134 t135 t136 t137 t138 t139 t144 t148"
INIT_CASES = "t102 t125 t139 t149 t15[0-9] t16[0-9] t17[0-2]"
GATE_CASES = "t70 t71 t72 t73 t74 t75 t76 t77 t78 t79 t80 t81 t82 t83 t109"
REC_CASES = "t9[0-9] t10[0-9] t11[0-9] t12[0-9] t13[0-9] t14[0-8]"
L, S, C = "lib/safe-lib.sh", "lib/shims.sh", "lib/captures.sh"
NS = "lib/nscheck.sh"
RB = "recovery/body.sh"
IB = "init/body.sh"
M = [  # (name, file, old, new, cases)
 ("L01 name: no sinter-t- prefix", L, "local re='^sinter-t-[a-z0-9]+(-[a-z0-9]+)*$'", "local re='^[a-z0-9]+(-[a-z0-9]+)*$'"),
 ("L02 name: no length limit", L, '[[ "$1" =~ $re ]] && [ "${#1}" -le 48 ]', '[[ "$1" =~ $re ]]'),
 ("L03 arch: anything", L, '    for a in $H_ARCHES; do [ "$1" = "$a" ] && return 0; done\n    return 1', '    return 0'),
 ("L04 spec: no colon checks", L, 'case "$s" in *:*:*|:*|*:|"") return 1 ;; esac\n    case "$s" in *:*) ;; *) return 1 ;; esac', ':'),
 ("L05 allowlist: always true", L, '    for x in "${H_PAYLOAD_ALLOW[@]+"${H_PAYLOAD_ALLOW[@]}"}"; do [ "$x" = "$1" ] && return 0; done\n    return 1', '    return 0'),
 ("L06 registered: always true", L, '    for x in "${H_REG[@]+"${H_REG[@]}"}"; do [ "$x" = "$1" ] && return 0; done\n    return 1', '    return 0'),
 ("L07 register: no allowlist check", L, '    h_in_allowlist "$s" || { h_abort "package is not in the scenario allowlist [$s]"; return 1; }\n', ''),
 ("L08 register: no maximum", L, '    [ "${#H_REG[@]}" -lt "$H_MAX_PKGS" ] || { h_abort "more than $H_MAX_PKGS packages registered"; return 1; }\n', ''),
 ('L09 payload: no file-name pattern', L, '    [[ "$f" =~ $re ]] || { h_abort "payload file name does not match the pattern [$(h_clip "$f")]"; return 1; }\n', '    [[ "$f" =~ $re ]]\n'),
 ('L10 payload: no deb field check', L, '    if [ "$H_RC" != 0 ] || [ -s "$H_ERRF" ] || [ "$(cat "$H_OUTF")" != "$want" ]; then\n        h_abort "the payload file does not contain the package its name says"; return 1\n    fi\n', ''),
 ('L11 payload: symlink accepted', L, '[ -n "${H_PK:-}" ] && [ -f "$H_PK/$f" ] && [ ! -L "$H_PK/$f" ] || { h_abort "payload file missing"; return 1; }\n    h_run "deb-fields:$f"', '[ -n "${H_PK:-}" ] && [ -f "$H_PK/$f" ] || { h_abort "payload file missing"; return 1; }\n    h_run "deb-fields:$f"'),
 ("L12 text: NUL accepted", L, '    [ $((a)) -eq $((b)) ] || return 1\n', ''),
 ("L13 text: non-printable accepted", L, "    if LC_ALL=C grep -q '[^[:print:][:space:]]' \"$f\"; then return 1; fi\n", ''),
 ("L14 text: CR accepted", L, '''    if LC_ALL=C grep -q "$(printf '[\\r\\v\\f]')" "$f"; then return 1; fi\n''', ''),
 ("L15 text: incomplete last line accepted", L, '''    [ "$(tail -c 1 "$f" | od -An -tx1 | tr -d ' \\n')" = "0a" ] || return 1\n''', ''),
 ("L16 snapshot: exit status ignored", L, '    [ "$H_RC" = 0 ] || { h_fail "snapshot:$label" "dpkg-query exited $H_RC"; return 1; }\n', ''),
 ("L17 snapshot: stderr ignored", L, '    [ ! -s "$H_ERRF" ] || { h_fail "snapshot:$label" "dpkg-query wrote to stderr: $(h_err_summary "$H_ERRF")"; return 1; }\n', ''),
 ("L18 snapshot: empty accepted", L, '    [ -s "$H_OUTF" ] || { h_fail "snapshot:$label" "the listing is empty (an empty package set is not a valid answer)"; return 1; }\n', ''),
 ("L19 snapshot: no minimum", L, '    [ "$n" -ge "$H_MIN_PKGS" ] || { h_fail "snapshot:$label" "only $n records (minimum $H_MIN_PKGS)"; return 1; }\n', ''),
 ("L20 snapshot: records not validated", L, '        h_parse_record "$line" || { h_fail "snapshot:$label" "unparseable record [$(h_clip "$line")]"; return 1; }\n        n=$((n + 1))', '        n=$((n + 1))'),
 ("L21 snapshot: duplicates accepted", L, '    if [ -n "$(LC_ALL=C cut -f2,3 "$f" | LC_ALL=C uniq -d)" ]; then h_fail "snapshot:$label" "duplicate name:arch records"; return 1; fi\n', ''),
 ("L22 snapshot: text check skipped", L, '    h_text_ok "$H_OUTF" || { h_fail "snapshot:$label" "the listing is not clean, complete text"; return 1; }\n', ''),
 ("L23 query: any error means absent", L, '    [ "$H_RC" = 0 ] || { h_fail "query:$n" "dpkg-query exited $H_RC: $(h_err_summary "$H_ERRF")"; return 1; }', '    [ "$H_RC" = 0 ] || { H_PSTATE=absent; return 0; }'),
 ("L24 query: another package accepted", L, '        [ "$H_R_NAME" = "$n" ] || { h_fail "query:$n" "the answer names another package [$(h_clip "$H_R_NAME")]"; return 1; }\n', ''),
 ("L25 query: stderr ignored", L, '    [ ! -s "$H_ERRF" ] || { h_fail "query:$n" "dpkg-query wrote to stderr: $(h_err_summary "$H_ERRF")"; return 1; }\n', ''),
 ("L26 query: other message means absent", L, 'if [ "$msg" = "dpkg-query: no packages found matching $n" ]; then H_PSTATE=absent; return 0; fi', 'H_PSTATE=absent; return 0'),
 ("L27 compare: non-test changes ignored", L, '    if cmp -s "$a" "$b"; then return 0; fi\n    H_DIFF="$(diff "$a" "$b" | head -6', '    return 0\n    H_DIFF="$(diff "$a" "$b" | head -6'),
 ("L28 baseline: leftovers accepted", L, '    if [ -n "$left" ]; then h_abort "leftover test packages exist before the run (not removed): $(h_clip "$left" 160)"; return 1; fi\n', ''),
 ("L29 cleanup: no non-test comparison", L, '    if ! h_compare_nonreg base cur; then h_abort "non-test packages differ from the baseline; nothing was purged: ${H_DIFF:-}"; return 1; fi\n', ''),
 ("L30 cleanup: no shrink guard", L, '    if [ "$cnt_c" -lt "$lim" ]; then h_abort "the package set shrank from $cnt_b to $cnt_c records; nothing was purged"; return 1; fi\n', ''),
 ("L31 cleanup: Essential accepted", L, '        if [ "$H_PESS" = yes ]; then h_abort "registered package $spec is Essential: removal needs a separate, reviewed plan"; return 1; fi\n', ''),
 ("L32 cleanup: error states accepted", L, '        case "${H_PSTATE:2:1}" in R|H|X) h_abort "registered package $spec is in an error state [$H_PSTATE]: removal needs a separate, reviewed plan"; return 1 ;; esac\n', ''),
 ("L33 cleanup: no plan maximum", L, '    [ "${#plan[@]}" -le "$H_MAX_PKGS" ] || { h_abort "the cleanup plan exceeds $H_MAX_PKGS packages"; return 1; }\n', ''),
 ("L34 cleanup: no final comparison", L, '    if ! h_compare_full base final; then h_fail "cleanup" "the host differs from the baseline after the cleanup: ${H_DIFF:-}"; return 1; fi\n', ''),
 ("L35 cleanup: wrappers not checked", L, '    h_wrappers_clear || return 1\n    h_snapshot cur', '    h_snapshot cur'),
 ("L36 purge: no registered check", L, '    h_valid_spec "$s" && h_is_registered "$s" && h_in_allowlist "$s" || { h_abort "refusing to purge [$(h_clip "$s")]"; return 1; }', '    :'),
 ('L37 purge: dry-run result ignored', L, '        h_dry_run_exact "$n" "$a" "$v" || { h_abort "the purge dry-run does not name exactly the target (empty, other packages, or another version)"; return 1; }\n', ''),
 ("L38 purge: failure ignored", L, '    [ "$H_RC" = 0 ] || { h_fail "cleanup:$s" "purge failed (exit $H_RC); no escalation: $(h_err_summary "$H_ERRF")"; return 1; }', '    :'),
 ("L39 cleanup failure does not abort", L, "    H_CLEANUP_STATUS=failed\n    H_ABORTED=1\n    return 1\n}\nh_cleanup_inner", "    H_CLEANUP_STATUS=failed\n    return 1\n}\nh_cleanup_inner"),
 ("L41 exit trap: exit status not changed", L, '        [ "$rc" = 0 ] && rc=70', '        :'),
 ("L42 verdict: cleanup failure ignored", L, '[ "$H_CLEANUP_STATUS" = ok ]; then\n        echo "SCENARIO: PASS"', 'true; then\n        echo "SCENARIO: PASS"'),
 ("L43 dir check: sticky bit not required", L, "        case \"$first\" in 1|3|5|7) ;; *) return 1 ;; esac", "        :"),
 ("L44 dir check: symlink accepted", L, '    [ -n "$d" ] && [ -d "$d" ] && [ ! -L "$d" ] || return 1\n    m="$(h_stat_mode', '    [ -n "$d" ] && [ -d "$d" ] || return 1\n    m="$(h_stat_mode'),
 ("L46 run: fixed temp file names", L, '    o="$(mktemp "$H_RUNDIR/o.XXXXXX")" || { h_fail "$label" "cannot create a temp file"; return 1; }\n    e="$(mktemp "$H_RUNDIR/e.XXXXXX")" || { h_fail "$label" "cannot create a temp file"; return 1; }', '    o="$H_RUNDIR/o.fixed"; e="$H_RUNDIR/e.fixed"; : >> "$o" 2> /dev/null; : >> "$e" 2> /dev/null'),
 ("L47 isolation: not enforced", L, '    [ "${H_TEST_MODE:-0}" = 1 ] || return 0\n    local v p', '    return 0\n    local v p'),
 ("L48 selection: any package", L, '        h_valid_spec "$s" && h_is_registered "$s" || { h_abort "selection for a package this run did not register [$(h_clip "$s")]"; return 1; }', '        :'),
 ("L49 flag names: any name", L, '    h_valid_name "$base" || return 1\n    case "$f" in', '    case "$f" in'),
 ("L50 snapshot: stale file kept (no rm, no noclobber)", L, '    rm -f "$f"\n    ( set -C; LC_ALL=C sort "$tmp" > "$f" ) 2> /dev/null && [ -f "$f" ] && [ ! -L "$f" ] || { h_fail "snapshot:$label" "cannot write the snapshot"; return 1; }', '    ( LC_ALL=C sort "$tmp" > "$f" ) 2> /dev/null || true'),
 ("L51 configure: unregistered package", L, '    h_valid_spec "$s" && h_is_registered "$s" && h_in_allowlist "$s" || { h_abort "refusing to configure [$(h_clip "$s")]"; return 1; }', '    :'),
 ("L52 shim check: wrappers not recognised", L, "h_is_shim() { LC_ALL=C grep -q 'SINTER-HARNESS-SHIM' \"$1\" 2> /dev/null; }", "h_is_shim() { return 1; }"),
 ("L53 traps: TERM not handled", L, "    trap 'exit 143' TERM\n", ""),
 ("L54 no-op cleanup ignores registrations", L, 'if [ "${#H_REG[@]}" -eq 0 ] && [ "${#H_ARMED[@]}" -eq 0 ]', 'if [ "${#H_ARMED[@]}" -eq 0 ]'),
 ("L55 arch: final check of the foreign architectures removed", L, '        if [ "$H_RC" != 0 ] || [ -s "$H_ERRF" ] || ! h_text_ok "$H_OUTF" || ! cmp -s "$H_OUTF" "$H_RUNDIR/foreign.base"; then\n            h_fail "cleanup" "the foreign architectures differ from the baseline"; return 1\n        fi\n', ''),
 ("L56 arch: a pre-existing architecture is removed too", L, '    if grep -qx -- "$a" "$H_RUNDIR/foreign.base"; then h_note "architecture $a was already configured; it is left as it was"; return 0; fi\n', ''),
 ("L57 arch: removed although packages of it remain", L, '    if awk -F\'\\t\' -v a="$H_ADDED_ARCH" \'$3 == a { found = 1 } END { exit !found }\' "$H_RUNDIR/snap.arch"; then\n        h_fail "cleanup" "packages of the architecture $H_ADDED_ARCH remain; it is not removed"; return 1\n    fi\n', ''),
 ("L58 configure failure ignored", L, '    [ "$H_RC" = 0 ] || { h_fail "cleanup:$s" "configure failed (exit $H_RC); no escalation: $(h_err_summary "$H_ERRF")"; return 1; }\n', ''),
 ("L59 half-configured is purged without configure", L, '        case "${H_PSTATE:1:1}" in F|U|W|t) h_configure_one "$spec" || return 1 ;; esac\n', ''),
 ("S01 shim: arm file symlink followed", S, '        if [ -f "$D/arm" ] && [ ! -L "$D/arm" ]; then', '        if [ -f "$D/arm" ]; then'),
 ("S02 shim: qmode symlink followed", S, 'if [ "$1" = -W ] && [ "$2" = "$instfmt" ] && [ -f "$D/qmode" ] && [ ! -L "$D/qmode" ]; then', 'if [ "$1" = -W ] && [ "$2" = "$instfmt" ] && [ -f "$D/qmode" ]; then'),
 ("S03 shim: capture failure is not a pass-through", S, 'cap="$(mktemp -d "$D/q.XXXXXX" 2> /dev/null)" || exec "$REAL" "$@"', 'cap="$(mktemp -d "$D/q.XXXXXX" 2> /dev/null)" || cap="$D/q.fixed"'),
 ("S04 shim: a test mode answers every query", S, 'if [ "$1" = -W ] && [ "$2" = "$instfmt" ] && [ -f "$D/qmode" ]', 'if [ "$1" = -W ] && [ -f "$D/qmode" ]'),
 ("S05 shim: dry-run captured and armed too", S, 'case " $* " in *" --dry-run "*) exec "$REAL" "$@" ;; esac\ncase " $* " in\n    *" --remove "*|*" --purge "*)', 'case " $* " in\n    *" --remove "*|*" --purge "*)'),
 ("S06 shim: exit status not kept", S, '        log "real rc=$rc cap=$cap"\n        exit "$rc"', '        log "real rc=$rc cap=$cap"\n        exit 0'),
 ('S07 shim install: second mount failure not rolled back', S, '    if ! h_sudo_run "$H_MOUNT" --bind "$shim" "$target"; then h_shim_rollback "$kind" "$target" "$real"; h_fail', '    if ! h_sudo_run "$H_MOUNT" --bind "$shim" "$target"; then h_fail'),
 ('S08 shim remove: still-mounted target ignored', S, '        if "$H_FINDMNT" -n -M "$target" > /dev/null 2>&1; then h_fail "shim:$kind" "$(h_clip "$target") is still mounted after umount"; h_mount_residue "$target"; return 1; fi\n', ''),
 ('S09 shim remove: files removed although mounted', S, '    if "$H_FINDMNT" -n -M "$real" > /dev/null 2>&1; then\n        h_sudo_run "$H_UMOUNT" "$real" || rc=1\n        if "$H_FINDMNT" -n -M "$real" > /dev/null 2>&1; then h_fail "shim:$kind" "the bind target is still mounted after umount"; h_mount_residue "$real"; return 1; fi\n    fi\n', ''),
 ('S10 shim arm: no payload verification', S, '    h_prepare_install "$f" || return 1\n    printf', '    printf'),
 ("S11 shim: harness keeps using the wrapped dpkg", S, '    case "$kind" in dpkg) H_DPKG_SAVED="$H_DPKG"; H_DPKG="$real" ;; dpkg_query) H_DPKGQ_SAVED="$H_DPKG_QUERY"; H_DPKG_QUERY="$real" ;; esac\n', ''),
 ("C01 capture: unregistered package", C, '    h_valid_spec "$s" && h_is_registered "$s" && h_in_allowlist "$s" || { h_abort "capture of an unregistered package [$(h_clip "$s")]"; return 1; }', '    :'),
 ("C02 capture: a force option", C, 'H_REFUSE=(--refuse-depends --refuse-remove-essential --refuse-remove-protected)', 'H_REFUSE=(--refuse-depends --force-depends --refuse-remove-protected)'),
 ('N01 purge_one: version not compared', L, '    if [ "$H_PVER" != "$v" ]; then h_abort "refusing to purge $s: installed version [$(h_clip "$H_PVER")] is not the registered [$v]"; return 1; fi\n', ''),
 ('N02 purge_one: Essential not checked', L, '    if [ "$H_PESS" = yes ]; then h_abort "refusing to purge $s: it is Essential"; return 1; fi\n', ''),
 ('N03 purge_one: any state is purged', L, 'case "$H_PSTATE" in "ii "|"ri "|"pi "|"rH "|"pH "|"iH "|?c?) ;; *) h_abort', 'case "$H_PSTATE" in *) ;; *) h_abort'),
 ('N04 dry-run: an empty answer is accepted', L, '    [ "$seen" = 1 ]\n}', '    [ "$seen" -le 1 ]\n}'),
 ('N05 dry-run: version not compared', L, '            [ "${BASH_REMATCH[3]}" = "$3" ] || return 1\n', ''),
 ('N06 dry-run: stderr ignored', L, '        [ ! -s "$H_ERRF" ] || { h_abort "the purge dry-run wrote to stderr: $(h_err_summary "$H_ERRF")"; return 1; }\n', ''),
 ('N07 install: pre-existing package adopted', L, '        [ "$H_PSTATE" = absent ] || { h_abort "$s exists before this run installed it [$H_PSTATE]: not adopted"; return 1; }\n', ''),
 ('N08 register: another version accepted', L, '        old="$(h_reg_ver "$s")" && [ "$old" = "$v" ] || { h_abort "$s is already registered with another version"; return 1; }\n', ''),
 ('N09 register: public registration allowed', L, '    h_abort "direct registration is not allowed: a package is registered only by h_install_deb / h_install_deb_bg / h_shim_arm after its payload file was verified"\n', '    :\n'),
 ('N10 payload: Essential not checked', L, '    case "$(cat "$H_OUTF")" in no|"") ;; *) h_abort "the payload file declares Essential"; return 1 ;; esac', '    :'),
 ('N11 payload: version of the .deb not compared', L, '    want="$(printf \'Package: %s\\nArchitecture: %s\\nVersion: %s\' "$H_PN" "$H_PA" "$H_PV")"', '    want="$(printf \'Package: %s\\nArchitecture: %s\\nVersion: %s\' "$H_PN" "$H_PA" "$(sed -n \'s/^Version: //p\' "$H_OUTF")")"'),
 ('N12 install: installed version not verified', L, '    if [ "$H_PVER" != "$3" ]; then h_abort "$1:$2 has the version [$(h_clip "$H_PVER")], this run registered [$3]"; return 1; fi\n', ''),
 ('N13 guard: mount residue ignored', L, '    if [ -n "$H_MOUNT_RESIDUE" ]; then h_fail "$1" "refused: a wrapper mount remains [$(h_clip "$H_MOUNT_RESIDUE" 120)]"; return 1; fi\n', ''),
 ('N14 cleanup: mount residue ignored', L, '    if [ -n "$H_MOUNT_RESIDUE" ]; then h_fail "cleanup:wrapper" "a wrapper mount remains [$(h_clip "$H_MOUNT_RESIDUE" 120)]: the cleanup does not purge (review by hand)"; return 1; fi\n', ''),
 ('N15 plan: versions not checked as a whole', L, '        [ "$H_PVER" = "$(h_reg_ver "$spec")" ] || { h_abort "registered package $spec has the version [$(h_clip "$H_PVER")], not the registered one: it is not the package this run installed"; return 1; }\n', ''),
 ('N16 cleanup: wrappers_clear not first', L, '    h_wrappers_clear || return 1     # a wrapper mount that could not be removed fails the cleanup before anything else\n', ''),
 ('N17 purge_one: registered version unknown is tolerated', L, '    v="$(h_reg_ver "$s")" || { h_abort "no registered version for $s"; return 1; }\n', '    v="$(h_reg_ver "$s")"\n'),
 ('S15 leak check always passes', S, '    [ "$rc" = 1 ]      # 0 = the wrapper is visible to the host, >=2 = could not verify: both are failures', '    true'),
 ('S16 leak check: could-not-verify accepted', S, '    [ "$rc" = 1 ]      # 0 = the wrapper is visible to the host, >=2 = could not verify: both are failures', '    [ "$rc" != 0 ]'),
 ('S17 rollback: residue not recorded', S, 'then h_mount_residue "$real"; return 1; fi\n    fi\n    h_sudo_run rm -f "$real" "$H_SHIMDIR/$kind-shim.sh"', 'then return 1; fi\n    fi\n    h_sudo_run rm -f "$real" "$H_SHIMDIR/$kind-shim.sh"'),
 ('S18 finish: wrappers not removed at the end', S, '    for k in $H_SHIMS; do h_shim_remove "$k" > /dev/null 2>&1 || h_fail "shim:$k" "the wrapper could not be removed at the end of the run"; done\n', ''),
 ('S19 collect: root-owned capture dir tested as the user', S, '            if h_sudo_run test -e "$capdir/$f"; then', '            if [ -e "$capdir/$f" ]; then'),
 ('C03 capture: identity not re-checked', C, '    if [ "$H_PVER" != "$v" ] || [ "$H_PESS" = yes ]; then h_abort', '    if false; then h_abort'),
 ('N18 state ri not purgeable', L, '"ii "|"ri "|"pi "|"rH "|"pH "|"iH "|?c?) ;; *) h_abort', '"ii "|"pi "|"rH "|"pH "|"iH "|?c?) ;; *) h_abort'),
 ('N19 state rH not purgeable', L, '"ii "|"ri "|"pi "|"rH "|"pH "|"iH "|?c?) ;; *) h_abort', '"ii "|"ri "|"pi "|"pH "|"iH "|?c?) ;; *) h_abort'),
 ("N20 disarm: flags of registered packages not removed", L, '            for sfx in "" .wait .seen .order; do h_disarm "$b$sfx" || { h_fail "disarm:$b$sfx" "cannot remove the flag"; rc=1; }; done\n', ''),
 ('G01 env guard: stray H_* accepted', NS, '        if [ -n "$bad" ]; then h_gate_fail "the environment carries H_* variables [${bad# }]: a production run accepts none (names only are shown)"; return 1; fi\n', ''),
 ('G02 env guard: test build without H_TEST_MODE accepted', NS, '        [ "${H_TEST_MODE:-0}" = 1 ] || { h_gate_fail "a test build runs only with H_TEST_MODE=1"; return 1; }\n', '        :\n'),
 ('G03 ns: same namespace as init accepted', NS, '    if [ "$mine" = "$pid1" ]; then h_gate_fail "this shell shares init\'s mount namespace [$mine]"; return 1; fi\n', ''),
 ('G04 ns: propagation not checked', NS, '            END { exit (bad || !root || NR == 0) }\' "$mi" 2> /dev/null; then', '            END { exit 0 }\' "$mi" 2> /dev/null; then'),
 ('G05 ns: unreadable own id accepted', NS, '    if [ -z "$mine" ]; then h_gate_fail "cannot read this shell\'s mount namespace id"; return 1; fi\n', ''),
 ('G06 ns: unreadable init id accepted', NS, '    if [ -z "$pid1" ]; then h_gate_fail "cannot read init\'s mount namespace id"; return 1; fi\n', ''),
 ('G07 ns: id format not checked', NS, '    [[ "$mine" =~ $idre ]] && [[ "$pid1" =~ $idre ]] || { h_gate_fail "unexpected namespace id format"; return 1; }\n', ''),
 ('G08 gate: the marker H_NS_ENTERED skips the kernel check', NS, '    h_ns_require\n}', '    return 0\n}'),
 ('G09 gate: the kernel check result is ignored', NS, '    # re-executed (or the marker was set by someone else): the marker proves nothing, the kernel state decides\n    h_ns_require\n', '    h_ns_require\n    return 0\n'),
 ('G10 production flips to non-production when unset', NS, 'h_production() { [ "${H_BUILD_KIND:-production}" != test ]; }', 'h_production() { [ "${H_BUILD_KIND:-test}" != test ]; }'),
 ('G11 production reads injected sources', NS, '    if h_production; then\n        self_link=/proc/self/ns/mnt; pid1_link=/proc/1/ns/mnt; mi=/proc/self/mountinfo\n    else', '    if false; then\n        self_link=/proc/self/ns/mnt; pid1_link=/proc/1/ns/mnt; mi=/proc/self/mountinfo\n    else'),
 ("G12 production keeps the caller's PATH", NS, '    if h_production; then PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH; fi\n', ''),
 ('G13 gate: environment guard result ignored', NS, '    h_gate_env || return 1\n', '    h_gate_env\n'),
 ('G14 mount table: a missing / mount is accepted', NS, '            END { exit (bad || !root || NR == 0) }', '            END { exit (bad || NR == 0) }'),
 ('G15 h_init: gate not run', L, '    h_ns_require 2> /dev/null || { h_abort "the private mount namespace could not be verified"; return 1; }\n', ''),
 ('G16 shims: wrapper install without the gate', S, '    if ! h_ns_require 2> "${H_RUNDIR:-/dev/null}/ns-check.err"; then', '    if false; then'),
 ('R02 recovery: nonce not compared', RB, '[ "$(cat "$rd/lock-nonce")" = "$nonce" ] ||', 'true ||'),
 ('R06 recovery: final status not required', RB, '&& grep -qx $\'cleanup\\tfailed\' "$fs" ||', '&& true ||'),
 ('R07 recovery: target need not be in the registry', RB, '    grep -qxF "$(printf \'%s\\t%s\\t%s\' "$n" "$a" "$v")" "$RF_REG" || rf_fail "target $t is not in the registry of run $RF_RUN_ID (name, arch and version must all match)"\n', '    :\n'),
 ('R08 recovery: other synthetic packages tolerated', RB, '[ "$others" = "$want_t" ] || rf_fail', 'true || rf_fail'),
 ('R09 recovery: database drift before the purge tolerated', RB, 'cmp -s "$RF_EV/nonreg-pre.tsv" "$RF_EV/base-sorted.tsv" || rf_fail', 'true || rf_fail'),
 ('R10 recovery: Maintainer not checked', RB, '[ "$H_RC" = 0 ] && [ ! -s "$H_ERRF" ] && [ "$(cat "$H_OUTF")" = \'Sinter Test <test@example.invalid>\' ] || rf_fail', 'true || rf_fail'),
 ('R11 recovery: installed version not compared', RB, '    [ "$H_PVER" = "$v" ] || rf_fail "$n:$a has the version [$H_PVER], not [$v]"\n', ''),
 ('R12 recovery: state not restricted', RB, '    case "$H_PSTATE" in "ii "|"ri "|"pi "|"rH "|"pH "|"iH "|?c?) ;; *) rf_fail "$n:$a is in the state [$H_PSTATE]: it needs a reviewed plan" ;; esac\n', ''),
 ('R13 recovery: purge failure does not stop', RB, '    h_purge_one "$n:$a" || rf_fail "the purge of $n:$a failed or did not complete (no further purge was attempted)"\n', '    h_purge_one "$n:$a"\n'),
 ('R14 recovery: remaining target not detected', RB, '    if [ "$H_PSTATE" != absent ] && ! h_state_gone "$H_PSTATE"; then rf_fail "$n:$a is still there after the purge (state [$H_PSTATE])"; fi\n', ''),
 ('R15 recovery: other package change after the purge tolerated', RB, 'h_compare_nonreg pre post || rf_fail', 'true || rf_fail'),
 ('R16 recovery: audit exit status ignored', RB, '[ "$H_RC" = 0 ] && [ ! -s "$H_OUTF" ] && [ ! -s "$H_ERRF" ] || rf_fail "dpkg --audit failed or reports problems (exit $H_RC)"', '[ ! -s "$H_OUTF" ] && [ ! -s "$H_ERRF" ] || rf_fail "dpkg --audit failed or reports problems (exit $H_RC)"'),
 ('R17 recovery: audit output ignored', RB, '[ "$H_RC" = 0 ] && [ ! -s "$H_OUTF" ] && [ ! -s "$H_ERRF" ] || rf_fail "dpkg --audit failed or reports problems (exit $H_RC)"', '[ "$H_RC" = 0 ] || rf_fail "dpkg --audit failed or reports problems (exit $H_RC)"'),
 ('R18 recovery: final database need not equal the baseline', RB, 'cmp -s "$H_RUNDIR/snap.post" "$RF_EV/base-sorted.tsv" || rf_fail', 'true || rf_fail'),
 ('R19 recovery: wrapper mounts before the purge tolerated', RB, 'rf_mounts_clear || rf_fail "$RF_WHY"\nrecord "pre:no-wrapper-mounts" ok ok', 'record "pre:no-wrapper-mounts" ok ok'),
 ('R20 recovery: wrapper mounts after the purge tolerated', RB, 'rf_mounts_clear || rf_fail "$RF_WHY"\n[ -z "$H_MOUNT_RESIDUE" ]', '[ -z "$H_MOUNT_RESIDUE" ]'),
 ('R21 recovery: evidence read-back not required', RB, '&& [ "$(cat "$RF_EV/recovery-report.tsv" 2> /dev/null)" = "$rep" ] || rf_fail "the evidence could not be saved', '|| rf_fail "the evidence could not be saved'),
 ('R27 recovery: run id format unchecked', RB, '[[ "$RF_RUN_ID" =~ ^[a-z0-9][a-z0-9-]{2,40}$ ]] || { echo "bad --run-id" >&2; rf_usage; }', ':'),
 ('R28 recovery: explicit target pattern unchecked', RB, '    [[ "$t" =~ $tre ]] && [ "${#BASH_REMATCH[1]}" -le 48 ] || { echo "bad --target [$t] (expected NAME:ARCH:VERSION of a synthetic package)" >&2; rf_usage; }\n', '    [[ "$t" =~ $tre ]]\n'),
 ('R29 recovery: the run directory is not confined to the base', RB, 'case "$RF_RUN_DIR" in "$H_BASE"/sinter-h-*) ;; *) echo "the run directory must be under $H_BASE and named sinter-h-*" >&2; rf_usage ;; esac\n', ''),
 ('R30 recovery: the production gate is not run', RB, 'h_gate_env || exit 70\n', ''),
 ("R31 recovery: foreign architectures not compared before the purge", RB, 'rf_foreign_arch_same || rf_fail "$RF_WHY"\nrecord "pre:foreign-architectures-equal-baseline" ok ok', 'record "pre:foreign-architectures-equal-baseline" ok ok'),
 ("R32 recovery: foreign architectures not compared after the purge", RB, 'rf_foreign_arch_same || rf_fail "$RF_WHY"\nrecord "post:foreign-architectures-equal-baseline" ok ok', 'record "post:foreign-architectures-equal-baseline" ok ok'),
 ("G17 env guard: BASH_ENV / LD_PRELOAD tolerated", NS, '|BASH_ENV|ENV|SHELLOPTS|BASHOPTS|LD_PRELOAD|LD_LIBRARY_PATH|BASH_XTRACEFD|PROMPT_COMMAND', ''),
 ("G18 production keeps imported functions", "lib/buildkind.sh", 'if [ "$H_BUILD_KIND" != test ]; then', 'if false; then'),
 ('R62 recovery: faults honoured in production', RB, 'rf_fault() { [ "${H_RF_FAULT:-}" = "$1" ] && ! h_production; }', 'rf_fault() { [ "${H_RF_FAULT:-}" = "$1" ]; }'),
 ('A01 audit: a command that can not run does not stop', RB, '    h_run "audit-pre" h_sudo_run "$H_DPKG" --audit || { RF_WHY="dpkg --audit could not be executed (no capture files could be created): purge refused"; return 1; }\n', '    h_run "audit-pre" h_sudo_run "$H_DPKG" --audit\n'),
 ('A02 audit: missing stdout accepted', RB, '    [ -f "$H_OUTF" ] && [ ! -L "$H_OUTF" ] || { RF_WHY="the standard output of dpkg --audit was not obtained: purge refused"; return 1; }\n', ''),
 ('A03 audit: missing stderr accepted', RB, '    [ -f "$H_ERRF" ] && [ ! -L "$H_ERRF" ] || { RF_WHY="the standard error of dpkg --audit was not obtained: purge refused"; return 1; }\n', ''),
 ('A04 audit: a failed save is ignored', RB, '    if [ "$RF_SAVE_FAIL" = 1 ] || ! {', '    if false; then :; elif ! {'),
 ('A05 audit: the read-back is not compared', RB, '    cmp -s "$H_OUTF" "$RF_EV/audit-pre.out" && cmp -s "$H_ERRF" "$RF_EV/audit-pre.err" && [ "$(cat "$RF_EV/audit-pre.rc" 2> /dev/null)" = "$rc" ] || { RF_WHY="the saved output of dpkg --audit reads back differently: purge refused"; return 1; }\n', ''),
 ('A06 audit: a non-zero exit status is accepted', RB, '    [ "$rc" = 0 ] || { RF_WHY="dpkg --audit exited with status $rc (the command failed; this is not interpreted as a diagnostic): purge refused"; return 1; }\n', ''),
 ('A07 audit: output on stderr is accepted', RB, '    [ ! -s "$H_ERRF" ] || { RF_WHY="dpkg --audit wrote to stderr [$(h_err_summary "$H_ERRF")]: purge refused"; return 1; }\n', ''),
 ('A08 audit: the first line of the report is not recognised', RB, '            0) [ "$line" = "$RF_AUDIT_H1" ] || { RF_WHY="dpkg --audit reports something this tool does not know (first line [$(h_clip "$line" 60)]): purge refused"; return 1; }; stage=1 ;;', '            0) stage=1 ;;'),
 ('A09 audit: the package description is not checked', RB, '                   [ "$desc" = "synthetic package for Sinter removal tests" ] || { RF_WHY="dpkg --audit lists [$name] with an unexpected description: purge refused"; return 1; }\n', ''),
 ('A10 audit: a listed package need not be a half-installed target', RB, '        [ "$ok" = 1 ] || { RF_WHY="dpkg --audit lists [$name], which is not an explicit target in a half-installed state: purge refused"; return 1; }', '        :'),
 ('A11 audit: a half-installed target need not be listed', RB, '                 [ "$ok" = 1 ] || { RF_WHY="the target ${RF_TNAMES[$i]} is half-installed but dpkg --audit does not list it: inconsistent, purge refused"; return 1; } ;;', '                 : ;;'),
 ('A12 audit: text after the known report is accepted', RB, '            4) RF_WHY="dpkg --audit: more than the one known report (text after the list): purge refused"; return 1 ;;', '            4) : ;;'),
 ('A13 audit: an incomplete report is accepted', RB, '    [ "$stage" -ge 3 ] && [ "${#listed[@]}" -ge 1 ] || { RF_WHY="dpkg --audit: the known report is incomplete: purge refused"; return 1; }\n', ''),
 ('A14 audit: unclean text is accepted', RB, '    h_text_ok "$H_OUTF" || { RF_WHY="the output of dpkg --audit is not clean text: purge refused"; return 1; }\n', ''),
 ('A15 audit: the pre-recovery audit is not run', RB, 'rf_audit_pre || rf_fail "$RF_WHY"\n', ''),
 ('A16 audit: the known report is rejected even when consistent', RB, '    record "pre:dpkg-audit" ok "B: ran', '    rf_fail "mutant"; record "pre:dpkg-audit" ok "B: ran'),
 # ---- R3: the run exclusion (flock on a stable file) and the state record ------------------------------------------------
 ("L40 finish: the state is UNLOCKED after a failed cleanup", L, '        if [ "$H_CLEANUP_STATUS" = ok ]; then h_lock_release; else h_lock_fail; fi', '        h_lock_release'),
 ("K01 init: old-format locks are not checked", L, '    if h_legacy_lock_present; then\n        h_abort "LEGACY_LOCK:', '    if false; then\n        h_abort "LEGACY_LOCK:'),
 ("K02 enter: a busy exclusion is tolerated", L, '        1) H_ENV_CLASS=BUSY; H_ENV_MSG="BUSY: another run or a recovery holds the exclusion; nothing was changed"; return 1 ;;', '        1) ;;'),
 ("K03 init: a lost state race leaves the run directory", L, '        unlink "$H_RUNDIR/lock-nonce" 2> /dev/null; unlink "$H_REGFILE" 2> /dev/null; rmdir "$H_RUNDIR" 2> /dev/null\n', ''),
 ("K04 enter: an unsafe exclusion file is tolerated", L, '        *) H_ENV_CLASS=UNSAFE; H_ENV_MSG="the exclusion file is unsafe or unusable (not a private regular file of yours, replaced, or cannot be opened); nothing was changed"; return 2 ;;', '        *) ;;'),
 ("K05 init: state RUNNING accepted", L, '        UNLOCKED|RECOVERED) ;;', '        UNLOCKED|RECOVERED|RUNNING) ;;'),
 ("K06 init: state FAILED_LOCKED accepted", L, '        UNLOCKED|RECOVERED) ;;', '        UNLOCKED|RECOVERED|FAILED_LOCKED) ;;'),
 ("K07 init: state RECOVERY_IN_PROGRESS accepted", L, '        UNLOCKED|RECOVERED) ;;', '        UNLOCKED|RECOVERED|RECOVERY_IN_PROGRESS) ;;'),
 ("K08 init: state PACKAGES_RECOVERED_LOCK_PENDING accepted", L, '        UNLOCKED|RECOVERED) ;;', '        UNLOCKED|RECOVERED|PACKAGES_RECOVERED_LOCK_PENDING) ;;'),
 ("K09 init: an UNKNOWN state accepted", L, '        UNLOCKED|RECOVERED) ;;', '        UNLOCKED|RECOVERED|UNKNOWN) ;;'),
 ("K10 init: a second init in the same process is allowed", L, '    if [ "$H_MUTEX_HELD" = 1 ]; then h_abort "this process already holds the exclusion"; return 1; fi\n', ''),
 ("K11 acquire: the inherited descriptor is not closed first", L, '    { exec 200<&-; } 2> /dev/null\n    { exec 200< "$p"; } 2> /dev/null || return 2', '    { exec 200< "$p"; } 2> /dev/null || return 2'),
 ("K12 mutex helper: busy is ignored", L, '    if busy:\n        code = 1\n', '    if busy:\n        code = 0\n'),
 ("K13 mutex helper: the inode at the path is not compared", L, '(a.st_dev, a.st_ino) == (b.st_dev, b.st_ino) and b.st_uid == uid and b.st_nlink == 1 and stat.S_IMODE', 'b.st_uid == uid and b.st_nlink == 1 and stat.S_IMODE'),
 ("K14 mutex helper: the owner is not compared", L, 'and b.st_uid == uid and b.st_nlink == 1 and stat.S_IMODE(b.st_mode) == 0o600', 'and b.st_nlink == 1 and stat.S_IMODE(b.st_mode) == 0o600'),
 ("K15 mutex helper: a second hard link is accepted", L, 'and b.st_nlink == 1 and stat.S_IMODE(b.st_mode) == 0o600', 'and stat.S_IMODE(b.st_mode) == 0o600'),
 ("K16 mutex helper: the mode is not compared", L, 'b.st_nlink == 1 and stat.S_IMODE(b.st_mode) == 0o600\n        code = 0 if same else 2', 'b.st_nlink == 1\n        code = 0 if same else 2'),
 ("K17 state CAS: the expected record is not compared", L, 'if cur != expect:\n    sys.exit(5)', 'if False:\n    sys.exit(5)'),
 ("K18 state CAS: the identity of the exclusion file is not checked", L, '    if not (stat.S_ISREG(b.st_mode) and (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino) and b.st_uid == uid and b.st_nlink == 1):', '    if False:'),
 ("K19 state CAS: a hard-linked state file is accepted", L, 'if not stat.S_ISREG(st.st_mode) or st.st_uid != uid or st.st_nlink != 1:', 'if not stat.S_ISREG(st.st_mode) or st.st_uid != uid:'),
 ("K20 state CAS: the owner of the state file is not compared", L, 'if not stat.S_ISREG(st.st_mode) or st.st_uid != uid or st.st_nlink != 1:', 'if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:'),
 ("K21 finish: a failed release is not reported", L, 'h_state_transition UNLOCKED scenario || { h_fail "lock" "the state record could not be set to UNLOCKED (compare-and-set failed): the state stays as it was and the exclusion is kept"; return 1; }', 'h_state_transition UNLOCKED scenario'),
 ("K22 finish: a failed FAILED_LOCKED write is not reported", L, 'h_state_transition FAILED_LOCKED scenario || { h_fail "lock" "the state record could not be set to FAILED_LOCKED (compare-and-set failed): the state stays RUNNING, which also refuses every new run"; return 1; }', 'h_state_transition FAILED_LOCKED scenario'),
 ("K23 state read: a symbolic link is accepted", L, '    if [ -L "$p" ] || { [ -e "$p" ] && [ ! -f "$p" ]; }; then H_ST_STATE="UNKNOWN"; return 1; fi', '    if { [ -e "$p" ] && [ ! -f "$p" ]; }; then H_ST_STATE="UNKNOWN"; return 1; fi'),
 ("K24 state read: the owner of the state file is not checked", L, '    { [ -O "$p" ] && [ "$(h_stat_mode "$p")" = 600 ]; } || { H_ST_STATE="UNKNOWN"; return 1; }', '    { [ "$(h_stat_mode "$p")" = 600 ]; } || { H_ST_STATE="UNKNOWN"; return 1; }'),
 ("K25 state read: more than one line is accepted", L, '    case "$raw" in *$\'\\n\'*) H_ST_STATE="UNKNOWN"; return 1 ;; esac\n', ''),
 ("K26 init: the RUNNING write does not expect the record it read", L, '    H_STATE_REC="$H_ST_RAW"\n', '    H_STATE_REC="ABSENT"\n'),
 ("K27 release: the exclusion is never dropped", L, '    if [ "$H_MUTEX_HELD" = 1 ]; then { exec 200<&-; } 2> /dev/null; fi', '    :'),
 ("K28 init: the exclusion is kept after a failed RUNNING write", L, '        H_RUNDIR=""; H_REGFILE=""; h_mutex_drop\n', '        H_RUNDIR=""; H_REGFILE=""\n'),
 ("Y01 recovery: old-format locks are not checked", RB, 'if h_legacy_lock_present; then\n    rf_fail "LEGACY_LOCK', 'if false; then\n    rf_fail "LEGACY_LOCK'),
 ("Y02 recovery: a busy exclusion is tolerated", RB, '    1) rf_fail "BUSY: a running scenario or another recovery holds the exclusion: it is not taken over" ;;', '    1) ;;'),
 ("Y03 recovery: a refusal of the environment is tolerated", RB, '    *) rf_fail "$H_ENV_MSG" ;;', '    *) ;;'),
 ("Y04 recovery: RUNNING is recovered without --allow-orphan", RB, '        RUNNING) [ "$RF_ALLOW_ORPHAN" = 1 ] || { RF_WHY="the state is RUNNING and nobody holds the exclusion (the run was killed): recovering it needs --allow-orphan"; return 1; } ;;', '        RUNNING) ;;'),
 ("Y05 recovery: RECOVERY_IN_PROGRESS is continued", RB, '        RECOVERY_IN_PROGRESS) RF_WHY="the state is RECOVERY_IN_PROGRESS: an earlier recovery was interrupted; a human must review it, it is NOT continued automatically"; return 1 ;;', '        RECOVERY_IN_PROGRESS) ;;'),
 ("Y06 recovery: PACKAGES_RECOVERED_LOCK_PENDING is continued", RB, '        PACKAGES_RECOVERED_LOCK_PENDING) RF_WHY="the state is PACKAGES_RECOVERED_LOCK_PENDING: an earlier recovery removed the packages but did not seal the state; a human must review the evidence, it is NOT completed automatically"; return 1 ;;', '        PACKAGES_RECOVERED_LOCK_PENDING) ;;'),
 ("Y07 recovery: UNLOCKED / RECOVERED are recovered", RB, '            RF_WHY="the state is $H_ST_STATE: nothing to recover"\n            return 1 ;;', '            RF_WHY="the state is $H_ST_STATE: nothing to recover"\n            return 0 ;;'),
 ("Y08 recovery: an UNKNOWN state is accepted", RB, '        UNKNOWN) RF_WHY="UNKNOWN: the state record is unreadable, malformed or not a plain file: it is NOT repaired automatically"; return 1 ;;', '        UNKNOWN) ;;'),
 ("Y09 recovery: the run id of the record is not compared", RB, '    [ "$rid" = "$RF_RUN_ID" ] || { RF_WHY="the state record belongs to run [$rid], not [$RF_RUN_ID]"; return 1; }\n', ''),
 ("Y10 recovery: the uid of the record is not compared", RB, '    [ "$uid" = "$RF_ME" ] || { RF_WHY="the state record was written by uid $uid, you are $RF_ME"; return 1; }\n', ''),
 ("Y11 recovery: the run directory of the record is not compared", RB, '    [ "$rd" = "$RF_RUN_DIR" ] || { RF_WHY="the state record names another run directory"; return 1; }\n', ''),
 ("Y12 recovery: the final status of a FAILED_LOCKED run is not required", RB, '    if [ "$H_ST_STATE" = FAILED_LOCKED ]; then\n', '    if false; then\n'),
 ("Y13 recovery: the first transition need not succeed", RB, 'rf_state_set RECOVERY_IN_PROGRESS || rf_fail "the state RECOVERY_IN_PROGRESS could not be recorded (compare-and-set failed: the state changed, or the exclusion file was replaced): nothing was purged"', 'rf_state_set RECOVERY_IN_PROGRESS'),
 ("Y14 recovery: PACKAGES_RECOVERED_LOCK_PENDING need not be recorded", RB, 'rf_state_set PACKAGES_RECOVERED_LOCK_PENDING || rf_fail "the state PACKAGES_RECOVERED_LOCK_PENDING could not be recorded (compare-and-set failed): the state stays as it is, new runs stay refused"', 'rf_state_set PACKAGES_RECOVERED_LOCK_PENDING'),
 ("Y15 recovery: the seal need not succeed", RB, 'rf_state_set RECOVERED || rf_fail "the state could not be sealed as RECOVERED (compare-and-set failed): it stays PACKAGES_RECOVERED_LOCK_PENDING, new runs stay refused"', 'rf_state_set RECOVERED'),
 ("Y16 recovery: the final evidence is not required before the seal", RB, ' || rf_fail "the final evidence could not be saved and read back: the state is NOT sealed (it stays PACKAGES_RECOVERED_LOCK_PENDING, new runs stay refused)"', ''),
 ("Y17 recovery: the original state is never put back", RB, '    if [ "$RF_LOCK_STATE" = RECOVERY_IN_PROGRESS ] && [ "$RF_PKG_RECOVERED" = no ] && [ "$RF_PURGES" = 0 ]; then', '    if false; then'),
 ("Y18 recovery: the original state is put back after a purge was issued", RB, ' && [ "$RF_PKG_RECOVERED" = no ] && [ "$RF_PURGES" = 0 ]; then', ' && [ "$RF_PKG_RECOVERED" = no ]; then'),
 ("Y19 recovery: the state record need not be copied to the evidence", RB, ' || rf_fail "the state record could not be saved to the evidence"', ''),
 ("Y20 recovery: the interim status need not be saved", RB, ' || rf_fail "the interim status (packages recovered, state not sealed) could not be saved: the state stays PACKAGES_RECOVERED_LOCK_PENDING and new runs stay refused"', ''),
 ("Y21 recovery: a final status that can not be saved is a success", RB, 'remain in $RF_EV)" >&2; exit 1; }', 'remain in $RF_EV)" >&2; exit 0; }'),
 ("Y22 recovery: the record just written is not remembered", RB, '    RF_REC_NOW="$new"; RF_SEQ=$((RF_SEQ + 1)); RF_LOCK_STATE="$1"', '    RF_SEQ=$((RF_SEQ + 1)); RF_LOCK_STATE="$1"'),
 ("Y23 recovery: the exclusion is taken after the state was read", RB, 'rf_phase exclusion-held\n', 'rf_phase exclusion-held\nh_mutex_drop\n'),
 # ---- R4: the persistent environment, the explicit initialisation, a missing record is never "fresh" ----------------------
 ("Q01 enter: an unsafe state directory is tolerated", L, '        2) H_ENV_CLASS=UNKNOWN; H_ENV_MSG="UNKNOWN: the state directory is unsafe (a symbolic link, not a directory, not yours, not mode 700, or an unsafe parent); nothing was changed"; return 2 ;;', '        2) ;;'),
 ("Q02 enter: a missing state directory is tolerated", L, 'nothing was changed"; return 2 ;;\n        2) H_ENV_CLASS=UNKNOWN; H_ENV_MSG="UNKNOWN: the state directory is unsafe', 'nothing was changed"; return 0 ;;\n        2) H_ENV_CLASS=UNKNOWN; H_ENV_MSG="UNKNOWN: the state directory is unsafe'),
 ("Q03 enter: a missing exclusion file next to existing records is tolerated", L, '        if [ "$hi" = 1 ] || [ "$hs" = 1 ]; then H_ENV_CLASS=UNKNOWN;', '        if false; then H_ENV_CLASS=UNKNOWN;'),
 ("Q04 enter: a run creates the exclusion file when it is missing", L, '    if [ "$hm" = 0 ]; then\n        if [ "$hi" = 1 ]', '    if false; then\n        if [ "$hi" = 1 ]'),
 ("Q05 classify: a MISSING state record of an initialised environment is accepted", L, '    if [ "$H_ST_STATE" = ABSENT ]; then H_ENV_CLASS=UNKNOWN; H_ENV_MSG="UNKNOWN: the environment was initialised but its state record is MISSING', '    if false; then H_ENV_CLASS=UNKNOWN; H_ENV_MSG="UNKNOWN: the environment was initialised but its state record is MISSING'),
 ("Q06 classify: the init id of the state record is not compared", L, '    if [ "$H_ST_INIT" != "$H_INIT_ID" ]; then H_ENV_CLASS=UNKNOWN;', '    if false; then H_ENV_CLASS=UNKNOWN;'),
 ("Q07 classify: an interrupted initialisation (phase started) is not recognised", L, '    if [ "$H_INIT_PHASE" = started ]; then', '    if false; then'),
 ("Q08 classify: a missing init record next to a state record is not recognised", L, '    if [ "$H_INIT_FILE" = ABSENT ]; then\n        if [ "$H_ST_STATE" = ABSENT ]', '    if false; then\n        if [ "$H_ST_STATE" = ABSENT ]'),
 ("Q09 init read: the uid of the init record is not compared", L, '[ "${BASH_REMATCH[3]}" = "$(h_my_uid)" ] && ', ''),
 ("Q10 init read: the directory of the init record is not compared", L, ' && [ "${BASH_REMATCH[4]}" = "$H_STATE_DIR" ]; then', '; then'),
 ("Q11 init read: the mode of the init record is not checked", L, '    { [ -O "$p" ] && [ "$(h_stat_mode "$p")" = 600 ]; } || { H_INIT_FILE="CORRUPT"; return 1; }', '    { [ -O "$p" ]; } || { H_INIT_FILE="CORRUPT"; return 1; }'),
 ("Q12 state read: the mode of the state record is not checked", L, '    { [ -O "$p" ] && [ "$(h_stat_mode "$p")" = 600 ]; } || { H_ST_STATE="UNKNOWN"; return 1; }', '    { [ -O "$p" ]; } || { H_ST_STATE="UNKNOWN"; return 1; }'),
 ("Q13 state directory: the mode is not checked", L, '    [ "$(h_stat_mode "$d")" = 700 ] || return 2\n', ''),
 ("Q14 state directory: the parent directory is not checked", L, '    h_check_dir "$(dirname "$d")" || return 2\n', ''),
 ("Q15 state directory: a symbolic link is accepted", L, '    [ -d "$d" ] && [ ! -L "$d" ] && [ -O "$d" ] || return 2', '    [ -d "$d" ] && [ -O "$d" ] || return 2'),
 ("Q16 legacy: the R3 state files in the base directory are not detected", L, ' "$H_BASE/sinter-h-state" "$H_BASE/sinter-h-mutex"; do', '; do'),
 ("Q17 legacy: the R3 temporary state files are not detected", L, ' "$H_BASE"/sinter-h-state.tmp.* 2> /dev/null | head -1)"', ' 2> /dev/null | head -1)"'),
 ("Q18 initialize: an initialised environment is not recognised (it would be written again)", L, '        INITIALIZED) H_INIT_RESULT=already; h_mutex_drop; return 0 ;;\n', ''),
 ("Q19 initialize: an UNKNOWN environment is initialised over", L, '        *) h_mutex_drop; return 1 ;;\n    esac\n    if [ "$H_INIT_FILE" = VALID ]', '        *) ;;\n    esac\n    if [ "$H_INIT_FILE" = VALID ]'),
 ("Q20 initialize: an interrupted initialisation gets a new init id", L, '    if [ "$H_INIT_FILE" = VALID ]; then id="$H_INIT_ID"; created="$H_INIT_CREATED"', '    if false; then id="$H_INIT_ID"; created="$H_INIT_CREATED"'),
 ("Q21 initialize: the init record is not completed", L, '    if h_env_fault fail-complete || ! h_file_cas "$H_INIT_PATH" "$started" "$complete"; then H_ENV_MSG="the init record could not be completed"; h_mutex_drop; return 2; fi\n', ''),
 ("Q22 init tool: the Owner's confirmation is not required", IB, 'if [ "$IS_CONFIRM" != 1 ]; then', 'if false; then'),
 ("Q23 init tool: a leftover run directory is accepted", IB, '[ -z "$leftover" ] || is_fail', 'true || is_fail'),
 ("Q24 init tool: synthetic packages are accepted", IB, '[ -z "$syn" ] || is_fail', 'true || is_fail'),
 ("Q25 init tool: a wrapper is accepted", IB, '    if h_is_shim "$p"; then is_fail "$p is a harness wrapper"; fi', '    :'),
 ("Q26 init tool: old-format locks are not checked", IB, 'if h_legacy_lock_present; then is_fail "LEGACY_LOCK', 'if false; then is_fail "LEGACY_LOCK'),
 ("Q27 init tool: an unknown environment is not refused", IB, '                   *) is_fail "$H_ENV_MSG" ;;', '                   *) need=resume ;;'),
 ("Q28 init tool: an unsafe state directory is not refused", IB, '    2) is_fail "UNKNOWN: the state directory is unsafe (a symbolic link, not a directory, not yours, not mode 700, or an unsafe parent)" ;;', '    2) need=resume ;;'),
 ("Q29 init tool: a busy exclusion is not refused", IB, '            1) is_fail "BUSY: a run, a recovery or another initialisation holds the exclusion" ;;', '            1) need=resume ;;'),
]
SCEN = ["L35", "L52", "L55", "L56", "L57", "S11", "N13", "N14", "N16"]    # mutants for which the end-to-end smoke cases are part of the run (wrapper/mount paths)

def run_one(m):
    name, rel, old, new = m[:4]
    d = tempfile.mkdtemp(prefix="m.", dir=WORK)
    try:
        dst = os.path.join(d, "harness")
        shutil.copytree(SRC, dst, ignore=shutil.ignore_patterns("__pycache__"))
        path = os.path.join(dst, rel)
        text = open(path, encoding="utf-8").read()
        want = m[4] if len(m) > 4 else 1
        if text.count(old) != want:
            return name, "NOT-APPLIED (pattern found %d times, wanted %d)" % (text.count(old), want), ""
        open(path, "w", encoding="utf-8").write(text.replace(old, new))
        if subprocess.run(["bash", "-n", path]).returncode != 0:
            return name, "SYNTAX-ERROR", ""
        cases = (LOCK_CASES + " " + INIT_CASES if name.startswith("K") else INIT_CASES if name.startswith("Q") else GATE_CASES if name.startswith("G") and not name.startswith(("G15", "G16")) else REC_CASES if name.startswith(("R", "A", "Y")) else SHIM_CASES + " t72 t70" if name.startswith(("G15", "G16")) else SHIM_CASES if name.startswith(("S", "C")) else LIB_CASES + " " + SHIM_CASES if name.split()[0] in SCEN else LIB_CASES)
        env = dict(os.environ, HT_TMP=os.path.join(d, "tmp"))
        r = subprocess.run([os.path.join(dst, "tests", "run-tests.sh"), cases], env=env, capture_output=True, text=True, timeout=1500)
        failed = [l.split("\t")[0] for l in r.stdout.splitlines() if "\tFAIL\t" in l]
        return name, ("KILLED" if r.returncode != 0 else "SURVIVED"), ",".join(failed[:6])
    except subprocess.TimeoutExpired:
        return name, "TIMEOUT(counted as killed)", ""
    finally:
        shutil.rmtree(d, ignore_errors=True)

def main():
    out = sys.argv[1]
    prefixes = sys.argv[2:]
    os.makedirs(WORK, exist_ok=True)
    todo = [m for m in M if not prefixes or any(m[0].startswith(p) for p in prefixes)]
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=JOBS) as ex:
        for res in ex.map(run_one, todo):
            print("%s\t%s\t%s" % res, flush=True)
            results.append(res)
    with open(out, "w", encoding="utf-8") as f:
        for res in results:
            f.write("%s\t%s\t%s\n" % res)
    bad = [r for r in results if r[1] not in ("KILLED",) and not r[1].startswith("TIMEOUT")]
    print("mutants=%d killed=%d not-killed=%d" % (len(results), len(results) - len(bad), len(bad)))

if __name__ == "__main__":
    main()
