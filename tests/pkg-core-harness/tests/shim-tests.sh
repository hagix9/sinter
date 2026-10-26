#!/bin/bash
# shim-tests.sh -- sourced by run-tests.sh (case t37).  Runs the wrapper templates of lib/shims.sh against the MOCK
# dpkg / dpkg-query (never a real program) and exercises the mount management with mock mount/umount/findmnt.

shim_tests() {
    . "$HERE/../lib/shims.sh"
    local D="$T/wrapdir" ok n i
    mkdir -p "$D"; chmod 755 "$D"
    h_shim_render dpkg_query "$T/bin/dpkg-query" "$D" > "$T/q-shim.sh" && chmod 755 "$T/q-shim.sh"
    h_shim_render dpkg "$T/bin/dpkg" "$D" > "$T/p-shim.sh" && chmod 755 "$T/p-shim.sh"
    a_true "the wrapper templates render and parse" bash -n "$T/q-shim.sh"
    a_true "the dpkg template parses" bash -n "$T/p-shim.sh"
    a_false "rendering refuses a path with a pipe" h_shim_render dpkg "/x|y" "$D"

    # S1: byte-exact pass-through (stdout, stderr, exit status) for several calls, with and without capture
    ok=1
    for args in "-W -f=\${Package}\\n" "-W -f=\${Package}\\n -- realpkg001" "-W -f=\${db:Status-Abbrev}\\t\${Package}\\n -- nosuchpkg" "-W -f=\${Status}"; do
        # shellcheck disable=SC2086
        "$T/bin/dpkg-query" $args > "$T/direct.out" 2> "$T/direct.err"; local drc=$?
        # shellcheck disable=SC2086
        "$T/q-shim.sh" $args > "$T/shim.out" 2> "$T/shim.err"; local src=$?
        cmp -s "$T/direct.out" "$T/shim.out" && cmp -s "$T/direct.err" "$T/shim.err" && [ "$drc" = "$src" ] || { ok=0; note "differs for [$args]"; }
    done
    a_eq "pass-through is byte-exact (stdout, stderr, exit status)" 1 "$ok"
    a_true "the call was logged" grep -q 'argv:' "$D/q.log"

    # S2: no stale output: an old fixed-name file is never printed; an unusable wrapper dir -> pure pass-through
    printf 'install ok installed\tbash\tamd64\n' > "$D/q.tmp.out"
    "$T/q-shim.sh" -W -f='${Package}\n' -- realpkg001 > "$T/shim.out" 2> /dev/null
    a_eq "the stale q.tmp.out was not printed" "realpkg001" "$(cat "$T/shim.out")"
    chmod 555 "$D"
    "$T/q-shim.sh" -W -f='${Package}\n' -- realpkg002 > "$T/shim.out" 2> "$T/shim.err"; local rc=$?
    a_eq "unwritable wrapper dir: output is the real program's" "realpkg002" "$(cat "$T/shim.out")"
    a_eq "unwritable wrapper dir: exit status 0" 0 "$rc"
    "$T/q-shim.sh" -W -f='${Package}\n' -- nosuchpkg > "$T/shim.out" 2> "$T/shim.err"; rc=$?
    a_eq "unwritable wrapper dir: the real exit status 1 is kept" 1 "$rc"
    a_true "unwritable wrapper dir: the real diagnostic is kept" grep -q 'no packages found matching nosuchpkg' "$T/shim.err"
    chmod 755 "$D"

    # S3: parallel calls do not mix their outputs
    rm -f "$T"/par.*
    for i in 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20; do
        ( "$T/q-shim.sh" -W -f='${Package}\n' -- "realpkg0$i" > "$T/par.$i.out" 2> "$T/par.$i.err" ) &
    done
    wait
    ok=1
    for i in 01 02 03 04 05 06 07 08 09 10 11; do
        [ "$(cat "$T/par.$i.out")" = "realpkg0$i" ] || ok=0
    done
    a_eq "20 parallel calls: every call printed its own answer" 1 "$ok"
    a_eq "no capture directory is left behind" 0 "$(find "$D" -maxdepth 1 -type d -name 'q.*' | wc -l | tr -d ' ')"

    # S4: test modes only change the per-instance query
    printf 'garbage' > "$D/qmode"
    "$T/q-shim.sh" -W '-f=${Status}\t${Package}\t${Architecture}\n' -- realpkg001 > "$T/shim.out" 2> /dev/null
    a_eq "garbage mode answers the instance query" "not a record" "$(cat "$T/shim.out")"
    "$T/q-shim.sh" -W -f='${Package}\n' -- realpkg001 > "$T/shim.out" 2> /dev/null
    a_eq "other queries are untouched in a test mode" "realpkg001" "$(cat "$T/shim.out")"
    rm -f "$D/qmode"; printf 'garbage' > "$T/qmode.src"; ln -s "$T/qmode.src" "$D/qmode"
    "$T/q-shim.sh" -W '-f=${Status}\t${Package}\t${Architecture}\n' -- realpkg001 > "$T/shim.out2" 2> /dev/null
    a_true "a symlinked qmode file is ignored" test "$(cat "$T/shim.out2")" != "not a record"
    rm -f "$D/qmode"

    # S5: the dpkg wrapper -- real remove/purge is captured per call, arm runs once, dry-run is pass-through
    mkdb 12; python3 -I - "$MOCK_DB" << 'PYEOF'
import json, sys
db = json.load(open(sys.argv[1]))
for n in ("sinter-t-x", "sinter-t-y"):
    db["pkgs"].append({"name": n, "arch": "all", "ver": "1.0", "ess": "", "abbr": "ii "})
json.dump(db, open(sys.argv[1], "w"))
PYEOF
    : > "$MOCK_LOG"
    "$T/p-shim.sh" --dry-run --purge sinter-t-x > "$T/p.out" 2> "$T/p.err"
    a_true "a dry-run is passed through" grep -q 'Would remove or purge sinter-t-x' "$T/p.out"
    a_eq "a dry-run creates no capture directory" 0 "$(ls -d "$D"/c.* 2> /dev/null | wc -l | tr -d ' ')"
    printf '%s\n%s\n' -i "$T/pk/sinter-t-armed_1.0_all.deb" > "$D/arm"; printf 'Package: sinter-t-armed\nArchitecture: all\nVersion: 1.0\n' > "$T/pk/sinter-t-armed_1.0_all.deb"
    "$T/p-shim.sh" --purge sinter-t-x > "$T/p.out" 2> "$T/p.err"; rc=$?
    a_eq "the real exit status is kept" 0 "$rc"
    a_true "the armed command ran first and only once" test "$(grep -c 'other process' "$D/shim.log")" = 1
    a_true "the arm file was consumed" test ! -e "$D/arm"
    a_true "the capture directory holds the real output" test -f "$(ls -d "$D"/c.* | head -1)/real.out"
    "$T/p-shim.sh" --purge sinter-t-y > "$T/p.out" 2> "$T/p.err"
    a_eq "no second 'other process'" 1 "$(grep -c 'other process' "$D/shim.log")"
    python3 -I - "$MOCK_DB" << 'PYEOF2'
import json, sys
db = json.load(open(sys.argv[1]))
db["pkgs"].append({"name": "sinter-t-z", "arch": "all", "ver": "1.0", "ess": "", "abbr": "ii "})
json.dump(db, open(sys.argv[1], "w"))
PYEOF2
    MOCK_P_RC_AFTER_REMOVE=1 "$T/p-shim.sh" --purge sinter-t-z > "$T/p.out" 2> "$T/p.err"; rc=$?
    a_eq "the exit status of a failing real purge is kept" 1 "$rc"
    ln -s "$T/pk/sinter-t-armed_1.0_all.deb" "$D/arm"
    "$T/p-shim.sh" --purge sinter-t-armed > "$T/p.out" 2> "$T/p.err"
    a_eq "a symlinked arm file is ignored" 1 "$(grep -c 'other process' "$D/shim.log")"
    rm -f "$D/arm"
    chmod 555 "$D"
    "$T/p-shim.sh" --purge sinter-t-armed > "$T/p.out" 2> "$T/p.err"; rc=$?
    a_eq "unwritable wrapper dir: pure pass-through, exit status kept" 0 "$rc"
    chmod 755 "$D"

    # S6: mount management with the copy-emulating mount mocks (no real mount): install, rollback, refusal, removal
    . "$HERE/smoke-tests.sh"; smoke_env_setup; export MOCK_MNT="$T/mnt"
    H_MOUNT="$T/bin/mount"; H_UMOUNT="$T/bin/umount"; H_FINDMNT="$T/bin/findmnt"
    H_DPKG_TARGET="$T/target/dpkg"; H_DPKGQ_TARGET="$T/target/dpkg-query"
    local ORIG_DPKG="$H_DPKG"
    h_init "t37-shim" > /dev/null 2>&1; h_baseline > /dev/null 2>&1
    h_shim_install dpkg > /dev/null 2>&1; a_eq "install succeeds with the emulated mounts" 0 "$?"
    a_true "the target is the wrapper now" h_is_shim "$H_DPKG_TARGET"
    a_eq "the harness's own dpkg is the saved real program, not the wrapper" "$H_SHIMDIR/dpkg-real" "$H_DPKG"
    a_false "and that program is not a wrapper" h_is_shim "$H_DPKG"
    h_shim_remove dpkg > /dev/null 2>&1; a_eq "removal succeeds" 0 "$?"
    a_eq "the harness's own dpkg is restored" "$ORIG_DPKG" "$H_DPKG"
    a_false "the target is the original again" h_is_shim "$H_DPKG_TARGET"
    a_true "the bind target file is gone after a clean removal" test ! -e "$H_SHIMDIR/dpkg-real"
    # the second bind mount fails: rollback, nothing left mounted, the first bind is unmounted, files removed afterwards
    MOUNT_FAIL_ON="$H_DPKG_TARGET" h_shim_install dpkg > /dev/null 2>&1; local irc=$?
    a_true "a failed second bind mount fails the install" test "$irc" -ne 0
    a_eq "and nothing is left mounted" 0 "$(ls "$T/mnt" 2> /dev/null | wc -l | tr -d ' ')"
    a_eq "and the harness's own dpkg was not switched" "$ORIG_DPKG" "$H_DPKG"
    # umount fails
    h_shim_install dpkg > /dev/null 2>&1
    UMOUNT_FAIL=1 h_shim_remove dpkg > /dev/null 2>&1; irc=$?
    a_true "a failed umount fails the removal" test "$irc" -ne 0
    a_true "the unremoved mount is recorded as a residue (B-3)" test -n "$H_MOUNT_RESIDUE"
    a_eq "and the harness is aborted" 1 "$H_ABORTED"
    H_ABORTED=0; h_guard residue-test > /dev/null 2>&1; a_eq "no mutation is allowed while a residue exists (even without an abort)" 1 "$?"
    H_ABORTED=1
    h_cleanup > /dev/null 2>&1; a_eq "the cleanup refuses to run while a mount remains" failed "$H_CLEANUP_STATUS"
    H_CLEANUP_STATUS=not-run
    a_true "and the bind target file is kept while it is still mounted" test -e "$H_SHIMDIR/dpkg-real"
    # umount claims success but the mount is still there
    UMOUNT_LIE=1 h_shim_remove dpkg > /dev/null 2>&1; irc=$?
    a_true "a umount that lies is detected (still mounted afterwards)" test "$irc" -ne 0
    UMOUNT_LIE_ON="$H_DPKG_TARGET" h_shim_remove dpkg > /dev/null 2>&1; irc=$?
    a_true "a umount of the target that lies is detected on its own" test "$irc" -ne 0
    H_MOUNT_RESIDUE=""; H_ABORTED=0   # (the emulated mounts are real files here: the next removal is the genuine one)
    h_shim_remove dpkg > /dev/null 2>&1; a_eq "after a real umount the removal succeeds" 0 "$?"
    # B-3: a rollback whose umount fails leaves a recorded residue (no silent success)
    H_ABORTED=0; H_MOUNT_RESIDUE=""
    MOUNT_FAIL_ON="$H_DPKG_TARGET" UMOUNT_FAIL=1 h_shim_install dpkg > /dev/null 2>&1; irc=$?
    a_true "an install whose rollback can not unmount fails" test "$irc" -ne 0
    a_true "and the mount that could not be removed is recorded (B-3)" test -n "$H_MOUNT_RESIDUE"
    a_eq "and the harness is aborted" 1 "$H_ABORTED"
    rm -f "$T"/mnt/*; H_MOUNT_RESIDUE=""; H_ABORTED=0; rm -f "$H_SHIMDIR/dpkg-real" "$H_SHIMDIR/dpkg-shim.sh"
    cp -p "$T/pid1root$T/target/dpkg" "$H_DPKG_TARGET" 2> /dev/null
    # B-1: the private mount namespace is verified before anything is mounted, and the host's own view afterwards
    local nsself; nsself="$(readlink "$H_NS_SELF_LINK")"
    ln -sfn "$(readlink "$H_NS_PID1_LINK")" "$H_NS_SELF_LINK"      # this shell shares init's mount namespace
    H_ABORTED=0; h_shim_install dpkg > /dev/null 2>&1; irc=$?
    a_true "a shell that shares init's mount namespace gets no wrapper (B-1)" test "$irc" -ne 0
    a_eq "nothing was mounted" 0 "$(ls "$T/mnt" 2> /dev/null | wc -l | tr -d ' ')"
    ln -sfn "$nsself" "$H_NS_SELF_LINK"
    write_mountinfo shared
    H_ABORTED=0; h_shim_install dpkg > /dev/null 2>&1; irc=$?
    a_true "a shared root propagation gets no wrapper" test "$irc" -ne 0
    a_eq "nothing was mounted (propagation)" 0 "$(ls "$T/mnt" 2> /dev/null | wc -l | tr -d ' ')"
    write_mountinfo private
    rm -f "$T/ns/pid1"; H_ABORTED=0; h_shim_install dpkg > /dev/null 2>&1; irc=$?
    a_true "an unreadable init namespace identity gets no wrapper" test "$irc" -ne 0
    ln -sfn 'mnt:[4026531000]' "$T/ns/pid1"
    # leak: init's own view of the target shows the wrapper -> the install is undone and the harness aborts
    local hostview="$H_PID1_ROOT$H_DPKG_TARGET"; mv "$hostview" "$hostview.orig"; ln -s "$H_DPKG_TARGET" "$hostview"
    H_ABORTED=0; h_shim_install dpkg > /dev/null 2>&1; irc=$?
    a_true "a wrapper that is visible in init's view is refused (B-1 leak check)" test "$irc" -ne 0
    a_eq "and the harness is aborted" 1 "$H_ABORTED"
    a_eq "and the wrapper was removed again" 0 "$(ls "$T/mnt" 2> /dev/null | wc -l | tr -d ' ')"
    a_false "the target is the original again" h_is_shim "$H_DPKG_TARGET"
    rm -f "$hostview"; H_ABORTED=0; h_shim_install dpkg > /dev/null 2>&1; irc=$?
    a_true "an unreadable host view means the isolation can not be shown: refused" test "$irc" -ne 0
    mv "$hostview.orig" "$hostview"; H_ABORTED=0
    h_shim_install dpkg > /dev/null 2>&1; a_eq "with a private namespace and a clean host view the install works" 0 "$?"
    h_shims_finish; a_eq "h_shims_finish removes what is still mounted" "" "$H_SHIMS"
    a_false "and the target is the original" h_is_shim "$H_DPKG_TARGET"
    # the shim arm accepts payload files only
    printf 'x\n' > "$H_PK/notadeb.txt"; H_ABORTED=0
    h_shim_arm notadeb.txt > /dev/null 2>&1; a_eq "a file that is not a payload name is refused" 1 "$H_ABORTED"
    a_true "and no arm file was written" test ! -e "$H_SHIMDIR/arm"
    H_ABORTED=0; h_shim_arm sinter-t-missing_1.0_all.deb > /dev/null 2>&1; a_eq "a missing payload file is refused" 1 "$H_ABORTED"
}
