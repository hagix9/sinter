#!/bin/bash
# smoke-tests.sh -- sourced by run-tests.sh (t39/t40/t41).  The assembled scenario files are run END TO END against the
# mocks: fake dpkg/dpkg-query/dpkg-deb on a JSON database, a mount emulation that copies files (no real mount), a fake
# `sinter`.  The scenario's product assertions fail against the fake Sinter by design; what is checked is the harness:
# it terminates, never calls a real package manager, purges only packages it registered, ends with an exact baseline
# and reports the cleanup separately.

smoke_env_setup() {  # smoke_env_setup -> mocks and environment inside $T
    mkdir -p "$T/home" "$T/ws" "$T/target" "$T/mnt" "$T/asm"
    cp "$T/bin/dpkg" "$T/target/dpkg"; cp "$T/bin/dpkg-query" "$T/target/dpkg-query"
    cat > "$T/bin/mount" << 'EOF'
#!/bin/sh
M="${MOCK_MNT:?}"
[ -n "$MOUNT_FAIL_ON" ] && case "$*" in *"$MOUNT_FAIL_ON") echo "mock mount: injected failure" >&2; exit 32 ;; esac
case "$1" in
    --bind) src="$2"; dst="$3"; key=$(printf '%s' "$dst" | tr '/ ' '__')
            [ -e "$M/$key" ] && { echo "mock mount: already mounted" >&2; exit 32; }
            cp -p "$dst" "$M/$key.orig" && cp -p "$src" "$dst" && : > "$M/$key" || exit 32 ;;
    --make-private) exit 0 ;;
    *) exit 2 ;;
esac
EOF
    cat > "$T/bin/umount" << 'EOF'
#!/bin/sh
M="${MOCK_MNT:?}"; dst="$1"; key=$(printf '%s' "$dst" | tr '/ ' '__')
[ -n "$UMOUNT_FAIL" ] && { echo "mock umount: injected failure" >&2; exit 32; }
[ -n "$UMOUNT_LIE" ] && exit 0        # claims success, the mount stays
[ -n "$UMOUNT_LIE_ON" ] && [ "$dst" = "$UMOUNT_LIE_ON" ] && exit 0   # lies for one path only
[ -n "$key" ] && [ -e "$M/$key" ] || { echo "mock umount: not mounted" >&2; exit 32; }
cp -p "$M/$key.orig" "$dst" && unlink "${M:?}/${key:?}" && unlink "${M:?}/${key:?}.orig"
EOF
    cat > "$T/bin/findmnt" << 'EOF'
#!/bin/sh
M="${MOCK_MNT:?}"
case "$*" in *PROPAGATION*) echo "${MOCK_PROPAGATION:-private}"; exit 0 ;; esac
for a; do p="$a"; done; key=$(printf '%s' "$p" | tr '/ ' '__'); [ -e "$M/$key" ]
EOF
    printf '#!/bin/sh\nshift\nexec "$@"\n' > "$T/bin/stdbuf-mock"
    cat > "$T/bin/sinter" << 'EOF'
#!/bin/sh
# fake sinter: a fixed, harmless answer
fmt=text; for a; do [ "$a" = json ] && fmt=json; done
if [ "$fmt" = json ]; then
    echo '{"resources":[{"id":"p","type":"package","change":"none","execution":"failed","verification":"not_performed","reason":"fake sinter","sensitive":false}]}'
else
    echo "FAILED  p [package] fake sinter"; echo "summary: 0 changed, 0 possible, 1 failed, 0 indeterminate, 1 total"
fi
exit 5
EOF
    chmod 755 "$T/bin/mount" "$T/bin/umount" "$T/bin/findmnt" "$T/bin/stdbuf-mock" "$T/bin/sinter"
    printf 'ID=ubuntu\nID_LIKE=debian\nVERSION_ID="24.04"\n' > "$T/os-release"
    # B-1 emulation: this shell has its own mount namespace id, init has another; init's view of the targets is a separate copy
    mkdir -p "$T/ns" "$T/pid1root$T/target"
    ln -sfn 'mnt:[4026531001]' "$T/ns/self"; ln -sfn 'mnt:[4026531000]' "$T/ns/pid1"
    cp "$T/bin/dpkg" "$T/pid1root$T/target/dpkg"; cp "$T/bin/dpkg-query" "$T/pid1root$T/target/dpkg-query"
    H_NS_SELF_LINK="$T/ns/self"; H_NS_PID1_LINK="$T/ns/pid1"; H_PID1_ROOT="$T/pid1root"
}
dbsig() { python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); print(sorted((r["name"],r["arch"],r["ver"],r["abbr"]) for r in d["pkgs"]), sorted(d["foreign"]))' "$1"; }
smoke_run() {  # smoke_run SCRIPT RUNID [NAME=VALUE ...] -> $T/scenario.out, $T/scenario.rc ; extra words override or add environment; DROP_ENV="A B" removes names
    local script="$1" rid="$2" w d keep=() base
    shift 2
    base=(PATH="$PATH" HOME="$T/home" TMPDIR="$T"
        H_TEST_MODE=1 H_TEST_ROOT="$T" H_BASE="$T/base" H_STATE_DIR="$T/state" H_FLAGDIR="$T/flags/flags"
        H_DPKG="$T/bin/dpkg" H_DPKG_QUERY="$T/bin/dpkg-query" H_DPKG_DEB="$T/bin/dpkg-deb"
        H_DPKG_TARGET="$T/target/dpkg" H_DPKGQ_TARGET="$T/target/dpkg-query"
        H_MOUNT="$T/bin/mount" H_UMOUNT="$T/bin/umount" H_FINDMNT="$T/bin/findmnt" H_STDBUF="$T/bin/stdbuf-mock"
        H_NS_SELF_LINK="$T/ns/self" H_NS_PID1_LINK="$T/ns/pid1" H_PID1_ROOT="$T/pid1root" H_MOUNTINFO="$T/ns/mountinfo"
        H_SUDO_BIN="$T/bin/sudo-mock" H_UNSHARE_BIN="$T/bin/unshare-mock" H_ENV_BIN="$T/bin/env-mock"
        MOCK_SUDO_FAIL="${MOCK_SUDO_FAIL:-}" MOCK_UNSHARE_FAIL="${MOCK_UNSHARE_FAIL:-}"
        H_SUDO_NONE=1 H_OS_RELEASE="$T/os-release" H_SHA256SUM="shasum -a 256" H_MIN_PKGS=3
        MOCK_DB="$MOCK_DB" MOCK_LOG="$MOCK_LOG" MOCK_TRIPWIRE_LOG="$MOCK_TRIPWIRE_LOG" MOCK_MNT="$T/mnt"
        ARTIFACT_PATH="$T/bin/sinter" RUN_ID="$rid" WORKSPACE="$T/ws")
    for w in "${base[@]}"; do
        for d in ${DROP_ENV:-}; do [ "${w%%=*}" = "$d" ] && continue 2; done
        keep[${#keep[@]}]="$w"
    done
    ( cd "$T" && env -i "${keep[@]}" "$@" bash "$script" "${SMOKE_ARGV[@]+"${SMOKE_ARGV[@]}"}" > "$T/scenario${SMOKE_TAG:-}.out" 2>&1; echo $? > "$T/scenario${SMOKE_TAG:-}.rc" )
}
smoke_case() {  # smoke_case sa3|multiarch
    local kind="$1" rc fs
    smoke_env_setup
    ASSEMBLE_BUILD=test "$HERE/../assemble.sh" "$T/asm" > "$T/asm.log" 2>&1; a_eq "the scenarios assemble (lint, syntax, payload)" 0 "$?"
    cp "$MOCK_DB" "$T/db.initial.json"
    smoke_run "$T/asm/scenario-$kind.sh" "smoke-$kind"
    rc="$(cat "$T/scenario.rc")"
    note "scenario exit status $rc"
    fs="$T/ws/out/final-status.tsv"
    a_true "the scenario ended with a final status file" test -f "$fs"
    a_true "cleanup=ok in the final status" grep -q $'^cleanup\tok' "$fs"
    a_true "no harness-level failure and no abort" bash -c "grep -q $'^harness_failed\\t0' '$fs' && grep -q $'^aborted\\t0' '$fs'"
    case "$kind" in
        stageb*) a_true "the stage scenario passes against the mocks (no product assertion involved)" grep -q 'SCENARIO: PASS' "$T/scenario.out"
                 a_eq "and exits 0" 0 "$rc" ;;
        *) a_true "the product assertions failed against the fake sinter (the verdict is not a PASS)" bash -c "! grep -q 'SCENARIO: PASS' '$T/scenario.out'"
           a_eq "the exit status reports the failed assertions, not success" 1 "$([ "$rc" != 0 ] && echo 1 || echo 0)" ;;
    esac
    a_true "no real package manager was called (tripwire log empty)" no_tripwire
    a_false "no force option anywhere" log_has_force
    a_false "no purge/remove command with a real package name" log_has_real_name
    a_true "the scenario really issued purge/remove commands (the next check is not vacuous)" test "$(grep $'^dpkg\t' "$MOCK_LOG" | grep -cE -- '[[:space:]]--(purge|remove)[[:space:]]')" -gt 0
    a_eq "every purge/remove target is a test package" 0 "$(grep $'^dpkg\t' "$MOCK_LOG" | grep -E -- '[[:space:]]--(purge|remove)[[:space:]]' | grep -vc -E -- '[[:space:]](sinter-t-[a-z0-9-]+(:[a-z0-9]+)?)([[:space:]]|$)')"
    a_eq "the host database is exactly the initial one again" "$(dbsig "$T/db.initial.json")" "$(dbsig "$MOCK_DB")"
    a_eq "no wrapper is left mounted" 0 "$(ls "$T/mnt" 2> /dev/null | wc -l | tr -d ' ')"
    a_eq "the targets are the original launchers again" 0 "$(grep -l SINTER-HARNESS-SHIM "$T"/target/* 2> /dev/null | wc -l | tr -d ' ')"
    a_eq "the state is UNLOCKED after the clean cleanup" UNLOCKED "$(st_name)"
    a_eq "every install in the log was a payload file of this scenario" 0 "$(grep $'^dpkg\t' "$MOCK_LOG" | grep $'\t-i ' | grep -vc "sinter-h-smoke-$kind/pkgs/sinter-t-")"
    cp "$T/ws/out/results.tsv" "$T/results.copy.tsv" 2> /dev/null
}
lint_coverage() {  # one deliberately bad line per lint rule: each rule must fire
    local d="$T/lintcov" id line ok
    mkdir -p "$d"
    while IFS='|' read -r id line; do
        printf '%s\n' "$line" > "$d/x.sh"
        "$HERE/../lint-harness.sh" "$d" 2> /dev/null | grep -q "\[$id" && ok=1 || ok=0
        a_eq "rule $id fires" 1 "$ok"
    done << 'RULES'
R01-force-options|dpkg --purge --force-depends x
R02-removal-outside-lib|dpkg --remove sinter-t-x
R03-package-manager-cli|apt-get install foo
R04-listing-fed-to-removal|for n in $(dpkg-query -W); do echo $n; done
R05-rm-recursive|rm -rf "$D"
R06-bind-mount-outside-shims|mount --bind /a /b
R07-world-writable|chmod 777 /var/tmp/x
R08-eval|eval "$cmd"
R09-absolute-pm-path|/usr/bin/dpkg --version
R10-raw-sudo|sudo apt-get update
R11-set-selections|dpkg --set-selections < x
R12-fixed-tmp-name|echo x > /tmp/fixed-name
R13-find-delete|find /var/tmp -name x -delete
R14-unquoted-expansion-to-removal|x --purge $names
R16-direct-registration|h_register sinter-t-x:all
R18-gate-skip|[ "${H_NS_ENTERED:-}" = 1 ] && skip=1
R17-root-owned-capture-dir|[ -e "$capdir/x" ] && echo y
RULES
    printf '# dpkg --purge --force-depends rm -rf\n' > "$d/x.sh"; "$HERE/../lint-harness.sh" "$d" > /dev/null 2>&1
    a_eq "comment lines are ignored by the lint" 0 "$?"
    mkdir -p "$d/empty"; "$HERE/../lint-harness.sh" "$d/empty" > /dev/null 2>&1
    a_eq "an empty tree is an error, not an OK" 2 "$?"
}

# ---------------------------------------------------------------- the namespace gate, end to end on ASSEMBLED scenarios (F-2)
gate_prepare() {  # gate_prepare [production] -> assembled Stage B1 scenario in $T/asm ; sets GATE_SCRIPT
    smoke_env_setup
    ASSEMBLE_BUILD="${1:-test}" "$HERE/../assemble.sh" "$T/asm" > "$T/asm.log" 2>&1; a_eq "the $1 scenarios assemble" 0 "$?"
    GATE_SCRIPT="$T/asm/scenario-stageb1.sh"
}
pm_calls() { grep -cE $'^(dpkg|dpkg-query|dpkg-deb)\t' "$MOCK_LOG" 2> /dev/null | tr -d ' '; }
gate_refused() {  # gate_refused DESCRIPTION -> the run stopped at the gate: exit 70, no package-manager call, no output directory, message printed
    local rc; rc="$(cat "$T/scenario.rc")"
    a_eq "$1: exit status 70" 70 "$rc"
    a_eq "$1: not a single package-manager call (dpkg/dpkg-query/dpkg-deb)" 0 "$(pm_calls)"
    a_true "$1: no output directory was created" test ! -d "$T/ws/out"
    a_true "$1: the gate said why" grep -q 'SCENARIO GATE FAILED' "$T/scenario.out"
    a_true "$1: nothing was mounted and the state record is still the initial one" bash -c "[ -z \"\$(ls '$T/mnt' 2>/dev/null)\" ] && grep -q '^sinter-state-v5;state=UNLOCKED;seq=0;' '$T/state/sinter-h-state'"
}

# ---------------------------------------------------------------- the recovery tool (F-1): a FAILED run made by the real library, then recover-synthetic.sh
SMOKE_ARGV=()
STP() { echo "$T/state/sinter-h-state"; }
MXP() { echo "$T/state/sinter-h-mutex"; }
INP() { echo "$T/state/sinter-h-init"; }
st_name() { sed -n 's/^sinter-state-v5;state=\([A-Z_]*\);.*/\1/p' "$(STP)" 2> /dev/null; }
st_rec() { cat "$(STP)" 2> /dev/null; }
rec_fixture() {  # rec_fixture DEBFILE... -> a run that ended with "cleanup failed" (its first purge was made to fail): lock kept, packages left
    local f n specs=()
    smoke_env_setup
    for f in "$@"; do n="${f%%_1.0_*}"; mkdeb "$n" all; specs[${#specs[@]}]="$n:all"; done
    EVD="$T/evid"; mkdir -p "$EVD"; chmod 700 "$EVD"
    ASSEMBLE_BUILD=test "$HERE/../assemble.sh" "$T/asm" > "$T/asm.log" 2>&1; a_eq "the tools assemble" 0 "$?"
    ( cd "$T" && REC_FIX_END="${REC_FIX_END:-finish}" MOCK_P_FAIL_ON=1 bash -c '. "$1/lib/nscheck.sh"; . "$1/lib/safe-lib.sh"; . "$1/lib/shims.sh"; H_SUDO=(); h=$1; shift
        specs=(); for f in "$@"; do specs[${#specs[@]}]="${f%%_1.0_*}:all"; done; H_PAYLOAD_ALLOW=("${specs[@]}")
        h_install_traps; h_init recfix1 || exit 3; if [ "$REC_FIX_END" = killinit ]; then kill -9 $$; fi; h_baseline || exit 4
        for f in "$@"; do h_install_deb "$f" || exit 5; done; if [ "$REC_FIX_END" = kill ]; then kill -9 $$; fi; h_finish; exit 0' _ "$HERE/.." "$@" ) > "$T/fixture.out" 2>&1
    RF_RDIR="$(ls -d "$T"/base/sinter-h-recfix1.* 2> /dev/null | head -1)"
    if [ "${REC_FIX_END:-finish}" = kill ] || [ "${REC_FIX_END:-finish}" = killinit ]; then
        a_eq "the fixture: the killed run left the state RUNNING" RUNNING "$(st_name)"
        a_true "the fixture: and a run directory" test -d "$RF_RDIR"
        a_true "the fixture: with no final status (it was killed)" test ! -e "$RF_RDIR/final-status.tsv"
    else
        a_eq "the fixture: the failed run left the state FAILED_LOCKED" FAILED_LOCKED "$(st_name)"
        a_true "the fixture: and a run directory" test -d "$RF_RDIR"
        a_true "the fixture: the run ended with cleanup failed" grep -qx $'cleanup\tfailed' "$RF_RDIR/final-status.tsv"
    fi
    RP0="$(n_real_purge)"
}
rec_dp() { echo $(( $(n_real_purge) - RP0 )); }
rec_args() {  # rec_args TARGET... -> SMOKE_ARGV
    local t; SMOKE_ARGV=(--run-id recfix1 --run-dir "$RF_RDIR" --evidence-dir "$EVD")
    for t in "$@"; do SMOKE_ARGV[${#SMOKE_ARGV[@]}]=--target; SMOKE_ARGV[${#SMOKE_ARGV[@]}]="$t"; done
}
rec_run() { smoke_run "$T/asm/recover-synthetic.sh" recfix1 "$@"; }
rec_status_has() { local d; d="$(ls -td "$EVD"/recovery.* 2> /dev/null | head -1)"; [ -n "$d" ] && grep -qx "$1" "$d/recovery-status.tsv" 2> /dev/null; }
rec_failed() {  # rec_failed DESC PURGES REASON -> like rec_stopped but the caller checks the state itself
    a_eq "$1: exit status 1" 1 "$(cat "$T/scenario.rc")"
    a_true "$1: it stopped for the expected reason [$3]" grep -qF -- "$3" "$T/scenario.out"
    a_eq "$1: purge commands issued by the recovery" "$2" "$(rec_dp)"
    a_true "$1: FAILED is recorded" rec_status_has $'result\tFAILED'
    a_false "$1: never recorded as a success" rec_status_has $'result\tRECOVERED'
    a_false "$1: no force option anywhere" log_has_force
}
rec_stopped() {  # rec_stopped DESC PURGES [REASON [STATE]] -> exit 1, that many purge commands, state kept (default FAILED_LOCKED), FAILED recorded, not RECOVERED, stopped for THE EXPECTED REASON
    a_eq "$1: exit status 1" 1 "$(cat "$T/scenario.rc")"
    [ -z "${3:-}" ] || a_true "$1: it stopped for the expected reason [$3]" grep -qF -- "$3" "$T/scenario.out"
    a_eq "$1: purge commands issued by the recovery" "$2" "$(rec_dp)"
    a_eq "$1: the state is kept" "${4:-FAILED_LOCKED}" "$(st_name)"
    a_true "$1: FAILED is recorded" rec_status_has $'result\tFAILED'
    a_false "$1: never recorded as a success" rec_status_has $'result\tRECOVERED'
    a_false "$1: no force option anywhere" log_has_force
}

# ---------------------------------------------------------------- R3: processes that use the REAL library (like rec_fixture), and waiting helpers
NR_PRE='. "$1/lib/nscheck.sh"; . "$1/lib/safe-lib.sh"; . "$1/lib/shims.sh"; H_SUDO=();'
new_run() {  # new_run [RUNID] -> only h_init, in a child process: NR_RC (0 = it got the run; the child is not finished, so the state stays RUNNING) and NR_OUT
    NR_PM0="$(pm_calls)"
    NR_OUT="$( cd "$T" && bash -c "$NR_PRE${NR_EXTRA:-}"'h_init "$2"; echo "INIT_RC=$?"; echo "HELD=$H_MUTEX_HELD"' _ "$HERE/.." "${1:-newrun1}" 2>&1 )"
    NR_PM1="$(pm_calls)"
    NR_RC="$(printf '%s\n' "$NR_OUT" | sed -n 's/^INIT_RC=//p')"
}
new_run_full() {  # new_run_full [RUNID] -> a complete clean run in a child process: NR_RC 0 and the state UNLOCKED afterwards
    NR_OUT="$( cd "$T" && bash -c "$NR_PRE"'h_init "$2" || exit 3; h_baseline || exit 4; h_finish; exit 0' _ "$HERE/.." "${1:-newrun1}" 2>&1 )"; NR_RC=$?
}
hold_run() {  # hold_run RUNID -> a child that takes the run (init + baseline), signals, waits for the go file, then finishes cleanly
    rm -f "$T/hold.up" "$T/hold.go"
    ( cd "$T" && bash -c "$NR_PRE"'h_init "$2" || exit 3; h_baseline || exit 4; : > "$3"; i=0; while [ ! -e "$4" ] && [ "$i" -lt 600 ]; do sleep 0.1; i=$((i+1)); done; h_finish; exit 0' _ "$HERE/.." "$1" "$T/hold.up" "$T/hold.go" ) > "$T/hold.out" 2>&1 &
    HOLD_PID=$!
    wait_for "$T/hold.up"
}
hold_release() { : > "$T/hold.go"; wait "$HOLD_PID"; HOLD_RC=$?; }
fk() {  # fk PATH -> what is at PATH: its content, ABSENT, or a description (a test oracle, never used by the tools)
    if [ -L "$1" ]; then echo "SYMLINK:$(readlink "$1")"
    elif [ ! -e "$1" ]; then echo ABSENT
    elif [ -d "$1" ]; then echo DIRECTORY
    else head -c 700 "$1" | od -An -c | tr -d ' \n'; fi
}
wait_for() {  # wait_for FILE -> 0 as soon as the file exists (at most 20 s)
    local i=0
    while [ ! -e "$1" ] && [ "$i" -lt 200 ]; do sleep 0.1; i=$((i + 1)); done
    [ -e "$1" ]
}
mx_free() {  # 0 if nobody holds the exclusion (a non-blocking flock from a separate process succeeds)
    python3 -I -c 'import fcntl, sys
f = open(sys.argv[1], "rb")
try:
    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
except OSError:
    sys.exit(1)' "$(MXP)"
}
st_kind() {  # what is at the state path: the record, ABSENT, or a description of what it is instead (a test oracle, never used by the tools)
    if [ -L "$(STP)" ]; then echo "SYMLINK:$(readlink "$(STP)")"
    elif [ ! -e "$(STP)" ]; then echo ABSENT
    elif [ -d "$(STP)" ]; then echo DIRECTORY
    else head -c 700 "$(STP)" | od -An -c | tr -d ' \n'; fi
}
