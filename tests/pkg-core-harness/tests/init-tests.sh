#!/bin/bash
# init-tests.sh -- sourced by run-tests.sh: the persistent environment and its EXPLICIT initialisation (R4-1).
# Every case starts in an environment that setup() initialised through the production function; a case that needs a fresh
# or a damaged environment says so.  A missing record is never "fresh": every refusal checks that the tool stopped FOR THE
# EXPECTED REASON, that the records it must not touch are byte-identical, and (for refusals before any check) that not a single
# package-manager command was issued.

INI_ENV=()
SD() { echo "$T/state"; }
env_uninit() { rm -rf "$T/state"; H_MUTEX_HELD=0; }
env_empty() { rm -rf "$T/state"; mkdir -p "$T/state"; chmod 700 "$T/state"; }
ini_setup() {  # assembled TEST tools and an evidence directory; the environment stays as setup() left it
    smoke_env_setup; EVD="$T/evid"; mkdir -p "$EVD"; chmod 700 "$EVD"
    ASSEMBLE_BUILD=test "$HERE/../assemble.sh" "$T/asm" > "$T/asm.log" 2>&1; a_eq "the tools assemble" 0 "$?"
    RP0="$(n_real_purge)"; INI_ENV=()
}
ini_run() {  # ini_run [FLAGS...] -> init-state.sh in the test environment (INI_ENV adds environment variables)
    SMOKE_ARGV=(--evidence-dir "$EVD" "$@"); smoke_run "$T/asm/init-state.sh" inirun1 "${INI_ENV[@]+"${INI_ENV[@]}"}"
}
fake_rec_args() { SMOKE_ARGV=(--run-id recfix1 --run-dir "$T/base/sinter-h-recfix1.FAKE12" --evidence-dir "$EVD" --target sinter-t-a:all:1.0); }
ini_failed() {  # ini_failed DESC RC REASON -> init-state.sh stopped with RC for REASON
    a_eq "$1: exit status" "$2" "$(cat "$T/scenario.rc")"
    a_true "$1: it stopped for the expected reason [$3]" grep -qF -- "$3" "$T/scenario.out"
}
sig3() { printf '%s|%s|%s' "$(fk "$T/state/sinter-h-mutex")" "$(fk "$T/state/sinter-h-init")" "$(fk "$T/state/sinter-h-state")"; }
# every consumer refuses: a new run, a recovery, an initialisation; nothing at all is changed
all_refuse() {  # all_refuse DESC NEWRUN_REASON RECOVERY_REASON [INIT_REASON]
    local before; before="$(sig3)"; ST_BEFORE="$(st_kind)"
    new_run; nr_refused "$1: a new run" "$2"
    fake_rec_args; rec_run; a_eq "$1: a recovery: exit 1" 1 "$(cat "$T/scenario.rc")"; a_true "$1: a recovery: for the expected reason [$3]" grep -qF -- "$3" "$T/scenario.out"
    ini_run --confirm-clean-host; ini_failed "$1: an initialisation (it must not repair or re-initialise)" 1 "${4:-$2}"
    a_eq "$1: the three records are untouched" "$before" "$(sig3)"
    a_eq "$1: no purge" 0 "$(rec_dp)"
}

t149() { . "$HERE/smoke-tests.sh"; ini_setup; env_uninit   # a completely new environment: a run does NOT initialise it
    ST_BEFORE="$(st_kind)"; new_run; nr_refused "a new run in an uninitialised environment" 'UNINITIALIZED'
    a_true "the state directory was not created by the run" test ! -e "$T/state"
    fake_rec_args; rec_run; a_eq "a recovery: exit 1" 1 "$(cat "$T/scenario.rc")"; a_true "a recovery: UNINITIALIZED" grep -q 'UNINITIALIZED' "$T/scenario.out"; a_true "and nothing was created" test ! -e "$T/state"
    a_eq "no purge, no package change" 0 "$(rec_dp)"; }
t150() { . "$HERE/smoke-tests.sh"; ini_setup; env_uninit   # the explicit initialisation
    ini_run; ini_failed "without the Owner's confirmation" 2 'needs --confirm-clean-host'; a_true "nothing was created" test ! -e "$T/state"
    ini_run --confirm-clean-host; a_eq "the initialisation succeeds" 0 "$(cat "$T/scenario.rc")"; a_true "created" grep -q 'INIT OK: created' "$T/scenario.out"
    a_eq "the state directory is mode 700" 700 "$(h_stat_mode "$T/state")"
    a_true "the exclusion file is a private regular file" bash -c "[ -f '$(MXP)' ] && [ ! -L '$(MXP)' ] && [ \"\$(ls -l '$(MXP)' | cut -c1-10)\" = '-rw-------' ]"
    a_match "the init record is complete" '^sinter-init-v5;id=[0-9a-f]{32};phase=complete;uid=[0-9]+;state_dir=/.+;created=[0-9TZ:-]+$' "$(cat "$(INP)")"
    a_match "the initial state record is UNLOCKED, seq 0, written by the initialisation, with the same init id" "^sinter-state-v5;state=UNLOCKED;seq=0;by=init;pid=[0-9]+;run_id=initial;uid=[0-9]+;run_dir=/.+;nonce=[0-9a-f]{32};init=$(sed 's/^[^;]*;id=\([0-9a-f]*\);.*/\1/' "$(INP)")\$" "$(st_rec)"
    a_true "the records were copied to the evidence and read back" bash -c "cmp -s '$(INP)' \"\$(ls -dt '$EVD'/init.* | head -1)/init-record.copy\" && cmp -s '$(STP)' \"\$(ls -dt '$EVD'/init.* | head -1)/state-record.copy\""
    a_true "the evidence names the automatic checks" bash -c "grep -q 'init:no-synthetic-package' \"\$(ls -dt '$EVD'/init.* | head -1)/steps.tsv\" && grep -q 'init:no-leftover-run-directory' \"\$(ls -dt '$EVD'/init.* | head -1)/steps.tsv\""
    a_eq "no package was changed" 0 "$(rec_dp)"
    new_run_full; a_eq "now a run is possible" 0 "$NR_RC"; a_eq "and ends UNLOCKED (seq 2)" 2 "$(st_rec | sed 's/.*;seq=\([0-9]*\);.*/\1/')"; }
t151() { . "$HERE/smoke-tests.sh"; rec_fixture $RA; ini_setup   # re-running the initialisation never overwrites, never clears a failure
    local before; before="$(sig3)"; a_eq "(setup) the failed run left FAILED_LOCKED" FAILED_LOCKED "$(st_name)"
    ini_run --confirm-clean-host; a_eq "idempotent: exit 0" 0 "$(cat "$T/scenario.rc")"; a_true "reported as already initialised" grep -q 'already initialised (state FAILED_LOCKED' "$T/scenario.out"
    a_eq "the three records are byte-identical" "$before" "$(sig3)"
    ini_run; a_eq "also without the confirmation (nothing to do): exit 0" 0 "$(cat "$T/scenario.rc")"; a_eq "still identical" "$before" "$(sig3)"; }
ini_fault_case() {  # ini_fault_case FAULT EXPECT_CLASS_WORD KIND(kill|fail) SAME_ID(0|1)
    local f="$1" cls="$2" kind="$3" same="$4" id0=""
    env_uninit; INI_ENV=(H_INIT_FAULT="$f"); ini_run --confirm-clean-host
    if [ "$kind" = kill ]; then a_eq "$f: the process was killed (137)" 137 "$(cat "$T/scenario.rc")"; else a_eq "$f: the initialisation failed (exit 1)" 1 "$(cat "$T/scenario.rc")"; a_true "$f: and said so" grep -q 'INIT FAILED' "$T/scenario.out"; fi
    if [ -e "$(MXP)" ]; then a_true "$f: the exclusion is free (the kernel dropped it)" mx_free; fi
    [ ! -e "$(INP)" ] || id0="$(sed 's/^[^;]*;id=\([0-9a-f]*\);.*/\1/' "$(INP)")"
    local before; before="$(sig3)"
    INI_ENV=(); ST_BEFORE="$(st_kind)"; new_run; a_eq "$f: a new run is refused" 1 "$NR_RC"; a_true "$f: as $cls" grep -q "$cls" <<< "$NR_OUT"; a_eq "$f: no package-manager call" "$NR_PM0" "$NR_PM1"
    fake_rec_args; rec_run; a_eq "$f: a recovery is refused" 1 "$(cat "$T/scenario.rc")"; a_true "$f: as $cls" grep -q "$cls" "$T/scenario.out"
    a_eq "$f: the records were not touched by the refusals" "$before" "$(sig3)"
    ini_run --confirm-clean-host; a_eq "$f: running the initialisation again completes it" 0 "$(cat "$T/scenario.rc")"
    if [ "$same" = 1 ]; then a_eq "$f: with the SAME init id" "$id0" "$(sed 's/^[^;]*;id=\([0-9a-f]*\);.*/\1/' "$(INP)")"; fi
    a_match "$f: complete" 'phase=complete' "$(cat "$(INP)")"; a_match "$f: initial state" '^sinter-state-v5;state=UNLOCKED;seq=0;by=init;' "$(st_rec)"
    new_run_full; a_eq "$f: afterwards a run works" 0 "$NR_RC"; rm -rf "$T"/base/sinter-h-newrun1.*     # test oracle: the next fault case starts on a host with no run directory
}
t152() { . "$HERE/smoke-tests.sh"; ini_setup   # SIGKILL at every point of the initialisation
    ini_fault_case kill-after-dir UNINITIALIZED kill 0
    ini_fault_case kill-after-mutex INIT_INCOMPLETE kill 0
    ini_fault_case kill-after-init-record INIT_INCOMPLETE kill 1
    ini_fault_case kill-after-state-record INIT_INCOMPLETE kill 1; }
t153() { . "$HERE/smoke-tests.sh"; ini_setup   # a write fails at every point of the initialisation
    ini_fault_case fail-create-mutex UNINITIALIZED fail 0
    ini_fault_case fail-init-record INIT_INCOMPLETE fail 0
    ini_fault_case fail-state-record INIT_INCOMPLETE fail 1
    ini_fault_case fail-complete INIT_INCOMPLETE fail 1; }
t154() { . "$HERE/smoke-tests.sh"; ini_setup   # the init record is damaged
    local orig; orig="$(cat "$(INP)")"
    damage() {  # damage DESC  (the init path was prepared by the caller)
        all_refuse "$1" 'init record is unreadable' 'init record is unreadable'; unlink "$(INP)" 2> /dev/null; rm -rf "$(INP)"; printf '%s\n' "$orig" > "$(INP)"; chmod 600 "$(INP)"
    }
    : > "$(INP)"; damage "an empty init record"
    printf '%s' "${orig:0:50}" > "$(INP)"; damage "a truncated init record"
    printf '\x00\x01garbage\xff\n' > "$(INP)"; damage "binary junk"
    printf '%s\n%s\n' "$orig" "$orig" > "$(INP)"; damage "two lines"
    printf '%s\n' "${orig/uid=*;state_dir/uid=99999;state_dir}" > "$(INP)"; damage "a record of another uid"
    printf '%s\n' "${orig/state_dir=*;created/state_dir=/elsewhere;created}" > "$(INP)"; damage "a record of another directory"
    printf '%s\n' "${orig/phase=complete/phase=weird}" > "$(INP)"; damage "an unknown phase"
    chmod 644 "$(INP)"; damage "mode 644"
    unlink "$(INP)"; ln -s "$T/nowhere" "$(INP)"; damage "a dangling symlink"
    unlink "$(INP)"; mkdir "$(INP)"; damage "a directory"
    new_run_full; a_eq "positive control: with the init record restored the run works" 0 "$NR_RC"; }
t155() { . "$HERE/smoke-tests.sh"; ini_setup   # the init record is missing
    unlink "$(INP)"; all_refuse "the init record is missing while a state record exists" 'init record is missing' 'init record is missing'; }
t156() { . "$HERE/smoke-tests.sh"; ini_setup   # the state record is MISSING in an initialised environment (the R4-1 case)
    unlink "$(STP)"; all_refuse "the state record vanished (an initialised environment)" 'its state record is MISSING' 'its state record is MISSING'
    a_true "the state record was NOT recreated" test ! -e "$(STP)"; }
t157() { . "$HERE/smoke-tests.sh"; ini_setup   # the exclusion file is missing
    unlink "$(MXP)"; all_refuse "the exclusion file vanished" 'exclusion file is missing' 'exclusion file is missing'
    a_true "the exclusion file was NOT recreated by anybody" test ! -e "$(MXP)"; }
t158() { . "$HERE/smoke-tests.sh"; ini_setup   # exclusion file AND state record are gone, the init record remains
    unlink "$(MXP)"; unlink "$(STP)"; all_refuse "mutex and state record both vanished (initialised before)" 'exclusion file is missing' 'exclusion file is missing'; }
t159() { . "$HERE/smoke-tests.sh"; ini_setup; env_empty   # an empty state directory is NOT an initialised one
    ST_BEFORE="$(st_kind)"; new_run; nr_refused "a run in an empty state directory" 'UNINITIALIZED'; a_eq "the directory stays empty" "" "$(ls -A "$T/state")"
    ini_run; ini_failed "without the confirmation" 2 'needs --confirm-clean-host'; a_eq "still empty" "" "$(ls -A "$T/state")"
    ini_run --confirm-clean-host; a_eq "with the confirmation it is initialised" 0 "$(cat "$T/scenario.rc")"; a_true "created" grep -q 'INIT OK: created' "$T/scenario.out"; }
t160() { . "$HERE/smoke-tests.sh"; ini_setup   # permissions and ownership of the records
    local mode orig_s orig_i; orig_s="$(st_rec)"; orig_i="$(cat "$(INP)")"
    for mode in 644 666 640 400; do
        chmod "$mode" "$(STP)"; all_refuse "the state record has mode $mode" 'state record is unreadable' 'state record is unreadable'; chmod 600 "$(STP)"
        chmod "$mode" "$(INP)"; all_refuse "the init record has mode $mode" 'init record is unreadable' 'init record is unreadable'; chmod 600 "$(INP)"
    done
    ST_BEFORE="$(st_kind)"; NR_EXTRA='h_my_uid() { echo 4242; };' new_run; nr_refused "files of another uid (simulated: the uid the tools expect differs)" 'exclusion file is unsafe'
    new_run_full; a_eq "positive control: with the modes restored the run works" 0 "$NR_RC"; }
t161() { . "$HERE/smoke-tests.sh"; ini_setup   # the state file is replaced by ANOTHER inode
    local rec; rec="$(st_rec)"
    cp "$(STP)" "$T/state/copy.x"; chmod 600 "$T/state/copy.x"; mv "$T/state/copy.x" "$(STP)"
    new_run_full; a_eq "an identical record in a new inode is the same record: the run works" 0 "$NR_RC"
    rm -rf "$T"/base/sinter-h-newrun1.*     # test oracle
    local other="${rec/init=*/init=ffffffffffffffffffffffffffffffff}"; printf '%s\n' "$other" > "$T/state/copy.x"; chmod 600 "$T/state/copy.x"; mv "$T/state/copy.x" "$(STP)"
    all_refuse "a record of ANOTHER initialisation swapped in" 'another initialisation' 'another initialisation'; }
t162() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # an automatic clean-up of the BASE directory (/var/tmp): the persistent state is elsewhere
    local before; before="$(sig3)"
    find "$T/base" -mindepth 1 -maxdepth 1 -exec rm -rf {} +     # test oracle: the clean-up removes everything under the base directory
    a_eq "the persistent records are untouched by the clean-up" "$before" "$(sig3)"
    ST_BEFORE="$(st_kind)"; new_run; nr_refused "the failed run is STILL refused after the clean-up" 'FAILED_LOCKED'
    rec_args sinter-t-a:all:1.0; rec_run; a_eq "a recovery is refused: the run directory is gone" 1 "$(cat "$T/scenario.rc")"; a_true "for that reason" grep -q 'run directory is not usable' "$T/scenario.out"; a_eq "no purge" 0 "$(rec_dp)"
    a_eq "the state is still FAILED_LOCKED" FAILED_LOCKED "$(st_name)"; }
t163() { . "$HERE/smoke-tests.sh"; rec_fixture $RA; ini_setup   # the whole state directory is lost after a failed run: no re-initialisation over a dirty host
    rm -rf "$T/state"; H_MUTEX_HELD=0
    ST_BEFORE="$(st_kind)"; new_run; nr_refused "a run when the whole directory vanished" 'UNINITIALIZED'
    ini_run --confirm-clean-host; a_eq "the initialisation is REFUSED (the host shows traces of the failed run)" 1 "$(cat "$T/scenario.rc")"
    a_true "for that reason" grep -qE 'run directory of an earlier run exists|synthetic packages are installed' "$T/scenario.out"
    a_true "the state directory was not created" test ! -e "$T/state"; a_eq "no purge" 0 "$(rec_dp)"
    rm -rf "$RF_RDIR"; ini_run --confirm-clean-host; ini_failed "also with the run directory gone: the synthetic package still shows" 1 'synthetic packages are installed'; a_true "still not created" test ! -e "$T/state"; }
t164() { . "$HERE/smoke-tests.sh"; ini_setup; env_uninit   # "reboot": every process is new, only the files persist
    ini_run --confirm-clean-host; a_eq "init" 0 "$(cat "$T/scenario.rc")"
    new_run_full; a_eq "a run in a new process" 0 "$NR_RC"; new_run_full; a_eq "another run in another process" 0 "$NR_RC"
    a_match "the state persisted across the processes: UNLOCKED, seq 4" '^sinter-state-v5;state=UNLOCKED;seq=4;' "$(st_rec)"; a_true "nobody holds the exclusion" mx_free; }
t165() { . "$HERE/smoke-tests.sh"; ini_setup   # the R3 location (the base directory) still holds a state: not interpreted, not merged, nothing starts
    local lg="$T/base" sig
    printf 'sinter-state-v4;state=FAILED_LOCKED;seq=2;by=scenario;pid=1;run_id=oldrun;uid=%s;run_dir=%s/sinter-h-oldrun.AbCdEf;nonce=00000000000000000000000000000000\n' "$(id -u)" "$T/base" > "$lg/sinter-h-state"; chmod 600 "$lg/sinter-h-state"; : > "$lg/sinter-h-mutex"; chmod 600 "$lg/sinter-h-mutex"
    sig="$(ls -ldn "$lg/sinter-h-state" "$lg/sinter-h-mutex"; cat "$lg/sinter-h-state")"
    all_refuse "R3 state files in the base directory (the new state says UNLOCKED)" 'LEGACY_LOCK' 'LEGACY_LOCK'
    a_eq "the old files are untouched" "$sig" "$(ls -ldn "$lg/sinter-h-state" "$lg/sinter-h-mutex"; cat "$lg/sinter-h-state")"
    unlink "$lg/sinter-h-mutex"; unlink "$lg/sinter-h-state"; : > "$lg/sinter-h-state.tmp.4242.abcdef"; all_refuse "an R3 temporary state file" 'LEGACY_LOCK' 'LEGACY_LOCK'; unlink "$lg/sinter-h-state.tmp.4242.abcdef"
    new_run_full; a_eq "positive control: with the old files gone (by a human) the run works" 0 "$NR_RC"; }
t166() { . "$HERE/smoke-tests.sh"; ini_setup   # the location of the state is replaced or made unsafe
    local m
    for m in 755 750 770 777 500; do chmod "$m" "$T/state"; all_refuse "the state directory has mode $m" 'state directory is unsafe' 'state directory is unsafe'; done; chmod 700 "$T/state"
    mv "$T/state" "$T/state.real"; ln -s "$T/state.real" "$T/state"; chmod -h 700 "$T/state" 2> /dev/null; all_refuse "the state directory was replaced by a symlink to a valid copy" 'state directory is unsafe' 'state directory is unsafe'; unlink "$T/state"; mv "$T/state.real" "$T/state"
    chmod 777 "$T"; all_refuse "the parent directory is world-writable (no sticky bit)" 'state directory is unsafe' 'state directory is unsafe'; chmod 700 "$T"
    new_run_full; a_eq "positive control: with everything restored the run works" 0 "$NR_RC"; }
t167() { . "$HERE/smoke-tests.sh"; ini_setup; env_uninit; mkdir "$T/hold"   # a run and a recovery while the initialisation is half-way
    INI_ENV=(H_INIT_FAULT=hold-after-init-record H_INIT_HOLD_DIR="$T/hold"); SMOKE_TAG=A; ( ini_run --confirm-clean-host ) & local pa=$!; SMOKE_TAG=""; INI_ENV=()
    wait_for "$T/hold/held-after-init-record"; a_true "the initialisation reached the point between the records" test -e "$T/hold/held-after-init-record"
    ST_BEFORE="$(st_kind)"; new_run; nr_refused "a run while the initialisation holds the exclusion" 'BUSY'
    fake_rec_args; SMOKE_TAG=B; rec_run; SMOKE_TAG=""; a_eq "a recovery: exit 1" 1 "$(cat "$T/scenarioB.rc")"; a_true "BUSY" grep -q 'BUSY' "$T/scenarioB.out"
    SMOKE_TAG=C; ini_run --confirm-clean-host; SMOKE_TAG=""; a_eq "a second initialisation: exit 1" 1 "$(cat "$T/scenarioC.rc")"; a_true "BUSY" grep -q 'BUSY' "$T/scenarioC.out"
    : > "$T/hold/go-after-init-record"; wait "$pa"; a_eq "the initialisation completed" 0 "$(cat "$T/scenarioA.rc")"
    new_run_full; a_eq "afterwards a run works" 0 "$NR_RC"; }
t168() { . "$HERE/smoke-tests.sh"; ini_setup   # two initialisations at the same moment, three rounds
    local round i
    for round in 1 2 3; do
        env_uninit; rm -f "$T/go"
        for i in A B; do
            ( while [ ! -e "$T/go" ]; do sleep 0.02; done; SMOKE_TAG=$i; ini_run --confirm-clean-host ) &
        done
        sleep 0.4; : > "$T/go"; wait
        local ra rb; ra="$(cat "$T/scenarioA.rc")"; rb="$(cat "$T/scenarioB.rc")"
        case "$ra$rb" in 00|01|10) pass "round $round: neither process crashed, at least one succeeded (exit codes $ra $rb)" ;; *) fail "round $round: unexpected exit codes $ra $rb" ;; esac
        ini_run --confirm-clean-host; a_eq "round $round: afterwards the environment is complete (a further call finds it initialised)" 0 "$(cat "$T/scenario.rc")"; a_true "round $round: already initialised" grep -q 'already initialised' "$T/scenario.out"
        a_match "round $round: one init record, complete" 'phase=complete' "$(cat "$(INP)")"; a_match "round $round: the initial state" '^sinter-state-v5;state=UNLOCKED;seq=0;by=init;' "$(st_rec)"
    done; }
t169() { . "$HERE/smoke-tests.sh"; ini_setup   # SIGKILL while the state file is being replaced
    export H_PY_STATE_CAS
    local rec new fp; rec="$(st_rec)"; new="${rec/state=UNLOCKED/state=RUNNING}"; new="${new/seq=0/seq=1}"
    h_env_paths; h_mutex_acquire; a_eq "(setup) the exclusion is held" 0 "$?"
    run_cas() {  # run_cas REPLACEMENT-FOR-"os.replace(tmp, sp)"
        python3 -I -c 'import os, sys
code = os.environ["H_PY_STATE_CAS"].replace("os.replace(tmp, sp)", sys.argv[1])
sys.argv = ["cas"] + sys.argv[2:]
exec(compile(code, "cas", "exec"))' "$1" 200 "$H_MUTEX_PATH" "$(id -u)" "$H_STATE_PATH" "$rec" "$new"
    }
    run_cas 'os.kill(os.getpid(), 9)'; a_eq "killed before the replace (137)" 137 "$?"
    a_eq "the state record is the OLD one, intact" "$rec" "$(st_rec)"
    a_eq "a temporary file of the killed writer is left behind" 1 "$(tmps | wc -l | tr -d ' ')"
    h_mutex_drop
    ST_BEFORE="$(st_kind)"; new_run_full; a_eq "the temporary file does not influence the decision: a run works" 0 "$NR_RC"
    rec="$(st_rec)"; new="${rec/state=UNLOCKED/state=RUNNING}"; new="${new/seq=*;by/seq=9;by}"
    h_mutex_acquire; a_eq "(re-acquired for the next step)" 0 "$?"
    run_cas 'os.replace(tmp, sp); os.kill(os.getpid(), 9)'; a_eq "killed right after the replace (137)" 137 "$?"
    a_eq "the NEW record is complete and valid" "$new" "$(st_rec)"
    run_cas 'os.replace(tmp, sp)'; a_eq "a compare-and-set against the old record is now refused (5)" 5 "$?"
    a_eq "the record is unchanged by the refused write" "$new" "$(st_rec)"; }
t170() { . "$HERE/smoke-tests.sh"; ini_setup; env_uninit   # the automatic evidence for an initialisation: nothing of an earlier run may be there
    local n
    mkdir "$T/base/sinter-h-oldrun.AbC123"; chmod 700 "$T/base/sinter-h-oldrun.AbC123"; ini_run --confirm-clean-host; ini_failed "a leftover run directory" 1 'run directory of an earlier run exists'; a_true "nothing created" test ! -e "$T/state"; rmdir "$T/base/sinter-h-oldrun.AbC123"
    db_mutate 'db["pkgs"].append({"name":"sinter-t-left","arch":"all","ver":"1.0","ess":"","abbr":"ii "})'; ini_run --confirm-clean-host; ini_failed "a synthetic package is installed" 1 'synthetic packages are installed'; a_true "nothing created" test ! -e "$T/state"
    db_mutate 'db["pkgs"] = [r for r in db["pkgs"] if r["name"] != "sinter-t-left"]'
    printf '#!/bin/sh\n# SINTER-HARNESS-SHIM\n' > "$T/target/dpkg"; ini_run --confirm-clean-host; ini_failed "a harness wrapper is installed" 1 'is a harness wrapper'; a_true "nothing created" test ! -e "$T/state"
    cp "$T/bin/dpkg" "$T/target/dpkg"
    mkdir "$T/base/sinter-h-lock"; ini_run --confirm-clean-host; ini_failed "an old-format lock" 1 'LEGACY_LOCK'; a_true "nothing created" test ! -e "$T/state"; rmdir "$T/base/sinter-h-lock"
    n="$(n_real_purge)"; a_eq "no purge, no package change by any refusal" "$RP0" "$n"
    ini_run --confirm-clean-host; a_eq "positive control: with the host clean the initialisation works" 0 "$(cat "$T/scenario.rc")"; }
t171() { . "$HERE/smoke-tests.sh"; ini_setup; env_uninit   # the PRODUCTION build of the initialisation tool: no test environment, no test hook
    ASSEMBLE_BUILD=production "$HERE/../assemble.sh" "$T/asm-p" > /dev/null 2>&1; a_true "the production tools assemble" test -f "$T/asm-p/init-state.sh"
    SMOKE_ARGV=(--evidence-dir "$EVD" --confirm-clean-host); smoke_run "$T/asm-p/init-state.sh" inirun1 H_INIT_FAULT=kill-after-dir
    a_eq "the production tool refuses the test environment (stray H_* variables): exit 70" 70 "$(cat "$T/scenario.rc")"
    a_true "naming the offending variable" grep -q 'H_' "$T/scenario.out"; a_true "and nothing was created" test ! -e "$T/state"; a_eq "no package-manager call" 0 "$(pm_calls)"
    DROP_ENV=H_TEST_MODE smoke_run "$T/asm/init-state.sh" inirun1; a_eq "a test build without H_TEST_MODE=1: exit 70" 70 "$(cat "$T/scenario.rc")"
    a_true "the production build has no test hook: the fault functions are not defined there" bash -c "! grep -q 'h_env_fault' <(sed -n '1,3p' '$T/asm-p/init-state.sh') && grep -q 'builtin unset -f' '$T/asm-p/init-state.sh'"; }
t172() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # the library function itself: idempotent, never overwrites, never initialises over an unknown environment
    local before; before="$(sig3)"; h_env_paths
    h_env_initialize; a_eq "an initialised environment (state FAILED_LOCKED): ok" 0 "$?"; a_eq "reported as already initialised" already "$H_INIT_RESULT"; a_eq "the records are untouched" "$before" "$(sig3)"
    a_eq "the exclusion was dropped" 0 "$H_MUTEX_HELD"
    unlink "$(STP)"; before="$(sig3)"; h_env_initialize; a_eq "the state record is MISSING: refused (1)" 1 "$?"; a_true "for that reason" grep -q 'MISSING' <<< "$H_ENV_MSG"
    a_eq "nothing was re-created" "$before" "$(sig3)"; a_true "nobody holds the exclusion" mx_free
    printf 'junk\n' > "$(INP)"; chmod 600 "$(INP)"; before="$(sig3)"; h_env_initialize; a_eq "a damaged init record: refused (1)" 1 "$?"; a_eq "records untouched" "$before" "$(sig3)"; }
t173() { . "$HERE/smoke-tests.sh"; ini_setup   # (final audit) a second h_init in the SAME process must not release the first run's exclusion
    h_init t173-a; a_eq "the first run is taken" 0 "$?"; a_eq "and the process holds the exclusion" 1 "$H_MUTEX_HELD"
    h_init t173-b; a_eq "a second init in the SAME process is refused" 1 "$?"
    a_eq "the first run STILL holds the exclusion" 1 "$H_MUTEX_HELD"; a_false "nobody else can take the exclusion meanwhile" mx_free
    a_match "the state is still the RUNNING record of the first run" '^sinter-state-v5;state=RUNNING;seq=1;by=scenario;pid=[0-9]+;run_id=t173-a;' "$(st_rec)"; }
