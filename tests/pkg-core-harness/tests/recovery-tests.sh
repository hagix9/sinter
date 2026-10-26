#!/bin/bash
# recovery-tests.sh -- sourced by run-tests.sh: the recovery tool and the run exclusion (contract v4: flock on a stable file + an
# atomically replaced state record), the state machine, the pre-recovery audit.
# A FAILED run is made by the REAL library in a child process (rec_fixture); the tool is the assembled TEST build.
# Every negative case checks that the tool stopped FOR THE EXPECTED REASON (a bare non-zero exit status proves nothing).

RA=sinter-t-a_1.0_all.deb; RB=sinter-t-b_1.0_all.deb
setstate() { printf '%s\n' "$1" > "$(STP)"; chmod 600 "$(STP)"; }           # test helper: put an arbitrary record at the state path
tmps() { ls "$T"/state/sinter-h-state.tmp.* 2> /dev/null; }
last_phase() { local d; d="$(ls -td "$EVD"/recovery.* 2> /dev/null | head -1)"; tail -1 "$d/phases.tsv" 2> /dev/null; }
a_match() { local d="$1" re="$2" v="$3"; if [[ "$v" =~ $re ]]; then pass "$d"; else fail "$d (value [$v])"; fi; }
ST_RE_PRE='^sinter-state-v5;state='
rec_ok_final() {  # a complete success: packages recovered AND state sealed AND final status saved
    a_eq "$1: exit status 0" 0 "$(cat "$T/scenario.rc")"
    a_true "$1: RECOVERED" rec_status_has $'result\tRECOVERED'
    a_true "$1: the packages are recovered" rec_status_has $'packages_recovered\tyes'
    a_true "$1: the state is recorded as RECOVERED" rec_status_has $'lock\tRECOVERED'
    a_eq "$1: the state record says RECOVERED" RECOVERED "$(st_name)"
    a_true "$1: the exclusion was dropped" mx_free
    a_eq "$1: no temporary state file remains" "" "$(tmps)"
    a_true "$1: the last phase is final" test "$(last_phase)" = final
}
refused() {  # refused DESC REASON [PURGES] -> exit 1, stopped for REASON, that many purges, the state path byte-identical to ST_BEFORE, FAILED recorded
    a_eq "$1: exit status 1" 1 "$(cat "$T/scenario.rc")"
    a_true "$1: it stopped for the expected reason [$2]" grep -qF -- "$2" "$T/scenario.out"
    a_eq "$1: purge commands issued by the recovery" "${3:-0}" "$(rec_dp)"
    a_eq "$1: the state path is untouched" "$ST_BEFORE" "$(st_kind)"
    a_true "$1: FAILED is recorded" rec_status_has $'result\tFAILED'
    a_false "$1: never recorded as a success" rec_status_has $'result\tRECOVERED'
    a_false "$1: no force option anywhere" log_has_force
}
nr_refused() {  # nr_refused DESC REASON -> a new run (child process) was refused for REASON and the state path is untouched
    a_eq "$1: the new run was refused" 1 "$NR_RC"
    if grep -qF -- "$2" <<< "$NR_OUT"; then pass "$1: for the expected reason [$2]"; else fail "$1: for the expected reason [$2] (output: $(printf %s "$NR_OUT" | tr '\n\t' '  ' | cut -c1-300))"; fi
    a_eq "$1: the state path is untouched" "$ST_BEFORE" "$(st_kind)"
    a_eq "$1: no run directory of the refused run" "" "$(ls -d "$T"/base/sinter-h-newrun1.* 2> /dev/null)"
    a_eq "$1: not a single package-manager call" "$NR_PM0" "$NR_PM1"
}

t91() { . "$HERE/smoke-tests.sh"; rec_fixture $RA $RB
    rec_args sinter-t-a:all:1.0 sinter-t-b:all:1.0; rec_run MOCK_P_FAIL_ON=2
    rec_stopped "purge failure with two targets" 1 'failed or did not complete' RECOVERY_IN_PROGRESS
    a_true "no further purge was attempted: both packages are still installed" bash -c "echo \"$(db_names)\" | grep -q sinter-t-a && echo \"$(db_names)\" | grep -q sinter-t-b"
    a_true "packages are NOT recorded as recovered" rec_status_has $'packages_recovered\tno'; }
t92() { . "$HERE/smoke-tests.sh"; rec_fixture $RA
    rec_args sinter-t-a:all:1.0; rec_run MOCK_P_NOOP=1; rec_stopped "purge exits 0 but the target stays" 1 'failed or did not complete' RECOVERY_IN_PROGRESS; }
t93() { . "$HERE/smoke-tests.sh"; rec_fixture $RA $RB
    rec_args sinter-t-a:all:1.0; rec_run; rec_stopped "an unnamed synthetic package (b) exists" 0 'are not exactly the explicit targets'; }
t94() { . "$HERE/smoke-tests.sh"; rec_fixture $RA
    db_mutate 'for r in db["pkgs"]:
    if r["name"] == "realpkg003": r["ver"] = "9.9"'
    rec_args sinter-t-a:all:1.0; rec_run; rec_stopped "a non-test package differs from the baseline" 0 'differs from the failed run'; }
t95() { . "$HERE/smoke-tests.sh"; rec_fixture $RA
    rec_args sinter-t-a:all:9.9; rec_run; rec_stopped "an explicit version that is not in the registry" 0 'is not in the registry'
    db_mutate 'for r in db["pkgs"]:
    if r["name"] == "sinter-t-a": r["ver"] = "4.4"'
    rec_args sinter-t-a:all:4.4; rec_run; rec_stopped "an installed version that is not the registered one (named explicitly)" 0 'is not in the registry'
    rec_args sinter-t-a:all:1.0; rec_run; rec_stopped "the registered version, but another one installed" 0 'are not exactly the explicit targets'; }
t96() { . "$HERE/smoke-tests.sh"; rec_fixture $RA
    db_mutate 'for r in db["pkgs"]:
    if r["name"] == "sinter-t-a": r["ess"] = "yes"'
    rec_args sinter-t-a:all:1.0; rec_run; rec_stopped "an Essential target" 0 'is Essential'; }
t97() { . "$HERE/smoke-tests.sh"; rec_fixture $RA
    rec_args sinter-t-a:all:1.0; rec_run MOCK_AUDIT_POST_RC=1; rec_stopped "the POST-recovery dpkg --audit exits 1" 1 'dpkg --audit failed or reports problems' RECOVERY_IN_PROGRESS
    a_true "the packages were purged but the post-checks did not all pass: packages_recovered=no, result FAILED" rec_status_has $'packages_recovered\tno'; }
t98() { . "$HERE/smoke-tests.sh"; rec_fixture $RA
    rec_args sinter-t-a:all:1.0; rec_run MOCK_AUDIT_POST_OUT="The following packages are only half installed"; rec_stopped "the POST-recovery dpkg --audit reports a problem (exit 0)" 1 'dpkg --audit failed or reports problems' RECOVERY_IN_PROGRESS; }
t99() { . "$HERE/smoke-tests.sh"; rec_fixture $RA
    rec_args sinter-t-a:all:1.0; rec_run MOCK_P_ALSO=realpkg000; rec_stopped "the purge also removed another package (database mismatch)" 1 'other than the targets changed' RECOVERY_IN_PROGRESS; }
t100() { . "$HERE/smoke-tests.sh"; rec_fixture $RA
    local key; key="$(printf '%s' "$H_DPKG_TARGET" | tr '/ ' '__')"
    : > "$T/mnt/$key"; rec_args sinter-t-a:all:1.0; rec_run; rec_stopped "a wrapper mount remains before the purge" 0 'is a mount point'
    rm -f "$T/mnt/$key"; rec_args sinter-t-a:all:1.0; rec_run MOCK_P_CREATE_MARK="$T/mnt/$key"; rec_stopped "a wrapper mount appears during the purge" 1 'is a mount point' RECOVERY_IN_PROGRESS; }
t101() { . "$HERE/smoke-tests.sh"; rec_fixture $RA
    rec_args sinter-t-a:all:1.0; rec_run MOCK_P_CHMOD="$EVD/recovery.*:500"
    a_eq "evidence can not be saved after the purge: exit 1" 1 "$(cat "$T/scenario.rc")"
    a_eq "the state stays RECOVERY_IN_PROGRESS (a purge was issued and the outcome was not recorded)" RECOVERY_IN_PROGRESS "$(st_name)"
    a_false "never recorded as a success" rec_status_has $'result\tRECOVERED'
    chmod 700 "$EVD"/recovery.* 2> /dev/null
    rm -rf "$T/evid2"; mkdir "$T/evid2"; chmod 500 "$T/evid2"; SMOKE_ARGV=(--run-id recfix1 --run-dir "$RF_RDIR" --evidence-dir "$T/evid2" --target sinter-t-a:all:1.0)
    RP0="$(n_real_purge)"; rec_run; a_eq "an unwritable evidence directory: exit 1" 1 "$(cat "$T/scenario.rc")"; a_true "for that reason" grep -q 'evidence directory is not usable' "$T/scenario.out"; a_eq "and nothing is purged" 0 "$(rec_dp)"; chmod 700 "$T/evid2"; }
t105() { . "$HERE/smoke-tests.sh"; rec_fixture $RA
    local bad
    for bad in "bash:amd64:5.2.21" "sinter-t-a:all" "sinter-t-a:all:1.0;x" "sinter-t-a:s390x:1.0" "Sinter-t-a:all:1.0" "sinter-t-:all:1.0"; do
        rec_args "$bad"; rec_run; a_eq "malformed or foreign target [$bad]: usage error 2" 2 "$(cat "$T/scenario.rc")"; a_eq "no purge for [$bad]" 0 "$(rec_dp)"
    done
    rec_args sinter-t-a:all:1.0 sinter-t-a:all:1.0; rec_run; a_eq "a duplicate target: usage error" 2 "$(cat "$T/scenario.rc")"
    SMOKE_ARGV=(--run-id recfix1 --run-dir "$RF_RDIR" --evidence-dir "$EVD"); rec_run; a_eq "no target at all: usage error" 2 "$(cat "$T/scenario.rc")"
    SMOKE_ARGV=(--run-id recfix1 --run-dir /etc --evidence-dir "$EVD" --target sinter-t-a:all:1.0); rec_run; a_eq "a run directory outside the base: usage error" 2 "$(cat "$T/scenario.rc")"
    SMOKE_ARGV=(--force --run-id recfix1); rec_run; a_eq "an unknown option: usage error" 2 "$(cat "$T/scenario.rc")"
    a_eq "the state record is untouched by all of these" FAILED_LOCKED "$(st_name)"; }
t106() { . "$HERE/smoke-tests.sh"; rec_fixture $RA
    db_mutate 'for r in db["pkgs"]:
    if r["name"] == "sinter-t-a": r["abbr"] = "iF "'
    rec_args sinter-t-a:all:1.0; rec_run; rec_stopped "a half-configured target needs a reviewed plan" 0 'needs a reviewed plan'
    db_mutate 'for r in db["pkgs"]:
    if r["name"] == "sinter-t-a": r["abbr"] = "rH "'
    rec_run MOCK_AUDIT_PRE_OUT="$AUDIT_KNOWN_A"; rec_ok_final "a half-installed target (rH) with the known audit report"; }
t107() { . "$HERE/smoke-tests.sh"; rec_fixture $RA
    ASSEMBLE_BUILD=production "$HERE/../assemble.sh" "$T/asm-p" > /dev/null 2>&1
    rec_args sinter-t-a:all:1.0
    smoke_run "$T/asm-p/recover-synthetic.sh" recfix1; a_eq "the production tool refuses the test environment (stray H_* variables): exit 70" 70 "$(cat "$T/scenario.rc")"
    a_true "naming H_TEST_MODE" grep -q H_TEST_MODE "$T/scenario.out"; a_eq "no purge" 0 "$(rec_dp)"; a_eq "the state is kept" FAILED_LOCKED "$(st_name)"
    DROP_ENV=H_TEST_MODE smoke_run "$T/asm/recover-synthetic.sh" recfix1; a_eq "a test build of the tool without H_TEST_MODE=1: exit 70" 70 "$(cat "$T/scenario.rc")"; }
t108() { . "$HERE/smoke-tests.sh"; rec_fixture $RA
    db_mutate 'db["foreign"] = ["i386"]'
    rec_args sinter-t-a:all:1.0; rec_run; rec_stopped "a foreign architecture that the failed run did not have" 0 'foreign architectures differ'
    db_mutate 'db["foreign"] = []'; rec_run; a_eq "positive control: without the difference the recovery succeeds" 0 "$(cat "$T/scenario.rc")"; }
t110() { . "$HERE/smoke-tests.sh"; rec_fixture $RA
    db_mutate 'db["pkgs"].append({"name": "sinter-t-b", "arch": "all", "ver": "1.0", "ess": "no", "abbr": "ii ", "maint": "Sinter Test <test@example.invalid>"})'
    rec_args sinter-t-a:all:1.0 sinter-t-b:all:1.0; rec_run; rec_stopped "a named target that the failed run never registered" 0 'is not in the registry'; }
t111() { . "$HERE/smoke-tests.sh"; rec_fixture $RA
    db_mutate 'for r in db["pkgs"]:
    if r["name"] == "sinter-t-a": r["maint"] = "Someone Else <x@example.invalid>"'
    rec_args sinter-t-a:all:1.0; rec_run; rec_stopped "a target whose Maintainer is not the harness's" 0 'Maintainer differs'; }
t112() { . "$HERE/smoke-tests.sh"; rec_fixture $RA $RB
    db_mutate 'for r in db["pkgs"]:
    if r["name"] == "sinter-t-a": r["abbr"] = "iF "'
    rec_args sinter-t-a:all:1.0 sinter-t-b:all:1.0; rec_run; rec_stopped "the last target in purge order needs a reviewed plan: nothing is purged, not even the good one" 0 'needs a reviewed plan'; }
t114() { . "$HERE/smoke-tests.sh"; rec_fixture $RA
    rec_args sinter-t-a:all:1.0; rec_run MOCK_P_FOREIGN=i386; rec_stopped "the foreign architectures change during the purge" 1 'foreign architectures differ' RECOVERY_IN_PROGRESS; }
# ---- R2-1: the release state machine ----------------------------------------------------------------------
# ---- R2-2: the pre-recovery audit -------------------------------------------------------------------------
AUDIT_KNOWN_A="$(printf '%s\n' 'The following packages are only half installed, due to problems during' 'installation.  The installation can probably be completed by retrying it;' 'the packages can be removed using dselect or dpkg --remove:' ' sinter-t-a   synthetic package for Sinter removal tests' '')"
t127() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # A: the command itself failed
    rec_args sinter-t-a:all:1.0
    rec_run H_RF_FAULT=audit-nocapture; rec_stopped "dpkg --audit could not be executed (no capture)" 0 'could not be executed'
    rec_run H_RF_FAULT=audit-stdout-missing; rec_stopped "the stdout of dpkg --audit was not obtained" 0 'standard output of dpkg --audit was not obtained'
    rec_run H_RF_FAULT=audit-stderr-missing; rec_stopped "the stderr of dpkg --audit was not obtained" 0 'standard error of dpkg --audit was not obtained'
    rec_run MOCK_AUDIT_PRE_RC=1; rec_stopped "dpkg --audit exits 1 (empty output)" 0 'exited with status 1'
    rec_run MOCK_AUDIT_PRE_RC=2 MOCK_AUDIT_PRE_OUT="$AUDIT_KNOWN_A"; rec_stopped "dpkg --audit exits 2 even though the output looks like the known report" 0 'exited with status 2'
    rec_run MOCK_AUDIT_PRE_ERR="dpkg: warning: something"; rec_stopped "dpkg --audit writes to stderr (exit 0)" 0 'wrote to stderr'
    rec_run MOCK_AUDIT_PRE_OUT=$'carriage\r'; rec_stopped "the audit output is not clean text (CR)" 0 'is not clean text'
    rec_run H_RF_FAULT=audit-save; rec_stopped "the audit output can not be saved to the evidence" 0 'could not be saved to the evidence'
    rec_run H_RF_FAULT=audit-readback; rec_stopped "the saved audit output reads back differently" 0 'reads back differently'
    rec_run; a_eq "positive control: with the faults gone (clean audit, state ii) the recovery succeeds" 0 "$(cat "$T/scenario.rc")"; }
t128() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # B: it ran, and reports the known half-installed report
    db_mutate 'for r in db["pkgs"]:
    if r["name"] == "sinter-t-a": r["abbr"] = "rH "'
    rec_args sinter-t-a:all:1.0
    rec_run MOCK_AUDIT_PRE_OUT="$AUDIT_KNOWN_A"; rec_ok_final "the known report for an explicit half-installed target"
    a_true "the diagnostic was saved" bash -c "grep -q 'only half installed' \"$EVD\"/recovery.*/audit-pre.out"
    a_true "and classified" bash -c "grep -q 'B: ran, exit 0, the known half-installed report' \"$EVD\"/recovery.*/steps.tsv"; }
t129() { . "$HERE/smoke-tests.sh"; rec_fixture $RA $RB   # B with something unexpected in it
    db_mutate 'for r in db["pkgs"]:
    if r["name"] in ("sinter-t-a",): r["abbr"] = "rH "'
    rec_args sinter-t-a:all:1.0 sinter-t-b:all:1.0
    rec_run MOCK_AUDIT_PRE_OUT="$(printf '%s\n' 'The following packages are only half installed, due to problems during' 'installation.  The installation can probably be completed by retrying it;' 'the packages can be removed using dselect or dpkg --remove:' ' sinter-t-a   synthetic package for Sinter removal tests' ' sinter-t-zzz   synthetic package for Sinter removal tests' '')"
    rec_stopped "the report lists a package that is not an explicit target" 0 'not an explicit target in a half-installed state'
    rec_run MOCK_AUDIT_PRE_OUT="$(printf '%s\n' 'The following packages are only half installed, due to problems during' 'installation.  The installation can probably be completed by retrying it;' 'the packages can be removed using dselect or dpkg --remove:' ' sinter-t-a   synthetic package for Sinter removal tests' ' bash   GNU Bourne Again SHell' '')"
    rec_stopped "the report lists a real package with another description" 0 'unexpected description'
    rec_run MOCK_AUDIT_PRE_OUT="$(printf '%s\n' 'The following packages are only half installed, due to problems during' 'installation.  The installation can probably be completed by retrying it;' 'the packages can be removed using dselect or dpkg --remove:' ' sinter-t-b   synthetic package for Sinter removal tests' '')"
    rec_stopped "the report lists a target that is NOT half-installed" 0 'not an explicit target in a half-installed state'
    rec_run MOCK_AUDIT_PRE_OUT="$(printf '%s\n' 'The following packages have been triggered, but the trigger processing has not yet been done:' ' sinter-t-a   synthetic package for Sinter removal tests' '')"
    rec_stopped "a report this tool does not know" 0 'reports something this tool does not know'
    rec_run MOCK_AUDIT_PRE_OUT="$(printf '%s\n' 'The following packages are only half installed, due to problems during' 'installation.  The installation can probably be completed by retrying it;' 'the packages can be removed using dselect or dpkg --remove:' ' sinter-t-a   synthetic package for Sinter removal tests' '' 'The following packages are not completely installed and configured:' ' sinter-t-b   synthetic package for Sinter removal tests' '')"
    rec_stopped "a second report after the known one" 0 'more than the one known report'
    rec_run MOCK_AUDIT_PRE_OUT="$(printf '%s\n' 'The following packages are only half installed, due to problems during' 'installation.  The installation can probably be completed by retrying it;' 'the packages can be removed using dselect or dpkg --remove:' '')"
    rec_stopped "the known header without any package" 0 'incomplete'
    :; }
t130() { . "$HERE/smoke-tests.sh"; rec_fixture $RA $RB   # a half-installed target that the report does not list; a non-empty report for targets that are not half-installed
    db_mutate 'for r in db["pkgs"]:
    if r["name"] in ("sinter-t-a", "sinter-t-b"): r["abbr"] = "rH "'
    rec_args sinter-t-a:all:1.0 sinter-t-b:all:1.0
    rec_run MOCK_AUDIT_PRE_OUT="$AUDIT_KNOWN_A"; rec_stopped "target b is half-installed but the report does not list it" 0 'does not list it'
    db_mutate 'for r in db["pkgs"]:
    if r["name"] in ("sinter-t-a", "sinter-t-b"): r["abbr"] = "ii "'
    rec_run MOCK_AUDIT_PRE_OUT="$AUDIT_KNOWN_A"; rec_stopped "the report lists a target whose state is plainly installed" 0 'not an explicit target in a half-installed state'; }

# ---- R2 self-audit additions: failures around the lock record and the evidence are never reported as success -------

# ---- R3: the new and the rewritten cases ------------------------------------------------------------------
t90() { . "$HERE/smoke-tests.sh"; rec_fixture $RA
    local owner want; owner="$(st_rec)"
    a_match "the fixture's state record: ONE line, FAILED_LOCKED, seq 2, written by the scenario" '^sinter-state-v5;state=FAILED_LOCKED;seq=2;by=scenario;pid=[0-9]+;run_id=recfix1;uid=[0-9]+;run_dir=/.+;nonce=[0-9a-f]{32};init=[0-9a-f]{32}$' "$owner"
    a_true "the exclusion file is a private regular file and nobody holds it" bash -c "[ -f '$(MXP)' ] && [ ! -L '$(MXP)' ] && [ \"\$(ls -l '$(MXP)' | cut -c1-10)\" = '-rw-------' ]"
    a_true "nobody holds the exclusion (the failed run is gone)" mx_free
    rec_args sinter-t-a:all:1.0; rec_run
    rec_ok_final "a normal recovery"
    a_eq "exactly ONE purge command (positive control: the search sees purges)" 1 "$(rec_dp)"
    a_true "the target is gone" bash -c "! echo \"$(db_names)\" | grep -q sinter-t-a"
    a_true "the state record was copied into the evidence" bash -c "[ \"\$(cat \"$EVD\"/recovery.*/lock-owner.copy)\" = \"$owner\" ]"
    a_true "the report, both snapshots and the final evidence were saved" bash -c "ls \"$EVD\"/recovery.*/recovery-report.tsv \"$EVD\"/recovery.*/snap-pre.tsv \"$EVD\"/recovery.*/snap-post.tsv \"$EVD\"/recovery.*/recovery-final.tsv > /dev/null"
    a_match "the sealed record: RECOVERED, seq 5, written by the recovery" '^sinter-state-v5;state=RECOVERED;seq=5;by=recovery;pid=[0-9]+;run_id=recfix1;uid=[0-9]+;run_dir=/.+;nonce=[0-9a-f]{32};init=[0-9a-f]{32}$' "$(st_rec)"
    a_eq "the run identity (run id, uid, run dir, nonce) of the sealed record is the original one" "${owner#*;run_id=}" "$(st_rec | sed 's/.*;run_id=//')"
    want="$(printf 'run_id\trecfix1 start exclusion-held prechecks-passed state-entered purge-started purges-done postchecks-passed state-pending sealed final')"
    a_eq "the phases show every stage in order" "$want" "$(tr '\n' ' ' < "$(ls -d "$EVD"/recovery.* | head -1)/phases.tsv" | sed 's/ $//')"
    a_true "the exclusion file still exists (it is never removed)" test -f "$(MXP)"
    a_false "no force option" log_has_force; a_false "no real package name in a purge" log_has_real_name; a_true "no tripwire" no_tripwire
    a_true "the database equals the run's baseline again" cmp -s "$RF_RDIR/snap.base" "$(ls "$EVD"/recovery.*/snap-post.tsv)"
    rec_run; a_eq "a second recovery finds nothing to recover and stops" 1 "$(cat "$T/scenario.rc")"; a_true "for that reason" grep -q 'the state is RECOVERED: nothing to recover' "$T/scenario.out"; a_eq "and purges nothing more" 1 "$(rec_dp)"
    # recovered and a new run permitted are two different facts: now (and only now) a new run is allowed
    new_run_full; a_eq "after the seal a new run is allowed and finishes cleanly" 0 "$NR_RC"; a_eq "and leaves the state UNLOCKED (seq 7)" 7 "$(st_rec | sed 's/.*;seq=\([0-9]*\);.*/\1/')"; a_eq "UNLOCKED" UNLOCKED "$(st_name)"; }
t102() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # identity of the state record, one variation at a time
    local good rd nonce
    good="$(st_rec)"; rd="$RF_RDIR"; nonce="$(cat "$rd/lock-nonce")"
    try() { ST_BEFORE="$(st_kind)"; rec_args sinter-t-a:all:1.0; rec_run; refused "$1" "$2"; unlink "$(STP)" 2> /dev/null; rm -f "$T/stcopy"; setstate "$good"; }
    setstate "${good/run_id=recfix1/run_id=otherrun}"; try "the record names another run id" 'belongs to run [otherrun]'
    setstate "${good/nonce=$nonce/nonce=00000000000000000000000000000000}"; try "the record's nonce differs from the run directory's" "does not carry this state record's nonce"
    setstate "$(echo "$good" | sed 's/;uid=[0-9]*;/;uid=0;/')"; try "the record was written by another uid" 'was written by uid 0'
    setstate "${good/run_dir=$rd/run_dir=$T/base/sinter-h-elsewhere.abc}"; try "the record names another run directory" 'another run directory'
    setstate "$good;extra=1"; try "the record has an extra field" 'UNKNOWN: the state record is unreadable, malformed'
    setstate "$(echo "$good" | sed 's/;uid=[0-9]*//')"; try "the record lacks a field" 'UNKNOWN: the state record is unreadable, malformed'
    setstate "${good/state=FAILED_LOCKED/state=SOMETHING_ELSE}"; try "an unknown state name" 'UNKNOWN: the state record is unreadable, malformed'
    setstate "4242 recfix1"; try "an old-format record in the state file" 'UNKNOWN: the state record is unreadable, malformed'
    setstate "/etc"; try "a path in the state file" 'UNKNOWN: the state record is unreadable, malformed'
    setstate "$good"$'\n'"$good"; try "two lines" 'UNKNOWN: the state record is unreadable, malformed'
    setstate "${good/state=FAILED_LOCKED/state=UNLOCKED}"; try "the state is UNLOCKED" 'the state is UNLOCKED: nothing to recover'
    setstate "${good/state=FAILED_LOCKED/state=RECOVERED}"; try "the state is RECOVERED" 'the state is RECOVERED: nothing to recover'
    setstate "${good/state=FAILED_LOCKED/state=RUNNING}"; try "the state is RUNNING and --allow-orphan is not given" 'recovering it needs --allow-orphan'
    setstate "${good/state=FAILED_LOCKED/state=RECOVERY_IN_PROGRESS}"; try "the state is RECOVERY_IN_PROGRESS" 'an earlier recovery was interrupted'
    setstate "${good/state=FAILED_LOCKED/state=PACKAGES_RECOVERED_LOCK_PENDING}"; try "the state is PACKAGES_RECOVERED_LOCK_PENDING" 'did not seal the state'
    unlink "$(STP)"; try "no state record at all (the environment WAS initialised)" 'its state record is MISSING'
    cp "$(STP)" "$T/stcopy"; unlink "$(STP)"; ln -s "$T/stcopy" "$(STP)"; try "the state path is a symlink to a perfectly valid record" 'UNKNOWN: the state record is unreadable, malformed'
    unlink "$(STP)"; mkdir "$(STP)"; ST_BEFORE="$(st_kind)"; rec_args sinter-t-a:all:1.0; rec_run; refused "the state path is a directory" 'UNKNOWN: the state record is unreadable, malformed'; rmdir "$(STP)"; setstate "$good"
    mv "$rd/lock-nonce" "$rd/lock-nonce.x"; try "the run directory has no nonce" "does not carry this state record's nonce"; mv "$rd/lock-nonce.x" "$rd/lock-nonce"
    mv "$rd/final-status.tsv" "$rd/fs.x"; try "no final status of the run" "did not end with 'cleanup failed'"; mv "$rd/fs.x" "$rd/final-status.tsv"
    cp "$rd/final-status.tsv" "$rd/fs.keep"; sed 's/^cleanup.*/cleanup\tok/' "$rd/fs.keep" > "$rd/final-status.tsv"; try "the run did not end with cleanup failed" "did not end with 'cleanup failed'"; mv "$rd/fs.keep" "$rd/final-status.tsv"
    rec_args sinter-t-a:all:1.0; rec_run; a_eq "positive control: with everything restored the recovery succeeds" 0 "$(cat "$T/scenario.rc")"; }
t103() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # the state can not be sealed (a failure injected into the last compare-and-set)
    rec_args sinter-t-a:all:1.0; rec_run H_RF_FAULT=seal-fail
    rec_stopped "the state can not be sealed" 1 'could not be sealed as RECOVERED' PACKAGES_RECOVERED_LOCK_PENDING
    a_match "the record is the intact PENDING record of this run (seq 4, written by the recovery)" '^sinter-state-v5;state=PACKAGES_RECOVERED_LOCK_PENDING;seq=4;by=recovery;pid=[0-9]+;run_id=recfix1;uid=[0-9]+;run_dir=/.+;nonce=[0-9a-f]{32};init=[0-9a-f]{32}$' "$(st_rec)"
    a_true "the final evidence was saved BEFORE the seal was attempted" bash -c "ls \"$EVD\"/recovery.*/recovery-final.tsv > /dev/null"
    a_true "the packages are recorded as recovered, the result is FAILED" bash -c "grep -qx $'packages_recovered\tyes' \"$EVD\"/recovery.*/recovery-status.tsv && grep -qx $'result\tFAILED' \"$EVD\"/recovery.*/recovery-status.tsv"
    ST_BEFORE="$(st_kind)"; new_run; nr_refused "a new run after the failed seal" 'PACKAGES_RECOVERED_LOCK_PENDING'
    rec_run; refused "a rerun does not treat the state as normal" 'the state is PACKAGES_RECOVERED_LOCK_PENDING' 1; }
t104() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # the state file can not be replaced right before the first transition (the base directory becomes read-only)
    local good; good="$(st_rec)"
    rec_args sinter-t-a:all:1.0; rec_run H_RF_FAULT=chmod-base-before-enter; chmod 700 "$T/state"
    rec_stopped "the state RECOVERY_IN_PROGRESS can not be written" 0 'RECOVERY_IN_PROGRESS could not be recorded'
    a_eq "the record is exactly the one the failed run left" "$good" "$(st_rec)"
    a_eq "no temporary state file is left" "" "$(tmps)"
    rec_run; rec_ok_final "positive control: once the directory is writable again the same recovery works (nothing had been changed)"; }
t113() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # another actor writes a record of ANOTHER run into the state file while the recovery purges
    local good other; good="$(st_rec)"
    other="${good/nonce=*/nonce=ffffffffffffffffffffffffffffffff}"; other="${other/state=FAILED_LOCKED/state=RUNNING}"
    rec_args sinter-t-a:all:1.0; rec_run MOCK_P_WRITE="$(STP)::$other"
    a_eq "exit status 1" 1 "$(cat "$T/scenario.rc")"
    a_true "stopped because the compare-and-set failed" grep -q 'PACKAGES_RECOVERED_LOCK_PENDING could not be recorded (compare-and-set failed' "$T/scenario.out"
    a_eq "the other actor's record is untouched" "$other" "$(st_rec)"
    a_eq "no temporary state file" "" "$(tmps)"
    a_eq "the one purge had happened" 1 "$(rec_dp)"
    a_false "never recorded as a success" rec_status_has $'result\tRECOVERED'; }
t115() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # the state names a VALID run directory, just not the one given on the command line
    local good; good="$(st_rec)"
    cp -R "$RF_RDIR" "$RF_RDIR.copy"; chmod 700 "$RF_RDIR.copy"
    setstate "${good/run_dir=$RF_RDIR/run_dir=$RF_RDIR.copy}"; ST_BEFORE="$(st_kind)"
    rec_args sinter-t-a:all:1.0; rec_run; refused "the state names another (valid) run directory" 'another run directory'; }
t116() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # the state stays VALID but its content changes (another pid, another seq) while the recovery runs
    local good other; good="$(st_rec)"
    other="$(echo "$good" | sed 's/;pid=[0-9]*;/;pid=999999;/; s/;seq=2;/;seq=77;/')"
    rec_args sinter-t-a:all:1.0; rec_run MOCK_P_WRITE="$(STP)::$other"
    a_eq "exit status 1" 1 "$(cat "$T/scenario.rc")"
    a_true "stopped because the compare-and-set failed (an equally valid record is still a different record)" grep -q 'compare-and-set failed' "$T/scenario.out"
    a_eq "the changed record is untouched" "$other" "$(st_rec)"; }
t117() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # the state is swapped between the pre-checks and the first transition (the recovery holds the exclusion)
    local good other; good="$(st_rec)"; other="${good/nonce=*/nonce=00000000000000000000000000000000}"
    mkdir "$T/hold"; rec_args sinter-t-a:all:1.0
    SMOKE_TAG=A; ( rec_run H_RF_FAULT=hold-before-enter H_RF_HOLD_DIR="$T/hold" ) & local pa=$!; SMOKE_TAG=""
    wait_for "$T/hold/held-before-enter"; a_true "the recovery reached the point between the pre-checks and the first transition" test -e "$T/hold/held-before-enter"
    setstate "$other"
    : > "$T/hold/go-before-enter"; wait "$pa"
    a_eq "exit status 1" 1 "$(cat "$T/scenarioA.rc")"
    a_true "stopped because the compare-and-set failed" grep -q 'RECOVERY_IN_PROGRESS could not be recorded (compare-and-set failed' "$T/scenarioA.out"
    a_eq "NOTHING was purged" 0 "$(rec_dp)"
    a_eq "the other actor's record is untouched (not even restored)" "$other" "$(st_rec)"
    a_eq "no temporary state file" "" "$(tmps)"; }
t118() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # a NEW run (and a second recovery) while the recovery holds the exclusion, between two transitions
    local good; good="$(st_rec)"
    mkdir "$T/hold"; rec_args sinter-t-a:all:1.0
    SMOKE_TAG=A; ( rec_run H_RF_FAULT=hold-before-enter H_RF_HOLD_DIR="$T/hold" ) & local pa=$!; SMOKE_TAG=""
    wait_for "$T/hold/held-before-enter"
    ST_BEFORE="$(st_kind)"; new_run; nr_refused "a new run while the recovery holds the exclusion (state still FAILED_LOCKED)" 'BUSY'
    SMOKE_TAG=B; rec_run; SMOKE_TAG=""
    a_eq "a second recovery: exit 1" 1 "$(cat "$T/scenarioB.rc")"; a_true "refused because the exclusion is busy" grep -q 'BUSY' "$T/scenarioB.out"
    a_eq "the state is untouched by both" "$ST_BEFORE" "$(st_kind)"
    : > "$T/hold/go-before-enter"; wait "$pa"
    a_eq "the recovery itself completed" 0 "$(cat "$T/scenarioA.rc")"; a_eq "with exactly one purge" 1 "$(rec_dp)"; a_eq "sealed" RECOVERED "$(st_name)"
    new_run_full; a_eq "and only then a new run is possible" 0 "$NR_RC"; }
t119() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # a new run right BEFORE the seal (after the packages are recovered, the state is PENDING)
    mkdir "$T/hold"; rec_args sinter-t-a:all:1.0
    SMOKE_TAG=A; ( rec_run H_RF_FAULT=hold-before-seal H_RF_HOLD_DIR="$T/hold" ) & local pa=$!; SMOKE_TAG=""
    wait_for "$T/hold/held-before-seal"
    a_eq "at this moment the state is PACKAGES_RECOVERED_LOCK_PENDING" PACKAGES_RECOVERED_LOCK_PENDING "$(st_name)"
    ST_BEFORE="$(st_kind)"; new_run; nr_refused "a new run right before the seal" 'BUSY'
    a_eq "the packages are already gone, yet nothing may start (recovered is not the same as released)" 0 "$(db_names | grep -c sinter-t-a)"
    : > "$T/hold/go-before-seal"; wait "$pa"
    a_eq "the recovery completed" 0 "$(cat "$T/scenarioA.rc")"; a_eq "sealed" RECOVERED "$(st_name)"
    new_run_full; a_eq "after the seal the new run works" 0 "$NR_RC"; }
t120() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # SIGKILL right after RECOVERY_IN_PROGRESS was recorded
    kill_case kill-after-enter RECOVERY_IN_PROGRESS state-entered 0; }
t121() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # SIGKILL right before the first transition: nothing had been recorded, nothing is lost
    kill_case kill-before-enter FAILED_LOCKED prechecks-passed 0; }
t122() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # the FINAL status can not be saved (after the seal)
    rec_args sinter-t-a:all:1.0; rec_run H_RF_FAULT=chmod-after-seal
    a_eq "exit status 1" 1 "$(cat "$T/scenario.rc")"
    a_true "the message separates the two results" grep -q 'packages are recovered and the state is sealed (new runs are allowed), but the FINAL status could not be saved' "$T/scenario.out"
    chmod 700 "$EVD"/recovery.*
    a_false "RECOVERED was never recorded in the status file" rec_status_has $'result\tRECOVERED'
    a_true "the interim status remains: packages recovered, state pending" rec_status_has $'result\tPACKAGES_RECOVERED_LOCK_PENDING'
    a_eq "the state is sealed" RECOVERED "$(st_name)"
    a_true "the final evidence (saved before the seal) exists and the owner record copy is intact" bash -c "[ -s \"\$(ls \"$EVD\"/recovery.*/recovery-final.tsv)\" ] && [ -s \"\$(ls \"$EVD\"/recovery.*/lock-owner.copy)\" ]"
    new_run_full; a_eq "a new run is allowed (RECOVERED implies the final evidence exists)" 0 "$NR_RC"; }
t123() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # two real recovery processes
    mkdir "$T/hold"; rec_args sinter-t-a:all:1.0
    SMOKE_TAG=A; ( rec_run H_RF_FAULT=hold-after-enter H_RF_HOLD_DIR="$T/hold" ) & local pa=$!; SMOKE_TAG=""
    wait_for "$T/hold/held-after-enter"
    a_eq "A has recorded RECOVERY_IN_PROGRESS" RECOVERY_IN_PROGRESS "$(st_name)"
    ST_BEFORE="$(st_kind)"
    SMOKE_TAG=B; rec_run; SMOKE_TAG=""
    a_eq "B was refused (exit 1)" 1 "$(cat "$T/scenarioB.rc")"; a_true "because A holds the exclusion" grep -q 'BUSY' "$T/scenarioB.out"
    a_eq "B did not touch the state" "$ST_BEFORE" "$(st_kind)"
    : > "$T/hold/go-after-enter"; wait "$pa"; a_eq "A completed" 0 "$(cat "$T/scenarioA.rc")"
    a_eq "exactly one purge happened" 1 "$(rec_dp)"; a_eq "and the state was sealed once" RECOVERED "$(st_name)"; }
t124() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # a lock of an OLD format is never released, interpreted or taken over (LEGACY_LOCK)
    local good lg sig; good="$(st_rec)"; ST_BEFORE="$(st_kind)"; lg="$T/base/sinter-h-lock"
    legacy_case() {  # legacy_case DESC PATH
        sig="$(ls -ldn "$2"; ls -ln "$2" 2> /dev/null; readlink "$2" 2> /dev/null)"
        rec_args sinter-t-a:all:1.0; rec_run; refused "$1" 'LEGACY_LOCK'
        a_true "$1: named as an old format" grep -q 'old format' "$T/scenario.out"
        new_run; nr_refused "$1 (new run)" 'LEGACY_LOCK'
        a_eq "$1: the old-format item is untouched" "$sig" "$(ls -ldn "$2"; ls -ln "$2" 2> /dev/null; readlink "$2" 2> /dev/null)"
    }
    mkdir "$lg"; printf 'format=2\npid=4242\nrun_id=recfix1\nuid=%s\nrun_dir=%s\nnonce=%s\n' "$(id -u)" "$RF_RDIR" "$(cat "$RF_RDIR/lock-nonce")" > "$lg/owner"
    legacy_case "the v2 directory lock with a perfectly matching owner file" "$lg"
    rm -rf "$lg"; mkdir "$lg"; printf '4242 recfix1\n' > "$lg/owner"; legacy_case "the v1 directory lock (PID RUN_ID)" "$lg"
    rm -rf "$lg"; mkdir "$lg"; legacy_case "an ownerless lock directory" "$lg"
    rmdir "$lg"; : > "$lg"; legacy_case "a regular file at the old lock path" "$lg"
    unlink "$lg"; ln -s "sinter-lock-v3;pid=4242;run_id=recfix1;uid=$(id -u);run_dir=$RF_RDIR;nonce=$(cat "$RF_RDIR/lock-nonce")" "$lg"; legacy_case "the v3 symbolic-link lock with a perfectly matching record" "$lg"
    unlink "$lg"; ln -s "sinter-rmutex-v1;pid=1;run_id=x;uid=1;nonce=00" "$lg.recovery"; legacy_case "a v3 recovery mutex" "$lg.recovery"
    unlink "$lg.recovery"; ln -s "sinter-lock-v3;pid=1;run_id=x;uid=1;run_dir=/x;nonce=00" "$lg.released.0123456789abcdef0123456789abcdef"; legacy_case "a v3 tombstone" "$lg.released.0123456789abcdef0123456789abcdef"
    unlink "$lg.released.0123456789abcdef0123456789abcdef"
    rec_args sinter-t-a:all:1.0; rec_run; a_eq "positive control: with the old-format items gone (by a human) the genuine record is recovered" 0 "$(cat "$T/scenario.rc")"; }
t125() {  # the library's side of the contract: taking the run, the record, a second taker, the clean release
    . "$HERE/smoke-tests.sh"
    mkdeb sinter-t-a all
    a_true "the environment was initialised explicitly: exclusion file, init record and the initial state record exist" bash -c "[ -f '$H_STATE_DIR/sinter-h-mutex' ] && [ -f '$H_STATE_DIR/sinter-h-init' ] && grep -q '^sinter-state-v5;state=UNLOCKED;seq=0;by=init;' '$H_STATE_DIR/sinter-h-state'"
    h_init t125-run; a_eq "a free system: the run is taken" 0 "$?"
    a_eq "this process holds the exclusion" 1 "$H_MUTEX_HELD"
    a_true "the exclusion file is a private regular file" bash -c "[ -f '$H_STATE_DIR/sinter-h-mutex' ] && [ ! -L '$H_STATE_DIR/sinter-h-mutex' ] && [ \"\$(ls -l '$H_STATE_DIR/sinter-h-mutex' | cut -c1-10)\" = '-rw-------' ]"
    a_match "the state record is RUNNING, seq 1, written by the scenario" '^sinter-state-v5;state=RUNNING;seq=1;by=scenario;pid=[0-9]+;run_id=t125-run;uid=[0-9]+;run_dir=/.+;nonce=[0-9a-f]{32};init=[0-9a-f]{32}$' "$(st_rec)"
    a_eq "the nonce in the run directory equals the nonce in the record" "$(cat "$H_RUNDIR/lock-nonce")" "$(st_rec | sed 's/.*;nonce=\([0-9a-f]*\);init=.*/\1/')"
    a_true "no old-format lock path was created" bash -c "[ -z \"\$(ls -d '$H_BASE'/sinter-h-lock* 2>/dev/null)\" ]"
    local sv; sv="$(st_rec)"
    ( h_init t125-run2 ) 2> /dev/null; a_eq "a second init in a subshell of the same process is refused" 1 "$?"
    ST_BEFORE="$(st_kind)"; new_run; nr_refused "a second process" 'BUSY'
    a_eq "the record is exactly the one the run wrote" "$sv" "$(st_rec)"
    h_baseline; h_install_deb sinter-t-a_1.0_all.deb; h_finish
    a_eq "a clean finish" ok "$H_CLEANUP_STATUS"
    a_match "the state is UNLOCKED, seq 2, the same run identity" '^sinter-state-v5;state=UNLOCKED;seq=2;by=scenario;pid=[0-9]+;run_id=t125-run;uid=[0-9]+;run_dir=/.+;nonce=[0-9a-f]{32};init=[0-9a-f]{32}$' "$(st_rec)"
    a_eq "the exclusion was dropped" 0 "$H_MUTEX_HELD"; a_true "nobody holds it" mx_free; a_true "the exclusion file was NOT removed" test -f "$(MXP)"
    a_eq "no temporary state file" "" "$(tmps)"
    H_ABORTED=0; H_FAILED=0; H_FINISHED=0; H_CLEANUP_STATUS=not-run; H_REG=(); H_ARMED=(); mkdb 12
    h_init t125-run3; a_eq "from UNLOCKED the next run is taken" 0 "$?"; a_match "seq 3, RUNNING, the new run's identity" '^sinter-state-v5;state=RUNNING;seq=3;by=scenario;pid=[0-9]+;run_id=t125-run3;uid=' "$(st_rec)"; }
t126() {  # a failed run keeps its state record with the owner information intact; a failed init takes nothing
    . "$HERE/smoke-tests.sh"
    mkdeb sinter-t-a all; start_run
    local rec; rec="$(st_rec)"
    h_install_deb sinter-t-a_1.0_all.deb
    export MOCK_P_FAIL_ON=1; h_finish; unset MOCK_P_FAIL_ON
    a_eq "cleanup failed" failed "$H_CLEANUP_STATUS"
    a_eq "the state is FAILED_LOCKED" FAILED_LOCKED "$(st_name)"
    a_eq "with exactly the owner information of the run (only state and seq changed)" "${rec#*;by=}" "$(st_rec | sed 's/.*;by=//')"
    a_match "seq 2" ';seq=2;by=scenario;' "$(st_rec)"
    a_eq "the exclusion was dropped (the STATE refuses the next run, not the OS lock)" 0 "$H_MUTEX_HELD"; a_true "nobody holds the exclusion" mx_free
    ST_BEFORE="$(st_kind)"; new_run; nr_refused "the next run" 'FAILED_LOCKED'; }
kill_case() {  # kill_case FAULT STATE_AFTER LAST_PHASE PURGES -> SIGKILL at a point of the recovery; what is left, who may do what next
    local fault="$1" st="$2" ph="$3" pg="$4" before
    rec_args sinter-t-a:all:1.0; rec_run H_RF_FAULT="$fault"
    a_eq "$fault: the process was killed (137)" 137 "$(cat "$T/scenario.rc")"
    a_eq "$fault: the state after the kill is identifiable" "$st" "$(st_name)"
    a_eq "$fault: the last phase says how far it got" "$ph" "$(last_phase)"
    a_true "$fault: the kernel dropped the exclusion" mx_free
    a_eq "$fault: purge commands issued" "$pg" "$(rec_dp)"
    a_eq "$fault: no temporary state file" "" "$(tmps)"
    a_true "$fault: the owner record copy is in the evidence" bash -c "[ -s \"\$(ls \"$EVD\"/recovery.*/lock-owner.copy)\" ]"
    ST_BEFORE="$(st_kind)"
    case "$st" in
        RECOVERED)
            new_run_full; a_eq "$fault: the state is sealed, so a new run is allowed" 0 "$NR_RC"
            a_true "$fault: the final evidence exists" bash -c "ls \"$EVD\"/recovery.*/recovery-final.tsv > /dev/null" ;;
        FAILED_LOCKED)
            new_run; nr_refused "$fault: a new run" 'FAILED_LOCKED'
            rec_run; rec_ok_final "$fault: nothing was recorded or lost, so the same recovery can simply be run again" ;;
        *)
            new_run; nr_refused "$fault: a new run" "$st"
            rec_run; refused "$fault: a rerun is not allowed to continue" "the state is $st" "$pg" ;;
    esac
}
t131() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # recovery tool: faults at the state-record copy, a foreign exclusion file, the interim status
    local good; good="$(st_rec)"; ST_BEFORE="$(st_kind)"
    rec_args sinter-t-a:all:1.0
    rec_run H_RF_FAULT=owner-save; refused "the state record can not be copied to the evidence" 'state record could not be saved'
    rec_run H_RF_FAULT=lock-foreign-owner; refused "the exclusion file belongs to another user" 'exclusion file is unsafe'
    rec_run H_RF_FAULT=interim-save; rec_stopped "the interim status (packages recovered, state not sealed) can not be saved" 1 'interim status' PACKAGES_RECOVERED_LOCK_PENDING
    a_match "the PENDING record keeps the run's owner information" "run_id=recfix1;uid=[0-9]+;run_dir=.*;nonce=${good##*nonce=}\$" "$(st_rec)"
    a_eq "interim-save: no temporary state file" "" "$(tmps)"
    ST_BEFORE="$(st_kind)"; rec_run; refused "a rerun after it" 'the state is PACKAGES_RECOVERED_LOCK_PENDING' 1; }
t132() {  # library: failures of the compare-and-set are never reported as a taken / released run
    . "$HERE/smoke-tests.sh"
    mkdeb sinter-t-a all
    eval "h_state_cas_orig() $(declare -f h_state_cas | tail -n +2)"
    SC_N=0; SC_FAIL_ON=0
    h_state_cas() { SC_N=$((SC_N + 1)); if [ "$SC_N" = "$SC_FAIL_ON" ]; then return 1; fi; h_state_cas_orig "$@"; }
    reset_lib() { h_mutex_drop; env_reset_state; H_ABORTED=0; H_FAILED=0; H_FINISHED=0; H_LOCK_HELD=0; H_CLEANUP_STATUS=not-run; H_REG=(); H_ARMED=(); SC_N=0; mkdb 12; }
    # (a) the record RUNNING can not be written: no run, nothing left
    SC_FAIL_ON=1; h_init t132-a; a_eq "the CAS of RUNNING fails: the run is refused" 1 "$?"
    a_eq "no run directory remains" "" "$(ls -d "$T"/base/sinter-h-t132-a.* 2> /dev/null)"; a_eq "the exclusion was dropped" 0 "$H_MUTEX_HELD"; a_true "nobody holds it" mx_free
    a_match "and the state record is still the initial one" '^sinter-state-v5;state=UNLOCKED;seq=0;by=init;' "$(st_rec)"
    # (b) the clean release can not be recorded: the state stays RUNNING, the failure is reported
    reset_lib; SC_FAIL_ON=2; h_init t132-b; h_baseline; h_install_deb sinter-t-a_1.0_all.deb; h_finish
    a_eq "the cleanup itself finished" ok "$H_CLEANUP_STATUS"
    a_match "the state is still the RUNNING record" '^sinter-state-v5;state=RUNNING;seq=1;' "$(st_rec)"
    a_eq "the failed release is a failure" 1 "$H_FAILED"; a_eq "the run still holds the exclusion (it was not released)" 1 "$H_LOCK_HELD"
    H_FINISHED=0; h_verdict > "$T/verdict.txt"; a_true "the verdict says FAIL" grep -q 'SCENARIO: FAIL' "$T/verdict.txt"
    ST_BEFORE="$(st_kind)"; new_run; nr_refused "another process meanwhile" 'BUSY'
    # (c) somebody else changed the state record during the run: the finish does not overwrite it
    reset_lib; SC_FAIL_ON=0; h_init t132-c; h_baseline; h_install_deb sinter-t-a_1.0_all.deb
    local other; other="$(st_rec | sed 's/;pid=[0-9]*;/;pid=999999;/')"; setstate "$other"
    h_finish
    a_eq "the other actor's record is untouched" "$other" "$(st_rec)"; a_eq "the failed release is a failure" 1 "$H_FAILED"
    # (d) the exclusion file is replaced by another inode while the run holds the old one: every transition refuses
    reset_lib; h_init t132-d; h_baseline; h_install_deb sinter-t-a_1.0_all.deb
    mv "$H_STATE_DIR/sinter-h-mutex" "$H_STATE_DIR/sinter-h-mutex.moved"; : > "$H_STATE_DIR/sinter-h-mutex"; chmod 600 "$H_STATE_DIR/sinter-h-mutex"
    h_finish
    a_eq "the finish could not record the release (identity of the exclusion file changed)" 1 "$H_FAILED"
    a_match "the state is still RUNNING" '^sinter-state-v5;state=RUNNING;' "$(st_rec)"
    ST_BEFORE="$(st_kind)"; new_run
    a_eq "a new process CAN lock the new inode, but the STATE still refuses it" 1 "$NR_RC"; a_true "naming the unfinished run" grep -q 'a previous run did not finish' <<< "$NR_OUT"
    # (e) the run FAILED and FAILED_LOCKED can not be recorded: the state stays RUNNING (which also refuses new runs) and the exclusion is kept
    reset_lib; SC_FAIL_ON=2; h_init t132-e; h_baseline; h_install_deb sinter-t-a_1.0_all.deb
    export MOCK_P_FAIL_ON=1; h_finish; unset MOCK_P_FAIL_ON
    a_eq "(e) the cleanup failed" failed "$H_CLEANUP_STATUS"
    a_match "(e) the state is still the RUNNING record" '^sinter-state-v5;state=RUNNING;seq=1;' "$(st_rec)"
    a_eq "(e) the failed FAILED_LOCKED write left the exclusion held" 1 "$H_LOCK_HELD"
    a_true "(e) and it is recorded as a failure of the lock step" grep -q $'^lock\t' "$T/records.tsv"; }
t133() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # a scenario that is RUNNING: a recovery and a second scenario are refused, nothing is changed
    rec_args sinter-t-a:all:1.0; rec_run; rec_ok_final "(setup) the failed run is recovered first"
    hold_run holdrun1; a_true "a live scenario holds the exclusion" test -e "$T/hold.up"
    a_eq "the state is RUNNING" RUNNING "$(st_name)"; ST_BEFORE="$(st_kind)"
    new_run; nr_refused "a second scenario" 'BUSY'
    rec_run; refused "a recovery while a scenario runs" 'BUSY' 1
    hold_release; a_eq "the live scenario was not disturbed and finished cleanly" 0 "$HOLD_RC"; a_eq "UNLOCKED" UNLOCKED "$(st_name)"; }
t134() {  # six processes try to take the run at the same moment, three rounds: never two inside the critical section
    . "$HERE/smoke-tests.sh"
    mkdeb sinter-t-a all
    local round i n won lost over
    for round in 1 2 3; do
        rm -f "$T/go" "$T/res".*; rmdir "$T/crit" 2> /dev/null
        for i in 1 2 3 4 5 6; do
            ( cd "$T" && bash -c "$NR_PRE"'while [ ! -e "$2" ]; do sleep 0.02; done
                if h_init "stress$3"; then
                    if mkdir "$4" 2> /dev/null; then sleep 1.0; rmdir "$4"; echo WON; else echo OVERLAP; fi
                    h_baseline; h_finish
                else echo "LOST:$(printf "%s" "$H_ABORTED")"; fi' _ "$HERE/.." "$T/go" "$i" "$T/crit" > "$T/res.$i" 2>&1 ) &
        done
        sleep 0.5; : > "$T/go"; wait
        won="$(cat "$T"/res.* | grep -c '^WON')"; lost="$(cat "$T"/res.* | grep -c '^LOST')"; over="$(cat "$T"/res.* | grep -c 'OVERLAP')"
        a_eq "round $round: never two runs inside the critical section" 0 "$over"
        a_true "round $round: at least one run got in" test "$won" -ge 1
        a_eq "round $round: every process either got in or was refused" 6 "$((won + lost))"
        a_true "round $round: at least one was refused while another held the run" test "$lost" -ge 1
        a_eq "round $round: afterwards the state is UNLOCKED and nobody holds the exclusion" UNLOCKED "$(st_name)"; mx_free || fail "round $round: the exclusion is still held"
    done; }
t135() { . "$HERE/smoke-tests.sh"; REC_FIX_END=kill rec_fixture $RA   # a scenario killed by SIGKILL while it ran (state RUNNING, nobody holds the exclusion)
    a_true "the kernel dropped the killed run's exclusion" mx_free
    ST_BEFORE="$(st_kind)"; new_run; nr_refused "a new run after a killed run" 'a previous run did not finish'
    rec_args sinter-t-a:all:1.0; rec_run; refused "a recovery without --allow-orphan" 'recovering it needs --allow-orphan'
    SMOKE_ARGV[${#SMOKE_ARGV[@]}]=--allow-orphan; rec_run
    rec_ok_final "with --allow-orphan the killed run is recovered by the same checks"
    a_eq "one purge" 1 "$(rec_dp)"; a_true "the database equals the run's baseline again" cmp -s "$RF_RDIR/snap.base" "$(ls "$EVD"/recovery.*/snap-post.tsv)"
    new_run_full; a_eq "and then a new run is allowed" 0 "$NR_RC"; }
t136() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # a damaged state file (UNKNOWN) is never repaired, interpreted or overwritten
    local good c; good="$(st_rec)"
    corrupt_case() {  # corrupt_case DESC  (the state path was prepared by the caller)
        ST_BEFORE="$(st_kind)"
        new_run; nr_refused "$1: a new run" 'UNKNOWN'
        rec_args sinter-t-a:all:1.0; rec_run; refused "$1: a recovery" 'UNKNOWN: the state record is unreadable, malformed'
    }
    : > "$(STP)"; corrupt_case "an empty file"
    head -c 40 "$(STP)" > /dev/null; printf '%s' "${good:0:60}" > "$(STP)"; corrupt_case "a truncated record"
    printf '\x00\x01\x02garbage\xff\n' > "$(STP)"; corrupt_case "binary junk"
    python3 -I -c 'import sys; sys.stdout.write("A" * 5000 + "\n")' > "$(STP)"; corrupt_case "5000 bytes"
    printf '%s trailing\n' "$good" > "$(STP)"; corrupt_case "a valid record followed by text on the same line"
    printf '%s\n%s\n' "$good" "$good" > "$(STP)"; corrupt_case "two records"
    unlink "$(STP)"; ln -s "$(STP).x" "$(STP)"; corrupt_case "a dangling symlink"
    unlink "$(STP)"; mkdir "$(STP)"; corrupt_case "a directory"; rmdir "$(STP)"
    setstate "${good/state=FAILED_LOCKED/state=UNLOCKED}"; ln "$(STP)" "$T/stlink"; ST_BEFORE="$(st_kind)"
    new_run; a_eq "a hard-linked state file (valid content): the new run is refused" 1 "$NR_RC"; a_true "because the record could not be written" grep -q 'could not be written' <<< "$NR_OUT"
    a_eq "and the state file is untouched" "$ST_BEFORE" "$(st_kind)"
    a_eq "no run directory" "" "$(ls -d "$T"/base/sinter-h-newrun1.* 2> /dev/null)"; }
t137() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # a stale temporary file of an interrupted write never decides anything and is never deleted
    rec_args sinter-t-a:all:1.0; rec_run; rec_ok_final "(setup) recovered"
    printf 'junk\n' > "$T/state/sinter-h-state.tmp.4242.deadbeef0000"
    new_run_full; a_eq "a new run is still decided by the state record alone" 0 "$NR_RC"
    a_true "the stale file is left exactly where it was (the harness deletes only what it created)" test -f "$T/state/sinter-h-state.tmp.4242.deadbeef0000"; }
t138() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # the exclusion file itself is tampered with: the new run is refused and nothing is changed
    rec_args sinter-t-a:all:1.0; rec_run; rec_ok_final "(setup) recovered"
    local mx; mx="$(MXP)"
    mx_case() {  # mx_case DESC  (the exclusion path was prepared by the caller)
        ST_BEFORE="$(st_kind)"; new_run; nr_refused "$1" 'exclusion file is unsafe'
    }
    chmod 644 "$mx"; mx_case "mode 644"; chmod 600 "$mx"
    ln "$mx" "$T/mxlink"; mx_case "a second hard link"; unlink "$T/mxlink"
    mv "$mx" "$T/mx.moved"; ln -s "$T/mx.moved" "$mx"; mx_case "a symbolic link"; unlink "$mx"; mv "$T/mx.moved" "$mx"
    mv "$mx" "$T/mx.moved"; mkdir "$mx"; mx_case "a directory"; rmdir "$mx"; mv "$T/mx.moved" "$mx"
    ST_BEFORE="$(st_kind)"; NR_EXTRA='h_my_uid() { echo 4242; };' new_run; nr_refused "an exclusion file of another user (uid mismatch)" 'exclusion file is unsafe'
    new_run_full; a_eq "positive control: with the file restored the new run works" 0 "$NR_RC"; }
t139() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # the state machine as a table: who may start from which persisted state
    local good st; good="$(st_rec)"
    for st in UNLOCKED RECOVERED ABSENT RUNNING FAILED_LOCKED RECOVERY_IN_PROGRESS PACKAGES_RECOVERED_LOCK_PENDING; do
        if [ "$st" = ABSENT ]; then unlink "$(STP)" 2> /dev/null; else setstate "${good/state=FAILED_LOCKED/state=$st}"; fi
        ST_BEFORE="$(st_kind)"; new_run
        case "$st" in
            UNLOCKED|RECOVERED) a_eq "new run from $st: allowed" 0 "$NR_RC"; a_eq "new run from $st: the child left RUNNING" RUNNING "$(st_name)"; rm -rf "$T"/base/sinter-h-newrun1.* ;;
            ABSENT) nr_refused "new run with the state record MISSING (the environment was initialised)" 'its state record is MISSING' ;;
            *) nr_refused "new run from $st" "$st" ;;
        esac
    done
    setstate "$good"
    for st in UNLOCKED RECOVERED RUNNING RECOVERY_IN_PROGRESS PACKAGES_RECOVERED_LOCK_PENDING; do
        setstate "${good/state=FAILED_LOCKED/state=$st}"; ST_BEFORE="$(st_kind)"; rec_args sinter-t-a:all:1.0; rec_run
        a_eq "recovery from $st: refused" 1 "$(cat "$T/scenario.rc")"; a_eq "recovery from $st: the state is untouched" "$ST_BEFORE" "$(st_kind)"; a_eq "recovery from $st: no purge" 0 "$(rec_dp)"
    done
    unlink "$(STP)"; ST_BEFORE="$(st_kind)"; rec_args sinter-t-a:all:1.0; rec_run
    a_eq "recovery with the state record MISSING: refused" 1 "$(cat "$T/scenario.rc")"; a_true "for that reason" grep -q 'its state record is MISSING' "$T/scenario.out"; a_eq "recovery with the state record MISSING: nothing recreated" ABSENT "$(st_kind)"; a_eq "recovery with the state record MISSING: no purge" 0 "$(rec_dp)"
    setstate "$good"; rec_run; a_eq "recovery from FAILED_LOCKED: the only state that is recovered" 0 "$(cat "$T/scenario.rc")"; }
t140() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # the state file can not be replaced right before the seal (the base directory becomes read-only)
    rec_args sinter-t-a:all:1.0; rec_run H_RF_FAULT=chmod-base-before-seal; chmod 700 "$T/state"
    rec_stopped "the seal can not be written" 1 'could not be sealed as RECOVERED' PACKAGES_RECOVERED_LOCK_PENDING
    a_eq "no temporary state file is left" "" "$(tmps)"
    a_true "the final evidence exists" bash -c "ls \"$EVD\"/recovery.*/recovery-final.tsv > /dev/null"
    ST_BEFORE="$(st_kind)"; new_run; nr_refused "a new run" 'PACKAGES_RECOVERED_LOCK_PENDING'
    rec_run; refused "a rerun does not complete it automatically" 'the state is PACKAGES_RECOVERED_LOCK_PENDING' 1; }
t141() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # SIGKILL after the purge
    kill_case kill-after-purge RECOVERY_IN_PROGRESS purges-done 1; }
t142() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # SIGKILL right before the seal
    kill_case kill-before-seal PACKAGES_RECOVERED_LOCK_PENDING state-pending 1; }
t143() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # SIGKILL right after the seal (the final status was not written)
    kill_case kill-after-seal RECOVERED sealed 1; }
t144() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # the exclusion is held by whoever still has the descriptor: a child that outlives the run keeps new runs out
    rec_args sinter-t-a:all:1.0; rec_run; rec_ok_final "(setup) recovered"
    ( cd "$T" && bash -c "$NR_PRE"'h_init inh1 || exit 3; sleep 60 > /dev/null 2>&1 & echo $! > "$2"; h_baseline; h_finish; exit 0' _ "$HERE/.." "$T/sleeper.pid" ) > "$T/inh.out" 2>&1
    a_eq "the run itself finished cleanly" UNLOCKED "$(st_name)"
    a_true "the exclusion is still held (by the child that inherited the descriptor)" bash -c "! python3 -I -c 'import fcntl,sys
f=open(sys.argv[1],\"rb\")
try:
    fcntl.flock(f, fcntl.LOCK_EX|fcntl.LOCK_NB)
except OSError:
    sys.exit(1)' '$(MXP)'"
    ST_BEFORE="$(st_kind)"; new_run; nr_refused "a new run while the child lives (fail-closed, even though the state is UNLOCKED)" 'BUSY'
    kill "$(cat "$T/sleeper.pid")" 2> /dev/null; sleep 0.3
    new_run_full; a_eq "after the child is gone the new run works" 0 "$NR_RC"; }
t145() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # a failure after the first transition but BEFORE any purge puts the ORIGINAL state back
    rec_args sinter-t-a:all:1.0; rec_run H_RF_FAULT=fail-after-enter
    a_eq "exit status 1" 1 "$(cat "$T/scenario.rc")"; a_true "the injected failure" grep -q 'injected failure after the first transition' "$T/scenario.out"
    a_eq "no purge was issued" 0 "$(rec_dp)"
    a_match "the original state is back (FAILED_LOCKED, seq 4, written by the recovery, same run identity)" '^sinter-state-v5;state=FAILED_LOCKED;seq=4;by=recovery;pid=[0-9]+;run_id=recfix1;uid=[0-9]+;run_dir=/.+;nonce=[0-9a-f]{32};init=[0-9a-f]{32}$' "$(st_rec)"
    a_eq "no temporary state file" "" "$(tmps)"
    rec_run; rec_ok_final "the failed run can simply be recovered again"; }
t146() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # ... and if the original state can NOT be put back, RECOVERY_IN_PROGRESS stays (new runs and recoveries are refused)
    rec_args sinter-t-a:all:1.0; rec_run H_RF_FAULT=fail-after-enter-readonly; chmod 700 "$T/state"
    a_eq "exit status 1" 1 "$(cat "$T/scenario.rc")"; a_eq "no purge was issued" 0 "$(rec_dp)"
    a_eq "the state stays RECOVERY_IN_PROGRESS" RECOVERY_IN_PROGRESS "$(st_name)"
    a_true "the evidence says the original state could not be put back" grep -q 'could not be put back' "$T/scenario.out"
    a_eq "no temporary state file" "" "$(tmps)"
    ST_BEFORE="$(st_kind)"; new_run; nr_refused "a new run" 'RECOVERY_IN_PROGRESS'
    rec_run; refused "a recovery" 'the state is RECOVERY_IN_PROGRESS'; }
t147() { . "$HERE/smoke-tests.sh"; REC_FIX_END=killinit rec_fixture $RA   # SIGKILL right after the run was taken (state RUNNING, no baseline yet)
    a_true "the kernel dropped the exclusion" mx_free; a_true "the run directory has no baseline" test ! -e "$RF_RDIR/snap.base"
    a_match "the record is the RUNNING record of the killed run (seq 1)" '^sinter-state-v5;state=RUNNING;seq=1;by=scenario;pid=[0-9]+;run_id=recfix1;' "$(st_rec)"
    ST_BEFORE="$(st_kind)"; new_run; nr_refused "a new run" 'a previous run did not finish'
    rec_args sinter-t-a:all:1.0; SMOKE_ARGV[${#SMOKE_ARGV[@]}]=--allow-orphan; rec_run; refused "a recovery with --allow-orphan (nothing to base it on)" 'lacks its registry or baseline snapshot'; }
t148() { . "$HERE/smoke-tests.sh"; rec_fixture $RA   # the FINAL evidence can not be saved: the state is NOT sealed (it stays PACKAGES_RECOVERED_LOCK_PENDING)
    rec_args sinter-t-a:all:1.0; rec_run H_RF_FAULT=chmod-before-seal; chmod 700 "$EVD"/recovery.*
    a_eq "exit status 1" 1 "$(cat "$T/scenario.rc")"
    a_true "stopped because the final evidence could not be saved" grep -q 'the final evidence could not be saved and read back: the state is NOT sealed' "$T/scenario.out"
    a_eq "the state is PACKAGES_RECOVERED_LOCK_PENDING (not sealed)" PACKAGES_RECOVERED_LOCK_PENDING "$(st_name)"
    a_false "no final evidence file" bash -c "ls \"$EVD\"/recovery.*/recovery-final.tsv > /dev/null 2>&1"
    ST_BEFORE="$(st_kind)"; new_run; nr_refused "a new run" 'PACKAGES_RECOVERED_LOCK_PENDING'; }
