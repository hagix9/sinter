#!/bin/bash
# run-tests.sh [PATTERN] -- failure-injection tests for lib/safe-lib.sh and the shim templates.
#
# Safety of the tests themselves (see 07-package-manager-isolation.md):
#  * every package-manager command the library may call is a MOCK inside the per-test root ($T/bin);
#  * H_TEST_MODE=1 makes the library abort if any command/dir variable points outside $T;
#  * PATH starts with tripwires named dpkg/dpkg-query/apt/dnf/rpm...: a bare call fails with exit 99 and is logged;
#  * the mock dpkg exits 99 on any --force* option; nothing here mounts, chowns or uses sudo.
# Output: one TSV line per case, then a summary.  Exit status 0 only if every case passed.
HERE="$(cd "$(dirname "$0")" && pwd)"
LIB="$HERE/../lib/safe-lib.sh"
HT_TMP="${HT_TMP:?set HT_TMP to a scratch directory on the external SSD (<EXTERNAL_TMP>/...)}"
PATTERN="${1:-}"
ORIG_PATH="/usr/bin:/bin:/usr/sbin:/sbin"
mkdir -p "$HT_TMP" || exit 2
SUITE="$(mktemp -d "$HT_TMP/suite.XXXXXX")" || exit 2
RESULTS="$SUITE/results.tsv"; : > "$RESULTS"

write_mountinfo() {  # write_mountinfo private|shared|master|empty|garbage|noroot -> $T/ns/mountinfo (the kernel's /proc/self/mountinfo format)
    case "$1" in
        private) printf '%s\n' '22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw' '23 22 0:5 / /proc rw,nosuid - proc proc rw' > "$T/ns/mountinfo" ;;
        shared)  printf '%s\n' '22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw' '23 22 0:5 / /proc rw,nosuid - proc proc rw' > "$T/ns/mountinfo" ;;
        shared2) printf '%s\n' '22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw' '23 22 0:5 / /proc rw,nosuid shared:7 - proc proc rw' > "$T/ns/mountinfo" ;;
        master)  printf '%s\n' '22 1 8:1 / / rw,relatime master:2 - ext4 /dev/sda1 rw' > "$T/ns/mountinfo" ;;
        unbind)  printf '%s\n' '22 1 8:1 / / rw,relatime unbindable - ext4 /dev/sda1 rw' > "$T/ns/mountinfo" ;;
        empty)   : > "$T/ns/mountinfo" ;;
        garbage) printf 'this is not a mount table\n' > "$T/ns/mountinfo" ;;
        noroot)  printf '%s\n' '23 22 0:5 / /proc rw,nosuid - proc proc rw' > "$T/ns/mountinfo" ;;
    esac
}
mock_ns_tools() {  # sudo / unshare / env stand-ins: they run the rest of the command line; no mount namespace is created
    cat > "$T/bin/sudo-mock" << 'EOF'
#!/bin/sh
[ -n "$MOCK_SUDO_FAIL" ] && { echo "sudo-mock: injected failure" >&2; exit 1; }
while [ $# -gt 0 ]; do case "$1" in -n) shift ;; -u) shift 2 ;; *) break ;; esac; done
exec "$@"
EOF
    cat > "$T/bin/unshare-mock" << 'EOF'
#!/bin/sh
[ -n "$MOCK_UNSHARE_FAIL" ] && { echo "unshare-mock: injected failure" >&2; exit 1; }
while [ $# -gt 0 ] && [ "$1" != -- ]; do shift; done
shift
exec "$@"
EOF
    printf '#!/bin/sh\nexec /usr/bin/env "$@"\n' > "$T/bin/env-mock"
    chmod 755 "$T/bin/sudo-mock" "$T/bin/unshare-mock" "$T/bin/env-mock"
}

# ---------------------------------------------------------------- per-test environment
setup() {  # setup NPKGS -> fresh isolated root; sources the library; no real tool is reachable
    T="$(mktemp -d "$SUITE/t.XXXXXX")"; chmod 700 "$T"
    mkdir -p "$T/base" "$T/flags" "$T/pk" "$T/bin" "$T/tripwire" "$T/out"
    chmod 700 "$T/base"; chmod 755 "$T/flags"
    cp "$HERE/mock/mock-pm.py" "$T/bin/"; cp "$HERE/mock/tripwire/"* "$T/tripwire/"
    for tool in dpkg dpkg-query dpkg-deb; do printf '#!/bin/sh\nexec python3 -I "%s/bin/mock-pm.py" %s "$@"\n' "$T" "$tool" > "$T/bin/$tool"; chmod 755 "$T/bin/$tool"; done
    export MOCK_DB="$T/db.json" MOCK_LOG="$T/mock.log" MOCK_TRIPWIRE_LOG="$T/tripwire.log"
    : > "$MOCK_LOG"; : > "$MOCK_TRIPWIRE_LOG"
    unset MOCK_P_WRITE MOCK_P_FOREIGN MOCK_I_VER MOCK_PROPAGATION MOCK_Q_MODE MOCK_P_FAIL_ON MOCK_P_ALSO MOCK_P_DRY_EXTRA MOCK_ALLOW_ESS MOCK_STALE MOCK_P_DRY_EMPTY MOCK_P_DRY_VER MOCK_P_DRY_TWICE MOCK_P_DRY_WARN MOCK_P_DRY_ODD
    export PATH="$T/tripwire:$ORIG_PATH"
    export H_TEST_MODE=1 H_TEST_ROOT="$T" H_BASE="$T/base" H_STATE_DIR="$T/state" H_FLAGDIR="$T/flags/flags"
    mkdir -p "$T/state"; chmod 700 "$T/state"
    export H_DPKG="$T/bin/dpkg" H_DPKG_QUERY="$T/bin/dpkg-query" H_DPKG_DEB="$T/bin/dpkg-deb" H_FINDMNT="$T/bin/findmnt-none"
    export H_DPKG_TARGET="$T/target/dpkg" H_DPKGQ_TARGET="$T/target/dpkg-query" H_MOUNT="$T/bin/mount" H_UMOUNT="$T/bin/umount" H_STDBUF="$T/bin/stdbuf-mock"
    mkdir -p "$T/ns" "$T/pid1root"; ln -sfn 'mnt:[4026531001]' "$T/ns/self"; ln -sfn 'mnt:[4026531000]' "$T/ns/pid1"
    write_mountinfo private
    mock_ns_tools
    export H_BUILD_KIND=test H_NS_SELF_LINK="$T/ns/self" H_NS_PID1_LINK="$T/ns/pid1" H_PID1_ROOT="$T/pid1root" H_MOUNTINFO="$T/ns/mountinfo"
    export H_SUDO_BIN="$T/bin/sudo-mock" H_UNSHARE_BIN="$T/bin/unshare-mock" H_ENV_BIN="$T/bin/env-mock"
    export H_MIN_PKGS=3 H_PK="$T/pk"
    H_SUDO=(); H_WRAPPER_PATHS=(); H_PAYLOAD_ALLOW=(); H_REG=(); H_ARMED=()
    FAILED=0; OUT="$T/out"
    # shellcheck disable=SC1090
    . "$HERE/../lib/nscheck.sh"
    . "$LIB"
    record() { printf '%s\t%s\t%s\n' "$1" "$2" "$3" >> "$T/records.tsv"; [ "$2" = "$3" ] || FAILED=1; }
    note() { printf '%s\n' "$*" >> "$T/notes.txt"; }
    mkdb "${1:-12}"
    env_init     # every case starts in an environment that was initialised EXPLICITLY (a missing record is never "fresh")
}
env_reset_state() {  # env_reset_state -> a human removed the whole state directory and initialised again (test helper)
    rm -rf "$T/state"; mkdir -p "$T/state"; chmod 700 "$T/state"; H_MUTEX_HELD=0; env_init
}
env_init() {  # env_init -> the state directory with mutex, init record and the initial UNLOCKED state, through the production function
    h_env_paths; h_env_initialize; local rc=$?
    [ "$rc" = 0 ] || { echo "SETUP FAILED: the test environment could not be initialised ($H_ENV_MSG)" >&2; exit 99; }
}
mkdb() {  # a fake host: N filler packages + the names the incident destroyed
    python3 -I - "$MOCK_DB" "$1" << 'PYEOF'
import json, sys
db = {"pkgs": [], "foreign": []}
real = [("bash", "5.2", "yes"), ("dpkg", "1.22.6", "yes"), ("libc6", "2.39", "yes"), ("grep", "3.11", "yes"), ("coreutils", "9.4", "yes"), ("apt", "2.7.14", "no"), ("chrony", "4.5", "no"), ("openssh-server", "9.6", "no")]
for n, v, e in real:
    db["pkgs"].append({"name": n, "arch": "amd64", "ver": v, "ess": e, "abbr": "ii "})
for i in range(int(sys.argv[2])):
    db["pkgs"].append({"name": "realpkg%03d" % i, "arch": "amd64", "ver": "1.%d" % i, "ess": "", "abbr": "ii "})
json.dump(db, open(sys.argv[1], "w"))
PYEOF
}
mkdeb() {  # mkdeb NAME ARCH [STATE] [ESSENTIAL] [noallow] -> fixture "deb" + allowlist entry
    local n="$1" a="$2" st="${3:-ii }" es="${4:-}" f
    f="$H_PK/${n}_1.0_${a}.deb"
    printf 'Package: %s\nArchitecture: %s\nVersion: 1.0\nMaintainer: Sinter Test <test@example.invalid>\nEssential: %s\nState: %s\n' "$n" "$a" "$es" "$st" > "$f"
    [ "${5:-}" = noallow ] || H_PAYLOAD_ALLOW[${#H_PAYLOAD_ALLOW[@]}]="$n:$a"
}
start_run() { h_init "t-$$-$RANDOM" && h_baseline; }

# ---------------------------------------------------------------- assertions (recorded in the subshell)
A_FAIL=0
pass() { printf 'ASSERT\tPASS\t%s\n' "$1" >> "$T/asserts.tsv"; }
fail() { printf 'ASSERT\tFAIL\t%s\n' "$1" >> "$T/asserts.tsv"; A_FAIL=1; }
a_eq() { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (want [$2] got [$3])"; fi; }
a_true() { local d="$1"; shift; if "$@"; then pass "$d"; else fail "$d"; fi; }
a_false() { local d="$1"; shift; if "$@"; then fail "$d"; else pass "$d"; fi; }
n_purge() { grep -c $'^dpkg\t.*--purge ' "$MOCK_LOG" 2> /dev/null | tr -d ' ' ; }       # all purge calls (also dry-run)
n_real_purge() { grep $'^dpkg\t' "$MOCK_LOG" | grep -- '--purge ' | grep -vc -- '--dry-run' | tr -d ' '; }
n_install() { grep $'^dpkg\t' "$MOCK_LOG" | grep -c $'\t-i ' | tr -d ' '; }
log_has_real_name() { grep $'^dpkg\t' "$MOCK_LOG" | grep -E -- '--(purge|remove)' | grep -Eq -- '(^|[ :])(bash|dpkg|libc6|grep|coreutils|apt|chrony|openssh-server|realpkg[0-9]+)([ :]|$)'; }
log_has_force() { grep -q -- '--force' "$MOCK_LOG"; }
no_tripwire() { [ ! -s "$MOCK_TRIPWIRE_LOG" ]; }
db_names() { python3 -I -c 'import json,sys; print(" ".join(sorted("%s:%s"%(r["name"],r["arch"]) for r in json.load(open(sys.argv[1]))["pkgs"])))' "$MOCK_DB"; }
purged_list() { python3 -I -c 'import json,sys; print(" ".join(json.load(open(sys.argv[1])).get("purges",[])))' "$MOCK_DB"; }
db_mutate() {  # db_mutate PYTHON-STATEMENTS on variable db
    python3 -I - "$MOCK_DB" "$1" << 'PYEOF'
import json, sys
db = json.load(open(sys.argv[1]))
exec(sys.argv[2])
json.dump(db, open(sys.argv[1], "w"))
PYEOF
}

# ---------------------------------------------------------------- case runner
CASE_N=0; CASE_FAIL=0
run_case() {  # run_case ID DESCRIPTION FUNCTION
    local id="$1" desc="$2" fn="$3" rc res
    if [ -n "$PATTERN" ]; then   # PATTERN: space-separated globs
        local p hit=0
        for p in $PATTERN; do [[ "$id" == $p ]] && hit=1; done
        [ "$hit" = 1 ] || return 0
    fi
    CASE_N=$((CASE_N + 1))
    (
        local np=12; { [ "$fn" = t29 ] || [ "$fn" = t49b ]; } && np=60
        setup "$np"
        echo "$T" > "$SUITE/last-T"
        "$fn"
        [ -f "$T/asserts.tsv" ] || { echo "no assertion was made"; exit 3; }
        exit "$A_FAIL"
    ) > "$SUITE/case.out" 2>&1
    rc=$?
    # the asserts file lives in the case's T; find the newest one
    local af; af="$(cat "$SUITE/last-T")/asserts.tsv"
    local na np nf; na=0; np=0; nf=0
    if [ -f "$af" ]; then na=$(wc -l < "$af" | tr -d ' '); np=$(grep -c $'\tPASS\t' "$af"); nf=$(grep -c $'\tFAIL\t' "$af"); fi
    if [ "$rc" = 0 ] && [ "$na" -gt 0 ] && [ "$nf" = 0 ]; then res=PASS; else res=FAIL; CASE_FAIL=$((CASE_FAIL + 1)); fi
    printf '%s\t%s\t%s\tasserts=%s pass=%s fail=%s\n' "$id" "$res" "$desc" "$na" "$np" "$nf" | tee -a "$RESULTS"
    if [ "$res" = FAIL ]; then grep $'\tFAIL\t' "$af" 2> /dev/null | sed 's/^/    /'; head -5 "$SUITE/case.out" | sed 's/^/    out: /'; fi
    mkdir -p "$SUITE/keep"; cp -R "$(dirname "$af")" "$SUITE/keep/$id" 2> /dev/null
    return 0
}

# ================================================================ cases
t01() {  # one test package, normal path
    mkdeb sinter-t-leaf-a all; start_run
    h_install_deb sinter-t-leaf-a_1.0_all.deb
    a_eq "installed" "sinter-t-leaf-a:all" "$(db_names | tr ' ' '\n' | grep sinter-t | tr '\n' ' ' | sed 's/ $//')"
    h_cleanup; a_eq "cleanup ok" ok "$H_CLEANUP_STATUS"
    a_eq "purged exactly the test package" "sinter-t-leaf-a:all" "$(purged_list)"
    a_false "no real name in a purge/remove command" log_has_real_name
    a_false "no force option" log_has_force; a_true "no tripwire" no_tripwire
}
t02() {  # several packages incl. Multi-Arch, reverse order
    mkdeb sinter-t-base all; mkdeb sinter-t-ma amd64; mkdeb sinter-t-ma i386; start_run
    h_install_deb sinter-t-base_1.0_all.deb; h_install_deb sinter-t-ma_1.0_amd64.deb; h_install_deb sinter-t-ma_1.0_i386.deb
    h_cleanup; a_eq "cleanup ok" ok "$H_CLEANUP_STATUS"
    a_eq "purge order is the reverse of the installs" "sinter-t-ma:i386 sinter-t-ma:amd64 sinter-t-base:all" "$(purged_list)"
    a_false "no real name" log_has_real_name; a_true "no tripwire" no_tripwire
}
t03() {  # empty allowlist
    mkdeb sinter-t-leaf-a all "ii " "" noallow; start_run
    h_install_deb sinter-t-leaf-a_1.0_all.deb; a_eq "install refused" 1 "$H_ABORTED"
    a_eq "no dpkg -i was issued" 0 "$(n_install)"
    h_cleanup; a_eq "nothing purged" 0 "$(n_real_purge)"
}
t04() {  # a real package name is mixed in
    mkdeb sinter-t-leaf-a all; start_run
    cp "$H_PK/sinter-t-leaf-a_1.0_all.deb" "$H_PK/bash_1.0_amd64.deb"
    H_PAYLOAD_ALLOW[${#H_PAYLOAD_ALLOW[@]}]="bash:amd64"
    h_install_deb bash_1.0_amd64.deb; a_eq "a real name is refused" 1 "$H_ABORTED"
    a_eq "no dpkg -i" 0 "$(n_install)"
    H_ABORTED=0; h_purge_one "bash:amd64"; a_eq "purge of a real name refused" 1 "$H_ABORTED"
    a_eq "no purge call" 0 "$(n_purge)"
    H_ABORTED=0; _h_register "libc6:amd64" 1.0; a_eq "register refuses a real name" 1 "$H_ABORTED"
    a_true "bash still installed" grep -q 'bash:amd64' <<< "$(db_names)"
}
t05() {  # Essential: a registered package that is Essential, and Essential names in the allowlist
    mkdeb sinter-t-ess all "ii " yes; start_run
    h_install_deb sinter-t-ess_1.0_all.deb; a_eq "a payload that declares Essential is refused (B-2)" 1 "$H_ABORTED"; a_eq "no dpkg -i" 0 "$(n_install)"
    # the host reports a registered package as Essential at cleanup time (state changed behind our back)
    H_ABORTED=0; H_FAILED=0; H_CLEANUP_STATUS=not-run; mkdeb sinter-t-ess2 all; h_install_deb sinter-t-ess2_1.0_all.deb
    db_mutate $'for r in db["pkgs"]:\n    if r["name"] == "sinter-t-ess2": r["ess"] = "yes"'
    h_cleanup; a_eq "cleanup failed" failed "$H_CLEANUP_STATUS"; a_eq "aborted (manual plan)" 1 "$H_ABORTED"
    a_eq "no purge call at all (no force option exists)" 0 "$(n_purge)"
    a_true "the Essential package is still there" grep -q 'sinter-t-ess2:all' <<< "$(db_names)"
    H_ABORTED=0; H_PAYLOAD_ALLOW[${#H_PAYLOAD_ALLOW[@]}]="dpkg:amd64"; _h_register "dpkg:amd64" 1.0; a_eq "allowlisted real Essential name refused" 1 "$H_ABORTED"
}
t06() {  # look-alike names
    mkdeb sinter-t-leaf-a all; start_run
    local n ok=1
    for n in sinter-tx-a sinter-t- sinter-t Sinter-t-a sinter-t-A xsinter-t-a "sinter-t-a b" "sinter-t-a;rm" 'sinter-t-$(id)' 'sinter-t-`id`' sinter-t--a sinter-t-a- ""; do
        h_valid_name "$n" && { ok=0; note "accepted $n"; }
    done
    a_eq "all look-alike names rejected" 1 "$ok"
    cp "$H_PK/sinter-t-leaf-a_1.0_all.deb" "$H_PK/sinter-t-leaf-a2_1.0_all.deb"
    h_install_deb sinter-t-leaf-a2_1.0_all.deb; a_eq "a name that is not in the exact allowlist is refused" 1 "$H_ABORTED"
    a_eq "no dpkg -i" 0 "$(n_install)"
}
t07() {  # duplicates
    mkdeb sinter-t-leaf-a all; H_PAYLOAD_ALLOW[1]="sinter-t-leaf-a:all"; start_run
    h_install_deb sinter-t-leaf-a_1.0_all.deb; h_install_deb sinter-t-leaf-a_1.0_all.deb
    a_eq "one registry entry" 1 "$(wc -l < "$H_REGFILE" | tr -d ' ')"
    h_cleanup; a_eq "cleanup ok" ok "$H_CLEANUP_STATUS"
    a_eq "purged once" 1 "$(n_real_purge)"
}
t08() {  # invalid architecture
    mkdeb sinter-t-a arm64; start_run
    h_install_deb sinter-t-a_1.0_arm64.deb; a_eq "arm64 file refused" 1 "$H_ABORTED"
    H_ABORTED=0; H_PAYLOAD_ALLOW[${#H_PAYLOAD_ALLOW[@]}]="sinter-t-a:s390x"; _h_register "sinter-t-a:s390x" 1.0; a_eq "unknown arch refused at registration" 1 "$H_ABORTED"
    a_eq "no dpkg -i" 0 "$(n_install)"
}
cleanup_with_mode() {  # cleanup_with_mode MODE -> installs one package, breaks dpkg-query, runs the cleanup
    mkdeb sinter-t-leaf-a all; start_run
    h_install_deb sinter-t-leaf-a_1.0_all.deb
    export MOCK_Q_MODE="$1"
    h_cleanup
    unset MOCK_Q_MODE
    a_eq "cleanup failed ($1)" failed "$H_CLEANUP_STATUS"
    a_eq "no purge/remove call was issued ($1)" 0 "$(n_purge)"
    a_true "the test package was left alone ($1)" grep -q 'sinter-t-leaf-a:all' <<< "$(db_names)"
    a_false "no real name ($1)" log_has_real_name; a_true "no tripwire" no_tripwire
}
t09() { cleanup_with_mode rc3; }
t10() { cleanup_with_mode empty; }
t11() { cleanup_with_mode warn; }
t12() {
    cleanup_with_mode truncate
}
t12b() { cleanup_with_mode nonl; }
t12c() { cleanup_with_mode crlf; }
t12d() { cleanup_with_mode nul; }
t12e() { cleanup_with_mode badfield; }
t12f() { cleanup_with_mode garbage; }
t12g() { cleanup_with_mode highbit; }
t13() {  # unsafe base directory (group/world writable without sticky bit) and a symlinked base
    chmod 777 "$H_BASE"; h_init "t13-a"; a_eq "world-writable base without sticky refused" 1 "$H_ABORTED"
    H_ABORTED=0; chmod 700 "$H_BASE"
    mkdir "$T/realbase"; chmod 700 "$T/realbase"; ln -s "$T/realbase" "$T/linkbase"
    H_BASE="$T/linkbase"; export H_BASE; h_init "t13-b"; a_eq "symlinked base refused" 1 "$H_ABORTED"
    a_eq "no run directory was created through the link" 0 "$(ls "$T/realbase" | wc -l | tr -d ' ')"
}
t14() {  # the run directory is not writable: every call fails closed (no stale temp file, no command output used)
    mkdeb sinter-t-leaf-a all; start_run
    h_install_deb sinter-t-leaf-a_1.0_all.deb
    printf 'install ok installed\tbash\tamd64\n' > "$H_RUNDIR/o.stale"      # a leftover that must never be read
    chmod 500 "$H_RUNDIR"
    h_cleanup; chmod 700 "$H_RUNDIR"
    a_eq "cleanup failed" failed "$H_CLEANUP_STATUS"
    a_eq "no purge call" 0 "$(n_purge)"; a_false "no real name" log_has_real_name
}
t15() {  # concurrent runs: the lock, and another run's packages seen as foreign changes
    mkdeb sinter-t-leaf-a all; start_run
    local base="$H_BASE" lock="$H_LOCKDIR"
    ( H_MUTEX_HELD=0; h_init "t15-second"; echo "$H_ABORTED" > "$T/second.aborted" ) 2> /dev/null
    a_eq "the second run (a second descriptor in another shell) is refused by the exclusion" 1 "$(cat "$T/second.aborted")"
    a_eq "and it left no run directory" "" "$(ls -d "$T"/base/sinter-h-t15-second.* 2> /dev/null)"
    h_install_deb sinter-t-leaf-a_1.0_all.deb
    db_mutate 'db["pkgs"].append({"name":"sinter-t-other-run","arch":"all","ver":"1.0","ess":"","abbr":"ii "})'
    h_cleanup; a_eq "cleanup failed: a foreign package appeared" failed "$H_CLEANUP_STATUS"
    a_eq "nothing was purged (not even the registered one)" 0 "$(n_real_purge)"
    a_true "the other run's package is untouched" grep -q 'sinter-t-other-run:all' <<< "$(db_names)"
}
t16() {  # cleanup fails half-way: stops, no escalation, the run lock stays
    mkdeb sinter-t-a all; mkdeb sinter-t-b all; mkdeb sinter-t-c all; start_run
    h_install_deb sinter-t-a_1.0_all.deb; h_install_deb sinter-t-b_1.0_all.deb; h_install_deb sinter-t-c_1.0_all.deb
    export MOCK_P_FAIL_ON=2
    h_cleanup; h_finish
    a_eq "cleanup failed" failed "$H_CLEANUP_STATUS"; a_eq "the harness is aborted" 1 "$H_ABORTED"
    a_eq "purge stopped after the failing call (2 real purges; finish does not retry)" 2 "$(n_real_purge)"
    a_false "no force option" log_has_force
    a_eq "the state is FAILED_LOCKED" FAILED_LOCKED "$(sed -n 's/^sinter-state-v5;state=\([A-Z_]*\);.*/\1/p' "$H_STATE_PATH")"
    a_eq "and the exclusion was dropped (the state, not the OS lock, refuses the next run)" 0 "$H_MUTEX_HELD"
    H_FINISHED=0; FAILED=0; h_verdict > "$T/verdict.txt"; a_true "verdict says FAIL" grep -q 'SCENARIO: FAIL' "$T/verdict.txt"
}
t17() {  # EXIT trap: a failed cleanup changes the exit status; the scenario's own status is kept separately
    mkdeb sinter-t-leaf-a all
    cat > "$T/scn.sh" << EOF
. "$HERE/../lib/nscheck.sh"
. "$LIB"
H_PAYLOAD_ALLOW=(sinter-t-leaf-a:all)
record() { printf '%s\t%s\t%s\n' "\$1" "\$2" "\$3" >> "$T/scn.records"; [ "\$2" = "\$3" ] || FAILED=1; }
note() { :; }
FAILED=0; OUT="$T/out"
trap h_on_exit EXIT
h_init t17-scn; h_baseline
h_install_deb sinter-t-leaf-a_1.0_all.deb
export MOCK_P_FAIL_ON=1
exit \${SCN_EXIT:-0}
EOF
    SCN_EXIT=0 bash "$T/scn.sh" > "$T/scn.out" 2>&1; local rc0=$?
    a_eq "scenario exits 0 but the cleanup failed -> exit 70" 70 "$rc0"
    a_true "final-status shows cleanup=failed" grep -q $'^cleanup\tfailed' "$T/out/final-status.tsv"
    a_true "final-status keeps the scenario result separately" grep -q $'^scenario_failed\t' "$T/out/final-status.tsv"
    H_TEST_STATE_RESET=1; env_reset_state; mkdb 12     # a human reviewed the failed run and re-initialised the environment
    SCN_EXIT=3 bash "$T/scn.sh" > "$T/scn.out" 2>&1; local rc3=$?
    a_eq "a scenario failure exit code is kept" 3 "$rc3"
    a_false "no real name" log_has_real_name
}
t17b() {  # the trap itself cannot write its status file
    mkdeb sinter-t-leaf-a all
    cat > "$T/scn.sh" << EOF
. "$HERE/../lib/nscheck.sh"
. "$LIB"
H_PAYLOAD_ALLOW=(sinter-t-leaf-a:all)
record() { printf '%s\t%s\t%s\n' "\$1" "\$2" "\$3" >> "$T/scn.records"; [ "\$2" = "\$3" ] || FAILED=1; }
note() { :; }
FAILED=0; OUT="$T/out-missing-dir"
trap h_on_exit EXIT
h_init t17b-scn; h_baseline
h_install_deb sinter-t-leaf-a_1.0_all.deb
exit 0
EOF
    bash "$T/scn.sh" > "$T/scn.out" 2>&1; local rc=$?
    a_eq "cleanup ok and the run dir status is written even if OUT is missing" 0 "$rc"
    a_true "final-status in the run dir" bash -c "ls '$T'/base/sinter-h-t17b-scn.*/final-status.tsv"
}
t17c() {  # SIGTERM during the scenario: the EXIT trap still runs the cleanup and the status is kept
    mkdeb sinter-t-leaf-a all
    cat > "$T/scn.sh" << EOF
. "$HERE/../lib/nscheck.sh"
. "$LIB"
H_PAYLOAD_ALLOW=(sinter-t-leaf-a:all)
record() { printf '%s\t%s\t%s\n' "\$1" "\$2" "\$3" >> "$T/scn.records"; [ "\$2" = "\$3" ] || FAILED=1; }
note() { :; }
FAILED=0; OUT="$T/out"
h_install_traps
h_init t17c-scn; h_baseline
h_install_deb sinter-t-leaf-a_1.0_all.deb
echo ready > "$T/scn.ready"
sleep 30 &
wait
EOF
    bash "$T/scn.sh" > "$T/scn.out" 2>&1 &
    local pid=$! i
    for i in $(seq 1 100); do [ -e "$T/scn.ready" ] && break; sleep 0.1; done
    kill -TERM "$pid"; wait "$pid"; local rc=$?
    a_eq "terminated by SIGTERM: exit status 143" 143 "$rc"
    a_true "the cleanup ran: the test package is gone" bash -c "! grep -q 'sinter-t-leaf-a:all' <<< '$(db_names)'"
    a_true "cleanup=ok was recorded" grep -q $'^cleanup\tok' "$T/out/final-status.tsv"
}
t17d() {  # nothing registered, nothing done: a failed init leaves nothing behind and the lock is released
    cat > "$T/scn.sh" << EOF
. "$HERE/../lib/nscheck.sh"
. "$LIB"
record() { :; }
note() { :; }
FAILED=0; OUT="$T/out"
h_install_traps
H_TEST_MODE=0
H_BASE="$T/does-not-exist"
h_init t17d-scn
exit 0
EOF
    bash "$T/scn.sh" > "$T/scn.out" 2>&1; local rc=$?
    a_eq "an aborted init is reported (exit 70)" 70 "$rc"
    a_true "final status says cleanup=ok because nothing was done" grep -q $'^cleanup\tok' "$T/out/final-status.tsv"
    a_true "and aborted=1" grep -q $'^aborted\t1' "$T/out/final-status.tsv"
}
t18() {  # half-configured / reinstreq
    mkdeb sinter-t-half all "iF "; start_run
    h_install_deb sinter-t-half_1.0_all.deb
    h_cleanup; a_eq "half-configured is configured, then purged normally" ok "$H_CLEANUP_STATUS"
    a_eq "one plain purge" 1 "$(n_real_purge)"; a_false "no force" log_has_force
    a_true "configure ran first, for the registered package only" bash -c "grep -q $'^dpkg\\t.*--configure sinter-t-half' '$MOCK_LOG'"
}
t18b() {  # reinstreq: a reviewed plan is required, no force option exists
    mkdeb sinter-t-reinst all "iHR"; start_run
    h_install_deb sinter-t-reinst_1.0_all.deb
    h_cleanup; a_eq "reinstreq needs a reviewed plan -> failed" failed "$H_CLEANUP_STATUS"
    a_eq "no purge issued" 0 "$(n_purge)"; a_false "no force" log_has_force
}
t19() {  # the tool removes more than asked
    mkdeb sinter-t-leaf-a all; start_run
    h_install_deb sinter-t-leaf-a_1.0_all.deb
    export MOCK_P_ALSO=chrony
    h_cleanup; a_eq "cleanup failed" failed "$H_CLEANUP_STATUS"
    a_true "the discrepancy is reported" grep -q 'differs from the baseline' "$T/notes.txt" "$T/records.tsv"
    a_eq "the verdict is not PASS" 1 "$(FAILED=0; h_verdict > /dev/null; echo $?)"
}
t20() {  # the whole listing comes back for a one-package query
    mkdeb sinter-t-leaf-a all; start_run
    h_install_deb sinter-t-leaf-a_1.0_all.deb
    export MOCK_Q_MODE=all
    h_cleanup; unset MOCK_Q_MODE
    a_eq "cleanup failed" failed "$H_CLEANUP_STATUS"; a_eq "no purge" 0 "$(n_purge)"; a_false "no real name" log_has_real_name
}
t21() {  # too many candidates
    export H_MAX_PKGS=2
    mkdeb sinter-t-a all; mkdeb sinter-t-b all; mkdeb sinter-t-c all; start_run
    h_install_deb sinter-t-a_1.0_all.deb; h_install_deb sinter-t-b_1.0_all.deb
    h_install_deb sinter-t-c_1.0_all.deb; a_eq "the third registration aborts" 1 "$H_ABORTED"
    a_eq "no third dpkg -i" 2 "$(n_install)"
}
t22() {  # stale files from an earlier run are never used
    mkdeb sinter-t-leaf-a all; start_run
    h_install_deb sinter-t-leaf-a_1.0_all.deb
    cp "$H_RUNDIR/snap.base" "$H_RUNDIR/snap.cur"; printf 'ii \tbash\tamd64\t5.2\tyes\n' >> "$H_RUNDIR/snap.cur"
    export MOCK_Q_MODE=rc3; h_cleanup; unset MOCK_Q_MODE
    a_eq "cleanup failed (the stale snapshot was not used)" failed "$H_CLEANUP_STATUS"; a_eq "no purge" 0 "$(n_purge)"
    : > "$H_RUNDIR/final-status.tsv.old"
    h_cleanup; a_eq "after a failed cleanup the harness stays aborted: a retry with a healthy tool purges nothing" 0 "$(n_real_purge)"
    a_eq "and it is still reported as failed" failed "$H_CLEANUP_STATUS"
}
t23() {  # disk full (file size limit): the writer is stopped, the library fails closed
    mkdeb sinter-t-leaf-a all; start_run
    h_install_deb sinter-t-leaf-a_1.0_all.deb
    ( ulimit -f 2; export MOCK_Q_MODE=bigerr; h_cleanup; echo "$H_CLEANUP_STATUS" > "$T/dfull.status"; echo "$(n_purge)" > "$T/dfull.purges" ) > /dev/null 2>&1
    a_eq "cleanup failed under a write limit" failed "$(cat "$T/dfull.status" 2> /dev/null)"
    a_eq "no purge under a write limit" 0 "$(cat "$T/dfull.purges" 2> /dev/null)"
}
t24() {  # symlinks: payload file, flag directory
    mkdeb sinter-t-leaf-a all; start_run
    mv "$H_PK/sinter-t-leaf-a_1.0_all.deb" "$T/elsewhere.deb"; ln -s "$T/elsewhere.deb" "$H_PK/sinter-t-leaf-a_1.0_all.deb"
    h_install_deb sinter-t-leaf-a_1.0_all.deb; a_eq "a symlinked payload file is refused" 1 "$H_ABORTED"
    a_eq "no dpkg -i" 0 "$(n_install)"
    H_ABORTED=0; mkdir -p "$T/realflags"; chmod 755 "$T/realflags"; rm -rf "$T/flags"; ln -s "$T/realflags" "$T/flags"; H_FLAGDIR="$T/flags"
    h_arm sinter-t-leaf-a; a_eq "a symlinked flag directory is refused" 1 "$H_ABORTED"
    a_eq "no flag was created through the link" 0 "$(ls "$T/realflags" | wc -l | tr -d ' ')"
}
t25() {  # hostile characters
    mkdeb sinter-t-leaf-a all; start_run
    local bad f ok=1
    for bad in $'sinter-t-a\nb' 'sinter-t-a b' 'sinter-t-a$(id)' 'sinter-t-a;x' $'sinter-t-a\tb' 'sinter-t-a|x' "sinter-t-a'x" 'sinter-t-ä'; do
        h_valid_name "$bad" && { ok=0; note "accepted [$bad]"; }
        h_valid_spec "$bad:all" && { ok=0; }
    done
    a_eq "hostile names rejected" 1 "$ok"
    h_install_deb $'sinter-t-leaf-a_1.0_all.deb\nextra'; a_eq "newline in a file name refused" 1 "$H_ABORTED"
    H_ABORTED=0; h_install_deb "../sinter-t-leaf-a_1.0_all.deb"; a_eq "path traversal refused" 1 "$H_ABORTED"
    a_eq "no dpkg -i" 0 "$(n_install)"
}
t26() {  # the 2026-10-24 incident, replayed
    mkdeb sinter-t-ma amd64; start_run
    h_install_deb sinter-t-ma_1.0_amd64.deb
    # (a) what the OLD cleanup did with a stale/wrong listing: it handed everything to dpkg --purge --force-remove-essential
    old_sa_clean() {
        local names; names="$("$H_DPKG_QUERY" -W -f='${Package}:${Architecture}\n' 'sinter-t-*' 2> /dev/null | sort -u)"
        [ -n "$names" ] && "$H_DPKG" --purge --force-remove-essential --force-remove-reinstreq $names > /dev/null 2>&1
        return 0
    }
    export MOCK_Q_MODE=all     # the wrong listing: every package of the host
    old_sa_clean
    a_true "(old code) the replay reaches dpkg --purge with real package names" log_has_real_name
    a_true "(old code) and with a force option" log_has_force
    cp "$MOCK_LOG" "$T/replay-old-cleanup.mock.log"       # kept as evidence: what the OLD cleanup logic issued against the mocks
    # (b) the new library under the same condition issues nothing
    : > "$MOCK_LOG"
    h_cleanup
    a_eq "(new code) cleanup failed" failed "$H_CLEANUP_STATUS"
    a_eq "(new code) NO purge/remove command at all" 0 "$(n_purge)"
    a_false "(new code) no command with a real package name" log_has_real_name
    a_false "(new code) no force option" log_has_force
    unset MOCK_Q_MODE
    MOCK_Q_MODE=stale h_cleanup
    a_eq "(new code, stale output) still no purge" 0 "$(n_purge)"
}
t27() {  # a wrapper is still mounted
    mkdeb sinter-t-leaf-a all; start_run
    h_install_deb sinter-t-leaf-a_1.0_all.deb
    cp "$T/bin/dpkg" "$T/bin/dpkg-wrapper"; printf '# SINTER-HARNESS-SHIM\n' >> "$T/bin/dpkg-wrapper"
    H_DPKG="$T/bin/dpkg-wrapper"
    h_cleanup; a_eq "cleanup refuses to run through a wrapper" failed "$H_CLEANUP_STATUS"; a_eq "no purge" 0 "$(n_purge)"
    H_ABORTED=0; H_DPKG="$T/bin/dpkg"; H_DPKG_QUERY="$T/bin/dpkg-query"
    cp "$T/bin/dpkg-query" "$T/bin/dpkg-query-wrapper"; printf '# SINTER-HARNESS-SHIM\n' >> "$T/bin/dpkg-query-wrapper"
    H_DPKG_QUERY="$T/bin/dpkg-query-wrapper"; h_cleanup; a_eq "also for the query program" failed "$H_CLEANUP_STATUS"
}
t28() {  # leftover test packages before the run: reported, not removed
    db_mutate 'db["pkgs"].append({"name":"sinter-t-old","arch":"all","ver":"1.0","ess":"","abbr":"ii "})'
    mkdeb sinter-t-leaf-a all; h_init "t28-run"; h_baseline
    a_eq "the run aborts at the baseline" 1 "$H_ABORTED"
    h_cleanup; a_eq "nothing purged, the leftover stays" 0 "$(n_purge)"
    a_true "leftover still there" grep -q 'sinter-t-old:all' <<< "$(db_names)"
}
t29() {  # the package set shrinks between baseline and cleanup
    export H_MIN_PKGS=3
    mkdeb sinter-t-leaf-a all; start_run
    h_install_deb sinter-t-leaf-a_1.0_all.deb
    db_mutate 'db["pkgs"] = [r for r in db["pkgs"] if not r["name"].startswith("realpkg05") and not r["name"].startswith("realpkg04") and not r["name"].startswith("realpkg03")]'
    h_cleanup; a_eq "cleanup failed" failed "$H_CLEANUP_STATUS"; a_eq "no purge" 0 "$(n_purge)"
}
t30() {  # a non-test package changed
    mkdeb sinter-t-leaf-a all; start_run
    h_install_deb sinter-t-leaf-a_1.0_all.deb
    db_mutate 'db["pkgs"][5]["ver"] = "9.9-changed"'
    h_cleanup; a_eq "cleanup failed" failed "$H_CLEANUP_STATUS"; a_eq "no purge" 0 "$(n_purge)"
}
t31() {  # failure flags
    mkdeb sinter-t-leaf-a all; start_run
    h_arm sinter-t-leaf-a; a_true "flag exists" test -e "$H_FLAGDIR/sinter-t-leaf-a"
    h_arm 'bash'; a_eq "a non-test name cannot be armed" 1 "$H_ABORTED"
    a_false "no flag for bash" test -e "$H_FLAGDIR/bash"
    H_ABORTED=0
    h_install_deb sinter-t-leaf-a_1.0_all.deb; h_cleanup
    a_false "the flag is removed by the cleanup" test -e "$H_FLAGDIR/sinter-t-leaf-a"
    a_eq "cleanup ok" ok "$H_CLEANUP_STATUS"
}
t32() {  # selections only for registered packages
    mkdeb sinter-t-leaf-a all; start_run
    h_install_deb sinter-t-leaf-a_1.0_all.deb
    h_restore_selection "sinter-t-leaf-a:all"; a_eq "ok for a registered package" 0 "$H_ABORTED"
    h_restore_selection "bash:amd64"; a_eq "refused for a real package" 1 "$H_ABORTED"
    h_cleanup
}
t33() {  # the payload does not contain what its name says
    mkdeb sinter-t-leaf-a all; start_run
    printf 'Package: bash\nArchitecture: amd64\nVersion: 1.0\n' > "$H_PK/sinter-t-leaf-a_1.0_all.deb"
    h_install_deb sinter-t-leaf-a_1.0_all.deb; a_eq "mismatching payload refused" 1 "$H_ABORTED"
    a_eq "no dpkg -i" 0 "$(n_install)"
}
t34() {  # isolation: the library refuses to run against anything outside the test root
    export H_DPKG="/usr/bin/dpkg"; h_init "t34-run"; a_eq "a real dpkg path is refused in test mode" 1 "$H_ABORTED"
    a_eq "no mock was even called" 0 "$(wc -l < "$MOCK_LOG" | tr -d ' ')"
    a_true "no tripwire" no_tripwire
}
t35() {  # a successful run still needs a clean cleanup for PASS
    mkdeb sinter-t-leaf-a all; start_run
    h_install_deb sinter-t-leaf-a_1.0_all.deb
    h_finish
    a_eq "cleanup ok" ok "$H_CLEANUP_STATUS"
    a_eq "the state is UNLOCKED after a clean cleanup" UNLOCKED "$(sed -n 's/^sinter-state-v5;state=\([A-Z_]*\);.*/\1/p' "$H_STATE_PATH")"
    FAILED=0; h_verdict > "$T/v.txt"; a_true "PASS printed" grep -q 'SCENARIO: PASS' "$T/v.txt"
}
t36() {  # purge dry-run lists another package
    mkdeb sinter-t-leaf-a all; start_run
    h_install_deb sinter-t-leaf-a_1.0_all.deb
    export MOCK_P_DRY_EXTRA=chrony
    h_cleanup; a_eq "cleanup failed" failed "$H_CLEANUP_STATUS"; a_eq "aborted" 1 "$H_ABORTED"
    a_eq "no real purge" 0 "$(n_real_purge)"
}
t37() {  # the shim templates (written in the next step) -- placeholder replaced by shim tests when present
    if [ -f "$HERE/shim-tests.sh" ]; then . "$HERE/shim-tests.sh"; shim_tests; else fail "shim tests file missing"; fi
}
t39() { . "$HERE/smoke-tests.sh"; smoke_case sa3; }
t40() { . "$HERE/smoke-tests.sh"; smoke_case multiarch; }
t39b() { . "$HERE/smoke-tests.sh"; smoke_case stageb1; }
t39c() { . "$HERE/smoke-tests.sh"; smoke_case stageb2; }
t41() { . "$HERE/smoke-tests.sh"; lint_coverage; }
t42() {  # an architecture that was already configured is never removed by the run
    db_mutate 'db["foreign"] = ["i386"]'
    mkdeb sinter-t-ma i386; start_run
    h_add_arch i386; a_eq "nothing was added" "" "$H_ADDED_ARCH"
    h_install_deb sinter-t-ma_1.0_i386.deb
    h_finish
    a_eq "cleanup ok" ok "$H_CLEANUP_STATUS"
    a_eq "i386 is still configured" "i386" "$(python3 -I -c 'import json,sys; print(" ".join(json.load(open(sys.argv[1]))["foreign"]))' "$MOCK_DB")"
    a_eq "no --remove-architecture was issued" 0 "$(grep -c -- '--remove-architecture' "$MOCK_LOG" | tr -d ' ')"
}
t43() {  # the architecture the run added is removed at the end, only when no package of it remains
    mkdeb sinter-t-ma i386; start_run
    h_add_arch i386; a_eq "added by this run" i386 "$H_ADDED_ARCH"
    h_install_deb sinter-t-ma_1.0_i386.deb
    h_cleanup; a_eq "a per-case cleanup keeps the architecture" i386 "$(python3 -I -c 'import json,sys; print(" ".join(json.load(open(sys.argv[1]))["foreign"]))' "$MOCK_DB")"
    h_install_deb sinter-t-ma_1.0_i386.deb
    h_finish; a_eq "final cleanup ok" ok "$H_CLEANUP_STATUS"
    a_eq "the added architecture is gone again" "" "$(python3 -I -c 'import json,sys; print(" ".join(json.load(open(sys.argv[1]))["foreign"]))' "$MOCK_DB")"
}
t44() {  # a package of the added architecture that the run did not register blocks the removal (and the cleanup)
    mkdeb sinter-t-ma i386; start_run
    h_add_arch i386
    db_mutate 'db["pkgs"].append({"name":"foreign-lib","arch":"i386","ver":"1.0","ess":"","abbr":"ii "})'
    h_finish; a_eq "cleanup failed (a foreign package appeared)" failed "$H_CLEANUP_STATUS"
    a_eq "i386 is still configured" "i386" "$(python3 -I -c 'import json,sys; print(" ".join(json.load(open(sys.argv[1]))["foreign"]))' "$MOCK_DB")"
    a_eq "no --remove-architecture was issued" 0 "$(grep -c -- '--remove-architecture' "$MOCK_LOG" | tr -d ' ')"
}
t45() {  # validators one by one (every check must be necessary on its own)
    local long49 long48
    long49="sinter-t-$(printf 'a%.0s' $(seq 1 40))"; long48="sinter-t-$(printf 'a%.0s' $(seq 1 39))"
    a_false "a 49-character name is refused" h_valid_name "$long49"
    a_true "a 48-character name is accepted" h_valid_name "$long48"
    local s
    for s in "sinter-t-a" "sinter-t-a:" ":all" "sinter-t-a:all:x" "" "sinter-t-a:arm64" "bash:amd64"; do a_false "spec [$s] is refused" h_valid_spec "$s"; done
    a_true "sinter-t-a:all is accepted" h_valid_spec "sinter-t-a:all"
    tf() { printf "$1" > "$T/f.txt"; h_text_ok "$T/f.txt"; }
    a_true "plain text with tabs" tf 'abc\tdef\n'
    a_true "an empty file is clean text" tf ''
    a_false "a NUL byte" tf 'ab\000cd\n'
    a_false "a carriage return" tf 'ab\r\n'
    a_false "a vertical tab" tf 'ab\vcd\n'
    a_false "a form feed" tf 'ab\fcd\n'
    a_false "an escape character" tf 'ab\033cd\n'
    a_false "a non-ASCII byte" tf 'ab\303\274cd\n'
    a_false "a missing final newline" tf 'abc'
    ln -s "$T/f.txt" "$T/f.link"; a_false "a symlink" h_text_ok "$T/f.link"
    a_false "a missing file" h_text_ok "$T/none.txt"
}
snap_with_mode() {  # snap_with_mode MODE [MIN] -> return status of h_snapshot under a dpkg-query fault mode
    mkdeb sinter-t-leaf-a all; start_run
    export MOCK_Q_MODE="$1"; H_MIN_PKGS="${2:-3}"
    h_snapshot probe; local rc=$?
    unset MOCK_Q_MODE; return $rc
}
t46() {  # snapshot and single-package query: each rule on its own
    mkdeb sinter-t-leaf-a all; mkdeb sinter-t-leaf-b all; start_run
    h_install_deb sinter-t-leaf-a_1.0_all.deb
    export MOCK_Q_MODE=ok; a_true "baseline: a healthy listing is accepted" h_snapshot probe0
    export MOCK_Q_MODE=rc1-with-data; a_false "valid data but exit status 1 (snapshot)" h_snapshot p1
    export MOCK_Q_MODE=warn;          a_false "valid data but a warning on stderr (snapshot)" h_snapshot p2
    export MOCK_Q_MODE=nonl;          a_false "valid data without the final newline (snapshot; the last record would be lost)" h_snapshot p3
    export MOCK_Q_MODE=dup;           a_false "a duplicated record (snapshot)" h_snapshot p4
    export MOCK_Q_MODE=empty; H_MIN_PKGS=0; a_false "an empty answer even where no minimum applies" h_snapshot p5
    export MOCK_Q_MODE=garbage; H_MIN_PKGS=0; a_false "garbage even where no minimum applies (records are validated)" h_snapshot p6
    export MOCK_Q_MODE=ok; H_MIN_PKGS=1000; a_false "a valid but too short listing" h_snapshot p7
    H_MIN_PKGS=3
    export MOCK_Q_MODE=ok
    a_true "baseline: the single query works" h_query_pkg sinter-t-leaf-a all
    a_eq "an installed package" "ii " "$H_PSTATE"
    h_query_pkg sinter-t-leaf-b all; a_eq "an absent package" absent "$H_PSTATE"
    export MOCK_Q_MODE=rc1-with-data; a_false "valid data but exit status 1 (query)" h_query_pkg sinter-t-leaf-a all
    export MOCK_Q_MODE=warn;          a_false "valid data but a warning (query)" h_query_pkg sinter-t-leaf-a all
    export MOCK_Q_MODE=rc1other;      a_false "exit 1 with another message is not 'absent' (query)" h_query_pkg sinter-t-leaf-b all
    export MOCK_Q_MODE=rc3;           a_false "exit 3 (query)" h_query_pkg sinter-t-leaf-b all
    unset MOCK_Q_MODE
}
t47() {  # stale files that look like old fixed names or old snapshots never influence a result
    mkdeb sinter-t-leaf-a all; start_run
    h_snapshot ref; cp "$H_RUNDIR/snap.ref" "$T/ref.copy"
    printf 'ii \tbash\tamd64\t5.2\tyes\n' > "$H_RUNDIR/o.fixed"; printf 'warning\n' > "$H_RUNDIR/e.fixed"; chmod 444 "$H_RUNDIR/o.fixed" "$H_RUNDIR/e.fixed"
    a_true "a read-only o.fixed/e.fixed does not stop or taint a snapshot" h_snapshot probe
    a_true "and the result is the real listing" cmp -s "$H_RUNDIR/snap.probe" "$T/ref.copy"
    printf 'ii \tbash\tamd64\t9.9\tyes\n' > "$H_RUNDIR/snap.cur"; chmod 444 "$H_RUNDIR/snap.cur"
    h_install_deb sinter-t-leaf-a_1.0_all.deb
    h_cleanup; a_eq "the cleanup works around a stale read-only snap.cur" ok "$H_CLEANUP_STATUS"
    a_true "snap.cur holds the real listing of that moment" bash -c "grep -q 'bash' '$H_RUNDIR/snap.cur' && ! grep -q '9.9' '$H_RUNDIR/snap.cur'"
}
t48() {  # direct calls of the guarded entry points with something this run never registered
    mkdeb sinter-t-leaf-a all; start_run
    h_configure_one "bash:amd64"; a_eq "configure of a real package is refused" 1 "$H_ABORTED"
    a_eq "no --configure call" 0 "$(grep -c -- '--configure' "$MOCK_LOG" | tr -d ' ')"
    H_ABORTED=0; . "$HERE/../lib/captures.sh"; OUT="$T/out"; mkdir -p "$OUT/logs"
    h_capture_remove x bash:amd64; a_eq "capture of a real package is refused" 1 "$H_ABORTED"
    a_eq "no --remove call" 0 "$(grep $'^dpkg\t' "$MOCK_LOG" | grep -c -- '--remove')"
    H_ABORTED=0; h_capture_remove x sinter-t-leaf-a:all; a_eq "capture of an allowlisted but unregistered package is refused" 1 "$H_ABORTED"
    H_ABORTED=0; H_FAILED=0; FAILED=0; H_CLEANUP_STATUS=failed; h_verdict > "$T/v.txt"; a_true "verdict FAIL for cleanup=failed alone" grep -q 'SCENARIO: FAIL' "$T/v.txt"
    H_CLEANUP_STATUS=ok; h_verdict > "$T/v.txt"; a_true "verdict PASS only with everything ok" grep -q 'SCENARIO: PASS' "$T/v.txt"
}
t49() {  # white-box: the plan maximum, constructed (the registry limit normally stops earlier)
    mkdeb sinter-t-a all; mkdeb sinter-t-b all; mkdeb sinter-t-c all; start_run
    h_install_deb sinter-t-a_1.0_all.deb; h_install_deb sinter-t-b_1.0_all.deb; h_install_deb sinter-t-c_1.0_all.deb
    H_MAX_PKGS=2; h_cleanup; a_eq "a plan larger than the maximum is refused" failed "$H_CLEANUP_STATUS"; a_eq "nothing purged" 0 "$(n_purge)"
}
t49b() {  # white-box: the shrink guard on its own (records the harness treats as its own disappear)
    mkdeb sinter-t-a all; start_run
    printf 'realpkg000\tamd64\nrealpkg001\tamd64\nrealpkg002\tamd64\nrealpkg003\tamd64\nrealpkg004\tamd64\n' >> "$H_REGFILE"
    h_install_deb sinter-t-a_1.0_all.deb
    db_mutate 'db["pkgs"] = [r for r in db["pkgs"] if r["name"] not in ("realpkg000","realpkg001","realpkg002","realpkg003","realpkg004")]'
    h_cleanup; a_eq "a shrinking package set stops the cleanup on its own" failed "$H_CLEANUP_STATUS"
    a_eq "nothing purged" 0 "$(n_purge)"
    a_true "with the shrink message" grep -q 'shrank' "$T/records.tsv"
}
t50() {  # a purge that exits non-zero although the package is gone
    mkdeb sinter-t-a all; start_run
    h_install_deb sinter-t-a_1.0_all.deb
    export MOCK_P_RC_AFTER_REMOVE=1; h_cleanup; unset MOCK_P_RC_AFTER_REMOVE
    a_eq "a purge that exits non-zero fails the cleanup even if the package is gone" failed "$H_CLEANUP_STATUS"
}
t50b() {  # a failing configure
    mkdeb sinter-t-half all "iF "; start_run
    h_install_deb sinter-t-half_1.0_all.deb
    export MOCK_C_FAIL=1; h_cleanup; unset MOCK_C_FAIL
    a_eq "a failing configure fails the cleanup (no purge is tried instead)" failed "$H_CLEANUP_STATUS"; a_eq "no purge" 0 "$(n_real_purge)"
}
t50c() {  # the foreign architectures changed during the run
    mkdeb sinter-t-a all; start_run
    h_install_deb sinter-t-a_1.0_all.deb
    db_mutate 'db["foreign"] = ["arm64"]'
    h_finish; a_eq "a foreign architecture that changed during the run fails the final cleanup" failed "$H_CLEANUP_STATUS"
}
t50e() {  # a registered package without any baseline: the cleanup has nothing to compare with and must fail
    mkdeb sinter-t-a all; h_init "t50e-run"
    _h_register sinter-t-a:all 1.0
    h_cleanup; a_eq "registered but no baseline: the cleanup fails (it is not a no-op)" failed "$H_CLEANUP_STATUS"
}
t50d() {  # installing before the baseline exists
    mkdeb sinter-t-a all; h_init "t50d-run"
    h_install_deb sinter-t-a_1.0_all.deb; a_eq "install before the baseline is refused" 1 "$H_ABORTED"; a_eq "no dpkg -i" 0 "$(n_install)"
    H_ABORTED=0; h_cleanup; a_eq "a cleanup of a run that registered nothing is a no-op" ok "$H_CLEANUP_STATUS"
}
# ---------------------------------------------------------------- v2 cases (B-2 identity, B-4 dry-run, B-1 registration)
t51() {  # B-2: the public registration is gone; direct calls fail loudly and register nothing
    mkdeb sinter-t-a all; start_run
    h_register sinter-t-a:all; a_eq "a direct h_register aborts the harness" 1 "$H_ABORTED"
    a_eq "and registers nothing" 0 "${#H_REG[@]}"
    H_ABORTED=0; h_purge_one sinter-t-a:all; a_eq "a purge of something that was never installed through the library is refused" 1 "$H_ABORTED"
    a_eq "no purge command" 0 "$(n_purge)"
    H_ABORTED=0; _h_register sinter-t-b:all 1.0; a_eq "even the internal registration checks the allowlist" 1 "$H_ABORTED"
}
t52() {  # B-2: a package that exists before this run installs it is not adopted
    mkdeb sinter-t-a all; start_run
    db_mutate 'db["pkgs"].append({"name": "sinter-t-a", "arch": "all", "ver": "1.0", "ess": "", "abbr": "ii "})'
    h_install_deb sinter-t-a_1.0_all.deb; a_eq "install refused: the package existed before" 1 "$H_ABORTED"
    a_eq "no dpkg -i" 0 "$(n_install)"; a_eq "not registered" 0 "${#H_REG[@]}"
    h_cleanup; a_eq "nothing purged (it is not ours)" 0 "$(n_real_purge)"
}
t53() {  # B-2: the version found at purge time must be the registered one
    mkdeb sinter-t-a all; start_run
    h_install_deb sinter-t-a_1.0_all.deb
    db_mutate 'for r in db["pkgs"]:
    if r["name"] == "sinter-t-a": r["ver"] = "2.5"'
    h_cleanup; a_eq "cleanup failed" failed "$H_CLEANUP_STATUS"; a_eq "aborted" 1 "$H_ABORTED"
    a_eq "no purge command (not the package this run installed)" 0 "$(n_purge)"
    H_ABORTED=0; H_CLEANUP_STATUS=not-run; h_purge_one sinter-t-a:all; a_eq "a direct purge_one refuses too" 1 "$H_ABORTED"; a_eq "still no purge" 0 "$(n_purge)"
}
t54() {  # B-4: an empty dry-run is not a success
    mkdeb sinter-t-a all; start_run
    h_install_deb sinter-t-a_1.0_all.deb
    export MOCK_P_DRY_EMPTY=1; h_cleanup; unset MOCK_P_DRY_EMPTY
    a_eq "cleanup failed" failed "$H_CLEANUP_STATUS"; a_eq "aborted" 1 "$H_ABORTED"
    a_eq "no real purge (the dry-run was the only purge call)" 0 "$(n_real_purge)"
    a_true "the package is still installed" grep -q 'sinter-t-a:all' <<< "$(db_names)"
}
dry_anomaly() {  # B-4: the dry-run names the right package with another version / twice / with a warning / with odd lines
    mkdeb sinter-t-a all; start_run
    h_install_deb sinter-t-a_1.0_all.deb
    export "$1"; h_cleanup; unset "${1%%=*}"
    a_eq "$1: cleanup failed" failed "$H_CLEANUP_STATUS"
    a_eq "$1: aborted" 1 "$H_ABORTED"
    a_eq "$1: no real purge" 0 "$(n_real_purge)"
}
t55a() { dry_anomaly MOCK_P_DRY_VER=9.9; }
t55b() { dry_anomaly MOCK_P_DRY_TWICE=1; }
t55c() { dry_anomaly MOCK_P_DRY_WARN=1; }
t55d() { dry_anomaly MOCK_P_DRY_ODD=1; }
t55e() { dry_anomaly MOCK_P_DRY_EXTRA=realpkg000; }
t56() {  # B-2: name/version of the payload file must agree with the .deb fields
    mkdeb sinter-t-a all; start_run
    printf 'Package: sinter-t-a\nArchitecture: all\nVersion: 2.0\nEssential: \nState: ii \n' > "$H_PK/sinter-t-a_1.0_all.deb"
    h_install_deb sinter-t-a_1.0_all.deb; a_eq "version in the name differs from the .deb: refused" 1 "$H_ABORTED"; a_eq "no dpkg -i" 0 "$(n_install)"
    H_ABORTED=0
    printf 'Package: sinter-t-b\nArchitecture: all\nVersion: 1.0\n' > "$H_PK/sinter-t-a_1.0_all.deb"
    h_install_deb sinter-t-a_1.0_all.deb; a_eq "package name differs from the .deb: refused" 1 "$H_ABORTED"; a_eq "still no dpkg -i" 0 "$(n_install)"
}
t57() {  # B-2: dpkg ends up with another version than the payload file says
    mkdeb sinter-t-a all; start_run
    export MOCK_I_VER=7.7; h_install_deb sinter-t-a_1.0_all.deb; unset MOCK_I_VER
    a_eq "the installed version is not the verified payload version: the harness aborts" 1 "$H_ABORTED"
    h_cleanup; a_eq "and the cleanup does not purge it" 0 "$(n_real_purge)"
}
t58() {  # real dpkg: a refused removal leaves "ri " (installed, selected for removal); the cleanup purges it normally
    mkdeb sinter-t-a all; start_run
    h_install_deb sinter-t-a_1.0_all.deb
    db_mutate 'for r in db["pkgs"]:
    if r["name"] == "sinter-t-a": r["abbr"] = "ri "'
    h_cleanup; a_eq "cleanup ok from the selected-for-removal state" ok "$H_CLEANUP_STATUS"
    a_eq "purged exactly the test package" "sinter-t-a:all" "$(purged_list)"
}
t59() {  # states that are not purged without a reviewed plan
    mkdeb sinter-t-a all "hi "; start_run
    h_install_deb sinter-t-a_1.0_all.deb
    h_cleanup; a_eq "a held package: the cleanup stops" failed "$H_CLEANUP_STATUS"; a_eq "no purge" 0 "$(n_real_purge)"
}
t60() {  # real dpkg: a failing postrm leaves "rH " (half-installed); with the flags disarmed the cleanup purges it normally
    mkdeb sinter-t-a all; start_run
    h_install_deb sinter-t-a_1.0_all.deb
    db_mutate 'for r in db["pkgs"]:
    if r["name"] == "sinter-t-a": r["abbr"] = "rH "'
    h_cleanup; a_eq "cleanup ok from the half-installed state" ok "$H_CLEANUP_STATUS"
    a_eq "purged exactly the test package" "sinter-t-a:all" "$(purged_list)"
    a_false "no force option" log_has_force
}
t61() {  # B-2: the same package with two versions is not one registration; a direct purge_one of an Essential package is refused
    mkdeb sinter-t-a all; start_run
    cp "$H_PK/sinter-t-a_1.0_all.deb" "$H_PK/sinter-t-a_1.1_all.deb"
    printf 'Package: sinter-t-a\nArchitecture: all\nVersion: 1.1\nState: ii \n' > "$H_PK/sinter-t-a_1.1_all.deb"
    h_install_deb sinter-t-a_1.0_all.deb; a_eq "first version installs" 0 "$H_ABORTED"
    h_install_deb sinter-t-a_1.1_all.deb; a_eq "a second version of the same package is refused" 1 "$H_ABORTED"
    a_eq "only the first install was issued" 1 "$(n_install)"
    H_ABORTED=0; H_FAILED=0
    db_mutate 'for r in db["pkgs"]:
    if r["name"] == "sinter-t-a": r["ess"] = "yes"'
    h_purge_one sinter-t-a:all; a_eq "a direct purge_one of an Essential package is refused" 1 "$H_ABORTED"
    a_eq "no purge command" 0 "$(n_purge)"
}
t62() {  # B-2: a capture (dpkg --remove) is aimed only at the package this run installed
    mkdeb sinter-t-a all; start_run
    . "$HERE/../lib/captures.sh"; mkdir -p "$T/out/logs"
    h_install_deb sinter-t-a_1.0_all.deb
    db_mutate 'for r in db["pkgs"]:
    if r["name"] == "sinter-t-a": r["ver"] = "4.4"'
    h_capture_remove cap-x sinter-t-a:all; a_eq "a capture of a package with another version is refused" 1 "$H_ABORTED"
    a_eq "no remove command was issued" 0 "$(grep -c -- '--remove' "$MOCK_LOG" | tr -d ' ')"
}
t63() {  # B-2: the cleanup plan is checked as a whole before anything is purged
    mkdeb sinter-t-a all; mkdeb sinter-t-b all; start_run
    h_install_deb sinter-t-a_1.0_all.deb; h_install_deb sinter-t-b_1.0_all.deb
    db_mutate 'for r in db["pkgs"]:
    if r["name"] == "sinter-t-a": r["ver"] = "4.4"'
    h_cleanup; a_eq "the cleanup stops" failed "$H_CLEANUP_STATUS"
    a_eq "and nothing at all was purged (also not the package that was fine)" 0 "$(n_real_purge)"
}
t64() {  # F-1: flags created by the packages' own scripts are removed for registered packages only
    mkdeb sinter-t-a all; start_run
    h_install_deb sinter-t-a_1.0_all.deb
    mkdir -p "$H_FLAGDIR"; : > "$H_FLAGDIR/sinter-t-a.order"; : > "$H_FLAGDIR/sinter-t-a.seen"; : > "$H_FLAGDIR/sinter-t-other.order"
    h_cleanup; a_eq "cleanup ok" ok "$H_CLEANUP_STATUS"
    a_true "the .order flag of the registered package is gone" test ! -e "$H_FLAGDIR/sinter-t-a.order"
    a_true "the .seen flag of the registered package is gone" test ! -e "$H_FLAGDIR/sinter-t-a.seen"
    a_true "the flag of a package this run did not register is left alone" test -e "$H_FLAGDIR/sinter-t-other.order"
}
t65() {  # the cleanup plan is checked as a whole: an Essential package registered FIRST stops everything before the good one is purged
    mkdeb sinter-t-a all; mkdeb sinter-t-b all; start_run
    h_install_deb sinter-t-a_1.0_all.deb; h_install_deb sinter-t-b_1.0_all.deb
    db_mutate 'for r in db["pkgs"]:
    if r["name"] == "sinter-t-a": r["ess"] = "yes"'
    h_cleanup; a_eq "the cleanup stops" failed "$H_CLEANUP_STATUS"
    a_eq "nothing was purged, not even the good package" 0 "$(n_real_purge)"
}
t66() {  # same for an error state (reinstreq flag in the third character)
    mkdeb sinter-t-a all; mkdeb sinter-t-b all; start_run
    h_install_deb sinter-t-a_1.0_all.deb; h_install_deb sinter-t-b_1.0_all.deb
    db_mutate 'for r in db["pkgs"]:
    if r["name"] == "sinter-t-a": r["abbr"] = "iiR"'
    h_cleanup; a_eq "the cleanup stops" failed "$H_CLEANUP_STATUS"
    a_eq "nothing was purged" 0 "$(n_real_purge)"
}
# ---------------------------------------------------------------- F-2: the namespace gate
t70() {  # unit: the kernel-state check
    h_ns_require 2> "$T/err"; a_eq "a private namespace of its own passes" 0 "$?"
    a_eq "and its identity is recorded" "mnt:[4026531001]" "$H_NS_ID"
    a_eq "and init's" "mnt:[4026531000]" "$H_NS_HOST_ID"
    ln -sfn "$(readlink "$H_NS_PID1_LINK")" "$H_NS_SELF_LINK"; h_ns_require 2> "$T/err"; a_eq "the same namespace as init fails" 1 "$?"
    a_true "with a reason" grep -q "shares init" "$T/err"
    ln -sfn 'mnt:[4026531001]' "$H_NS_SELF_LINK"
    rm -f "$H_NS_SELF_LINK"; h_ns_require 2> "$T/err"; a_eq "an unreadable own namespace id fails" 1 "$?"
    ln -sfn 'mnt:[4026531001]' "$H_NS_SELF_LINK"; rm -f "$H_NS_PID1_LINK"; h_ns_require 2> "$T/err"; a_eq "an unreadable init namespace id fails" 1 "$?"
    ln -sfn 'mnt:[4026531000]' "$H_NS_PID1_LINK"
    ln -sfn 'not-a-namespace-id' "$H_NS_SELF_LINK"; h_ns_require 2> "$T/err"; a_eq "an id of an unexpected format fails" 1 "$?"
    ln -sfn 'mnt:[4026531001]' "$H_NS_SELF_LINK"
    h_ns_require 2> "$T/err"; a_eq "and everything is back to normal afterwards (positive control)" 0 "$?"
}
t71() {  # unit: every way the mount table can fail the check
    local m
    for m in shared shared2 master unbind empty garbage noroot; do
        write_mountinfo "$m"; h_ns_require 2> "$T/err"; a_eq "mount table [$m] fails the check" 1 "$?"
    done
    rm -f "$H_MOUNTINFO"; h_ns_require 2> "$T/err"; a_eq "a missing mount table fails" 1 "$?"
    write_mountinfo private; h_ns_require 2> "$T/err"; a_eq "the private table passes again (positive control)" 0 "$?"
}
t72() {  # unit: h_init (before the lock, the baseline and any package operation) runs the gate; a failure leaves nothing behind
    ln -sfn "$(readlink "$H_NS_PID1_LINK")" "$H_NS_SELF_LINK"
    h_init "t72-run"; a_eq "h_init refuses in init's namespace" 1 "$?"
    a_eq "the harness is aborted" 1 "$H_ABORTED"
    a_eq "the state record is still the initial one (nothing was taken)" "UNLOCKED:0" "$(sed -n 's/^sinter-state-v5;state=\([A-Z_]*\);seq=\([0-9]*\);.*/\1:\2/p' "$H_STATE_DIR/sinter-h-state")"
    h_baseline; a_eq "the baseline is refused afterwards" 1 "$?"
    mkdeb sinter-t-a all; h_install_deb sinter-t-a_1.0_all.deb; a_eq "and so is an install" 1 "$?"
    a_eq "no package-manager call at all" 0 "$(grep -cE $'^(dpkg|dpkg-query|dpkg-deb)\t' "$MOCK_LOG" | tr -d ' ')"
    ln -sfn 'mnt:[4026531001]' "$H_NS_SELF_LINK"; write_mountinfo shared; H_ABORTED=0; H_FAILED=0
    h_init "t72-run2"; a_eq "h_init refuses with a shared mount table" 1 "$?"
    a_eq "still no package-manager call" 0 "$(grep -cE $'^(dpkg|dpkg-query|dpkg-deb)\t' "$MOCK_LOG" | tr -d ' ')"
}
t73() {  # unit: the environment guard (each negative check starts from a CLEAN environment, so it can only fail for its own reason)
    ( clean_h_env; H_BUILD_KIND=production; h_env_guard 2> "$T/err" ); a_eq "(positive control) production with a clean environment passes the guard" 0 "$?"
    ( clean_h_env; H_BUILD_KIND=production; export H_FOO=1; h_env_guard 2> "$T/err" ); a_eq "production: a stray H_* variable fails the guard" 1 "$?"
    a_true "naming the variable but not its value" bash -c "grep -q 'H_FOO' '$T/err' && ! grep -q '=1' '$T/err'"
    ( clean_h_env; H_BUILD_KIND=production; export H_TEST_MODE=1; h_env_guard 2> "$T/err" ); a_eq "production: H_TEST_MODE fails the guard" 1 "$?"
    ( clean_h_env; H_BUILD_KIND=production; export H_NS_ENTERED=1; h_env_guard 2> "$T/err" ); a_eq "production: only the re-exec marker is tolerated (and proves nothing)" 0 "$?"
    ( clean_h_env; H_BUILD_KIND=production; export H_NS_ENTERED=1 H_NS_SELF_LINK=/x; h_env_guard 2> "$T/err" ); a_eq "production: an injected namespace source fails the guard" 1 "$?"
    ( clean_h_env; H_BUILD_KIND=test; unset H_TEST_MODE; h_env_guard 2> "$T/err" ); a_eq "a test build refuses to run without H_TEST_MODE=1" 1 "$?"
    ( clean_h_env; H_BUILD_KIND=test; export H_TEST_MODE=1; h_env_guard 2> "$T/err" ); a_eq "a test build with H_TEST_MODE=1 passes the guard" 0 "$?"
    ( unset H_BUILD_KIND; h_production ); a_eq "an unset build kind is production (fail-closed)" 0 "$?"
    ( clean_h_env; H_BUILD_KIND=production; PATH=/nonexistent:/usr/bin; h_gate_env 2> /dev/null; [ "$PATH" = /usr/sbin:/usr/bin:/sbin:/bin ] ); a_eq "production resets PATH to the fixed system path" 0 "$?"
    ( clean_h_env; H_BUILD_KIND=test; export H_TEST_MODE=1; PATH=/nonexistent:/usr/bin; h_gate_env 2> /dev/null; [ "$PATH" = /nonexistent:/usr/bin ] ); a_eq "a test build keeps its PATH (the mocks)" 0 "$?"
    ( H_BUILD_KIND='@BUILD_KIND@'; h_production ); a_eq "an unreplaced placeholder is production (fail-closed)" 0 "$?"
}
t74() {  # unit: production reads the kernel state only from the fixed /proc paths, never from an injected source
    local r
    if [ -e /proc/self/ns/mnt ]; then
        a_true "(skipped: this host has /proc/self/ns/mnt, the production path would read the real kernel state)" true
    else
        ( H_BUILD_KIND=production; h_ns_require 2> "$T/err" ); r=$?
        a_eq "production ignores the injected, perfectly valid fixtures (no /proc here, so it must fail)" 1 "$r"
        a_true "and it failed reading the REAL own-namespace source, not something later" grep -q "this shell's mount namespace id" "$T/err"
    fi
    a_true "the production root-command path is the fixed /usr/bin/sudo (read from the source; sudo is never run here)" grep -q 'then /usr/bin/sudo -n' "$HERE/../lib/nscheck.sh"
}
# --- the gate on assembled scenarios (test build driven through mock sudo/unshare; production build driven on its own)
t75() { . "$HERE/smoke-tests.sh"; gate_prepare test; smoke_run "$GATE_SCRIPT" gate-ok
    a_eq "positive control: with a private namespace the scenario runs" 0 "$(cat "$T/scenario.rc")"
    a_true "positive control: package-manager calls were made" test "$(pm_calls)" -gt 0; }
t76() { . "$HERE/smoke-tests.sh"; gate_prepare test; ln -sfn "$(readlink "$T/ns/pid1")" "$T/ns/self"
    smoke_run "$GATE_SCRIPT" gate-spoof H_NS_ENTERED=1; gate_refused "H_NS_ENTERED=1 in init's namespace"; }
t77() { . "$HERE/smoke-tests.sh"; gate_prepare test; write_mountinfo shared
    smoke_run "$GATE_SCRIPT" gate-shared H_NS_ENTERED=1; gate_refused "shared propagation (marker set)"
    smoke_run "$GATE_SCRIPT" gate-shared2; gate_refused "shared propagation (full entry chain)"; }
t78() { . "$HERE/smoke-tests.sh"; gate_prepare test; write_mountinfo garbage
    smoke_run "$GATE_SCRIPT" gate-unknown; gate_refused "unknown propagation (unparsable table)"
    write_mountinfo empty; smoke_run "$GATE_SCRIPT" gate-unknown2; gate_refused "unknown propagation (empty table)"; }
t79() { . "$HERE/smoke-tests.sh"; gate_prepare test; rm -f "$T/ns/self"
    smoke_run "$GATE_SCRIPT" gate-noid; gate_refused "mount namespace id not obtainable"; }
t80() { . "$HERE/smoke-tests.sh"; gate_prepare test
    smoke_run "$GATE_SCRIPT" gate-unshare MOCK_UNSHARE_FAIL=1; a_true "unshare failure: non-zero exit" test "$(cat "$T/scenario.rc")" -ne 0
    a_eq "unshare failure: no package-manager call" 0 "$(pm_calls)"; a_true "unshare failure: no output directory" test ! -d "$T/ws/out"
    smoke_run "$GATE_SCRIPT" gate-sudo MOCK_SUDO_FAIL=1; a_true "sudo failure: non-zero exit" test "$(cat "$T/scenario.rc")" -ne 0
    a_eq "sudo failure: no package-manager call" 0 "$(pm_calls)"; a_true "sudo failure: no output directory" test ! -d "$T/ws/out"; }
t81() { . "$HERE/smoke-tests.sh"; gate_prepare test
    DROP_ENV=H_TEST_MODE smoke_run "$GATE_SCRIPT" gate-notest; gate_refused "a test build without H_TEST_MODE=1"; }
t82() { . "$HERE/smoke-tests.sh"; gate_prepare production
    smoke_run "$GATE_SCRIPT" gate-prod1 H_NS_ENTERED=1; gate_refused "production build, H_TEST_MODE=1 and every injection variable set"
    a_true "naming the offending variables" grep -q 'H_TEST_MODE' "$T/scenario.out"
    DROP_ENV="H_TEST_MODE H_TEST_ROOT H_BASE H_FLAGDIR H_DPKG H_DPKG_QUERY H_DPKG_DEB H_DPKG_TARGET H_DPKGQ_TARGET H_MOUNT H_UMOUNT H_FINDMNT H_STDBUF H_NS_SELF_LINK H_NS_PID1_LINK H_PID1_ROOT H_MOUNTINFO H_SUDO_BIN H_UNSHARE_BIN H_ENV_BIN H_SUDO_NONE H_OS_RELEASE H_SHA256SUM H_MIN_PKGS" \
        smoke_run "$GATE_SCRIPT" gate-prod2 H_NS_ENTERED=1
    a_eq "production build, only the marker H_NS_ENTERED=1 (a spoof): exit 70" 70 "$(cat "$T/scenario.rc")"
    a_eq "production build, spoofed marker: no package-manager call" 0 "$(pm_calls)"
    a_true "production build, spoofed marker: no output directory" test ! -d "$T/ws/out"
    a_true "production build, spoofed marker: the kernel state decided" grep -q 'SCENARIO GATE FAILED' "$T/scenario.out"; }
t83() {  # the production and the test build differ in the build-kind line only
    . "$HERE/smoke-tests.sh"; smoke_env_setup
    ASSEMBLE_BUILD=production "$HERE/../assemble.sh" "$T/asm-p" > /dev/null 2>&1; ASSEMBLE_BUILD=test "$HERE/../assemble.sh" "$T/asm-t" > /dev/null 2>&1
    sed '/^__PAYLOAD__$/q' "$T/asm-p/scenario-sa3.sh" > "$T/p.code"; sed '/^__PAYLOAD__$/q' "$T/asm-t/scenario-sa3.sh" > "$T/t.code"
    a_eq "exactly one line differs" 1 "$(diff "$T/p.code" "$T/t.code" | grep -c '^<')"
    a_true "it is the build-kind line (production vs test)" bash -c "head -1 '$T/p.code' | grep -qx 'H_BUILD_KIND=production' && head -1 '$T/t.code' | grep -qx 'H_BUILD_KIND=test'"
    ASSEMBLE_BUILD=bogus "$HERE/../assemble.sh" "$T/asm-x" > /dev/null 2>&1; a_eq "an unknown build kind is refused by the assembler" 2 "$?"; }
# ---------------------------------------------------------------- F-1: the recovery tool
clean_h_env() {  # inside a subshell: drop every variable the production guard looks at (the test setup exports many H_*)
    local v; for v in $(compgen -e); do case "$v" in H_*|BASH_ENV|ENV|SHELLOPTS|BASHOPTS|LD_PRELOAD|LD_LIBRARY_PATH|BASH_XTRACEFD|PROMPT_COMMAND) unset "$v" ;; esac; done
}
RA=sinter-t-a_1.0_all.deb; RB=sinter-t-b_1.0_all.deb
t109() {  # production: shell start-up hooks and imported functions can not interfere with the gate
    ( clean_h_env; H_BUILD_KIND=production; export BASH_ENV=/dev/null; h_env_guard 2> "$T/err" ); a_eq "production: BASH_ENV fails the guard" 1 "$?"
    a_true "naming BASH_ENV" grep -q BASH_ENV "$T/err"
    ( clean_h_env; H_BUILD_KIND=production; export LD_PRELOAD=/x; h_env_guard 2> "$T/err" ); a_eq "production: LD_PRELOAD fails the guard" 1 "$?"
    ( clean_h_env; H_BUILD_KIND=production; export SHELLOPTS=xtrace; h_env_guard 2> "$T/err" ); a_eq "production: SHELLOPTS fails the guard" 1 "$?"
    printf '%s\n' 'H_BUILD_KIND=production' "$(sed -n 2p "$HERE/../lib/buildkind.sh")" 'declare -F readlink > /dev/null && echo FUNCTION-SURVIVED || echo function-gone' > "$T/frag.sh"
    a_eq "production: a function imported from the environment is removed before anything runs" function-gone "$(readlink() { :; }; export -f readlink; bash "$T/frag.sh" 2>&1 | tail -1)"
    printf '%s\n' 'H_BUILD_KIND=test' "$(sed -n 2p "$HERE/../lib/buildkind.sh")" 'declare -F readlink > /dev/null && echo FUNCTION-SURVIVED || echo function-gone' > "$T/frag.sh"
    a_eq "(positive control) a test build leaves it alone" FUNCTION-SURVIVED "$(readlink() { :; }; export -f readlink; bash "$T/frag.sh" 2>&1 | tail -1)"; }
t38() {  # lint
    if [ -x "$HERE/../lint-harness.sh" ]; then
        "$HERE/../lint-harness.sh" "$(cd "$HERE/.." && pwd)" > "$T/lint.out" 2>&1; a_eq "lint passes on the harness" 0 "$?"
        mkdir -p "$T/badharness"; printf 'dpkg --purge --force-remove-essential $names\nrm -rf "$X"\nmount --bind /usr/bin/dpkg /tmp/x\nfor n in $(dpkg-query -W); do dpkg --purge $n; done\n' > "$T/badharness/body.sh"
        "$HERE/../lint-harness.sh" "$T/badharness" > "$T/lint-bad.out" 2>&1; a_true "lint rejects a bad sample" test $? -ne 0
    else fail "lint-harness.sh missing"; fi
}

. "$HERE/recovery-tests.sh"
. "$HERE/init-tests.sh"
for c in t01:"one test package" t02:"several packages incl. Multi-Arch" t03:"empty allowlist" t04:"real package name mixed in" t05:"Essential" \
         t06:"look-alike names" t07:"duplicates" t08:"invalid architecture" t09:"dpkg-query exit status non-zero" t10:"stdout empty" \
         t11:"stderr warning" t12:"truncated output" t12b:"missing final newline" t12c:"CRLF" t12d:"NUL byte" t12e:"malformed record" \
         t12f:"garbage output" t12g:"non-ASCII output" t13:"unsafe/symlinked base directory" t14:"run dir not writable + stale file" \
         t15:"concurrent runs" t16:"cleanup fails half-way" t17:"EXIT trap failure handling" t17b:"status file unwritable" t17c:"SIGTERM runs the cleanup" t17d:"aborted init leaves nothing" \
         t18:"half-configured" t18b:"reinstreq" t19:"unexpected state change" t20:"whole listing returned" t21:"candidates over the maximum" \
         t22:"old logs/snapshots" t23:"disk full" t24:"symlinks" t25:"hostile characters" t26:"incident replay" t27:"wrapper still mounted" \
         t28:"leftover test packages" t29:"package set shrinks" t30:"non-test package changed" t31:"failure flags" t32:"selections" \
         t33:"payload/name mismatch" t34:"test isolation" t35:"clean run needs clean cleanup" t36:"purge dry-run names another package" \
         t45:"validators one by one" t46:"snapshot/query rules one by one" t47:"stale files" t48:"guarded entry points" t49:"plan maximum (white-box)" t49b:"shrink guard (white-box)" t50:"purge exit status" t50b:"configure failure" t50c:"foreign architecture drift" t50d:"install before baseline" t50e:"registered without baseline" t42:"pre-existing architecture kept" t43:"added architecture removed at the end" t44:"foreign package blocks the removal" t51:"direct registration refused" t52:"pre-existing package not adopted" t53:"version mismatch at purge" t54:"empty dry-run" t55a:"dry-run: another version" t55b:"dry-run: target twice" t55c:"dry-run: stderr warning" t55d:"dry-run: odd line" t55e:"dry-run: another package" t56:"payload name/version/fields" t57:"post-install identity" t58:"ri state purged normally" t59:"held package not purged" t60:"rH state purged normally" t61:"two versions / Essential purge_one" t62:"capture identity" t63:"plan checked as a whole" t64:"leftover flags of registered packages" t65:"Essential registered first" t66:"error state registered first" t37:"shim templates" t70:"gate: kernel-state check" t71:"gate: mount tables" t72:"gate: h_init" t73:"gate: environment guard" t74:"gate: production sources" t75:"gate e2e: normal" t76:"gate e2e: marker spoof" t77:"gate e2e: shared propagation" t78:"gate e2e: unknown propagation" t79:"gate e2e: ns id failure" t80:"gate e2e: unshare/sudo failure" t81:"gate e2e: test build without test mode" t82:"gate e2e: production build" t83:"production vs test build" t90:"recovery: normal" t91:"recovery: purge failure" t92:"recovery: target remains" t93:"recovery: unnamed package" t94:"recovery: other package drift" t95:"recovery: version mismatch" t96:"recovery: Essential" t97:"recovery: audit fails" t98:"recovery: audit reports" t99:"recovery: database mismatch" t100:"recovery: wrapper mount" t101:"recovery: evidence" t102:"recovery: state identity" t103:"recovery: seal fault" t104:"recovery: first-transition fault" t105:"recovery: arguments" t106:"recovery: states" t107:"recovery: environment" t108:"recovery: foreign architecture" t109:"gate: startup hooks / imported functions" t110:"recovery: target not in registry" t111:"recovery: Maintainer" t112:"recovery: later target state" t113:"recovery: foreign record during recovery" t114:"recovery: foreign arch changes" t115:"recovery: state names another run dir" t116:"recovery: record changes during recovery" t117:"swap before first transition" t118:"new run during recovery" t119:"new run before the seal" t120:"SIGKILL after first transition" t121:"SIGKILL before first transition" t122:"final status not saved after seal" t123:"recovery: concurrency" t124:"recovery: old-format locks" t125:"lock v4: library lifecycle" t126:"lock v4: failed run keeps record" t127:"audit: command failures" t128:"audit: known report" t129:"audit: unexpected reports" t130:"audit: consistency" t131:"recovery: evidence and exclusion faults" t132:"lock v4: failures reported as failures" t133:"live scenario vs recovery and second run" t134:"six simultaneous takers x3" t135:"SIGKILLed scenario (orphan)" t136:"damaged state file" t137:"stale temporary file" t138:"exclusion file tampering" t139:"state machine table" t140:"seal blocked by read-only base" t141:"SIGKILL after purge" t142:"SIGKILL before seal" t143:"SIGKILL after seal" t144:"inherited descriptor keeps the exclusion" t145:"failure before any purge restores the state" t146:"restore fails: stays RECOVERY_IN_PROGRESS" t147:"SIGKILL right after the run was taken" t148:"final evidence not saved: not sealed" t149:"fresh environment: a run does not initialise" t150:"explicit initialisation" t151:"initialisation is idempotent" t152:"SIGKILL during initialisation" t153:"write failure during initialisation" t154:"damaged init record" t155:"init record missing" t156:"state record MISSING" t157:"exclusion file missing" t158:"exclusion file and state missing" t159:"empty state directory" t160:"record permissions and ownership" t161:"state inode replaced" t162:"base directory clean-up" t163:"state directory lost after a failed run" t164:"reboot equivalent" t165:"R3 location still holds a state" t166:"unsafe state directory" t167:"initialisation vs run and recovery" t168:"two simultaneous initialisations" t169:"SIGKILL during the state replace" t170:"clean-host evidence for the initialisation" t171:"production build of the initialisation tool" t172:"library initialisation is idempotent and never writes over unknown" t173:"second init in the same process keeps the first lock" t38:"lint" t39:"SA-3 scenario end to end against mocks" t40:"Multi-Arch scenario end to end against mocks" t41:"lint rule coverage" t39b:"Stage B1 scenario against mocks" t39c:"Stage B2 scenario against mocks"; do
    run_case "${c%%:*}" "${c#*:}" "${c%%:*}"
done
echo "----"
echo "cases=$CASE_N failed=$CASE_FAIL suite=$SUITE"
AP=0; AF=0
for d in "$SUITE"/keep/*; do [ -f "$d/asserts.tsv" ] && { AP=$((AP + $(grep -c $'\tPASS\t' "$d/asserts.tsv"))); AF=$((AF + $(grep -c $'\tFAIL\t' "$d/asserts.tsv"))); }; done
echo "assertions: pass=$AP fail=$AF"
echo "tripwire hits: $(cat "$SUITE"/keep/*/tripwire.log 2> /dev/null | wc -l | tr -d ' ')"
[ "$CASE_FAIL" = 0 ] && [ "$AF" = 0 ]
