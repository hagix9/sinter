#!/bin/bash
# collect-stats.sh SUITE_DIR -- facts about what the mocks saw during one run of run-tests.sh (the evidence that no real
# package manager was called and that no removal command ever named a package outside the test packages).
S="${1:?SUITE_DIR}"
K="$S/keep"
cases=$(ls "$K" | wc -l | tr -d ' ')
echo "cases with artifacts: $cases"
echo "assertions: pass=$(cat "$K"/*/asserts.tsv | grep -c $'\tPASS\t') fail=$(cat "$K"/*/asserts.tsv | grep -c $'\tFAIL\t')"
echo "tripwire log lines (a real package manager name was called by bare name): $(cat "$K"/*/tripwire.log 2> /dev/null | wc -l | tr -d ' ')"
echo "mock invocations in total: $(cat "$K"/*/mock.log | wc -l | tr -d ' ')"
echo "by tool:"; cat "$K"/*/mock.log | cut -f1 | sort | uniq -c | sed 's/^/  /'
echo "dpkg sub-commands (first argument):"; cat "$K"/*/mock.log | awk -F'\t' '$1 == "dpkg" { n = split($3, a, " "); k = a[1]; if (k ~ /^--refuse/) { k = "(capture) " a[4] }; print k }' | sort | uniq -c | sort -rn | sed 's/^/  /'
echo "lines with a force-style option in the logs of the NEW code (all cases): $(cat "$K"/*/mock.log | grep -c -- '--force')"
echo "  in the replay of the OLD cleanup logic (t26, kept separately; the mock refused it with exit 99): $(grep -c -- '--force' "$K/t26/replay-old-cleanup.mock.log" 2> /dev/null)"
RM='[[:space:]]--(purge|remove)[[:space:]]'
REAL='[[:space:]:](bash|dpkg|libc6|grep|coreutils|apt|chrony|openssh-server|realpkg[0-9]+)([[:space:]:]|$)'
allrm() { for d in "$K"/*; do [ "$(basename "$d")" = t26 ] && continue; grep $'^dpkg\t' "$d/mock.log" | grep -E -- "$RM"; done; }
echo "purge/remove commands issued by the NEW code in all cases except the t26 replay: $(allrm | wc -l | tr -d ' ')  (positive control: this number must not be 0)"
echo "  of which with a target that is not a test package (sinter-t-…): $(allrm | grep -vcE -- '[[:space:]](sinter-t-[a-z0-9-]+(:[a-z0-9]+)?)([[:space:]]|$)')"
echo "  of which naming a real package (bash, dpkg, libc6, grep, coreutils, apt, chrony, openssh-server, realpkgNNN): $(allrm | grep -cE -- "$REAL")"
echo "t26 replay of the OLD cleanup logic against the mock: $(grep $'^dpkg\t' "$K/t26/replay-old-cleanup.mock.log" 2> /dev/null | grep -cE -- "$RM") purge command(s), $(grep $'^dpkg\t' "$K/t26/replay-old-cleanup.mock.log" 2> /dev/null | grep -E -- "$RM" | grep -cE -- "$REAL") of them naming a real package (positive control)"
echo "t26 NEW code under the same condition (after the replay): $(grep $'^dpkg\t' "$K/t26/mock.log" | grep -cE -- "$RM") purge/remove commands"
