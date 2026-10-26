#!/bin/bash
# lint-harness.sh [DIR] -- static safety lint of the harness (lib/, sa3/, multiarch/, build scripts).
# Exit 0 only if no rule is violated; exit 2 if nothing could be scanned (never a silent "OK").
# Comment lines are ignored (so rules can be explained in comments).  Paths may contain spaces.
# The rules exist because of the 2026-10-24 ubuntu24 incident; each is a pattern the old harness contained.
ROOT="${1:-$(cd "$(dirname "$0")" && pwd)}"
SELF="$(basename "$0")"
bad=0
FILES=()
while IFS= read -r -d '' f; do FILES[${#FILES[@]}]="$f"; done < <(find "$ROOT" -type f \( -name '*.sh' -o -name '*.py' -o -name '*.in' \) ! -path "$ROOT/tests/*" ! -name "$SELF" -print0 | sort -z)
[ "${#FILES[@]}" -gt 0 ] || { echo "lint: no harness files under $ROOT"; exit 2; }
viol() { echo "LINT-VIOLATION [$1] $2"; bad=1; }
scan() {  # scan RULE REGEX [ALLOWED-FILE-REGEX]
    local rule="$1" re="$2" allow="${3:-^\$}" f hits h
    for f in "${FILES[@]}"; do
        if [[ "$f" =~ $allow ]]; then continue; fi
        hits="$(awk '!/^[[:space:]]*#/ { print FNR "\t" $0 }' "$f" 2> /dev/null | grep -E -- "$re")"
        if [ "${PIPESTATUS[0]}" != 0 ] && [ -z "$hits" ]; then :; fi
        if [ -n "$hits" ]; then
            while IFS= read -r h; do viol "$rule" "${f#"$ROOT"/}:$(printf '%s' "$h" | cut -c1-200)"; done <<< "$hits"
        fi
    done
}
# every file must be readable by awk (a file that can not be scanned is a failure, not a pass)
for f in "${FILES[@]}"; do
    awk 'END{}' "$f" > /dev/null 2>&1 || viol "R00-unreadable" "${f#"$ROOT"/}"
done
scan R01-force-options        '--force|--nodeps|--noscripts|--allmatches|--no-act-force'
scan R02-removal-outside-lib  '(dpkg|\$H_DPKG|\$REAL[A-Z]*|"\$REAL")[^|;&#]*[[:space:]](--purge|--remove([[:space:]"]|$)|-P[[:space:]]|-r[[:space:]])' '/lib/(safe-lib|captures)\.sh$'
scan R03-package-manager-cli  '(^|[[:space:];&|(])(apt-get|apt|aptitude|dnf|yum|rpm|zypper)[[:space:]]+(remove|purge|autoremove|erase|-e[[:space:]]|install|upgrade|dist-upgrade)'
scan R04-listing-fed-to-removal '(for [a-z_]+ in [^;]*(dpkg-query|dpkg -l|apt-cache|rpm -qa)|names="\$\(|\$names|xargs[^|]*(dpkg|apt|rpm))'
scan R05-rm-recursive         '(^|[[:space:];&|(])rm[[:space:]]+(-[a-zA-Z]*[rR][a-zA-Z]*)([[:space:]]|$)'
scan R06-bind-mount-outside-shims '(^|[[:space:];&|(])mount[[:space:]]+(--bind|-o[[:space:]]+bind|--rbind)' '/lib/shims\.sh$'
scan R07-world-writable       'chmod[[:space:]]+(-R[[:space:]]+)?(0?777|a\+w|o\+w|666|0?666)'
scan R08-eval                 '(^|[[:space:];&|(])eval[[:space:]]'
scan R09-absolute-pm-path     '/usr/(s?bin)/(dpkg|dpkg-query|dpkg-deb|apt|apt-get|dnf|rpm)([^a-zA-Z_-]|$)' '/lib/(safe-lib|shims)\.sh$'
scan R10-raw-sudo             '(^|[[:space:];&|(])sudo[[:space:]]' '(/common\.sh|/lib/safe-lib\.sh)$'
scan R11-set-selections       'set-selections' '/lib/(safe-lib|captures)\.sh$'
scan R12-fixed-tmp-name       '(>>?|tee)[[:space:]]+"?(/tmp|/var/tmp)/[A-Za-z0-9._-]+"?([[:space:]]|$)'
scan R13-find-delete          'find[[:space:]].*(-delete|-exec[[:space:]]+rm)'
scan R14-unquoted-expansion-to-removal '(--purge|--remove)[[:space:]]+\$[A-Za-z_{(]'
scan R17-root-owned-capture-dir '\[ -[efdrs] "\$capdir'
scan R18-gate-skip '(H_NS_ENTERED|H_TEST_MODE|H_BUILD_KIND)' '(/lib/(nscheck|safe-lib|buildkind)\.sh|/assemble\.sh)$'
scan R16-direct-registration  '(^|[[:space:];&|(])_?h_register([[:space:]]|$)' '/lib/safe-lib\.sh$'
cnt="$(awk '!/^[[:space:]]*#/' "$ROOT/lib/safe-lib.sh" 2> /dev/null | grep -c -- '--purge')"
if [ "$cnt" -gt 3 ]; then viol "R15-purge-sites" "safe-lib.sh has $cnt lines with --purge (expected: the dry-run, the real purge, and the target computation only)"; fi
if [ "$bad" = 0 ]; then echo "lint: OK (${#FILES[@]} files)"; fi
exit "$bad"
