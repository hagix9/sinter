# =====================================================================================
# Stage B2: three synthetic packages (base <- app, leaf-a) on a real dpkg: dependency order, dpkg's own refusal of a
# removal that would break a dependent, reverse-order cleanup.  Two rounds:
#   round 1: after the refused removal the package is left in the state "ri " (selected for removal); the library's
#            cleanup must purge it normally (no selection restore, no force option);
#   round 2: the selection is restored with `dpkg --set-selections` (registered packages only) before the cleanup.
# Own run id / dir / allowlist / baseline / cleanup / verdict.
# =====================================================================================
H_PAYLOAD_ALLOW=(sinter-t-base:all sinter-t-app:all sinter-t-leaf-a:all)
h_install_traps
h_init "stageb2-$(date -u +%m%d%H%M)" || exit 70
h_baseline || exit 70
note "Stage B2 run $H_RUN_ID; baseline packages: $(h_snap_count base)"
cp "$H_RUNDIR/snap.base" "$OUT/snap-base.tsv" 2> /dev/null || h_fail "evidence:snap-base" "cannot save the baseline"
yn() { if "$@"; then echo yes; else echo no; fi; }
has_line() { grep -qxF -- "$2" "$OUT/logs/$1.err"; }
same() { if h_compare_full "$2" "$3"; then record "$1" unchanged unchanged; else record "$1" unchanged "changed: ${H_DIFF:-?}"; fi; }

b2_round() {  # b2_round N restore|keep
    local r="$1" mode="$2"
    h_install_deb sinter-t-base_1.0_all.deb; record "B2.$r:install-base" 0 "$?"
    h_install_deb sinter-t-app_1.0_all.deb;  record "B2.$r:install-app" 0 "$?"
    h_install_deb sinter-t-leaf-a_1.0_all.deb; record "B2.$r:install-leaf-a" 0 "$?"
    snapc "r$r-after-install"
    nonreg_same "B2.$r:no-other-package-changed-by-the-installs" base "r$r-after-install"
    # dpkg's own refusal (--refuse-depends): the removal of base while app is installed
    h_capture_remove "b2-$r-dep" sinter-t-base:all
    record "B2.$r:dependency-removal-refused-rc-nonzero" yes "$([ "$(cat "$OUT/logs/b2-$r-dep.rc")" != 0 ] && echo yes || echo no)"
    record "B2.$r:dependency-refusal-first-line" yes "$(yn has_line "b2-$r-dep" "dpkg: dependency problems prevent removal of sinter-t-base:")"
    record "B2.$r:no-Removing-line" yes "$(grep -q '^Removing ' "$OUT/logs/b2-$r-dep.out" && echo no || echo yes)"
    snapc "r$r-after-refusal"
    h_query_pkg sinter-t-base all
    record "B2.$r:state-after-the-refused-removal" "ri " "$H_PSTATE"   # real dpkg changes the SELECTION before the dependency check
    nonreg_same "B2.$r:the-refusal-changed-no-other-package" "r$r-after-install" "r$r-after-refusal"
    if [ "$mode" = restore ]; then
        h_restore_selection sinter-t-base:all sinter-t-app:all; record "B2.$r:selection-restored" 0 "$?"
        h_query_pkg sinter-t-base all
        record "B2.$r:state-after-the-selection-restore" "ii " "$H_PSTATE"
        snapc "r$r-after-restore"
        same "B2.$r:the-restore-returned-the-host-to-the-installed-state" "r$r-after-install" "r$r-after-restore"
    fi
    cleanup_case
    snapc "r$r-after-cleanup"
    same "B2.$r:the-host-equals-the-baseline" base "r$r-after-cleanup"
}
b2_round 1 keep
b2_round 2 restore
record "B2:cleanup-status" ok "$H_CLEANUP_STATUS"
record "B2:purge-order-is-the-reverse-of-the-installs" "sinter-t-leaf-a:all sinter-t-app:all sinter-t-base:all" "$(printf '%s\n' "${H_REG[@]}" | awk '{a[NR]=$0} END{for(i=NR;i>=1;i--) printf "%s%s", a[i], (i>1?" ":"")}')"

h_finish
h_verdict
exit $?
