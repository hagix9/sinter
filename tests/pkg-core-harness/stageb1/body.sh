# =====================================================================================
# Stage B1: ONE synthetic package on a real dpkg.  Own run id, run directory, allowlist, baseline, cleanup and verdict.
# Purpose: show that the real dpkg accepts the synthetic .deb, that the identity checks agree with the real dpkg-query
# output, that the strict dry-run parser accepts the real dry-run text, and that the library's cleanup restores the
# baseline exactly.  No Sinter binary is involved; no force option is used; only sinter-t-leaf-a is ever purged.
# =====================================================================================
H_PAYLOAD_ALLOW=(sinter-t-leaf-a:all)
h_install_traps
h_init "stageb1-$(date -u +%m%d%H%M)" || exit 70
h_baseline || exit 70
"$H_DPKG" --version | head -1 > "$OUT/tool-versions.txt"
note "Stage B1 run $H_RUN_ID; dpkg: $("$H_DPKG" --version | head -1); baseline packages: $(h_snap_count base)"
cp "$H_RUNDIR/snap.base" "$OUT/snap-base.tsv" 2> /dev/null || h_fail "evidence:snap-base" "cannot save the baseline"
full_same() { if h_compare_full "$2" "$3"; then record "$1" unchanged unchanged; else record "$1" unchanged "changed: ${H_DIFF:-?}"; fi; }
record "B1:baseline-has-no-test-package" 0 "$(awk -F'\t' '$2 ~ /^sinter-t-/' "$H_RUNDIR/snap.base" | wc -l | tr -d ' ')"

# the real dpkg-deb on the synthetic package (evidence for the payload checks)
h_run "debinfo" "$H_DPKG_DEB" -I "$H_PK/sinter-t-leaf-a_1.0_all.deb" && cp "$H_OUTF" "$OUT/logs/debinfo.out" && cp "$H_ERRF" "$OUT/logs/debinfo.err"
record "B1:dpkg-deb-reads-the-synthetic-deb" 0 "$H_RC"
h_run "debcontents" "$H_DPKG_DEB" -c "$H_PK/sinter-t-leaf-a_1.0_all.deb" && cp "$H_OUTF" "$OUT/logs/debcontents.out"
record "B1:dpkg-deb-lists-the-contents" 0 "$H_RC"
h_run "debfield-essential" "$H_DPKG_DEB" -f "$H_PK/sinter-t-leaf-a_1.0_all.deb" Essential && { cp "$H_OUTF" "$OUT/logs/debfield-essential.out"; cp "$H_ERRF" "$OUT/logs/debfield-essential.err"; }
record "B1:absent-Essential-field-prints-no-exit-0-no-stderr" "0/no/0" "$H_RC/$(cat "$H_OUTF")/$(wc -c < "$H_ERRF" | tr -d ' ')"
h_run "debfield-unknown" "$H_DPKG_DEB" -f "$H_PK/sinter-t-leaf-a_1.0_all.deb" Foo && cp "$H_OUTF" "$OUT/logs/debfield-unknown.out"
record "B1:unknown-field-prints-an-empty-line" "0/1" "$H_RC/$(wc -c < "$H_OUTF" | tr -d ' ')"
h_run "debfield-multi" "$H_DPKG_DEB" -f "$H_PK/sinter-t-leaf-a_1.0_all.deb" Package Architecture Version && cp "$H_OUTF" "$OUT/logs/debfield-multi.out"
record "B1:several-fields-are-printed-with-labels" "Package: sinter-t-leaf-a|Architecture: all|Version: 1.0" "$(tr '\n' '|' < "$H_OUTF" | sed 's/|$//')"

# install through the library only
h_install_deb sinter-t-leaf-a_1.0_all.deb; record "B1:install-through-the-library" 0 "$?"
h_query_pkg sinter-t-leaf-a all
record "B1:state-after-install" "ii " "$H_PSTATE"
record "B1:version-after-install" 1.0 "$H_PVER"
record "B1:not-essential" no "$H_PESS"
snapc after-install
nonreg_same "B1:no-other-package-changed-by-the-install" base after-install

# the real dry-run text, as the library reads it
h_capture_dry_purge dry-real sinter-t-leaf-a:all
record "B1:real-dry-run-exit" 0 "$H_RC"
if h_dry_run_exact sinter-t-leaf-a all 1.0; then record "B1:strict-dry-run-parser-accepts-the-real-text" yes yes; else record "B1:strict-dry-run-parser-accepts-the-real-text" yes no; fi
snapc after-dry
full_same "B1:the-dry-run-changed-nothing" after-install after-dry

# the library's cleanup (strict dry-run, plain purge, exact comparison with the baseline)
cleanup_case
snapc after-cleanup
full_same "B1:the-host-equals-the-baseline" base after-cleanup
h_query_pkg sinter-t-leaf-a all
record "B1:package-absent-after-cleanup" absent "$H_PSTATE"
record "B1:cleanup-status" ok "$H_CLEANUP_STATUS"

h_finish
h_verdict
exit $?
