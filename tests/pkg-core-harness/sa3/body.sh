
# =====================================================================================
# SA-3 real-host scenario (APT only).  Own run id, run directory, allowlist, baseline, cleanup and verdict.
# Assembled after lib/common.sh, lib/safe-lib.sh, lib/shims.sh, lib/captures.sh.
#
# What it establishes (see the evidence documents): what dpkg itself writes on refusal / failure (P1), and how
# Sinter classifies the real outcome (P2).  Packages are installed only through h_install_deb, removed only by
# Sinter (state: absent) or by the library's cleanup, and nothing here uses a force option.
# The essential-package case of the earlier harness is NOT part of this scenario: an Essential package can not be
# purged without a force option, so it needs its own reviewed plan.
# =====================================================================================
H_PAYLOAD_ALLOW=(sinter-t-base:all sinter-t-app:all sinter-t-leaf-a:all sinter-t-slow-install:all
                 sinter-t-sp-prerm:all sinter-t-sp-postrm:all sinter-t-trg-b:all sinter-t-trg-t:all)
h_install_traps
h_init "sa3-$(date -u +%m%d%H%M)" || exit 70
h_baseline || exit 70
"$H_DPKG" --version 2>&1 | head -1 > "$OUT/tool-versions.txt"
note "SA-3 run $H_RUN_ID; dpkg: $("$H_DPKG" --version | head -1); baseline packages: $(h_snap_count base)"
cp "$H_RUNDIR/snap.base" "$OUT/snap-base.tsv" 2> /dev/null || h_fail "evidence:snap-base" "cannot save the baseline"
python3 --version > /dev/null 2>&1 && record "P0:python3-present" yes yes || record "P0:python3-present" yes no
command -v stdbuf > /dev/null 2>&1 && record "P0:stdbuf-present" yes yes || record "P0:stdbuf-present" yes no

has_line() { grep -qxF -- "$2" "$OUT/logs/$1.err"; }
no_removing() { ! grep -q '^Removing ' "$OUT/logs/$1.out"; }
yn() { if "$@"; then echo yes; else echo no; fi; }
rcf() { cat "$OUT/logs/$1.rc"; }
inst() { h_install_deb "$1" || note "install of $1 failed"; }
full_same() { if h_compare_full "$2" "$3"; then record "$1" unchanged unchanged; else record "$1" unchanged "changed: ${H_DIFF:-?}"; fi; }

# ===== P1: what dpkg itself writes (direct dpkg on packages this run registered; Sinter's --refuse-* options) =====
# B1 dependency refusal
inst sinter-t-base_1.0_all.deb; inst sinter-t-app_1.0_all.deb
h_capture_remove b1-dep sinter-t-base:all
record "B1:dep.rc-nonzero" yes "$([ "$(rcf b1-dep)" != 0 ] && echo yes || echo no)"
record "B1:dep.whole-line" yes "$(yn has_line b1-dep "dpkg: dependency problems prevent removal of sinter-t-base:")"
record "B1:dep.no-Removing-line" yes "$(yn no_removing b1-dep)"
note "B1 dependency refusal: rc=$(rcf b1-dep) state-after=[$(state_of sinter-t-base all)] stderr=[$(tr '\n' '|' < "$OUT/logs/b1-dep.err" | cut -c1-400)]"
h_restore_selection sinter-t-base:all sinter-t-app:all
cleanup_case

# B2 lock refusal (a real dpkg holds the lock)
inst sinter-t-leaf-a_1.0_all.deb
h_install_deb_bg sinter-t-slow-install_1.0_all.deb; HOLDER="${H_BGPID:-0}"
sleep 6
h_capture_remove b2-lock sinter-t-leaf-a:all
record "B2:lock.rc" 2 "$(rcf b2-lock)"
record "B2:lock.first-line-pattern" yes "$(head -1 "$OUT/logs/b2-lock.err" | grep -qE '^dpkg: error: dpkg frontend lock was locked by another process with pid [0-9]+$' && echo yes || echo no)"
record "B2:lock.no-Removing-line" yes "$(yn no_removing b2-lock)"
note "B2 lock refusal: stderr=[$(tr '\n' '|' < "$OUT/logs/b2-lock.err" | cut -c1-300)]"
wait "$HOLDER" 2> /dev/null
cleanup_case

# B3 no privilege
if [ "$(id -u)" != 0 ]; then
    inst sinter-t-leaf-a_1.0_all.deb
    h_capture_remove b3-priv sinter-t-leaf-a:all unpriv
    record "B3:priv.rc" 2 "$(rcf b3-priv)"
    record "B3:priv.whole-line" yes "$(yn has_line b3-priv "dpkg: error: requested operation requires superuser privilege")"
    record "B3:priv.no-Removing-line" yes "$(yn no_removing b3-priv)"
    cleanup_case
else
    note "B3 skipped: the login user is root"
fi

# B5 the order of dpkg's "Removing" line and the pre-removal script. The script of sinter-t-sp-prerm (armed) waits up to
# 8 s until a reader of dpkg's stdout has seen the Removing line, records whether it had, then fails with refusal-like words.
inst sinter-t-sp-prerm_1.0_all.deb
h_arm sinter-t-sp-prerm; h_arm sinter-t-sp-prerm wait
h_capture_remove_ordered b5a sinter-t-sp-prerm:all line
record "B5a:line-buffered.rc-nonzero" yes "$([ "$(rcf b5a)" != 0 ] && echo yes || echo no)"
record "B5a:line-buffered.script-saw-Removing-already" saw "$(h_flag_read sinter-t-sp-prerm.order)"
record "B5a:line-buffered.stdout-has-Removing" yes "$(grep -q ' Removing ' "$OUT/logs/b5a.stdout.log" && echo yes || echo no)"
record "B5a:stderr-has-the-script-s-refusal-looking-lines" yes "$(yn has_line b5a "dpkg: dependency problems prevent removal of sinter-t-sp-prerm:")"
h_disarm sinter-t-sp-prerm.order; h_disarm sinter-t-sp-prerm.seen
h_capture_remove_ordered b5b sinter-t-sp-prerm:all default
note "B5b (default buffering, as through a pipe): the script saw Removing before it ran: $(h_flag_read sinter-t-sp-prerm.order) [informational]"
record "B5b:default-buffering.final-stdout-has-Removing" yes "$(grep -q ' Removing ' "$OUT/logs/b5b.stdout.log" && echo yes || echo no)"
cleanup_case

# B6 failing post-removal script with refusal-like words
inst sinter-t-sp-postrm_1.0_all.deb
h_arm sinter-t-sp-postrm
h_capture_remove b6-post sinter-t-sp-postrm:all
record "B6:postrm.rc-nonzero" yes "$([ "$(rcf b6-post)" != 0 ] && echo yes || echo no)"
record "B6:postrm.stdout-has-Removing" yes "$(yn grep -q '^Removing ' "$OUT/logs/b6-post.out")"
record "B6:postrm.stderr-has-the-script-s-lines" yes "$(yn has_line b6-post 'dpkg: dependency problems prevent removal of sinter-t-sp-postrm:')"
note "B6 postrm: state-after=[$(state_of sinter-t-sp-postrm all)]"
cleanup_case

# B7 the package is gone but dpkg exits non-zero: a trigger of another package fails after the removal
inst sinter-t-trg-t_1.0_all.deb; inst sinter-t-trg-b_1.0_all.deb
h_arm sinter-t-trg-t
h_capture_remove b7-trg sinter-t-trg-b:all
TRG_REPRO=no
grep -q 'dpkg: error processing package sinter-t-trg-t' "$OUT/logs/b7-trg.err" && [ "$(rcf b7-trg)" != 0 ] && TRG_REPRO=yes
note "B7 trigger case: reproduced=$TRG_REPRO rc=$(rcf b7-trg) trg-b=[$(state_of sinter-t-trg-b all)] trg-t=[$(state_of sinter-t-trg-t all)]"
record "B7:trigger.Removing-line-present" yes "$(yn grep -q '^Removing ' "$OUT/logs/b7-trg.out")"
cleanup_case

# ===== P2: Sinter against real dpkg failures (the dpkg wrapper keeps what the real removing dpkg wrote) ===============
h_shim_install dpkg || exit 70
WRAPPED=1
record "P2:dpkg-wrapper-installed" yes yes

# C1 dependency refused by Sinter's own dry-run
inst sinter-t-base_1.0_all.deb; inst sinter-t-app_1.0_all.deb
snapc c1-before
recipe c1.yaml sinter-t-base absent
sinj c1 c1.yaml --sudo; snapc c1-after; report c1
record "C1:change" none "$(jf c1 change)"; record "C1:execution" failed "$(jf c1 execution)"; record "C1:verification" not_performed "$(jf c1 verification)"
full_same "C1:nothing-on-the-host-changed" c1-before c1-after
record "C1:no-removing-dpkg-ran" yes "$([ ! -e "$OUT/logs/c1.shim.real.err" ] && echo yes || echo no)"
case "$(jf c1 reason)" in *depend*) record "C1:reason-names-dependency" yes yes ;; *) record "C1:reason-names-dependency" yes no ;; esac
sint c1t c1.yaml --sudo; cons c1 c1t
cleanup_case

# C2 a dependent is installed after Sinter's dry-run, right before its real dpkg --remove
inst sinter-t-base_1.0_all.deb
# sinter-t-app is installed by the wrapper ("another process"); h_shim_arm below verifies and registers it, so the cleanup knows it
snapc c2-before
h_shim_arm sinter-t-app_1.0_all.deb
recipe c2.yaml sinter-t-base absent
sinj c2 c2.yaml --sudo; snapc c2-after; report c2
record "C2:shim-fired" yes "$(grep -q '^other process:' "$OUT/logs/c2.shim.log" 2> /dev/null && echo yes || echo no)"
record "C2:real-dpkg-ran" yes "$([ -e "$OUT/logs/c2.shim.real.err" ] && echo yes || echo no)"
nonreg_same "C2:no-other-package-changed" c2-before c2-after
record "C2:change-is-not-changed" yes "$([ "$(jf c2 change)" != changed ] && echo yes || echo no)"
record "C2:execution" failed "$(jf c2 execution)"
note "C2 real dpkg said: stdout=[$(tr '\n' '|' < "$OUT/logs/c2.shim.real.out" 2> /dev/null | cut -c1-200)] stderr=[$(tr '\n' '|' < "$OUT/logs/c2.shim.real.err" 2> /dev/null | cut -c1-400)] state-after=[$(state_of sinter-t-base all)]"
inv c2; h_shim_unarm
h_restore_selection sinter-t-base:all sinter-t-app:all
cleanup_case

# C3 package database lock held by another process
inst sinter-t-leaf-a_1.0_all.deb
h_install_deb_bg sinter-t-slow-install_1.0_all.deb; HOLDER="${H_BGPID:-0}"
sleep 6
snapc c3-before
recipe c3.yaml sinter-t-leaf-a absent
sinj c3 c3.yaml --sudo; report c3
sint c3t c3.yaml --sudo
record "C3:change" none "$(jf c3 change)"; record "C3:execution" failed "$(jf c3 execution)"; record "C3:verification" not_performed "$(jf c3 verification)"
record "C3:holder-still-running" yes "$(kill -0 "$HOLDER" 2> /dev/null && echo yes || echo no)"
record "C3:package-kept" yes "$([ "$(state_of sinter-t-leaf-a all)" = "ii " ] && echo yes || echo no)"
note "C3 real dpkg said: stderr=[$(tr '\n' '|' < "$OUT/logs/c3.shim.real.err" 2> /dev/null | cut -c1-300)]"
inv c3; cons c3 c3t
wait "$HOLDER" 2> /dev/null
cleanup_case

# C4 no privilege (login user without --sudo)
if [ "$(id -u)" != 0 ]; then
    inst sinter-t-leaf-a_1.0_all.deb
    snapc c4-before
    recipe c4.yaml sinter-t-leaf-a absent
    sinj c4 c4.yaml; snapc c4-after; report c4
    record "C4:change" none "$(jf c4 change)"; record "C4:execution" failed "$(jf c4 execution)"
    full_same "C4:nothing-on-the-host-changed" c4-before c4-after
    inv c4
    sint c4t c4.yaml; cons c4 c4t
    cleanup_case
fi

# C5 pre-removal script fails and prints dpkg-looking refusal words
inst sinter-t-sp-prerm_1.0_all.deb; h_arm sinter-t-sp-prerm
snapc c5-before
recipe c5.yaml sinter-t-sp-prerm absent
sinj c5 c5.yaml --sudo; snapc c5-after; report c5
record "C5:change-is-not-none" yes "$([ "$(jf c5 change)" != none ] && echo yes || echo no)"
record "C5:execution" failed "$(jf c5 execution)"
nonreg_same "C5:no-other-package-changed" c5-before c5-after
record "C5:real-dpkg-printed-Removing" yes "$(grep -q '^Removing ' "$OUT/logs/c5.shim.real.out" 2> /dev/null && echo yes || echo no)"
note "C5 real dpkg said: stderr=[$(tr '\n' '|' < "$OUT/logs/c5.shim.real.err" 2> /dev/null | cut -c1-300)] state-after=[$(state_of sinter-t-sp-prerm all)]"
inv c5
cleanup_case
inst sinter-t-sp-prerm_1.0_all.deb; h_arm sinter-t-sp-prerm
sint c5t c5.yaml --sudo; cons c5 c5t
cleanup_case

# C6 post-removal script fails and prints dpkg-looking refusal words
inst sinter-t-sp-postrm_1.0_all.deb; h_arm sinter-t-sp-postrm
snapc c6-before
recipe c6.yaml sinter-t-sp-postrm absent
sinj c6 c6.yaml --sudo; snapc c6-after; report c6
record "C6:change-is-not-none" yes "$([ "$(jf c6 change)" != none ] && echo yes || echo no)"
record "C6:execution" failed "$(jf c6 execution)"
nonreg_same "C6:no-other-package-changed" c6-before c6-after
inv c6
cleanup_case
inst sinter-t-sp-postrm_1.0_all.deb; h_arm sinter-t-sp-postrm
sint c6t c6.yaml --sudo; cons c6 c6t
cleanup_case

# C7 the package is gone but dpkg exits non-zero (a trigger of another package fails)
if [ "$TRG_REPRO" = yes ]; then
    inst sinter-t-trg-t_1.0_all.deb; inst sinter-t-trg-b_1.0_all.deb; h_arm sinter-t-trg-t
    snapc c7-before
    recipe c7.yaml sinter-t-trg-b absent
    sinj c7 c7.yaml --sudo; snapc c7-after; report c7
    # "gone" = removed: not installed, or only its configuration files remain (a plain --remove ends in "rc ")
    case "$(state_of sinter-t-trg-b all)" in absent|?n?|?c?) trg_gone=gone ;; *) trg_gone=present ;; esac
    record "C7:target-removed" gone "$trg_gone"
    record "C7:change" changed "$(jf c7 change)"
    record "C7:execution" failed "$(jf c7 execution)"
    nonreg_same "C7:no-other-package-changed" c7-before c7-after
    note "C7 trg-t afterwards: [$(state_of sinter-t-trg-t all)]"
    inv c7
    cleanup_case
    inst sinter-t-trg-t_1.0_all.deb; inst sinter-t-trg-b_1.0_all.deb; h_arm sinter-t-trg-t
    sint c7t c7.yaml --sudo; cons c7 c7t
    cleanup_case
else
    note "C7 not run: the failing-trigger state could not be produced on this host (B7)"
fi

# C8 sensitive resource: no package name anywhere in the output (SA-3 paths)
for sc in sp-prerm sp-postrm; do
    inst "sinter-t-${sc}_1.0_all.deb"; h_arm "sinter-t-$sc"
    recipe "c8-$sc.yaml" "sinter-t-$sc" absent sensitive
    sinj "c8-$sc" "c8-$sc.yaml" --sudo
    cleanup_case
    inst "sinter-t-${sc}_1.0_all.deb"; h_arm "sinter-t-$sc"
    sint "c8t-$sc" "c8-$sc.yaml" --sudo
    LEAK=0
    grep -qF "sinter-t-$sc" "$OUT/logs/c8-$sc.json" "$OUT/logs/c8t-$sc.txt" 2> /dev/null && LEAK=1
    record "C8:$sc.no-name-in-output" 0 "$LEAK"
    python3 -I -c 'import json,sys; json.load(open(sys.argv[1]))' "$OUT/logs/c8-$sc.json" 2> /dev/null && record "C8:$sc.json-valid" yes yes || record "C8:$sc.json-valid" yes no
    cleanup_case
done

if h_shim_remove dpkg; then WRAPPED=0; else note "the dpkg wrapper could not be removed: stopping (no further mutation)"; exit 70; fi
record "P2:dpkg-wrapper-removed" yes "$([ "$WRAPPED" = 0 ] && echo yes || echo no)"

# ===== end: the cleanup result is a separate part of the verdict =====================================================
h_finish
h_verdict
exit $?
