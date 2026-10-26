
# =====================================================================================
# Multi-Arch real-host scenario (APT only).  Own run id, run directory, allowlist, baseline, cleanup and verdict
# (it shares no state with the SA-3 scenario and never adopts leftovers of another run).
# Assembled after lib/common.sh, lib/safe-lib.sh, lib/shims.sh, lib/captures.sh.
#
# Host settings touched, all restored by the library's final cleanup (which fails the run if they are not):
# the dpkg foreign architecture i386 (only if the baseline did not have it), two temporary non-persistent bind-mount
# wrappers (dpkg, dpkg-query) and the run's own files.  Packages: synthetic sinter-t-ma and sinter-t-mab only.
# =====================================================================================
H_PAYLOAD_ALLOW=(sinter-t-ma:amd64 sinter-t-ma:i386 sinter-t-mab:amd64 sinter-t-mab:i386)
h_install_traps
h_init "ma-$(date -u +%m%d%H%M)" || exit 70
h_baseline || exit 70
"$H_DPKG" --version 2>&1 | head -1 > "$OUT/tool-versions.txt"
note "Multi-Arch run $H_RUN_ID; dpkg: $("$H_DPKG" --version | head -1); baseline packages: $(h_snap_count base); foreign architectures: [$(tr '\n' ' ' < "$H_RUNDIR/foreign.base")]"
cp "$H_RUNDIR/snap.base" "$OUT/snap-base.tsv" 2> /dev/null || h_fail "evidence:snap-base" "cannot save the baseline"
python3 --version > /dev/null 2>&1 && record "P0:python3-present" yes yes || record "P0:python3-present" yes no

yn() { if "$@"; then echo yes; else echo no; fi; }
inst() { h_install_deb "$1" || note "install of $1 failed"; }
full_same() { if h_compare_full "$2" "$3"; then record "$1" unchanged unchanged; else record "$1" unchanged "changed: ${H_DIFF:-?}"; fi; }
QINST='Architecture}\\n -- '    # argv of the per-instance query: ...${Architecture}\n -- NAME (the inventory query has no "-- NAME")
qcount() { grep -c -- "$QINST" "$OUT/logs/$1.q.log" 2> /dev/null || true; }
nonremoving_calls() {  # real (non dry-run) --remove/--purge calls seen by the dpkg wrapper
    grep -E -- ' --(remove|purge) ' "$OUT/logs/$1.shim.log" 2> /dev/null | grep -vc -- '--dry-run' || true
}
ma_raw() {  # ma_raw LABEL NAME -> the queries Sinter's observer relies on, answered by the real dpkg-query
    local l="$1" n="$2"
    h_run "raw:$l:status" "$H_DPKG_QUERY" -W -f='${Status}' -- "$n" && cp "$H_OUTF" "$OUT/logs/$l.q-status.out"
    h_run "raw:$l:instances" "$H_DPKG_QUERY" -W '-f=${Status}\t${Package}\t${Architecture}\n' -- "$n" && cp "$H_OUTF" "$OUT/logs/$l.q-instances.out"
    h_run "raw:$l:binary" "$H_DPKG_QUERY" -W '-f=${db:Status-Abbrev}\t${binary:Package}\n' -- "$n" && cp "$H_OUTF" "$OUT/logs/$l.q-binary.out"
    note "$l raw: ${n}: status=[$(cat "$OUT/logs/$l.q-status.out" 2> /dev/null)] instances=[$(tr '\t\n' '~|' < "$OUT/logs/$l.q-instances.out" 2> /dev/null)] binary=[$(tr '\t\n' '~|' < "$OUT/logs/$l.q-binary.out" 2> /dev/null)]"
}
st() { state_of "$1" "$2"; }

h_add_arch i386 || exit 70
record "P3:i386-available" yes "$(grep -qx i386 <<< "$(h_sudo_run "$H_DPKG" --print-foreign-architectures)" && echo yes || echo no)"
h_shim_install dpkg || exit 70
h_shim_install dpkg_query || exit 70
WRAPPED=1
record "P3:wrappers-installed" yes yes
recipe present.yaml sinter-t-ma present; recipe absent.yaml sinter-t-ma absent

# D1 single architecture (the ordinary case)
inst sinter-t-ma_1.0_amd64.deb
ma_raw d1 sinter-t-ma
snapc d1-before
sinj d1p present.yaml --sudo; report d1p
record "D1:present.change" none "$(jf d1p change)"; record "D1:present.execution" succeeded "$(jf d1p execution)"
record "D1:present.no-instance-query" 0 "$(qcount d1p)"
sinj d1a absent.yaml --sudo; snapc d1-after; report d1a
record "D1:absent.change" changed "$(jf d1a change)"; record "D1:absent.execution" succeeded "$(jf d1a execution)"; record "D1:absent.verification" verified "$(jf d1a verification)"
nonreg_same "D1:absent.no-other-package-changed" d1-before d1-after
# "gone" = removed: not installed, or only its configuration files remain (a plain --remove ends in "rc ")
removed_state() { case "$1" in absent|?n?|?c?) echo gone ;; *) echo present ;; esac; }
record "D1:absent.target-removed" gone "$(removed_state "$(st sinter-t-ma amd64)")"
record "D1:absent.no-instance-query" 0 "$(qcount d1a)"
inv d1a
cleanup_case

# D2 amd64 installed + i386 config-files (the false refusal of the earlier E2E)
inst sinter-t-ma_1.0_amd64.deb; inst sinter-t-ma_1.0_i386.deb
h_capture_remove d2-setup sinter-t-ma:i386
record "D2:setup.i386-config-files" "rc " "$(st sinter-t-ma i386)"
ma_raw d2 sinter-t-ma
snapc d2-before
sinj d2p present.yaml --sudo; report d2p; snapc d2-mid
record "D2:present.change" none "$(jf d2p change)"; record "D2:present.execution" succeeded "$(jf d2p execution)"
record "D2:present.instance-query-issued" yes "$([ "$(qcount d2p)" -ge 1 ] && echo yes || echo no)"
record "D2:present.first-query-answer-was-run-together" "install ok installeddeinstall ok config-files" "$(grep -A1 -- '-f=${Status} ' "$OUT/logs/d2p.q.out.log" 2> /dev/null | sed -n 2p | head -1 | sed 's/--- rc=[0-9]*$//')"
full_same "D2:present.nothing-changed" d2-before d2-mid
sinj d2a absent.yaml --sudo; snapc d2-after; report d2a
record "D2:absent.change" changed "$(jf d2a change)"; record "D2:absent.execution" succeeded "$(jf d2a execution)"; record "D2:absent.verification" verified "$(jf d2a verification)"
nonreg_same "D2:absent.no-other-package-changed" d2-before d2-after
record "D2:absent.amd64-removed" gone "$(removed_state "$(st sinter-t-ma amd64)")"
record "D2:absent.i386-config-files-untouched" "rc " "$(st sinter-t-ma i386)"
record "D2:absent.exactly-one-real-remove" 1 "$(nonremoving_calls d2a)"
record "D2:absent.real-remove-argv-is-the-bare-name" yes "$(grep -E -- ' --remove ' "$OUT/logs/d2a.shim.log" | grep -v -- '--dry-run' | grep -q -- '--remove sinter-t-ma$' && echo yes || echo no)"
record "D2:absent.identity-rechecked-before-the-removal" yes "$(python3 -I - "$OUT/logs/d2a.q.log" "$OUT/logs/d2a.shim.log" << 'PYEOF'
import sys
def stamps(path, pred):
    out = []
    for l in open(path):
        if l[:1].isdigit() and pred(l):
            try:
                out.append(float(l.split()[0]))
            except ValueError:
                pass
    return sorted(out)
ids = stamps(sys.argv[1], lambda l: "Version}" in l)
rm = stamps(sys.argv[2], lambda l: " --remove " in l and "--dry-run" not in l)
print("yes" if len(ids) >= 2 and rm and ids[1] < rm[0] else "no (identity queries: %d, removes: %d)" % (len(ids), len(rm)))
PYEOF
)"
inv d2a
cleanup_case

# D3 amd64 installed + i386 purged
inst sinter-t-ma_1.0_amd64.deb; inst sinter-t-ma_1.0_i386.deb; h_purge_now sinter-t-ma:i386
ma_raw d3 sinter-t-ma
snapc d3-before
sinj d3a absent.yaml --sudo; snapc d3-after; report d3a
record "D3:absent.change" changed "$(jf d3a change)"; record "D3:absent.execution" succeeded "$(jf d3a execution)"
nonreg_same "D3:absent.no-other-package-changed" d3-before d3-after
record "D3:absent.no-instance-query" 0 "$(qcount d3a)"
cleanup_case

# D4 both architectures installed: ambiguous, refused, nothing removed
inst sinter-t-ma_1.0_amd64.deb; inst sinter-t-ma_1.0_i386.deb
ma_raw d4 sinter-t-ma
snapc d4-before
for stt in absent present; do
    sinj "d4$stt" "$stt.yaml" --sudo; report "d4$stt"
    record "D4:$stt.change" none "$(jf "d4$stt" change)"; record "D4:$stt.execution" failed "$(jf "d4$stt" execution)"
    case "$(jf "d4$stt" reason)" in *"more than one"*) record "D4:$stt.reason-says-more-than-one" yes yes ;; *) record "D4:$stt.reason-says-more-than-one" yes "no: $(jf "d4$stt" reason | cut -c1-160)" ;; esac
    record "D4:$stt.no-real-remove" 0 "$(nonremoving_calls "d4$stt")"
done
snapc d4-after; full_same "D4:nothing-changed" d4-before d4-after
cleanup_case

# D5 amd64 installed + i386 in a broken state (its pre-removal script fails: deinstall ok installed)
inst sinter-t-mab_1.0_amd64.deb; inst sinter-t-mab_1.0_i386.deb
h_arm sinter-t-mab
h_capture_remove d5-setup sinter-t-mab:i386
record "D5:setup.i386-broken" "ri " "$(st sinter-t-mab i386)"
ma_raw d5 sinter-t-mab
snapc d5-before
for stt in absent present; do
    recipe "d5$stt.yaml" sinter-t-mab "$stt"
    sinj "d5$stt" "d5$stt.yaml" --sudo; report "d5$stt"
    record "D5:$stt.execution" failed "$(jf "d5$stt" execution)"; record "D5:$stt.change" none "$(jf "d5$stt" change)"
    record "D5:$stt.no-real-remove" 0 "$(nonremoving_calls "d5$stt")"
done
snapc d5-after; full_same "D5:nothing-changed" d5-before d5-after
cleanup_case

# D6 the target has no installed instance (leftovers only / unknown name)
inst sinter-t-ma_1.0_amd64.deb; inst sinter-t-ma_1.0_i386.deb
h_capture_remove d6-setup1 sinter-t-ma:amd64; h_capture_remove d6-setup2 sinter-t-ma:i386
ma_raw d6 sinter-t-ma
snapc d6-before
sinj d6a absent.yaml --sudo; snapc d6-after; report d6a
record "D6:leftovers-only.change" none "$(jf d6a change)"; record "D6:leftovers-only.execution" succeeded "$(jf d6a execution)"
record "D6:leftovers-only.no-real-remove" 0 "$(nonremoving_calls d6a)"
full_same "D6:leftovers-only.nothing-changed" d6-before d6-after
recipe d6n.yaml sinter-t-never-installed absent
sinj d6n d6n.yaml --sudo; report d6n
record "D6:unknown-name.change" none "$(jf d6n change)"; record "D6:unknown-name.execution" succeeded "$(jf d6n execution)"
cleanup_case

# D7 invalid answers to the per-instance query: Sinter must refuse and remove nothing
inst sinter-t-ma_1.0_amd64.deb; inst sinter-t-ma_1.0_i386.deb; h_capture_remove d7-setup sinter-t-ma:i386
snapc d7-before
for mode in garbage two mismatch nonl exit1 empty broken stderr; do
    h_shim_qmode "$mode"
    sinj "d7-$mode" absent.yaml --sudo; report "d7-$mode"
    record "D7:$mode.refused" "none/failed" "$(jf "d7-$mode" change)/$(jf "d7-$mode" execution)"
    record "D7:$mode.instance-query-was-issued" yes "$(grep -q "answered in test mode: $mode" "$OUT/logs/d7-$mode.q.log" 2> /dev/null && echo yes || echo no)"
    record "D7:$mode.no-real-remove" 0 "$(nonremoving_calls "d7-$mode")"
    record "D7:$mode.amd64-still-installed" "ii " "$(st sinter-t-ma amd64)"
done
for mode in garbage two; do
    h_shim_qmode "$mode"
    sinj "d7p-$mode" present.yaml --sudo; report "d7p-$mode"
    record "D7:present.$mode.fails" failed "$(jf "d7p-$mode" execution)"
done
h_shim_qmode ""
snapc d7-after; full_same "D7:nothing-changed" d7-before d7-after
cleanup_case

# D8 the second architecture appears between Sinter's checks and its removing dpkg (the race, made deterministic)
inst sinter-t-ma_1.0_amd64.deb; inst sinter-t-ma_1.0_i386.deb; h_purge_now sinter-t-ma:i386
snapc d8-before
h_shim_arm sinter-t-ma_1.0_i386.deb
sinj d8 absent.yaml --sudo; snapc d8-after; report d8
record "D8:shim-fired" yes "$(grep -q 'other process:' "$OUT/logs/d8.shim.log" 2> /dev/null && echo yes || echo no)"
record "D8:real-dpkg-ran" yes "$([ -e "$OUT/logs/d8.shim.real.err" ] && echo yes || echo no)"
note "D8 real dpkg said: stdout=[$(tr '\n' '|' < "$OUT/logs/d8.shim.real.out" 2> /dev/null | cut -c1-160)] stderr=[$(tr '\n' '|' < "$OUT/logs/d8.shim.real.err" 2> /dev/null | cut -c1-300)] amd64=[$(st sinter-t-ma amd64)] i386=[$(st sinter-t-ma i386)]"
record "D8:change-is-not-changed-unless-dpkg-removed" yes "$({ [ "$(jf d8 change)" != changed ] || grep -q '^Removing ' "$OUT/logs/d8.shim.real.out" 2> /dev/null; } && echo yes || echo no)"
record "D8:execution" failed "$(jf d8 execution)"
nonreg_same "D8:no-other-package-changed" d8-before d8-after
inv d8; h_shim_unarm
cleanup_case

# D9 informational: how dpkg-query answers for names it knows only by reference
for n in debconf-2.0 sinter-t-never-installed; do
    h_run "d9:$n" "$H_DPKG_QUERY" -W '-f=${Status}\t${Package}\t${Architecture}\n' -- "$n"
    cp "$H_OUTF" "$OUT/logs/d9-$n.out" 2> /dev/null; cp "$H_ERRF" "$OUT/logs/d9-$n.err" 2> /dev/null
    note "D9 informational: instance format for [$n]: rc=$H_RC stdout=[$(tr '\t\n' '~|' < "$H_OUTF" | cut -c1-200)] stderr=[$(tr '\n' '|' < "$H_ERRF" | cut -c1-160)]"
done

h_shim_remove dpkg_query; QOK=$?
h_shim_remove dpkg; POK=$?
[ "$QOK" = 0 ] && [ "$POK" = 0 ] && WRAPPED=0
record "P3:wrappers-removed" yes "$([ "$WRAPPED" = 0 ] && echo yes || echo no)"
[ "$WRAPPED" = 0 ] || { note "a wrapper could not be removed: stopping (no further mutation)"; exit 70; }

# ===== end: the final cleanup also removes the architecture this run added and compares the foreign architectures ====
h_finish
h_verdict
exit $?
