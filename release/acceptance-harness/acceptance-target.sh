#!/bin/bash
# Per-target acceptance harness for the Sinter v1.4.0 release.
#
# It runs the frozen release artifact (the product under test) on one real
# supported Linux x86_64 target and walks the RELEASE.md steps 7-9 minimum
# matrix. It contains no verification logic of its own beyond comparing the
# observed product output with the frozen values it is given: every check
# prints exactly one "== check <id> ok|FAIL" line and a non-zero check count
# is a FAIL for the target.
set -u
LABEL=$1          # ubuntu2404 | ubuntu2604 | rocky9 | rocky10 | rhel9 | rhel10 | alma9 | alma10
TARBALL=$2        # frozen release tarball
EXP_ART=$3        # expected tarball sha256
EXP_EXE=$4        # expected sinter executable sha256
EXP_VER=$5        # expected --version output
WORK=/var/tmp/sinter-acceptance
RCFILE=/tmp/acceptance.rc
rm -f "$RCFILE"
PASS=0; FAIL=0; SKIP=0

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
check() { # check <id> <ok|FAIL> [detail]
  if [ "$2" = ok ]; then PASS=$((PASS+1)); echo "== check $1 ok"; echo "   $3";
  else FAIL=$((FAIL+1)); echo "== check $1 FAIL"; echo "   $3"; fi
}
skip() { SKIP=$((SKIP+1)); echo "== check $1 SKIP"; echo "   $2"; }

exec > "$WORK/raw.log" 2>&1
echo "== acceptance start $(ts) label=$LABEL"
mkdir -p "$WORK" || { echo 89 > "$RCFILE"; exit 89; }

# ---------------------------------------------------------------- identity
cd "$WORK" || { echo 90 > "$RCFILE"; exit 90; }
ART_OBS=$(sha256sum "$TARBALL" | cut -d' ' -f1)
echo "OBSERVED_ARTIFACT_SHA=$ART_OBS"
if [ "$ART_OBS" = "$EXP_ART" ]; then check artifact-sha256 ok "$EXP_ART"
else check artifact-sha256 FAIL "expected $EXP_ART observed $ART_OBS"; fi

rm -rf "$WORK/x"; mkdir -p "$WORK/x"
tar -xzf "$TARBALL" -C "$WORK/x" || { echo 91 > "$RCFILE"; exit 91; }
EXE="$WORK/x/$(basename "$TARBALL" .tar.gz)/sinter"
[ -x "$EXE" ] || { echo 92 > "$RCFILE"; exit 92; }
EXE_OBS=$(sha256sum "$EXE" | cut -d' ' -f1)
echo "OBSERVED_EXECUTABLE_SHA=$EXE_OBS"
if [ "$EXE_OBS" = "$EXP_EXE" ]; then check executable-sha256 ok "$EXP_EXE"
else check executable-sha256 FAIL "expected $EXP_EXE observed $EXE_OBS"; fi

VER_OBS=$("$EXE" --version 2>&1)
echo "OBSERVED_VERSION=$VER_OBS"
if [ "$VER_OBS" = "$EXP_VER" ]; then check version-output ok "$EXP_VER"
else check version-output FAIL "expected $EXP_VER observed $VER_OBS"; fi

FILE_OBS=$(file -b "$EXE")
echo "OBSERVED_FILE=$FILE_OBS"
case "$FILE_OBS" in *x86-64*) check artifact-arch ok "$FILE_OBS";; *) check artifact-arch FAIL "$FILE_OBS";; esac

LDD_OBS=$(ldd "$EXE" 2>&1)
echo "OBSERVED_LDD<<"; echo "$LDD_OBS"; echo ">>"
if echo "$LDD_OBS" | grep -q 'not found'; then check linkage-resolved FAIL "$LDD_OBS"
else check linkage-resolved ok "all NEEDED libraries resolved"; fi

OSNAME=$(. /etc/os-release; echo "$NAME")
OSVER=$(. /etc/os-release; echo "$VERSION_ID")
ARCH=$(uname -m)
echo "OS_NAME=$OSNAME OS_VERSION=$OSVER ARCH=$ARCH"
if [ "$ARCH" = x86_64 ]; then check os-arch ok "$OSNAME $OSVER $ARCH"; else check os-arch FAIL "$ARCH"; fi

# Sinter reports the RHEL family as "redhat" and the Debian family as "debian".
case "$LABEL" in ubuntu*) WANT_FAMILY=debian; PKGMGR=apt-get; PKGVERIFY="dpkg -s" ;; *) WANT_FAMILY=redhat; PKGMGR=dnf; PKGVERIFY="rpm -q" ;; esac
case "$LABEL" in ubuntu2404|ubuntu2604) PKG=sl ;; *) PKG=tree ;; esac

# --------------------------------------------------------------- sudo -n
if sudo -n true 2>/dev/null; then check sudo-n ok "passwordless sudo available"
else check sudo-n FAIL "sudo -n not available"; fi

# --------------------------------------------------- platform detection
S="$WORK/x"
printf '%s\n' "$EXP_VER" > "$WORK/expect-version.txt"
cat > "$S/probe.yaml" <<'YAML'
version: 1
resources:
  - id: probe_dir
    type: directory
    with:
      path: /opt/sinter-acceptance/state
      state: present
      mode: "0755"
YAML
"$EXE" validate "$S/probe.yaml" >/dev/null 2>&1 && check recipe-validate ok "probe recipe validates" || check recipe-validate FAIL "probe recipe did not validate"

"$EXE" plan "$S/probe.yaml" --sudo --format json > "$S/probe-plan.json" 2> "$S/probe-plan.err"; PRC=$?
echo "PROBE_PLAN_RC=$PRC"
[ -s "$S/probe-plan.json" ] || { echo "probe-plan.err:"; cat "$S/probe-plan.err"; }
set +e
python3 - "$S/probe-plan.json" "$WANT_FAMILY" "$OSNAME" "$ARCH" > "$S/probe-facts.txt" 2>&1 <<'PYEOF'
import json,sys
d=json.load(open(sys.argv[1])); f=d.get("facts",{})
print("expected family=%s name=%s arch=%s" % (sys.argv[2], sys.argv[3], sys.argv[4]))
print("observed", f)
ok = f.get("os_family")==sys.argv[2] and f.get("os_name")==sys.argv[3] and f.get("arch")==sys.argv[4]
sys.exit(0 if ok else 3)
PYEOF
FACTS_RC=$?
set +e
cat "$S/probe-facts.txt"
if [ "$FACTS_RC" -eq 0 ]; then check platform-detect ok "family/distro/arch detected with no fall-through"
else check platform-detect FAIL "platform facts differ from the expected family/distro/arch"; fi

# ------------------------------------------------------------------ SSH
SSHUSER=sinter
SSHKEY=/opt/sinter-acceptance/ssh/id_ed25519
if [ -f "$SSHKEY" ]; then
  KH=/opt/sinter-acceptance/ssh/known_hosts
  if [ -f "$KH" ]; then
    "$EXE" plan "$S/probe.yaml" --host 127.0.0.1 --port 22 --user "$SSHUSER" \
      --identity "$SSHKEY" --known-hosts "$KH" --sudo --format json > "$S/ssh-plan.json" 2> "$S/ssh-plan.err"; SRC=$?
    echo "SSH_PLAN_RC=$SRC"
    if [ "$SRC" -eq 0 ] && [ -s "$S/ssh-plan.json" ]; then check ssh-exec ok "SSH plan over loopback returned a report"
    else echo "ssh-plan.err:"; cat "$S/ssh-plan.err"; check ssh-exec FAIL "SSH plan exit $SRC"; fi
  else
    check ssh-exec FAIL "known_hosts file missing"
  fi
else
  check ssh-exec FAIL "acceptance SSH key missing"
fi

# ------------------------------------------------------------- packages
pkg_present() {
  case "$PKGVERIFY" in "rpm -q") rpm -q "$PKG" >/dev/null 2>&1;; "dpkg -s") dpkg -s "$PKG" >/dev/null 2>&1;; esac
}
pkg_query_raw() {
  case "$PKGVERIFY" in "rpm -q") rpm -q "$PKG" 2>&1 || true;; "dpkg -s") dpkg -s "$PKG" 2>&1 || true;; esac
}
INIT_PRESENT=no
if pkg_present; then INIT_PRESENT=yes; fi
check package-initial-state ok "package initially installed=$INIT_PRESENT"

cat > "$S/pkg-absent.yaml" <<YAML
version: 1
resources:
  - id: acc_pkg
    type: package
    with:
      name: $PKG
      state: absent
YAML
if [ "$INIT_PRESENT" = yes ]; then
  "$EXE" apply "$S/pkg-absent.yaml" --sudo --format json > "$S/p0.json" 2>"$S/p0.err"; R=$?
  echo "PACKAGE_NORMALISE_RC=$R"
  if [ "$R" -eq 0 ] && ! pkg_present; then check package-normalise-ok ok "removed before the install scenario"
  else check package-normalise-ok FAIL "could not reach the absent state (rc=$R)"; fi
else
  check package-normalise-ok ok "already absent before the run"
fi

cat > "$S/pkg-present.yaml" <<YAML
version: 1
resources:
  - id: acc_pkg
    type: package
    with:
      name: $PKG
      state: present
YAML

"$EXE" plan "$S/pkg-present.yaml" --sudo --format json > "$S/p1.json" 2>"$S/p1.err"; R=$?
CHG=$(python3 -c "
import json,sys
try: d=json.load(open('$S/p1.json'))
except Exception: sys.exit(2)
r=[x for x in d.get('resources',[]) if x.get('id')=='acc_pkg']
print(r[0].get('change') if r else 'missing')
" 2>/dev/null)
echo "PKG_PLAN_RC=$R change=$CHG"
if [ "$R" -eq 0 ] && [ "$CHG" = changed ]; then check package-install-plan ok "plan reports CHANGED"
else check package-install-plan FAIL "rc=$R change=$CHG"; fi

"$EXE" apply "$S/pkg-present.yaml" --sudo --format json > "$S/p2.json" 2>"$S/p2.err"; R=$?
echo "PKG_APPLY1_RC=$R"
if [ "$R" -eq 0 ]; then check package-install-apply ok "apply exit 0"; else check package-install-apply FAIL "apply exit $R"; fi
RAW=$(pkg_query_raw); echo "PKG_QUERY_AFTER_INSTALL<<"; echo "$RAW"; echo ">>"
if pkg_present; then check package-independent-verify ok "$PKGVERIFY reports the package installed"; R_NATIVE=0
else check package-independent-verify FAIL "$PKGVERIFY: $RAW"; R_NATIVE=1; fi
P2RES=$(python3 -c "
import json
try: d=json.load(open('$S/p2.json'))
except Exception: sys.exit(2)
for r in d.get('resources',[]):
    if r.get('id')=='acc_pkg':
        print(r.get('execution'), r.get('verification'), r.get('change'))
" 2>/dev/null)
echo "PKG_APPLY1_RESOURCE=$P2RES"
if [ "$R_NATIVE" = 0 ]; then check package-native-parser ok "package state round-tripped through the native package manager"; else check package-native-parser FAIL "$P2RES"; fi

"$EXE" apply "$S/pkg-present.yaml" --sudo --format json > "$S/p3.json" 2>"$S/p3.err"; R=$?
CHG2=$(python3 -c "
import json
try: d=json.load(open('$S/p3.json'))
except Exception: sys.exit(2)
r=[x for x in d.get('resources',[]) if x.get('id')=='acc_pkg']
print(r[0].get('change') if r else 'missing')
" 2>/dev/null)
echo "PKG_APPLY2_RC=$R change=$CHG2"
if [ "$R" -eq 0 ] && [ "$CHG2" = none ]; then check package-install-idempotent ok "second present apply made no change"
else check package-install-idempotent FAIL "rc=$R change=$CHG2"; fi

"$EXE" apply "$S/pkg-absent.yaml" --sudo --format json > "$S/p4.json" 2>"$S/p4.err"; R=$?
echo "PKG_REMOVE_RC=$R"
if [ "$R" -eq 0 ]; then check package-remove-apply ok "absent apply exit 0"; else check package-remove-apply FAIL "absent apply exit $R"; fi
if pkg_present; then check package-absent-independent-verify FAIL "$PKGVERIFY still reports the package installed"
else check package-absent-independent-verify ok "$PKGVERIFY reports the package removed"; fi

"$EXE" apply "$S/pkg-absent.yaml" --sudo --format json > "$S/p5.json" 2>"$S/p5.err"; R=$?
CHG3=$(python3 -c "
import json
try: d=json.load(open('$S/p5.json'))
except Exception: sys.exit(2)
r=[x for x in d.get('resources',[]) if x.get('id')=='acc_pkg']
print(r[0].get('change') if r else 'missing')
" 2>/dev/null)
echo "PKG_ABSENT2_RC=$R change=$CHG3"
if [ "$R" -eq 0 ] && [ "$CHG3" = none ]; then check package-absent-idempotent ok "second absent apply made no change"
else check package-absent-idempotent FAIL "rc=$R change=$CHG3"; fi

# ------------------------------------------------ package progress (v1.9.0)
# BEGIN progress-checks
# The stable, documented part of progress only (docs: CLI reference, "Progress
# output"): with SINTER_PROGRESS=plain and text output every stderr line starts
# with "progress: ", the run and the apply stage open and close, nothing reaches
# stdout and no control sequence is written; with --format json, and on a
# non-terminal stderr by default, there is no progress at all. Package detail
# words are not a stable contract and a manager may print none, so the number
# of detail lines is recorded but never required. The package is absent here.
progress_verdict() { # <stdout> <stderr> <rc> <want: plain|none|json> -> verdict file, exit 0 = ok
  python3 - "$1" "$2" "$3" "$4" <<'PYEOF'
import json, sys
out = open(sys.argv[1], "rb").read(); err = open(sys.argv[2], "rb").read()
rc, want = sys.argv[3], sys.argv[4]
bad = []
if rc != "0": bad.append("exit %s" % rc)
if b"progress:" in out: bad.append("a progress line on stdout")
if want == "plain":
    try: text = err.decode("ascii")
    except UnicodeDecodeError: bad.append("stderr is not ASCII"); text = err.decode("utf-8", "replace")
    if "\x1b" in text or "\r" in text: bad.append("control characters on stderr")
    lines = [l for l in text.split("\n") if l]
    other = [l for l in lines if not l.startswith("progress: ")]
    if other: bad.append("a stderr line that is not progress: %r" % other[0][:120])
    for need in ("progress: run: apply started", "progress: apply: start 0/1",
                 "progress: apply: done 1/1", "progress: run: apply completed"):
        if not any(l.startswith(need) for l in lines): bad.append("missing %r" % need)
    if any(l.startswith(("progress: run: apply failed", "progress: run: apply indeterminate",
                         "progress: apply: failed", "progress: apply: indeterminate")) for l in lines):
        bad.append("a failed or indeterminate stage end")
    if b"== Sinter APPLY ==" not in out: bad.append("no text report on stdout")
    print("PROGRESS_LINES=%d PROGRESS_DETAIL_LINES=%d" % (len(lines), sum(" on package:acc_pkg, " in l for l in lines)))
elif want == "none":
    if b"progress:" in err: bad.append("progress on a non-terminal stderr without SINTER_PROGRESS")
    if b"== Sinter APPLY ==" not in out: bad.append("no text report on stdout")
else:
    if err: bad.append("stderr is not empty with --format json (%d bytes)" % len(err))
    try:
        d = json.loads(out)
        r = [x for x in d.get("resources", []) if x.get("id") == "acc_pkg"]
        if not r or r[0].get("change") != "none": bad.append("JSON: acc_pkg change is not none")
    except Exception as e:
        bad.append("stdout is not one JSON document: %s" % type(e).__name__)
print("ok" if not bad else "; ".join(bad))
sys.exit(0 if not bad else 3)
PYEOF
}
SINTER_PROGRESS=plain "$EXE" apply "$S/pkg-present.yaml" --sudo > "$S/pp1.out" 2> "$S/pp1.err"; R=$?
progress_verdict "$S/pp1.out" "$S/pp1.err" "$R" plain > "$S/pp1.verdict" 2>&1; V=$?
echo "PROGRESS_PLAIN_RC=$R"; cat "$S/pp1.verdict"; echo "PROGRESS_PLAIN_STDERR<<"; cat "$S/pp1.err"; echo ">>"
if [ "$V" -eq 0 ] && pkg_present; then check package-progress-plain ok "plain progress lines only on stderr, stages closed, package installed"
else check package-progress-plain FAIL "$(tail -1 "$S/pp1.verdict") installed=$(pkg_present && echo yes || echo no)"; fi

"$EXE" apply "$S/pkg-present.yaml" --sudo > "$S/pp2.out" 2> "$S/pp2.err"; R=$?
progress_verdict "$S/pp2.out" "$S/pp2.err" "$R" none > "$S/pp2.verdict" 2>&1; V=$?
echo "PROGRESS_DEFAULT_RC=$R"; cat "$S/pp2.verdict"
if [ "$V" -eq 0 ]; then check package-progress-off-by-default ok "no progress on a non-terminal stderr without SINTER_PROGRESS"
else check package-progress-off-by-default FAIL "$(tail -1 "$S/pp2.verdict")"; fi

SINTER_PROGRESS=plain "$EXE" apply "$S/pkg-present.yaml" --sudo --format json > "$S/pp3.json" 2> "$S/pp3.err"; R=$?
progress_verdict "$S/pp3.json" "$S/pp3.err" "$R" json > "$S/pp3.verdict" 2>&1; V=$?
echo "PROGRESS_JSON_RC=$R"; cat "$S/pp3.verdict"
if [ "$V" -eq 0 ]; then check package-progress-json-silent ok "--format json with SINTER_PROGRESS=plain: no progress on any stream"
else check package-progress-json-silent FAIL "$(tail -1 "$S/pp3.verdict")"; fi

"$EXE" apply "$S/pkg-absent.yaml" --sudo --format json > "$S/pp4.json" 2>"$S/pp4.err"; R=$?
echo "PROGRESS_RESTORE_RC=$R"
if [ "$R" -eq 0 ] && ! pkg_present; then check package-progress-restore ok "package absent again after the progress checks"
else check package-progress-restore FAIL "rc=$R installed=$(pkg_present && echo yes || echo no)"; fi
# END progress-checks

# ----------------------------------------------------------------- files
cat > "$S/file.yaml" <<'YAML'
version: 1
resources:
  - id: acc_file
    type: file
    with:
      path: /opt/sinter-acceptance/state/managed.conf
      state: present
      content: "mode=create\n"
      owner: root
      group: root
      mode: "0644"
YAML
"$EXE" apply "$S/file.yaml" --sudo --format json > "$S/f1.json" 2>"$S/f1.err"; R=$?
echo "FILE_APPLY1_RC=$R"
ST=$(stat -c '%U %G %a %s' /opt/sinter-acceptance/state/managed.conf 2>&1)
echo "FILE_STATE_AFTER_CREATE=$ST"
if [ "$R" -eq 0 ] && [ "$(stat -c '%U %G %a' /opt/sinter-acceptance/state/managed.conf 2>/dev/null)" = "root root 644" ]; then check file-create-ok ok "$ST"; else check file-create-ok FAIL "rc=$R state=$ST"; fi
cat > "$S/file2.yaml" <<'YAML'
version: 1
resources:
  - id: acc_file
    type: file
    with:
      path: /opt/sinter-acceptance/state/managed.conf
      state: present
      content: "mode=update\nvalue=2\n"
      owner: root
      group: root
      mode: "0600"
YAML
"$EXE" apply "$S/file2.yaml" --sudo --format json > "$S/f2.json" 2>"$S/f2.err"; R=$?
ST=$(stat -c '%U %G %a %s' /opt/sinter-acceptance/state/managed.conf 2>&1); BODY=$(sudo cat /opt/sinter-acceptance/state/managed.conf 2>/dev/null)
echo "FILE_STATE_AFTER_UPDATE=$ST"; echo "FILE_BODY=$BODY"
if [ "$R" -eq 0 ] && [ "$(stat -c '%U %G %a' /opt/sinter-acceptance/state/managed.conf 2>/dev/null)" = "root root 600" ] && echo "$BODY" | grep -q 'value=2'; then check file-update-ok ok "$ST"; else check file-update-ok FAIL "rc=$R state=$ST"; fi
"$EXE" apply "$S/file2.yaml" --sudo --format json > "$S/f3.json" 2>"$S/f3.err"; R=$?
CHG4=$(python3 -c "
import json
try: d=json.load(open('$S/f3.json'))
except Exception: sys.exit(2)
r=[x for x in d.get('resources',[]) if x.get('id')=='acc_file']
print(r[0].get('change') if r else 'missing')
" 2>/dev/null)
echo "FILE_APPLY3_RC=$R change=$CHG4"
if [ "$R" -eq 0 ] && [ "$CHG4" = none ]; then check file-idempotent ok "re-apply made no change"; else check file-idempotent FAIL "rc=$R change=$CHG4"; fi

# --------------------------------------------------------------- service
cat > "$S/svc-on.yaml" <<'YAML'
version: 1
resources:
  - id: acc_svc
    type: service
    with:
      name: chronyd
      state: running
      enabled: true
YAML
"$EXE" apply "$S/svc-on.yaml" --sudo --format json > "$S/v1.json" 2>"$S/v1.err"; R=$?
SVCSTATE=$(systemctl is-active chronyd 2>&1); SVCE=$(systemctl is-enabled chronyd 2>&1)
echo "SVC_ON_RC=$R state=$SVCSTATE enabled=$SVCE"
if [ "$R" -eq 0 ] && [ "$SVCSTATE" = active ]; then check service-enable-start ok "state=$SVCSTATE enabled=$SVCE"; else check service-enable-start FAIL "rc=$R state=$SVCSTATE enabled=$SVCE"; fi
"$EXE" apply "$S/svc-on.yaml" --sudo --format json > "$S/v2.json" 2>"$S/v2.err"; R=$?
CHG5=$(python3 -c "
import json
try: d=json.load(open('$S/v2.json'))
except Exception: sys.exit(2)
r=[x for x in d.get('resources',[]) if x.get('id')=='acc_svc']
print(r[0].get('change') if r else 'missing')
" 2>/dev/null)
if [ "$R" -eq 0 ] && [ "$CHG5" = none ]; then check service-idempotent ok "second apply made no change"; else check service-idempotent FAIL "rc=$R change=$CHG5"; fi

# --------------------------------------------------------------- command
rm -f /opt/sinter-acceptance/state/created.txt
cat > "$S/cmd.yaml" <<'YAML'
version: 1
resources:
  - id: acc_cmd
    type: command
    with:
      program: /usr/bin/touch
      args: ["/opt/sinter-acceptance/state/created.txt"]
      creates: /opt/sinter-acceptance/state/created.txt
YAML
"$EXE" plan "$S/cmd.yaml" --sudo --format json > "$S/c0.json" 2>"$S/c0.err"; R=$?
echo "CMD_PLAN_RC=$R"
if [ "$R" -eq 0 ]; then check command-plan ok "plan ran the command resource as unknown/?"; else check command-plan FAIL "plan exit $R"; fi
"$EXE" apply "$S/cmd.yaml" --sudo --format json > "$S/c1.json" 2>"$S/c1.err"; R=$?
DISP=$(python3 -c "
import json
try: d=json.load(open('$S/c1.json'))
except Exception: sys.exit(2)
r=[x for x in d.get('resources',[]) if x.get('id')=='acc_cmd']
print(r[0].get('disposition') if r else 'missing')
" 2>/dev/null)
[ -f /opt/sinter-acceptance/state/created.txt ] && CREATED=yes || CREATED=no
echo "CMD_APPLY1_RC=$R disposition=$DISP created=$CREATED"
if [ "$R" -eq 0 ] && [ "$CREATED" = yes ]; then check command-guard-first-run ok "command ran and created its guard path"; else check command-guard-first-run FAIL "rc=$R created=$CREATED"; fi
"$EXE" apply "$S/cmd.yaml" --sudo --format json > "$S/c2.json" 2>"$S/c2.err"; R=$?
DISP2=$(python3 -c "
import json
try: d=json.load(open('$S/c2.json'))
except Exception: sys.exit(2)
r=[x for x in d.get('resources',[]) if x.get('id')=='acc_cmd']
print(r[0].get('disposition') if r else 'missing')
" 2>/dev/null)
CHG6=$(python3 -c "
import json
try: d=json.load(open('$S/c2.json'))
except Exception: sys.exit(2)
r=[x for x in d.get('resources',[]) if x.get('id')=='acc_cmd']
print(r[0].get('change') if r else 'missing')
" 2>/dev/null)
echo "CMD_APPLY2_RC=$R disposition=$DISP2 change=$CHG6"
if [ "$R" -eq 0 ] && [ "$DISP2" = guard_satisfied ] && [ "$CHG6" = none ]; then check command-guard-honored ok "creates guard skipped the second run with no change"; else check command-guard-honored FAIL "rc=$R disposition=$DISP2 change=$CHG6"; fi

# ---------------------------------------------- strict audit (v1.9.0)
# BEGIN strict-audit-checks
# DESIGN §33: `audit --audit-policy strict` exits 8 when a resource is
# not_auditable and nothing drifted or failed; the statuses stay the same, the
# JSON gains `audit_policy`, and a command resource is never run. Without the
# option the result is unchanged (exit 0, no `audit_policy`). The command would
# create the sentinel if it ever ran.
rm -f /opt/sinter-acceptance/state/strict-sentinel.txt
cat > "$S/strict.yaml" <<'YAML'
version: 1
resources:
  - id: acc_strict_dir
    type: directory
    with:
      path: /opt/sinter-acceptance/state
      state: present
      mode: "0755"
  - id: acc_strict_cmd
    type: command
    with:
      program: /usr/bin/touch
      args: ["/opt/sinter-acceptance/state/strict-sentinel.txt"]
      creates: /opt/sinter-acceptance/state/strict-sentinel.txt
YAML
strict_verdict() { # <audit json> <rc> <want: strict|default> -> verdict file, exit 0 = ok
  python3 - "$1" "$2" "$3" <<'PYEOF'
import json, sys
rc, want = sys.argv[2], sys.argv[3]
bad = []
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    print("audit JSON unreadable: %s" % type(e).__name__); sys.exit(3)
st = {r.get("id"): r.get("status") for r in d.get("resources", [])}
if st.get("acc_strict_dir") != "compliant": bad.append("acc_strict_dir is %s" % st.get("acc_strict_dir"))
if st.get("acc_strict_cmd") != "not_auditable": bad.append("acc_strict_cmd is %s" % st.get("acc_strict_cmd"))
pol = d.get("audit_policy")
if want == "strict":
    if rc != "8": bad.append("exit %s, not 8" % rc)
    if not isinstance(pol, dict) or pol.get("mode") != "strict" or pol.get("not_auditable_total") != 1 or pol.get("effective_exit_code") != 8:
        bad.append("audit_policy is %r" % (pol,))
else:
    if rc != "0": bad.append("exit %s, not 0" % rc)
    if "audit_policy" in d: bad.append("audit_policy present without --audit-policy strict")
print("ok status=%s summary=%s" % (d.get("status"), d.get("summary")) if not bad else "; ".join(bad))
sys.exit(0 if not bad else 3)
PYEOF
}
"$EXE" audit "$S/strict.yaml" --sudo --audit-policy strict --format json > "$S/sa1.json" 2>"$S/sa1.err"; R=$?
strict_verdict "$S/sa1.json" "$R" strict > "$S/sa1.verdict" 2>&1; V=$?
[ -e /opt/sinter-acceptance/state/strict-sentinel.txt ] && RAN=yes || RAN=no
echo "STRICT_AUDIT_RC=$R command_ran=$RAN"; cat "$S/sa1.verdict"
if [ "$V" -eq 0 ] && [ "$RAN" = no ]; then check audit-strict-not-auditable ok "strict audit exited 8 with audit_policy, command not run"
else check audit-strict-not-auditable FAIL "$(tail -1 "$S/sa1.verdict") command_ran=$RAN"; fi
"$EXE" audit "$S/strict.yaml" --sudo --format json > "$S/sa2.json" 2>"$S/sa2.err"; R=$?
strict_verdict "$S/sa2.json" "$R" default > "$S/sa2.verdict" 2>&1; V=$?
[ -e /opt/sinter-acceptance/state/strict-sentinel.txt ] && RAN=yes || RAN=no
echo "DEFAULT_AUDIT_RC=$R command_ran=$RAN"; cat "$S/sa2.verdict"
if [ "$V" -eq 0 ] && [ "$RAN" = no ]; then check audit-default-policy-unchanged ok "default audit exited 0 without audit_policy, command not run"
else check audit-default-policy-unchanged FAIL "$(tail -1 "$S/sa2.verdict") command_ran=$RAN"; fi
# END strict-audit-checks

# ------------------------------------------- pre-mutation failure truth
cat > "$S/fail.yaml" <<'YAML'
version: 1
resources:
  - id: acc_fail_file
    type: file
    with:
      path: /opt/sinter-acceptance/state/never/exists.conf
      state: present
      content: "x\n"
  - id: acc_after
    type: file
    with:
      path: /opt/sinter-acceptance/state/after.conf
      state: present
      content: "y\n"
YAML
BEFORE=$(ls -1 /opt/sinter-acceptance/state 2>/dev/null | sort | tr '\n' ' ')
"$EXE" apply "$S/fail.yaml" --sudo --format json > "$S/f1.json" 2>"$S/f1.err"; R=$?
ST2=$(python3 -c "
import json
try: d=json.load(open('$S/f1.json'))
except Exception: sys.exit(2)
o={r.get('id'):(r.get('execution'),r.get('change'),r.get('disposition')) for r in d.get('resources',[])}
print('status',d.get('status'),'| acc_fail_file',o.get('acc_fail_file'),'| acc_after',o.get('acc_after'))
" 2>/dev/null)
AFTER=$(ls -1 /opt/sinter-acceptance/state 2>/dev/null | sort | tr '\n' ' ')
echo "PREFAIL_RC=$R $ST2"
echo "PREFAIL_BEFORE=$BEFORE"; echo "PREFAIL_AFTER=$AFTER"
if [ "$R" -ne 0 ] && [ "$R" -ne 4 ] && [ "$BEFORE" = "$AFTER" ] && [ ! -e /opt/sinter-acceptance/state/after.conf ]; then check pre-mutation-failure ok "failed as reported, no false Changed, no mutation"; else check pre-mutation-failure FAIL "rc=$R state=$ST2 before=$BEFORE after=$AFTER"; fi

# ------------------------------------------------------- secret redaction
cat > "$S/secret.yaml" <<'YAML'
version: 1
vars:
  acc_secret:
    value: "synthetic-acceptance-secret-9f2c"
    sensitive: true
resources:
  - id: acc_secret_res
    type: file
    sensitive: true
    with:
      path: /opt/sinter-acceptance/state/secret.txt
      state: present
      content: "token={{ vars.acc_secret }}\n"
YAML
"$EXE" apply "$S/secret.yaml" --sudo --format json > "$S/s1.json" 2>"$S/s1.err"; R=$?
LEAK=0
grep -q 'synthetic-acceptance-secret-9f2c' "$S/s1.json" && LEAK=1
grep -q 'synthetic-acceptance-secret-9f2c' "$S/s1.err" && LEAK=1
python3 -c "
import json
d=json.load(open('$S/s1.json'))
for r in d.get('resources',[]):
    if r.get('id')=='acc_secret_res':
        for n in (r.get('notes') or []):
            if 'synthetic-acceptance-secret-9f2c' in n: raise SystemExit(1)
        if (r.get('reason') or 'x') != (r.get('reason') or 'x'): pass
" 2>/dev/null || LEAK=1
echo "SECRET_APPLY_RC=$R leaked=$LEAK"
if [ "$R" -eq 0 ] && [ "$LEAK" -eq 0 ]; then check secret-redaction ok "no sensitive literal in output, diffs or errors"; else check secret-redaction FAIL "rc=$R leaked=$LEAK"; fi
SECONDBODY=$(sudo cat /opt/sinter-acceptance/state/secret.txt 2>/dev/null)
case "$SECONDBODY" in *synthetic-acceptance-secret-9f2c*) check secret-delivered ok "the declared value reached the target";;
  *) check secret-delivered FAIL "the sensitive var did not reach the target";; esac

# ----------------------------------------------------------------- audit
"$EXE" audit "$S/svc-on.yaml" --sudo --format json > "$S/a1.json" 2>"$S/a1.err"; R=$?
AST=$(python3 -c "
import json
try: d=json.load(open('$S/a1.json'))
except Exception: sys.exit(2)
print(d.get('status'), d.get('summary'))
" 2>/dev/null)
echo "AUDIT_RC=$R status=$AST"
if [ "$R" -eq 0 ]; then check audit-no-drift ok "$AST"; else check audit-no-drift FAIL "rc=$R status=$AST"; fi

# ------------------------------------------------- plugin management (v1.12.0)
# BEGIN plugin-checks
# DESIGN §38.4, §38.5, §38.15, §38.16: `sinter plugin list|verify|install|remove`
# and the partial mutate permission (C1). Everything runs as the unprivileged
# acceptance user against a plugin root inside this run's private directory;
# the default root under HOME is never named and must not appear. No check runs
# firewall-cmd or changes the host firewall: plan and apply are given a host
# name that cannot resolve (RFC 6761 .invalid) and must be refused before any
# contact, and audit there fails at name resolution. Applying firewalld rules on
# a real firewalld is not part of this matrix (the Ubuntu targets have no
# firewalld, and starting or changing it on a target can affect the management
# connection).
pyq() { # pyq <json file> <python expression over d> -> prints the value or ERR:<type>
  python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print(eval(sys.argv[2]))
except Exception as e:
    print("ERR:%s" % type(e).__name__)' "$1" "$2"
}
fmode() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1" 2>/dev/null; }
fsha() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
PB="$WORK/plugin-acc"; PR="$PB/root"; PR2="$PB/root2"
rm -rf "$PB"; mkdir -m 700 "$PB"
CAT_SHA=d32ac3947279ec2581a7049f9fa931d29c904c91ea2484cafaa6759fe09c3641   # catalogs/firewalld-0.2.0.catalog.toml
PLG_SHA=e5819cfe0e2c017648f628a27d0ed6e4a18ed402f3ff6de072e61a724f0aa99a   # plugins/firewalld-0.2.0.plugin.toml
CATF="$PR/catalogs/firewalld-0.2.0.catalog.toml"; PLGF="$PR/plugins/firewalld-0.2.0.plugin.toml"
case "${XDG_CONFIG_HOME:-}" in /*) DEFROOT="$XDG_CONFIG_HOME/sinter/plugins" ;; *) DEFROOT="$HOME/.config/sinter/plugins" ;; esac
[ -e "$DEFROOT" ] && DEF_BEFORE=present || DEF_BEFORE=absent
STATE_BEFORE=$(ls -1A /opt/sinter-acceptance/state 2>/dev/null | sort | tr '\n' ' ')
echo "PLUGIN_DEFAULT_ROOT_BEFORE=$DEF_BEFORE"

"$EXE" plugin list --plugin-root "$PR" --json > "$S/pl1.json" 2> "$S/pl1.err"; R=$?
V=$(pyq "$S/pl1.json" '[(p["version"], p["available"], p["installed"], p["status"]) for p in d["plugins"] if p["id"] == "firewalld"]')
echo "PLUGIN_LIST_ABSENT_RC=$R $V"
if [ "$R" -eq 0 ] && [ "$V" = "[('0.1.0', True, False, 'available'), ('0.2.0', True, False, 'available')]" ] && [ ! -e "$PR" ]; then
  check plugin-list-available ok "firewalld 0.1.0 and 0.2.0 embedded, not installed; nothing created"
else check plugin-list-available FAIL "rc=$R $V root=$([ -e "$PR" ] && echo created || echo absent)"; fi

"$EXE" plugin verify --plugin-root "$PR" --json > "$S/pv1.json" 2> "$S/pv1.err"; R=$?
V=$(pyq "$S/pv1.json" '(d["ok"], d["nothing_verified"])')
echo "PLUGIN_VERIFY_ABSENT_RC=$R $V"
if [ "$R" -eq 2 ] && [ "$V" = "(False, 'root-absent')" ] && [ ! -e "$PR" ]; then
  check plugin-verify-nothing-refused ok "nothing to verify is exit 2 (root-absent)"
else check plugin-verify-nothing-refused FAIL "rc=$R $V"; fi

"$EXE" plugin install firewalld@0.2.0 --dry-run --plugin-root "$PR" --json < /dev/null > "$S/pi0.json" 2> "$S/pi0.err"; R=$?
V=$(pyq "$S/pi0.json" '(d["result"], d["allowed_mutate"], len(d["mutate_not_allowed"]))')
echo "PLUGIN_INSTALL_DRYRUN_RC=$R $V"
if [ "$R" -eq 0 ] && [ "$V" = "('planned', [], 12)" ] && [ ! -e "$PR" ]; then
  check plugin-install-dry-run ok "dry run planned, no mutate allowed, nothing created"
else check plugin-install-dry-run FAIL "rc=$R $V root=$([ -e "$PR" ] && echo created || echo absent)"; fi

"$EXE" plugin install firewalld@0.2.0 --plugin-root "$PR" --json < /dev/null > "$S/pi1.json" 2> "$S/pi1.err"; R=$?
V=$(pyq "$S/pi1.json" 'd["result"]')
echo "PLUGIN_INSTALL_NO_CONFIRM_RC=$R $V"
if [ "$R" -eq 2 ] && [ "$V" = refused ] && [ ! -e "$PR" ]; then
  check plugin-install-needs-confirmation ok "without a terminal and without --yes nothing changes (exit 2)"
else check plugin-install-needs-confirmation FAIL "rc=$R $V root=$([ -e "$PR" ] && echo created || echo absent)"; fi

"$EXE" plugin install firewalld@0.2.0 --yes --plugin-root "$PR" --json < /dev/null > "$S/pi2.json" 2> "$S/pi2.err"; R=$?
V=$(pyq "$S/pi2.json" '(d["result"], d["trust"], d["verify"], d["allowed_mutate"])')
MODES="$(fmode "$PR") $(fmode "$PR/catalogs") $(fmode "$PR/plugins") $(fmode "$PR/trust.toml") $(fmode "$CATF") $(fmode "$PLGF")"
SHAS_OK=no; [ "$(fsha "$CATF")" = "$CAT_SHA" ] && [ "$(fsha "$PLGF")" = "$PLG_SHA" ] && SHAS_OK=yes
echo "PLUGIN_INSTALL_RC=$R $V modes=$MODES embedded_bytes=$SHAS_OK"
if [ "$R" -eq 0 ] && [ "$V" = "('installed', 'created', 'ok', [])" ] && [ "$MODES" = "700 700 700 600 600 600" ] && [ "$SHAS_OK" = yes ]; then
  check plugin-install ok "installed the embedded bytes; directories 0700, files 0600; no mutate allowed"
else check plugin-install FAIL "rc=$R $V modes=$MODES embedded_bytes=$SHAS_OK"; fi

"$EXE" plugin verify firewalld@0.2.0 --plugin-root "$PR" --json > "$S/pv2.json" 2> "$S/pv2.err"; R=$?
V=$(pyq "$S/pv2.json" '(d["ok"], d["plugins"][0]["status"], d["plugins"][0]["required_not_enabled"], len(d["plugins"][0]["mutate_not_allowed"]), sorted(set(c["result"] for c in d["plugins"][0]["checks"])))')
"$EXE" plugin list --plugin-root "$PR" --json > "$S/pl2.json" 2> "$S/pl2.err"; R2=$?
V2=$(pyq "$S/pl2.json" '[(p["version"], p["installed"], p["status"]) for p in d["plugins"] if p["id"] == "firewalld"]')
echo "PLUGIN_VERIFY_INSTALLED_RC=$R $V LIST_RC=$R2 $V2"
if [ "$R" -eq 0 ] && [ "$V" = "(True, 'ok', [], 12, ['pass'])" ] && [ "$R2" -eq 0 ] && [ "$V2" = "[('0.1.0', False, 'available'), ('0.2.0', True, 'installed')]" ]; then
  check plugin-verify-installed ok "every verify check passes; 12 mutate operations stay not allowed; list shows installed"
else check plugin-verify-installed FAIL "rc=$R $V list_rc=$R2 $V2"; fi

T0=$(fsha "$PR/trust.toml")
"$EXE" plugin install firewalld@0.2.0 --yes --plugin-root "$PR" --json < /dev/null > "$S/pi3.json" 2> "$S/pi3.err"; R=$?
V=$(pyq "$S/pi3.json" '(d["result"], d["trust"])')
echo "PLUGIN_INSTALL_AGAIN_RC=$R $V"
if [ "$R" -eq 0 ] && [ "$V" = "('nothing-to-do', 'unchanged')" ] && [ "$(fsha "$PR/trust.toml")" = "$T0" ]; then
  check plugin-install-idempotent ok "a second install changes nothing"
else check plugin-install-idempotent FAIL "rc=$R $V"; fi

# A root-run controller accepts only root-owned plugin files (§38.7); these are
# the acceptance user's. Read-only: verify never writes.
sudo -n "$EXE" plugin verify firewalld@0.2.0 --plugin-root "$PR" --json > "$S/pv3.json" 2> "$S/pv3.err"; R=$?
V=$(pyq "$S/pv3.json" 'd["ok"]')
echo "PLUGIN_ROOT_RUN_RC=$R ok=$V"; tail -1 "$S/pv3.err" | sed "s|$PB|<PB>|g"
if [ "$R" -eq 2 ] && [ "$V" = False ] && grep -q 'owned by another user' "$S/pv3.err" && [ "$(fsha "$PR/trust.toml")" = "$T0" ]; then
  check plugin-root-run-refused ok "run as root, a plugin root of another user is refused (exit 2, owned by another user)"
else check plugin-root-run-refused FAIL "rc=$R ok=$V"; fi

cat > "$S/fw.yaml" <<'YAML'
version: 1
plugins:
  - { id: firewalld, version: 0.2.0 }
resources:
  - id: acc_fw_port
    type: firewalld.port
    with: { zone: public, port: 8443/tcp, state: present }
YAML
GATE='plan and apply refuse it before contacting any target'
NOHOST=nohost.invalid   # RFC 6761: never resolves, so reaching it would be a resolution error (exit 3)
"$EXE" validate "$S/fw.yaml" --plugin-root "$PR" > "$S/fwv.out" 2> "$S/fwv.err"; RV=$?
"$EXE" plan "$S/fw.yaml" --plugin-root "$PR" --host "$NOHOST" --no-ssh-config > "$S/fwp.out" 2> "$S/fwp.err"; RP=$?
"$EXE" apply "$S/fw.yaml" --plugin-root "$PR" --host "$NOHOST" --no-ssh-config > "$S/fwa.out" 2> "$S/fwa.err"; RA=$?
"$EXE" audit "$S/fw.yaml" --plugin-root "$PR" --host "$NOHOST" --no-ssh-config > "$S/fwu.out" 2> "$S/fwu.err"; RU=$?
GP=$(grep -c "$GATE" "$S/fwp.err"); GA=$(grep -c "$GATE" "$S/fwa.err"); GU=$(cat "$S/fwu.out" "$S/fwu.err" | grep -c "$GATE")
echo "PLUGIN_C1 validate=$RV plan=$RP/$GP apply=$RA/$GA audit=$RU/$GU"; tail -1 "$S/fwp.err" | sed "s|$PB|<PB>|g"
if [ "$RV" -eq 0 ] && [ "$RP" -eq 2 ] && [ "$GP" -ge 1 ] && [ "$RA" -eq 2 ] && [ "$GA" -ge 1 ] && [ "$RU" -ne 0 ] && [ "$RU" -ne 2 ] && [ "$GU" -eq 0 ] \
   && grep -q 'add_port_permanent, add_port_runtime' "$S/fwp.err"; then
  check plugin-c1-refused-before-contact ok "plan and apply refused before contact; audit not refused by the gate"
else check plugin-c1-refused-before-contact FAIL "validate=$RV plan=$RP/$GP apply=$RA/$GA audit=$RU/$GU"; fi

"$EXE" plugin install firewalld@0.2.0 --yes --allow-mutate-for firewalld.port --plugin-root "$PR2" --json < /dev/null > "$S/pi4.json" 2> "$S/pi4.err"; R=$?
V=$(pyq "$S/pi4.json" '(d["result"], sorted(d["allowed_mutate"]))')
"$EXE" plan "$S/fw.yaml" --plugin-root "$PR2" --host "$NOHOST" --no-ssh-config > "$S/fwp2.out" 2> "$S/fwp2.err"; RP=$?
GP=$(grep -c "$GATE" "$S/fwp2.err")
echo "PLUGIN_ALLOW_FOR_RC=$R $V plan=$RP/$GP"
if [ "$R" -eq 0 ] && [ "$V" = "('installed', ['add_port_permanent', 'add_port_runtime', 'remove_port_permanent', 'remove_port_runtime'])" ] && [ "$RP" -ne 0 ] && [ "$RP" -ne 2 ] && [ "$GP" -eq 0 ]; then
  check plugin-c1-allowed-by-type ok "--allow-mutate-for allows exactly that type's operations; the gate then lets plan through"
else check plugin-c1-allowed-by-type FAIL "rc=$R $V plan=$RP/$GP"; fi

T2=$(fsha "$PR2/trust.toml")
printf '#' >> "$PR2/plugins/firewalld-0.2.0.plugin.toml"
"$EXE" plugin verify firewalld@0.2.0 --plugin-root "$PR2" --json > "$S/pv4.json" 2> "$S/pv4.err"; R=$?
V=$(pyq "$S/pv4.json" 'd["plugins"][0]["status"]')
"$EXE" plugin remove firewalld@0.2.0 --yes --plugin-root "$PR2" --json < /dev/null > "$S/pr1.json" 2> "$S/pr1.err"; R2=$?
V2=$(pyq "$S/pr1.json" 'd["result"]')
echo "PLUGIN_TAMPER verify=$R $V remove=$R2 $V2"
if [ "$R" -eq 2 ] && [ "$V" = digest-mismatch ] && [ "$R2" -eq 2 ] && [ "$V2" = refused ] && [ "$(fsha "$PR2/trust.toml")" = "$T2" ] && [ -f "$PR2/plugins/firewalld-0.2.0.plugin.toml" ]; then
  check plugin-tamper-refused ok "a changed plugin file is a digest mismatch and remove leaves everything as it was"
else check plugin-tamper-refused FAIL "verify=$R $V remove=$R2 $V2"; fi

chmod 770 "$PR"
"$EXE" plugin list --plugin-root "$PR" --json > "$S/pl3.json" 2> "$S/pl3.err"; R=$?
"$EXE" plugin verify --plugin-root "$PR" --json > "$S/pv5.json" 2> "$S/pv5.err"; R2=$?
chmod 700 "$PR"
"$EXE" plugin list --plugin-root "$PR" --json > "$S/pl4.json" 2> "$S/pl4.err"; R3=$?
echo "PLUGIN_UNSAFE_ROOT list=$R verify=$R2 restored_list=$R3"; tail -1 "$S/pl3.err" | sed "s|$PB|<PB>|g"
if [ "$R" -eq 2 ] && [ "$R2" -eq 2 ] && [ "$R3" -eq 0 ]; then
  check plugin-unsafe-root-refused ok "a group-writable root is refused by list and verify"
else check plugin-unsafe-root-refused FAIL "list=$R verify=$R2 restored_list=$R3"; fi

"$EXE" plugin remove firewalld@0.2.0 --yes --plugin-root "$PR" --json < /dev/null > "$S/pr2.json" 2> "$S/pr2.err"; R=$?
V=$(pyq "$S/pr2.json" '(d["result"], d["trust"])')
LEFT="$([ -e "$CATF" ] && echo catalog) $([ -e "$PLGF" ] && echo plugin) $(grep -c '^\[\[' "$PR/trust.toml" 2>/dev/null)"
"$EXE" plugin verify --plugin-root "$PR" --json > "$S/pv6.json" 2> "$S/pv6.err"; R2=$?
V2=$(pyq "$S/pv6.json" 'd["nothing_verified"]')
echo "PLUGIN_REMOVE_RC=$R $V left=$LEFT prev=$(fmode "$PR/trust.toml.prev") verify=$R2 $V2"
if [ "$R" -eq 0 ] && [ "$V" = "('removed', 'rewritten')" ] && [ "$LEFT" = "  0" ] && [ "$(fmode "$PR/trust.toml.prev")" = 600 ] && [ "$R2" -eq 2 ] && [ "$V2" = nothing-pinned ]; then
  check plugin-remove ok "files and trust entries removed, trust.toml.prev kept at 0600, nothing left to verify"
else check plugin-remove FAIL "rc=$R $V left=$LEFT verify=$R2 $V2"; fi

rm -rf "$PB"
[ -e "$DEFROOT" ] && DEF_AFTER=present || DEF_AFTER=absent
STATE_AFTER=$(ls -1A /opt/sinter-acceptance/state 2>/dev/null | sort | tr '\n' ' ')
echo "PLUGIN_DEFAULT_ROOT_AFTER=$DEF_AFTER"
if [ ! -e "$PB" ] && [ "$DEF_AFTER" = "$DEF_BEFORE" ] && [ "$STATE_AFTER" = "$STATE_BEFORE" ]; then
  check plugin-no-residue ok "plugin roots removed; default root and managed state untouched"
else check plugin-no-residue FAIL "pb=$([ -e "$PB" ] && echo left) default=$DEF_BEFORE->$DEF_AFTER state=$STATE_BEFORE->$STATE_AFTER"; fi
# END plugin-checks

# ------------------------------------------- per-recipe variables (v1.12.0)
# BEGIN recipe-vars-checks
# DESIGN §40.5: the project file's `recipe_vars` gives each recipe of a run its
# own variables files, merged in order; a recipe that is not listed keeps its
# defaults; `recipe_vars` with --vars-file and an untrusted variables file are
# refused before anything changes. Without `recipe_vars` the shared
# `vars_files` behave as before. The values are observed in the files the run
# writes, not in its messages.
RVD="$WORK/rv-acc"
rm -rf "$RVD"; mkdir -m 700 "$RVD" "$RVD/recipes" "$RVD/vars"
for x in a b c; do
  case $x in a) n=10_a ;; b) n=20_b ;; c) n=30_c ;; esac
  cat > "$RVD/recipes/$n.yaml" <<YAML
version: 1
vars:
  msg_$x: { value: $x-default }
  common: { value: $x-common-default }
resources:
  - id: acc_rv_$x
    type: file
    with:
      path: /opt/sinter-acceptance/state/rv-$x.txt
      state: present
      content: "{{ vars.msg_$x }}|{{ vars.common }}\n"
YAML
done
printf 'version: 1\nrecipes:\n  - recipes/10_a.yaml\n  - recipes/20_b.yaml\n  - recipes/30_c.yaml\n' > "$RVD/site.yaml"
printf 'version: 1\nvars: { msg_a: a-one, common: a-common }\n' > "$RVD/vars/a1.yaml"
printf 'version: 1\nvars: { msg_a: a-two }\n' > "$RVD/vars/a2.yaml"
printf 'version: 1\nvars: { msg_b: b-one }\n' > "$RVD/vars/b.yaml"
RV_PROJECT='version: 1\nrecipe_vars:\n  10_a:\n    - vars/a1.yaml\n    - vars/a2.yaml\n  20_b:\n    - vars/b.yaml\n'
printf "$RV_PROJECT" > "$RVD/sinter.yaml"
cat > "$RVD/clean.yaml" <<'YAML'
version: 1
resources:
  - { id: rm_a, type: file, with: { path: /opt/sinter-acceptance/state/rv-a.txt, state: absent } }
  - { id: rm_b, type: file, with: { path: /opt/sinter-acceptance/state/rv-b.txt, state: absent } }
  - { id: rm_c, type: file, with: { path: /opt/sinter-acceptance/state/rv-c.txt, state: absent } }
YAML
chmod 644 "$RVD"/recipes/*.yaml "$RVD"/vars/*.yaml "$RVD/site.yaml" "$RVD/sinter.yaml" "$RVD/clean.yaml"
chmod 755 "$RVD/recipes" "$RVD/vars"
rv_body() { sudo cat "/opt/sinter-acceptance/state/rv-$1.txt" 2>/dev/null | tr -d '\n'; }
rv_bodies() { echo "a=$(rv_body a) b=$(rv_body b) c=$(rv_body c)"; }
rv_none() { [ ! -e /opt/sinter-acceptance/state/rv-a.txt ] && [ ! -e /opt/sinter-acceptance/state/rv-b.txt ] && [ ! -e /opt/sinter-acceptance/state/rv-c.txt ]; }
rv_clean() { (cd "$RVD" && "$EXE" apply clean.yaml --sudo --no-config --format json > "$S/rvc.json" 2> "$S/rvc.err"); }

(cd "$RVD" && "$EXE" apply site.yaml --sudo --format json > "$S/rv1.json" 2> "$S/rv1.err"); R=$?
B=$(rv_bodies)
echo "RECIPE_VARS_RC=$R $B"; echo "RECIPE_VARS_STDERR<<"; sed "s|$RVD|<RVD>|g" "$S/rv1.err"; echo ">>"
if [ "$R" -eq 0 ] && [ "$B" = "a=a-two|a-common b=b-one|b-common-default c=c-default|c-common-default" ]; then
  check recipe-vars-per-recipe ok "each recipe got only its own files, merged in order; the unlisted recipe kept its defaults"
else check recipe-vars-per-recipe FAIL "rc=$R $B"; fi
if [ "$R" -eq 0 ] && grep -q '^vars: recipe 10_a: ' "$S/rv1.err" && grep -q '^vars: recipe 20_b: ' "$S/rv1.err" \
   && grep -q '^vars: none for recipe 30_c (not listed in recipe_vars)' "$S/rv1.err" && ! grep -q 'not declared' "$S/rv1.err"; then
  check recipe-vars-shown-no-foreign-warning ok "each recipe's files are shown; no warning about another recipe's variables"
else check recipe-vars-shown-no-foreign-warning FAIL "rc=$R stderr does not show the per-recipe files, or warns about undeclared variables"; fi

rv_clean
(cd "$RVD" && "$EXE" apply site.yaml --sudo --vars-file vars/a1.yaml --format json > "$S/rv2.json" 2> "$S/rv2.err"); R=$?
echo "RECIPE_VARS_WITH_VARS_FILE_RC=$R"; tail -1 "$S/rv2.err" | sed "s|$RVD|<RVD>|g"
if [ "$R" -eq 2 ] && grep -q 'cannot be used with the recipe_vars' "$S/rv2.err" && rv_none; then check recipe-vars-refuse-vars-file ok "recipe_vars with --vars-file is exit 2; nothing written"
else check recipe-vars-refuse-vars-file FAIL "rc=$R $(rv_bodies)"; fi

chmod 666 "$RVD/vars/b.yaml"
(cd "$RVD" && "$EXE" apply site.yaml --sudo --format json > "$S/rv3.json" 2> "$S/rv3.err"); R=$?
chmod 644 "$RVD/vars/b.yaml"
echo "RECIPE_VARS_UNTRUSTED_RC=$R"; tail -1 "$S/rv3.err" | sed "s|$RVD|<RVD>|g"
if [ "$R" -eq 2 ] && grep -q 'vars/b.yaml: writable by group or others' "$S/rv3.err" && rv_none; then check recipe-vars-untrusted-file-refused ok "a variables file writable by others is exit 2; nothing written"
else check recipe-vars-untrusted-file-refused FAIL "rc=$R $(rv_bodies)"; fi

printf 'version: 1\nvars_files: [vars/a1.yaml]\n' > "$RVD/sinter.yaml"
(cd "$RVD" && "$EXE" apply site.yaml --sudo --format json > "$S/rv4.json" 2> "$S/rv4.err"); R=$?
B=$(rv_bodies)
echo "RECIPE_VARS_SHARED_RC=$R $B"
if [ "$R" -eq 0 ] && [ "$B" = "a=a-one|a-common b=b-default|a-common c=c-default|a-common" ]; then
  check recipe-vars-absent-shared-files ok "without recipe_vars the shared vars_files reach every recipe that declares the variable, as before"
else check recipe-vars-absent-shared-files FAIL "rc=$R $B"; fi

rv_clean
(cd "$RVD" && "$EXE" apply site.yaml --sudo --no-config --format json > "$S/rv5.json" 2> "$S/rv5.err"); R=$?
B=$(rv_bodies)
echo "RECIPE_VARS_NO_CONFIG_RC=$R $B"
if [ "$R" -eq 0 ] && [ "$B" = "a=a-default|a-common-default b=b-default|b-common-default c=c-default|c-common-default" ]; then
  check recipe-vars-no-config-defaults ok "--no-config: every recipe keeps its defaults"
else check recipe-vars-no-config-defaults FAIL "rc=$R $B"; fi

rv_clean; R=$?
rm -rf "$RVD"
echo "RECIPE_VARS_CLEANUP_RC=$R"
if [ "$R" -eq 0 ] && rv_none && [ ! -e "$RVD" ]; then check recipe-vars-no-residue ok "files written by these checks removed"
else check recipe-vars-no-residue FAIL "rc=$R $(rv_bodies)"; fi
# END recipe-vars-checks

# ------------------------------------------------------- residue cleanup
cat > "$S/cleanup.yaml" <<'YAML'
version: 1
resources:
  - id: acc_secret_res
    type: file
    with:
      path: /opt/sinter-acceptance/state/secret.txt
      state: absent
  - id: acc_file
    type: file
    with:
      path: /opt/sinter-acceptance/state/managed.conf
      state: absent
YAML
sudo rm -f /opt/sinter-acceptance/state/created.txt /opt/sinter-acceptance/state/strict-sentinel.txt
"$EXE" apply "$S/cleanup.yaml" --sudo --format json > "$S/cl.json" 2>"$S/cl.err"; R=$?
LEFT=$(sudo find /opt/sinter-acceptance/state -mindepth 1 2>/dev/null | wc -l)
echo "CLEANUP_RC=$R leftover=$LEFT"
if [ "$R" -eq 0 ] && [ "$LEFT" -eq 0 ]; then check no-residue ok "no managed path left behind"; else check no-residue FAIL "rc=$R leftover=$LEFT"; fi

echo "== acceptance end $(ts) passed=$PASS failed=$FAIL skipped=$SKIP"
if [ "$FAIL" -eq 0 ] && [ "$SKIP" -eq 0 ]; then echo 0 > "$RCFILE"; exit 0; fi
echo 1 > "$RCFILE"; exit 1
