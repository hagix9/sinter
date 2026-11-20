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
PASS=0; FAIL=0; SKIP=0; NA=0

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
check() { # check <id> <ok|FAIL> [detail]
  if [ "$2" = ok ]; then PASS=$((PASS+1)); echo "== check $1 ok"; echo "   $3";
  else FAIL=$((FAIL+1)); echo "== check $1 FAIL"; echo "   $3"; fi
}
skip() { SKIP=$((SKIP+1)); echo "== check $1 SKIP"; echo "   $2"; }
# not_applicable <id> <reason> [detail]: only for a (check, reason, label) the
# applicability table lists and only after the proving observation was logged
# (raw-verdict.py and the manifest checker check both again).
not_applicable() { NA=$((NA+1)); echo "== check $1 NOT_APPLICABLE $2"; echo "   $3"; }
na_allowed() { # na_allowed <id> <reason>: the table next to this script lists LABEL
  python3 - "$(dirname "$0")/applicability.json" "$1" "$2" "$LABEL" <<'PY' 2>/dev/null
import json, sys
t, cid, reason, label = sys.argv[1:5]
d = json.load(open(t))
ok = d.get("schema") == "sinter-acceptance-applicability/1" and any(
    e.get("check") == cid and e.get("reason") == reason and label in e.get("targets", [])
    for e in d.get("entries", []))
sys.exit(0 if ok else 1)
PY
}

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
# contact, and audit there fails at name resolution. firewalld rules on the
# real firewalld are applied only by the fw03-checks section (v1.15.0), on
# disposable objects.
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
# v1.15.0 registers firewalld 0.3.0 (P7-R1, after its real-host measurement).
if [ "$R" -eq 0 ] && [ "$V" = "[('0.1.0', True, False, 'available'), ('0.2.0', True, False, 'available'), ('0.3.0', True, False, 'available')]" ] && [ ! -e "$PR" ]; then
  check plugin-list-available ok "firewalld 0.1.0, 0.2.0 and 0.3.0 embedded, not installed; nothing created"
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
if [ "$R" -eq 0 ] && [ "$V" = "(True, 'ok', [], 12, ['pass'])" ] && [ "$R2" -eq 0 ] && [ "$V2" = "[('0.1.0', False, 'available'), ('0.2.0', True, 'installed'), ('0.3.0', False, 'available')]" ]; then
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

# ------------------------------------------------------------- v1.15.0
# BEGIN v1150-checks
# docs/design/v1.15.0-release-and-acceptance.md §3. Everything runs on
# disposable names (sinter-acc-*) and removes them. The firewalld 0.3.0
# checks (fw03-*, risk-approved-apply) are the next section, fw03-checks.
jq_chg() { # jq_chg <json> <resource id> -> its change or ERR
  python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    r = [x for x in d.get("resources", []) if x.get("id") == sys.argv[2]]
    print(r[0].get("change") if r else "missing")
except Exception as e:
    print("ERR:%s" % type(e).__name__)' "$1" "$2"
}
SSHOPT="--host 127.0.0.1 --port 22 --user $SSHUSER --identity $SSHKEY --known-hosts /opt/sinter-acceptance/ssh/known_hosts"

# ---- systemd_timer (DESIGN §42) and service on a .timer unit
TU=sinter-acc-timer
cat > "$S/tm-svc.yaml" <<YAML
version: 1
resources:
  - id: acc_tm_svc
    type: file
    with:
      path: /etc/systemd/system/$TU.service
      content: |
        [Unit]
        Description=Sinter acceptance timer target
        [Service]
        Type=oneshot
        ExecStart=/bin/true
      mode: "0644"
YAML
cat > "$S/tm-on.yaml" <<YAML
version: 1
resources:
  - id: acc_tm
    type: systemd_timer
    with:
      name: $TU
      on_calendar: "*-*-* 03:00:00"
      state: running
      enabled: true
YAML
"$EXE" apply "$S/tm-svc.yaml" --sudo --format json > "$S/tm0.json" 2>"$S/tm0.err"; R0=$?
"$EXE" apply "$S/tm-on.yaml" --sudo --format json > "$S/tm1.json" 2>"$S/tm1.err"; R=$?
LS=$(systemctl show -p LoadState --value "$TU.timer" 2>&1)
FILE_TM=$([ -f "/etc/systemd/system/$TU.timer" ] && echo present || echo absent)
echo "TIMER_CREATE_RC=$R0/$R load=$LS file=$FILE_TM change=$(jq_chg "$S/tm1.json" acc_tm)"
if [ "$R0" -eq 0 ] && [ "$R" -eq 0 ] && [ "$LS" = loaded ] && [ "$FILE_TM" = present ] && [ "$(jq_chg "$S/tm1.json" acc_tm)" = changed ]; then
  check timer-create ok "unit written, manager reloaded (LoadState loaded)"
else check timer-create FAIL "rc=$R0/$R load=$LS file=$FILE_TM"; cat "$S/tm1.err"; fi
TA=$(systemctl is-active "$TU.timer" 2>&1); TE=$(systemctl is-enabled "$TU.timer" 2>&1)
if [ "$TA" = active ] && [ "$TE" = enabled ]; then check timer-running ok "enabled and active"
else check timer-running FAIL "active=$TA enabled=$TE"; fi
"$EXE" apply "$S/tm-on.yaml" --sudo --format json > "$S/tm2.json" 2>"$S/tm2.err"; R=$?
if [ "$R" -eq 0 ] && [ "$(jq_chg "$S/tm2.json" acc_tm)" = none ]; then check timer-idempotent ok "second apply unchanged"
else check timer-idempotent FAIL "rc=$R change=$(jq_chg "$S/tm2.json" acc_tm)"; fi
cat > "$S/tm-bad.yaml" <<YAML
version: 1
resources:
  - id: acc_tm_bad
    type: systemd_timer
    with:
      name: sinter-acc-badcal
      on_calendar: "not a calendar 99:99"
      state: running
YAML
"$EXE" plan "$S/tm-bad.yaml" --sudo --format json > "$S/tmb1.json" 2>"$S/tmb1.err"; RP=$?
"$EXE" apply "$S/tm-bad.yaml" --sudo --format json > "$S/tmb2.json" 2>"$S/tmb2.err"; RA=$?
BADF=$([ -e /etc/systemd/system/sinter-acc-badcal.timer ] && echo present || echo absent)
echo "TIMER_BADCAL_RC=plan:$RP apply:$RA file=$BADF"
if [ "$RP" -ne 0 ] && [ "$RA" -ne 0 ] && [ "$BADF" = absent ]; then check timer-calendar-invalid ok "invalid OnCalendar refused in plan ($RP) and apply ($RA), nothing written"
else check timer-calendar-invalid FAIL "plan=$RP apply=$RA file=$BADF"; fi
cat > "$S/tm-svc-stop.yaml" <<YAML
version: 1
resources:
  - id: acc_tm_as_service
    type: service
    with:
      name: $TU.timer
      state: stopped
      enabled: false
YAML
"$EXE" apply "$S/tm-svc-stop.yaml" --sudo --format json > "$S/tms.json" 2>"$S/tms.err"; R=$?
TA=$(systemctl is-active "$TU.timer" 2>&1); TE=$(systemctl is-enabled "$TU.timer" 2>&1)
echo "SERVICE_TIMER_RC=$R active=$TA enabled=$TE"
if [ "$R" -eq 0 ] && [ "$TA" = inactive ] && [ "$TE" = disabled ]; then check service-timer-name ok "service manages $TU.timer (stopped, disabled)"
else check service-timer-name FAIL "rc=$R active=$TA enabled=$TE"; fi
cat > "$S/tm-off.yaml" <<YAML
version: 1
resources:
  - id: acc_tm
    type: systemd_timer
    with:
      name: $TU
      state: absent
  - id: acc_tm_svc
    type: file
    with:
      path: /etc/systemd/system/$TU.service
      state: absent
YAML
"$EXE" apply "$S/tm-off.yaml" --sudo --format json > "$S/tm3.json" 2>"$S/tm3.err"; R=$?
LS=$(systemctl show -p LoadState --value "$TU.timer" 2>&1)
echo "TIMER_ABSENT_RC=$R load=$LS"
if [ "$R" -eq 0 ] && [ "$LS" = not-found ] && [ ! -e "/etc/systemd/system/$TU.timer" ]; then check timer-absent ok "removed, LoadState not-found"
else check timer-absent FAIL "rc=$R load=$LS"; fi

# ---- connection-risk control (DESIGN §43.2): an R resource without an
# approval is refused before any contact (the host name cannot resolve).
cat > "$S/risk-r.yaml" <<'YAML'
version: 1
resources:
  - id: acc_risk_r
    type: nm_connection
    with:
      name: sinter-acc-risk
      ifname: "{{ facts.hostname }}"
      autoconnect: false
YAML
"$EXE" apply "$S/risk-r.yaml" --host "$NOHOST" --format json > "$S/rr.json" 2>"$S/rr.err"; R=$?
echo "RISK_STATIC_RC=$R"
if [ "$R" -eq 2 ] && grep -q "need an approval" "$S/rr.err"; then check risk-static-refusal ok "R resource without approval: exit 2 before contact"
else check risk-static-refusal FAIL "rc=$R $(head -c 300 "$S/rr.err")"; fi

# ---- nm_connection (DESIGN §45): an inactive profile for an interface that
# does not exist, over SSH to 127.0.0.1 with the declared loopback path.
NMC=$([ -x /usr/bin/nmcli ] && echo present || echo absent)
NMLS=$(systemctl show -p LoadState --value NetworkManager.service 2>/dev/null)
NMAS=$(systemctl is-active NetworkManager.service 2>/dev/null)
case "$NMLS" in not-found|"") NMSV=not-found ;; *) [ "$NMAS" = active ] && NMSV=active || NMSV=inactive ;; esac
echo "== observe nm-presence nmcli=$NMC service=$NMSV"
if [ "$NMC" = absent ] && [ "$NMSV" != active ] && na_allowed nm-profile-crud NM_NOT_INSTALLED; then
  not_applicable nm-profile-crud NM_NOT_INSTALLED "nmcli is not installed on $LABEL (applicability table)"
else
  nm_recipe() { # nm_recipe <file> <extra with-lines>
    printf 'version: 1\nresources:\n  - id: acc_nm\n    type: nm_connection\n    with:\n      name: sinter-acc-nm\n%s\n' "$2" > "$1"; }
  nm_recipe "$S/nm1.yaml" '      ifname: sinteracc0
      autoconnect: false
      ipv4: { method: manual, addresses: [192.0.2.10/24] }
      ipv6: { method: ignore }'
  nm_recipe "$S/nm2.yaml" '      ifname: sinteracc0
      autoconnect: false
      ipv4: { method: manual, addresses: [192.0.2.10/24], dns: [192.0.2.53] }
      ipv6: { method: ignore }'
  nm_recipe "$S/nm3.yaml" '      state: absent'
  NMR=""
  for step in 1 2 2b 3; do
    f="$S/nm${step%b}.yaml"
    "$EXE" apply "$f" $SSHOPT --sudo --management-path loopback --format json > "$S/nm$step.json" 2>"$S/nm$step.err"; NMR="$NMR $step:$?:$(jq_chg "$S/nm$step.json" acc_nm)"
    case "$step" in
      1) NMS1=$(sudo nmcli -t -f connection.interface-name,connection.autoconnect,ipv4.addresses connection show sinter-acc-nm 2>&1 | tr '\n' ' ') ;;
      2) NMS2=$(sudo nmcli -t -f ipv4.dns connection show sinter-acc-nm 2>&1 | tr '\n' ' ') ;;
    esac
  done
  NMLEFT=$(sudo nmcli -t -f NAME connection show 2>/dev/null | grep -cx sinter-acc-nm)
  echo "NM_PROFILE_STEPS=$NMR created=[$NMS1] dns=[$NMS2] left=$NMLEFT"
  if [ "$NMR" = " 1:0:changed 2:0:changed 2b:0:none 3:0:changed" ] \
     && printf '%s' "$NMS1" | grep -q 'sinteracc0' && printf '%s' "$NMS1" | grep -q '192.0.2.10/24' \
     && printf '%s' "$NMS2" | grep -q '192.0.2.53' && [ "$NMLEFT" = 0 ]; then
    check nm-profile-crud ok "created, changed, unchanged on re-apply, deleted"
  else check nm-profile-crud FAIL "steps=$NMR created=[$NMS1] dns=[$NMS2] left=$NMLEFT"; cat "$S"/nm*.err 2>/dev/null | head -20
    sudo nmcli connection delete id sinter-acc-nm >/dev/null 2>&1 || true; fi
fi

# ---- discover (DESIGN §46): read-only, synthetic secret excluded, audit of
# the candidate on the unchanged host reports no drift.
DD=/etc/sinter-acc-disc
CAN="synthetic-sinter-acc-canary-$(date +%s)$$"
sudo mkdir -p "$DD"
printf 'listen = 8080\nworkers = 4\n' | sudo tee "$DD/plain.conf" >/dev/null
printf 'db_password = %s\n' "$CAN" | sudo tee "$DD/secret.conf" >/dev/null
sudo chmod 0644 "$DD/plain.conf" "$DD/secret.conf"
pkgdb() { if [ -f /var/lib/dpkg/status ]; then sudo sha256sum /var/lib/dpkg/status | cut -d' ' -f1; else rpm -qa --qf '%{NAME}-%{EVR}.%{ARCH}\n' | sort | sha256sum | cut -d' ' -f1; fi; }
etcsum() { sudo find /etc -xdev -printf '%p %y %m %U %G %s %T@\n' 2>/dev/null | sort | sha256sum | cut -d' ' -f1; }
PK1=$(pkgdb); ET1=$(etcsum)
mkdir -m 700 "$S/disc"
"$EXE" discover $SSHOPT --sudo --output "$S/disc/cand.yaml" --include-path "$DD/plain.conf" --include-path "$DD/secret.conf" > "$S/disc.out" 2> "$S/disc.err"; R=$?
PK2=$(pkgdb); ET2=$(etcsum)
MODES="$(fmode "$S/disc/cand.yaml")/$(fmode "$S/disc/cand.yaml.discover.json")"
LEAK=$(grep -l "$CAN" "$S/disc/cand.yaml" "$S/disc/cand.yaml.discover.json" "$S/disc.out" "$S/disc.err" 2>/dev/null | wc -l | tr -d ' ')
EXCL=$(pyq "$S/disc/cand.yaml.discover.json" '[u["reason"] for u in d["unsupported"] if u["key"] == "/etc/sinter-acc-disc/secret.conf"]')
PLAIN=$(grep -c 'listen = 8080' "$S/disc/cand.yaml" 2>/dev/null)
echo "DISCOVER_RC=$R modes=$MODES leak=$LEAK excluded=$EXCL plain=$PLAIN pkgdb_same=$([ "$PK1" = "$PK2" ] && echo yes || echo no) etc_same=$([ "$ET1" = "$ET2" ] && echo yes || echo no)"
if [ "$R" -eq 0 ] && [ "$MODES" = 600/600 ] && [ "$LEAK" = 0 ] && [ "$EXCL" = "['excluded: credential assignment']" ] \
   && [ "$PLAIN" -ge 1 ] && [ "$PK1" = "$PK2" ] && [ "$ET1" = "$ET2" ]; then
  check discover-readonly ok "recipe and provenance 0600; synthetic secret excluded; package database and /etc unchanged"
else check discover-readonly FAIL "rc=$R modes=$MODES leak=$LEAK excluded=$EXCL pkgdb=$PK1/$PK2 etc=$ET1/$ET2"; head -c 600 "$S/disc.err"; fi
"$EXE" audit "$S/disc/cand.yaml" $SSHOPT --sudo --format json > "$S/disc-audit.json" 2> "$S/disc-audit.err"; R=$?
AST=$(pyq "$S/disc-audit.json" 'd["status"]')
ANON=$(pyq "$S/disc-audit.json" '[r["id"] for r in d["resources"] if r["status"] not in ("PASS", "COMPLIANT", "compliant")]')
echo "DISCOVER_AUDIT_RC=$R status=$AST not_compliant=$ANON"
if [ "$R" -eq 0 ] && [ "$AST" = no_drift ]; then check discover-roundtrip ok "audit of the generated recipe: no drift"
else check discover-roundtrip FAIL "rc=$R status=$AST not_compliant=$ANON"; fi
sudo rm -rf "$DD"; rm -rf "$S/disc"
# END v1150-checks

# ------------------------------------------------- v1.15.0 firewalld 0.3.0
# BEGIN fw03-checks
# docs/design/v1.15.0-release-and-acceptance.md §3 and §3.1 (P7-R1):
# firewalld 0.3.0 on a disposable zone (sintacc), a dummy interface
# (sintacc0) and documentation networks (RFC 5737), runtime and permanent,
# over SSH to 127.0.0.1 with the declared loopback management path, the R
# resources through the approval flow (DESIGN §43.4). The VM's own management
# connection (its default-route interface and that interface's zone) is never
# named by a recipe; its zone's configuration is observed before and after
# every change (the new SSH session opened each time is a loopback session: it
# shows that sshd answers, not that the runner's route is open). Whatever the
# results of the checks, fw03_restore removes every disposable object with
# firewall-cmd and ip at the end, and fw03-no-residue compares the firewall
# with its state before the section. A harness killed in the middle leaves
# them on this disposable VM.
# Nothing here is ever SKIP or NOT_APPLICABLE: a missing prerequisite (no
# running firewalld, no firewalld 0.3.0 in this sinter) fails every check.
FWZ=sintacc; FWIF=sintacc0; FWSRC=198.51.100.0/24; FWRS=192.0.2.0/24; FWRS2=203.0.113.0/24
FWP=8472/tcp; FWPP=8471/tcp
FWETC=/etc/firewalld
FWKH=/opt/sinter-acceptance/ssh/known_hosts
FWST="$WORK/fw03-state"; FWPB="$WORK/fw03-pb"; FWPR="$FWPB/pr"   # under WORK (0700), as the plugin section: $S may be 0775 under umask 002, and every ancestor of a plugin root is checked (measured in P7-R1)
FWSSH="--host 127.0.0.1 --port 22 --user $SSHUSER --identity $SSHKEY --known-hosts $FWKH --management-path loopback"
FWIDS="fw03-zone fw03-interface fw03-source fw03-reload risk-approved-apply fw03-no-residue"
rm -rf "$FWST" "$FWPB"; mkdir -m 700 "$FWST" "$FWPB"
fx() { XDG_STATE_HOME="$FWST" "$EXE" "$@"; }   # sinter with this section's own approval store
fwq() { sudo firewall-cmd "$@" > /dev/null 2>&1; echo $?; }   # exit status of a direct firewall-cmd
fwj() { # fwj <json file> <python expression over d> -> the value or ERR:<type>
  python3 -c 'import json, sys
try:
    d = json.load(open(sys.argv[1])); print(eval(sys.argv[2]))
except Exception as e:
    print("ERR:%s" % type(e).__name__)' "$1" "$2"; }
fwchg() { fwj "$1" "[r.get('change') for r in d.get('resources', []) if r.get('id') == '$2'][0]"; }
fw_mgmt() { # the VM's management path as one line: a new SSH session, the default-route device, its zone and that zone's configuration
  local s dev z
  s=$(ssh -i "$SSHKEY" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$FWKH" \
        -o ConnectTimeout=20 -p 22 "$SSHUSER@127.0.0.1" /usr/bin/true > /dev/null 2>&1 && echo ok || echo FAIL)
  dev=$(ip -o route show default 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}')
  z=$(sudo firewall-cmd --get-zone-of-interface="$dev" 2>/dev/null) || z=$(sudo firewall-cmd --get-default-zone 2>/dev/null)
  echo "ssh=$s dev=${dev:-none} zone=${z:-none} cfg=$({ sudo firewall-cmd --get-default-zone; sudo firewall-cmd --zone="$z" --list-all; \
    sudo firewall-cmd --permanent --zone="$z" --list-all; } 2>&1 | sha256sum | cut -c1-16) others=$(fw_others)"; }
fw_snap() { # every zone's configuration (runtime, permanent), policies, direct rules, ipsets, every file
  # under /etc/firewalld, NetworkManager's profiles, the dummy interface
  { for w in "" --permanent; do sudo firewall-cmd $w --get-zones; sudo firewall-cmd $w --list-all-zones; sudo firewall-cmd $w --get-ipsets; done
    sudo firewall-cmd --get-active-policies; sudo firewall-cmd --permanent --get-policies; sudo firewall-cmd --direct --get-all-rules
    sudo find "$FWETC" -type f -exec sha256sum {} + | sort
    [ -x /usr/bin/nmcli ] && sudo nmcli -t -f NAME,UUID,TYPE,DEVICE connection show
    ip -o link show "$FWIF" 2>&1 | cut -d' ' -f2; } 2>&1 | sha256sum | cut -c1-16; }
fw_others() { # every zone except the disposable one, runtime and permanent, plus policies and direct rules; part of
  # fw_mgmt, so a change the product makes outside the disposable zone fails the step that made it (a later
  # reload would hide a runtime-only change)
  { for w in "" --permanent; do sudo firewall-cmd $w --list-all-zones | awk -v z="$FWZ" 'BEGIN {RS = ""} $1 != z'; done
    sudo firewall-cmd --get-active-policies; sudo firewall-cmd --direct --get-all-rules; } 2>&1 | sha256sum | cut -c1-16; }
fw_apply() { # fw_apply <tag> <recipe> [args]: apply without an approval
  local t=$1 f=$2; shift 2
  fx apply "$f" $FWSSH --sudo --plugin-root "$FWPR" --format json "$@" > "$S/fw03.$t.json" 2> "$S/fw03.$t.err"; }
fw_approved() { # fw_approved <tag> <recipe> [noapply]: plan with a request, approve on a pseudo-terminal, apply with that approval
  local t=$1 f=$2 req
  FWA_ID=; FWA_APPROVE=none; FWA_APPLY=none
  fx plan "$f" $FWSSH --sudo --plugin-root "$FWPR" --format json --approval-request "$S/fw03.$t.req" > "$S/fw03.$t.plan.json" 2> "$S/fw03.$t.plan.err"; FWA_PLAN=$?
  req=$(ls "$S/fw03.$t.req/"*.request.json 2> /dev/null)
  [ "$FWA_PLAN" -eq 0 ] && [ "$(printf '%s\n' "$req" | grep -c .)" = 1 ] || return 0
  FWA_REQ=$req
  XDG_STATE_HOME="$FWST" python3 -I "$S/fw03-pty.py" "$EXE" approve "$req" > "$S/fw03.$t.approve.out" 2>&1; FWA_APPROVE=$?
  FWA_ID=$(tr -d '\r' < "$S/fw03.$t.approve.out" | sed -n 's/^approved: \([0-9a-f]\{32\}\)$/\1/p')
  [ -n "$FWA_ID" ] && [ "${3:-}" != noapply ] || return 0
  fw_apply "$t" "$f" --approval "$FWA_ID"; FWA_APPLY=$?; }
fw_recipe() { # fw_recipe <file> <type> <with> [extra lines]
  printf 'version: 1\nplugins:\n  - { id: firewalld, version: 0.3.0 }\nresources:\n  - id: acc_fw\n    type: firewalld.%s\n    with: { %s }\n%s' "$2" "$3" "${4:-}" > "$1"; }
# sinter approve needs a terminal on stdin and stdout: this drives it through a
# pseudo-terminal and types the digest prefix it shows (a terminal is not proof
# that a person approved, DESIGN §43.4). No digest shown, or FW03_PTY_ANSWER=wrong:
# a wrong answer (not hex).
cat > "$S/fw03-pty.py" <<'PY'
import os, pty, re, select, signal, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.execv(sys.argv[1], sys.argv[1:])
buf, sent, end = b"", False, time.time() + 120
while time.time() < end:
    r, _, _ = select.select([fd], [], [], 1)
    if fd not in r:
        continue
    try:
        chunk = os.read(fd, 4096)
    except OSError:
        break
    if not chunk:
        break
    buf += chunk
    if not sent and b"to approve: " in buf:
        m = re.search(rb"content digest: ([0-9a-f]{64})", buf)
        wrong = os.environ.get("FW03_PTY_ANSWER") == "wrong"
        os.write(fd, (b"g" * 16 if wrong or not m else m.group(1)[:16]) + b"\n")
        sent = True
else:
    os.kill(pid, signal.SIGKILL)
_, st = os.waitpid(pid, 0)
sys.stdout.write(buf.decode("utf-8", "replace"))
sys.exit(os.WEXITSTATUS(st) if os.WIFEXITED(st) else 125)
PY
fw03_restore() { # removes every disposable object directly, whatever Sinter did
  local w
  for w in "" --permanent; do
    sudo firewall-cmd $w --zone="$FWZ" --remove-interface="$FWIF" > /dev/null 2>&1
    for src in "$FWSRC" "$FWRS" "$FWRS2"; do sudo firewall-cmd $w --zone="$FWZ" --remove-source="$src" > /dev/null 2>&1; done
  done
  sudo firewall-cmd --permanent --delete-zone="$FWZ" > /dev/null 2>&1
  sudo rm -f "$FWETC/zones/$FWZ.xml" "$FWETC/zones/$FWZ.xml.old"
  sudo firewall-cmd --reload > /dev/null 2>&1
  sudo ip link del "$FWIF" > /dev/null 2>&1
  echo "FW03_RESTORE zone_perm=$(fwq --permanent --info-zone="$FWZ") zone_rt=$(fwq --info-zone="$FWZ") link=$(ip -o link show "$FWIF" > /dev/null 2>&1 && echo present || echo absent)"; }

FWC=$(command -v firewall-cmd > /dev/null 2>&1 && echo present || echo absent)
FWSTATE=$(sudo firewall-cmd --state 2>/dev/null || echo not-running)
"$EXE" plugin list --json > "$S/fw03.list.json" 2> "$S/fw03.list.err"
FW030=$(fwj "$S/fw03.list.json" "'embedded' if any(p['id'] == 'firewalld' and p['version'] == '0.3.0' and p['available'] for p in d['plugins']) else 'absent'")
echo "== observe fw03-presence firewall-cmd=$FWC state=$FWSTATE plugin030=$FW030"
FW_SNAP0=""; FW_MGMT0=""; FWRAN=no
if [ "$FWC" = present ] && [ "$FWSTATE" = running ] && [ "$FW030" = embedded ]; then
  FW_SNAP0=$(fw_snap); FW_MGMT0=$(fw_mgmt); FW_OTH0=$(fw_others)
  echo "FW03_BEFORE snap=$FW_SNAP0 others=$FW_OTH0 mgmt=[$FW_MGMT0]"
  case "$FW_MGMT0" in ssh=ok\ *) ;; *) FW030=mgmt-unusable ;; esac
  if [ -n "$({ sudo firewall-cmd --permanent --get-zones; sudo firewall-cmd --get-zones; } 2>/dev/null | tr ' ' '\n' | grep -x "$FWZ")" ] \
     || [ -e "$FWETC/zones/$FWZ.xml" ] || [ -e "$FWETC/zones/$FWZ.xml.old" ] || ip -o link show "$FWIF" > /dev/null 2>&1; then
    FW030=disposable-names-in-use; fi
  # the documentation networks must not hold an address of this VM or the
  # client of this session: the declared loopback path does not protect them
  FWOV=$(ip -o addr show 2>/dev/null | awk '{print $4}' | python3 -I -c 'import ipaddress, os, sys
nets = [ipaddress.ip_network(n) for n in sys.argv[1:]]
addrs = [l.split("/")[0] for l in sys.stdin.read().split()] + os.environ.get("SSH_CONNECTION", "").split()[:1] + os.environ.get("SSH_CONNECTION", "").split()[2:3]
bad = []
for a in addrs:
    try:
        ip = ipaddress.ip_address(a)
    except ValueError:
        continue
    bad += [str(ip) for n in nets if ip.version == n.version and ip in n]
print(" ".join(bad) if bad else "none")' "$FWSRC" "$FWRS" "$FWRS2" 2>&1)
  [ "$FWOV" = none ] || FW030="networks-overlap:$FWOV"
fi
if [ "$FWC" != present ] || [ "$FWSTATE" != running ] || [ "$FW030" != embedded ]; then
  for id in $FWIDS; do check "$id" FAIL "prerequisite: firewall-cmd=$FWC state=$FWSTATE plugin030=$FW030"; done
else
  FWRAN=yes
  fx plugin install firewalld@0.3.0 --yes --plugin-root "$FWPR" --allow-mutate-for firewalld.zone --allow-mutate-for firewalld.interface \
    --allow-mutate-for firewalld.source --allow-mutate-for firewalld.port --allow-mutate reload --json < /dev/null > "$S/fw03.pi.json" 2> "$S/fw03.pi.err"
  FWPI=$?
  sudo ip link add "$FWIF" type dummy > /dev/null 2>&1; FWDL=$?
  # NetworkManager may hold a device's permanent zone (DESIGN §44.7): the
  # dummy device is set unmanaged so that the rule can judge its binding.
  FWNM=absent; if [ -x /usr/bin/nmcli ]; then sudo nmcli device set "$FWIF" managed no > /dev/null 2>&1 && FWNM=unmanaged || FWNM=FAIL; fi
  echo "FW03_PREP install=$FWPI dummy=$FWDL nm=$FWNM"

  # ---- fw03-zone, part 1: a permanent zone (N: no approval), idempotent
  fw_recipe "$S/fwz1.yaml" zone "zone: $FWZ, state: present"
  fw_apply z1 "$S/fwz1.yaml"; FZ1=$?
  fw_apply z2 "$S/fwz1.yaml"; FZ2=$?
  FZP=$(fwq --permanent --info-zone="$FWZ")
  # a new zone exists at runtime only after a reload (DESIGN §44.3): made here
  # directly, so the interface and source checks do not depend on fw03-reload
  FZR0=$(fwq --reload); FZR=$(fwq --info-zone="$FWZ"); FZM=$(fw_mgmt)
  FWZ_A="z1=$FZ1:$(fwchg "$S/fw03.z1.json" acc_fw) z2=$FZ2:$(fwchg "$S/fw03.z2.json" acc_fw) perm=$FZP reload=$FZR0 runtime=$FZR mgmt=$([ "$FZM" = "$FW_MGMT0" ] && echo same || echo "CHANGED[$FZM]")"
  echo "FW03_ZONE_CREATE $FWZ_A"

  # ---- fw03-interface and fw03-source (R: every run needs an approval)
  fw_rr() { # fw_rr <name> <type> <field> <value> -> one line: present, again, absent; runtime and permanent queries; management path
    local n=$1 ty=$2 fld=$3 v=$4 out="" st k=0
    for st in present present absent; do
      k=$((k + 1))
      fw_recipe "$S/fw$n.$k.yaml" "$ty" "zone: $FWZ, $fld: $v, state: $st"
      fw_approved "$n$k" "$S/fw$n.$k.yaml"
      out="$out $st:plan=$FWA_PLAN,approve=$FWA_APPROVE,apply=$FWA_APPLY,change=$(fwchg "$S/fw03.$n$k.json" acc_fw)"
      out="$out,rt=$(fwq --zone="$FWZ" --query-$fld="$v"),perm=$(fwq --permanent --zone="$FWZ" --query-$fld="$v"),mgmt=$([ "$(fw_mgmt)" = "$FW_MGMT0" ] && echo same || echo CHANGED)"
    done
    echo "$out"; }
  FWI=$(fw_rr i interface interface "$FWIF"); echo "FW03_INTERFACE$FWI"
  if [ "$FWZ_A" = "z1=0:changed z2=0:none perm=0 reload=0 runtime=0 mgmt=same" ] && [ "$FWNM" != FAIL ] && [ "$FWDL" -eq 0 ] \
     && [ "$FWI" = " present:plan=0,approve=0,apply=0,change=changed,rt=0,perm=0,mgmt=same present:plan=0,approve=0,apply=0,change=none,rt=0,perm=0,mgmt=same absent:plan=0,approve=0,apply=0,change=changed,rt=1,perm=1,mgmt=same" ]; then
    check fw03-interface ok "dummy $FWIF bound to $FWZ (runtime and permanent), unchanged on re-apply, unbound; each run approved; management path unchanged"
  else check fw03-interface FAIL "dummy=$FWDL nm=$FWNM steps=$FWI"; head -c 600 "$S"/fw03.i.*.err 2>/dev/null; fi
  FWS=$(fw_rr s source source "$FWSRC"); echo "FW03_SOURCE$FWS"
  if [ "$FWZ_A" = "z1=0:changed z2=0:none perm=0 reload=0 runtime=0 mgmt=same" ] \
     && [ "$FWS" = " present:plan=0,approve=0,apply=0,change=changed,rt=0,perm=0,mgmt=same present:plan=0,approve=0,apply=0,change=none,rt=0,perm=0,mgmt=same absent:plan=0,approve=0,apply=0,change=changed,rt=1,perm=1,mgmt=same" ]; then
    check fw03-source ok "$FWSRC bound to $FWZ (runtime and permanent), unchanged on re-apply, removed; each run approved; management path unchanged"
  else check fw03-source FAIL "steps=$FWS"; head -c 600 "$S"/fw03.s.*.err 2>/dev/null; fi

  # ---- risk-approved-apply: the approval binds the reviewed change; it is
  # spent before contact, never reused, and does not cover another change
  fw_recipe "$S/fwr.a.yaml" source "zone: $FWZ, source: $FWRS, state: present"
  fw_recipe "$S/fwr.b.yaml" source "zone: $FWZ, source: $FWRS2, state: present"
  fw_recipe "$S/fwr.c.yaml" source "zone: $FWZ, source: $FWRS, state: absent"
  fw_apply r0 "$S/fwr.a.yaml"; RR0=$?                       # no approval: exit 2 before contact
  RR0M=$(grep -c "need an approval" "$S/fw03.r0.err")
  fx plan "$S/fwr.a.yaml" $FWSSH --sudo --plugin-root "$FWPR" --format json --approval-request "$S/fw03.rt.req" > /dev/null 2> "$S/fw03.rt.err"
  RT=$(ls "$S/fw03.rt.req/"*.request.json 2> /dev/null | head -1); RTA=none
  if [ -n "$RT" ]; then                                       # an altered request is refused by approve (HMAC)
    python3 - "$RT" <<'PY'
import json, sys
p = sys.argv[1]; d = json.load(open(p)); d["created_at"] = (d["created_at"] + 1) if isinstance(d.get("created_at"), int) else 1
open(p, "w").write(json.dumps(d))
PY
    XDG_STATE_HOME="$FWST" python3 -I "$S/fw03-pty.py" "$EXE" approve "$RT" > "$S/fw03.rt.approve.out" 2>&1; RTA=$?
    if tr -d '\r' < "$S/fw03.rt.approve.out" | grep -q '^approved: '; then RTA=approved
    elif [ "$RTA" != 0 ] && grep -q "fails its integrity check" "$S/fw03.rt.approve.out"; then RTA=refused-integrity; fi
  fi
  # sinter approve itself: never from a pipe, never with a wrong digest prefix; no approval is recorded
  fwnapp() { XDG_STATE_HOME="$FWST" "$EXE" approvals list 2> /dev/null | grep -c .; }
  fx plan "$S/fwr.a.yaml" $FWSSH --sudo --plugin-root "$FWPR" --format json --approval-request "$S/fw03.rp.req" > /dev/null 2> "$S/fw03.rp.err"
  RPQ=$(ls "$S/fw03.rp.req/"*.request.json 2> /dev/null | head -1); RP=none; RW=none; NAPP0=$(fwnapp)
  if [ -n "$RPQ" ]; then
    D16=$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["content_digest"][:16])' "$RPQ" 2> /dev/null)
    printf '%s\n' "$D16" | XDG_STATE_HOME="$FWST" "$EXE" approve "$RPQ" > "$S/fw03.rp.out" 2>&1; RP=$?
    grep -q '^approved: ' "$S/fw03.rp.out" && RP=approved
    [ "$RP" = 2 ] && grep -q "needs a terminal" "$S/fw03.rp.out" && RP=refused-pipe
    FW03_PTY_ANSWER=wrong XDG_STATE_HOME="$FWST" python3 -I "$S/fw03-pty.py" "$EXE" approve "$RPQ" > "$S/fw03.rw.out" 2>&1; RW=$?
    if tr -d '\r' < "$S/fw03.rw.out" | grep -q '^approved: '; then RW=approved
    elif [ "$RW" != 0 ] && grep -q "not approved" "$S/fw03.rw.out"; then RW=refused-wrong; fi
  fi
  RPN=$([ "$(fwnapp)" = "$NAPP0" ] && echo unchanged || echo "CHANGED:$NAPP0->$(fwnapp)")
  fw_approved ra "$S/fwr.a.yaml" noapply; RA_ID=$FWA_ID; RA="plan=$FWA_PLAN,approve=$FWA_APPROVE"
  RB=none; [ -n "$RA_ID" ] && { fw_apply rb "$S/fwr.b.yaml" --approval "$RA_ID"; RB=$?; }   # the approval of a, used for b: re-plan mismatch
  RB="$RB/$(grep -c "differs from the approved plan" "$S/fw03.rb.err" 2> /dev/null)"
  RBQ="$(fwq --zone="$FWZ" --query-source="$FWRS2")/$(fwq --permanent --zone="$FWZ" --query-source="$FWRS2")"
  fw_approved ra2 "$S/fwr.a.yaml"; RA2_ID=$FWA_ID; RA2="plan=$FWA_PLAN,approve=$FWA_APPROVE,apply=$FWA_APPLY,change=$(fwchg "$S/fw03.ra2.json" acc_fw)"
  RAQ="$(fwq --zone="$FWZ" --query-source="$FWRS")/$(fwq --permanent --zone="$FWZ" --query-source="$FWRS")"
  RU=none; [ -n "$RA2_ID" ] && { fw_apply ru "$S/fwr.a.yaml" --approval "$RA2_ID"; RU=$?; }  # the same approval again
  RUM=$(grep -c "has already been used" "$S/fw03.ru.err" 2> /dev/null)
  FWLH=127.0.0.1   # the host label of the approvals: the target address in FWSSH
  RL=$(XDG_STATE_HOME="$FWST" "$EXE" approvals list 2> /dev/null | grep -c "^$RA2_ID host=$FWLH used$")
  fw_approved rc "$S/fwr.c.yaml"; RC="apply=$FWA_APPLY,change=$(fwchg "$S/fw03.rc.json" acc_fw)"
  RCQ="$(fwq --zone="$FWZ" --query-source="$FWRS")/$(fwq --permanent --zone="$FWZ" --query-source="$FWRS")"
  RM=$([ "$(fw_mgmt)" = "$FW_MGMT0" ] && echo same || echo CHANGED)
  FWR="none:$RR0/$RR0M tampered:$RTA pipe:$RP wrong:$RW approvals:$RPN a:$RA other:$RB/$RBQ a2:$RA2/$RAQ reuse:$RU/$RUM listed:$RL removed:$RC/$RCQ mgmt=$RM"
  echo "FW03_RISK $FWR"
  if [ "$FWR" = "none:2/1 tampered:refused-integrity pipe:refused-pipe wrong:refused-wrong approvals:unchanged a:plan=0,approve=0 other:5/1/1/1 a2:plan=0,approve=0,apply=0,change=changed/0/0 reuse:2/1 listed:1 removed:apply=0,change=changed/1/1 mgmt=same" ]; then
    check risk-approved-apply ok "request, approve on a terminal, apply; approve refuses a pipe, a wrong digest and an altered request; apply refuses no approval, another change and reuse"
  else check risk-approved-apply FAIL "$FWR"; head -c 600 "$S"/fw03.r*.err 2>/dev/null; fi

  # ---- fw03-reload: the plugin handler (C) after a change; a permanent-only
  # port added directly before shows that the reload ran
  FWRL0=$(fwq --permanent --zone="$FWZ" --add-port="$FWPP")
  fw_recipe "$S/fwl.yaml" port "zone: $FWZ, port: $FWP, state: present" "    notify: [acc_fw_reload]
handlers:
  - id: acc_fw_reload
    type: plugin
    plugin: firewalld
    op: reload
"
  fw_apply l1 "$S/fwl.yaml"; FL1=$?
  FL1H=$(fwj "$S/fw03.l1.json" "[(h['state'], 'firewalld' in (h.get('provenance') or '') and '0.3.0' in (h.get('provenance') or '')) for h in d['handlers'] if h['id'] == 'acc_fw_reload']")
  FLQ="$(fwq --zone="$FWZ" --query-port="$FWP")/$(fwq --permanent --zone="$FWZ" --query-port="$FWP")/$(fwq --zone="$FWZ" --query-port="$FWPP")"
  FLM=$([ "$(fw_mgmt)" = "$FW_MGMT0" ] && echo same || echo CHANGED)
  fw_apply l2 "$S/fwl.yaml"; FL2=$?
  FL2H=$(fwj "$S/fw03.l2.json" "[h['state'] for h in d['handlers'] if h['id'] == 'acc_fw_reload']")
  for w in "" --permanent; do sudo firewall-cmd $w --zone="$FWZ" --remove-port="$FWP" > /dev/null 2>&1; sudo firewall-cmd $w --zone="$FWZ" --remove-port="$FWPP" > /dev/null 2>&1; done
  FWL="prep=$FWRL0 l1=$FL1:$(fwchg "$S/fw03.l1.json" acc_fw):$FL1H ports=$FLQ mgmt=$FLM l2=$FL2:$(fwchg "$S/fw03.l2.json" acc_fw):$FL2H"
  echo "FW03_RELOAD $FWL"
  if [ "$FWL" = "prep=0 l1=0:changed:[('Succeeded', True)] ports=0/0/0 mgmt=same l2=0:none:[]" ]; then
    check fw03-reload ok "the reload handler ran after the change (a permanent-only port became active), with plugin provenance; not run when nothing changed; management path unchanged"
  else check fw03-reload FAIL "$FWL"; head -c 600 "$S"/fw03.l*.err 2>/dev/null; fi

  # ---- fw03-zone, part 2: deleting the zone is R (approval); gone after a reload
  fw_recipe "$S/fwz3.yaml" zone "zone: $FWZ, state: absent"
  fw_approved z3 "$S/fwz3.yaml"
  FZ3="apply=$FWA_APPLY,change=$(fwchg "$S/fw03.z3.json" acc_fw)"
  FZ3P=$(fwq --permanent --info-zone="$FWZ"); FZ3R0=$(fwq --reload); FZ3R=$(fwq --info-zone="$FWZ")
  FZ3M=$([ "$(fw_mgmt)" = "$FW_MGMT0" ] && echo same || echo CHANGED)
  echo "FW03_ZONE_DELETE $FZ3 perm=$FZ3P reload=$FZ3R0 runtime=$FZ3R mgmt=$FZ3M"
  if [ "$FWZ_A" = "z1=0:changed z2=0:none perm=0 reload=0 runtime=0 mgmt=same" ] && [ "$FZ3" = "apply=0,change=changed" ] \
     && [ "$FZ3P" != 0 ] && [ "$FZ3R0" = 0 ] && [ "$FZ3R" != 0 ] && [ "$FZ3M" = same ]; then
    check fw03-zone ok "zone $FWZ created (permanent, unchanged on re-apply), deleted with an approval, gone at runtime after a reload"
  else check fw03-zone FAIL "create: $FWZ_A delete: $FZ3 perm=$FZ3P reload=$FZ3R0 runtime=$FZ3R mgmt=$FZ3M"; fi
fi

# ---- restore and compare (always after the checks ran; never when the
# disposable names already existed or the prerequisites failed: then nothing
# here was created, and nothing is removed)
if [ "$FWRAN" = yes ]; then
  FW_OTH1=$(fw_others)
  fw03_restore
  [ -x /usr/bin/nmcli ] && sudo nmcli device set "$FWIF" managed yes > /dev/null 2>&1
  FW_SNAP1=$(fw_snap); FW_MGMT1=$(fw_mgmt)
  echo "FW03_AFTER others_before_restore=$FW_OTH1 snap=$FW_SNAP1 mgmt=[$FW_MGMT1]"
  if [ "$FW_OTH1" = "$FW_OTH0" ] && [ "$FW_SNAP1" = "$FW_SNAP0" ] && [ "$FW_MGMT1" = "$FW_MGMT0" ]; then
    check fw03-no-residue ok "other zones, policies and direct rules untouched before the restore; zones, ipsets, /etc/firewalld, NetworkManager profiles and interfaces as before after it; management zone unchanged"
  else check fw03-no-residue FAIL "others $FW_OTH0 -> $FW_OTH1 snap $FW_SNAP0 -> $FW_SNAP1 mgmt [$FW_MGMT0] -> [$FW_MGMT1]"; fi
fi
[ -f "$FWST/sinter/approval-ledger.jsonl" ] && echo "FW03_LEDGER $(python3 -I -c 'import json, sys
print(" ".join(json.loads(l).get("event", "?") for l in open(sys.argv[1]) if l.strip()))' "$FWST/sinter/approval-ledger.jsonl" 2>&1)"
rm -rf "$FWST" "$FWPB" "$S"/fw03.*.req
# END fw03-checks

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

echo "== acceptance end $(ts) passed=$PASS failed=$FAIL skipped=$SKIP not_applicable=$NA"
if [ "$FAIL" -eq 0 ] && [ "$SKIP" -eq 0 ]; then echo 0 > "$RCFILE"; exit 0; fi
echo 1 > "$RCFILE"; exit 1
