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

# ------------------------------------------------------------- v1.16.0
# BEGIN v1160-checks
# docs/design/v1.16.0-release-and-acceptance.md §2-§4. One block per check: it
# writes its recipes below $V6 (the run's private directory), runs the frozen
# sinter on this host with --sudo, compares exit codes and fields of the JSON
# documents, and judges the host itself where it can (stat, the tool's own
# answer). Whatever a block changes on the host is recorded before the change
# and put back at the end of the block, also when the check failed; an armed
# restore that has not run yet runs from the EXIT/TERM trap when the harness
# stops in the middle. Names are disposable (sinter-acc*, /opt/sinter-acc-*,
# /etc/sinter-acc); one that exists before the block is a failed prerequisite
# and is never removed. NOT_APPLICABLE only through na_allowed and after the
# fixed observation line applicability.json names. The "== observe v116-..."
# lines record the raw facts the plan's §4 asks for (evidence, not checks).
# Nothing here restarts sshd, changes a firewall or the network, or reboots.
V6ROOT=""   # the host's root directory; the stand-in tests replace this line only
V6="$S/v116"; rm -rf "$V6"; mkdir -m 700 "$V6"
V6B=/opt/sinter-acc-v116; V6W=/opt/sinter-acc-writable; V6E=/etc/sinter-acc
# Time (README "Time budget"): the section's checks share V6_BUDGET seconds from
# here. v6t gives one command min(its cap, what is left) and runs nothing once
# the budget is spent (exit 124, the check fails); v6r is a restore step with
# its own cap, run also after the budget so that what was changed is put back.
V6_BUDGET=1200   # seconds; the stand-in tests replace this line only
V6_T0=$(date +%s)
v6left() { echo $(( V6_T0 + V6_BUDGET - $(date +%s) )); }
v6t() { local c=$1 l; shift; l=$(v6left); [ "$l" -gt 0 ] || return 124; [ "$l" -lt "$c" ] && c=$l; timeout -k 5 "$c" "$@"; }
v6r() { local c=$1; shift; timeout -k 5 "$c" "$@"; }
v6h() { printf '%s' "$V6ROOT$1"; }   # a host path as the harness itself reaches it
v6j() { # v6j <json file> <python expression over d> -> the value or ERR:<type>
  python3 -I -c 'import json, sys
def R(d):  # the resources of a recipe document, or of every execution of a bundle document
    if isinstance(d, dict) and "executions" in d:
        return [r for e in d["executions"] for r in ((e.get("result") or {}).get("resources") or [])]
    return d.get("resources") or []
def by(d, i):
    m = [r for r in R(d) if r.get("id") == i]
    return m[0] if len(m) == 1 else {}
def C(d): return sorted(set(r.get("change") for r in R(d)))
def ST(d): return sorted(set(r.get("status") for r in R(d)))
def TXT(r): return " ".join([str(r.get("reason") or "")] + [str(n) for n in (r.get("notes") or [])])
def DIM(r): return sorted(x.get("dimension") for x in (r.get("details") or []))
try:
    d = json.load(open(sys.argv[1])); print(eval(sys.argv[2]))
except Exception as e:
    print("ERR:%s" % type(e).__name__)' "$1" "$2"; }
v6x() { # v6x <tag> <plan|apply|audit> <recipe> [args]: the frozen sinter as root, JSON in $V6/<tag>.json, stderr in .err
  local t=$1 c=$2 f=$3; shift 3
  v6t 300 "$EXE" "$c" "$f" --sudo --format json "$@" > "$V6/$t.json" 2> "$V6/$t.err"
  local rc=$?; printf '%s %s rc=%s\n' "$c" "${f##*/}" "$rc" > "$V6/$t.rc"; return $rc; }
v6diag() { # v6diag <tag>...: on a FAIL, what each run of the check said (command, exit code, JSON results or the start of a non-JSON stdout, stderr)
  local t; for t in "$@"; do
    echo "   DIAG $t $(cat "$V6/$t.rc" 2> /dev/null || echo 'not run')"
    echo "   DIAG $t results=$(v6j "$V6/$t.json" '[(r.get("id"), r.get("status"), r.get("change"), r.get("unknown"), TXT(r)[:300]) for r in R(d)]' | cut -c1-1500)"
    [ "$(v6j "$V6/$t.json" '1')" = 1 ] || echo "   DIAG $t stdout=$(head -c 600 "$V6/$t.json" 2> /dev/null | tr '\n' ' ')"
    echo "   DIAG $t stderr=$(head -c 600 "$V6/$t.err" 2> /dev/null | tr '\n' ' ')"
  done; }
v6in() { cat "$V6/$1.json" "$V6/$1.err" 2> /dev/null | grep -qF -- "$2" && echo yes || echo no; }   # v6in <tag> <text>: is it in that run's output
v6e() { head -c 300 "$V6/$1.err" 2> /dev/null | tr '\n' ' '; }
v6st() { sudo stat -c "$2" "$(v6h "$1")" 2> /dev/null || echo missing; }
v6ex() { sudo test -e "$(v6h "$1")" || sudo test -L "$(v6h "$1")"; }
v6body() { sudo cat "$(v6h "$1")" 2> /dev/null; }
v6_now() { # the state of a host path as one word: absent, link:<text>, file:<sha256> or other
  local p; p=$(v6h "$1")
  if sudo test -L "$p"; then echo "link:$(sudo readlink "$p")"
  elif sudo test -f "$p"; then echo "file:$(sudo cat "$p" | sha256sum | cut -d' ' -f1)"
  elif sudo test -e "$p"; then echo other; else echo absent; fi; }
v6_save() { # v6_save <key> <host path>: keep the bytes (or the link, or the absence) for v6_put_back
  v6_now "$2" > "$V6/orig.$1.state"
  case "$(cat "$V6/orig.$1.state")" in file:*) sudo cat "$(v6h "$2")" > "$V6/orig.$1" ;; esac; }
v6_same() { [ "$(v6_now "$2")" = "$(cat "$V6/orig.$1.state" 2> /dev/null)" ]; }
v6_put_back() { # v6_put_back <key> <host path>: the saved bytes rewritten in place, the saved link, or removed when it was absent
  local was p; was=$(cat "$V6/orig.$1.state" 2> /dev/null); p=$(v6h "$2")
  v6_same "$1" "$2" && return 0
  case "$was" in
    file:*) sudo test -L "$p" && sudo rm -f "$p"; sudo sh -c 'cat > "$1"' sh "$p" < "$V6/orig.$1" ;;
    link:*) sudo ln -sfn "${was#link:}" "$p" ;;
    absent) sudo rm -f "$p" ;;
  esac; }
v6_mkdir() { # v6_mkdir <host dir> <mode>: a disposable root:root directory -> created | in-use | FAIL
  if v6ex "$1"; then echo in-use
  elif sudo mkdir -m "$2" "$(v6h "$1")" && sudo chown 0:0 "$(v6h "$1")" && sudo chmod "$2" "$(v6h "$1")"; then echo created
  else echo FAIL; fi; }
v6_put() { # v6_put <host path> <mode> < content: a root:root file the harness plants
  sudo sh -c 'cat > "$1"' sh "$(v6h "$1")" && sudo chown 0:0 "$(v6h "$1")" && sudo chmod "$2" "$(v6h "$1")"; }
# Restores: v6_arm records one, v6_restore runs it once; v6_restore_all runs what is still armed.
V6_ARMED=""
v6_arm() { case " $V6_ARMED " in *" $1 "*) ;; *) V6_ARMED="$V6_ARMED $1" ;; esac; }
v6_restore() { case " $V6_ARMED " in *" $1 "*) V6_ARMED=$(printf ' %s ' $V6_ARMED | sed "s/ $1 / /; s/^ *//; s/ *$//"); "$1" ;; esac; }
v6_restore_all() { local f; for f in $V6_ARMED; do v6_restore "$f"; done; }
trap v6_restore_all EXIT
trap 'v6_restore_all; exit 143' TERM HUP INT

V6FAM=$(. "$V6ROOT/etc/os-release" 2> /dev/null; case " ${ID:-} ${ID_LIKE:-} " in (*" rhel "*|*" fedora "*) echo redhat ;; (*" debian "*|*" ubuntu "*) echo debian ;; (*) echo unknown ;; esac)
V6MAJ=$(. "$V6ROOT/etc/os-release" 2> /dev/null; v=${VERSION_ID:-}; v=${v%%.*}; case "$v" in (''|*[!0-9]*) echo unknown ;; (*) echo "$v" ;; esac)
if [ -L "$V6ROOT/usr/bin/dnf" ]; then V6DNF="link:$(readlink "$V6ROOT/usr/bin/dnf")"; elif [ -e "$V6ROOT/usr/bin/dnf" ]; then V6DNF=file; else V6DNF=absent; fi
case "${V6DNF##*/}" in link:dnf5*|dnf5*) V6GEN=dnf5 ;; link:dnf-*|dnf-*|link:dnf4*|dnf4*) V6GEN=dnf4 ;; absent) V6GEN=none ;; *) V6GEN=unknown ;; esac
echo "== observe v116-os family=$V6FAM major=$V6MAJ dnf=$V6DNF"
V6RH=no; [ "$V6FAM" = redhat ] && [ "$V6GEN" = dnf4 ] && V6RH=yes   # a DNF 4 host of the RHEL family
V6B_ST=$(v6_mkdir "$V6B" 0755)
v6r_base() { [ "$V6B_ST" = created ] && sudo rm -rf "$(v6h "$V6B")"; }
[ "$V6B_ST" = created ] && v6_arm v6r_base
echo "V116_BASE $V6B=$V6B_ST"

# ---- v116-audit-fresh-drift, v116-bundle-nested: a top bundle -> os -> os/net
# (two levels below it, DESIGN §19.3); the audit of the fresh paths first
# (§49.4: drift, exit 7, nothing created), then validate, plan (the later
# recipes' parent path checks are deferred to apply, §49.1), apply, re-apply
# and audit. The files below os/10_base's directory are decided changes (the
# file is absent, its content declared): unknown=False, with the note
# "parent path check deferred to apply ... (recipe os/10_base)" (DESIGN §29,
# §49.1; RC 3: RC 2 wrongly expected unknown=True)
N6="$V6/nest"; mkdir -p "$N6/os/net"
printf 'version: 1\nname: v116site\nrecipes:\n  - os\n  - 30_top.yaml\n' > "$N6/site.yaml"
printf 'version: 1\nname: os\nrecipes:\n  - 10_base.yaml\n  - net\n' > "$N6/os/bundle.yaml"
printf 'version: 1\nname: net\nrecipes:\n  - 20_net.yaml\n' > "$N6/os/net/bundle.yaml"
v6_file_res() { # v6_file_res <id> <path> <content>: one file resource as YAML lines
  printf '  - id: %s\n    type: file\n    with:\n      path: %s\n      content: "%s"\n      owner: root\n      group: root\n      mode: "0644"\n' "$1" "$2" "$3"; }
printf 'version: 1\nresources:\n  - id: nest_dir\n    type: directory\n    with:\n      path: %s/nest\n      owner: root\n      group: root\n      mode: "0755"\n' "$V6B" > "$N6/os/10_base.yaml"
{ printf 'version: 1\nresources:\n'; v6_file_res nest_net "$V6B/nest/net.conf" 'v116 nested level 2\n'; } > "$N6/os/net/20_net.yaml"
{ printf 'version: 1\nresources:\n'; v6_file_res nest_top "$V6B/nest/top.conf" 'v116 top level\n'; } > "$N6/30_top.yaml"
v6x n1 audit "$N6/site.yaml"; NR1=$?
NS1="rc=$NR1 statuses=$(v6j "$V6/n1.json" 'ST(d)') resources=$(v6j "$V6/n1.json" 'len(R(d))') created=$(v6ex "$V6B/nest" && echo yes || echo no)"
echo "V116_NEST_FRESH_AUDIT $NS1"
if [ "$V6B_ST" = created ] && [ "$NS1" = "rc=7 statuses=['drift'] resources=3 created=no" ]; then
  check v116-audit-fresh-drift ok "audit of a bundle nothing is applied to: exit 7, every resource drift, nothing created"
else check v116-audit-fresh-drift FAIL "base=$V6B_ST $NS1 $(v6e n1)"; fi
v6t 60 "$EXE" validate "$N6/site.yaml" > "$V6/n0.out" 2>&1; NR0=$?
v6x n2 plan "$N6/site.yaml"; NR2=$?
NP2="labels=$(v6j "$V6/n2.json" '[r["recipe"] for r in d["bundle"]["recipes"]]') unknown=$(v6j "$V6/n2.json" '[(r["id"], r["unknown"]) for r in R(d)]') carried=$(v6j "$V6/n2.json" 'all("(recipe os/10_base)" in TXT(by(d, i)) and "parent path check deferred to apply" in TXT(by(d, i)) for i in ("nest_net", "nest_top"))')"
v6x n3 apply "$N6/site.yaml"; NR3=$?
NB3="$(v6body "$V6B/nest/net.conf" | tr '\n' '|')$(v6body "$V6B/nest/top.conf" | tr '\n' '|')"
v6x n4 apply "$N6/site.yaml"; NR4=$?
v6x n5 audit "$N6/site.yaml"; NR5=$?
NS="validate=$NR0/$(grep -qF '3 recipe(s) from 2 nested bundle(s)' "$V6/n0.out" && echo yes || echo no) plan=$NR2 $NP2 apply=$NR3:$(v6j "$V6/n3.json" 'C(d)') bodies=$NB3 reapply=$NR4:$(v6j "$V6/n4.json" 'C(d)') audit=$NR5:$(v6j "$V6/n5.json" 'ST(d)')"
echo "V116_NEST $NS"
if [ "$V6B_ST" = created ] && [ "$NS" = "validate=0/yes plan=0 labels=['os/10_base', 'os/net/20_net', '30_top'] unknown=[('nest_dir', False), ('nest_net', False), ('nest_top', False)] carried=True apply=0:['changed'] bodies=v116 nested level 2|v116 top level| reapply=0:['none'] audit=0:['compliant']" ]; then
  check v116-bundle-nested ok "nested bundle two levels deep: labels, plan carry across sub-bundles, apply, no change on re-apply, audit compliant"
else check v116-bundle-nested FAIL "$NS $(v6e n2)"; v6diag n2 n3 n4 n5; fi

# ---- v116-bundle-carry: a later recipe's directory owned by an account an
# earlier recipe creates (§49.1 accounts). A group and a user resource, not a
# package's creates_accounts: no small distribution package that creates a
# system account is known to be absent on every image (creates_accounts is
# exercised by the PostgreSQL bundle on the RHEL family).
V6U=sinteracc
CU0=$(getent passwd "$V6U" > /dev/null 2>&1 && echo present || echo absent)
CG0=$(getent group "$V6U" > /dev/null 2>&1 && echo present || echo absent)
CA="$V6/carry"; mkdir -p "$CA"
printf 'version: 1\nname: v116carry\nrecipes:\n  - 10_group.yaml\n  - 20_user.yaml\n  - 30_dir.yaml\n' > "$CA/bundle.yaml"
printf 'version: 1\nresources:\n  - id: acc_grp\n    type: group\n    with:\n      name: %s\n      system: true\n' "$V6U" > "$CA/10_group.yaml"
printf 'version: 1\nresources:\n  - id: acc_user\n    type: user\n    with:\n      name: %s\n      system: true\n      group: %s\n      shell: /usr/sbin/nologin\n' "$V6U" "$V6U" > "$CA/20_user.yaml"
printf 'version: 1\nresources:\n  - id: acc_dir\n    type: directory\n    with:\n      path: %s/carry\n      owner: %s\n      group: %s\n      mode: "0750"\n' "$V6B" "$V6U" "$V6U" > "$CA/30_dir.yaml"
v6r_carry() { # only what this block created
  [ "$CU0" = absent ] && getent passwd "$V6U" > /dev/null 2>&1 && v6r 30 sudo userdel "$V6U" > /dev/null 2>&1
  [ "$CG0" = absent ] && getent group "$V6U" > /dev/null 2>&1 && v6r 30 sudo groupdel "$V6U" > /dev/null 2>&1
  echo "V116_CARRY_RESTORE sinteracc_accounts=$(getent passwd "$V6U" > /dev/null 2>&1 && echo present || echo absent)/$(getent group "$V6U" > /dev/null 2>&1 && echo present || echo absent)"; }
if [ "$V6B_ST" = created ] && [ "$CU0" = absent ] && [ "$CG0" = absent ]; then
  v6_arm v6r_carry
  v6x c1 plan "$CA/bundle.yaml"; CR1=$?
  CP1="plan=$CR1 dir_unknown=$(v6j "$V6/c1.json" 'by(d, "acc_dir").get("unknown")') named=$(v6j "$V6/c1.json" '"(recipe 20_user)" in TXT(by(d, "acc_dir")) or "(recipe 10_group)" in TXT(by(d, "acc_dir"))')"
  v6x c2 apply "$CA/bundle.yaml"; CR2=$?
  CS="$CP1 apply=$CR2 dir=$(v6st "$V6B/carry" '%U:%G %a')"
  v6_restore v6r_carry
else CS="prerequisite: base=$V6B_ST user=$CU0 group=$CG0 (an existing account is never removed)"; fi
echo "V116_CARRY $CS"
if [ "$CS" = "plan=0 dir_unknown=True named=True apply=0 dir=$V6U:$V6U 750" ]; then
  check v116-bundle-carry ok "plan defers the directory owned by the account an earlier recipe creates; apply creates it with that owner"
else check v116-bundle-carry FAIL "$CS $(v6e c1)"; fi

# ---- v116-directory-parents: parents: true creates the missing parents
# (0755, root) top down, the declared mode on the leaf; an existing parent
# keeps its mode and identity; plan creates nothing; re-apply changes nothing
PK=FAIL; [ "$V6B_ST" = created ] && sudo mkdir -m 0711 "$(v6h "$V6B/keep")" && sudo chown 0:0 "$(v6h "$V6B/keep")" && sudo chmod 0711 "$(v6h "$V6B/keep")" && PK=ok
PB0="$(v6st "$V6B" '%a %u %g %i')/$(v6st "$V6B/keep" '%a %u %g %i')"
cat > "$V6/par.yaml" <<YAML
version: 1
resources:
  - id: par_new
    type: directory
    with:
      path: $V6B/p1/p2/p3
      parents: true
      owner: root
      group: root
      mode: "0750"
  - id: par_keep
    type: directory
    with:
      path: $V6B/keep/k1/k2
      parents: true
      mode: "0700"
YAML
v6x pa1 plan "$V6/par.yaml"; PR1=$?
PP1="plan=$PR1:$(v6j "$V6/pa1.json" '[(r["id"], r["change"]) for r in R(d)]') created=$(v6ex "$V6B/p1" && echo yes || echo no)/$(v6ex "$V6B/keep/k1" && echo yes || echo no)"
v6x pa2 apply "$V6/par.yaml"; PR2=$?
PM="$(for p in p1 p1/p2 p1/p2/p3 keep/k1 keep/k1/k2; do printf '%s ' "$(v6st "$V6B/$p" '%F:%a:%u:%g' | tr ' ' _)"; done)"
PB1="$(v6st "$V6B" '%a %u %g %i')/$(v6st "$V6B/keep" '%a %u %g %i')"
v6x pa3 apply "$V6/par.yaml"; PR3=$?
PS="prep=$PK $PP1 apply=$PR2 modes=[$PM] existing=$([ "$PB0" = "$PB1" ] && echo unchanged || echo "CHANGED:$PB0->$PB1") reapply=$PR3:$(v6j "$V6/pa3.json" 'C(d)')"
echo "V116_PARENTS $PS"
if [ "$V6B_ST" = created ] && [ "$PS" = "prep=ok plan=0:[('par_new', 'changed'), ('par_keep', 'changed')] created=no/no apply=0 modes=[directory:755:0:0 directory:755:0:0 directory:750:0:0 directory:755:0:0 directory:700:0:0 ] existing=unchanged reapply=0:['none']" ]; then
  check v116-directory-parents ok "missing parents created 0755 root, leaf as declared, existing parents untouched, plan creates nothing, re-apply unchanged"
else check v116-directory-parents FAIL "$PS $(v6e pa2)"; fi

# ---- v116-template-undefined-var: an undeclared vars.* in a template body is
# exit 2 at validate and before any contact (§49.5)
mkdir -p "$V6/tpl"
printf 'a={{ vars.known }}\nb={{ vars.v116_undeclared }}\n' > "$V6/tpl/t.j2"
printf 'version: 1\nvars:\n  known: { value: x }\nresources:\n  - id: tpl\n    type: template\n    with:\n      path: %s/tpl.conf\n      source: t.j2\n      mode: "0644"\n' "$V6B" > "$V6/tpl/t.yaml"
v6t 60 "$EXE" validate "$V6/tpl/t.yaml" > "$V6/t1.out" 2>&1; TR1=$?
v6x t2 plan "$V6/tpl/t.yaml"; TR2=$?
TS="validate=$TR1:$(grep -qF 'references the undefined variable vars.v116_undeclared' "$V6/t1.out" && echo yes || echo no) plan=$TR2:$(v6in t2 'references the undefined variable vars.v116_undeclared') file=$(v6ex "$V6B/tpl.conf" && echo created || echo absent)"
echo "V116_TEMPLATE $TS"
if [ "$TS" = "validate=2:yes plan=2:yes file=absent" ]; then check v116-template-undefined-var ok "undeclared template variable: exit 2 at validate and at plan, nothing written"
else check v116-template-undefined-var FAIL "$TS"; fi

# ---- v116-skip-resource-backup: in a partial run the backup only the
# excluded resource needs is skipped (SKIPPED_BY_USER) and the one a running
# resource needs is taken (§49.6); the store is below the disposable base
BK=FAIL
[ "$V6B_ST" = created ] && sudo mkdir -m 0755 "$(v6h "$V6B/bk")" && printf 'a-old\n' | v6_put "$V6B/bk/a.conf" 0644 && printf 's-old\n' | v6_put "$V6B/bk/s.conf" 0644 && BK=ok
{ printf 'version: 1\nbackup:\n  directory: %s/bk-store\n  paths:\n    - path: %s/bk/a.conf\n      resources: [bk_a]\n    - path: %s/bk/s.conf\n      resources: [bk_a, bk_b]\nresources:\n' "$V6B" "$V6B" "$V6B"
  v6_file_res bk_a "$V6B/bk/a.conf" 'a-new\n'; v6_file_res bk_b "$V6B/bk/s.conf" 's-new\n'; } > "$V6/bk.yaml"
v6x b1 apply "$V6/bk.yaml" --skip-resource bk_a; BR1=$?
BS="prep=$BK apply=$BR1 entries=$(v6j "$V6/b1.json" 'sorted((e["path"].rsplit("/", 1)[-1], e["status"], e.get("reason")) for e in d["backup"]["entries"])') bodies=$(v6body "$V6B/bk/a.conf" | tr -d '\n')/$(v6body "$V6B/bk/s.conf" | tr -d '\n') copies=$(sudo find "$(v6h "$V6B/bk-store")" -type f -name a.conf 2> /dev/null | grep -c .)/$(sudo find "$(v6h "$V6B/bk-store")" -type f -name s.conf 2> /dev/null | grep -c .)"
echo "V116_SKIP_BACKUP $BS"
if [ "$BS" = "prep=ok apply=0 entries=[('a.conf', 'skipped', 'SKIPPED_BY_USER'), ('s.conf', 'backed_up', None)] bodies=a-old/s-new copies=0/1" ]; then
  check v116-skip-resource-backup ok "--skip-resource: the excluded resource's backup is skipped (SKIPPED_BY_USER), the shared one is taken"
else check v116-skip-resource-backup FAIL "$BS $(v6e b1)"; fi

# ---- allow_writable_parents (§63) in a non-sticky 0777 directory of this
# block, as root. First the raw facts of §63.4 (observations only).
V6W_ST=$(v6_mkdir "$V6W" 0777)
v6r_writable() { [ "$V6W_ST" = created ] && sudo rm -rf "$(v6h "$V6W")"; }
[ "$V6W_ST" = created ] && v6_arm v6r_writable
WD=$(v6h "$V6W")
echo "V116_WRITABLE $V6W=$V6W_ST mode=$(v6st "$V6W" '%a %u %g')"
if [ "$V6W_ST" = created ]; then
  echo "== observe v116-fs type=$(stat -f -c %T "$WD" 2>&1 | tr -s ' ' _)"
  printf 'probe\n' | v6_put "$V6W/.v116-probe" 0644
  echo "V116_STAT_RECORD $(sudo stat -c '%F|%a|%u|%g|%s|%d|%i|%y|%z|%h' "$WD/.v116-probe" 2>&1 | tr ' ' _)"
  echo "== observe v116-stat fields=$(sudo stat -c '%F|%a|%u|%g|%s|%d|%i|%y|%z|%h' "$WD/.v116-probe" 2> /dev/null | awk -F'|' '{print NF}') links=$(sudo stat -c %h "$WD/.v116-probe" 2>&1)"
  z0=$(sudo stat -c %z "$WD/.v116-probe"); sleep 1; sudo mv "$WD/.v116-probe" "$WD/.v116-probe2"; z1=$(sudo stat -c %z "$WD/.v116-probe2")
  sleep 1; sudo ln "$WD/.v116-probe2" "$WD/.v116-probe3"; z2=$(sudo stat -c %z "$WD/.v116-probe2")
  sleep 1; sudo rm -f "$WD/.v116-probe3"; z3=$(sudo stat -c %z "$WD/.v116-probe2")
  echo "== observe v116-ctime rename=$([ "$z0" != "$z1" ] && echo changed || echo same) link=$([ "$z1" != "$z2" ] && echo changed || echo same) unlink=$([ "$z2" != "$z3" ] && echo changed || echo same)"
  echo "== observe v116-find $(find --version 2>&1 | head -1 | tr -s ' \t' __ | cut -c1-80)"
  echo "== observe v116-removed-dir-fd links=$(sudo sh -c 'mkdir "$1" && exec 5< "$1" && rmdir "$1" && stat -L -c %h /proc/self/fd/5' sh "$WD/.v116-fdprobe" 2>&1 | tr -s ' \n' __)"
  sudo ln -s /etc/hostname "$WD/.v116-link"; sudo mkfifo "$WD/.v116-fifo"; sudo sh -c 'head -c 262144 /dev/zero > "$1"' sh "$WD/.v116-big"
  DL=$(sudo dd if="$WD/.v116-link" iflag=nofollow,nonblock bs=262145 count=1 status=none 2>&1 > /dev/null); DLR=$?
  timeout 20 sudo dd if="$WD/.v116-fifo" iflag=nofollow,nonblock bs=262145 count=1 status=none > /dev/null 2>&1; DFR=$?
  DB=$(sudo dd if="$WD/.v116-big" iflag=nofollow,nonblock bs=262145 count=1 status=none 2> /dev/null | wc -c | tr -d ' ')
  echo "== observe v116-dd symlink_rc=$DLR fifo_rc=$DFR big_bytes=$DB symlink_err=$(printf '%s' "$DL" | head -1 | tr -s ' ' _ | cut -c1-80)"
  sudo rm -f "$WD/.v116-probe2" "$WD/.v116-link" "$WD/.v116-fifo" "$WD/.v116-big"
fi
v6_w() { # v6_w <file> <resource lines>: a recipe that lists the writable directory
  printf 'version: 1\nallow_writable_parents: [%s]\nresources:\n%s' "$V6W" "$2" > "$1"; }
v6_w "$V6/w1.yaml" "$(v6_file_res w_app "$V6W/app.conf" 'v116 one\n')"
v6_w "$V6/w2.yaml" "$(v6_file_res w_app "$V6W/app.conf" 'v116 two\n')"
v6t 60 "$EXE" validate "$V6/w1.yaml" > "$V6/w0.out" 2>&1; WR0=$?
v6x w1 apply "$V6/w1.yaml"; WR1=$?
WB1="$(v6body "$V6W/app.conf" | tr -d '\n'):$(v6st "$V6W/app.conf" '%U:%G:%a:%h'):$(v6in w1 'allowed by allow_writable_parents')"
v6x w2 apply "$V6/w2.yaml"; WR2=$?
WB2="$(v6body "$V6W/app.conf" | tr -d '\n'):$(v6st "$V6W/app.conf" '%U:%G:%a:%h')"
v6x w3 audit "$V6/w2.yaml"; WR3=$?
WS="validate=$WR0:$(grep -qF "allow_writable_parents lists $V6W" "$V6/w0.out" && echo yes || echo no) new=$WR1:$WB1 replace=$WR2:$WB2 audit=$WR3:$(v6j "$V6/w3.json" 'ST(d)')"
echo "V116_WRITABLE_PUBLISH $WS"
if [ "$V6W_ST" = created ] && [ "$WS" = "validate=0:yes new=0:v116 one:root:root:644:1:yes replace=0:v116 two:root:root:644:1 audit=0:['compliant']" ]; then
  check v116-writable-publish ok "in a listed 0777 directory: published new, replaced, audit compliant; the result notes the exception"
else check v116-writable-publish FAIL "$WS $(v6e w1)"; fi
# metadata alone, and a directory, stay refused there (plan and apply)
v6_w "$V6/w4.yaml" "$(v6_file_res w_app "$V6W/app.conf" 'v116 two\n' | sed 's/"0644"/"0600"/')"
v6_w "$V6/w5.yaml" "$(printf '  - id: w_dir\n    type: directory\n    with:\n      path: %s/sub\n      mode: "0755"\n' "$V6W")"
v6x w4p plan "$V6/w4.yaml"; WR4P=$?; v6x w4a apply "$V6/w4.yaml"; WR4A=$?
v6x w5p plan "$V6/w5.yaml"; WR5P=$?; v6x w5a apply "$V6/w5.yaml"; WR5A=$?
WN='is not supported there'
WRF="metadata=$WR4P:$(v6in w4p "$WN")/$WR4A:$(v6in w4a "$WN"):$(v6st "$V6W/app.conf" '%a') directory=$WR5P:$(v6in w5p "$WN")/$WR5A:$(v6in w5a "$WN"):$(v6ex "$V6W/sub" && echo created || echo absent)"
echo "V116_WRITABLE_REFUSED $WRF"
if [ "$V6W_ST" = created ] && [ "$WRF" = "metadata=4:yes/5:yes:644 directory=4:yes/5:yes:absent" ]; then check v116-writable-refusals ok "a mode-only change and a directory are refused in plan (4) and apply (5); nothing changed"
else check v116-writable-refusals FAIL "$WRF"; fi
# a trusted principal's 0600 file renamed into the managed name: plan shows no
# content of it, and file_merge does not make it readable by more accounts
CANW="synthetic-v116-planted-canary-$$"
PL=FAIL; [ "$V6W_ST" = created ] && printf 'planted=%s\n' "$CANW" | v6_put "$V6W/.v116-plant" 0600 && sudo mv "$WD/.v116-plant" "$WD/merge.conf" && PL=ok
PL0="$PL:$(v6st "$V6W/merge.conf" '%U:%a:%h')"; PLS0=$(v6_now "$V6W/merge.conf")
v6_w "$V6/w6.yaml" "$(v6_file_res w_merge "$V6W/merge.conf" 'replaced\n')"
v6_w "$V6/w7.yaml" "$(printf '  - id: w_merge\n    type: file_merge\n    with:\n      path: %s/merge.conf\n      merge: key_value\n      key: planted\n      value: "x"\n      mode: "0644"\n' "$V6W")"
v6x w6 plan "$V6/w6.yaml"; WR6=$?
v6t 300 "$EXE" plan "$V6/w6.yaml" --sudo > "$V6/w6t.json" 2> "$V6/w6t.err"; WR6T=$?
v6x w7 plan "$V6/w7.yaml"; WR7=$?
v6t 300 "$EXE" plan "$V6/w7.yaml" --sudo > "$V6/w7t.json" 2> "$V6/w7t.err"; WR7T=$?
v6x w8 apply "$V6/w7.yaml"; WR8=$?
WLEAK=$(cat "$V6"/w6.json "$V6"/w6.err "$V6"/w6t.json "$V6"/w6t.err "$V6"/w7.json "$V6"/w7.err "$V6"/w7t.json "$V6"/w7t.err "$V6"/w8.json "$V6"/w8.err 2> /dev/null | grep -c "$CANW")
WP="planted=$PL0 file_plan=$WR6/$WR6T:$(v6j "$V6/w6.json" '(by(d, "w_merge").get("diff") or {}).get("type")'):$(v6in w6 'content differs (not shown)') merge_plan=$WR7/$WR7T:$(v6in w7 'readable by more accounts') merge_apply=$WR8:$(v6in w8 'readable by more accounts') leak=$WLEAK after=$(v6st "$V6W/merge.conf" '%U:%a:%h'):$([ "$(v6_now "$V6W/merge.conf")" = "$PLS0" ] && echo same-bytes || echo CHANGED)"
echo "V116_WRITABLE_PLANTED $(printf '%s' "$WP" | sed "s/$CANW/<canary>/g")"
if [ "$WP" = "planted=ok:root:600:1 file_plan=0/0:summary:yes merge_plan=4/4:yes merge_apply=5:yes leak=0 after=root:600:1:same-bytes" ]; then
  check v116-writable-planted ok "a planted 0600 root file: plan shows a summary only (text and JSON), file_merge with mode 0644 refused in plan and apply, the file unchanged"
else check v116-writable-planted FAIL "$(printf '%s' "$WP" | sed "s/$CANW/<canary>/g")"; fi
WSG=$(sudo find "$WD" -maxdepth 1 -name '.sinter-stage.*' 2> /dev/null | grep -c .)
WSL=$(cat "$V6"/w1.json "$V6"/w2.json "$V6"/w1.err "$V6"/w2.err 2> /dev/null | grep -c 'was left in place')
echo "V116_STAGING_LEFT dirs=$WSG notes=$WSL entries=[$(sudo ls -A "$WD" 2> /dev/null | tr '\n' ' ')]"
if [ "$V6W_ST" = created ] && [ "$WR1" -eq 0 ] && [ "$WR2" -eq 0 ] && [ "$WSG" = 0 ] && [ "$WSL" = 0 ]; then
  check v116-writable-staging-cleanup ok "no .sinter-stage.* directory is left in the writable directory after the publications"
else check v116-writable-staging-cleanup FAIL "dirs=$WSG notes=$WSL publish=$WR1/$WR2"; fi
v6_restore v6r_writable

# ---- v116-file-merge: line, block and key_value on a file of this block in
# /etc/sinter-acc; exact bytes after the edit; unchanged on re-apply; audit
# compliant; the original bytes again after the parts are removed
V6E_ST=$(v6_mkdir "$V6E" 0755)
v6r_etc() { [ "$V6E_ST" = created ] && sudo rm -rf "$(v6h "$V6E")"; }
[ "$V6E_ST" = created ] && v6_arm v6r_etc
FMF="$V6E/merge.conf"
[ "$V6E_ST" = created ] && printf '# v116 file_merge target\nalpha=1\nkeep=yes\n' | v6_put "$FMF" 0644
FM0=$(v6_now "$FMF")
fm_recipe() { # fm_recipe <file> <alpha value> <line state> <block state>
  printf 'version: 1\nresources:\n  - id: fm_kv\n    type: file_merge\n    with:\n      path: %s\n      merge: key_value\n      key: alpha\n      value: "%s"\n  - id: fm_line\n    type: file_merge\n    with:\n      path: %s\n      merge: line\n      line: "sinter-acc-line"\n      state: %s\n  - id: fm_block\n    type: file_merge\n    with:\n      path: %s\n      merge: block\n      marker: v116\n      state: %s\n%s' \
    "$FMF" "$2" "$FMF" "$3" "$FMF" "$4" "$([ "$4" = present ] && printf '      content: "b1\\nb2\\n"\n')" > "$1"; }
fm_recipe "$V6/fm1.yaml" 2 present present
fm_recipe "$V6/fm2.yaml" 1 absent absent
v6x fm1 apply "$V6/fm1.yaml"; FR1=$?
FMB=$(v6body "$FMF" | od -An -c | tr -s ' \n' ' ')
FWANT=$(printf '# v116 file_merge target\nalpha=2\nkeep=yes\nsinter-acc-line\n# BEGIN SINTER MANAGED BLOCK v116\nb1\nb2\n# END SINTER MANAGED BLOCK v116\n' | od -An -c | tr -s ' \n' ' ')
v6x fm2 apply "$V6/fm1.yaml"; FR2=$?
v6x fm3 audit "$V6/fm1.yaml"; FR3=$?
v6x fm4 apply "$V6/fm2.yaml"; FR4=$?
FS="apply=$FR1:$(v6j "$V6/fm1.json" 'C(d)') bytes=$([ "$FMB" = "$FWANT" ] && echo exact || echo DIFFERENT) reapply=$FR2:$(v6j "$V6/fm2.json" 'C(d)') audit=$FR3:$(v6j "$V6/fm3.json" 'ST(d)') remove=$FR4 original=$([ "$(v6_now "$FMF")" = "$FM0" ] && echo yes || echo no)"
echo "V116_FILE_MERGE $FS"; [ "$FMB" = "$FWANT" ] || echo "V116_FILE_MERGE_BYTES $FMB"
if [ "$V6E_ST" = created ] && [ "$FS" = "apply=0:['changed'] bytes=exact reapply=0:['none'] audit=0:['compliant'] remove=0 original=yes" ]; then
  check v116-file-merge ok "line, block and key_value: exact bytes, unchanged on re-apply, audit compliant, original bytes after removal"
else check v116-file-merge FAIL "etc=$V6E_ST $FS $(v6e fm1)"; fi
v6_restore v6r_etc

# ---- dnf_repository (§51): a disabled local file:/// repository in a file of
# this block (RHEL family); the refusal on a host that is not DNF 4
DRF=/etc/yum.repos.d/sinter-acc.repo
dr_recipe() { # dr_recipe <file> <state> [gpgcheck value]
  if [ "$2" = present ]; then
    printf 'version: 1\nresources:\n  - id: acc_repo\n    type: dnf_repository\n    with:\n      name: sinter-acc\n      file: %s\n      description: "Sinter acceptance local repository"\n      baseurl: "file://%s/repo"\n      enabled: false\n      gpgcheck: %s\n' "$DRF" "$V6B" "${3:-true}" > "$1"
  else printf 'version: 1\nresources:\n  - id: acc_repo\n    type: dnf_repository\n    with:\n      name: sinter-acc\n      file: %s\n      state: absent\n' "$DRF" > "$1"; fi; }
dr_recipe "$V6/dr1.yaml" present; dr_recipe "$V6/dr2.yaml" absent; dr_recipe "$V6/dr0.yaml" present false
v6t 60 "$EXE" validate "$V6/dr0.yaml" > "$V6/dr0.out" 2>&1; DR0=$?
v6x dr0p plan "$V6/dr0.yaml"; DR0P=$?
DG="validate=$DR0:$(grep -c 'never writes gpgcheck=0' "$V6/dr0.out") plan=$DR0P file=$(v6ex "$DRF" && echo present || echo absent)"
echo "V116_DNF_REPO_GPGCHECK_FALSE $DG"
if [ "$DG" = "validate=2:1 plan=2 file=absent" ]; then check v116-dnf-repository-gpgcheck-refused ok "gpgcheck: false is a load error (exit 2) on every host; nothing written"
else check v116-dnf-repository-gpgcheck-refused FAIL "$DG"; fi
DR_PRE=$(v6ex "$DRF" && echo in-use || echo absent)
v6r_repo() { [ "$DR_PRE" = absent ] && sudo rm -f "$(v6h "$DRF")"; }
v6_dnf_list() { v6t 60 sudo dnf -q --disablerepo='*' repolist --disabled 2>&1 | awk '{print $1}' | grep -cx sinter-acc; }   # reads every .repo file, loads no metadata
if [ "$V6RH" = yes ] && [ "$DR_PRE" = absent ]; then
  v6_arm v6r_repo
  v6x dr1 plan "$V6/dr1.yaml"; D1=$?
  v6x dr2 apply "$V6/dr1.yaml"; D2=$?
  DRB=$(v6body "$DRF")
  echo "V116_DNF_REPO_FILE<<"; printf '%s\n' "$DRB"; echo ">>"
  DREAD=$(v6_dnf_list)
  v6x dr3 apply "$V6/dr1.yaml"; D3=$?
  v6x dr4 audit "$V6/dr1.yaml"; D4=$?
  v6x dr5 apply "$V6/dr2.yaml"; D5=$?
  DS="plan=$D1:$(v6j "$V6/dr1.json" 'C(d)') apply=$D2 lines=$(printf '%s\n' "$DRB" | grep -cxE '\[sinter-acc\]|baseurl=file://'"$V6B"'/repo|enabled=0|gpgcheck=1') owner=$(v6st "$DRF" '%U:%G:%a') dnf_reads=$DREAD reapply=$D3:$(v6j "$V6/dr3.json" 'C(d)') audit=$D4:$(v6j "$V6/dr4.json" 'ST(d)') absent=$D5:$(v6body "$DRF" | grep -c '^\[sinter-acc\]')/$(v6_dnf_list)/$(v6ex "$DRF" && echo kept || echo removed)"
  v6_restore v6r_repo
elif [ "$V6RH" = no ]; then
  v6x dr1 plan "$V6/dr1.yaml"; D1=$?
  DWP='dnf_repository is not supported on this host'   # the product's sentence, in its two forms
  case "$V6GEN" in dnf5) DW="$DWP: it uses DNF 5, which this type does not support in this release" ;; *) DW="$DWP (its package manager is not DNF)" ;; esac
  DS="refusal plan=$D1:$(v6in dr1 "$DW") file=$(v6ex "$DRF" && echo present || echo absent)"
else DS="prerequisite: $DRF exists"; fi
echo "V116_DNF_REPO $DS"
case "$V6RH:$DS" in
  "yes:plan=0:['changed'] apply=0 lines=4 owner=root:root:644 dnf_reads=1 reapply=0:['none'] audit=0:['compliant'] absent=0:0/0/kept") DOK=yes ;;
  "no:refusal plan=4:yes file=absent") DOK=yes ;;
  *) DOK=no ;; esac
if [ "$DOK" = yes ]; then check v116-dnf-repository ok "$([ "$V6RH" = yes ] && echo 'section written with gpgcheck=1, read back by dnf, unchanged, compliant, removed' || echo 'refused on a host that is not DNF 4, nothing written')"
else check v116-dnf-repository FAIL "$DS $(v6e dr1)"; fi

# ---- dnf_module (§52): EL 9: enable a stream of nodejs (one the host lists),
# disable, reset; EL 10: no module streams (NOT_APPLICABLE, proven); not DNF 4: refused
DMF=/etc/dnf/modules.d/nodejs.module
dm_recipe() { printf 'version: 1\nresources:\n  - id: acc_mod\n    type: dnf_module\n    with:\n      name: nodejs\n      state: %s\n%s' "$2" "${3:+      stream: \"$3\"
}" > "$1"; }
dm_state() { v6body "$DMF" | sed -n 's/^state=//p' | head -1; }
dm_stream() { v6body "$DMF" | sed -n 's/^stream=//p' | head -1; }
DMDO=no
if [ "$V6RH" = yes ]; then
  MDD=$(v6h /etc/dnf/modules.d)
  if [ ! -d "$MDD" ]; then MDS=absent; elif [ -z "$(ls -A "$MDD" 2> /dev/null)" ]; then MDS=empty; else MDS=nonempty; fi
  MLS=cache; ML=$(v6t 120 sudo dnf -q -C module list 2>&1); MLR=$?
  if [ "$MLR" -ne 0 ] && printf '%s' "$ML" | grep -qi 'cache'; then MLS=refresh; ML=$(v6t 180 sudo dnf -q module list 2>&1); MLR=$?; fi
  MROWS=$(printf '%s\n' "$ML" | awk '/^Name[ \t]+Stream/ {h = 1; next} /^$/ {h = 0} h && NF >= 2 {n++} END {print n + 0}')
  if [ "$MROWS" -gt 0 ]; then MLIST=rows; elif [ "$MLR" -eq 0 ] || printf '%s' "$ML" | grep -q 'No matching Modules to list'; then MLIST=empty; else MLIST=error; fi
  echo "V116_DNF_MODULE_LIST rc=$MLR<<"; printf '%s\n' "$ML" | head -60; echo ">>"
  echo "== observe v116-dnf-modules modules_d=$MDS list=$MLIST rows=$MROWS source=$MLS"
  DMS0=$(v6_now "$DMF"); DMST0=$(dm_state)
  if { [ "$MDS" = absent ] || [ "$MDS" = empty ]; } && [ "$MLIST" = empty ] && na_allowed v116-dnf-module NO_MODULE_STREAMS; then
    # the plan's expectation, recorded: plan reports the change, apply fails at dnf
    dm_recipe "$V6/dm0.yaml" enabled 22
    v6r_dnfmod0() { [ "$DMS0" = absent ] && v6ex "$DMF" && { v6r 90 sudo dnf -y -q module reset nodejs > /dev/null 2>&1; sudo rm -f "$(v6h "$DMF")"; }; }
    v6_arm v6r_dnfmod0
    v6x dm0p plan "$V6/dm0.yaml"; DM0P=$?; v6x dm0a apply "$V6/dm0.yaml"; DM0A=$?
    echo "V116_DNF_MODULE_EL10 plan=$DM0P apply=$DM0A state_file=$(v6_now "$DMF") apply_reason=$(v6j "$V6/dm0a.json" 'TXT(by(d, "acc_mod"))' | cut -c1-200)"
    v6_restore v6r_dnfmod0
    not_applicable v116-dnf-module NO_MODULE_STREAMS "no module streams on $LABEL: /etc/dnf/modules.d $MDS, dnf module list empty"
  else DMDO=yes; fi
else DMDO=refusal; fi
if [ "$DMDO" = yes ]; then
  DMSTR=$(printf '%s\n' "$ML" | awk '/^Name[ \t]+Stream/ {h = 1; next} /^$/ {h = 0} h && $1 == "nodejs" {s = $2; d = ($3 == "[d]" || $3 ~ /^\[d/) ? 1 : 0; if (d && !dd) {print s; dd = 1; exit}; if (!f) f = s} END {if (!dd && f) print f}' | head -1)
  echo "V116_DNF_MODULE stream=${DMSTR:-none} state_before=${DMST0:-default}/$DMS0"
  v6r_dnfmod() { [ -n "$(dm_state)" ] && v6r 90 sudo dnf -y -q module reset nodejs > /dev/null 2>&1; echo "V116_DNF_MODULE_RESTORE $(v6_now "$DMF") state=$(dm_state)"; }
  if [ -n "$DMSTR" ] && [ -z "$DMST0" ]; then
    v6_arm v6r_dnfmod
    dm_recipe "$V6/dm1.yaml" enabled "$DMSTR"; dm_recipe "$V6/dm2.yaml" disabled; dm_recipe "$V6/dm3.yaml" reset
    v6x dm1 plan "$V6/dm1.yaml"; M1=$?
    v6x dm2 apply "$V6/dm1.yaml"; M2=$?; MS2="$(dm_state)/$(dm_stream)"
    echo "V116_DNF_MODULE_FILE_ENABLED<<"; v6body "$DMF"; echo ">>"
    v6x dm3 apply "$V6/dm1.yaml"; M3=$?
    v6x dm4 audit "$V6/dm1.yaml"; M4=$?
    v6x dm5 apply "$V6/dm2.yaml"; M5=$?; MS5=$(dm_state)
    echo "V116_DNF_MODULE_FILE_DISABLED<<"; v6body "$DMF"; echo ">>"
    v6x dm6 audit "$V6/dm2.yaml"; M6=$?
    v6x dm7 apply "$V6/dm3.yaml"; M7=$?; MS7="$(v6_now "$DMF" | cut -d: -f1)/$(dm_state)"
    echo "V116_DNF_MODULE_FILE_RESET<<"; v6body "$DMF"; echo ">>"
    v6x dm8 audit "$V6/dm3.yaml"; M8=$?
    DMR="plan=$M1:$(v6j "$V6/dm1.json" 'C(d)') enable=$M2:$MS2 reapply=$M3:$(v6j "$V6/dm3.json" 'C(d)') audit=$M4 disable=$M5:$MS5 audit=$M6 reset=$M7:$MS7 audit=$M8"
    v6_restore v6r_dnfmod
  else DMR="prerequisite: stream=${DMSTR:-none} state_before=${DMST0:-default} (a module not in its default state is not touched)"; fi
  echo "V116_DNF_MODULE $DMR"
  case "$DMR" in "plan=0:['changed'] enable=0:enabled/$DMSTR reapply=0:['none'] audit=0 disable=0:disabled audit=0 reset=0:"*"/ audit=0") DMOK=yes ;; *) DMOK=no ;; esac
  if [ "$DMOK" = yes ]; then check v116-dnf-module ok "nodejs:$DMSTR enabled, unchanged, compliant, disabled, reset (state file read back each time)"
  else check v116-dnf-module FAIL "$DMR $(v6e dm2)"; fi
elif [ "$DMDO" = refusal ]; then
  dm_recipe "$V6/dm1.yaml" enabled 22
  v6x dm1 plan "$V6/dm1.yaml"; M1=$?
  DWP='dnf_module is not supported on this host'   # the product's sentence, in its two forms
  case "$V6GEN" in dnf5) DW="$DWP: it uses DNF 5, which this type does not support in this release" ;; *) DW="$DWP (its package manager is not DNF)" ;; esac
  DMR="refusal plan=$M1:$(v6in dm1 "$DW")"; echo "V116_DNF_MODULE $DMR"
  if [ "$DMR" = "refusal plan=4:yes" ]; then check v116-dnf-module ok "refused on a host that is not DNF 4"; else check v116-dnf-module FAIL "$DMR"; fi
fi

# ---- crypto_policy (§53): EL 9 DEFAULT -> DEFAULT:NO-SHA1 -> back with
# allow_weaker; EL 10 the missing module refused and a run at the current
# policy unchanged; no update-crypto-policies: refused. Nothing is restarted.
CPT=$(v6h /usr/bin/update-crypto-policies)
cp_recipe() { printf 'version: 1\nresources:\n  - id: acc_cp\n    type: crypto_policy\n    with:\n      policy: %s\n%s' "$2" "${3:+      allow_weaker: true
}" > "$1"; }
cp_show() { v6r 30 sudo "$CPT" --show 2> /dev/null; }
cp_recipe "$V6/cp1.yaml" DEFAULT:NO-SHA1
if [ -x "$CPT" ]; then
  CP0=$(cp_show)
  echo "== observe v116-crypto show=$CP0 nosha1_module=$([ -f "$(v6h /usr/share/crypto-policies/policies/modules/NO-SHA1.pmod)" ] && echo present || echo absent) modules=$(ls "$(v6h /usr/share/crypto-policies/policies/modules)" 2> /dev/null | sed 's/\.pmod$//' | tr '\n' ',')"
  v6r_crypto() { [ -n "$CP0" ] && [ "$(cp_show)" != "$CP0" ] && v6r 120 sudo "$CPT" --set "$CP0" > /dev/null 2>&1; echo "V116_CRYPTO_RESTORE show=$(cp_show)"; }
  v6_arm v6r_crypto
  if [ "$V6MAJ" = 9 ] && [ "$CP0" = DEFAULT ]; then
    cp_recipe "$V6/cp2.yaml" DEFAULT; cp_recipe "$V6/cp3.yaml" DEFAULT weaker
    v6x cp1 apply "$V6/cp1.yaml"; K1=$?; KS1=$(cp_show)
    KSSH=$(v6t 40 ssh -i "$SSHKEY" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/opt/sinter-acceptance/ssh/known_hosts \
      -o ConnectTimeout=20 -p 22 "$SSHUSER@127.0.0.1" /usr/bin/true > /dev/null 2>&1 && echo ok || echo FAIL)
    echo "== observe v116-crypto-ssh policy=$KS1 new_loopback_session=$KSSH sshd_restarted=no"
    v6x cp2 apply "$V6/cp1.yaml"; K2=$?
    v6x cp3 audit "$V6/cp1.yaml"; K3=$?
    v6x cp4 plan "$V6/cp2.yaml"; K4=$?
    v6x cp5 apply "$V6/cp3.yaml"; K5=$?; KS5=$(cp_show)
    # §4: the tool's own --set answer, measured by setting the policy it already has (no change of strength)
    if [ "$KS5" = "$CP0" ]; then KSO=$(v6t 120 sudo "$CPT" --set "$CP0" 2>&1); KSR=$?
      echo "== observe v116-crypto-set policy=$CP0 rc=$KSR lines=$(printf '%s\n' "$KSO" | grep -c .) first=$(printf '%s' "$KSO" | head -1 | tr -s ' \t' __ | cut -c1-100) show_after=$(cp_show)"; fi
    KS="set=$K1:$KS1 reapply=$K2:$(v6j "$V6/cp2.json" 'C(d)') audit=$K3:$(v6j "$V6/cp3.json" 'ST(d)') lower=$K4:$(v6in cp4 'removing it weakens the policy') back=$K5:$KS5"
    KW="set=0:DEFAULT:NO-SHA1 reapply=0:['none'] audit=0:['compliant'] lower=4:yes back=0:DEFAULT"
  elif [ "$V6MAJ" != 9 ] && [ "$V6MAJ" != unknown ] && [ -n "$CP0" ]; then
    case "$CP0" in DEFAULT|FUTURE) cp_recipe "$V6/cp2.yaml" "$CP0" ;; *) cp_recipe "$V6/cp2.yaml" "$CP0" weaker ;; esac
    v6x cp1 plan "$V6/cp1.yaml"; K1=$?
    v6x cp2 apply "$V6/cp2.yaml"; K2=$?
    KS="missing_module=$K1:$(v6in cp1 'is not defined on this host'):$(cp_show) current=$K2:$(v6j "$V6/cp2.json" 'C(d)'):$(cp_show)"
    KW="missing_module=4:yes:$CP0 current=0:['none']:$CP0"
  else KS="prerequisite: EL$V6MAJ policy=$CP0 (EL 9 must start at DEFAULT)"; KW=no; fi
  v6_restore v6r_crypto
else
  v6x cp1 plan "$V6/cp1.yaml"; K1=$?
  KS="refusal plan=$K1:$(v6in cp1 'crypto_policy is not supported on this host (update-crypto-policies was not found)')"
  KW="refusal plan=4:yes"; [ "$V6FAM" = redhat ] && KW="no update-crypto-policies on a RHEL-family host"
fi
echo "V116_CRYPTO $KS"
if [ "$KS" = "$KW" ]; then check v116-crypto-policy ok "$KS"
else check v116-crypto-policy FAIL "$KS (want $KW) $(v6e cp1)"; fi

# ---- sysctl (§54): vm.dirty_expire_centisecs (writeback timing only) set at
# run time and in Sinter's file; audit `boot` compliant, then drift while a
# later file of this block sets another value; absent removes Sinter's file;
# the original running value is put back.
SK=vm.dirty_expire_centisecs; SF="/etc/sysctl.d/90-sinter-$SK.conf"; SL=/etc/sysctl.d/99-zz-sinter-acc.conf
SV0=$(sysctl -n "$SK" 2> /dev/null); case "$SV0" in 2999) SV=3001 ;; *) SV=2999 ;; esac; SW=$((SV + 2))
SCAT=$(v6t 60 sudo systemd-analyze cat-config sysctl.d 2> "$V6/sy-cat.err"); SCR=$?
echo "V116_SYSCTL_HEADERS rc=$SCR stderr_bytes=$(wc -c < "$V6/sy-cat.err" | tr -d ' ')<<"; printf '%s\n' "$SCAT" | grep '^# /'; echo ">>"
echo "== observe v116-sysctl-order rc=$SCR headers=$(printf '%s\n' "$SCAT" | grep -cE '^# /[^ ,]+\.conf$') sysctl_conf=$(printf '%s\n' "$SCAT" | grep -qxF '# /etc/sysctl.conf' && echo listed || echo not-listed) masked=$(printf '%s\n' "$SCAT" | grep '^# /' | grep -c '/dev/null') link99=$(sudo readlink "$(v6h /etc/sysctl.d/99-sysctl.conf)" 2> /dev/null || { v6ex /etc/sysctl.d/99-sysctl.conf && echo file || echo absent; })"
SPRE="$(v6ex "$SF" && echo in-use || echo absent)/$(v6ex "$SL" && echo in-use || echo absent)"
v6r_sysctl() { sudo rm -f "$(v6h "$SL")"; [ "${SPRE%%/*}" = absent ] && sudo rm -f "$(v6h "$SF")"
  [ -n "$SV0" ] && [ "$(sysctl -n "$SK" 2> /dev/null)" != "$SV0" ] && v6r 30 sudo sysctl -q -w "$SK=$SV0" > /dev/null 2>&1
  echo "V116_SYSCTL_RESTORE value=$(sysctl -n "$SK" 2> /dev/null) files=$(v6ex "$SF" && echo left || echo none)/$(v6ex "$SL" && echo left || echo none)"; }
if [ -n "$SV0" ] && [ "$SPRE" = absent/absent ]; then
  v6_arm v6r_sysctl
  printf 'version: 1\nresources:\n  - id: acc_sysctl\n    type: sysctl\n    with:\n      name: %s\n      value: "%s"\n' "$SK" "$SV" > "$V6/sy1.yaml"
  printf 'version: 1\nresources:\n  - id: acc_sysctl\n    type: sysctl\n    with:\n      name: %s\n      state: absent\n' "$SK" > "$V6/sy2.yaml"
  v6x sy1 plan "$V6/sy1.yaml"; Y1=$?
  v6x sy2 apply "$V6/sy1.yaml"; Y2=$?; YO=$(v6st "$SF" '%U:%G:%a')
  YB=$(v6body "$SF" | od -An -c | tr -s ' \n' ' '); YW=$(printf '# Managed by Sinter (sysctl). Local changes are replaced.\n%s = %s\n' "$SK" "$SV" | od -An -c | tr -s ' \n' ' ')
  YV2=$(sysctl -n "$SK" 2> /dev/null)
  v6x sy3 apply "$V6/sy1.yaml"; Y3=$?
  v6x sy4 audit "$V6/sy1.yaml"; Y4=$?
  printf '%s = %s\n' "$SK" "$SW" | v6_put "$SL" 0644
  v6x sy5 audit "$V6/sy1.yaml"; Y5=$?
  echo "V116_SYSCTL_LATER_FILE_AUDIT $(v6j "$V6/sy5.json" '[(x.get("dimension"), x.get("observed"), x.get("desired")) for x in by(d, "acc_sysctl").get("details") or []]')"
  sudo rm -f "$(v6h "$SL")"
  v6x sy6 apply "$V6/sy2.yaml"; Y6=$?
  YS="plan=$Y1:$(v6j "$V6/sy1.json" 'C(d)') apply=$Y2:value=$YV2:file=$([ "$YB" = "$YW" ] && echo exact || echo DIFFERENT):$YO reapply=$Y3:$(v6j "$V6/sy3.json" 'C(d)') audit=$Y4:$(v6j "$V6/sy4.json" 'ST(d)') later_file=$Y5:$(v6j "$V6/sy5.json" 'DIM(by(d, "acc_sysctl"))') absent=$Y6:$(v6ex "$SF" && echo left || echo removed):running=$(sysctl -n "$SK" 2> /dev/null)"
  v6_restore v6r_sysctl
else YS="prerequisite: value=${SV0:-unreadable} files=$SPRE"; fi
echo "V116_SYSCTL $YS"
if [ "$YS" = "plan=0:['changed'] apply=0:value=$SV:file=exact:root:root:644 reapply=0:['none'] audit=0:['compliant'] later_file=7:['boot'] absent=0:removed:running=$SV" ]; then
  check v116-sysctl ok "$SK set and persisted, compliant, boot drift from a later file, file removed by absent (running value kept), original value restored"
else check v116-sysctl FAIL "$YS $(v6e sy2)"; fi

# ---- hostname (§55): sinter-acc-<label> as the static name, unchanged on
# re-apply, compliant; the static, transient and pretty names, /etc/hostname
# and /etc/hosts as before afterwards. While the test name is set, /etc/hosts
# carries a temporary line for it so that sudo can resolve the host name.
HN="sinter-acc-$LABEL"
HS0=$(v6r 15 hostnamectl --static 2> /dev/null); HT0=$(v6r 15 hostnamectl --transient 2> /dev/null); HP0=$(v6r 15 hostnamectl --pretty 2> /dev/null)   # the original state: read also after the budget
v6_save hostname /etc/hostname; v6_save hosts /etc/hosts; v6_save machineinfo /etc/machine-info
echo "V116_HOSTNAME_BEFORE static=$HS0 transient=$HT0 pretty=[$HP0] etc_hostname=$(cat "$V6/orig.hostname.state")"
v6r_hostname() {
  if [ -n "$HS0" ]; then v6r 30 sudo hostnamectl set-hostname "$HS0" > /dev/null 2>&1; fi
  v6_put_back hostname /etc/hostname
  [ "$(v6r 15 hostnamectl --transient 2> /dev/null)" != "$HT0" ] && [ -n "$HT0" ] && v6r 30 sudo hostnamectl --transient set-hostname "$HT0" > /dev/null 2>&1
  [ "$(v6r 15 hostnamectl --pretty 2> /dev/null)" != "$HP0" ] && v6r 30 sudo hostnamectl --pretty set-hostname "$HP0" > /dev/null 2>&1
  v6_put_back machineinfo /etc/machine-info
  v6_put_back hosts /etc/hosts
  echo "V116_HOSTNAME_RESTORE static=$(v6r 15 hostnamectl --static 2> /dev/null) transient=$(v6r 15 hostnamectl --transient 2> /dev/null) pretty=[$(v6r 15 hostnamectl --pretty 2> /dev/null)]"; }
if [ "$HS0" != "$HN" ] && v6t 15 hostnamectl --static > /dev/null 2>&1; then
  v6_arm v6r_hostname
  HNL=""; [ -n "$(v6body /etc/hosts | tail -c 1)" ] && HNL='\n'   # a last line without its newline is ended first
  HH=not-needed; getent hosts "$HN" > /dev/null 2>&1 || { printf "$HNL"'127.0.1.1 %s # sinter acceptance, temporary\n' "$HN" | sudo sh -c 'cat >> "$1"' sh "$(v6h /etc/hosts)" && HH=added; }
  printf 'version: 1\nresources:\n  - id: acc_hostname\n    type: hostname\n    with:\n      name: %s\n' "$HN" > "$V6/hn1.yaml"
  v6x hn1 plan "$V6/hn1.yaml"; H1=$?
  v6x hn2 apply "$V6/hn1.yaml"; H2=$?
  HS2=$(v6t 15 hostnamectl --static 2> /dev/null)
  echo "== observe v116-hostname after_set static=$HS2 transient=$(v6t 15 hostnamectl --transient 2> /dev/null) pretty_kept=$([ "$(v6t 15 hostnamectl --pretty 2> /dev/null)" = "$HP0" ] && echo yes || echo no) etc_hostname=$(v6body /etc/hostname | head -1) hosts_line=$HH"
  v6x hn3 apply "$V6/hn1.yaml"; H3=$?
  v6x hn4 audit "$V6/hn1.yaml"; H4=$?
  HSS="plan=$H1:$(v6j "$V6/hn1.json" 'C(d)') apply=$H2:$HS2 reapply=$H3:$(v6j "$V6/hn3.json" 'C(d)') audit=$H4:$(v6j "$V6/hn4.json" 'ST(d)')"
  v6_restore v6r_hostname
else HSS="prerequisite: static=$HS0"; fi
echo "V116_HOSTNAME $HSS"
if [ "$HSS" = "plan=0:['changed'] apply=0:$HN reapply=0:['none'] audit=0:['compliant']" ] && [ "$(v6t 15 hostnamectl --static 2> /dev/null)" = "$HS0" ] && v6_same hostname /etc/hostname && v6_same hosts /etc/hosts && v6_same machineinfo /etc/machine-info; then
  check v116-hostname ok "static name set, unchanged, compliant; names, /etc/hostname and /etc/hosts restored"
else check v116-hostname FAIL "$HSS restored_static=$(v6t 15 hostnamectl --static 2> /dev/null)"; fi

# ---- timezone (§60): Asia/Tokyo (Etc/UTC when the host already is in Tokyo); the
# link /etc/localtime (and /etc/timezone where it exists) as before afterwards
TZL0=$(sudo readlink "$(v6h /etc/localtime)" 2> /dev/null); TZ0=${TZL0##*zoneinfo/}
case "$TZ0" in Asia/Tokyo) TZW=Etc/UTC ;; *) TZW=Asia/Tokyo ;; esac
v6_save localtime /etc/localtime; v6_save etctz /etc/timezone
v6r_tz() { [ -n "$TZL0" ] && [ "$(sudo readlink "$(v6h /etc/localtime)" 2> /dev/null)" != "$TZL0" ] && { v6r 30 sudo timedatectl set-timezone "$TZ0" > /dev/null 2>&1; v6_put_back localtime /etc/localtime; }
  v6_put_back etctz /etc/timezone; echo "V116_TIMEZONE_RESTORE link=$(sudo readlink "$(v6h /etc/localtime)" 2> /dev/null)"; }
if [ -n "$TZL0" ] && [ "$TZ0" != "$TZL0" ]; then
  v6_arm v6r_tz
  printf 'version: 1\nresources:\n  - id: acc_tz\n    type: timezone\n    with:\n      name: %s\n' "$TZW" > "$V6/tz1.yaml"
  v6x tz1 plan "$V6/tz1.yaml"; Z1=$?
  v6x tz2 apply "$V6/tz1.yaml"; Z2=$?; TZL2=$(sudo readlink "$(v6h /etc/localtime)" 2> /dev/null)
  echo "== observe v116-timezone before=$TZL0 after=$TZL2 etc_timezone=$(cat "$V6/orig.etctz.state" | cut -d: -f1)->$(v6_same etctz /etc/timezone && echo same || echo changed)"
  v6x tz3 apply "$V6/tz1.yaml"; Z3=$?
  v6x tz4 audit "$V6/tz1.yaml"; Z4=$?
  ZS="plan=$Z1:$(v6j "$V6/tz1.json" 'C(d)') apply=$Z2:${TZL2##*zoneinfo/} reapply=$Z3:$(v6j "$V6/tz3.json" 'C(d)') audit=$Z4:$(v6j "$V6/tz4.json" 'ST(d)')"
  v6_restore v6r_tz
else ZS="prerequisite: /etc/localtime is not a link into zoneinfo ($(cat "$V6/orig.localtime.state"))"; fi
echo "V116_TIMEZONE $ZS"
if [ "$ZS" = "plan=0:['changed'] apply=0:$TZW reapply=0:['none'] audit=0:['compliant']" ] && v6_same localtime /etc/localtime && v6_same etctz /etc/timezone; then
  check v116-timezone ok "$TZW set through timedatectl, unchanged, compliant; link restored to $TZL0"
else check v116-timezone FAIL "$ZS now=$(v6_now /etc/localtime)"; fi

# ---- locale (§61): LANG=C.UTF-8 (C.utf8 when the file already says
# C.UTF-8) in the family's file; the file's bytes as before afterwards
case "$V6FAM" in debian) LF=/etc/default/locale ;; *) LF=/etc/locale.conf ;; esac
v6_save locale "$LF"
# Ubuntu 24.04 and later: /etc/default/locale is the OS's link ../locale.conf
# and localectl writes /etc/locale.conf (RC 3, DESIGN §61): keep both, put
# both back, and require the link itself unchanged after the apply
v6_save localeconf /etc/locale.conf
LANG0=$(v6body "$LF" | sed -n 's/^LANG=//p' | tr -d '"' | head -1)
case "$LANG0" in C.UTF-8) LW=C.utf8 ;; *) LW=C.UTF-8 ;; esac
echo "V116_LOCALE_BEFORE file=$LF $(cat "$V6/orig.locale.state")<<"; v6body "$LF"; echo ">>"
v6menv() { v6r 15 systemctl show-environment 2> /dev/null | sed -n 's/^LANG=//p' | head -1; }   # the service manager's LANG
LME0=$(v6menv); LMES0=$(v6r 15 systemctl show-environment > /dev/null 2>&1 && echo read || echo unreadable)
LA=$(v6t 30 locale -a 2> /dev/null); LAR=$?
echo "== observe v116-locale-a rc=$LAR lines=$(printf '%s\n' "$LA" | grep -c .) c_utf8=$(printf '%s\n' "$LA" | grep -qixE 'c\.utf-?8' && echo listed || echo absent)"
v6r_locale() { v6_put_back locale "$LF"; v6_put_back localeconf /etc/locale.conf
  # localectl may also set the service manager's LANG: put that back too
  if [ "$LMES0" = read ] && [ "$(v6menv)" != "$LME0" ]; then
    if [ -n "$LME0" ]; then v6r 30 sudo systemctl set-environment "LANG=$LME0" > /dev/null 2>&1; else v6r 30 sudo systemctl unset-environment LANG > /dev/null 2>&1; fi; fi
  echo "V116_LOCALE_RESTORE $(v6_same locale "$LF" && v6_same localeconf /etc/locale.conf && echo same-bytes || echo DIFFERENT) manager_lang=$([ "$(v6menv)" = "$LME0" ] && echo same || echo DIFFERENT)"; }
v6_arm v6r_locale
printf 'version: 1\nresources:\n  - id: acc_locale\n    type: locale\n    with:\n      lang: %s\n' "$LW" > "$V6/lc1.yaml"
v6x lc1 plan "$V6/lc1.yaml"; L1=$?
v6x lc2 apply "$V6/lc1.yaml"; L2=$?; LB2=$(v6body "$LF"); LL2=$(v6_now "$LF")
echo "== observe v116-locale-layout before=$(cut -c1-20 "$V6/orig.locale.state") after_apply=$(printf '%s' "$LL2" | cut -c1-20) locale_conf_before=$(cut -c1-20 "$V6/orig.localeconf.state")"
echo "V116_LOCALE_AFTER<<"; printf '%s\n' "$LB2"; echo ">>"
echo "== observe v116-locale-manager before=${LME0:-unset} after_apply=$(v6menv | sed 's/^$/unset/') readable=$LMES0"
echo "== observe v116-locale file=$LF keys_before=$(sed -n 's/=.*//p' "$V6/orig.locale" 2> /dev/null | sort | tr '\n' ',') keys_after=$(printf '%s\n' "$LB2" | sed -n 's/=.*//p' | sort | tr '\n' ',') comments_after=$(printf '%s\n' "$LB2" | grep -c '^#')"
v6x lc3 apply "$V6/lc1.yaml"; L3=$?
v6x lc4 audit "$V6/lc1.yaml"; L4=$?
LS="plan=$L1:$(v6j "$V6/lc1.json" 'C(d)') apply=$L2:$(printf '%s\n' "$LB2" | sed -n 's/^LANG=//p' | tr -d '"') reapply=$L3:$(v6j "$V6/lc3.json" 'C(d)') audit=$L4:$(v6j "$V6/lc4.json" 'ST(d)')"
v6_restore v6r_locale
echo "V116_LOCALE $LS"
LKEPT=yes; case "$(cat "$V6/orig.locale.state")" in link:*) [ "$LL2" = "$(cat "$V6/orig.locale.state")" ] || LKEPT=no ;; esac
LS="$LS link_kept=$LKEPT"
if [ "$LS" = "plan=0:['changed'] apply=0:$LW reapply=0:['none'] audit=0:['compliant'] link_kept=yes" ] && v6_same locale "$LF" && v6_same localeconf /etc/locale.conf && [ "$(v6menv)" = "$LME0" ]; then
  check v116-locale ok "LANG=$LW through localectl, unchanged, compliant; $LF restored byte for byte"
else check v116-locale FAIL "$LS restored=$(v6_same locale "$LF" && v6_same localeconf /etc/locale.conf && echo yes || echo no)"; v6diag lc1 lc2 lc3 lc4; fi

# ---- kernel_module (§62): dummy loaded and persisted, re-apply unchanged,
# compliant, absent removes Sinter's file. Sinter never unloads, so the module
# stays loaded on this disposable VM; a dummy interface the load created is
# removed. NOT_APPLICABLE only when the dry run says the module does not exist.
KMF=/etc/modules-load.d/sinter-dummy.conf
KL0=$([ -d "$(v6h /sys/module/dummy)" ] && echo yes || echo no)
KMN=$(v6t 30 modprobe -n -v -- dummy 2>&1); KMR=$?
KIF0=$(ip -o link show type dummy 2> /dev/null | awk -F': ' '{print $2}' | tr '\n' ' ')
echo "V116_MODPROBE_DRY_RUN rc=$KMR<<"; printf '%s\n' "$KMN" | head -5; echo ">>"
echo "== observe v116-kmod loaded=$KL0 modprobe_n_rc=$KMR"
echo "== observe v116-kmod-dry-run loaded_after=$([ -d "$(v6h /sys/module/dummy)" ] && echo yes || echo no) modules_load_d=$(ls -A "$(v6h /etc/modules-load.d)" 2> /dev/null | grep -c .)"
v6r_kmod() { [ "$KPRE" = absent ] && sudo rm -f "$(v6h "$KMF")"
  for i in $(ip -o link show type dummy 2> /dev/null | awk -F': ' '{print $2}'); do
    case " $KIF0 " in *" $i "*) ;; *) case "$i" in dummy[0-9]*) v6r 30 sudo ip link del "$i" > /dev/null 2>&1 ;; esac ;; esac; done
  echo "V116_KMOD_RESTORE file=$(v6ex "$KMF" && echo left || echo none) loaded=$([ -d "$(v6h /sys/module/dummy)" ] && echo yes || echo no) dummy_links=$(ip -o link show type dummy 2> /dev/null | grep -c .)"; }
KPRE=$(v6ex "$KMF" && echo in-use || echo absent)
if [ "$KL0" = no ] && [ "$KMR" -eq 1 ] && na_allowed v116-kernel-module MODULE_UNAVAILABLE; then
  not_applicable v116-kernel-module MODULE_UNAVAILABLE "modprobe -n reports no dummy module for the running kernel of $LABEL"
elif [ "$KPRE" = absent ]; then
  v6_arm v6r_kmod
  printf 'version: 1\nresources:\n  - id: acc_kmod\n    type: kernel_module\n    with:\n      name: dummy\n' > "$V6/km1.yaml"
  printf 'version: 1\nresources:\n  - id: acc_kmod\n    type: kernel_module\n    with:\n      name: dummy\n      state: absent\n' > "$V6/km2.yaml"
  v6x km1 plan "$V6/km1.yaml"; KR1=$?
  v6x km2 apply "$V6/km1.yaml"; KR2=$?
  KB=$(v6body "$KMF" | od -An -c | tr -s ' \n' ' '); KW=$(printf '# Managed by Sinter (kernel_module). Local changes are replaced.\ndummy\n' | od -An -c | tr -s ' \n' ' ')
  KL2=$([ -d "$(v6h /sys/module/dummy)" ] && echo loaded || echo not-loaded)
  v6x km3 apply "$V6/km1.yaml"; KR3=$?
  v6x km4 audit "$V6/km1.yaml"; KR4=$?
  v6x km5 apply "$V6/km2.yaml"; KR5=$?
  KS="plan=$KR1:$(v6j "$V6/km1.json" 'C(d)') apply=$KR2:$KL2:file=$([ "$KB" = "$KW" ] && echo exact || echo DIFFERENT) reapply=$KR3:$(v6j "$V6/km3.json" 'C(d)') audit=$KR4:$(v6j "$V6/km4.json" 'ST(d)') absent=$KR5:$(v6ex "$KMF" && echo left || echo removed):$([ -d "$(v6h /sys/module/dummy)" ] && echo still-loaded || echo unloaded)"
  echo "V116_KMOD loaded_before=$KL0 $KS"
  v6_restore v6r_kmod
  if [ "$KS" = "plan=0:['changed'] apply=0:loaded:file=exact reapply=0:['none'] audit=0:['compliant'] absent=0:removed:still-loaded" ]; then
    check v116-kernel-module ok "dummy loaded (/sys/module/dummy) and persisted, unchanged, compliant, file removed by absent (module stays loaded)"
  else check v116-kernel-module FAIL "$KS $(v6e km2)"; fi
else check v116-kernel-module FAIL "prerequisite: $KMF exists"; fi

# ---- tuned (§57): install tuned (package) and start it (service) in the same
# recipe as the tuned resource; another vendor profile than the current one
# with verify; off. Restored: the selection, the service state, and the package
# removed only when it was not installed before.
TUIDS="v116-tuned-profile v116-tuned-verify v116-tuned-off"
tu_inst() { if [ "$V6FAM" = debian ]; then dpkg-query -W -f='${Status}' tuned 2> /dev/null | grep -q 'install ok installed'; else rpm -q tuned > /dev/null 2>&1; fi; }
tu_prof() { v6body /etc/tuned/active_profile | tr -d '\n'; }
TI0=$(tu_inst && echo yes || echo no)
if [ "$TI0" = yes ]; then TC=present
elif [ "$V6FAM" = debian ]; then TC=$(v6t 60 apt-cache policy tuned 2> /dev/null | awk '/Candidate:/ {print ($2 == "" || $2 == "(none)") ? "none" : "present"; f = 1} END {if (!f) print "none"}')
else TC=$(v6t 120 sudo dnf -q list --available tuned > /dev/null 2>&1 && echo present || echo none); fi
TA0=$(v6r 15 systemctl is-active tuned 2> /dev/null); TE0=$(v6r 15 systemctl is-enabled tuned 2> /dev/null); TP0=$(tu_prof)
TM0=$(v6body /etc/tuned/profile_mode | tr -d '\n')
echo "== observe v116-tuned installed=$TI0 candidate=$TC"
echo "V116_TUNED_BEFORE service=${TA0:-none}/${TE0:-none} profile=${TP0:-none} mode=${TM0:-none}"
if [ "$TI0" = no ] && [ "$TC" = none ] && na_allowed v116-tuned-profile TUNED_NOT_AVAILABLE && na_allowed v116-tuned-verify TUNED_NOT_AVAILABLE && na_allowed v116-tuned-off TUNED_NOT_AVAILABLE; then
  for id in $TUIDS; do not_applicable "$id" TUNED_NOT_AVAILABLE "the tuned package is neither installed nor installable on $LABEL"; done
else
  case "$TP0" in virtual-guest) TP1=balanced; TP2=throughput-performance ;; balanced) TP1=virtual-guest; TP2=throughput-performance ;; *) TP1=virtual-guest; TP2=balanced ;; esac
  v6r_tuned() {
    if [ "$TI0" = no ]; then
      if tu_inst; then
        v6r 60 sudo systemctl disable --now tuned > /dev/null 2>&1
        if [ "$V6FAM" = debian ]; then v6r 120 sudo env DEBIAN_FRONTEND=noninteractive apt-get -y -q remove tuned > /dev/null 2>&1; else v6r 120 sudo dnf -y -q remove tuned > /dev/null 2>&1; fi
      fi
    else
      [ "$(v6r 15 systemctl is-active tuned 2> /dev/null)" = active ] || v6r 60 sudo systemctl start tuned > /dev/null 2>&1
      if [ "$TM0" = auto ]; then v6r 120 sudo tuned-adm auto_profile > /dev/null 2>&1
      elif [ -n "$TP0" ]; then [ "$(tu_prof)" = "$TP0" ] || v6r 120 sudo tuned-adm profile "$TP0" > /dev/null 2>&1
      else [ -z "$(tu_prof)" ] || v6r 120 sudo tuned-adm off > /dev/null 2>&1; fi
      [ "$TA0" = active ] || v6r 60 sudo systemctl stop tuned > /dev/null 2>&1
      case "$TE0" in enabled) v6r 60 sudo systemctl enable tuned > /dev/null 2>&1 ;; disabled) v6r 60 sudo systemctl disable tuned > /dev/null 2>&1 ;; esac
    fi
    echo "V116_TUNED_RESTORE installed=$(tu_inst && echo yes || echo no) service=$(v6r 15 systemctl is-active tuned 2> /dev/null)/$(v6r 15 systemctl is-enabled tuned 2> /dev/null) profile=$(tu_prof)"; }
  v6_arm v6r_tuned
  tu_recipe() { # tu_recipe <file> <tuned with-lines>
    printf 'version: 1\nresources:\n  - id: acc_tuned_pkg\n    type: package\n    with:\n      name: tuned\n      state: present\n  - id: acc_tuned_svc\n    type: service\n    depends_on: [acc_tuned_pkg]\n    with:\n      name: tuned\n      state: running\n      enabled: true\n  - id: acc_tuned\n    type: tuned\n    depends_on: [acc_tuned_svc]\n    with:\n%s' "$2" > "$1"; }
  tu_recipe "$V6/tu1.yaml" "$(printf '      profile: %s\n' "$TP1")"
  tu_recipe "$V6/tu2.yaml" "$(printf '      profile: %s\n      verify: true\n' "$TP2")"
  tu_recipe "$V6/tu3.yaml" "$(printf '      state: off\n')"
  v6x tu1 plan "$V6/tu1.yaml"; U1=$?
  echo "V116_TUNED_PLAN rc=$U1 $(v6j "$V6/tu1.json" '[(r["id"], r["change"], r["unknown"]) for r in R(d)]')"
  v6t 600 "$EXE" apply "$V6/tu1.yaml" --sudo --format json > "$V6/tu2.json" 2> "$V6/tu2.err"; U2=$?; UP2=$(tu_prof)
  echo "== observe v116-tuned-after-select active_profile=$UP2 profile_mode=$(v6body /etc/tuned/profile_mode | tr -d '\n') service=$(v6t 15 systemctl is-active tuned 2> /dev/null) tuned_adm=$(ls -l "$(v6h /usr/sbin/tuned-adm)" 2> /dev/null | awk '{print $1}')"
  v6x tu3 apply "$V6/tu1.yaml"; U3=$?
  v6x tu4 audit "$V6/tu1.yaml"; U4=$?
  US1="plan=$U1 apply=$U2:$UP2 reapply=$U3:$(v6j "$V6/tu3.json" 'C(d)') audit=$U4:$(v6j "$V6/tu4.json" 'ST(d)')"
  v6x tu5 apply "$V6/tu2.yaml"; U5=$?; UP5=$(tu_prof)
  # the harness's own answer of tuned-adm verify (DESIGN §57.5: 0 applied, 1
  # not applied, anything else no answer), asked right after the apply and
  # again after the audit; whether the profile verifies on a VM is TuneD's
  # and the image's business, so both answers are accepted when the product
  # reports the same one (RC 3: RC 2 assumed that it always verifies)
  tu_verify() { v6t 120 sudo tuned-adm verify > /dev/null 2>&1; echo $?; }
  TV1=$(tu_verify)
  tu_files() { echo "$(v6_now /etc/tuned/active_profile | cut -c1-20)/$(v6_now /etc/tuned/profile_mode | cut -c1-20)"; }
  TF0=$(tu_files); TRC=$(v6t 120 sudo tuned-adm recommend 2> /dev/null | head -1); TRR=$?; TF1=$(tu_files)
  v6x tu6 audit "$V6/tu2.yaml"; U6=$?; TF2=$(tu_files); TV2=$(tu_verify)
  echo "== observe v116-tuned-verify-independent after_apply=$TV1 after_audit=$TV2 profile=$TP2"
  echo "== observe v116-tuned-readonly recommend=${TRC:-none} recommend_rc=$TRR recommend_changed=$([ "$TF0" = "$TF1" ] && echo no || echo yes) verify_audit_changed=$([ "$TF1" = "$TF2" ] && echo no || echo yes)"
  US2="apply=$U5:$UP5:$(v6in tu5 'verify: tuned-adm verify reports the selected profile as applied') audit=$U6:$(v6j "$V6/tu6.json" 'ST(d)'):$(v6in tu6 'tuned-adm verify reports the profile as applied')"
  # not applied: the resource FAILED with the change reported (execution
  # failed, change changed, verification failed), the selection is TP2, and
  # audit reports exactly the `applied` dimension as drift
  US2N="apply=$U5:$UP5:$(v6j "$V6/tu5.json" '(lambda r: (r.get("execution"), r.get("change"), r.get("verification"), "tuned-adm verify reports that the system differs" in TXT(r)))(by(d, "acc_tuned"))') audit=$U6:$(v6j "$V6/tu6.json" '(lambda r: (r.get("status"), DIM(r)))(by(d, "acc_tuned"))')"
  v6x tu7 apply "$V6/tu3.yaml"; U7=$?; UP7=$(tu_prof)
  echo "== observe v116-tuned-after-off active_profile_file=$(v6_now /etc/tuned/active_profile | cut -c1-12) bytes=$(v6body /etc/tuned/active_profile | wc -c | tr -d ' ')"
  v6x tu8 apply "$V6/tu3.yaml"; U8=$?
  v6x tu9 audit "$V6/tu3.yaml"; U9=$?
  US3="apply=$U7:[$UP7] reapply=$U8:$(v6j "$V6/tu8.json" 'C(d)') audit=$U9:$(v6j "$V6/tu9.json" 'ST(d)')"
  echo "V116_TUNED profile $US1 | verify $US2 | off $US3"
  v6_restore v6r_tuned
  if [ "$US1" = "plan=0 apply=0:$TP1 reapply=0:['none'] audit=0:['compliant']" ]; then check v116-tuned-profile ok "tuned installed and started in the recipe, $TP1 selected, unchanged, compliant"
  else check v116-tuned-profile FAIL "$US1 $(v6e tu2)"; fi
  if [ "$TV1/$TV2" = 0/0 ] && [ "$US2" = "apply=0:$TP2:yes audit=0:['compliant']:yes" ]; then check v116-tuned-verify ok "$TP2 selected with verify: applied after the change and in audit (tuned-adm verify, asked by the harness: 0 twice)"
  elif [ "$TV1/$TV2" = 1/1 ] && [ "$US2N" = "apply=5:$TP2:('failed', 'changed', 'failed', True) audit=7:('drift', ['applied'])" ]; then check v116-tuned-verify ok "$TP2 selected with verify: TuneD reports it not applied on this host (tuned-adm verify, asked by the harness: 1 twice); the resource failed with the change reported and audit reports the applied dimension as drift"
  else check v116-tuned-verify FAIL "independent=$TV1/$TV2 $US2 | $US2N $(v6e tu5)"; v6diag tu5 tu6; fi
  if [ "$US3" = "apply=0:[] reapply=0:['none'] audit=0:['compliant']" ]; then check v116-tuned-off ok "state off clears the selection, unchanged, compliant"
  else check v116-tuned-off FAIL "$US3 $(v6e tu7)"; fi
fi

# ---- PostgreSQL bundle (§56.3): examples/bundles/postgresql-pgdg17, embedded
# here byte for byte (a stand-in test compares it with the repository), on a
# fresh RHEL-family system: plan with the deferrals, audit drift, apply (PGDG
# over the network), re-apply unchanged, audit compliant; then the service is
# stopped and what the bundle installed is removed again. Its repository host
# and account name are covered by the screening exception recorded in
# release/tests/test_acceptance_harness.py (Owner decision 2026-11-27).
PGIDS="v116-pg-plan v116-pg-apply v116-pg-reapply v116-pg-audit"
PG="$V6/pg"; mkdir -p "$PG/files"
v6_emb() { cat > "$PG/$1"; }
# BEGIN embedded postgresql-pgdg17
v6_emb 01_repository.yaml <<'V116EOF'
# The PGDG signing key (a file, pinned in the recipe) and the two repositories
# that are needed, with package and metadata signature checking on.
# Fingerprint of the key: D4BF 08AE 67A0 B4C7 A1DB  CCD2 40BC A2B4 08B4 0D20
# (compare with https://download.postgresql.org/pub/repos/yum/keys/PGDG-RPM-GPG-KEY-RHEL).
version: 1

resources:
  - id: pgdg_key
    type: file
    with:
      path: /etc/pki/rpm-gpg/PGDG-RPM-GPG-KEY-RHEL
      source: files/PGDG-RPM-GPG-KEY-RHEL
      owner: root
      group: root
      mode: "0644"

  - id: pgdg_common
    type: dnf_repository
    depends_on: [pgdg_key]
    with:
      name: pgdg-common
      file: /etc/yum.repos.d/pgdg-17.repo
      description: "PostgreSQL common RPMs for RHEL / Rocky Linux / AlmaLinux $releasever - $basearch"
      baseurl: "https://download.postgresql.org/pub/repos/yum/common/redhat/rhel-$releasever-$basearch"
      enabled: true
      gpgcheck: true
      repo_gpgcheck: true
      gpgkey: "file:///etc/pki/rpm-gpg/PGDG-RPM-GPG-KEY-RHEL"

  - id: pgdg17
    type: dnf_repository
    depends_on: [pgdg_common]
    with:
      name: pgdg17
      file: /etc/yum.repos.d/pgdg-17.repo
      description: "PostgreSQL 17 for RHEL / Rocky Linux / AlmaLinux $releasever - $basearch"
      baseurl: "https://download.postgresql.org/pub/repos/yum/17/redhat/rhel-$releasever-$basearch"
      enabled: true
      gpgcheck: true
      repo_gpgcheck: true
      gpgkey: "file:///etc/pki/rpm-gpg/PGDG-RPM-GPG-KEY-RHEL"
V116EOF
v6_emb 02_module.yaml <<'V116EOF'
# EL9: the distribution's postgresql module would shadow the PGDG packages, so
# it is disabled. EL10 ships no module streams; the step is skipped there.
version: 1

resources:
  - id: pg_module_off
    type: dnf_module
    when: "facts.os.version_major < 10"
    with:
      name: postgresql
      state: disabled
V116EOF
v6_emb 03_package.yaml <<'V116EOF'
# The server package. Installing it creates the postgres account; saying so
# lets plan defer, instead of refuse, what the later recipes give to postgres.
version: 1

resources:
  - id: pg_pkg
    type: package
    with:
      name: postgresql17-server
      state: present
      creates_accounts:
        users: [postgres]
        groups: [postgres]
V116EOF
v6_emb 04_initdb.yaml <<'V116EOF'
# Create the database cluster once (the guard makes a second apply a no-op).
version: 1

resources:
  - id: pg_initdb
    type: command
    with:
      program: /usr/pgsql-17/bin/postgresql-17-setup
      args: ["initdb"]
      creates: /var/lib/pgsql/17/data/PG_VERSION
V116EOF
v6_emb 05_directory.yaml <<'V116EOF'
# The directory postgresql.conf includes (include_dir = 'conf.d').
version: 1

resources:
  - id: pg_confd
    type: directory
    with:
      path: /var/lib/pgsql/17/data/conf.d
      owner: postgres
      group: postgres
      mode: "0700"
V116EOF
v6_emb 06_config.yaml <<'V116EOF'
# Server configuration, validated by postgres itself before it is published,
# and client authentication.
version: 1

vars:
  datadir: { value: /var/lib/pgsql/17/data }
  port: { value: 5432 }

resources:
  - id: pg_conf
    type: template
    notify: [restart_pg]
    with:
      path: /var/lib/pgsql/17/data/postgresql.conf
      source: files/postgresql.conf.tmpl
      owner: postgres
      group: postgres
      mode: "0600"
      validate:
        program: /usr/pgsql-17/bin/postgres
        args: ["-C", "port", "-D", "/var/lib/pgsql/17/data", "--config-file={{ staged }}"]

  - id: pg_hba
    type: file
    notify: [reload_pg]
    with:
      path: /var/lib/pgsql/17/data/pg_hba.conf
      source: files/pg_hba.conf
      owner: postgres
      group: postgres
      mode: "0600"

handlers:
  - id: restart_pg
    service: postgresql-17
    action: restart
  - id: reload_pg
    service: postgresql-17
    action: reload
V116EOF
v6_emb 07_service.yaml <<'V116EOF'
version: 1

resources:
  - id: pg_service
    type: service
    with:
      name: postgresql-17
      state: running
      enabled: true
V116EOF
v6_emb bundle.yaml <<'V116EOF'
# PostgreSQL 17 from the PostgreSQL project's repository (PGDG) on Rocky Linux,
# RHEL or AlmaLinux 9 and 10, as a bundle: one small recipe per step, run in
# this order. (examples/recipes/postgresql-pgdg17.yaml is the same server as a
# single recipe.)
#
# The whole bundle can be planned and audited on a host where nothing is
# installed yet:
#
#   sinter plan  examples/bundles/postgresql-pgdg17/bundle.yaml --host <host> --sudo
#   sinter audit examples/bundles/postgresql-pgdg17/bundle.yaml --host <host> --sudo   # drift, exit 7
#   sinter apply examples/bundles/postgresql-pgdg17/bundle.yaml --host <host> --sudo
#   sinter apply examples/bundles/postgresql-pgdg17/bundle.yaml --host <host> --sudo   # no change
#
# Plan reports what an earlier recipe creates (the postgres account, the data
# directory, the service unit) as "decided at apply" in the later recipes.
version: 1
name: postgresql-pgdg17
recipes:
  - 01_repository.yaml
  - 02_module.yaml
  - 03_package.yaml
  - 04_initdb.yaml
  - 05_directory.yaml
  - 06_config.yaml
  - 07_service.yaml
V116EOF
v6_emb files/PGDG-RPM-GPG-KEY-RHEL <<'V116EOF'
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQGNBGWBr8EBDAC+atC3Hl2yKkFg0F4tDg4ABCTvvhgMn7g7oZ0vJqpaUAwUgijU
+jLXH8qVSkyhk2eruSXlbj4dIMHhsbRQ1wUnd+tb8pZPdRaBFR9MzFMjvDzobAlZ
RH6cUbgm2EdAHrrZFVQJuIb6SRzQzkk4QEWTkWP6CHzvxnlVpkI7T1yjsJnmLefN
TT/J+r0gxC1DRXOKwSMmWUCzYcRXiv/RZcp+IwM04e5BXOj6xoLIpAwhSGZ0LR6b
dwliBpMSFuVyXFIu+7AS2M8tEO1cGK+ywDhg7TriMc/rgjZjeu11WusXFwbvEUeM
FIYM9oXQlAlWDIob85YcGtNXV4EVGovQ2nFd4Ivl9OYq+HixAhWBLulkEAUREKq8
uXV8HDjxOfYa8VhczphvkCLr5UEMzXmC2eDc6nCH2hveAqSVLnFNkhtExvVOPRBB
gRsviaGWvdOA3eNeEofHX9YWtSzM43tWABKUzI/oTMcdFJlkJ465bvh4p7KyHDth
5I46iBUZmfP4RckAEQEAAbQ+UG9zdGdyZVNRTCBSUE0gUmVwb3NpdG9yeSA8cGdz
cWwtcGtnLXl1bUBsaXN0cy5wb3N0Z3Jlc3FsLm9yZz6JAdIEEwEIADwWIQTUvwiu
Z6C0x6HbzNJAvKK0CLQNIAUCZYGvwQIbAwULCQgHAgMiAgEGFQoJCAsCBBYCAwEC
HgcCF4AACgkQQLyitAi0DSBwkwwAvE1vGNMiP8Qvqvpk5otuJOvz5meELUwmhT60
IOWNr9RMroKfb27mnc5RHlOmMk/0SPyboFX9qtOdwFUq3cYbjsP+bqI9vuQuQ4Gz
siLIvSZPtQrdtUP8wdndndeKNpDIvRdYwvaPfIrBxxCSslB8iuCtjbyCl2rzlika
sCOWi7oTwuNB4eKHCRt9oh7NHFas92bF2JiaR7hvmXlCU058/lnR+jXCp/NWiGfE
QV37xAu/ssRH5MykGweEzQ3mX2EKppdKmmoOaJsTfS7UNujeZQqo1uqZg9yRHgwf
PaquIwgdXBY6JkMUM4Zhn7QkP5ssD6g+GzWe2UAMN+K8Xe3QwEMfp9AF7sEEM/Zp
+p5m7D1GlOho/m9juxcRa5r7VfvCFL05uyXdDoefOCFal/pDmwvZofK+pqtDZfKt
+AnF/Y6Z3ewvJ0ZRNBX/0Iw30uJusDIgkXaHwxEeDOnlKi8jVyBCMr1In2QKrb1+
N9PR5P5ZKKq40WNvbiPfoUeKwKKSuQGNBGWBr8EBDAD1nXgbf+Qki5Z0H2k0xLbI
GYhxnousjVlrWcxOTYqVilSvBig7RKuVFGt0D3yuBWrAS7+MCUvpuCshHcc+w97G
iWmRskIHqZoD26kkU8PhgYayyArqepZp50ALIdOhedOp9b/NUkSPEL4BJow9H8Lp
a28WEXpHZcam43RDMzLMUvJBWem474APx5674EZYX+994lT2cNSAFrnJK956lKmc
ZdzzKuMTcIVGyRF6+KXCmScLAyQks8lHuTJb+AA4eseZnbOsnwnA1xuVfYIfMF/F
bLlR7vl5Autmgnz1SdCaUqIp4MO54GZOgh4MjVadsxIWj8H0cN3uTfukuW4A0+dP
d0YrOKb52Mnejh7x39qWIsMtT8DgcufGcVsuVhC/5LCiHB3pB73J9SMxBafcyGyK
XfLFL5FoDkKTU5KkBfqMQ4k//27mLbJ4kWxHHtNsvnn/6a5m7rRYxFD4dxBWn1CU
BpMjf3m9B3xLc7lKlQZiLLNC7p15gHS51yMvCGxCaHcAEQEAAYkBtgQYAQgAIBYh
BNS/CK5noLTHodvM0kC8orQItA0gBQJlga/BAhsMAAoJEEC8orQItA0guy0L/1ze
AHxV8pxPawOIlgDWoALLb/tqvmG+yz8SN5IWDfvMkMW5kbVoY8zi9SnJtOHVULBC
sdiYN4Dn/Ox1eLlW50F4Z76RI2r/O9rBlHzUk/jAQOcDDCRWjj4a+pYX9I4atU6e
+qOOzxMBsFD0vK84NYJ6caC0LHR64xWnyvXStkDEPSzgHhAlhdn9oTqbIoXuDhSx
zBVSXyowi+cBL8tNsAH4Zlj0li1Gii6bM4DFseQGhKIiTFbx1HD47DT6Pu0X2PSA
pIuZ47n8rP2uTLCYjtnfpXbMwmVOXWxIojhUqIceF+KRr4vRsspSbMxMKg0yeGka
RfQX29x8baM4mdKVBmU9KQxRgno6lcks14STnawqf6o9nHxKp80VQrcNTsYHlq2B
PGAanK8G4WeYojQWCQHBi73qCoTERMpBG73gpTIr836TBinGZaSZ8I1deUS89Hnw
A62QO1TS57zxMTrstzaawLoCIHTqyJ2VeZrVC1INV4ENnyVsud3NaZtfWuIk7Q==
=Elfg
-----END PGP PUBLIC KEY BLOCK-----
V116EOF
v6_emb files/pg_hba.conf <<'V116EOF'
# Managed by Sinter. Local socket: peer (the OS account must match the role;
# Sinter's postgresql_role connects this way as postgres). TCP on loopback:
# SCRAM-SHA-256 passwords only.
# TYPE  DATABASE  USER  ADDRESS        METHOD
local   all       all                  peer
host    all       all   127.0.0.1/32   scram-sha-256
host    all       all   ::1/128        scram-sha-256
V116EOF
v6_emb files/postgresql.conf.tmpl <<'V116EOF'
# Managed by Sinter (examples/recipes/postgresql-pgdg17.yaml). Settings not listed
# keep PostgreSQL's built-in defaults; add your own in conf.d/.
listen_addresses = 'localhost'
port = {{ vars.port }}
max_connections = 100
shared_buffers = 128MB
dynamic_shared_memory_type = posix
password_encryption = scram-sha-256
logging_collector = on
log_directory = 'log'
log_filename = 'postgresql-%a.log'
log_rotation_age = 1d
log_rotation_size = 0
log_truncate_on_rotation = on
log_line_prefix = '%m [%p] '
log_timezone = 'UTC'
datestyle = 'iso, mdy'
timezone = 'UTC'
lc_messages = 'C'
lc_monetary = 'C'
lc_numeric = 'C'
lc_time = 'C'
default_text_search_config = 'pg_catalog.english'
# Absolute, so the file also validates from its staging location.
include_dir = '{{ vars.datadir }}/conf.d'
V116EOF
# END embedded postgresql-pgdg17
PGRF=/etc/yum.repos.d/pgdg-17.repo; PGKF=/etc/pki/rpm-gpg/PGDG-RPM-GPG-KEY-RHEL
if [ "$V6RH" = yes ]; then
  PGP0=$(rpm -qa --qf '%{NAME}\n' 2> /dev/null | grep '^postgresql' | sort | tr '\n' ' ')
  PGD0=$(v6ex /var/lib/pgsql && echo present || echo absent); PGU0=$(getent passwd postgres > /dev/null 2>&1 && echo present || echo absent)
  PGG0=$(getent group postgres > /dev/null 2>&1 && echo present || echo absent)
  PGM0=$(v6body /etc/dnf/modules.d/postgresql.module | sed -n 's/^state=//p' | head -1)
  PGPRE="$(v6ex "$PGRF" && echo in-use || echo absent)/$(v6ex "$PGKF" && echo in-use || echo absent)/$([ -z "$PGP0" ] && echo none || echo "$PGP0")"
  echo "V116_PG_BEFORE files=$PGPRE datadir=$PGD0 postgres=$PGU0 module=${PGM0:-default}"
  v6r_pg() {
    [ "$(v6r 15 systemctl is-active postgresql-17 2> /dev/null)" = active ] || [ "$(v6r 15 systemctl is-enabled postgresql-17 2> /dev/null)" = enabled ] && v6r 60 sudo systemctl disable --now postgresql-17 > /dev/null 2>&1
    PGNEW=$(rpm -qa --qf '%{NAME}\n' 2> /dev/null | grep '^postgresql' | sort | tr '\n' ' ')
    [ -n "$PGNEW" ] && [ -z "$PGP0" ] && v6r 120 sudo dnf -y -q remove $PGNEW > /dev/null 2>&1
    sudo rm -f "$(v6h "$PGRF")" "$(v6h "$PGKF")"
    [ "$V6MAJ" = 9 ] && [ -z "$PGM0" ] && [ -n "$(v6body /etc/dnf/modules.d/postgresql.module | sed -n 's/^state=//p')" ] && v6r 90 sudo dnf -y -q module reset postgresql > /dev/null 2>&1
    [ "$PGD0" = absent ] && sudo rm -rf "$(v6h /var/lib/pgsql)"
    [ "$PGU0" = absent ] && getent passwd postgres > /dev/null 2>&1 && v6r 30 sudo userdel postgres > /dev/null 2>&1
    [ "$PGG0" = absent ] && getent group postgres > /dev/null 2>&1 && v6r 30 sudo groupdel postgres > /dev/null 2>&1
    echo "V116_PG_RESTORE packages=[$(rpm -qa --qf '%{NAME}\n' 2> /dev/null | grep '^postgresql' | sort | tr '\n' ' ')] repo=$(v6ex "$PGRF" && echo left || echo none) datadir=$(v6ex /var/lib/pgsql && echo left || echo none) service=$(v6r 15 systemctl is-active postgresql-17 2> /dev/null)"; }
  PGLEFT=$(v6left)
  if [ "$PGPRE" = absent/absent/none ] && [ "$PGD0" = absent ] && [ "$PGLEFT" -ge 540 ]; then
    v6_arm v6r_pg
    v6t 300 "$EXE" plan "$PG/bundle.yaml" --sudo --format json > "$V6/pg1.json" 2> "$V6/pg1.err"; G1=$?; echo "plan bundle.yaml rc=$G1" > "$V6/pg1.rc"
    GD=$(v6j "$V6/pg1.json" '[(r["id"], r["unknown"]) for r in R(d) if r["id"] in ("pgdg_key", "pgdg_common", "pg_pkg", "pg_confd", "pg_conf", "pg_hba", "pg_service")]')
    GM=$(v6j "$V6/pg1.json" '(by(d, "pg_module_off").get("change"), by(d, "pg_module_off").get("disposition"))')
    v6t 300 "$EXE" audit "$PG/bundle.yaml" --sudo --format json > "$V6/pg2.json" 2> "$V6/pg2.err"; G2=$?; echo "audit bundle.yaml rc=$G2" > "$V6/pg2.rc"
    case "$V6MAJ" in 9) GMW="('changed', 'normal')" ;; *) GMW="('none', 'skipped_by_condition')" ;; esac
    GS1="plan=$G1 deferred=$GD module=$GM audit_fresh=$G2"
    echo "V116_PG_PLAN $GS1"
    # unknown: the postgres account (owner and group of conf.d, the config and
    # pg_hba) is deferred while it is missing (creates_accounts, §49.2); when it
    # exists already only their parent path check waits for the package (a
    # note, not unknown, §29 / §49.1; RC 3); the unit waits for the package
    GDA=False; [ "$PGU0" = absent ] || [ "$PGG0" = absent ] && GDA=True
    if [ "$GS1" = "plan=0 deferred=[('pgdg_key', False), ('pgdg_common', False), ('pg_pkg', False), ('pg_confd', $GDA), ('pg_conf', $GDA), ('pg_hba', $GDA), ('pg_service', True)] module=$GMW audit_fresh=7" ]; then
      check v116-pg-plan ok "on a fresh system plan exits 0 with the account, cluster and unit deferred to apply; audit drift (7)"
    else check v116-pg-plan FAIL "$GS1 accounts_absent=$GDA $(v6e pg1)"; v6diag pg1 pg2; fi
    v6t 900 "$EXE" apply "$PG/bundle.yaml" --sudo --format json > "$V6/pg3.json" 2> "$V6/pg3.err"; G3=$?
    GA="apply=$G3:$(v6j "$V6/pg3.json" '[e["exit_code"] for e in d["executions"]]') rpm=$(rpm -q postgresql17-server > /dev/null 2>&1 && echo installed || echo missing) service=$(v6t 15 systemctl is-active postgresql-17 2> /dev/null) confd=$(v6st /var/lib/pgsql/17/data/conf.d '%U:%G:%a')"
    echo "== observe v116-pg-dnf repolist=$(v6t 120 sudo dnf -q repolist --enabled 2> /dev/null | awk '{print $1}' | grep -E '^pgdg(-common|17)$' | sort | tr '\n' ',') pgdg_key_imported=$(rpm -q gpg-pubkey --qf '%{SUMMARY}\n' 2> /dev/null | grep -ci postgresql) module=$(v6body /etc/dnf/modules.d/postgresql.module | sed -n 's/^state=//p' | head -1)"
    echo "V116_PG_APPLY $GA"
    if [ "$GA" = "apply=0:[0, 0, 0, 0, 0, 0, 0] rpm=installed service=active confd=postgres:postgres:700" ]; then
      check v116-pg-apply ok "the bundle applied: PGDG repositories, server package, cluster, configuration validated by postgres, service active"
    else check v116-pg-apply FAIL "$GA $(v6e pg3)"; fi
    v6t 600 "$EXE" apply "$PG/bundle.yaml" --sudo --format json > "$V6/pg4.json" 2> "$V6/pg4.err"; G4=$?
    GR="reapply=$G4:$(v6j "$V6/pg4.json" 'C(d)')"; echo "V116_PG_REAPPLY $GR"
    if [ "$GR" = "reapply=0:['none']" ]; then check v116-pg-reapply ok "second apply of the bundle: no change"
    else check v116-pg-reapply FAIL "$GR $(v6e pg4)"; fi
    v6t 300 "$EXE" audit "$PG/bundle.yaml" --sudo --format json > "$V6/pg5.json" 2> "$V6/pg5.err"; G5=$?
    GU="audit=$G5:$(v6j "$V6/pg5.json" '[(r["id"], r["status"]) for r in R(d) if r["status"] != "compliant"]')"; echo "V116_PG_AUDIT $GU"
    case "$V6MAJ" in 9) GUW="audit=0:[('pg_initdb', 'not_auditable')]" ;; *) GUW="audit=0:[('pg_module_off', 'not_applicable'), ('pg_initdb', 'not_auditable')]" ;; esac
    if [ "$GU" = "$GUW" ]; then check v116-pg-audit ok "audit of the applied bundle: compliant (the initdb command not auditable, the module step not applicable on EL 10)"
    else check v116-pg-audit FAIL "$GU $(v6e pg5)"; fi
    v6_restore v6r_pg
  else for id in $PGIDS; do check "$id" FAIL "prerequisite: existing PostgreSQL or PGDG files=$PGPRE datadir=$PGD0 (never removed); budget left ${PGLEFT}s of the 540 s the bundle needs"; done; fi
elif [ "$V6FAM" = debian ] && [ "$V6DNF" = absent ] && na_allowed v116-pg-plan NOT_DNF_HOST && na_allowed v116-pg-apply NOT_DNF_HOST \
     && na_allowed v116-pg-reapply NOT_DNF_HOST && na_allowed v116-pg-audit NOT_DNF_HOST; then
  for id in $PGIDS; do not_applicable "$id" NOT_DNF_HOST "the bundle installs PGDG RPMs; $LABEL is not a DNF host"; done
else for id in $PGIDS; do check "$id" FAIL "not a DNF 4 host of the RHEL family and not listed as not applicable (family=$V6FAM dnf=$V6DNF)"; done; fi

# ---- v116-secrets-keygen (DESIGN §65, RC 3): the frozen sinter creates an
# age identity on the target, without a terminal and without age-keygen; the
# file is 0600, -y prints the same public key, a file encrypted to it with -r
# decrypts with -i, an existing identity is never replaced, and the private
# key appears in no output. Synthetic key in the harness's private directory,
# removed afterwards; nothing of it is printed.
KG="$V6/keygen"; mkdir -m 700 "$KG"
kg() { local t=$1; shift; v6t 60 "$EXE" secrets "$@" > "$KG/$t.out" 2> "$KG/$t.err" < /dev/null; local rc=$?; printf 'secrets %s rc=%s\n' "$1" "$rc" > "$KG/$t.rc"; return $rc; }
kg k1 keygen -o "$KG/id.txt"; K1=$?
KMODE=$(stat -c %a "$KG/id.txt" 2> /dev/null || echo missing)
KPUB=$(sed -n 's/^Public key: //p' "$KG/k1.err" | head -1)
KSHA=$(sha256sum "$KG/id.txt" 2> /dev/null | cut -d' ' -f1)
KFORM=$(grep -c '^AGE-SECRET-KEY-1[0-9A-Z]*$' "$KG/id.txt" 2> /dev/null)/$(grep -c "^# public key: $KPUB\$" "$KG/id.txt" 2> /dev/null)
kg k2 keygen -y "$KG/id.txt"; K2=$?
KY=$([ -n "$KPUB" ] && [ "$(cat "$KG/k2.out")" = "$KPUB" ] && echo same || echo DIFFERENT)
printf 'v116 keygen synthetic payload\n' > "$KG/plain.txt"
kg k3 encrypt -r "$KPUB" -o "$KG/plain.txt.age" "$KG/plain.txt"; K3=$?
kg k4 decrypt -i "$KG/id.txt" "$KG/plain.txt.age"; K4=$?
KD=$(cmp -s "$KG/k4.out" "$KG/plain.txt" && echo same || echo DIFFERENT)
kg k5 keygen -o "$KG/id.txt"; K5=$?
KAGAIN=$([ "$K5" -ne 0 ] && [ "$(sha256sum "$KG/id.txt" 2> /dev/null | cut -d' ' -f1)" = "$KSHA" ] && echo refused-unchanged || echo REPLACED)
KLEAK=no; KSEC=$(grep '^AGE-SECRET-KEY-1' "$KG/id.txt" 2> /dev/null | head -1)
if [ -z "$KSEC" ]; then KLEAK=unknown
else for f in k1 k2 k3 k4 k5; do grep -qF -- "$KSEC" "$KG/$f.out" "$KG/$f.err" 2> /dev/null && KLEAK=yes; done; fi
KSEC=""
KS="keygen=$K1 mode=$KMODE form=$KFORM pub=$(case "$KPUB" in age1?*) echo age1 ;; *) echo none ;; esac) y=$K2:$KY enc=$K3 dec=$K4:$KD again=$KAGAIN leak=$KLEAK"
echo "V116_KEYGEN $KS"
if [ "$KS" = "keygen=0 mode=600 form=1/1 pub=age1 y=0:same enc=0 dec=0:same again=refused-unchanged leak=no" ]; then
  check v116-secrets-keygen ok "an age identity created by sinter alone: 0600, -y gives its public key, encrypt -r / decrypt -i round trip, never replaced, no secret in any output"
else check v116-secrets-keygen FAIL "$KS"
  for f in k1 k2 k3 k4 k5; do echo "   DIAG $f $(cat "$KG/$f.rc" 2> /dev/null) stderr=$(sed -E 's/AGE-SECRET-KEY-1[0-9A-Za-z]*/<withheld>/g' "$KG/$f.err" 2> /dev/null | head -c 400 | tr '\n' ' ')"; done; fi
rm -rf "$KG"

# ---- v116-no-residue: every restore ran, and what this section changed is as
# it was before (files, names, values, the disposable directories, accounts)
v6_restore_all
NRS="base=$(v6ex "$V6B" && echo left || echo gone) writable=$(v6ex "$V6W" && echo left || echo gone) etc=$(v6ex "$V6E" && echo left || echo gone)"
NRS="$NRS repo=$([ "$DR_PRE" = absent ] && v6ex "$DRF" && echo left || echo ok) sysctl=$([ -z "$SV0" ] || [ "$(sysctl -n "$SK" 2> /dev/null)" = "$SV0" ] && echo ok || echo DIFF)/$(v6ex "$SL" && echo left || echo ok)"
NRS="$NRS names=$([ "$(v6r 15 hostnamectl --static 2> /dev/null)" = "$HS0" ] && v6_same hostname /etc/hostname && v6_same hosts /etc/hosts && v6_same machineinfo /etc/machine-info && echo ok || echo DIFF)"
NRS="$NRS timezone=$(v6_same localtime /etc/localtime && echo ok || echo DIFF) locale=$(v6_same locale "$LF" && v6_same localeconf /etc/locale.conf && [ "$(v6menv)" = "$LME0" ] && echo ok || echo DIFF)"
NRS="$NRS accounts=$([ "$CU0" = absent ] && getent passwd "$V6U" > /dev/null 2>&1 && echo left || echo ok) kmod_file=$([ "$KPRE" = absent ] && v6ex "$KMF" && echo left || echo ok)"
[ -x "$CPT" ] && NRS="$NRS crypto=$([ "$(cp_show)" = "$CP0" ] && echo ok || echo DIFF)"
[ "$DMDO" = yes ] && NRS="$NRS nodejs_module=$([ -z "$(dm_state)" ] && echo ok || echo DIFF)"
[ -n "${TI0:-}" ] && NRS="$NRS tuned=$([ "$(tu_inst && echo yes || echo no)" = "$TI0" ] && echo ok || echo DIFF)"
[ "$V6RH" = yes ] && NRS="$NRS pg=$(v6ex "$PGRF" || [ "$(v6r 15 systemctl is-active postgresql-17 2> /dev/null)" = active ] && echo left || echo ok)"
trap - EXIT TERM HUP INT
echo "V116_NO_RESIDUE $NRS armed=[${V6_ARMED}] elapsed=$(( $(date +%s) - V6_T0 ))s budget=${V6_BUDGET}s"
case " $NRS " in *" base=gone writable=gone etc=gone "*) NRB=ok ;; *) NRB=no ;; esac
if [ "$NRB" = ok ] && ! printf '%s' "$NRS" | grep -qE '=(left|DIFF)|/left' && [ -z "$V6_ARMED" ]; then
  check v116-no-residue ok "disposable directories removed; files, names, values, accounts and packages as before the section"
else check v116-no-residue FAIL "$NRS"; fi
rm -rf "$V6"
# END v1160-checks

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
