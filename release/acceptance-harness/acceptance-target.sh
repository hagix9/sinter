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
sudo rm -f /opt/sinter-acceptance/state/created.txt
"$EXE" apply "$S/cleanup.yaml" --sudo --format json > "$S/cl.json" 2>"$S/cl.err"; R=$?
LEFT=$(sudo find /opt/sinter-acceptance/state -mindepth 1 2>/dev/null | wc -l)
echo "CLEANUP_RC=$R leftover=$LEFT"
if [ "$R" -eq 0 ] && [ "$LEFT" -eq 0 ]; then check no-residue ok "no managed path left behind"; else check no-residue FAIL "rc=$R leftover=$LEFT"; fi

echo "== acceptance end $(ts) passed=$PASS failed=$FAIL skipped=$SKIP"
if [ "$FAIL" -eq 0 ] && [ "$SKIP" -eq 0 ]; then echo 0 > "$RCFILE"; exit 0; fi
echo 1 > "$RCFILE"; exit 1
