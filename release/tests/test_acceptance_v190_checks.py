"""Mock tests for the v1.9.0 acceptance checks (strict audit and package
progress) in acceptance-target.sh.

The two sections between their BEGIN/END markers are extracted from the
harness exactly as written and run against a fake `sinter`. The fake behaves
like the documented contract by default; each defect makes it break one rule,
and the test asserts that exactly the check that guards that rule fails. Paths
under /opt/sinter-acceptance/state are redirected to ./state in a temporary
directory;
nothing else in the sections is changed.
"""
import os
import re
import stat
import subprocess
import tempfile
import textwrap
import unittest

HARNESS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "acceptance-harness")
TARGET = os.path.join(HARNESS, "acceptance-target.sh")
STATE = "/opt/sinter-acceptance/state"

ORIGINAL_33 = """artifact-arch artifact-sha256 audit-no-drift command-guard-first-run
command-guard-honored command-plan executable-sha256 file-create-ok file-idempotent file-update-ok
linkage-resolved no-residue os-arch package-absent-idempotent package-absent-independent-verify
package-independent-verify package-initial-state package-install-apply package-install-idempotent
package-install-plan package-native-parser package-normalise-ok package-remove-apply platform-detect
pre-mutation-failure recipe-validate secret-delivered secret-redaction service-enable-start
service-idempotent ssh-exec sudo-n version-output""".split()

NEW = {
    "progress": ["package-progress-plain", "package-progress-off-by-default",
                 "package-progress-json-silent", "package-progress-restore"],
    "strict": ["audit-strict-not-auditable", "audit-default-policy-unchanged"],
}

FAKE = r'''#!/usr/bin/env python3
import json, os, sys
defect = os.environ.get("FAKE_DEFECT", "")
state, pkg = os.environ["FAKE_STATE"], os.environ["FAKE_PKG"]
args = sys.argv[1:]
cmd, recipe = args[0], args[1]
fmt_json = "--format" in args and args[args.index("--format") + 1] == "json"
plain = os.environ.get("SINTER_PROGRESS") == "plain"
out, err = sys.stdout, sys.stderr
if cmd == "apply":
    present = recipe.endswith("pkg-present.yaml")
    if present and not (defect == "not-installed" and plain and not fmt_json):
        open(pkg, "w").close()
    if not present and defect != "restore-fails" and os.path.exists(pkg):
        os.remove(pkg)
    if fmt_json:
        change = "changed" if defect == "json-change" else "none"
        print(json.dumps({"status": "success", "resources": [{"id": "acc_pkg", "change": change}]}))
        if plain and defect == "json-progress":
            err.write("progress: run: apply started\n")
        sys.exit(0)
    print("== Sinter APPLY ==")
    print("CHANGED  acc_pkg [package]")
    if plain or defect == "default-progress":
        lines = ["progress: run: apply started", "progress: apply: start 0/1",
                 "progress: apply: 0/1 on package:acc_pkg, install 50% (pkg, 1s)",
                 "progress: apply: done 1/1 (2s)", "progress: run: apply completed (2s)"]
        if defect == "missing-close": lines = lines[:-1]
        if defect == "failed-word": lines[3] = "progress: apply: failed 0/1 (2s)"
        if defect == "run-failed": lines[4] = "progress: run: apply failed (2s)"
        if defect == "detail-word": lines[2] = "progress: apply: 0/1 on package:acc_pkg, removing failed-old-pkg (1s)"
        if defect == "other-line": lines.insert(2, "dnf: something the manager printed")
        if defect == "escape": lines[2] = "progress: apply: \x1b[2K0/1"
        if defect == "stdout-progress": print(lines[0])
        err.write("\n".join(lines) + "\n")
    sys.exit(3 if defect == "rc" and plain else 0)
if cmd == "audit":
    strict = "--audit-policy" in args
    if defect == "audit-runs-command":
        open(os.path.join(state, "strict-sentinel.txt"), "w").close()
    cmd_status = "compliant" if defect == "cmd-compliant" else "not_auditable"
    d = {"status": "no_drift", "summary": {"total": 2, "not_auditable": 1},
         "resources": [{"id": "acc_strict_dir", "status": "compliant"},
                       {"id": "acc_strict_cmd", "status": cmd_status}]}
    if strict and defect != "no-policy":
        total = 2 if defect == "policy-total" else 1
        d["audit_policy"] = {"mode": "strict", "not_auditable_total": total, "effective_exit_code": 8}
    if not strict and defect == "default-policy":
        d["audit_policy"] = {"mode": "strict", "not_auditable_total": 1, "effective_exit_code": 8}
    print(json.dumps(d))
    if strict:
        sys.exit(0 if defect == "strict-rc0" else 8)
    sys.exit(8 if defect == "default-rc8" else 0)
sys.exit(99)
'''


def section(name):
    text = open(TARGET, encoding="utf-8").read()
    m = re.search(r"^# BEGIN %s\n(.*?)^# END %s\n" % (name, name), text, re.S | re.M)
    assert m, name
    return m.group(1)


class V190Checks(unittest.TestCase):
    def run_section(self, name, defect=""):
        with tempfile.TemporaryDirectory() as d:
            state = os.path.join(d, "state"); os.mkdir(state)
            s = os.path.join(d, "x"); os.mkdir(s)
            pkg = os.path.join(d, "pkg-installed")
            exe = os.path.join(d, "sinter")
            with open(exe, "w") as f:
                f.write(FAKE)
            os.chmod(exe, os.stat(exe).st_mode | stat.S_IXUSR)
            prelude = textwrap.dedent(f"""\
                set -u
                PASS=0; FAIL=0
                check() {{ if [ "$2" = ok ]; then PASS=$((PASS+1)); echo "== check $1 ok"; echo "   $3";
                  else FAIL=$((FAIL+1)); echo "== check $1 FAIL"; echo "   $3"; fi; }}
                pkg_present() {{ [ -e "{pkg}" ]; }}
                EXE="{exe}"; S="{s}"
                """)
            # Relative, so a temporary path with spaces cannot split the
            # unquoted literal the harness uses for the fixed target path.
            body = section(name).replace(STATE, "./state")
            env = dict(os.environ, FAKE_DEFECT=defect, FAKE_STATE=state, FAKE_PKG=pkg)
            env.pop("SINTER_PROGRESS", None)
            p = subprocess.run(["bash", "-c", prelude + body], capture_output=True, text=True, env=env,
                               timeout=120, cwd=d)
            self.assertEqual(p.returncode, 0, p.stderr)
            ok = re.findall(r"^== check (\S+) ok$", p.stdout, re.M)
            bad = re.findall(r"^== check (\S+) FAIL$", p.stdout, re.M)
            return ok, bad, p.stdout

    def test_the_documented_behavior_passes_every_new_check(self):
        for name, ids in [("progress-checks", NEW["progress"]), ("strict-audit-checks", NEW["strict"])]:
            with self.subTest(section=name):
                ok, bad, log = self.run_section(name)
                self.assertEqual(bad, [], log)
                self.assertEqual(sorted(ok), sorted(ids), log)

    def test_each_progress_defect_fails_its_check(self):
        cases = {
            "rc": "package-progress-plain",
            "not-installed": "package-progress-plain",
            "stdout-progress": "package-progress-plain",
            "other-line": "package-progress-plain",
            "escape": "package-progress-plain",
            "missing-close": "package-progress-plain",
            "failed-word": "package-progress-plain",
            "run-failed": "package-progress-plain",
            "default-progress": "package-progress-off-by-default",
            "json-progress": "package-progress-json-silent",
            "json-change": "package-progress-json-silent",
            "restore-fails": "package-progress-restore",
        }
        for defect, check_id in cases.items():
            with self.subTest(defect=defect):
                ok, bad, log = self.run_section("progress-checks", defect)
                self.assertIn(check_id, bad, log)
                self.assertNotIn(check_id, ok, log)

    def test_package_detail_words_are_never_judged(self):
        # Detail words are not a stable contract: a word such as "failed" in a
        # package name inside a detail line must not fail the check.
        ok, bad, log = self.run_section("progress-checks", "detail-word")
        self.assertEqual(bad, [], log)
        self.assertIn("package-progress-plain", ok, log)

    def test_each_strict_audit_defect_fails_its_check(self):
        cases = {
            "strict-rc0": ["audit-strict-not-auditable"],
            "no-policy": ["audit-strict-not-auditable"],
            "policy-total": ["audit-strict-not-auditable"],
            "cmd-compliant": ["audit-strict-not-auditable", "audit-default-policy-unchanged"],
            "audit-runs-command": ["audit-strict-not-auditable", "audit-default-policy-unchanged"],
            "default-policy": ["audit-default-policy-unchanged"],
            "default-rc8": ["audit-default-policy-unchanged"],
        }
        for defect, ids in cases.items():
            with self.subTest(defect=defect):
                ok, bad, log = self.run_section("strict-audit-checks", defect)
                self.assertEqual(sorted(bad), sorted(ids), log)

    def test_the_expected_id_set_is_derived_and_keeps_the_original_checks(self):
        ids = [l.strip() for l in open(os.path.join(HARNESS, "expected-check-ids.txt")) if l.strip()]
        text = open(TARGET, encoding="utf-8").read()
        derived = sorted({m.split()[1] for m in re.findall(r"check [A-Za-z0-9_-]+ (?:ok|FAIL)", text)})
        self.assertEqual(ids, derived)
        self.assertTrue(set(ORIGINAL_33) <= set(ids))
        self.assertEqual(len(ORIGINAL_33), 33)
        # Later releases add their own checks (test_acceptance_v1120_checks.py
        # owns the full set); the v1.9.0 checks must all still be there.
        self.assertTrue(set(NEW["progress"] + NEW["strict"]) <= set(ids) - set(ORIGINAL_33))
        for new_id in NEW["progress"] + NEW["strict"]:
            self.assertEqual(len(re.findall(r"check %s ok" % re.escape(new_id), text)), 1, new_id)
            self.assertEqual(len(re.findall(r"check %s FAIL" % re.escape(new_id), text)), 1, new_id)


if __name__ == "__main__":
    unittest.main()
