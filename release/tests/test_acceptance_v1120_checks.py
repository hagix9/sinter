"""Mock tests for the v1.12.0 acceptance checks (plugin management and
per-recipe variables) in acceptance-target.sh.

The two sections between their BEGIN/END markers are extracted from the
harness exactly as written and run against a fake `sinter` that follows the
documented contract (DESIGN §38.15, §38.16, §38.4 C1 and §40.5). Each defect
makes the fake break one rule, and the test asserts that the check guarding
that rule fails. Paths under /opt/sinter-acceptance/state are redirected to
./state in a temporary directory, WORK and HOME point into it, and `sudo` is a
shell function that marks the fake as running as root; nothing else in the
sections is changed.

With SINTER_ACCEPTANCE_REAL_BIN=<path to a built sinter>, the plugin section
also runs against that binary (a Unix controller is enough: the plugin commands
contact no target). Its root-run check needs a real `sudo` and is expected to
fail there; it is covered by the fake. The recipe_vars section writes files on
the local target and runs on Linux only, in the release acceptance.
"""
import hashlib
import os
import re
import stat
import subprocess
import tempfile
import textwrap
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
HARNESS = os.path.join(os.path.dirname(HERE), "acceptance-harness")
TARGET = os.path.join(HARNESS, "acceptance-target.sh")
FIRST_PARTY = os.path.join(os.path.dirname(os.path.dirname(HERE)), "plugins", "first-party")
STATE = "/opt/sinter-acceptance/state"

ORIGINAL_39 = """artifact-arch artifact-sha256 audit-default-policy-unchanged audit-no-drift
audit-strict-not-auditable command-guard-first-run command-guard-honored command-plan
executable-sha256 file-create-ok file-idempotent file-update-ok linkage-resolved no-residue os-arch
package-absent-idempotent package-absent-independent-verify package-independent-verify
package-initial-state package-install-apply package-install-idempotent package-install-plan
package-native-parser package-normalise-ok package-progress-json-silent package-progress-off-by-default
package-progress-plain package-progress-restore package-remove-apply platform-detect
pre-mutation-failure recipe-validate secret-delivered secret-redaction service-enable-start
service-idempotent ssh-exec sudo-n version-output""".split()

NEW = {
    "plugin-checks": [
        "plugin-list-available", "plugin-verify-nothing-refused", "plugin-install-dry-run",
        "plugin-install-needs-confirmation", "plugin-install", "plugin-verify-installed",
        "plugin-install-idempotent", "plugin-root-run-refused", "plugin-c1-refused-before-contact",
        "plugin-c1-allowed-by-type", "plugin-tamper-refused", "plugin-unsafe-root-refused",
        "plugin-remove", "plugin-no-residue",
    ],
    "recipe-vars-checks": [
        "recipe-vars-per-recipe", "recipe-vars-shown-no-foreign-warning", "recipe-vars-refuse-vars-file",
        "recipe-vars-untrusted-file-refused", "recipe-vars-absent-shared-files",
        "recipe-vars-no-config-defaults", "recipe-vars-no-residue",
    ],
}

FAKE = r'''#!/usr/bin/env python3
"""A stand-in for sinter that follows the documented contract; FAKE_DEFECT breaks one rule."""
import json, os, re, stat, sys
defect = os.environ.get("FAKE_DEFECT", "")
state = os.environ["FAKE_STATE"]
fp = os.environ["FAKE_FIRST_PARTY"]
as_root = os.environ.get("FAKE_AS_ROOT") == "1"
args = sys.argv[1:]
CAT = os.path.join("catalogs", "firewalld-0.2.0.catalog.toml")
PLG = os.path.join("plugins", "firewalld-0.2.0.plugin.toml")
OBSERVE = ["state", "zone_defined", "service_defined", "query_service_runtime", "query_service_permanent",
           "query_port_runtime", "query_port_permanent", "query_protocol_runtime", "query_protocol_permanent"]
MUTATE = [a + "_" + k + "_" + w for k in ("service", "port", "protocol") for a in ("add", "remove")
          for w in ("runtime", "permanent")]
PORT_OPS = ["add_port_runtime", "add_port_permanent", "remove_port_runtime", "remove_port_permanent"]
GATE = "plan and apply refuse it before contacting any target"

def opt(name):
    return args[args.index(name) + 1] if name in args else None

def out(d, rc):
    print(json.dumps(d)); sys.exit(rc)

def embedded(rel):
    return open(os.path.join(fp, rel), "rb").read()

def unsafe(root):
    return os.path.isdir(root) and os.stat(root).st_mode & 0o022 and defect != "unsafe-ok"

def allowed(root):
    try: t = open(os.path.join(root, "trust.toml")).read()
    except OSError: return None
    if "[[plugin]]" not in t: return None
    m = re.search(r"allowed_mutate = \[(.*?)\]", t)
    return [x.strip(' "') for x in m.group(1).split(",") if x.strip()] if m else []

def installed(root):
    return allowed(root) is not None and os.path.exists(os.path.join(root, PLG))

def plugin_cmd():
    sub, root = args[1], opt("--plugin-root")
    if defect == "default-root":
        os.makedirs(os.path.join(os.environ["HOME"], ".config", "sinter", "plugins"), exist_ok=True)
    if sub == "list":
        if unsafe(root): sys.stderr.write("sinter: plugin: writable by group or others\n"); sys.exit(2)
        inst = installed(root) or defect == "list-installed"
        out({"plugins": [
            {"id": "firewalld", "version": "0.1.0", "available": True, "installed": False, "status": "available"},
            {"id": "firewalld", "version": "0.2.0", "available": True, "installed": bool(inst),
             "status": "installed" if inst else "available"}]}, 0)
    if sub == "verify":
        if unsafe(root): sys.exit(2)
        if not os.path.isdir(root):
            out({"ok": defect == "verify-absent-ok", "nothing_verified": None if defect == "verify-absent-ok" else "root-absent", "plugins": []},
                0 if defect == "verify-absent-ok" else 2)
        if as_root and defect == "root-other-reason":
            sys.stderr.write("sinter: plugin: trust.toml: invalid\n")
            out({"ok": False, "nothing_verified": None, "plugins": []}, 2)
        if as_root and defect != "root-accepted":
            sys.stderr.write("sinter: plugin: /x: an ancestor of the plugin root is owned by another user\n")
            out({"ok": False, "nothing_verified": None, "plugins": [{"status": "refused"}]}, 2)
        al = allowed(root)
        if al is None: out({"ok": False, "nothing_verified": "nothing-pinned", "plugins": []}, 2)
        same = open(os.path.join(root, PLG), "rb").read() == embedded(PLG)
        status = "ok" if same or defect == "tamper-ok" else "digest-mismatch"
        nmut = [m for m in MUTATE if m not in al]
        if defect == "verify-mutate-allowed": nmut = nmut[:3]
        checks = [{"name": n, "result": "pass" if status == "ok" else "fail"} for n in ("embedded", "load")]
        out({"ok": status == "ok", "nothing_verified": None, "plugins": [{"status": status, "required_not_enabled": [],
             "mutate_not_allowed": nmut, "checks": checks}]}, 0 if status == "ok" else 2)
    if sub == "install":
        allow = []
        if opt("--allow-mutate-for") == "firewalld.port": allow = list(PORT_OPS)
        if defect == "allow-for-all" and allow: allow = list(MUTATE)
        base = {"result": "planned", "allowed_mutate": allow, "mutate_not_allowed": [m for m in MUTATE if m not in allow],
                "trust": "unchanged", "verify": None}
        if "--dry-run" in args:
            if defect == "dryrun-writes": os.makedirs(root, exist_ok=True)
            out(base, 0)
        if "--yes" not in args and defect != "noyes-installs":
            base["result"] = "refused"; out(base, 2)
        if installed(root):
            if defect == "reinstall-rewrites":
                open(os.path.join(root, "trust.toml"), "a").write("# again\n")
            base.update(result="nothing-to-do"); out(base, 0)
        for sub_dir in ("", "catalogs", "plugins"):
            os.makedirs(os.path.join(root, sub_dir), exist_ok=True); os.chmod(os.path.join(root, sub_dir), 0o700)
        fmode = 0o644 if defect == "mode-644" else 0o600
        for rel in (CAT, PLG):
            data = embedded(rel) + (b"x" if defect == "wrong-bytes" else b"")
            open(os.path.join(root, rel), "wb").write(data); os.chmod(os.path.join(root, rel), fmode)
        t = os.path.join(root, "trust.toml")
        open(t, "w").write('format = 1\n\n[[catalog]]\nallowed_mutate = [%s]\n\n[[plugin]]\nid = "firewalld"\n'
                           % ", ".join('"%s"' % a for a in allow))
        os.chmod(t, 0o600)
        base.update(result="installed", trust="created", verify="ok"); out(base, 0)
    if sub == "remove":
        p = os.path.join(root, PLG)
        if open(p, "rb").read() != embedded(PLG) and defect != "remove-tampered":
            out({"result": "refused", "trust": "unchanged"}, 2)
        t = os.path.join(root, "trust.toml")
        if defect != "no-prev":
            open(t + ".prev", "w").write(open(t).read()); os.chmod(t + ".prev", 0o600)
        open(t, "w").write("format = 1\n")
        if defect != "remove-keeps-files":
            for rel in (CAT, PLG): os.remove(os.path.join(root, rel))
        out({"result": "removed", "trust": "rewritten"}, 0)
    sys.exit(99)

def plugin_recipe():
    cmd, root = args[0], opt("--plugin-root")
    if cmd == "validate": sys.exit(0)
    al = allowed(root) or []
    need = ["add_port_permanent", "add_port_runtime"]
    gated = [m for m in need if m not in al]
    if cmd in ("plan", "apply") and gated and defect != "c1-no-gate":
        sys.stderr.write("sinter: acc_fw_port: resource type firewalld.port could need mutate operations the trust "
                         "file does not allow: %s; %s\n" % (", ".join(gated), GATE)); sys.exit(2)
    if cmd == "audit" and defect == "audit-gated":
        sys.stderr.write("sinter: %s\n" % GATE); sys.exit(2)
    sys.stderr.write("sinter: cannot resolve SSH address nohost.invalid:22\n"); sys.exit(3)

def kv(path):
    m = re.search(r"vars: \{(.*)\}", open(path).read())
    return dict(x.strip().split(": ", 1) for x in m.group(1).split(",")) if m else {}

def rv_apply(recipe):
    if recipe == "clean.yaml":
        for x in "abc":
            p = os.path.join(state, "rv-%s.txt" % x)
            if os.path.exists(p) and defect != "clean-fails": os.remove(p)
        sys.exit(0)
    project = None if "--no-config" in args else (open("sinter.yaml").read() if os.path.exists("sinter.yaml") else None)
    if defect == "noconfig-reads" and project is None: project = open("sinter.yaml").read()
    per = {}
    shared = []
    if project and "recipe_vars" in project:
        if "--vars-file" in args and defect == "vars-file-other-reason":
            sys.stderr.write("sinter: cannot read a file\n"); sys.exit(2)
        if "--vars-file" in args and defect != "vars-file-accepted":
            sys.stderr.write("sinter: --vars-file cannot be used with the recipe_vars of project file\n"); sys.exit(2)
        cur = None
        for line in project.splitlines():
            m = re.match(r"  (\w+):$", line)
            if m: cur = m.group(1); per[cur] = []; continue
            m = re.match(r"    - (\S+)$", line)
            if m: per[cur].append(m.group(1))
    elif project and "vars_files" in project:
        shared = re.search(r"vars_files: \[(.*)\]", project).group(1).split(", ")
        if defect == "shared-broken": shared = []
    for f in [f for fs in per.values() for f in fs] + shared:
        if os.stat(f).st_mode & 0o022 and defect == "untrusted-other-reason":
            sys.stderr.write("sinter: variables: the static checks failed\n"); sys.exit(2)
        if os.stat(f).st_mode & 0o022 and defect != "untrusted-accepted":
            sys.stderr.write("sinter: file named by the project file %s: writable by group or others (mode 666)\n" % f)
            sys.stderr.write("sinter: variables: the static checks failed\n"); sys.exit(2)
    labels = {"a": "10_a", "b": "20_b", "c": "30_c"}
    if per:
        for x in "abc":
            if labels[x] in per: sys.stderr.write("vars: recipe %s: %s\n" % (labels[x], ", ".join(per[labels[x]])))
            else: sys.stderr.write("vars: none for recipe %s (not listed in recipe_vars)\n" % labels[x])
        if defect == "warn": sys.stderr.write("sinter: 20_b: variable msg_a is not declared by the recipe\n")
    for x in "abc":
        vals = {"msg_" + x: x + "-default", "common": x + "-common-default"}
        files = list(shared) if shared else list(per.get(labels[x], []))
        if defect == "leak" and per: files = [f for fs in per.values() for f in fs]
        if defect == "unlisted-gets" and per and x == "c": files = per["10_a"]
        if defect == "order": files = list(reversed(files))
        for f in files:
            for k, v in kv(f).items():
                if k in vals: vals[k] = v
        open(os.path.join(state, "rv-%s.txt" % x), "w").write("%s|%s\n" % (vals["msg_" + x], vals["common"]))
    sys.exit(0)

if args[0] == "plugin": plugin_cmd()
if "--plugin-root" in args: plugin_recipe()
if args[0] == "apply": rv_apply(args[1])
sys.exit(99)
'''


def section(name):
    text = open(TARGET, encoding="utf-8").read()
    m = re.search(r"^# BEGIN %s\n(.*?)^# END %s\n" % (name, name), text, re.S | re.M)
    assert m, name
    return m.group(1)


def results(stdout):
    return (re.findall(r"^== check (\S+) ok$", stdout, re.M), re.findall(r"^== check (\S+) FAIL$", stdout, re.M))


class V1120Checks(unittest.TestCase):
    def run_section(self, name, defect="", exe=None):
        # The private directory of a run (mode 0700 below a sticky or root-owned
        # ancestor) is what the plugin root's ancestor checks see on a target.
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d, 0o700)
            state = os.path.join(d, "state"); os.mkdir(state)
            s = os.path.join(d, "x"); os.mkdir(s)
            home = os.path.join(d, "home"); os.mkdir(home, 0o700)
            if exe is None:
                exe = os.path.join(d, "sinter")
                with open(exe, "w") as f:
                    f.write(FAKE)
                os.chmod(exe, os.stat(exe).st_mode | stat.S_IXUSR)
            prelude = textwrap.dedent(f"""\
                set -u
                PASS=0; FAIL=0
                check() {{ if [ "$2" = ok ]; then PASS=$((PASS+1)); echo "== check $1 ok"; echo "   $3";
                  else FAIL=$((FAIL+1)); echo "== check $1 FAIL"; echo "   $3"; fi; }}
                sudo() {{ [ "$1" = -n ] && shift; FAKE_AS_ROOT=1 "$@"; }}
                command -v sha256sum > /dev/null || sha256sum() {{ shasum -a 256 "$@"; }}
                EXE="{exe}"; S="{s}"; WORK="{d}"
                """)
            body = section(name).replace(STATE, os.path.join(d, "state"))
            env = dict(os.environ, FAKE_DEFECT=defect, FAKE_STATE=state, FAKE_FIRST_PARTY=FIRST_PARTY, HOME=home)
            env.pop("XDG_CONFIG_HOME", None)
            p = subprocess.run(["bash", "-c", prelude + body], capture_output=True, text=True, env=env,
                               timeout=300, cwd=d)
            self.assertEqual(p.returncode, 0, p.stderr)
            ok, bad = results(p.stdout)
            return ok, bad, p.stdout + p.stderr

    def test_the_documented_behavior_passes_every_new_check(self):
        for name, ids in NEW.items():
            with self.subTest(section=name):
                ok, bad, log = self.run_section(name)
                self.assertEqual(bad, [], log)
                self.assertEqual(sorted(ok), sorted(ids), log)

    def test_each_plugin_defect_fails_its_check(self):
        cases = {
            "list-installed": "plugin-list-available",
            "verify-absent-ok": "plugin-verify-nothing-refused",
            "dryrun-writes": "plugin-install-dry-run",
            "noyes-installs": "plugin-install-needs-confirmation",
            "mode-644": "plugin-install",
            "wrong-bytes": "plugin-install",
            "verify-mutate-allowed": "plugin-verify-installed",
            "reinstall-rewrites": "plugin-install-idempotent",
            "root-accepted": "plugin-root-run-refused",
            "root-other-reason": "plugin-root-run-refused",
            "c1-no-gate": "plugin-c1-refused-before-contact",
            "audit-gated": "plugin-c1-refused-before-contact",
            "allow-for-all": "plugin-c1-allowed-by-type",
            "tamper-ok": "plugin-tamper-refused",
            "remove-tampered": "plugin-tamper-refused",
            "unsafe-ok": "plugin-unsafe-root-refused",
            "remove-keeps-files": "plugin-remove",
            "no-prev": "plugin-remove",
            "default-root": "plugin-no-residue",
        }
        for defect, check_id in cases.items():
            with self.subTest(defect=defect):
                ok, bad, log = self.run_section("plugin-checks", defect)
                self.assertIn(check_id, bad, log)
                self.assertNotIn(check_id, ok, log)

    def test_each_recipe_vars_defect_fails_its_check(self):
        cases = {
            "leak": "recipe-vars-per-recipe",
            "order": "recipe-vars-per-recipe",
            "unlisted-gets": "recipe-vars-per-recipe",
            "warn": "recipe-vars-shown-no-foreign-warning",
            "vars-file-accepted": "recipe-vars-refuse-vars-file",
            "vars-file-other-reason": "recipe-vars-refuse-vars-file",
            "untrusted-accepted": "recipe-vars-untrusted-file-refused",
            "untrusted-other-reason": "recipe-vars-untrusted-file-refused",
            "shared-broken": "recipe-vars-absent-shared-files",
            "noconfig-reads": "recipe-vars-no-config-defaults",
            "clean-fails": "recipe-vars-no-residue",
        }
        for defect, check_id in cases.items():
            with self.subTest(defect=defect):
                ok, bad, log = self.run_section("recipe-vars-checks", defect)
                self.assertIn(check_id, bad, log)
                self.assertNotIn(check_id, ok, log)

    def test_a_run_leaves_nothing_behind(self):
        # The sections remove their own plugin roots and project directory.
        for name in NEW:
            ok, bad, log = self.run_section(name)
            self.assertNotIn("no-residue", " ".join(bad), log)

    def test_the_embedded_digests_match_the_first_party_files(self):
        text = section("plugin-checks")
        for var, rel in [("CAT_SHA", "catalogs/firewalld-0.2.0.catalog.toml"),
                         ("PLG_SHA", "plugins/firewalld-0.2.0.plugin.toml")]:
            want = re.search(r"^%s=([0-9a-f]{64})" % var, text, re.M).group(1)
            got = hashlib.sha256(open(os.path.join(FIRST_PARTY, rel), "rb").read()).hexdigest()
            self.assertEqual(want, got, rel)

    def test_no_new_check_touches_the_host_firewall_or_a_reachable_host(self):
        text = section("plugin-checks") + section("recipe-vars-checks")
        self.assertNotIn("firewall-cmd", re.sub(r"^#.*$", "", text, flags=re.M))
        for line in text.splitlines():
            if "--host" in line and not line.lstrip().startswith("#"):
                self.assertIn('--host "$NOHOST"', line)
        self.assertIn("NOHOST=nohost.invalid", text)

    @unittest.skipUnless(os.environ.get("SINTER_ACCEPTANCE_REAL_BIN"), "SINTER_ACCEPTANCE_REAL_BIN not set")
    def test_the_plugin_section_against_a_real_binary(self):
        ok, bad, log = self.run_section("plugin-checks", exe=os.environ["SINTER_ACCEPTANCE_REAL_BIN"])
        # `sudo` here is the stand-in function: a real binary is not run as root.
        self.assertEqual(bad, ["plugin-root-run-refused"], log)
        self.assertEqual(sorted(ok), sorted(set(NEW["plugin-checks"]) - {"plugin-root-run-refused"}), log)

    def test_the_expected_id_set_is_derived_and_keeps_the_original_checks(self):
        ids = [l.strip() for l in open(os.path.join(HARNESS, "expected-check-ids.txt")) if l.strip()]
        text = open(TARGET, encoding="utf-8").read()
        derived = sorted({m.split()[1] for m in re.findall(r"check [A-Za-z0-9_-]+ (?:ok|FAIL)", text)})
        self.assertEqual(ids, derived)
        self.assertEqual(len(ORIGINAL_39), 39)
        self.assertTrue(set(ORIGINAL_39) <= set(ids))
        new = NEW["plugin-checks"] + NEW["recipe-vars-checks"]
        self.assertEqual(set(ids) - set(ORIGINAL_39), set(new))
        self.assertEqual(len(ids), 39 + len(new))
        for new_id in new:
            self.assertEqual(len(re.findall(r"check %s ok" % re.escape(new_id), text)), 1, new_id)
            self.assertEqual(len(re.findall(r"check %s FAIL" % re.escape(new_id), text)), 1, new_id)


if __name__ == "__main__":
    unittest.main()
