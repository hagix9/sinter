"""Mock tests for the v1.15.0 firewalld 0.3.0 acceptance checks (the
fw03-checks section of acceptance-target.sh, P7-R1).

The section between its BEGIN/END markers is extracted from the harness
exactly as written and run against a fake `sinter` that follows the documented
contract (DESIGN §43.2, §43.4, §44.3, §44.4), a fake `firewall-cmd` with a
runtime and a permanent configuration, a fake `ip` and a fake `ssh`. Each
defect makes one fake break one rule, and the test asserts that the check
guarding that rule fails. `sudo` is a shell function; /etc/firewalld is
redirected to a temporary directory; nothing else in the section is changed.

The real behaviour (firewalld exit codes, the loopback management path, the
reload rule, NetworkManager, the dummy device) is measured on real hosts only
(docs/design/v1.15.0-release-and-acceptance.md §3.2); these tests show that
the harness does not report PASS when the product breaks a rule, and that it
never removes what it did not create.
"""
import json
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
IDS = ["fw03-zone", "fw03-interface", "fw03-source", "fw03-reload", "risk-approved-apply", "fw03-no-residue"]

FIREWALL_CMD = r'''#!/usr/bin/env python3
"""A stand-in for firewall-cmd: runtime and permanent zones in a JSON file."""
import json, os, sys
st_path = os.environ["FAKE_FW"]; etc = os.environ["FAKE_ETC"]; defect = os.environ.get("FAKE_DEFECT", "")
st = json.load(open(st_path))
a = sys.argv[1:]
perm = "--permanent" in a
a = [x for x in a if x != "--permanent"]
def save():
    json.dump(st, open(st_path, "w"))
def zfile(z):
    d = os.path.join(etc, "zones"); os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, z + ".xml"), "w") as f:
        f.write(json.dumps(st["perm"][z], sort_keys=True))
def opt(name):
    for x in a:
        if x.startswith(name + "="):
            return x.split("=", 1)[1]
    return None
if not st["running"]:
    sys.exit(252)
view = st["perm"] if perm else st["rt"]
if a == ["--state"]:
    print("running"); sys.exit(0)
if a == ["--version"]:
    print("9.9.9"); sys.exit(0)
if a == ["--reload"]:
    st["rt"] = json.loads(json.dumps(st["perm"]))
    if defect == "reload-residue":
        open(os.path.join(etc, "direct.xml"), "w").write("x")
    save(); sys.exit(0)
if a == ["--get-zones"]:
    print(" ".join(sorted(view))); sys.exit(0)
if a == ["--get-default-zone"]:
    print(st["default"]); sys.exit(0)
z = opt("--get-zone-of-interface")
if z is not None:
    for name, c in sorted(st["rt"].items()):
        if z in c["interface"]:
            print(name); sys.exit(0)
    print("no zone"); sys.exit(2)
nz = opt("--new-zone")
if nz is not None and perm:
    if nz in st["perm"]:
        sys.exit(26)
    st["perm"][nz] = {"interface": [], "source": [], "port": [], "service": []}; zfile(nz); save(); sys.exit(0)
dz = opt("--delete-zone")
if dz is not None and perm:
    if dz not in st["perm"]:
        sys.exit(112)
    del st["perm"][dz]
    f = os.path.join(etc, "zones", dz + ".xml")
    if os.path.exists(f):
        os.replace(f, f + ".old")
    save(); sys.exit(0)
iz = opt("--info-zone")
if iz is not None:
    if iz not in view:
        sys.exit(112)
    print(json.dumps(view[iz])); sys.exit(0)
zone = opt("--zone") or st["default"]
if zone not in view:
    sys.exit(112)
c = view[zone]
if "--list-all" in a:
    print(zone, json.dumps(c, sort_keys=True)); sys.exit(0)
for verb in ("query", "add", "remove", "change"):
    for kind in ("interface", "source", "port", "service"):
        v = opt("--%s-%s" % (verb, kind))
        if v is None:
            continue
        if verb == "query":
            sys.exit(0 if v in c[kind] else 1)
        if verb in ("add", "change"):
            if verb == "change":
                for other in view.values():
                    if v in other[kind]:
                        other[kind].remove(v)
            if v not in c[kind]:
                c[kind].append(v)
        elif v in c[kind]:
            c[kind].remove(v)
        if perm:
            zfile(zone)
        save(); sys.exit(0)
sys.stderr.write("fake firewall-cmd: unsupported %r\n" % (sys.argv[1:],)); sys.exit(99)
'''

IP = r'''#!/usr/bin/env python3
import json, os, sys
st_path = os.environ["FAKE_FW"]; st = json.load(open(st_path)); a = sys.argv[1:]
if a[:4] == ["-o", "route", "show", "default"]:
    print("default via 192.0.2.1 dev ens4 proto dhcp metric 100"); sys.exit(0)
if a[:2] == ["link", "add"]:
    if a[2] in st["links"] or os.environ.get("FAKE_DEFECT") == "no-dummy":
        sys.exit(2)
    st["links"].append(a[2]); json.dump(st, open(st_path, "w")); sys.exit(0)
if a[:2] == ["link", "del"]:
    if a[2] not in st["links"]:
        sys.exit(1)
    st["links"].remove(a[2]); json.dump(st, open(st_path, "w")); sys.exit(0)
if a[:3] == ["-o", "link", "show"]:
    if a[3] in st["links"]:
        print("9: %s: <BROADCAST,NOARP> mtu 1500" % a[3]); sys.exit(0)
    sys.stderr.write('Device "%s" does not exist.\n' % a[3]); sys.exit(1)
sys.exit(99)
'''

SSH = r'''#!/usr/bin/env python3
import json, os, sys
st = json.load(open(os.environ["FAKE_FW"]))
sys.exit(0 if st["ssh_ok"] and "ssh" in st["rt"].get("public", {}).get("service", []) else 255)
'''

SINTER = r'''#!/usr/bin/env python3
"""A stand-in for sinter that follows the documented contract; FAKE_DEFECT breaks one rule."""
import hashlib, json, os, re, secrets, subprocess, sys
defect = os.environ.get("FAKE_DEFECT", "")
args = sys.argv[1:]
store = os.path.join(os.environ.get("XDG_STATE_HOME", "/nonexistent"), "sinter")
KEY = b"synthetic-fake-key"

def opt(name):
    return args[args.index(name) + 1] if name in args else None

def fw(*a):
    return subprocess.run(["firewall-cmd"] + list(a), capture_output=True).returncode

def fwst():
    return json.load(open(os.environ["FAKE_FW"]))

def canon(d):
    return json.dumps(d, sort_keys=True, separators=(",", ":"))

def recipe(path):
    t = open(path).read()
    ty = re.search(r"type: firewalld\.(\w+)", t).group(1)
    w = dict(kv.split(": ", 1) for kv in re.search(r"with: \{ (.*) \}", t).group(1).split(", "))
    return t, ty, w, "notify:" in t

def klass(ty, w):
    if ty in ("interface", "source") or (ty == "zone" and w["state"] == "absent"):
        return "R"
    return "N"

def observe(ty, w):
    z = w["zone"]
    if ty == "zone":
        return {"permanent": fw("--permanent", "--info-zone=" + z)}
    f = {"interface": "interface", "source": "source", "port": "port"}[ty]
    return {"runtime": fw("--zone=" + z, "--query-%s=%s" % (f, w[f])),
            "permanent": fw("--permanent", "--zone=" + z, "--query-%s=%s" % (f, w[f]))}

def content(path):
    t, ty, w, _ = recipe(path)
    return {"recipe": t, "observed": observe(ty, w), "host": "127.0.0.1"}

def mac(req):
    return hashlib.sha256(KEY + canon(req).encode()).hexdigest()

def ledger(ev):
    with open(os.path.join(store, "ledger.jsonl"), "a") as f:
        f.write(json.dumps(ev) + "\n")

def run(path, mode):
    t, ty, w, notify = recipe(path)
    z = w["zone"]; obs = observe(ty, w); want = 0 if w["state"] == "present" else 1
    changed = False
    if ty == "zone":
        if obs["permanent"] != want and defect != "zone-not-deleted":
            if mode == "apply":
                fw("--permanent", ("--new-zone=" if want == 0 else "--delete-zone=") + z)
            changed = True
        elif defect == "zone-not-deleted" and w["state"] == "absent":
            changed = True
    else:
        f = {"interface": "interface", "source": "source", "port": "port"}[ty]
        verb = ("change" if f == "interface" else "add") if want == 0 else "remove"
        for facet in ("runtime", "permanent"):
            if obs[facet] != want:
                changed = True
                if mode == "apply" and not (facet == "permanent" and defect == "runtime-only"):
                    fw(*((["--permanent"] if facet == "permanent" else []) + ["--zone=" + z, "--%s-%s=%s" % (verb, f, w[f])]))
        if defect == "not-idempotent":
            changed = True
        if mode == "apply" and defect in ("touch-mgmt", "touch-mgmt-perm") and ty == "interface":
            fw("--zone=public", "--remove-service=ssh")
            if defect == "touch-mgmt-perm":
                fw("--permanent", "--zone=public", "--remove-service=ssh")
    handlers = []
    rc = 0
    if mode == "apply" and notify and changed and defect != "reload-not-run":
        if defect == "reload-refused":
            sys.stderr.write("handler acc_fw_reload: management path unknown: reload on a declared loopback path is not measured\n")
            handlers.append({"id": "acc_fw_reload", "state": "Failed", "provenance": None}); rc = 5
        else:
            fw("--reload")
            if defect == "ssh-cut":
                s = fwst(); s["ssh_ok"] = False; json.dump(s, open(os.environ["FAKE_FW"], "w"))
            handlers.append({"id": "acc_fw_reload", "state": "Succeeded",
                             "provenance": "plugin firewalld 0.3.0 catalog firewalld 0.3.0 sha256 " + "ab" * 32 + " op reload"})
    print(json.dumps({"resources": [{"id": "acc_fw", "change": "changed" if changed else "none"}], "handlers": handlers}))
    return rc

def approved_record(aid):
    p = os.path.join(store, "approvals", aid + ".json")
    return json.load(open(p)) if os.path.exists(p) else None

cmd = args[0]
if cmd == "plugin" and args[1] == "list":
    vs = ["0.1.0", "0.2.0"] + ([] if defect == "no-030" else ["0.3.0"])
    print(json.dumps({"plugins": [{"id": "firewalld", "version": v, "available": True} for v in vs]})); sys.exit(0)
if cmd == "plugin" and args[1] == "install":
    os.makedirs(opt("--plugin-root"), mode=0o700, exist_ok=True); print("{}"); sys.exit(0)
if cmd == "plan":
    path = args[1]
    os.makedirs(store, mode=0o700, exist_ok=True)
    rc = run(path, "plan")
    d = opt("--approval-request")
    if d:
        os.makedirs(d, mode=0o700, exist_ok=True)
        c = content(path)
        req = {"content": c, "content_digest": hashlib.sha256(canon(c).encode()).hexdigest(), "created_at": 1,
               "nonce": secrets.token_hex(16)}
        req["mac"] = mac(req)
        p = os.path.join(d, "127.0.0.1.request.json")
        with open(p, "x") as f:
            f.write(json.dumps(req))
        sys.stderr.write("approval request written: %s\n" % p)
    sys.exit(rc)
if cmd == "approve":
    if not (os.isatty(0) and os.isatty(1)):
        sys.stderr.write("sinter approve needs a terminal on stdin and stdout\n"); sys.exit(2)
    req = json.load(open(args[1]))
    m = req.pop("mac", "")
    if m != mac(req) and defect != "tamper-ok":
        if defect == "tamper-other-reason":
            print("sinter: the request names no valid host"); sys.exit(2)
        print("sinter: the request fails its integrity check (edited, or not written by this controller)"); sys.exit(2)
    rd = hashlib.sha256(canon(req).encode()).hexdigest()
    print("host: 127.0.0.1")
    print("content digest: " + req["content_digest"])
    sys.stdout.write("type the first 16 hex digits of the content digest to approve: "); sys.stdout.flush()
    line = sys.stdin.readline().strip()
    if line != req["content_digest"][:16]:
        print("not approved"); sys.exit(2)
    for sub in ("approvals", "approvals/by-request", "used"):
        os.makedirs(os.path.join(store, sub), mode=0o700, exist_ok=True)
    open(os.path.join(store, "approvals/by-request", rd), "x").close()
    aid = secrets.token_hex(16)
    json.dump({"approval_id": aid, "host": "127.0.0.1", "request_digest": rd, "content_digest": req["content_digest"]},
              open(os.path.join(store, "approvals", aid + ".json"), "w"))
    print("approved: " + aid); sys.exit(0)
if cmd == "approvals":
    applied = set()
    if os.path.exists(os.path.join(store, "ledger.jsonl")):
        applied = {json.loads(l)["approval_id"] for l in open(os.path.join(store, "ledger.jsonl")) if '"applied"' in l}
    for n in sorted(os.listdir(os.path.join(store, "approvals"))):
        if n.endswith(".json"):
            r = json.load(open(os.path.join(store, "approvals", n)))
            used = os.path.exists(os.path.join(store, "used", r["request_digest"]))
            state = ("used" if r["approval_id"] in applied else "used (interrupted: state unknown)") if used else "unused"
            print("%s host=127.0.0.1 %s" % (r["approval_id"], state))
    sys.exit(0)
if cmd == "apply":
    path = args[1]
    _, ty, w, _ = recipe(path)
    aid = opt("--approval")
    if klass(ty, w) == "R" and not aid and defect != "no-approval-needed":
        sys.stderr.write("connection-risk resources acc_fw need an approval; nothing was contacted\n"); sys.exit(2)
    if aid:
        rec = approved_record(aid)
        if rec is None:
            sys.stderr.write("approval %s does not exist\n" % aid); sys.exit(2)
        used = os.path.join(store, "used", rec["request_digest"])
        if os.path.exists(used) and defect != "reuse-ok":
            sys.stderr.write("approval %s has already been used\n" % aid); sys.exit(2)
        open(used, "a").close()
        ledger({"event": "used", "approval_id": aid})
        c = content(path)
        if hashlib.sha256(canon(c).encode()).hexdigest() != rec["content_digest"] and defect != "mismatch-ok":
            ledger({"event": "mismatch", "approval_id": aid})
            sys.stderr.write("host 127.0.0.1: the re-observed plan differs from the approved plan (approval %s); nothing was changed\n" % aid)
            sys.exit(5)
    rc = run(path, "apply")
    if aid:
        ledger({"event": "applied", "approval_id": aid})
    sys.exit(rc)
sys.stderr.write("fake sinter: unsupported %r\n" % (args,)); sys.exit(99)
'''


def section(name):
    text = open(TARGET, encoding="utf-8").read()
    m = re.search(r"^# BEGIN %s\n(.*?)^# END %s\n" % (name, name), text, re.S | re.M)
    assert m, name
    return m.group(1)


def results(stdout):
    return (re.findall(r"^== check (\S+) ok$", stdout, re.M), re.findall(r"^== check (\S+) FAIL$", stdout, re.M))


def initial_state(**over):
    pub = {"interface": ["ens4"], "source": [], "port": [], "service": ["ssh", "dhcpv6-client"]}
    st = {"running": True, "default": "public", "ssh_ok": True, "links": ["lo", "ens4"],
          "perm": {"public": dict(pub), "trusted": {"interface": [], "source": [], "port": [], "service": []}},
          "rt": {}}
    st["rt"] = json.loads(json.dumps(st["perm"]))
    st.update(over)
    return st


class Fw03Checks(unittest.TestCase):
    def run_section(self, defect="", state=None, extra_files=()):
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d, 0o700)
            s = os.path.join(d, "x"); os.mkdir(s)
            bin_ = os.path.join(d, "bin"); os.mkdir(bin_)
            etc = os.path.join(d, "etc-firewalld"); os.makedirs(os.path.join(etc, "zones"))
            open(os.path.join(etc, "firewalld.conf"), "w").write("DefaultZone=public\n")
            for rel, body in extra_files:
                open(os.path.join(etc, rel), "w").write(body)
            for name, body in (("firewall-cmd", FIREWALL_CMD), ("ip", IP), ("ssh", SSH), ("sinter", SINTER)):
                p = os.path.join(bin_, name)
                with open(p, "w") as f:
                    f.write(body)
                os.chmod(p, os.stat(p).st_mode | stat.S_IXUSR)
            fwst = os.path.join(d, "fw.json")
            json.dump(state or initial_state(), open(fwst, "w"))
            prelude = textwrap.dedent(f"""\
                set -u
                PASS=0; FAIL=0
                check() {{ if [ "$2" = ok ]; then PASS=$((PASS+1)); echo "== check $1 ok"; echo "   $3";
                  else FAIL=$((FAIL+1)); echo "== check $1 FAIL"; echo "   $3"; fi; }}
                sudo() {{ [ "$1" = -n ] && shift; "$@"; }}
                command -v sha256sum > /dev/null || sha256sum() {{ shasum -a 256 "$@"; }}
                EXE="{bin_}/sinter"; S="{s}"; WORK="{d}"; LABEL=rocky9
                SSHUSER=sinter; SSHKEY="{d}/id_ed25519"
                """)
            body = section("fw03-checks").replace("FWETC=/etc/firewalld", "FWETC='%s'" % etc)
            env = dict(os.environ, FAKE_DEFECT=defect, FAKE_FW=fwst, FAKE_ETC=etc,
                       PATH=bin_ + os.pathsep + os.environ["PATH"])
            env.pop("XDG_STATE_HOME", None)
            p = subprocess.run(["bash", "-c", prelude + body], capture_output=True, text=True, env=env,
                               timeout=600, cwd=d)
            self.assertEqual(p.returncode, 0, p.stderr)
            ok, bad = results(p.stdout)
            final = json.load(open(fwst))
            left = sorted(os.listdir(s))
            return ok, bad, p.stdout + p.stderr, final, left

    def test_the_documented_behavior_passes_every_check(self):
        ok, bad, log, final, left = self.run_section()
        self.assertEqual(bad, [], log)
        self.assertEqual(sorted(ok), sorted(IDS), log)
        self.assertNotIn("sintacc", final["perm"]); self.assertNotIn("sintacc", final["rt"])
        self.assertEqual(final["links"], ["lo", "ens4"])
        self.assertEqual(final["perm"]["public"]["service"], ["ssh", "dhcpv6-client"])
        self.assertFalse([x for x in left if x.startswith("fw03-state") or x.startswith("fw03-pr") or x.endswith(".req")], left)

    def test_each_defect_fails_its_check(self):
        cases = {
            "no-approval-needed": ["risk-approved-apply"],
            "reuse-ok": ["risk-approved-apply"],
            "mismatch-ok": ["risk-approved-apply"],
            "tamper-ok": ["risk-approved-apply"],
            "tamper-other-reason": ["risk-approved-apply"],
            "runtime-only": ["fw03-interface", "fw03-source"],
            "not-idempotent": ["fw03-interface", "fw03-source"],
            "zone-not-deleted": ["fw03-zone"],
            "reload-refused": ["fw03-reload"],
            "reload-not-run": ["fw03-reload"],
            "ssh-cut": ["fw03-reload", "fw03-no-residue"],
            # runtime only: the harness's final reload heals it, the step that did it fails
            "touch-mgmt": ["fw03-interface"],
            "touch-mgmt-perm": ["fw03-interface", "fw03-no-residue"],
            "reload-residue": ["fw03-no-residue"],
            "no-dummy": ["fw03-interface"],
        }
        for defect, ids in cases.items():
            with self.subTest(defect=defect):
                ok, bad, log, _, _ = self.run_section(defect)
                for i in ids:
                    self.assertIn(i, bad, log)
                    self.assertNotIn(i, ok, log)

    def test_a_missing_prerequisite_fails_every_check_and_changes_nothing(self):
        for name, defect, state in (("no 0.3.0", "no-030", None),
                                    ("firewalld stopped", "", initial_state(running=False))):
            with self.subTest(case=name):
                before = json.loads(json.dumps(state or initial_state()))
                ok, bad, log, final, _ = self.run_section(defect, state)
                self.assertEqual(ok, [], log)
                self.assertEqual(sorted(bad), sorted(IDS), log)
                self.assertEqual(final, before)

    def test_existing_disposable_names_are_never_removed(self):
        st = initial_state()
        st["perm"]["sintacc"] = {"interface": [], "source": ["192.0.2.0/24"], "port": [], "service": []}
        st["rt"] = json.loads(json.dumps(st["perm"]))
        before = json.loads(json.dumps(st))
        ok, bad, log, final, _ = self.run_section("", st, extra_files=(("zones/sintacc.xml", "pre-existing"),))
        self.assertEqual(ok, [], log)
        self.assertEqual(sorted(bad), sorted(IDS), log)
        self.assertIn("disposable-names-in-use", log)
        self.assertEqual(final, before)
        st2 = initial_state(links=["lo", "ens4", "sintacc0"])
        ok, bad, log, final, _ = self.run_section("", st2)
        self.assertEqual(ok, [], log)
        self.assertEqual(final["links"], ["lo", "ens4", "sintacc0"])

    def test_the_section_never_skips_and_uses_only_disposable_names(self):
        text = section("fw03-checks")
        code = re.sub(r"^\s*#.*$", "", text, flags=re.M)
        self.assertNotRegex(code, r"\bskip \w|NOT_APPLICABLE|not_applicable ")
        # every sinter target command goes to 127.0.0.1 with the declared loopback path
        self.assertIn('FWSSH="--host 127.0.0.1 --port 22 ', text)
        self.assertIn("--management-path loopback", text)
        for line in code.splitlines():
            if re.search(r"\bfx (plan|apply)\b", line):
                self.assertIn("$FWSSH", line, line)
            self.assertNotRegex(line, r"--host (?!127\.0\.0\.1)")
        # recipes name only the disposable zone, the dummy interface and documentation networks
        for m in re.finditer(r'fw_recipe "[^"]+" (\w+) "([^"]+)"', code):
            self.assertIn("zone: $FWZ", m.group(2))
        self.assertIn("FWZ=sintacc; FWIF=sintacc0; FWSRC=198.51.100.0/24; FWRS=192.0.2.0/24; FWRS2=203.0.113.0/24", text)
        self.assertNotIn("--complete-reload", code)
        self.assertNotRegex(code, r"--zone=(public|\$z\b.*--(add|remove|change))")
        # restore only what the section created
        self.assertIn('if [ "$FWRAN" = yes ]; then', text)

    def test_the_new_ids_are_expected(self):
        ids = [l.strip() for l in open(os.path.join(HARNESS, "expected-check-ids.txt")) if l.strip()]
        for i in IDS:
            self.assertIn(i, ids)


if __name__ == "__main__":
    unittest.main()
