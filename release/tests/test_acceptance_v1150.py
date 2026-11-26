"""v1.15.0 release tooling: Tier F/P, manifest /2, NOT APPLICABLE, approval set /3.

docs/design/v1.15.0-release-and-acceptance.md §1-§4. Every fixture is
synthetic and built in a temporary directory (throwaway git repositories, a
synthetic ELF file, synthetic logs); no network, no cloud, no GitHub, and no
real release candidate or docs commit.

Run: python3 -m unittest discover -s release/tests
"""
import copy
import hashlib
import importlib.util
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
RELEASE = os.path.dirname(HERE)
HARNESS = os.path.join(RELEASE, "acceptance-harness")
RAW_VERDICT = os.path.join(HARNESS, "raw-verdict.py")
TABLE_PATH = os.path.join(HARNESS, "applicability.json")
IDS_PATH = os.path.join(HARNESS, "expected-check-ids.txt")
TIER = os.path.join(RELEASE, "tier_assess.py")
MAKE = os.path.join(RELEASE, "make_approval_set.py")
VERIFY = os.path.join(RELEASE, "verify_approval_set.py")
sys.path.insert(0, HERE)
import test_check_acceptance_manifest as tcam  # noqa: E402  (fixtures, not tests)
import test_verify_approval_set as tvas  # noqa: E402

LABELS = ["ubuntu2404", "ubuntu2604", "rocky9", "rocky10", "rhel9", "rhel10", "alma9", "alma10"]
NEW_CHECKS = ["timer-create", "timer-idempotent", "timer-running", "timer-absent", "timer-calendar-invalid",
              "service-timer-name", "risk-static-refusal", "nm-profile-crud", "discover-readonly",
              "discover-roundtrip"]
# P7-R1: the checks BLOCKED in P7 are built (fw03-checks section), plus fw03-no-residue
FW03_CHECKS = ["fw03-interface", "fw03-source", "fw03-zone", "fw03-reload", "risk-approved-apply",
               "fw03-no-residue"]


def H(b):
    return hashlib.sha256(b).hexdigest()


def rd(path, mode="rb"):
    with open(path, mode) as f:
        return f.read()


def wr(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb" if isinstance(data, bytes) else "w") as f:
        f.write(data)


def git(repo, *args, env=None, inp=None):
    e = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
         "HOME": repo, "GIT_AUTHOR_NAME": "fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
         "GIT_COMMITTER_NAME": "fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
         "GIT_AUTHOR_DATE": "2026-01-02T00:00:00Z", "GIT_COMMITTER_DATE": "2026-01-02T00:00:00Z"}
    e.update(env or {})
    p = subprocess.run(["git", "-C", repo, *args], env=e, input=inp, capture_output=True)
    if p.returncode != 0:
        raise AssertionError(f"git {args}: {p.stderr.decode(errors='replace')}")
    return p.stdout.decode().strip()


def commit_on(repo, parents, files, message="fixture", base_tree=None, remove=()):
    """A commit with `parents` whose tree is the first parent's (or base_tree)
    plus `files`, built in a private index: the working tree is untouched."""
    with tempfile.TemporaryDirectory(prefix="fixture-index-") as t:
        env = {"GIT_INDEX_FILE": os.path.join(t, "index")}
        tree = base_tree or (git(repo, "rev-parse", parents[0] + "^{tree}") if parents else None)
        if tree:
            git(repo, "read-tree", tree, env=env)
        for path, data in files.items():
            blob = git(repo, "hash-object", "-w", "--stdin", inp=data if isinstance(data, bytes) else data.encode())
            git(repo, "update-index", "--add", "--cacheinfo", f"100644,{blob},{path}", env=env)
        for path in remove:
            git(repo, "update-index", "--force-remove", path, env=env)
        new_tree = git(repo, "write-tree", env=env)
    return git(repo, "commit-tree", new_tree, *sum((["-p", p] for p in parents), []), "-m", message)


# ---------------------------------------------------------------------------
# raw verdict and NOT APPLICABLE
# ---------------------------------------------------------------------------
IDS = [x.strip() for x in rd(IDS_PATH, "r").splitlines() if x.strip()]
OBS_ABSENT = "== observe nm-presence nmcli=absent service=not-found"


def raw_log(ok_ids, na=(), observe=OBS_ABSENT, passed=None, na_count=None, extra=(), end=True):
    lines = ["== acceptance start 2026-09-01T01:00:30Z label=fixture"]
    if observe is not None:
        lines.append(observe)
    lines += [f"== check {c} ok" for c in ok_ids]
    lines += [f"== check {c} NOT_APPLICABLE {r}" for c, r in na]
    lines += list(extra)
    if end:
        p = len(ok_ids) if passed is None else passed
        n = len(na) if na_count is None else na_count
        tail = "" if n == "omit" else f" not_applicable={n}"
        lines.append(f"== acceptance end 2026-09-01T01:30:00Z passed={p} failed=0 skipped=0{tail}")
    return "\n".join(lines) + "\n"


class RawVerdict(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory(prefix="raw-verdict-")
        self.t = self._t.name

    def tearDown(self):
        self._t.cleanup()

    def verdict(self, text, label="ubuntu2404", table=TABLE_PATH, legacy=False):
        raw = os.path.join(self.t, "raw.log")
        wr(raw, text)
        args = [raw, IDS_PATH, "2026-09-01T01:00:00Z", "0"]
        if not legacy:
            args += [table, label]
        p = subprocess.run([sys.executable, RAW_VERDICT, *args], capture_output=True, text=True)
        return p.returncode, p.stdout.strip()

    def table(self, doc):
        p = os.path.join(self.t, "table.json")
        wr(p, json.dumps(doc))
        return p

    def no_nm(self):
        return [c for c in IDS if c != "nm-profile-crud"]

    def test_all_checks_ok_passes_with_and_without_the_table(self):
        text = raw_log(IDS, observe="== observe nm-presence nmcli=present service=active")
        self.assertEqual(self.verdict(text), (0, "PASS"))
        self.assertEqual(self.verdict(text, legacy=True), (0, "PASS"))

    def test_a_pre_v1150_end_marker_still_passes(self):
        self.assertEqual(self.verdict(raw_log(IDS, observe=None, na_count="omit"), legacy=True), (0, "PASS"))

    def test_proven_not_applicable_on_an_allowed_target_passes(self):
        text = raw_log(self.no_nm(), na=[("nm-profile-crud", "NM_NOT_INSTALLED")])
        for label in ("ubuntu2404", "ubuntu2604"):
            self.assertEqual(self.verdict(text, label), (0, "PASS"), label)
        inactive = text.replace("service=not-found", "service=inactive")
        self.assertEqual(self.verdict(inactive), (0, "PASS"))

    def test_not_applicable_on_a_target_the_table_does_not_list(self):
        text = raw_log(self.no_nm(), na=[("nm-profile-crud", "NM_NOT_INSTALLED")])
        for label in ("rocky9", "rocky10", "rhel9", "rhel10", "alma9", "alma10"):
            rc, out = self.verdict(text, label)
            self.assertEqual(rc, 1)
            self.assertTrue(out.startswith("NOT_APPLICABLE_NOT_ALLOWED"), out)

    def test_not_applicable_needs_the_table(self):
        text = raw_log(self.no_nm(), na=[("nm-profile-crud", "NM_NOT_INSTALLED")])
        self.assertEqual(self.verdict(text, legacy=True), (1, "NOT_APPLICABLE_WITHOUT_TABLE"))
        self.assertEqual(self.verdict(text, table=os.path.join(self.t, "missing.json")),
                         (1, "NOT_APPLICABLE_WITHOUT_TABLE"))

    def test_a_tampered_or_malformed_table_is_refused(self):
        text = raw_log(self.no_nm(), na=[("nm-profile-crud", "NM_NOT_INSTALLED")])
        good = json.loads(rd(TABLE_PATH, "r"))
        bad_schema = dict(good, schema="sinter-acceptance-applicability/9")
        bad_reason = copy.deepcopy(good)
        bad_reason["entries"][0]["reason"] = "NO_REASON_CLASS"
        bad_targets = copy.deepcopy(good)
        bad_targets["entries"][0]["targets"] = "ubuntu2404"
        for doc in (bad_schema, bad_reason, bad_targets, ["not", "an", "object"]):
            with self.subTest(doc=doc):
                self.assertEqual(self.verdict(text, table=self.table(doc)), (1, "NOT_APPLICABLE_WITHOUT_TABLE"))
        widened = copy.deepcopy(good)
        widened["entries"][0]["targets"].append("rocky9")
        # A widened table passes raw-verdict on its own: the table's bytes are
        # bound to the RC by the recorded scripts, the approval set and the
        # manifest checker (ManifestV2.test_tampered_table_in_the_bundle).
        self.assertEqual(self.verdict(text, "rocky9", table=self.table(widened)), (0, "PASS"))

    def test_observation_missing_forged_or_contradicting(self):
        na = [("nm-profile-crud", "NM_NOT_INSTALLED")]
        cases = {
            "missing": raw_log(self.no_nm(), na=na, observe=None),
            "stopped NetworkManager": raw_log(self.no_nm(), na=na,
                                              observe="== observe nm-presence nmcli=present service=inactive"),
            "running without nmcli": raw_log(self.no_nm(), na=na,
                                             observe="== observe nm-presence nmcli=absent service=active"),
            "free text": raw_log(self.no_nm(), na=na, observe="== observe nm-presence nmcli=absent (trust me)"),
            "duplicate": raw_log(self.no_nm(), na=na, extra=[OBS_ABSENT]),
            "second differing": raw_log(self.no_nm(), na=na,
                                        extra=["== observe nm-presence nmcli=present service=active"]),
            "indented": raw_log(self.no_nm(), na=na, observe="  " + OBS_ABSENT),
        }
        for name, text in cases.items():
            with self.subTest(name):
                rc, out = self.verdict(text)
                self.assertEqual(rc, 1)
                self.assertTrue(out.startswith("NOT_APPLICABLE_NOT_PROVEN"), out)

    def test_not_applicable_is_never_counted_as_passed(self):
        na = [("nm-profile-crud", "NM_NOT_INSTALLED")]
        rc, out = self.verdict(raw_log(self.no_nm(), na=na, passed=len(IDS)))
        self.assertEqual(rc, 1)
        self.assertTrue(out.startswith("CHECK_COUNT_MISMATCH"), out)

    def test_not_applicable_count_must_match_the_end_line(self):
        na = [("nm-profile-crud", "NM_NOT_INSTALLED")]
        for n in (0, 2, "omit"):
            with self.subTest(n=n):
                self.assertEqual(self.verdict(raw_log(self.no_nm(), na=na, na_count=n)),
                                 (1, "NOT_APPLICABLE_COUNT_MISMATCH"))
        self.assertEqual(self.verdict(raw_log(IDS, na_count=1)), (1, "NOT_APPLICABLE_COUNT_MISMATCH"))

    def test_a_check_both_run_and_not_applicable(self):
        na = [("nm-profile-crud", "NM_NOT_INSTALLED")]
        self.assertEqual(self.verdict(raw_log(IDS, na=na)), (1, "CHECK_DUPLICATE"))
        self.assertEqual(self.verdict(raw_log(self.no_nm(), na=na + na)), (1, "CHECK_DUPLICATE"))

    def test_not_applicable_for_an_unknown_check(self):
        doc = json.loads(rd(TABLE_PATH, "r"))
        doc["entries"].append({"check": "no-such-check", "reason": "NM_NOT_INSTALLED", "targets": ["ubuntu2404"]})
        text = raw_log(self.no_nm(), na=[("nm-profile-crud", "NM_NOT_INSTALLED"),
                                         ("no-such-check", "NM_NOT_INSTALLED")])
        self.assertEqual(self.verdict(text, table=self.table(doc)), (1, "NOT_APPLICABLE_UNKNOWN_CHECK no-such-check"))

    def test_other_reasons_and_malformed_check_lines(self):
        rc, out = self.verdict(raw_log(self.no_nm(), na=[("nm-profile-crud", "FIREWALLD_MISSING")]))
        self.assertEqual(rc, 1)
        self.assertTrue(out.startswith("NOT_APPLICABLE_NOT_ALLOWED"), out)
        for line in ("== check nm-profile-crud NOT_APPLICABLE", "== check nm-profile-crud PASS",
                     "== check nm-profile-crud NOT_APPLICABLE NM_NOT_INSTALLED extra"):
            with self.subTest(line=line):
                self.assertEqual(self.verdict(raw_log(self.no_nm(), extra=[line])), (1, "CHECK_LINE_MALFORMED"))

    def test_missing_check_without_not_applicable_fails(self):
        rc, out = self.verdict(raw_log(self.no_nm()))
        self.assertEqual(rc, 1)
        self.assertIn("missing=['nm-profile-crud']", out)


class HarnessStatic(unittest.TestCase):
    """The check script, the expected ids and the table agree (no target run)."""

    def test_expected_ids_are_derived_from_the_script(self):
        with tempfile.TemporaryDirectory(prefix="derive-") as t:
            out = os.path.join(t, "ids.txt")
            p = subprocess.run(["bash", os.path.join(HARNESS, "derive-expected-checks.sh"),
                                os.path.join(HARNESS, "acceptance-target.sh"), out], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(rd(out), rd(IDS_PATH))
        self.assertEqual(len(IDS), 104)  # 76 of v1.15.0 and the 28 v116-* checks of v1.16.0 (test_acceptance_v1160.py)
        for c in NEW_CHECKS + FW03_CHECKS:
            self.assertIn(c, IDS)

    def test_shell_syntax(self):
        for n in sorted(os.listdir(HARNESS)):
            if n.endswith(".sh"):
                with self.subTest(n):
                    p = subprocess.run(["bash", "-n", os.path.join(HARNESS, n)], capture_output=True, text=True)
                    self.assertEqual(p.returncode, 0, p.stderr)

    def test_harness_sha256sums_cover_every_file(self):
        self.assertEqual(harness_sums_problems(HARNESS), [])


def harness_sums_problems(d):
    """The SHA256SUMS of a harness directory against its entries: every entry but SHA256SUMS and dot files must be
    listed (a directory such as __pycache__ is an unlisted entry too), every listed file must exist and match, and
    every line must be `<64 hex>  <name>` with a name listed once.  Returns the problems (empty when consistent)."""
    problems, listed = [], {}
    for i, line in enumerate(rd(os.path.join(d, "SHA256SUMS"), "r").splitlines(), 1):
        m = re.fullmatch(r"([0-9a-f]{64})  ([^/\s][^/]*)", line)
        if not m:
            problems.append("SHA256SUMS line %d is malformed" % i)
            continue
        if m.group(2) in listed:
            problems.append("%s is listed twice" % m.group(2))
        listed[m.group(2)] = m.group(1)
    entries = sorted(n for n in os.listdir(d) if n != "SHA256SUMS" and not n.startswith("."))
    for n in entries:
        if n not in listed:
            problems.append("%s is not listed" % n)
    for n in sorted(listed):
        p = os.path.join(d, n)
        if not os.path.isfile(p) or os.path.islink(p):
            problems.append("%s is missing" % n)
        elif listed[n] != H(rd(p)):
            problems.append("%s does not match" % n)
    return problems


class HarnessSumsCheck(unittest.TestCase):
    """The cover check itself still detects every kind of drift (P8-R7: it must not be weakened to pass CI)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="sums-")
        self.d = os.path.join(self.tmp, "h")
        os.makedirs(self.d)
        for n, b in (("a.sh", b"echo a\n"), ("b.py", b"print(1)\n")):
            wr(os.path.join(self.d, n), b)
        self.write_sums()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def write_sums(self, extra=""):
        names = sorted(n for n in os.listdir(self.d) if n != "SHA256SUMS")
        wr(os.path.join(self.d, "SHA256SUMS"),
           "".join("%s  %s\n" % (H(rd(os.path.join(self.d, n))), n) for n in names) + extra)

    def test_consistent(self):
        self.assertEqual(harness_sums_problems(self.d), [])

    def test_unlisted_regular_file(self):
        wr(os.path.join(self.d, "extra.txt"), b"x")
        self.assertEqual(harness_sums_problems(self.d), ["extra.txt is not listed"])

    def test_pycache_directory_is_unlisted(self):
        wr(os.path.join(self.d, "__pycache__", "b.cpython-312.pyc"), b"\0")
        self.assertEqual(harness_sums_problems(self.d), ["__pycache__ is not listed"])

    def test_modified_file(self):
        wr(os.path.join(self.d, "a.sh"), b"echo changed\n")
        self.assertEqual(harness_sums_problems(self.d), ["a.sh does not match"])

    def test_missing_file(self):
        os.remove(os.path.join(self.d, "b.py"))
        self.assertEqual(harness_sums_problems(self.d), ["b.py is missing"])

    def test_malformed_and_duplicate_lines(self):
        self.write_sums(extra="nothex  a.sh\n%s  a.sh\n" % H(b"echo a\n"))
        self.assertEqual(harness_sums_problems(self.d), ["SHA256SUMS line 3 is malformed", "a.sh is listed twice"])

    def test_listed_directory_is_missing(self):
        self.write_sums(extra="%s  sub\n" % H(b""))
        os.makedirs(os.path.join(self.d, "sub"))
        self.assertEqual(harness_sums_problems(self.d), ["sub is missing"])

    def test_table_allows_only_the_nm_check(self):
        doc = json.loads(rd(TABLE_PATH, "r"))
        self.assertEqual(doc["schema"], "sinter-acceptance-applicability/1")
        # v1.16.0 adds v116-* entries (checked in test_acceptance_v1160.py); the v1.15.0 entry is unchanged
        self.assertEqual([(e["check"], e["reason"], e["targets"]) for e in doc["entries"] if not e["check"].startswith("v116-")],
                         [("nm-profile-crud", "NM_NOT_INSTALLED", ["ubuntu2404", "ubuntu2604"])])

    def test_script_declares_not_applicable_only_after_the_observation(self):
        s = rd(os.path.join(HARNESS, "acceptance-target.sh"), "r")
        calls = [c for c in re.findall(r"(?m)^\s*not_applicable (\S+) (\S+)", s) if not c[0].startswith("v116-")]
        self.assertEqual(calls, [("nm-profile-crud", "NM_NOT_INSTALLED")])
        obs = s.index('echo "== observe nm-presence nmcli=$NMC service=$NMSV"')
        self.assertLess(obs, s.index("not_applicable nm-profile-crud"))
        self.assertIn('[ "$NMC" = absent ] && [ "$NMSV" != active ] && na_allowed nm-profile-crud', s)
        self.assertIn("not_applicable=$NA", s)

    def test_new_checks_use_the_loopback_management_path_and_clean_up(self):
        s = rd(os.path.join(HARNESS, "acceptance-target.sh"), "r")
        sec = s[s.index("# BEGIN v1150-checks"):s.index("# END v1150-checks")]
        self.assertIn("--host 127.0.0.1", sec)
        self.assertIn("--management-path loopback", sec)
        self.assertIn("192.0.2.", sec)  # documentation network only
        for leftover in ("sinter-acc-timer", "sinter-acc-nm", "/etc/sinter-acc-disc"):
            self.assertIn(leftover, sec)
        self.assertNotIn("firewall-cmd --permanent", sec)


def load_collector():
    """Import the harness collector in place (its HERE must stay the harness directory) without writing a bytecode
    cache: an in-place __pycache__ would be an unlisted entry of the hash-pinned harness directory (P8-R7, CI run
    44967562055).  Only this import is affected; the process setting is restored."""
    spec = importlib.util.spec_from_file_location("collect_evidence_v1150", os.path.join(HARNESS, "collect-evidence.py"))
    mod = importlib.util.module_from_spec(spec)
    old = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.dont_write_bytecode = old
    return mod


class CollectorImportLeavesHarnessClean(unittest.TestCase):
    """Regression for CI run 44967562055: importing the collector with bytecode writing on and no cache prefix
    leaves the harness directory exactly as it was."""

    def test_import_writes_nothing_into_the_harness(self):
        before = sorted(os.listdir(HARNESS))
        old_flag, old_prefix = sys.dont_write_bytecode, sys.pycache_prefix
        sys.dont_write_bytecode, sys.pycache_prefix = False, None
        try:
            load_collector()
        finally:
            sys.dont_write_bytecode, sys.pycache_prefix = old_flag, old_prefix
        self.assertEqual(sorted(os.listdir(HARNESS)), before)
        self.assertEqual(harness_sums_problems(HARNESS), [])


class CollectorScope(unittest.TestCase):
    """The collector's GO gate takes the approved target set only (T-6)."""

    @classmethod
    def setUpClass(cls):
        cls.c = load_collector()

    def labels(self, scope, targets):
        return self.c.scope_labels(scope, targets)

    def refused(self, scope, targets):
        with self.assertRaises(SystemExit) as cm:
            with open(os.devnull, "w") as dn:
                old, sys.stderr = sys.stderr, dn
                try:
                    self.c.scope_labels(scope, targets)
                finally:
                    sys.stderr = old
        self.assertEqual(cm.exception.code, 64)

    def test_full_is_the_eight(self):
        self.assertEqual(self.labels("full", ""), LABELS)
        self.assertEqual(self.labels("full", ",".join(reversed(LABELS))), LABELS)

    def test_patch_set(self):
        self.assertEqual(self.labels("patch", "rocky9,ubuntu2404,rhel10"), ["ubuntu2404", "rocky9", "rhel10"])

    def test_refusals(self):
        for scope, targets in (("full", "ubuntu2404,rocky9,ubuntu2604"), ("full", ",".join(LABELS[:7])),
                               ("patch", ""), ("patch", "ubuntu2404,ubuntu2604"), ("patch", "rocky9,rocky10"),
                               ("patch", "ubuntu2404,rocky9,rhel9"), ("patch", "ubuntu2404,rocky9,rocky10,rocky10"),
                               ("patch", "ubuntu2404,rocky9,debian12"), ("patch", ",".join(LABELS)),
                               ("partial", "ubuntu2404"), ("", "")):
            with self.subTest(scope=scope, targets=targets):
                self.refused(scope, targets)


# ---------------------------------------------------------------------------
# manifest /2 (checker)
# ---------------------------------------------------------------------------
TABLE_BYTES = rd(TABLE_PATH)
ABI = {"dt_needed": ["libc.so.6", "libgcc_s.so.1", "libm.so.6"], "max_glibc": "GLIBC_2.34", "max_openssl": "none"}
CHECK_IDS = [f"fixture-check-{i:02d}" for i in range(42)] + ["nm-profile-crud"]
_saved = {}
_repo_tmp = None


def setUpModule():
    """A fixture crate whose commit carries the applicability table."""
    global _repo_tmp
    _saved.update(REPO=tcam.REPO, COMMIT=tcam.COMMIT)
    _repo_tmp = tempfile.TemporaryDirectory(prefix="sinter-v1150-repo-")
    tcam.REPO = _repo_tmp.name
    tcam._git("init", "-q")
    files = dict(tcam.FIXTURE_CRATE)
    files["release/acceptance-harness/applicability.json"] = TABLE_BYTES.decode()
    tcam.COMMIT = tcam._commit(None, files, message="fixture crate with applicability table")


def tearDownModule():
    tcam.REPO, tcam.COMMIT = _saved["REPO"], _saved["COMMIT"]
    _repo_tmp.cleanup()


class V2Evidence(tcam.Evidence):
    def __init__(self, tmp, targets=None, na=(), observe=None, exe=None):
        super().__init__(tmp)
        # /2: the checker measures abi on this executable (a synthetic ELF)
        self.exe = exe if exe is not None else elf(["libc.so.6", "libm.so.6", "libgcc_s.so.1"],
                                                   {"libc.so.6": ["GLIBC_2.17", "GLIBC_2.34"]})
        self.targets = list(targets or LABELS)
        self.na = set(na)
        self.observe = observe or {}
        for label in LABELS:
            del self.files[f"logs/{label}.log"]
        for label in self.targets:
            self.files[f"logs/{label}.log"] = self.log(label).encode()
        self.files["harness/applicability.json"] = TABLE_BYTES

    def log(self, label):
        na = label in self.na
        obs = self.observe.get(label, "nmcli=absent service=not-found" if na else "nmcli=present service=active")
        lines = [f"== acceptance start 2026-09-01T01:00:30Z label={label}", f"sinter {tcam.VERSION}",
                 f"== observe nm-presence {obs}"]
        lines += [f"== check {c} ok" for c in CHECK_IDS if not (na and c == "nm-profile-crud")]
        if na:
            lines.append("== check nm-profile-crud NOT_APPLICABLE NM_NOT_INSTALLED")
        p = len(CHECK_IDS) - (1 if na else 0)
        lines.append(f"== acceptance end 2026-09-01T01:30:00Z passed={p} failed=0 skipped=0 not_applicable={int(na)}")
        return "\n".join(lines) + "\n"

    def manifest(self):
        missing = [l for l in LABELS if f"logs/{l}.log" not in self.files]
        for l in missing:  # the base fixture hashes a log for each of the eight
            self.files[f"logs/{l}.log"] = b""
        try:
            doc = super().manifest()
        finally:
            for l in missing:
                del self.files[f"logs/{l}.log"]
        doc["schema"] = "sinter-acceptance-manifest/2"
        doc["acceptance_scope"] = "full" if len(self.targets) == 8 else "patch"
        doc["required_targets"] = list(self.targets)
        doc["abi"] = copy.deepcopy(ABI)
        doc["harness"]["files"].append({"path": "harness/applicability.json", "sha256": H(TABLE_BYTES)})
        doc["targets"] = [t for t in doc["targets"] if t["label"] in self.targets]
        for t in doc["targets"]:
            na = t["label"] in self.na
            t["checks"] = {"total": len(CHECK_IDS), "passed": len(CHECK_IDS) - int(na), "failed": 0, "skipped": 0,
                           "not_applicable": int(na)}
            t["not_applicable_checks"] = [{"id": "nm-profile-crud", "reason": "NM_NOT_INSTALLED"}] if na else []
        n = len(doc["targets"])
        nna = sum(1 for t in self.targets if t in self.na)
        doc["totals"] = {"targets": n, "total": n * len(CHECK_IDS), "passed": n * len(CHECK_IDS) - nna,
                         "failed": 0, "skipped": 0, "not_applicable": nna}
        return doc


PATCH = ["ubuntu2404", "ubuntu2604", "rocky9"]


class V2Base(tcam.Base):
    def setUp(self):
        super().setUp()
        self.ev = V2Evidence(self.tmp, na=("ubuntu2404", "ubuntu2604"))

    def patch_ev(self, **kw):
        self.ev = V2Evidence(self.tmp, targets=PATCH, na=kw.pop("na", ("ubuntu2404",)), **kw)

    def reference(self, shift="2026-08-20T", mutate=None, version="9.9.8"):
        """A full /2 GO reference manifest file and the full_reference of it."""
        with tempfile.TemporaryDirectory(prefix="ref-") as t:
            doc = V2Evidence(t).manifest()
        doc = json.loads(json.dumps(doc).replace("2026-09-01T", shift).replace(tcam.VERSION, version))
        if mutate:
            mutate(doc)
        raw = (json.dumps(doc, indent=2) + "\n").encode()
        path = os.path.join(self.tmp, "reference-manifest.json")
        wr(path, raw)
        fr = {"version": doc["candidate"]["version"], "manifest_sha256": H(raw),
              "finished_at": doc["run"]["finished_at"], "releases_since": []}
        return path, fr

    def check_v2(self, mutate_doc=None, mutate_files=None, ref=None, full_reference=None):
        m, a, _ = self.ev.write(mutate_doc, mutate_files)
        b = self.ev.archive()
        args = [m, "--bundle-archive", b, "--artifact", a, "--sums", self.write_sums(m, b)]
        if full_reference:
            args += ["--full-reference", full_reference]
        return tcam.run_checker(*args)

    def check_patch(self, fr_change=None, ref_mutate=None, shift="2026-08-20T", mutate_doc=None, use_ref=True,
                    mutate_files=None):
        self.patch_ev()
        path, fr = self.reference(shift, ref_mutate)
        if fr_change:
            fr_change(fr)

        def mut(doc):
            doc["full_reference"] = fr
            if mutate_doc:
                mutate_doc(doc)
        return self.check_v2(mut, mutate_files, full_reference=path if use_ref else None)


class ManifestV1Compat(tcam.Base):
    def test_published_v1_manifest_still_passes(self):
        self.assertPass(self.check(sums=True))

    def test_v1_manifest_refuses_v2_only_options(self):
        p = os.path.join(self.tmp, "ref.json")
        wr(p, b"{}")
        m, a, d = self.ev.write()
        self.assertReject(tcam.run_checker(m, "--bundle", d, "--artifact", a, "--full-reference", p),
                          "only a patch-scope /2 manifest takes a reference")


class ManifestV2(V2Base):
    def test_full_scope_with_proven_not_applicable_passes(self):
        rc, out, err = self.check_v2()
        self.assertEqual(rc, 0, err)
        self.assertIn("(verdict GO)", out)

    def test_full_scope_without_not_applicable_passes(self):
        self.ev = V2Evidence(self.tmp)
        self.assertPass(self.check_v2())

    def test_template_structure(self):
        rc, out, err = tcam.run_checker("--template", os.path.join(RELEASE, "acceptance-manifest.v2.template.json"))
        self.assertEqual(rc, 0, err)

    def test_missing_target(self):
        def drop(doc):
            doc["targets"] = [t for t in doc["targets"] if t["label"] != "rhel9"]
            doc["totals"]["targets"] -= 1
            doc["totals"]["total"] -= 43
            doc["totals"]["passed"] -= 43
        self.assertReject(self.check_v2(drop, lambda f: f.pop("logs/rhel9.log")), "rhel9")

    def test_full_scope_needs_the_eight_required_targets(self):
        def seven(doc):
            doc["required_targets"] = LABELS[:7]
        self.assertReject(self.check_v2(seven), "full scope requires exactly the eight")

    def test_skipped_is_never_accepted(self):
        def sk(doc):
            t = doc["targets"][2]
            t["checks"]["passed"] -= 1
            t["checks"]["skipped"] = 1
            doc["totals"]["passed"] -= 1
            doc["totals"]["skipped"] = 1
        self.assertReject(self.check_v2(sk), "targets[2].verdict: must be FAIL", "$.verdict: must be NO-GO")

    def test_failed_and_empty_targets(self):
        def fl(doc):
            t = doc["targets"][3]
            t["checks"]["passed"] -= 1
            t["checks"]["failed"] = 1
            doc["totals"]["passed"] -= 1
            doc["totals"]["failed"] = 1
        self.assertReject(self.check_v2(fl), "targets[3].verdict: must be FAIL", "$.verdict: must be NO-GO")

        def empty(doc):
            t = doc["targets"][3]
            doc["totals"]["total"] -= t["checks"]["total"]
            doc["totals"]["passed"] -= t["checks"]["passed"]
            t["checks"] = {"total": 0, "passed": 0, "failed": 0, "skipped": 0, "not_applicable": 0}
        self.assertReject(self.check_v2(empty), "targets[3].verdict: must be FAIL")

    def test_inconsistent_counts_and_totals(self):
        def counts(doc):
            doc["targets"][4]["checks"]["passed"] -= 1
        self.assertReject(self.check_v2(counts), "passed + failed + skipped + not_applicable != total")

        def totals(doc):
            doc["totals"]["not_applicable"] = 0
        self.assertReject(self.check_v2(totals))

    def test_not_applicable_counted_as_passed(self):
        def as_pass(doc):
            t = doc["targets"][0]
            t["checks"]["passed"] += 1
            t["checks"]["not_applicable"] = 0
            t["not_applicable_checks"] = []
            doc["totals"]["passed"] += 1
            doc["totals"]["not_applicable"] -= 1
        self.assertReject(self.check_v2(as_pass), "logs/ubuntu2404.log")

    def test_not_applicable_on_a_target_the_table_does_not_allow(self):
        self.ev = V2Evidence(self.tmp, na=("rocky9",))
        self.assertReject(self.check_v2(), "NOT_APPLICABLE nm-profile-crud NM_NOT_INSTALLED is not allowed for rocky9")

    def test_stopped_networkmanager_is_not_not_applicable(self):
        self.ev = V2Evidence(self.tmp, na=("ubuntu2404",),
                             observe={"ubuntu2404": "nmcli=present service=inactive"})
        self.assertReject(self.check_v2(), "is not proven by the observation line")

    def test_missing_or_forged_observation(self):
        for name, obs in (("running", "nmcli=absent service=active"), ("free text", "nmcli=absent somehow")):
            with self.subTest(name):
                self.ev = V2Evidence(self.tmp, na=("ubuntu2404",), observe={"ubuntu2404": obs})
                self.assertReject(self.check_v2(), "is not proven by the observation line")

        def strip_obs(files):
            files["logs/ubuntu2404.log"] = b"".join(
                l for l in files["logs/ubuntu2404.log"].splitlines(True) if not l.startswith(b"== observe"))
        self.ev = V2Evidence(self.tmp, na=("ubuntu2404",))
        self.assertReject(self.check_v2(mutate_files=strip_obs), "is not proven by the observation line")

    def test_not_applicable_list_differs_from_the_log(self):
        def unlisted(doc):
            doc["targets"][0]["not_applicable_checks"] = [{"id": "fixture-check-00", "reason": "NM_NOT_INSTALLED"}]
        self.assertReject(self.check_v2(unlisted), "NOT_APPLICABLE lines differ from not_applicable_checks")

        def missing(doc):
            doc["targets"][0]["not_applicable_checks"] = []
        self.assertReject(self.check_v2(missing), "entries but checks.not_applicable is 1")

    def test_tampered_table_in_the_bundle(self):
        def widen(files):
            doc = json.loads(files["harness/applicability.json"])
            doc["entries"][0]["targets"].append("rocky9")
            files["harness/applicability.json"] = (json.dumps(doc) + "\n").encode()

        def rehash(doc):
            for f in doc["harness"]["files"]:
                if f["path"] == "harness/applicability.json":
                    f["sha256"] = H(self.widened)
        doc = json.loads(TABLE_BYTES)
        doc["entries"][0]["targets"].append("rocky9")
        self.widened = (json.dumps(doc) + "\n").encode()
        self.ev = V2Evidence(self.tmp, na=("rocky9",))
        self.assertReject(self.check_v2(rehash, widen), "differs from the table at candidate.source_commit")

    def test_missing_table_and_missing_log(self):
        def no_table(doc):
            doc["harness"]["files"] = [f for f in doc["harness"]["files"] if f["path"] != "harness/applicability.json"]
        self.assertReject(self.check_v2(no_table, lambda f: f.pop("harness/applicability.json")),
                          "harness/applicability.json: missing or invalid")
        self.assertReject(self.check_v2(mutate_files=lambda f: f.pop("logs/alma9.log")), "logs/alma9.log missing")

    def test_end_line_must_carry_the_counts(self):
        def old_end(files):
            files["logs/ubuntu2404.log"] = files["logs/ubuntu2404.log"].replace(b" not_applicable=1", b"")

        def rehash(doc):
            doc["targets"][0]["log"]["sha256"] = H(self.ev.log("ubuntu2404").replace(" not_applicable=1", "").encode())
        self.assertReject(self.check_v2(rehash, old_end), "end line counts differ from the manifest")

    def test_abi_fields(self):
        for name, abi in (("unsorted", dict(ABI, dt_needed=["libm.so.6", "libc.so.6"])),
                          ("empty", dict(ABI, dt_needed=[])), ("glibc", dict(ABI, max_glibc="2.34")),
                          ("openssl", dict(ABI, max_openssl="3.0")), ("missing", None)):
            with self.subTest(name):
                def mut(doc, abi=abi):
                    if abi is None:
                        del doc["abi"]
                    else:
                        doc["abi"] = abi
                self.assertReject(self.check_v2(mut))

    def test_scope_and_reference_rules(self):
        self.assertReject(self.check_v2(lambda d: d.update(acceptance_scope="partial")), "must be full or patch")
        path, fr = self.reference()
        self.assertReject(self.check_v2(lambda d: d.update(full_reference=fr), full_reference=path),
                          "only a patch scope names a reference")

    def test_abi_is_measured_on_the_frozen_executable(self):
        other = dict(ABI, max_glibc="GLIBC_2.28")
        self.assertReject(self.check_v2(lambda d: d.update(abi=other)),
                          "abi: differs from the ABI measured on the frozen executable")
        self.assertReject(self.check_v2(lambda d: d.update(abi=dict(ABI, dt_needed=["libc.so.6", "libm.so.6"]))),
                          "abi: differs from the ABI measured")
        self.ev = V2Evidence(self.tmp, na=("ubuntu2404",), exe=b"synthetic sinter executable\n")
        self.assertReject(self.check_v2(), "the executable's ABI cannot be measured")


class ManifestV2Patch(V2Base):
    def test_patch_scope_with_a_valid_reference_passes(self):
        rc, out, err = self.check_patch()
        self.assertEqual(rc, 0, err)
        self.assertIn("(verdict GO)", out)

    def test_patch_scope_needs_the_reference_file(self):
        self.assertReject(self.check_patch(use_ref=False), "--full-reference: required for a patch-scope manifest")

    def test_copying_the_reference_abi_does_not_hide_a_changed_executable(self):
        changed = dict(ABI, max_glibc="GLIBC_2.38")
        self.assertReject(self.check_patch(ref_mutate=lambda d: d.update(abi=changed),
                                           mutate_doc=lambda d: d.update(abi=changed)),
                          "abi: differs from the ABI measured on the frozen executable")

    def test_patch_scope_never_names_all_eight(self):
        self.assertReject(self.check_patch(mutate_doc=lambda d: d.update(required_targets=list(LABELS))),
                          "a patch scope never names all eight targets")

    def test_reference_option_is_not_trusted(self):
        self.assertReject(self.check_patch(lambda fr: fr.update(manifest_sha256="0" * 64)),
                          "SHA-256 differs from full_reference.manifest_sha256")
        self.assertReject(self.check_patch(lambda fr: fr.update(version="9.9.7")),
                          "version differs from full_reference.version")
        self.assertReject(self.check_patch(lambda fr: fr.update(finished_at="2026-08-20T01:00:00Z")),
                          "finished_at differs")

    def test_reference_must_be_a_full_go_manifest(self):
        self.assertReject(self.check_patch(ref_mutate=lambda d: d.update(verdict="NO-GO")),
                          "the reference verdict is not GO")
        self.assertReject(self.check_patch(ref_mutate=lambda d: d.update(acceptance_scope="patch")),
                          "not a full-scope sinter-acceptance-manifest/2")
        self.assertReject(self.check_patch(ref_mutate=lambda d: d.update(schema="sinter-acceptance-manifest/1")),
                          "not a full-scope sinter-acceptance-manifest/2")
        self.assertReject(self.check_patch(ref_mutate=lambda d: d["targets"].pop()),
                          "the reference manifest is not valid")

    def test_reference_age_and_releases_since(self):
        self.assertReject(self.check_patch(shift="2026-06-01T"), "more than 60 days after the reference")
        self.assertReject(self.check_patch(shift="2026-09-05T"), "does not start after the reference finished")
        self.assertReject(self.check_patch(lambda fr: fr.update(releases_since=["9.9.6", "9.9.7", "9.9.8"])),
                          "more than 2 releases since the reference")
        rc, _, err = self.check_patch(lambda fr: fr.update(releases_since=["9.9.6", "9.9.7"]))
        self.assertEqual(rc, 0, err)

    def test_abi_must_equal_the_reference(self):
        self.assertReject(self.check_patch(ref_mutate=lambda d: d["abi"].update(max_glibc="GLIBC_2.28")),
                          "abi differs from the reference")

    def test_patch_required_targets(self):
        for name, req in (("no rocky9", ["ubuntu2404", "ubuntu2604"]), ("no newer", ["ubuntu2404", "rocky9"]),
                          ("unknown", ["ubuntu2404", "rocky9", "ubuntu2604", "debian12"])):
            with self.subTest(name):
                self.assertReject(self.check_patch(mutate_doc=lambda d, r=req: d.update(required_targets=r)))

    def test_extra_or_missing_target_against_required(self):
        self.assertReject(self.check_patch(mutate_doc=lambda d: d.update(required_targets=PATCH + ["rhel10"])),
                          "rhel10")

        def extra(doc):
            doc["required_targets"] = ["ubuntu2404", "rocky9", "rocky10"]
        self.assertReject(self.check_patch(mutate_doc=extra), "ubuntu2604")


# ---------------------------------------------------------------------------
# Tier F / P assessment
# ---------------------------------------------------------------------------
def elf(needed, versions):
    """A minimal ELF64 little-endian file with .dynstr, .dynamic and
    .gnu.version_r sections: needed = [lib], versions = {lib: [VER, ...]}."""
    strtab = b"\0"
    offs = {}

    def s(x):
        nonlocal strtab
        if x not in offs:
            offs[x] = len(strtab)
            strtab += x.encode() + b"\0"
        return offs[x]
    for n in needed:
        s(n)
    for lib, vs in versions.items():
        s(lib)
        for v in vs:
            s(v)
    dyn = b"".join(struct.pack("<qQ", 1, offs[n]) for n in needed) + struct.pack("<qQ", 0, 0)
    vr = b""
    libs = list(versions.items())
    for i, (lib, vs) in enumerate(libs):
        nxt = 16 + 16 * len(vs) if i + 1 < len(libs) else 0
        vr += struct.pack("<HHIII", 1, len(vs), offs[lib], 16, nxt)
        for j, v in enumerate(vs):
            vr += struct.pack("<IHHII", 0, 0, j + 2, offs[v], 16 if j + 1 < len(vs) else 0)
    body = strtab + dyn + vr
    o_str, o_dyn, o_vr = 64, 64 + len(strtab), 64 + len(strtab) + len(dyn)
    shoff = 64 + len(body)
    hdr = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    hdr += struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0, 0, shoff, 0, 64, 0, 0, 64, 4, 0)
    sh = struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    sh += struct.pack("<IIQQQQIIQQ", 0, 3, 0, 0, o_str, len(strtab), 0, 0, 1, 0)
    sh += struct.pack("<IIQQQQIIQQ", 0, 6, 0, 0, o_dyn, len(dyn), 1, 0, 8, 16)
    sh += struct.pack("<IIQQQQIIQQ", 0, 0x6FFFFFFE, 0, 0, o_vr, len(vr), 1, len(libs), 4, 0)
    return hdr + body + sh


LOCK = """version = 4

[[package]]
name = "sinter"
version = "{v}"

[[package]]
name = "serde"
version = "{serde}"

[[package]]
name = "openssl-sys"
version = "{ossl}"
"""


class TierAssess(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._t = tempfile.TemporaryDirectory(prefix="tier-")
        t = cls.t = cls._t.name
        cls.repo = os.path.join(t, "repo")
        os.makedirs(cls.repo)
        git(cls.repo, "init", "-q")
        base = {"Cargo.toml": '[package]\nname = "sinter"\nversion = "1.4.0"\n',
                "Cargo.lock": LOCK.format(v="1.4.0", serde="1.0.0", ossl="0.9.100"),
                "src/platform.rs": "// platform\n", "src/cli.rs": "// cli\n", "docs-site/x.md": "x\n"}
        cls.tag_commit = commit_on(cls.repo, [], base, "v1.4.0")
        git(cls.repo, "tag", "v1.4.0", cls.tag_commit)

        def cand(files, v="1.4.1"):
            f = {"Cargo.toml": f'[package]\nname = "sinter"\nversion = "{v}"\n'}
            f.update(files)
            lock = f.pop("lock", {})
            f["Cargo.lock"] = LOCK.format(v=v, serde=lock.get("serde", "1.0.0"), ossl=lock.get("ossl", "0.9.100"))
            return commit_on(cls.repo, [cls.tag_commit], f)
        cls.docs_only = cand({"docs-site/x.md": "y\n"})
        cls.minor = cand({"docs-site/x.md": "y\n"}, v="1.5.0")
        cls.os_code = cand({"src/platform.rs": "// changed\n"})
        cls.dep = cand({"lock": {"serde": "1.0.1"}})
        cls.static = cand({"lock": {"ossl": "0.9.101"}})
        cls.exe = os.path.join(t, "sinter")
        wr(cls.exe, elf(["libc.so.6", "libm.so.6", "libgcc_s.so.1"],
                        {"libc.so.6": ["GLIBC_2.17", "GLIBC_2.34", "GLIBC_2.28"], "libgcc_s.so.1": ["GCC_3.0"]}))
        cls.abi = {"dt_needed": ["libc.so.6", "libgcc_s.so.1", "libm.so.6"], "max_glibc": "GLIBC_2.34",
                   "max_openssl": "none"}

    @classmethod
    def tearDownClass(cls):
        cls._t.cleanup()

    def answers(self, **kw):
        a = {"schema": "sinter-tier-answers/1",
             "triggers": {"os_or_image_change": {"answer": "no", "evidence": "no image change in the diff"}},
             "static_dependencies": {}, "first_available_newer": "ubuntu2604", "t3_targets": []}
        a.update(kw)
        return a

    def reference(self, finished="2026-11-01T02:00:00Z", abi=None, scope="full", verdict="GO"):
        doc = {"schema": "sinter-acceptance-manifest/2", "acceptance_scope": scope, "verdict": verdict,
               "candidate": {"version": "1.4.0"}, "run": {"finished_at": finished}, "abi": abi or self.abi}
        p = tempfile.mktemp(prefix="ref-", suffix=".json", dir=self.t)
        wr(p, json.dumps(doc))
        return p

    def assess(self, candidate, request="P", answers=None, reference="default", since="", date="2026-11-20",
               exe=None):
        out = tempfile.mkdtemp(prefix="out-", dir=self.t)
        ans = tempfile.mktemp(prefix="ans-", suffix=".json", dir=self.t)
        wr(ans, json.dumps(answers if answers is not None else self.answers()))
        args = [sys.executable, TIER, "--repo", self.repo, "--last-tag", "v1.4.0", "--source-candidate", candidate,
                "--executable", exe or self.exe, "--answers", ans, "--run-date", date, "--request", request,
                "--out", out]
        ref = self.reference() if reference == "default" else reference
        if ref:
            args += ["--reference-manifest", ref]
        if since:
            args += ["--releases-since", since]
        p = subprocess.run(args, capture_output=True, text=True)
        res = None
        if p.returncode == 0:
            res = json.loads(rd(os.path.join(out, "TIER_ASSESSMENT.json"), "r"))
            self.assertTrue(os.path.exists(os.path.join(out, "TIER_ASSESSMENT.md")))
        return p, res, out

    def test_elf_abi_is_read_from_the_file(self):
        spec = importlib.util.spec_from_file_location("tier_assess_t", TIER)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.assertEqual(mod.elf_abi(self.exe), self.abi)
        ossl = os.path.join(self.t, "ossl")
        wr(ossl, elf(["libc.so.6", "libssl.so.3"], {"libc.so.6": ["GLIBC_2.34"],
                                                    "libssl.so.3": ["OPENSSL_3.0.0", "OPENSSL_3.2.0"]}))
        self.assertEqual(mod.elf_abi(ossl)["max_openssl"], "OPENSSL_3.2.0")
        for bad in (b"not an elf", elf([], {"libc.so.6": ["GLIBC_2.34"]})):
            p = os.path.join(self.t, "bad")
            wr(p, bad)
            with self.assertRaises(mod.Bad):
                mod.elf_abi(p)

    def test_docs_only_patch_with_valid_reference_is_tier_p(self):
        p, res, _ = self.assess(self.docs_only)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(res["tier"], "P")
        self.assertEqual(res["acceptance_scope"], "patch")
        self.assertEqual(res["required_targets"], ["ubuntu2404", "ubuntu2604", "rocky9"])
        self.assertEqual(res["reasons_for_tier_f"], [])

    def test_every_shipped_code_path_is_tier_f(self):
        for path in ("src/package_removal/dnf.rs", "src/package_progress/apt.rs",
                     "src/resources/exact_removal/rpm.rs", "src/fsbackup.sh", "src/fsstage.sh", "src/cli.rs",
                     "plugins/first-party/x.toml", "build.rs", ".cargo/config.toml"):
            with self.subTest(path):
                c = commit_on(self.repo, [self.docs_only], {path: "// changed\n"}, path)
                p, res, _ = self.assess(c)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(res["tier"], "F", path)
                self.assertIn(path, " ".join(res["reasons_for_tier_f"]))

    def test_tests_and_release_tooling_do_not_force_tier_f(self):
        c = commit_on(self.repo, [self.docs_only], {"tests/cli.rs": "// t\n", "release/x.py": "# r\n"}, "t")
        p, res, _ = self.assess(c)
        self.assertEqual(res["tier"], "P", res["reasons_for_tier_f"])

    def test_t3_targets_are_added(self):
        p, res, _ = self.assess(self.docs_only, answers=self.answers(first_available_newer="rhel10",
                                                                     t3_targets=["alma9"]))
        self.assertEqual(res["required_targets"], ["ubuntu2404", "rocky9", "rhel10", "alma9"])

    def test_tier_f_triggers(self):
        cases = {
            "minor": dict(candidate=self.minor),
            "os code": dict(candidate=self.os_code),
            "static dependency unanswered": dict(candidate=self.static),
            "image change not answered": dict(candidate=self.docs_only, answers=self.answers(triggers={})),
            "image change yes": dict(candidate=self.docs_only, answers=self.answers(
                triggers={"os_or_image_change": {"answer": "yes", "evidence": "new image"}})),
            "no reference": dict(candidate=self.docs_only, reference=None),
            "reference too old": dict(candidate=self.docs_only, date="2027-01-15"),
            "too many releases": dict(candidate=self.docs_only, since="1.4.1,1.4.2,1.4.3"),
            "abi differs": dict(candidate=self.docs_only, reference="abi"),
            "F requested": dict(candidate=self.docs_only, request="F"),
        }
        for name, kw in cases.items():
            with self.subTest(name):
                if kw.get("reference") == "abi":
                    kw["reference"] = self.reference(abi=dict(self.abi, max_glibc="GLIBC_2.28"))
                p, res, _ = self.assess(**kw)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(res["tier"], "F", name)
                self.assertEqual(res["required_targets"], LABELS)
                self.assertTrue(res["reasons_for_tier_f"], name)

    def test_static_dependency_answered_unreached_and_plain_dependency(self):
        ans = self.answers(static_dependencies={"openssl-sys": {"reached": "no", "evidence": "vendored, unused"}})
        p, res, _ = self.assess(self.static, answers=ans)
        self.assertEqual(res["tier"], "P", res["reasons_for_tier_f"])
        self.assertEqual(res["facts"]["static_changes"], ["openssl-sys"])
        unknown = self.answers(static_dependencies={"openssl-sys": {"reached": "unknown", "evidence": "?"}})
        self.assertEqual(self.assess(self.static, answers=unknown)[1]["tier"], "F")
        no_evidence = self.answers(static_dependencies={"openssl-sys": {"reached": "no"}})
        self.assertEqual(self.assess(self.static, answers=no_evidence)[1]["tier"], "F")
        p, res, _ = self.assess(self.dep)
        self.assertEqual(res["tier"], "P", res["reasons_for_tier_f"])
        self.assertEqual(res["facts"]["changed_crates"], ["serde"])

    def test_never_downgrades_and_fails_closed_on_bad_input(self):
        bad = {
            "not a reference": dict(reference=self.reference(scope="patch")),
            "reference NO-GO": dict(reference=self.reference(verdict="NO-GO")),
            "answers schema": dict(answers={"schema": "x"}),
            "bad newer": dict(answers=self.answers(first_available_newer="rhel9")),
            "bad t3": dict(answers=self.answers(t3_targets=["debian12"])),
            "bad since": dict(since="next"),
            "not an elf": dict(exe=TABLE_PATH),
        }
        for name, kw in bad.items():
            with self.subTest(name):
                p, res, out = self.assess(self.docs_only, **kw)
                self.assertEqual(p.returncode, 2, name)
                self.assertFalse(os.path.exists(os.path.join(out, "TIER_ASSESSMENT.json")))

    def test_does_not_overwrite_an_existing_record(self):
        p, res, out = self.assess(self.docs_only)
        ans = os.path.join(self.t, "ans-again.json")
        wr(ans, json.dumps(self.answers()))
        p = subprocess.run([sys.executable, TIER, "--repo", self.repo, "--last-tag", "v1.4.0", "--source-candidate",
                            self.docs_only, "--executable", self.exe, "--answers", ans, "--run-date", "2026-11-20",
                            "--request", "F", "--out", out], capture_output=True, text=True)
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(json.loads(rd(os.path.join(out, "TIER_ASSESSMENT.json"), "r"))["tier"], "P")


# ---------------------------------------------------------------------------
# approval set /3 (docs commit D)
# ---------------------------------------------------------------------------
class ApprovalSetV3(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._t = tempfile.TemporaryDirectory(prefix="approval-set-v3-")
        cls.f = tvas.Fixture(os.path.join(cls._t.name, "pristine"))
        f = cls.f
        cls.man = rd(os.path.join(f.acceptance, f"sinter-v{tvas.VERSION}-acceptance-manifest.json"))
        cls.mpath = f"release/evidence/v{tvas.VERSION}/acceptance-manifest.json"
        cls.docs = {cls.mpath: cls.man, "docs-site/src/data/resources.json": '{"version": "9.9.9"}\n',
                    "README.md": "Sinter 9.9.9\n", "examples/start/README.ja.md": "9.9.9\n"}
        cls.D = commit_on(f.repo, [f.rc], cls.docs, "docs: v9.9.9")
        cls.set3, cls.digest3 = cls.make(cls.D)

    @classmethod
    def tearDownClass(cls):
        cls._t.cleanup()

    @classmethod
    def make(cls, d, base=None, expect_ok=True):
        out = tempfile.mkdtemp(prefix="set3-", dir=cls._t.name)
        os.rmdir(out)
        f = cls.f
        args = [sys.executable, MAKE, out, "--acceptance", f.acceptance, "--evidence", f.evidence,
                "--collector", os.path.join(f.repo, "release/acceptance-harness/collect-evidence.py"),
                *sum((["--collector-run", r] for r in f.collector_runs), []), "--rc-tree", f.tree,
                "--docs-commit", d, "--rc-repo", f.repo]
        if base:
            args += ["--docs-base", base]
        p = subprocess.run(args, capture_output=True, text=True)
        if expect_ok:
            assert p.returncode == 0, p.stderr
            return out, p.stdout.strip()
        return p

    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="w-", dir=self._t.name)
        self.set = os.path.join(self.work, "set")
        shutil.copytree(self.set3, self.set)

    def verify(self, s=None, *extra, rc_repo=True):
        args = [s or self.set]
        if rc_repo:
            args += ["--rc-repo", self.f.repo]
        return subprocess.run([sys.executable, VERIFY, *args, *extra], capture_output=True, text=True,
                              env=tvas.clean_env())

    def full(self, s=None, *extra):
        return subprocess.run([sys.executable, VERIFY, s or self.set, "--rc-repo", self.f.repo, "--evidence",
                               self.f.evidence, "--artifact", self.f.artifact, "--expect-rc", self.f.rc, *extra],
                              capture_output=True, text=True, env=tvas.clean_env(**tvas.SANITIZE_ENV))

    def relist(self):
        old, self.f.set = self.f.set, self.set
        try:
            self.f.relist()
        finally:
            self.f.set = old

    def forge(self, d=None, meta=None, patch=None):
        """Replace D in the copied set as a forger would, and relist."""
        mp = os.path.join(self.set, "APPROVAL-SET-META.json")
        m = json.loads(rd(mp, "r"))
        if d:
            m["docs_commit"] = d
            m["docs_tree"] = git(self.f.repo, "rev-parse", d + "^{tree}")
            wr(os.path.join(self.set, "docs-commit/D.patch"),
               subprocess.run(["git", "-C", self.f.repo, "format-patch", "-1", "--stdout", "--no-signature", d],
                              capture_output=True).stdout)
        if meta:
            meta(m)
        wr(mp, json.dumps(m, indent=2, sort_keys=True) + "\n")
        if patch:
            pp = os.path.join(self.set, "docs-commit/D.patch")
            wr(pp, patch(rd(pp)))
        self.relist()

    def assertInvalid(self, p, needle=None):
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        if needle:
            self.assertIn(needle, p.stdout + p.stderr)

    def test_valid_v3_set_is_pending_and_only_its_digest_is_go(self):
        p = self.full()
        self.assertEqual(p.returncode, 3, p.stdout + p.stderr)
        for label in ("D the docs commit has exactly one parent", "D the patch applied to the base tree reproduces",
                      "D every path the docs commit changes is in the docs allow-list",
                      f"D {self.mpath} in the docs commit == the approved acceptance manifest"):
            self.assertIn(label, p.stdout)
        m = json.loads(rd(os.path.join(self.set, "APPROVAL-SET-META.json"), "r"))
        self.assertEqual(m["schema"], "sinter-approval-set/3")
        self.assertEqual((m["docs_commit"], m["docs_tree"]), (self.D, git(self.f.repo, "rev-parse", self.D + "^{tree}")))
        self.assertEqual(self.verify(None, "--approved-digest", self.digest3).returncode, 0)

    def test_v2_set_still_verifies(self):
        p = tvas.verify(self.f.set, "--rc-repo", self.f.repo, "--evidence", self.f.evidence, "--artifact",
                        self.f.artifact, env=tvas.clean_env(**tvas.SANITIZE_ENV))
        self.assertEqual(p.returncode, 3, p.stdout + p.stderr)
        self.assertEqual(tvas.verify(self.f.set, "--approved-digest", self.f.digest).returncode, 0)

    def test_v3_needs_the_rc_repository(self):
        p = self.verify(rc_repo=False)
        self.assertNotIn(p.returncode, (0, 3), p.stdout + p.stderr)
        self.assertIn("needs --rc-repo", p.stdout + p.stderr)

    def test_wrong_parent(self):
        x = commit_on(self.f.repo, [self.f.rc], {"NOTE": "moved\n"})
        self.forge(commit_on(self.f.repo, [x], self.docs))
        self.assertInvalid(self.verify(), "D the docs commit has exactly one parent")
        p = self.make(commit_on(self.f.repo, [x], self.docs, "again"), expect_ok=False)
        self.assertNotEqual(p.returncode, 0)

    def test_wrong_tree(self):
        self.forge(meta=lambda m: m.update(docs_tree=self.f.tree))
        self.assertInvalid(self.verify(), "D docs_tree == git tree of docs_commit")

    def test_tampered_patch(self):
        self.forge(patch=lambda b: b.replace(b"Sinter 9.9.9", b"Sinter 9.9.8"))
        self.assertInvalid(self.verify(), "D the patch applied to the base tree reproduces docs_tree")
        self.setUp()
        self.forge(patch=lambda b: b + b"\n" + b.split(b"\n", 1)[0] + b"\n")
        self.assertInvalid(self.verify(), "D docs-commit/D.patch holds exactly one commit")
        self.setUp()
        self.forge(patch=lambda b: b.replace(self.D.encode(), b"0" * 40, 1))
        self.assertInvalid(self.verify(), "D docs-commit/D.patch is format-patch output of docs_commit")

    def test_path_outside_the_allow_list(self):
        for path in ("src/main.rs", "release/acceptance-harness/applicability.json", "Cargo.toml",
                     "release/evidence/v9.9.8/acceptance-manifest.json", "examples/start/recipe.yaml"):
            with self.subTest(path):
                d = commit_on(self.f.repo, [self.f.rc], dict(self.docs, **{path: "changed\n"}), path)
                s, _ = self.make(d)
                self.assertInvalid(self.verify(s), "D every path the docs commit changes is in the docs allow-list")

    def test_manifest_copy_must_be_the_approved_manifest(self):
        for name, docs in (("changed", dict(self.docs, **{self.mpath: self.man + b" "})),
                           ("missing", {k: v for k, v in self.docs.items() if k != self.mpath})):
            with self.subTest(name):
                s, _ = self.make(commit_on(self.f.repo, [self.f.rc], docs, name))
                self.assertInvalid(self.verify(s), "in the docs commit == the approved acceptance manifest")

    def test_old_approval_does_not_cover_a_changed_d(self):
        d2 = commit_on(self.f.repo, [self.f.rc], dict(self.docs, **{"README.md": "Sinter 9.9.9 (fixed)\n"}))
        s2, digest2 = self.make(d2)
        self.assertNotEqual(digest2, self.digest3)
        p = self.verify(s2, "--approved-digest", self.digest3)
        self.assertEqual(p.returncode, 1)
        self.assertIn("DIFFERS", p.stdout)
        self.forge(d=d2)  # the old set with the new D swapped in
        self.assertEqual(self.verify(None, "--approved-digest", self.digest3).returncode, 1)

    def test_incomplete_set(self):
        os.remove(os.path.join(self.set, "docs-commit/D.patch"))
        self.relist()
        self.assertInvalid(self.verify())
        self.setUp()
        self.forge(meta=lambda m: m.pop("docs_tree"))
        self.assertInvalid(self.verify(), "docs_commit / docs_tree are not full 40-hex ids")
        self.setUp()
        self.forge(meta=lambda m: m.update(schema="sinter-approval-set/2"))
        self.assertInvalid(self.verify())

    def test_a_v2_manifest_needs_a_v3_set(self):
        work = tempfile.mkdtemp(prefix="v2man-", dir=self._t.name)
        s2 = os.path.join(work, "set")
        shutil.copytree(self.f.set, s2)
        old, self.f.set = self.f.set, s2
        try:
            def to_v2(files):
                m = json.loads(files["acceptance-manifest.json"])
                m.update(schema="sinter-acceptance-manifest/2", acceptance_scope="full", required_targets=LABELS)
                files["acceptance-manifest.json"] = (json.dumps(m, indent=2) + "\n").encode()
            self.f.rebuild_bundle(to_v2)
            self.f.relist()
        finally:
            self.f.set = old
        p = self.verify(s2, rc_repo=False)
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("C a sinter-acceptance-manifest/2 needs a sinter-approval-set/3 (with D)", p.stdout + p.stderr)
        acc = tempfile.mkdtemp(prefix="acc-", dir=self._t.name)
        for n in os.listdir(os.path.join(s2, "acceptance")):
            shutil.copyfile(os.path.join(s2, "acceptance", n), os.path.join(acc, n))
        out = os.path.join(self._t.name, "refused-v2-set")
        p = subprocess.run([sys.executable, MAKE, out, "--acceptance", acc, "--evidence", self.f.evidence,
                            "--collector", os.path.join(self.f.repo, "release/acceptance-harness/collect-evidence.py"),
                            *sum((["--collector-run", r] for r in self.f.collector_runs), []),
                            "--rc-tree", self.f.tree], capture_output=True, text=True)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("needs the docs commit D", p.stderr)

    def test_recovery_on_a_merge_base(self):
        other = commit_on(self.f.repo, [self.f.rc], {"OTHER": "main moved\n"}, "main moved")
        clean = git(self.f.repo, "merge-tree", "--write-tree", other, self.f.rc).splitlines()[0]
        merge = commit_on(self.f.repo, [other, self.f.rc], {}, "Merge RC", base_tree=clean)
        # a merge that drops main's change is not the clean merge of its parents
        lossy = commit_on(self.f.repo, [other, self.f.rc], {}, "Merge RC (lossy)", base_tree=self.f.tree)
        dl = commit_on(self.f.repo, [lossy], self.docs, "docs on lossy merge")
        self.assertNotEqual(self.make(dl, base=lossy, expect_ok=False).returncode, 0)
        self.forge(d=dl, meta=lambda m: m.update(docs_base=lossy))
        self.assertInvalid(self.verify(), "D docs_base's tree is the clean merge of its two parents")
        self.setUp()
        d = commit_on(self.f.repo, [merge], self.docs, "docs on merge")
        s, _ = self.make(d, base=merge)
        p = self.verify(s)
        self.assertEqual(p.returncode, 3, p.stdout + p.stderr)
        self.assertIn("D docs_base is a merge with two parents, one of them rc_commit", p.stdout)
        # without docs_base the same D has the wrong parent
        self.assertNotEqual(self.make(d, expect_ok=False).returncode, 0)
        # a docs_base that is not a merge of RC_COMMIT
        x = commit_on(self.f.repo, [self.f.rc], {"NOTE": "x\n"})
        dx = commit_on(self.f.repo, [x], self.docs, "docs on x")
        self.assertNotEqual(self.make(dx, base=x, expect_ok=False).returncode, 0)
        self.forge(d=dx, meta=lambda m: m.update(docs_base=x))
        self.assertInvalid(self.verify(), "D docs_base is a merge with two parents, one of them rc_commit")
        self.setUp()
        self.forge(meta=lambda m: m.update(docs_base="nothex"))
        self.assertInvalid(self.verify(), "docs_base is only allowed")


if __name__ == "__main__":
    unittest.main()
