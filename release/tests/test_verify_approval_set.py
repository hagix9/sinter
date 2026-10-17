"""Tests for release/make_approval_set.py and release/verify_approval_set.py.

Every fixture is synthetic and built in a temporary directory: a throwaway
git repository plays the release candidate, the acceptance evidence is
written run by run with the repository's own harness files, the repository's
collector tallies it and its sanitizer writes the bundle logs. No network,
no cloud, no GitHub; identifiers are obviously fake.

Run: python3 -m unittest discover -s release/tests
"""
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
RELEASE = os.path.dirname(HERE)
HARNESS = os.path.join(RELEASE, "acceptance-harness")
VERIFY = os.path.join(RELEASE, "verify_approval_set.py")
MAKE = os.path.join(RELEASE, "make_approval_set.py")

VERSION = "9.9.9"
LABELS = ["ubuntu2404", "ubuntu2604", "rocky9", "rocky10", "rhel9", "rhel10", "alma9", "alma10"]
OS = {"ubuntu2404": ("Ubuntu", "24.04"), "ubuntu2604": ("Ubuntu", "26.04"), "rocky9": ("Rocky Linux", "9.8"),
      "rocky10": ("Rocky Linux", "10.2"), "rhel9": ("Red Hat Enterprise Linux", "9.8"),
      "rhel10": ("Red Hat Enterprise Linux", "10.2"), "alma9": ("AlmaLinux", "9.8"), "alma10": ("AlmaLinux", "10.2")}
EXE = "e" * 64
# The runtime record of every run: the files the driver copies.
RECORD = ["run-target.sh", "run-all.sh", "finalize-verdict.sh", "collect-evidence.py", "raw-verdict.py",
          "derive-expected-checks.sh", "run-acceptance-wrapper.sh", "remote-cleanup.sh", "acceptance-target.sh",
          "target-prep.sh", "sanitize.py", "expected-check-ids.txt"]
NOT_RUN = {"collect-evidence.py", "finalize-verdict.sh", "derive-expected-checks.sh"}
SANITIZE_ENV = {"SINTER_PROJECT": "fixture-project", "SINTER_ZONE": "fixture-zone-a",
                "SINTER_SPECS": " ".join(f"fixture-vm-{i}:{lb}:no:no" for i, lb in enumerate(LABELS))}


def H(b):
    return hashlib.sha256(b).hexdigest()


def read(path, mode="r"):
    with open(path, mode) as f:
        return f.read()


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb" if isinstance(data, bytes) else "w") as f:
        f.write(data)


def run(argv, env=None, cwd=None):
    return subprocess.run(argv, env=env, cwd=cwd, capture_output=True, text=True, timeout=180)


def clean_env(**extra):
    e = {k: v for k, v in os.environ.items() if not k.startswith("SINTER_")}
    e.update(extra)
    return e


class Fixture:
    """One complete, consistent approval set for a synthetic release candidate."""

    def __init__(self, root, earlier_failure=False, marker="first"):
        self.marker = marker
        self.root = root
        self.repo = os.path.join(root, "repo")
        self.evidence = os.path.join(root, "out")
        self.acceptance = os.path.join(root, "acceptance")
        self.set = os.path.join(root, "approval-set")
        self.artifact = os.path.join(root, f"sinter-v{VERSION}-linux-x86_64.tar.gz")
        write(self.artifact, b"synthetic release tarball\n")
        self.art_sha = H(read(self.artifact, "rb"))
        self._repo()
        self._evidence()
        runs = []
        if earlier_failure:
            # A first tally without the rhel10 run: NO-GO, kept in the record.
            hidden = os.path.join(root, "hidden")
            rid = "fixture-run-rhel10"
            shutil.move(os.path.join(self.evidence, "runs", rid), hidden)
            runs.append(self._collect("01"))
            shutil.move(hidden, os.path.join(self.evidence, "runs", rid))
        runs.append(self._collect(f"{len(runs) + 1:02d}", write_verdict=True))
        self.collector_runs = runs
        self._assets()
        p = run([sys.executable, MAKE, self.set, "--acceptance", self.acceptance, "--evidence", self.evidence,
                 "--collector", os.path.join(self.repo, "release/acceptance-harness/collect-evidence.py"),
                 *sum((["--collector-run", d] for d in runs), []), "--rc-tree", self.tree])
        assert p.returncode == 0, p.stderr
        self.digest = p.stdout.strip()

    def _repo(self):
        os.makedirs(self.repo)
        shutil.copytree(HARNESS, os.path.join(self.repo, "release/acceptance-harness"))
        write(os.path.join(self.repo, "Cargo.toml"), f'[package]\nname = "sinter"\nversion = "{VERSION}"\n')
        write(os.path.join(self.repo, "NOTE"), self.marker + "\n")  # distinguishes candidates
        g = ["git", "-C", self.repo, "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid"]
        assert run(["git", "init", "-q", self.repo]).returncode == 0
        assert run(g + ["add", "-A"]).returncode == 0
        assert run(g + ["commit", "-q", "-m", "fixture rc"]).returncode == 0
        self.rc = run(["git", "-C", self.repo, "rev-parse", "HEAD"]).stdout.strip()
        self.tree = run(["git", "-C", self.repo, "rev-parse", "HEAD^{tree}"]).stdout.strip()

    def _evidence(self):
        hdir = os.path.join(self.repo, "release/acceptance-harness")
        ids = [x.strip() for x in read(os.path.join(hdir, "expected-check-ids.txt")).splitlines() if x.strip()]
        sums = "".join(f"{H(read(os.path.join(hdir, n), 'rb'))}  ./{n}\n" for n in sorted(RECORD))
        self.runtime_record = sums.encode()
        for i, lb in enumerate(LABELS):
            rid = f"fixture-run-{lb}"
            d = os.path.join(self.evidence, "runs", rid)
            start = f"2026-01-01T0{i}:00:00Z"
            raw = [f"== acceptance start 2026-01-01T0{i}:00:30Z label={lb}",
                   f"OBSERVED_ARTIFACT_SHA={self.art_sha}", f"OBSERVED_EXECUTABLE_SHA={EXE}",
                   f"OBSERVED_VERSION=sinter {VERSION}", f"OS_NAME={OS[lb][0]} OS_VERSION={OS[lb][1]} ARCH=x86_64",
                   f"connected to fixture-vm-{i} in fixture-project"]
            raw += [f"== check {c} ok" for c in ids]
            raw += [f"== acceptance end 2026-01-01T0{i}:05:00Z passed={len(ids)} failed=0 skipped=0"]
            raw_b = ("\n".join(raw) + "\n").encode()
            write(os.path.join(d, "raw.log"), raw_b)
            os.makedirs(os.path.join(d, "scripts"))
            for n in RECORD:
                shutil.copyfile(os.path.join(hdir, n), os.path.join(d, "scripts", n))
            write(os.path.join(d, "scripts", "SHA256SUMS"), sums)
            rj = {"run_id": rid, "label": lb, "vm": f"fixture-vm-{i}", "verdict": "PASS", "acceptance_rc": "0",
                  "started_at": start, "finished_at": f"2026-01-01T0{i}:06:00Z", "raw_log_sha256": H(raw_b),
                  "remote_raw_sha256": H(raw_b), "remote_raw_stat": "1 2 3",
                  "acceptance_end": raw[-1], "rc_commit": self.rc, "artifact_sha256": self.art_sha,
                  "remote_raw_path": f"/var/tmp/sinter-acceptance-{rid}/raw.log", "cleanup_ok": True,
                  "source_image": f"fixture-{lb}-image-v1", "source_image_id": "1234567890"}
            write(os.path.join(d, "run.json"), json.dumps(rj, indent=2) + "\n")

    def _collect(self, rid, write_verdict=False):
        env = clean_env(SINTER_RC_COMMIT=self.rc, SINTER_EXP_ART=self.art_sha, SINTER_EXP_VER=f"sinter {VERSION}")
        for n in ("summary.txt", "VERDICT.txt"):
            if os.path.exists(os.path.join(self.evidence, n)):
                os.remove(os.path.join(self.evidence, n))
        p = run([sys.executable, "-I", os.path.join(self.repo, "release/acceptance-harness/collect-evidence.py"),
                 self.evidence] + (["--write-verdict"] if write_verdict else []), env=env)
        assert p.returncode == 0, p.stderr
        d = os.path.join(self.root, "collector-runs", rid)
        write(os.path.join(d, "collect.txt"), p.stdout)
        shutil.copyfile(os.path.join(self.evidence, "summary.txt"), os.path.join(d, "summary.txt"))
        if write_verdict:
            shutil.copyfile(os.path.join(self.evidence, "VERDICT.txt"), os.path.join(d, "VERDICT.txt"))
        return d

    def _assets(self):
        stem = f"sinter-v{VERSION}-acceptance-evidence"
        files = {}
        hdir = os.path.join(self.repo, "release/acceptance-harness")
        prov_files = []
        for n in sorted(RECORD):
            b = read(os.path.join(hdir, n), "rb")
            e = {"name": n, "runtime_sha256": H(b), "source_path": f"release/acceptance-harness/{n}"}
            if n in NOT_RUN:
                e.update(bundle_form="not-included", bundle_path=None)
            else:
                e.update(bundle_form="verbatim", bundle_path=f"harness/{n}")
                files[f"harness/{n}"] = b
            prov_files.append(e)
        last_collect = read(os.path.join(self.collector_runs[-1], "collect.txt"))
        digest = [ln for ln in last_collect.splitlines() if ln.startswith("evidence_digest: ")][-1].split(": ")[1]
        rec_sums = self._record_sums()
        results = []
        for d in self.collector_runs:
            v = [ln for ln in read(os.path.join(d, "collect.txt")).splitlines()
                 if ln.startswith("overall verdict: ")][-1].split(": ")[1]
            results.append({"result": v})
        prov = {"schema": "sinter-harness-provenance/1", "source_commit": self.rc,
                "runtime_record": {"sha256": H(self.runtime_record)}, "files": prov_files,
                "post_acceptance_collector": {"sha256": H(read(os.path.join(hdir, "collect-evidence.py"), "rb")),
                                              "results": results, "evidence_digest": digest,
                                              "collector_record_sha256sums_sha256": rec_sums}}
        files["harness/PROVENANCE.json"] = (json.dumps(prov, indent=2) + "\n").encode()
        targets = []
        env = clean_env(**SANITIZE_ENV)
        for lb in LABELS:
            rdir = os.path.join(self.evidence, "runs", f"fixture-run-{lb}")
            out = os.path.join(self.root, "logs", f"{lb}.log")
            os.makedirs(os.path.dirname(out), exist_ok=True)
            p = run([sys.executable, "-I", os.path.join(hdir, "sanitize.py"), lb, os.path.join(rdir, "raw.log"), out],
                    env=env)
            assert p.returncode == 0, p.stderr
            files[f"logs/{lb}.log"] = read(out, "rb")
            rj = json.loads(read(os.path.join(rdir, "run.json")))
            n = len([x for x in read(os.path.join(rdir, "raw.log")).splitlines() if x.startswith("== check ")])
            targets.append({"label": lb, "os_name": OS[lb][0], "os_version": OS[lb][1], "arch": "x86_64",
                            "image": rj["source_image"], "started_at": rj["started_at"],
                            "finished_at": rj["finished_at"], "artifact_sha256": self.art_sha,
                            "executable_sha256": EXE, "version_output": f"sinter {VERSION}",
                            "checks": {"total": n, "passed": n, "failed": 0, "skipped": 0}, "verdict": "PASS",
                            "log": {"path": f"logs/{lb}.log", "sha256": H(files[f"logs/{lb}.log"])}})
        files["validation/linux-gate.log"] = b"== step root-test start\n== step root-test rc=0 end\n"
        man = {"schema": "sinter-acceptance-manifest/1",
               "candidate": {"version": VERSION, "tag": f"v{VERSION}", "source_commit": self.rc,
                             "artifact": {"filename": os.path.basename(self.artifact), "sha256": self.art_sha,
                                          "size_bytes": os.path.getsize(self.artifact)},
                             "executable_sha256": EXE},
               "harness": {"name": "fixture", "version": self.rc,
                           "files": [{"path": p, "sha256": H(b)} for p, b in sorted(files.items())
                                     if p.startswith("harness/")]},
               "run": {"started_at": "2026-01-01T00:00:00Z", "finished_at": "2026-01-01T08:00:00Z"},
               "targets": targets, "verdict": "GO", "evidence_bundle": f"{stem}.tar.gz"}
        man_b = (json.dumps(man, indent=2) + "\n").encode()
        self.manifest = man
        files["acceptance-manifest.json"] = man_b
        os.makedirs(self.acceptance)
        write(os.path.join(self.acceptance, f"sinter-v{VERSION}-acceptance-manifest.json"), man_b)
        bun = self.tar(stem, files)
        write(os.path.join(self.acceptance, f"{stem}.tar.gz"), bun)
        write(os.path.join(self.acceptance, f"sinter-v{VERSION}-acceptance-SHA256SUMS"),
              f"{H(man_b)}  sinter-v{VERSION}-acceptance-manifest.json\n{H(bun)}  {stem}.tar.gz\n")
        self.bundle_files = files

    def _record_sums(self):
        """SHA-256 of the collector record's SHA256SUMS as make_approval_set.py writes it."""
        hdir = os.path.join(self.repo, "release/acceptance-harness")
        entries = {"collect-evidence.py": read(os.path.join(hdir, "collect-evidence.py"), "rb"),
                   "runtime-scripts-SHA256SUMS": self.runtime_record}
        for i, d in enumerate(self.collector_runs, 1):
            names = ["collect.txt", "summary.txt"] + (["VERDICT.txt"] if i == len(self.collector_runs) else [])
            for n in names:
                entries[f"runs/{i:02d}/{n}"] = read(os.path.join(d, n), "rb")
        names = sorted(entries, key=lambda s: s.encode())
        return H("".join(f"{H(entries[n])}  {n}\n" for n in names).encode())

    @staticmethod
    def tar(stem, files, owner=("root", 0)):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.USTAR_FORMAT) as tf:
            dirs = {stem}
            for p in files:
                parts = p.split("/")[:-1]
                for i in range(1, len(parts) + 1):
                    dirs.add(stem + "/" + "/".join(parts[:i]))
            for d in sorted(dirs):
                ti = tarfile.TarInfo(d)
                ti.type, ti.mode, ti.mtime = tarfile.DIRTYPE, 0o755, 0
                ti.uid = ti.gid = owner[1]
                ti.uname = ti.gname = owner[0]
                tf.addfile(ti)
            for p, b in sorted(files.items()):
                ti = tarfile.TarInfo(f"{stem}/{p}")
                ti.size, ti.mode, ti.mtime = len(b), 0o644, 0
                ti.uid = ti.gid = owner[1]
                ti.uname = ti.gname = owner[0]
                tf.addfile(ti, io.BytesIO(b))
        return buf.getvalue()

    # ---- helpers for tampering ------------------------------------------------
    def relist(self):
        """Recompute APPROVAL-SET.sha256 after a deliberate change (a forger would)."""
        members = []
        for d, _, names in os.walk(self.set):
            for n in names:
                rel = os.path.relpath(os.path.join(d, n), self.set).replace(os.sep, "/")
                if rel != "APPROVAL-SET.sha256":
                    members.append(rel)
        members.sort(key=lambda s: s.encode())
        write(os.path.join(self.set, "APPROVAL-SET.sha256"),
              "".join(f"{H(read(os.path.join(self.set, p), 'rb'))}  {p}\n" for p in members))

    def meta(self):
        return json.loads(read(os.path.join(self.set, "APPROVAL-SET-META.json")))

    def current_bundle(self):
        stem = f"sinter-v{VERSION}-acceptance-evidence"
        files = {}
        with tarfile.open(os.path.join(self.set, "acceptance", f"{stem}.tar.gz"), "r:gz") as tf:
            for m in tf.getmembers():
                if m.isreg():
                    files[m.name[len(stem) + 1:]] = tf.extractfile(m).read()
        return files

    def rebuild_bundle(self, mutate, owner=("root", 0)):
        """Rewrite the three acceptance assets consistently after mutate(files)."""
        files = self.current_bundle()
        mutate(files)
        man = json.loads(files["acceptance-manifest.json"])
        man["harness"]["files"] = [{"path": p, "sha256": H(b)} for p, b in sorted(files.items())
                                   if p.startswith("harness/")]
        man_b = (json.dumps(man, indent=2) + "\n").encode()
        files["acceptance-manifest.json"] = man_b
        stem = f"sinter-v{VERSION}-acceptance-evidence"
        bun = Fixture.tar(stem, files, owner)
        acc = os.path.join(self.set, "acceptance")
        write(os.path.join(acc, f"sinter-v{VERSION}-acceptance-manifest.json"), man_b)
        write(os.path.join(acc, f"{stem}.tar.gz"), bun)
        write(os.path.join(acc, f"sinter-v{VERSION}-acceptance-SHA256SUMS"),
              f"{H(man_b)}  sinter-v{VERSION}-acceptance-manifest.json\n{H(bun)}  {stem}.tar.gz\n")

    def edit_provenance(self, change):
        def mutate(files):
            prov = json.loads(files["harness/PROVENANCE.json"])
            change(prov)
            files["harness/PROVENANCE.json"] = (json.dumps(prov, indent=2) + "\n").encode()
        self.rebuild_bundle(mutate)

    def rewrite_record(self):
        """Recompute collector-record/SHA256SUMS and the META/PROVENANCE digests of it."""
        cr = os.path.join(self.set, "collector-record")
        names = sorted((os.path.relpath(os.path.join(d, n), cr).replace(os.sep, "/")
                        for d, _, ns in os.walk(cr) for n in ns if n != "SHA256SUMS" or d != cr),
                       key=lambda x: x.encode())
        write(os.path.join(cr, "SHA256SUMS"), "".join(f"{H(read(os.path.join(cr, n), 'rb'))}  {n}\n" for n in names))
        digest = H(read(os.path.join(cr, "SHA256SUMS"), "rb"))
        m = self.meta()
        m["collector"]["record_sha256sums_sha256"] = digest
        self.set_meta(m)
        self.edit_provenance(lambda prov: prov["post_acceptance_collector"].update(
            collector_record_sha256sums_sha256=digest))

    def set_meta(self, m):
        write(os.path.join(self.set, "APPROVAL-SET-META.json"), json.dumps(m, indent=2, sort_keys=True) + "\n")


def verify(*args, env=None):
    return run([sys.executable, VERIFY, *args], env=env or clean_env())


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="approval-set-test-")
        cls.pristine = Fixture(os.path.join(cls.tmp.name, "pristine"))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        # Each test tampers with its own copy of the set.
        self.f = self.pristine
        self.work = tempfile.mkdtemp(prefix="set-", dir=self.tmp.name)
        self.set = os.path.join(self.work, "approval-set")
        shutil.copytree(self.f.set, self.set)
        self.f_set = self.f.set
        self.f.set = self.set

    def tearDown(self):
        self.f.set = self.f_set

    def full(self, *extra, env=None):
        return verify(self.set, "--rc-repo", self.f.repo, "--evidence", self.f.evidence,
                      "--artifact", self.f.artifact, *extra, env=env or clean_env(**SANITIZE_ENV))


class ValidSet(Base):
    def test_structural_check_is_pending_never_go(self):
        p = verify(self.set)
        self.assertEqual(p.returncode, 3, p.stdout + p.stderr)
        self.assertIn("PENDING_OWNER_APPROVAL", p.stdout)
        self.assertIn(f"APPROVAL_SET_DIGEST {self.f.digest}", p.stdout)

    def test_full_check_with_rc_evidence_and_artifact_is_pending(self):
        p = self.full("--expect-rc", self.f.rc, "--expect-version", VERSION)
        self.assertEqual(p.returncode, 3, p.stdout + p.stderr)
        for label in ("H rc_tree", "I collector reproduces the last run's output", "M rocky10: image",
                      "I exactly one recorded run per target label", "R artifact"):
            self.assertIn(label, p.stdout)

    def test_only_the_approved_digest_is_go(self):
        self.assertEqual(verify(self.set, "--approved-digest", self.f.digest).returncode, 0)
        p = verify(self.set, "--approved-digest", "0" * 64)
        self.assertEqual(p.returncode, 1)
        self.assertIn("DIFFERS", p.stdout)

    def test_evidence_without_sanitize_identity_fails_closed(self):
        p = self.full(env=clean_env())
        self.assertEqual(p.returncode, 1)
        self.assertIn("bundle log == RC sanitize.py", p.stderr)


class RejectedSets(Base):
    def assertInvalid(self, p, needle=None):
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("INVALID", p.stdout)
        if needle:
            self.assertIn(needle, p.stdout + p.stderr)

    def test_modified_member(self):
        p = os.path.join(self.set, "collector-record/runs/01/summary.txt")
        write(p, read(p) + "x\n")
        self.assertInvalid(verify(self.set), "A canonical member list")

    def test_extra_member(self):
        write(os.path.join(self.set, "acceptance/notes.txt"), "extra\n")
        self.f.relist()
        self.assertInvalid(verify(self.set), "extra=['acceptance/notes.txt']")

    def test_missing_member(self):
        os.remove(os.path.join(self.set, "collector-record/runs/01/VERDICT.txt"))
        self.f.relist()
        self.assertInvalid(verify(self.set), "missing=")

    def test_duplicate_list_entry(self):
        lst = os.path.join(self.set, "APPROVAL-SET.sha256")
        lines = read(lst).splitlines(keepends=True)
        write(lst, "".join(lines + lines[:1]))
        self.assertInvalid(verify(self.set), "duplicate entry")

    def test_symlink_and_empty_directory(self):
        os.symlink("APPROVAL-SET-META.json", os.path.join(self.set, "link.json"))
        self.assertInvalid(verify(self.set), "symlink")
        os.remove(os.path.join(self.set, "link.json"))
        os.mkdir(os.path.join(self.set, "empty"))
        self.assertInvalid(verify(self.set), "empty directory")

    def test_malformed_meta(self):
        write(os.path.join(self.set, "APPROVAL-SET-META.json"), "{not json")
        self.f.relist()
        self.assertInvalid(verify(self.set))

    def test_meta_identity_must_match_the_manifest(self):
        for key, value in (("rc_commit", "1" * 40), ("executable_sha256", "d" * 64), ("tag", "v0.0.1")):
            with self.subTest(key=key):
                shutil.rmtree(self.set)
                shutil.copytree(self.f_set, self.set)
                m = self.f.meta()
                m[key] = value
                self.f.set_meta(m)
                self.f.relist()
                self.assertInvalid(verify(self.set), f"C META.{key}")

    def test_set_of_another_rc_is_not_reused(self):
        p = verify(self.set, "--expect-rc", "2" * 40, "--approved-digest", self.f.digest)
        self.assertInvalid(p, "the set belongs to another release candidate")
        p = verify(self.set, "--expect-version", "9.9.8")
        self.assertInvalid(p, "another version")

    def test_approval_for_one_rc_does_not_cover_a_set_for_another(self):
        other = Fixture(os.path.join(self.work, "other"), marker="second")
        self.assertNotEqual(other.rc, self.f.rc)
        p = verify(other.set, "--approved-digest", self.f.digest)
        self.assertEqual(p.returncode, 1)
        self.assertIn("DIFFERS", p.stdout)

    def test_rc_tree_and_version_must_match_the_repository(self):
        m = self.f.meta()
        m["rc_tree"] = "3" * 40
        self.f.set_meta(m)
        self.f.relist()
        self.assertInvalid(verify(self.set, "--rc-repo", self.f.repo), "H rc_tree")

    def test_collector_must_be_the_rc_collector(self):
        c = os.path.join(self.set, "collector-record/collect-evidence.py")
        write(c, read(c) + "# patched after acceptance\n")
        # A forger rewrites every digest that names the collector.
        cr = os.path.join(self.set, "collector-record")
        names = sorted((os.path.relpath(os.path.join(d, n), cr).replace(os.sep, "/")
                        for d, _, ns in os.walk(cr) for n in ns if n != "SHA256SUMS" or d != cr),
                       key=lambda s: s.encode())
        write(os.path.join(cr, "SHA256SUMS"), "".join(f"{H(read(os.path.join(cr, n), 'rb'))}  {n}\n" for n in names))
        m = self.f.meta()
        m["collector"]["sha256"] = H(read(c, "rb"))
        m["collector"]["record_sha256sums_sha256"] = H(read(os.path.join(cr, "SHA256SUMS"), "rb"))
        self.f.set_meta(m)
        self.f.relist()
        self.assertInvalid(verify(self.set), "is the runtime-record collector")

    def test_patched_collector_recorded_everywhere_is_still_not_the_executed_one(self):
        c = os.path.join(self.set, "collector-record/collect-evidence.py")
        write(c, read(c) + "# patched after acceptance\n")
        new = H(read(c, "rb"))
        m = self.f.meta()
        m["collector"]["sha256"] = new
        self.f.set_meta(m)
        self.f.edit_provenance(lambda prov: prov["post_acceptance_collector"].update(sha256=new))
        self.f.rewrite_record()
        self.f.relist()
        self.assertInvalid(verify(self.set), "FAIL E collector (PROVENANCE == META == record) is the runtime-record collector")

    def test_consistently_forged_result_is_caught_by_reproduction(self):
        cr = os.path.join(self.set, "collector-record")
        s = os.path.join(cr, "runs/01/summary.txt")
        write(s, read(s).replace("label\trun_id", "label\trun_id ", 1))
        names = sorted((os.path.relpath(os.path.join(d, n), cr).replace(os.sep, "/")
                        for d, _, ns in os.walk(cr) for n in ns if n != "SHA256SUMS" or d != cr),
                       key=lambda s: s.encode())
        write(os.path.join(cr, "SHA256SUMS"), "".join(f"{H(read(os.path.join(cr, n), 'rb'))}  {n}\n" for n in names))
        m = self.f.meta()
        m["collector"]["record_sha256sums_sha256"] = H(read(os.path.join(cr, "SHA256SUMS"), "rb"))
        self.f.set_meta(m)
        self.f.relist()
        # The structural run sees only the PROVENANCE mismatch of the record digest...
        self.assertInvalid(verify(self.set), "collector record digest")
        # ...and reproduction from the evidence shows the summary was not produced by the collector.
        self.assertInvalid(self.full(), "FAIL I collector reproduces summary.txt")

    def test_fully_consistent_forgery_of_the_output_is_caught_by_reproduction(self):
        c = os.path.join(self.set, "collector-record/runs/01/collect.txt")
        write(c, read(c).replace("collected runs", "collected runs ", 1))
        self.f.rewrite_record()
        self.f.relist()
        self.assertEqual(verify(self.set).returncode, 3)  # structurally consistent
        self.assertInvalid(self.full(), "FAIL I collector reproduces the last run's output")

    def test_last_run_must_be_pending_and_complete(self):
        cr = os.path.join(self.set, "collector-record/runs/01")
        for n in ("collect.txt", "summary.txt"):
            write(os.path.join(cr, n), read(os.path.join(cr, n)).replace(
                "overall verdict: PENDING_OWNER_APPROVAL", "overall verdict: GO"))
        self.assertInvalid(verify(self.set))

    def test_bundle_owned_by_a_local_account(self):
        self.f.rebuild_bundle(lambda files: None, owner=("fixtureuser", 501))
        self.f.relist()
        self.assertInvalid(verify(self.set), "FAIL T every tar member owned by root:root")

    def test_two_recorded_runs_for_one_label(self):
        ev = os.path.join(self.work, "out")
        shutil.copytree(self.f.evidence, ev)
        shutil.copytree(os.path.join(ev, "runs/fixture-run-rocky9"), os.path.join(ev, "runs/fixture-run-rocky9-again"))
        p = verify(self.set, "--rc-repo", self.f.repo, "--evidence", ev, env=clean_env(**SANITIZE_ENV))
        self.assertInvalid(p, "FAIL I exactly one recorded run per target label")

    def test_artifact_mismatch(self):
        art = os.path.join(self.work, os.path.basename(self.f.artifact))
        write(art, b"another tarball\n")
        self.assertInvalid(verify(self.set, "--artifact", art), "R artifact")

    def test_tampered_evidence_is_caught(self):
        ev = os.path.join(self.work, "out")
        shutil.copytree(self.f.evidence, ev)
        raw = os.path.join(ev, "runs/fixture-run-alma9/raw.log")
        write(raw, read(raw).replace("== check ", "== check  ", 1))
        p = verify(self.set, "--rc-repo", self.f.repo, "--evidence", ev, env=clean_env(**SANITIZE_ENV))
        self.assertInvalid(p)

    def test_checker_result_is_required(self):
        stub = os.path.join(self.work, "checker.py")
        write(stub, "import sys\nprint('checker: NO-GO')\nsys.exit(1)\n")
        self.assertInvalid(verify(self.set, "--checker", stub, "--artifact", self.f.artifact), "J official checker")
        write(stub, "print('OK (verdict GO)')\n")
        self.assertEqual(verify(self.set, "--checker", stub, "--artifact", self.f.artifact).returncode, 3)

    def test_publication_copy_is_not_accepted(self):
        # Rebuild the bundle with one harness file declared as a publication copy.
        f = self.f
        files = dict(f.bundle_files)
        prov = json.loads(files["harness/PROVENANCE.json"])
        for e in prov["files"]:
            if e["name"] == "sanitize.py":
                e["bundle_form"] = "publication-copy"
        files["harness/PROVENANCE.json"] = (json.dumps(prov, indent=2) + "\n").encode()
        man = json.loads(files["acceptance-manifest.json"])
        man["harness"]["files"] = [{"path": p, "sha256": H(b)} for p, b in sorted(files.items()) if p.startswith("harness/")]
        man_b = (json.dumps(man, indent=2) + "\n").encode()
        files["acceptance-manifest.json"] = man_b
        stem = f"sinter-v{VERSION}-acceptance-evidence"
        bun = Fixture.tar(stem, files)
        acc = os.path.join(self.set, "acceptance")
        write(os.path.join(acc, f"sinter-v{VERSION}-acceptance-manifest.json"), man_b)
        write(os.path.join(acc, f"{stem}.tar.gz"), bun)
        write(os.path.join(acc, f"sinter-v{VERSION}-acceptance-SHA256SUMS"),
              f"{H(man_b)}  sinter-v{VERSION}-acceptance-manifest.json\n{H(bun)}  {stem}.tar.gz\n")
        f.relist()
        self.assertInvalid(verify(self.set), "E sanitize.py: bundle_form")


class EarlierFailure(unittest.TestCase):
    def test_failed_first_tally_is_kept_and_last_is_pending(self):
        with tempfile.TemporaryDirectory(prefix="approval-set-test-") as t:
            f = Fixture(t, earlier_failure=True)
            meta = json.loads(read(os.path.join(f.set, "APPROVAL-SET-META.json")))
            self.assertEqual([r["verdict"] for r in meta["collector"]["runs"]], ["NO-GO", "PENDING_OWNER_APPROVAL"])
            p = verify(f.set, "--rc-repo", f.repo, "--evidence", f.evidence, env=clean_env(**SANITIZE_ENV))
            self.assertEqual(p.returncode, 3, p.stdout + p.stderr)
            # An earlier run recorded as GO is never acceptable, even when consistent.
            saved = os.path.join(t, "saved-set")
            shutil.copytree(f.set, saved)
            r1 = os.path.join(f.set, "collector-record/runs/01")
            for n in ("collect.txt", "summary.txt"):
                write(os.path.join(r1, n), read(os.path.join(r1, n)).replace(
                    "overall verdict: NO-GO", "overall verdict: GO"))
            m = json.loads(read(os.path.join(f.set, "APPROVAL-SET-META.json")))
            m["collector"]["runs"][0]["verdict"] = "GO"
            f.set_meta(m)
            f.edit_provenance(lambda prov: prov["post_acceptance_collector"]["results"][0].update(result="GO"))
            f.rewrite_record()
            f.relist()
            p = verify(f.set)
            self.assertEqual(p.returncode, 1)
            self.assertIn("FAIL G run 01: an earlier run is never GO", p.stderr)
            shutil.rmtree(f.set)
            shutil.copytree(saved, f.set)
            # Dropping the failed first result is detected.
            shutil.rmtree(os.path.join(f.set, "collector-record/runs/01"))
            self.assertEqual(verify(f.set).returncode, 1)


class FinalFailure(unittest.TestCase):
    def test_a_consistent_set_whose_last_tally_is_no_go_is_invalid(self):
        with tempfile.TemporaryDirectory(prefix="approval-set-test-") as t:
            f = Fixture(t, earlier_failure=True)
            # Present the NO-GO tally as the last one.
            r1, r2 = (os.path.join(f.set, f"collector-record/runs/{i}") for i in ("01", "02"))
            for n in ("collect.txt", "summary.txt"):
                shutil.copyfile(os.path.join(r1, n), os.path.join(r2, n))
            write(os.path.join(r2, "VERDICT.txt"), "NO-GO\n")
            m = json.loads(read(os.path.join(f.set, "APPROVAL-SET-META.json")))
            m["collector"]["runs"][1]["verdict"] = "NO-GO"
            f.set_meta(m)
            f.edit_provenance(lambda prov: prov["post_acceptance_collector"]["results"][1].update(result="NO-GO"))
            f.rewrite_record()
            f.relist()
            p = verify(f.set)
            self.assertEqual(p.returncode, 1)
            self.assertIn("FAIL G run 02 (last): PENDING_OWNER_APPROVAL", p.stderr)


class Usage(unittest.TestCase):
    def test_usage_errors(self):
        for args in (["/nonexistent-dir"], [".", "--approved-digest", "abc"], [".", "--expect-rc", "abc"],
                     [".", "--evidence", "x"], [".", "--checker", "x"], [".", "--no-such-flag"]):
            with self.subTest(args=args):
                self.assertEqual(verify(*args).returncode, 2)

    def test_make_refuses_to_overwrite(self):
        with tempfile.TemporaryDirectory() as t:
            p = run([sys.executable, MAKE, t, "--acceptance", t, "--evidence", t, "--collector", t,
                     "--collector-run", t, "--rc-tree", "0" * 40])
            self.assertEqual(p.returncode, 1)
            self.assertIn("refusing to overwrite", p.stderr)


if __name__ == "__main__":
    unittest.main()
