"""Threat-model tests for release/check_acceptance_manifest.py.

Every fixture is synthetic and built in a temporary directory: no network,
no cloud, no GitHub. Sensitive-looking values are obviously fake fixtures
(`fixture-*`, reserved or private ranges) and are assembled at run time so
this file itself carries no credential-shaped literal.

Run: python3 -m unittest discover -s release/tests
"""
import base64
import copy
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
CHECKER = os.path.join(os.path.dirname(HERE), "check_acceptance_manifest.py")
TEMPLATE = os.path.join(os.path.dirname(HERE), "acceptance-manifest.template.json")

VERSION = "9.9.9"  # synthetic candidate version
STEM = f"sinter-v{VERSION}-acceptance-evidence"
BUNDLE_NAME = STEM + ".tar.gz"
ARTIFACT_NAME = f"sinter-v{VERSION}-linux-x86_64.tar.gz"
# Set by setUpModule: commits of a small fixture crate in a temporary git
# repository, from which the checker derives the root test inventory.
REPO = None
COMMIT = None
COMMIT_ADDED = COMMIT_UNGATED = COMMIT_RENAMED = None
TARGETS = {
    "ubuntu2404": ("Ubuntu", "24.04"),
    "ubuntu2604": ("Ubuntu", "26.04"),
    "rocky9": ("Rocky Linux", "9.8"),
    "rocky10": ("Rocky Linux", "10.2"),
    "rhel9": ("Red Hat Enterprise Linux", "9.8"),
    "rhel10": ("Red Hat Enterprise Linux", "10.2"),
    "alma9": ("AlmaLinux", "9.8"),
    "alma10": ("AlmaLinux", "10.2"),
}
GATE_STEPS = [
    ("root-fmt", "cargo fmt --check", 0),
    ("root-clippy", "cargo clippy --locked --all-targets --all-features -- -D warnings", 0),
    ("root-test", "cargo test --locked --all-targets --all-features", 900),
    ("installer-test", "python3 tests/installer/test_install.py", 20),
    ("checker-test", "python3 -m unittest discover -s release/tests", 60),
    ("gateway-fmt", "cargo fmt --manifest-path gateway/Cargo.toml --check", 0),
    ("gateway-clippy", "cargo clippy --manifest-path gateway/Cargo.toml --locked --all-targets --all-features -- -D warnings", 0),
    ("gateway-test", "cargo test --manifest-path gateway/Cargo.toml --locked --all-targets --all-features", 300),
]
SUITES = ["tests/audit.rs", "tests/cli.rs"]
ROOT_CMD = "cargo test --locked --all-targets --all-features"
# The root test harnesses of the fixture crate and their pass counts; the sum
# (900) is the root-test count recorded in the synthetic manifest.
ROOT_BLOCKS = [
    ("unittests src/lib.rs", 400),
    ("unittests src/main.rs", 0),
    ("tests/audit.rs", 10),
    ("tests/cli.rs", 10),
    ("tests/frontends.rs", 480),
]
LINUX_SUITE = '#![cfg(target_os = "linux")]\n#[test]\nfn t() {}\n'
FIXTURE_CRATE = {
    "Cargo.toml": '[package]\nname = "fixture"\nversion = "0.1.0"\nedition = "2021"\n',
    "src/lib.rs": "pub fn f() {}\n",
    "src/main.rs": "fn main() {}\n",
    "tests/audit.rs": LINUX_SUITE,
    "tests/cli.rs": LINUX_SUITE,
    "tests/frontends.rs": "#[test]\nfn t() {}\n",
}
_repo_tmp = None


def _git(*args):
    return subprocess.run(
        ["git", "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
         "-c", "commit.gpgsign=false", "-C", REPO, *args],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
    ).stdout.strip()


def _commit(base, write=None, remove=(), message="fixture"):
    if base:
        _git("checkout", "-q", "--detach", base)
    for rel, text in (write or {}).items():
        path = os.path.join(REPO, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)
    for rel in remove:
        os.remove(os.path.join(REPO, *rel.split("/")))
    _git("add", "-A")
    _git("commit", "-q", "-m", message)
    return _git("rev-parse", "HEAD")


def setUpModule():
    global REPO, COMMIT, COMMIT_ADDED, COMMIT_UNGATED, COMMIT_RENAMED, _repo_tmp
    _repo_tmp = tempfile.TemporaryDirectory(prefix="sinter-fixture-repo-")
    REPO = _repo_tmp.name
    _git("init", "-q")
    COMMIT = _commit(None, FIXTURE_CRATE, message="fixture crate")
    COMMIT_ADDED = _commit(COMMIT, {"tests/extra.rs": LINUX_SUITE}, message="add a Linux-only suite")
    COMMIT_UNGATED = _commit(COMMIT, {"tests/cli.rs": "#[test]\nfn t() {}\n"}, message="cli runs everywhere")
    COMMIT_RENAMED = _commit(COMMIT, {"tests/audit_renamed.rs": LINUX_SUITE}, ["tests/audit.rs"], "rename audit")


def tearDownModule():
    _repo_tmp.cleanup()


def gate_log(blocks=None, command=ROOT_CMD, rc=0):
    """A gate log with one root-test section, as the gate harness writes it."""
    lines = ["== step root-test start 2026-09-01T00:10:00Z", "$ " + command]
    for label, n in ROOT_BLOCKS if blocks is None else blocks:
        lines += [
            f"     Running {label} (target/debug/deps/x-0000)",
            "",
            f"running {n} tests",
            f"test result: ok. {n} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out",
            "",
        ]
    lines.append(f"== step root-test rc={rc} end 2026-09-01T00:20:00Z")
    return ("\n".join(lines) + "\n").encode()


def sha(b):
    return hashlib.sha256(b).hexdigest()


def gz_tar(path, entries):
    """entries: list of (TarInfo, bytes or None)."""
    with tarfile.open(path, "w:gz") as tf:
        for info, data in entries:
            if data is not None:
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            else:
                tf.addfile(info)


def reg(name, mode=0o644):
    i = tarfile.TarInfo(name)
    i.type = tarfile.REGTYPE
    i.mode = mode
    return i


def dir_info(name):
    i = tarfile.TarInfo(name)
    i.type = tarfile.DIRTYPE
    i.mode = 0o755
    return i


class Evidence:
    """A complete, valid synthetic evidence set that tests then break."""

    def __init__(self, tmp):
        self.tmp = tmp
        self.exe = b"synthetic sinter executable\n"
        self.files = {
            "harness/run.sh": b"#!/bin/sh\necho synthetic acceptance harness\n",
            "validation/linux-gate.log": gate_log(),
        }
        for label in TARGETS:
            self.files[f"logs/{label}.log"] = (
                f"[{label}] synthetic acceptance log\nsinter {VERSION}\nresult: 43/43 PASS\n"
            ).encode()
        self.artifact_members = None
        self.sanitize = []

    def artifact_bytes(self):
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            d = f"sinter-v{VERSION}-linux-x86_64"
            tf.addfile(dir_info(d))
            info = reg(d + "/sinter", 0o755)
            info.size = len(self.exe)
            tf.addfile(info, io.BytesIO(self.exe))
        return buf.getvalue()

    def manifest(self):
        art = self.artifact_bytes()
        target = lambda label, i: {
            "label": label,
            "os_name": TARGETS[label][0],
            "os_version": TARGETS[label][1],
            "arch": "x86_64",
            "image": f"public-{label}-image-v20260901",
            "started_at": f"2026-09-01T01:{i:02d}:00Z",
            "finished_at": f"2026-09-01T01:{i:02d}:30Z",
            "artifact_sha256": sha(art),
            "executable_sha256": sha(self.exe),
            "version_output": f"sinter {VERSION}",
            "checks": {"total": 43, "passed": 43, "failed": 0, "skipped": 0},
            "verdict": "PASS",
            "log": {"path": f"logs/{label}.log", "sha256": sha(self.files[f"logs/{label}.log"])},
        }
        return {
            "schema": "sinter-acceptance-manifest/1",
            "candidate": {
                "version": VERSION,
                "tag": f"v{VERSION}",
                "source_commit": COMMIT,
                "artifact": {"filename": ARTIFACT_NAME, "sha256": sha(art), "size_bytes": len(art)},
                "executable_sha256": sha(self.exe),
                "build": {
                    "baseline": "Rocky Linux 9.8 x86_64",
                    "rustc": "rustc 1.85.0 (4d91de4e4 2025-02-17)",
                    "cargo": "cargo 1.85.0 (d73d2caf9 2024-12-31)",
                    "max_glibc": "GLIBC_2.34",
                },
            },
            "harness": {
                "name": "synthetic-harness",
                "version": "1",
                "files": [{"path": "harness/run.sh", "sha256": sha(self.files["harness/run.sh"])}],
                "runner": "harness/run.sh <target-label>",
                "operator": "release maintainer",
            },
            "run": {"started_at": "2026-09-01T01:00:00Z", "finished_at": "2026-09-01T02:00:00Z"},
            "linux_validation": {
                "os_name": "Rocky Linux",
                "os_version": "9.8",
                "arch": "x86_64",
                "source_commit": COMMIT,
                "rustc": "rustc 1.85.0 (4d91de4e4 2025-02-17)",
                "cargo": "cargo 1.85.0 (d73d2caf9 2024-12-31)",
                "started_at": "2026-09-01T00:00:00Z",
                "finished_at": "2026-09-01T00:30:00Z",
                "linux_only_suites": list(SUITES),
                "steps": [
                    {"name": n, "command": c, "result": "PASS", "passed": p, "failed": 0, "ignored": 0}
                    for n, c, p in GATE_STEPS
                ],
                "verdict": "PASS",
                "log": {"path": "validation/linux-gate.log", "sha256": sha(self.files["validation/linux-gate.log"])},
            },
            "targets": [target(label, i) for i, label in enumerate(TARGETS)],
            "totals": {"targets": 8, "total": 344, "passed": 344, "failed": 0, "skipped": 0},
            "verdict": "GO",
            "evidence_bundle": BUNDLE_NAME,
            "sanitization": {"allowed_literals": list(self.sanitize)},
        }

    def write(self, mutate_doc=None, mutate_files=None, raw_manifest=None):
        """Write manifest, artifact and bundle dir; return their paths."""
        doc = self.manifest()
        if mutate_doc:
            mutate_doc(doc)
        raw = raw_manifest if raw_manifest is not None else json.dumps(doc, indent=2).encode()
        mpath = os.path.join(self.tmp, f"sinter-v{VERSION}-acceptance-manifest.json")
        with open(mpath, "wb") as f:
            f.write(raw)
        apath = os.path.join(self.tmp, ARTIFACT_NAME)
        with open(apath, "wb") as f:
            f.write(self.artifact_bytes())
        files = dict(self.files)
        files["acceptance-manifest.json"] = raw
        if mutate_files:
            mutate_files(files)
        self.bundle_files = files
        bdir = os.path.join(self.tmp, STEM)
        for rel, data in files.items():
            p = os.path.join(bdir, *rel.split("/"))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(data)
        os.makedirs(bdir, exist_ok=True)
        return mpath, apath, bdir

    def archive(self, extra=None, replace=None):
        """Build the bundle archive from the last written bundle files."""
        entries = [(dir_info(STEM), None)]
        for rel, data in sorted(self.bundle_files.items()):
            entries.append((reg(f"{STEM}/{rel}"), data))
        if replace:
            entries = replace(entries)
        entries += extra or []
        path = os.path.join(self.tmp, BUNDLE_NAME)
        gz_tar(path, entries)
        return path


def run_checker(*args):
    p = subprocess.run(
        [sys.executable, CHECKER, *args, "--repo", REPO],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
        timeout=60,
    )
    return p.returncode, p.stdout, p.stderr


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="sinter-evidence-test-")
        self.tmp = self._tmp.name
        self.ev = Evidence(self.tmp)

    def tearDown(self):
        self._tmp.cleanup()

    def check(self, mutate_doc=None, mutate_files=None, archive=True, sums=False,
              extra=None, replace=None, artifact=None, raw_manifest=None):
        m, a, d = self.ev.write(mutate_doc, mutate_files, raw_manifest)
        args = [m]
        if archive:
            b = self.ev.archive(extra, replace)
            args += ["--bundle-archive", b]
            if sums:
                args += ["--sums", self.write_sums(m, b)]
        else:
            args += ["--bundle", d]
        args += ["--artifact", artifact or a]
        return run_checker(*args)

    def write_sums(self, m, b, override=None):
        with open(m, "rb") as f:
            mh = sha(f.read())
        with open(b, "rb") as f:
            bh = sha(f.read())
        lines = override or [
            f"{mh}  sinter-v{VERSION}-acceptance-manifest.json",
            f"{bh}  {BUNDLE_NAME}",
        ]
        p = os.path.join(self.tmp, f"sinter-v{VERSION}-acceptance-SHA256SUMS")
        with open(p, "w") as f:
            f.write("\n".join(lines) + "\n")
        return p

    def assertPass(self, result):
        rc, out, err = result
        self.assertEqual(rc, 0, err)
        self.assertIn("OK", out)
        self.assertEqual(err, "")

    def assertReject(self, result, *needles):
        rc, out, err = result
        self.assertEqual(rc, 1, f"expected rejection, got rc={rc}\n{out}{err}")
        self.assertNotIn("Traceback", err)
        self.assertTrue(err.startswith("FAIL "), err)
        for n in needles:
            self.assertIn(n, err)


class Positive(Base):
    def test_valid_archive_bundle_with_sums(self):
        self.assertPass(self.check(sums=True))

    def test_valid_directory_bundle(self):
        self.assertPass(self.check(archive=False))

    def test_template_structure(self):
        rc, out, err = run_checker(TEMPLATE, "--template")
        self.assertEqual(rc, 0, err)

    def test_reserved_and_redacted_values_are_not_findings(self):
        self.ev.files["logs/rocky9.log"] += (
            b"docs: https://sinter.fulltrust.co.jp/en/ and https://github.com/x/y\n"
            b"peer 192.0.2.10 / 2001:db8::10 / 127.0.0.1 (documentation ranges)\n"
            b"mail: someone@example.com host: localhost user: root\n"
            b"password: [redacted] token=<redacted>\n"
            b"kernel 5.14.0-570.12.1.el9_6.x86_64 glibc 2.34 at 12:30:45\n"
            b"test engine::apply_is_idempotent ... ok\n"
            b"host key verification ok; running on x86_64; project root ok\n"
        )
        self.assertPass(self.check())

    def test_allowed_literal_clears_reviewed_false_positive(self):
        self.ev.sanitize = ["fixture-host-7"]
        self.ev.files["logs/rocky9.log"] += b"hostname: fixture-host-7\n"
        self.assertPass(self.check())

    def test_synthetic_redaction_fixture_value_can_be_declared(self):
        self.ev.sanitize = ["synthetic-redaction-probe"]
        self.ev.files["harness/run.sh"] += b"password: synthetic-redaction-probe\n"
        self.assertPass(self.check())


class PathContainment(Base):
    def test_original_exploit_empty_bundle_outside_refs(self):
        outside = os.path.join(self.tmp, "outside")
        os.makedirs(outside)
        with open(os.path.join(outside, "t1.log"), "wb") as f:
            f.write(b"x")

        def doc(d):
            d["harness"]["files"][0]["path"] = "../outside/run.sh"
            d["targets"][0]["log"]["path"] = "../outside/t1.log"
        self.assertReject(
            self.check(doc, mutate_files=lambda f: f.clear(), archive=False),
            "leaves the bundle", "empty",
        )

    def test_parent_relative_log(self):
        self.assertReject(self.check(lambda d: d["targets"][0]["log"].update(path="../x.log")), "leaves the bundle")

    def test_absolute_unix_path(self):
        self.assertReject(self.check(lambda d: d["harness"]["files"][0].update(path="/etc/hosts")), "absolute path")

    def test_absolute_windows_path(self):
        self.assertReject(
            self.check(lambda d: d["harness"]["files"][0].update(path="C:\\evidence\\run.sh")),
            "backslash",
        )
        self.assertReject(
            self.check(lambda d: d["harness"]["files"][0].update(path="C:/evidence/run.sh")),
            "absolute path",
        )

    def test_nested_traversal(self):
        self.assertReject(
            self.check(lambda d: d["harness"]["files"][0].update(path="harness/../../outside/run.sh")),
            "leaves the bundle",
        )

    def test_symlink_escape_in_directory_bundle(self):
        m, a, d = self.ev.write()
        outside = os.path.join(self.tmp, "outside.sh")
        with open(outside, "wb") as f:
            f.write(self.ev.files["harness/run.sh"])
        os.remove(os.path.join(d, "harness", "run.sh"))
        os.symlink(outside, os.path.join(d, "harness", "run.sh"))
        self.assertReject(run_checker(m, "--bundle", d, "--artifact", a), "symlink not allowed")

    def test_dangling_symlink(self):
        m, a, d = self.ev.write()
        os.symlink(os.path.join(self.tmp, "does-not-exist"), os.path.join(d, "harness", "extra"))
        self.assertReject(run_checker(m, "--bundle", d, "--artifact", a), "symlink not allowed")

    def test_hardlink_in_directory_bundle(self):
        m, a, d = self.ev.write()
        target = os.path.join(d, "harness", "run.sh")
        os.link(target, os.path.join(self.tmp, "outside-link"))
        self.assertReject(run_checker(m, "--bundle", d, "--artifact", a), "hardlink not allowed")

    def test_fifo_in_directory_bundle(self):
        m, a, d = self.ev.write()
        os.mkfifo(os.path.join(d, "harness", "pipe"))
        self.assertReject(run_checker(m, "--bundle", d, "--artifact", a), "not a regular file")

    def test_directory_referenced_as_file(self):
        def files(f):
            f["harness/sub/inner.sh"] = b"echo synthetic\n"
        def doc(d):
            d["harness"]["files"].append({"path": "harness/sub", "sha256": "0" * 64})
        self.assertReject(self.check(doc, files, archive=False), "is a directory")

    def test_missing_referenced_file(self):
        self.assertReject(self.check(mutate_files=lambda f: f.pop("logs/alma10.log")), "missing from bundle")

    def test_duplicate_and_case_conflicting_paths(self):
        def dup(d):
            d["harness"]["files"].append(dict(d["harness"]["files"][0]))
        self.assertReject(self.check(dup), "duplicate or conflicting path")

        def case(d):
            d["harness"]["files"].append({"path": "harness/RUN.sh", "sha256": "0" * 64})
        self.assertReject(self.check(case), "duplicate or conflicting path")

    def test_unreferenced_hidden_file(self):
        self.assertReject(
            self.check(mutate_files=lambda f: f.update({"harness/.env": b"EXTRA=1\n"})),
            "not referenced by the manifest",
        )

    def test_empty_bundle_directory(self):
        self.assertReject(self.check(mutate_files=lambda f: f.clear(), archive=False), "bundle: empty")


class ArchiveSafety(Base):
    def test_traversal_member(self):
        self.assertReject(self.check(extra=[(reg(f"{STEM}/../evil.sh"), b"x")]), "path traversal member")

    def test_absolute_member(self):
        self.assertReject(self.check(extra=[(reg("/tmp/evil.sh"), b"x")]), "absolute member path")

    def test_symlink_member(self):
        i = tarfile.TarInfo(f"{STEM}/harness/link")
        i.type = tarfile.SYMTYPE
        i.linkname = "/etc/hosts"
        self.assertReject(self.check(extra=[(i, None)]), "symlink/hardlink member")

    def test_hardlink_member(self):
        i = tarfile.TarInfo(f"{STEM}/harness/hard")
        i.type = tarfile.LNKTYPE
        i.linkname = "../../outside"
        self.assertReject(self.check(extra=[(i, None)]), "symlink/hardlink member")

    def test_device_and_fifo_members(self):
        for t in (tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE):
            i = tarfile.TarInfo(f"{STEM}/harness/special")
            i.type = t
            self.assertReject(self.check(extra=[(i, None)]), "special file member")

    def test_member_outside_top_level_directory(self):
        self.assertReject(self.check(extra=[(reg("other/x.log"), b"x")]), "outside the top-level directory")

    def test_duplicate_member(self):
        self.assertReject(
            self.check(extra=[(reg(f"{STEM}/logs/rocky9.log"), b"replaced")]),
            "duplicate or conflicting member",
        )

    def test_setuid_member(self):
        self.assertReject(self.check(extra=[(reg(f"{STEM}/harness/suid", 0o4755), b"x")]), "setuid")

    def test_corrupt_archive_fails_cleanly(self):
        m, a, d = self.ev.write()
        b = os.path.join(self.tmp, BUNDLE_NAME)
        with open(b, "wb") as f:
            f.write(b"\x1f\x8b\x08\x00not really gzip")
        self.assertReject(run_checker(m, "--bundle-archive", b, "--artifact", a), "--bundle-archive")

    def test_wrong_archive_name(self):
        m, a, d = self.ev.write()
        b = self.ev.archive()
        other = os.path.join(self.tmp, "sinter-v9.9.8-acceptance-evidence.tar.gz")
        os.rename(b, other)
        self.assertReject(run_checker(m, "--bundle-archive", other, "--artifact", a), "wrong bundle")


class Integrity(Base):
    def test_modified_log(self):
        self.assertReject(
            self.check(mutate_files=lambda f: f.update({"logs/rocky9.log": b"edited after hashing\n"})),
            "sha256 mismatch",
        )

    def test_modified_harness(self):
        self.assertReject(
            self.check(mutate_files=lambda f: f.update({"harness/run.sh": b"#!/bin/sh\nexit 0\n"})),
            "sha256 mismatch",
        )

    def test_wrong_bundle_manifest_copy(self):
        def files(f):
            f["acceptance-manifest.json"] = f["acceptance-manifest.json"].replace(b'"GO"', b'"GO" ')
        self.assertReject(self.check(mutate_files=files), "not byte-identical")

    def test_manifest_a_with_artifact_b(self):
        m, a, d = self.ev.write()
        b = self.ev.archive()
        self.ev.exe = b"a different synthetic executable\n"
        other_dir = os.path.join(self.tmp, "b")
        os.makedirs(other_dir)
        other = os.path.join(other_dir, ARTIFACT_NAME)
        with open(other, "wb") as f:
            f.write(self.ev.artifact_bytes())
        self.assertReject(run_checker(m, "--bundle-archive", b, "--artifact", other), "do not match")

    def test_duplicate_target(self):
        def doc(d):
            d["targets"].append(copy.deepcopy(d["targets"][0]))
            d["totals"].update(targets=9, total=387, passed=387)
        self.assertReject(self.check(doc), "duplicate ubuntu2404")

    def test_missing_target(self):
        def doc(d):
            d["targets"].pop()
            d["totals"].update(targets=7, total=301, passed=301)
        self.assertReject(
            self.check(doc, mutate_files=lambda f: f.pop("logs/alma10.log")),
            "required target alma10 is missing",
        )

    def test_target_observed_different_artifact(self):
        self.assertReject(
            self.check(lambda d: d["targets"][3].update(artifact_sha256="f" * 64)),
            "artifact_sha256 differs",
        )

    def test_no_go_cannot_pass(self):
        def doc(d):
            d["targets"][0]["checks"].update(passed=42, failed=1)
            d["targets"][0]["verdict"] = "FAIL"
            d["totals"].update(passed=343, failed=1)
            d["verdict"] = "NO-GO"
        self.assertReject(self.check(doc), "NO-GO evidence cannot support a release")

    def test_sums_mismatch(self):
        m, a, d = self.ev.write()
        b = self.ev.archive()
        s = self.write_sums(m, b, override=[
            f"{'0' * 64}  sinter-v{VERSION}-acceptance-manifest.json",
            f"{'0' * 64}  {BUNDLE_NAME}",
        ])
        self.assertReject(run_checker(m, "--bundle-archive", b, "--sums", s, "--artifact", a), "checksum mismatch")

    def test_non_utf8_log(self):
        def files(f):
            f["logs/rocky9.log"] = b"\xff\xfe binary"
        def doc(d):
            d["targets"][2]["log"]["sha256"] = sha(b"\xff\xfe binary")
        self.assertReject(self.check(doc, files), "not UTF-8")

    def test_missing_required_options(self):
        m, a, d = self.ev.write()
        rc, out, err = run_checker(m, "--bundle", d)
        self.assertEqual(rc, 2)
        self.assertNotIn("Traceback", err)


class LinuxGate(Base):
    def test_failed_step_blocks(self):
        self.assertReject(
            self.check(lambda d: d["linux_validation"]["steps"][2].update(result="FAIL", failed=3)),
            "root-test must PASS",
        )

    def test_missing_step_blocks(self):
        self.assertReject(
            self.check(lambda d: d["linux_validation"]["steps"].pop(3)),
            "required step installer-test is missing",
        )

    def test_weakened_command_blocks(self):
        self.assertReject(
            self.check(lambda d: d["linux_validation"]["steps"][2].update(command="cargo test")),
            "command: must be",
        )

    def test_macos_is_not_a_substitute(self):
        self.assertReject(
            self.check(lambda d: d["linux_validation"].update(arch="arm64", os_name="macOS")),
            "macOS or other hosts are not a substitute",
        )

    def test_gate_must_precede_acceptance_and_match_commit(self):
        def doc(d):
            d["linux_validation"]["finished_at"] = "2026-09-01T03:00:00Z"
            d["linux_validation"]["source_commit"] = "f" * 40
        self.assertReject(self.check(doc), "must finish before acceptance", "must equal candidate.source_commit")

    def test_linux_only_suite_absent_from_log(self):
        self.assertReject(
            self.check(lambda d: d["linux_validation"]["linux_only_suites"].append("tests/engine.rs")),
            "tests/engine.rs did not run tests",
        )

    def test_linux_only_suite_compiled_out_is_not_a_run(self):
        # What a macOS run looks like: the suite binary exists but is empty.
        self.ev.files["validation/linux-gate.log"] = (
            "     Running tests/audit.rs (target/debug/deps/x-0000)\n\nrunning 0 tests\n"
            "test result: ok. 0 passed; 0 failed; 0 ignored\n"
            "     Running tests/cli.rs (target/debug/deps/x-0000)\n\nrunning 10 tests\n"
            "test result: ok. 10 passed; 0 failed; 0 ignored\n"
        ).encode()
        self.assertReject(self.check(), "tests/audit.rs did not run tests")

    def test_missing_cargo_version(self):
        self.assertReject(self.check(lambda d: d["candidate"]["build"].pop("cargo")), "candidate.build.cargo: missing")


# Synthetic sensitive values. Each is an obvious fixture; credential shapes
# are assembled at run time.
_B64 = lambda s: base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")
SENSITIVE = {
    "IPv4 address": "peer 10.20.30.40 connected",
    "IPv6 address": "peer fd00:5ec7:0:1::40 connected",
    "hostname": "fetched from web01.fixture-corp.io",
    "internal DNS name": "resolver db01.fixture.internal ok",
    "hostname context": "hostname: fixture-host-7",
    "bare hostname": "artifact built on build-host-7",
    "ssh hostname": "ssh fixture-user@build-host-7 true",
    "bare cloud project": "gcloud project fixture-proj-123456",
    "uname hostname": "Linux fixture-host-7 5.14.0-570.el9.x86_64 #1 SMP",
    "username": "user=fixture-user",
    "uid username": "uid=1001(fixtureuser) gid=1001(fixtureuser)",
    "cloud project id": "project: fixture-proj-123456",
    "cloud resource path": "projects/fixture-proj-123456/zones/z1/instances/i1",
    "home path": "cwd /home/fixtureuser/sinter",
    "macOS home path": "cwd /Users/fixtureuser/sinter",
    "Windows profile path": "cwd C:\\Users\\fixtureuser\\sinter",
    "volume path": "cwd /Volumes/FixtureDisk/sinter",
    "email": "contact fixture.person@fixture-corp.io",
    "credential": "password=" + "fixture" + "-not-a-password",
    "api key": "api_key: " + "fixture" + "KeyValue0000",
    "client secret": "client_secret=" + "fixture" + "SecretValue",
    "private key": "-----BEGIN " + "OPENSSH PRIVATE KEY" + "-----",
    "JWT": _B64('{"alg":"none","fixture":1}') + "." + _B64('{"sub":"fixture"}') + "." + "c2lnbmF0dXJl",
    "authorization": "Authorization: " + "Bearer " + "fixtureTokenValue0000",
    "cookie": "Cookie: " + "session=fixture0000",
    "github token": "gh" + "p_" + "F" * 36,
    "aws key": "AK" + "IA" + "SYNTHETICFIXTURE",
}


class SensitiveData(Base):
    def test_each_category_is_rejected(self):
        for name, line in SENSITIVE.items():
            with self.subTest(name):
                ev = Evidence(self.tmp)
                ev.files["logs/rocky9.log"] += (line + "\n").encode()
                self.ev = ev
                self.assertReject(self.check(), "logs/rocky9.log:4: sensitive content")

    def test_sensitive_value_in_manifest_is_rejected(self):
        self.assertReject(
            self.check(lambda d: d["targets"][0].update(image="projects/fixture-proj-123456/images/x")),
            "sensitive content (cloud resource ID)",
        )

    def test_findings_never_echo_the_value(self):
        self.ev.files["logs/rocky9.log"] += b"peer 10.20.30.40\n"
        rc, out, err = self.check()
        self.assertEqual(rc, 1)
        self.assertNotIn("10.20.30.40", err)

    def test_allowlist_cannot_clear_credentials_or_keys(self):
        secret = "fixture" + "-not-a-password"
        self.ev.sanitize = [secret]
        self.ev.files["logs/rocky9.log"] += ("password=" + secret + "\n").encode()
        self.assertReject(self.check(), "sensitive content (credential)")

    def test_sensitive_bundle_path_is_rejected(self):
        def files(f):
            f["harness/web01.fixture-corp.io/run.sh"] = b"echo synthetic\n"
        def doc(d):
            d["harness"]["files"].append(
                {"path": "harness/web01.fixture-corp.io/run.sh", "sha256": sha(b"echo synthetic\n")}
            )
        self.assertReject(self.check(doc, files), "bundle paths:")


class RootTestEvidence(Base):
    """The gate log must show the full root suite of the candidate commit (F-1).

    The expected harnesses and Linux-only suites come from the fixture
    repository, so a partial run cannot be recorded as the full suite.
    """

    def set_log(self, blocks=None, **kw):
        self.ev.files["validation/linux-gate.log"] = gate_log(blocks, **kw)

    @staticmethod
    def root(d):
        return next(s for s in d["linux_validation"]["steps"] if s["name"] == "root-test")

    @staticmethod
    def at(commit):
        def doc(d):
            d["candidate"]["source_commit"] = commit
            d["linux_validation"]["source_commit"] = commit
        return doc

    def test_full_suite_passes(self):
        self.assertPass(self.check())

    def test_single_suite_log_is_rejected(self):
        # The F-1 exploit: one suite in the log, declared as the only
        # Linux-only suite, and root-test recorded as passed: 1.
        self.set_log([("tests/audit.rs", 1)])

        def doc(d):
            d["linux_validation"]["linux_only_suites"] = ["tests/audit.rs"]
            self.root(d)["passed"] = 1
        self.assertReject(self.check(doc), "unittests src/lib.rs did not run", "missing tests/cli.rs")

    def test_subset_of_harnesses_is_rejected(self):
        self.set_log([b for b in ROOT_BLOCKS if b[0] != "tests/frontends.rs"])
        self.assertReject(self.check(lambda d: self.root(d).update(passed=420)),
                          "tests/frontends.rs did not run")

    def test_subset_of_linux_suites_is_rejected(self):
        self.assertReject(
            self.check(lambda d: d["linux_validation"].update(linux_only_suites=["tests/cli.rs"])),
            "missing tests/audit.rs",
        )

    def test_inflated_count_is_rejected(self):
        self.assertReject(self.check(lambda d: self.root(d).update(passed=901)),
                          "recorded passed=901 but the log shows 900")

    def test_deflated_count_is_rejected(self):
        self.assertReject(self.check(lambda d: self.root(d).update(passed=899)),
                          "recorded passed=899 but the log shows 900")

    def test_missing_linux_suite_in_log_is_rejected(self):
        self.set_log([b for b in ROOT_BLOCKS if b[0] != "tests/cli.rs"])
        self.assertReject(self.check(lambda d: self.root(d).update(passed=890)), "tests/cli.rs did not run")

    def test_unknown_linux_suite_is_rejected(self):
        def doc(d):
            d["linux_validation"]["linux_only_suites"] += ["tests/frontends.rs", "tests/unknown.rs"]
        self.assertReject(self.check(doc), "tests/frontends.rs is not a Linux-only suite",
                          "tests/unknown.rs is not a Linux-only suite")

    def test_duplicate_linux_suite_is_rejected(self):
        self.assertReject(
            self.check(lambda d: d["linux_validation"]["linux_only_suites"].append("tests/cli.rs")),
            "tests/cli.rs is listed twice",
        )

    def test_zero_execution_is_rejected(self):
        self.set_log([(label, 0) for label, _ in ROOT_BLOCKS])
        self.assertReject(self.check(lambda d: self.root(d).update(passed=0)),
                          "a test step must run tests", "Linux-only suite tests/audit.rs ran no tests")

    def test_log_command_mismatch_is_rejected(self):
        self.set_log(command="cargo test --locked --all-targets --all-features --test cli")
        self.assertReject(self.check(), "the section must start with '$ " + ROOT_CMD + "'")

    def test_nonzero_rc_is_rejected(self):
        self.set_log(rc=101)
        self.assertReject(self.check(), "the step exited with rc=101")

    def test_unsectioned_log_is_rejected(self):
        self.ev.files["validation/linux-gate.log"] = gate_log().replace(b"== step root-test", b"== step other")
        self.assertReject(self.check(), "exactly one section")

    def test_unknown_and_duplicate_harness_in_log_are_rejected(self):
        self.set_log(ROOT_BLOCKS + [("tests/other.rs", 0), ("tests/audit.rs", 0)])
        self.assertReject(self.check(), "tests/other.rs is not a test harness of the candidate commit",
                          "tests/audit.rs appears more than once")

    def test_stale_evidence_for_added_suite_is_rejected(self):
        self.assertReject(self.check(self.at(COMMIT_ADDED)), "tests/extra.rs did not run",
                          "missing tests/extra.rs")

    def test_stale_evidence_for_ungated_suite_is_rejected(self):
        self.assertReject(self.check(self.at(COMMIT_UNGATED)), "tests/cli.rs is not a Linux-only suite")

    def test_stale_evidence_for_renamed_suite_is_rejected(self):
        self.assertReject(self.check(self.at(COMMIT_RENAMED)),
                          "tests/audit.rs is not a test harness of the candidate commit",
                          "tests/audit_renamed.rs did not run")

    def test_commit_missing_from_repository_is_rejected(self):
        self.assertReject(self.check(self.at("e" * 40)), "cannot read commit")


if __name__ == "__main__":
    unittest.main()
