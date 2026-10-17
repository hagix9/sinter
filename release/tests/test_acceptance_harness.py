"""Fail-closed tests for release/acceptance-harness against a fake gcloud.

No cloud, no network, no SSH: GCLOUD points at a scripted stand-in that
records every call and answers the driver's remote commands from a scenario
held in environment variables. Every identifier is synthetic.

Run: python3 -m unittest discover -s release/tests
"""
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
HARNESS = os.path.join(os.path.dirname(HERE), "acceptance-harness")
RUN_TARGET = os.path.join(HARNESS, "run-target.sh")
RUN_ALL = os.path.join(HARNESS, "run-all.sh")


def read(path, mode="r"):
    with open(path, mode) as f:
        return f.read()


def write(path, data):
    with open(path, "wb" if isinstance(data, bytes) else "w") as f:
        f.write(data)

VERSION = "9.9.9"
TARNAME = "sinter-v%s-linux-x86_64.tar.gz" % VERSION
RC = "0" * 39 + "1"
EXE = "e" * 64

# The fake gcloud. Remote state lives in FAKE_DIR; the scenario knobs are:
#   FAKE_BOOT_DISK   boot disk name returned by `instances describe` ("" = none)
#   FAKE_IMAGE / FAKE_IMAGE_ID   the disk's sourceImage / sourceImageId
#   FAKE_PREP        what the prep step prints ("0", "1", "stale", "missing")
#   FAKE_MAKECACHE   the makecache step's output line
#   FAKE_REMOTE_SHA  "actual" (default) or a value to report for raw.log
#   FAKE_ACCESS_CONFIG / FAKE_ADD_AC_FAIL   external-IP state / add failure
FAKE_GCLOUD = textwrap.dedent(r'''
    #!/usr/bin/env python3
    import datetime, hashlib, os, shlex, shutil, sys
    d = os.environ["FAKE_DIR"]
    args = sys.argv[1:]
    with open(os.path.join(d, "calls.log"), "a") as f:
        f.write(" ".join(args) + "\n")
    def opt(name):
        for a in args:
            if a.startswith(name + "="):
                return a.split("=", 1)[1]
        return ""
    def status():
        p = os.path.join(d, "status")
        return open(p).read() if os.path.exists(p) else "TERMINATED"
    raw = os.path.join(d, "raw.log")
    sub = args[:3]
    if sub == ["compute", "instances", "describe"]:
        fmt = opt("--format")
        if fmt == "get(status)":
            print(status())
        elif "disks[0]" in fmt:
            print(os.environ.get("FAKE_BOOT_DISK", "boot-disk-fixture"))
        elif "accessConfigs" in fmt:
            print(os.environ.get("FAKE_ACCESS_CONFIG", "ONE_TO_ONE_NAT"))
        sys.exit(0)
    if sub == ["compute", "disks", "describe"]:
        fmt = opt("--format")
        if "sourceImageId" in fmt:
            print(os.environ.get("FAKE_IMAGE_ID", "1234567890123456789"))
        else:
            print(os.environ.get("FAKE_IMAGE", "fixture-image-v1"))
        sys.exit(0)
    if sub == ["compute", "instances", "add-access-config"]:
        sys.exit(1 if os.environ.get("FAKE_ADD_AC_FAIL") else 0)
    if sub == ["compute", "instances", "start"]:
        open(os.path.join(d, "status"), "w").write("RUNNING"); sys.exit(0)
    if sub == ["compute", "instances", "stop"]:
        open(os.path.join(d, "status"), "w").write("TERMINATED"); sys.exit(0)
    if args[:2] == ["compute", "scp"]:
        paths = [a for a in args[2:] if not a.startswith("--")]
        src, dst = paths[0], paths[1]
        if ":" in src:                      # download: the raw log
            if not os.path.exists(raw):
                sys.exit(1)
            shutil.copy(raw, dst)
        sys.exit(0)
    if args[:2] == ["compute", "ssh"]:
        cmd = args[args.index("--command") + 1]
        if cmd.startswith("cat > "):
            sys.stdin.read(); sys.exit(0)
        if status() != "RUNNING":
            sys.exit(255)
        def has(s): return s in cmd
        if cmd == "echo SSH_READY": print("SSH_READY")
        elif has("sha256sum /tmp/sinter-v"): print(os.environ["FAKE_ART_SHA"])
        elif has("target-prep.sh"): print(os.environ.get("FAKE_PREP", "0"))
        elif has("makecache"): print(os.environ.get("FAKE_MAKECACHE", "MAKECACHE_RC=0"))
        elif has("unshare -m"): print("UNSHARE_OK")
        elif has("-L /var/tmp/sinter-acceptance"): print("DIR")
        elif has("sudo mkdir -m 700"): print("MKDIR_OK")
        elif has("pgrep"): print("CLEAR")
        elif has("test -f /tmp/acceptance.rc && echo"): print("CLEAR")
        elif has("setsid"):
            now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            ids = [l.strip() for l in open(os.environ["FAKE_IDS"]) if l.strip()]
            label = shlex.split(cmd)[5]
            body = ["== acceptance start %s label=%s" % (now, label)]
            body += ["== check %s ok" % i for i in ids]
            body += ["== acceptance end %s passed=%d failed=0 skipped=0" % (now, len(ids))]
            open(raw, "w").write("\n".join(body) + "\n")
            open(os.path.join(d, "acceptance.rc"), "w").write("0")
            print("launched")
        elif cmd == "test -f /tmp/acceptance.rc":
            sys.exit(0 if os.path.exists(os.path.join(d, "acceptance.rc")) else 1)
        elif has("cat /tmp/acceptance.rc"): print(open(os.path.join(d, "acceptance.rc")).read())
        elif has("sha256sum") and has("raw.log"):
            want = os.environ.get("FAKE_REMOTE_SHA", "actual")
            if want == "actual" and os.path.exists(raw):
                print(hashlib.sha256(open(raw, "rb").read()).hexdigest())
            elif want != "actual":
                print(want)
        elif has("stat -c"): print("100 1700000000 42")
        elif has("sudo cat") and has("raw.log"):
            sys.stdout.write(open(raw).read())
        elif has("remote-cleanup.sh"):
            print("STATE=OKDIR\nTMP_RC=0\nDIR_RC=0\nEXISTS=no")
        sys.exit(0)
    sys.exit(0)
''').lstrip()


class HarnessCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.fake = os.path.join(self.dir, "fake")
        os.mkdir(self.fake)
        self.gcloud = os.path.join(self.dir, "gcloud")
        write(self.gcloud, FAKE_GCLOUD)
        os.chmod(self.gcloud, os.stat(self.gcloud).st_mode | stat.S_IEXEC)
        self.art = os.path.join(self.dir, TARNAME)
        write(self.art, b"synthetic release tarball\n")
        self.art_sha = hashlib.sha256(read(self.art, "rb")).hexdigest()
        self.out = os.path.join(self.dir, "out")

    def tearDown(self):
        self.tmp.cleanup()

    def env(self, **over):
        e = {k: v for k, v in os.environ.items() if not k.startswith("SINTER_")}
        e.update({
            "GCLOUD": self.gcloud,
            "FAKE_DIR": self.fake,
            "FAKE_ART_SHA": self.art_sha,
            "FAKE_IDS": os.path.join(HARNESS, "expected-check-ids.txt"),
            "SINTER_PROJECT": "fixture-project",
            "SINTER_ZONE": "fixture-zone-a",
            "SINTER_ARTIFACT": self.art,
            "SINTER_RC_COMMIT": RC,
            "SINTER_EXP_ART": self.art_sha,
            "SINTER_EXP_EXE": EXE,
            "SINTER_EXP_VER": "sinter %s" % VERSION,
            "SINTER_SSH_WAIT_TRIES": "1",
            "SINTER_UPLOAD_TRIES": "1",
            "SINTER_ACCEPT_POLL_TRIES": "1",
            "SINTER_ACCEPT_POLL_INTERVAL": "0",
        })
        for k, v in over.items():
            if v is None:
                e.pop(k, None)
            else:
                e[k] = v
        return e

    def run_target(self, run_id="fixture-run-1", vm="fixture-vm", label="rocky10", need_ip="no", **over):
        p = subprocess.run(
            ["bash", RUN_TARGET, vm, label, self.out, need_ip, "yes", run_id],
            env=self.env(**over), capture_output=True, text=True, timeout=120)
        self.run_dir = os.path.join(self.out, "runs", run_id)
        return p

    def reset_fake(self):
        for f in ("calls.log", "status", "raw.log", "acceptance.rc"):
            p = os.path.join(self.fake, f)
            if os.path.exists(p):
                os.remove(p)

    def calls(self):
        p = os.path.join(self.fake, "calls.log")
        return read(p).splitlines() if os.path.exists(p) else []

    def meta(self):
        return json.loads(read(os.path.join(self.run_dir, "run.json")))

    def driver_log(self):
        return read(os.path.join(self.run_dir, "driver.log"))


class RequiredConfiguration(HarnessCase):
    def test_each_missing_value_stops_before_any_cloud_call(self):
        for v in ["SINTER_PROJECT", "SINTER_ZONE", "SINTER_ARTIFACT", "SINTER_RC_COMMIT",
                  "SINTER_EXP_ART", "SINTER_EXP_EXE", "SINTER_EXP_VER"]:
            with self.subTest(missing=v):
                p = self.run_target(**{v: None})
                self.assertEqual(p.returncode, 64, p.stderr)
                self.assertIn(v, p.stderr)
                self.assertEqual(self.calls(), [])

    def test_malformed_values_stop_before_any_cloud_call(self):
        bad = {
            "SINTER_RC_COMMIT": "abc123",
            "SINTER_EXP_ART": "Z" * 64,
            "SINTER_EXP_EXE": "e" * 63,
            "SINTER_ARTIFACT": os.path.join(self.dir, "renamed.tar.gz"),
            "SINTER_EXP_VER": "1.5.0; reboot",
        }
        for k, v in bad.items():
            with self.subTest(field=k):
                p = self.run_target(**{k: v})
                self.assertEqual(p.returncode, 64, p.stderr)
                self.assertEqual(self.calls(), [])

    def test_unsafe_instance_name_or_label_stops_before_any_cloud_call(self):
        for kw in [{"vm": "vm'; reboot; '"}, {"label": "rocky10 x"}, {"vm": ""}]:
            with self.subTest(**kw):
                p = self.run_target(**kw)
                self.assertEqual(p.returncode, 64, p.stderr)
                self.assertEqual(self.calls(), [])

    def test_local_artifact_hash_mismatch_never_starts_the_instance(self):
        p = self.run_target(SINTER_EXP_ART="a" * 64)
        self.assertEqual(p.returncode, 64)
        self.assertIn("LOCAL ARTIFACT SHA-256 MISMATCH", p.stderr)
        self.assertEqual(self.calls(), [])

    def test_run_all_requires_specs(self):
        p = subprocess.run(["bash", RUN_ALL, self.out], env=self.env(),
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 64)
        self.assertIn("SINTER_SPECS", p.stderr)
        self.assertEqual(self.calls(), [])

    def test_run_all_rejects_malformed_specs(self):
        p = subprocess.run(["bash", RUN_ALL, self.out],
                           env=self.env(SINTER_SPECS="vm;rm -rf /:rocky10:no:no"),
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 64)
        self.assertEqual(self.calls(), [])


class StopConditions(HarnessCase):
    def assert_stopped(self, verdict):
        self.assertEqual(read(os.path.join(self.run_dir, "result")).strip(), verdict)
        self.assertEqual(self.meta()["verdict"], verdict)
        # The instance is stopped on every non-PASS path.
        self.assertTrue(any(c.startswith("compute instances stop fixture-vm") for c in self.calls()))
        self.assertEqual(read(os.path.join(self.fake, "status")), "TERMINATED")

    def test_missing_image_provenance_is_an_error_before_start(self):
        p = self.run_target(FAKE_BOOT_DISK="")
        self.assertEqual(p.returncode, 14)
        self.assert_stopped("ERROR")
        self.assertFalse(any(c.startswith("compute instances start") for c in self.calls()))

    def test_missing_or_non_numeric_image_id_is_an_error(self):
        for value in ["", "abc", "12a"]:
            with self.subTest(image_id=value):
                self.reset_fake()
                p = self.run_target(run_id="fixture-img-%s" % (value or "empty"), FAKE_IMAGE_ID=value)
                self.assertEqual(p.returncode, 14)
                self.assert_stopped("ERROR")

    def test_failed_external_ip_addition_stops_the_run(self):
        p = self.run_target(need_ip="yes", FAKE_ACCESS_CONFIG="", FAKE_ADD_AC_FAIL="1")
        self.assertEqual(p.returncode, 16)
        self.assert_stopped("ERROR")
        self.assertFalse(any(c.startswith("compute instances start") for c in self.calls()))

    def test_failed_makecache_stops_the_run(self):
        p = self.run_target(FAKE_MAKECACHE="MAKECACHE_RC=1")
        self.assertEqual(p.returncode, 15)
        self.assert_stopped("ERROR")
        self.assertIn("dnf makecache failed", self.driver_log())
        self.assertFalse(any("setsid" in c for c in self.calls()))

    def test_empty_makecache_answer_stops_the_run(self):
        p = self.run_target(FAKE_MAKECACHE="")
        self.assertEqual(p.returncode, 15)
        self.assert_stopped("ERROR")

    def test_stale_missing_or_failed_prep_rc_stops_the_run(self):
        for answer in ["stale", "missing", "1", ""]:
            with self.subTest(prep=answer):
                self.reset_fake()
                p = self.run_target(run_id="fixture-prep-%s" % (answer or "empty"), FAKE_PREP=answer)
                self.assertEqual(p.returncode, 7)
                self.assert_stopped("ERROR")

    def test_prep_removes_a_previous_rc_before_running(self):
        self.run_target()
        prep = [c for c in self.calls() if "target-prep.sh" in c and "--command" in c]
        self.assertEqual(len(prep), 1)
        cmd = prep[0]
        self.assertLess(cmd.index("rm -f /tmp/prep.rc"), cmd.index("bash /tmp/target-prep.sh"))

    def test_raw_log_hash_mismatch_stops_the_run(self):
        p = self.run_target(FAKE_REMOTE_SHA="b" * 64)
        self.assertEqual(p.returncode, 1)
        self.assert_stopped("RAW_SHA_MISMATCH")
        self.assertIn("RAW SHA MISMATCH", self.driver_log())

    def test_unavailable_remote_hash_stops_the_run(self):
        p = self.run_target(FAKE_REMOTE_SHA="")
        self.assertEqual(p.returncode, 1)
        self.assert_stopped("RAW_SHA_MISMATCH")


class HappyPath(HarnessCase):
    def test_verified_pass_records_image_provenance_and_hashes(self):
        p = self.run_target()
        log = self.driver_log()
        self.assertEqual(p.returncode, 0, log)
        m = self.meta()
        self.assertEqual(m["verdict"], "PASS")
        self.assertEqual(m["source_image"], "fixture-image-v1")
        self.assertEqual(m["source_image_id"], "1234567890123456789")
        self.assertEqual(m["rc_commit"], RC)
        self.assertEqual(m["artifact_sha256"], self.art_sha)
        self.assertEqual(m["raw_log_sha256"], m["remote_raw_sha256"])
        self.assertTrue(m["cleanup_ok"])
        self.assertEqual(read(os.path.join(self.fake, "status")), "TERMINATED")
        # Every cloud call carries the configured project/zone, nothing else.
        for c in self.calls():
            if c.startswith("compute "):
                self.assertIn("--project=fixture-project", c)
                self.assertIn("--zone=fixture-zone-a", c)
        # Script provenance uses the current file names.
        sums = read(os.path.join(self.run_dir, "scripts", "SHA256SUMS"))
        self.assertIn("run-target.sh", sums)
        self.assertNotIn("fixed", sums)

    def test_a_used_run_directory_is_never_reused(self):
        self.assertEqual(self.run_target().returncode, 0)
        p = self.run_target()
        self.assertEqual(p.returncode, 65)


LABELS = ["ubuntu2404", "ubuntu2604", "rocky9", "rocky10", "rhel9", "rhel10", "alma9", "alma10"]


class CollectorAndApproval(HarnessCase):
    COLLECT = os.path.join(HARNESS, "collect-evidence.py")
    APPROVE = os.path.join(HARNESS, "approve.py")

    def collect(self, *extra, **over):
        p = subprocess.run([sys.executable, self.COLLECT, self.out, *extra], env=self.env(**over),
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr)
        return p.stdout

    def verdict(self, text):
        return [l for l in text.splitlines() if l.startswith("overall verdict:")][0].split(": ", 1)[1]

    def run_matrix(self, labels=LABELS):
        for i, lb in enumerate(labels):
            self.reset_fake()
            self.assertEqual(self.run_target(run_id="fixture-%s" % lb, vm="fixture-vm-%d" % i,
                                             label=lb).returncode, 0, lb)

    def approve(self, key_text="fixture-approval-key\n"):
        key = os.path.join(self.dir, "approval.key")
        write(key, key_text)
        appr = os.path.join(self.dir, "approval.txt")
        p = subprocess.run([sys.executable, self.APPROVE, self.out, "--key", key,
                            "--owner", "fixture-owner", "--out", appr],
                           env=self.env(), capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        return key, appr

    def test_collector_and_approve_require_release_identity(self):
        os.makedirs(os.path.join(self.out, "runs"))
        key = os.path.join(self.dir, "key")
        write(key, "fixture-key\n")
        cases = [
            [sys.executable, self.COLLECT, self.out],
            [sys.executable, self.APPROVE, self.out,
             "--key", key, "--owner", "fixture-owner", "--out", os.path.join(self.dir, "a.txt")],
        ]
        for argv in cases:
            for over in [{"SINTER_RC_COMMIT": None}, {"SINTER_EXP_ART": None},
                         {"SINTER_RC_COMMIT": "1234"}]:
                with self.subTest(script=os.path.basename(argv[1]), env=over):
                    p = subprocess.run(argv, env=self.env(**over), capture_output=True,
                                       text=True, timeout=60)
                    self.assertEqual(p.returncode, 64, p.stderr)

    def test_matrix_cannot_be_narrowed_from_the_environment(self):
        self.run_matrix(["rocky10"])
        key, appr = self.approve()
        text = self.collect("--approval-key", key, "--owner-approval", appr, SINTER_LABELS="rocky10")
        self.assertEqual(self.verdict(text), "NO-GO")
        self.assertIn("rhel9: no accepted PASS evidence", text)

    def test_go_needs_all_eight_labels_and_a_valid_signed_approval(self):
        self.run_matrix()
        self.assertEqual(self.verdict(self.collect()), "PENDING_OWNER_APPROVAL")
        key, appr = self.approve()
        self.assertEqual(self.verdict(self.collect("--approval-key", key, "--owner-approval", appr)), "GO")
        # wrong key, tampered approval, approval for another RC
        other = os.path.join(self.dir, "other.key")
        write(other, "another-fixture-key\n")
        self.assertNotEqual(self.verdict(self.collect("--approval-key", other, "--owner-approval", appr)), "GO")
        tampered = os.path.join(self.dir, "tampered.txt")
        original = read(appr)
        self.assertIn("owner: fixture-owner\n", original)
        write(tampered, original.replace("owner: fixture-owner\n", "owner: someone-else\n"))
        self.assertNotEqual(self.verdict(self.collect("--approval-key", key, "--owner-approval", tampered)), "GO")
        self.assertEqual(self.verdict(self.collect("--approval-key", key, "--owner-approval", appr,
                                                   SINTER_RC_COMMIT="2" * 40)), "NO-GO")

    def test_pass_without_image_provenance_or_server_hash_is_rejected(self):
        self.run_matrix(["rocky10"])
        meta_path = os.path.join(self.out, "runs", "fixture-rocky10", "run.json")
        original = read(meta_path)
        for field in ["source_image", "source_image_id", "remote_raw_sha256"]:
            with self.subTest(field=field):
                m = json.loads(original)
                m[field] = ""
                write(meta_path, json.dumps(m))
                text = self.collect()
                self.assertTrue(any(l.strip().startswith("- rocky10:") and
                                    ("provenance" in l or "server-side" in l)
                                    for l in text.splitlines()), text)
        write(meta_path, original)
        self.assertFalse(any(l.strip().startswith("- rocky10:") for l in self.collect().splitlines()))


class Sanitizer(HarnessCase):
    def sanitize(self, text, patterns=None, **over):
        log = os.path.join(self.dir, "raw.txt")
        self.sanitized = os.path.join(self.dir, "sanitized.log")
        write(log, text)
        over.setdefault("SINTER_SPECS", "fixture-vm-9:rocky10:no:no\nrocky9:rocky9:no:no")
        env = self.env(**over)
        if patterns is not None:
            pf = os.path.join(self.dir, "patterns.tsv")
            write(pf, patterns)
            env["SINTER_SANITIZE_PATTERNS"] = pf
        return subprocess.run([sys.executable, os.path.join(HARNESS, "sanitize.py"), "rocky10",
                               log, self.sanitized],
                              env=env, capture_output=True, text=True, timeout=60)

    def test_without_the_runs_identifiers_nothing_is_written(self):
        for var in ["SINTER_PROJECT", "SINTER_ZONE", "SINTER_SPECS"]:
            with self.subTest(missing=var):
                p = self.sanitize("fixture-project fixture-vm-9\n", **{var: None})
                self.assertEqual(p.returncode, 2)
                self.assertFalse(os.path.exists(self.sanitized))

    def test_malformed_patterns_fail_closed(self):
        for pat in ["no-tab-here\n", "\tempty-regex\n"]:
            with self.subTest(patterns=pat):
                p = self.sanitize("x\n", pat)
                self.assertEqual(p.returncode, 2)
                self.assertFalse(os.path.exists(self.sanitized))

    def test_run_identifiers_and_generic_values_are_masked(self):
        text = ("ssh: connect to host fixture-vm-9 port 22 in fixture-project\n"
                "zone fixture-zone-a; label rocky9 stays\n"
                "path /home/fixtureuser/x /Users/fixtureuser/y /Volumes/Fixture Disk/z\n"
                "from 192.0.2.10 and 2001:db8::7, at 12:34:56, loopback ::1\n")
        p = self.sanitize(text, "fixture-extra-[0-9]+\t<extra>\n")
        self.assertEqual(p.returncode, 0, p.stderr)
        out = read(self.sanitized)
        for leaked in ["fixture-project", "fixture-vm-9", "fixture-zone-a", "fixtureuser",
                       "Fixture", "Disk", "192.0.2.10", "2001:db8::7"]:
            self.assertNotIn(leaked, out)
        for kept in ["label rocky9 stays", "12:34:56", "::1", "<target>", "<project>", "<zone>"]:
            self.assertIn(kept, out)


if __name__ == "__main__":
    unittest.main()
