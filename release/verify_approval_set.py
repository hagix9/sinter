#!/usr/bin/env python3
"""Verify an Owner approval set (schema sinter-approval-set/2 or /3).

RELEASE.md step 13. This complements release/check_acceptance_manifest.py; it
does not replace it. The checker proves the three acceptance assets are
self-consistent; this verifier proves the approval set is exactly the set the
Owner approves, that its parts agree with each other, with the release
candidate (commit, tree, version, artifact) and, when given, with the recorded
evidence. Every check fails closed: a missing, extra, duplicated, unreadable
or inconsistent part makes the set invalid.

  A  structure: regular files only (no symlinks, hard links, special files or
     empty directories); APPROVAL-SET.sha256 equals the canonical list
     recomputed from the files
  B  exactly the required members (the three acceptance assets named after
     the version, the collector record, the META file)
  C  APPROVAL-SET-META.json matches the manifest's candidate identity; the tag
     is v<version>; --expect-rc / --expect-version, when given, match
  D  the acceptance SHA256SUMS lists exactly manifest + bundle, hashes match
  E  the bundle's manifest copy is byte-identical; harness/PROVENANCE.json
     agrees with the manifest, the bundle, the runtime record and the
     collector record; every bundled harness file is the executed bytes
     (verbatim); the collector is the runtime-record collector and is not
     bundled as a harness file
  T  bundle tar headers: one top-level directory, regular files and
     directories only, root:root uid/gid 0, no pax headers
  F  collector-record/SHA256SUMS lists exactly the record files and verifies
  G  every collector run is recorded in order; earlier runs are never GO; the
     last run is PENDING_OWNER_APPROVAL with no problems and one PASS row for
     each of the eight labels; one evidence_digest across the last run,
     META and PROVENANCE
  H  (--rc-repo) rc_commit exists, rc_tree is its tree, its Cargo.toml has the
     version, every harness file's source_path at rc_commit is the executed
     bytes, and the collector is release/acceptance-harness/collect-evidence.py
  K  every bundle log's end line equals the manifest counts; (--gate-log) the
     bundle gate log equals the recorded step-4 log
  I  (--evidence) INDEX.tsv lists exactly the recorded runs, one per label,
     and every run a tally saw is still recorded; the RC collector (run only
     when it equals the recorded one, with a minimal environment) reproduces
     the last run's output, summary and verdict; RC sanitize.py reproduces every bundle log from the recorded raw
     log (it needs SINTER_PROJECT, SINTER_ZONE and SINTER_SPECS of the run in
     the environment, plus SINTER_SANITIZE_PATTERNS if the run used one);
     exactly one recorded run per label; every run carries
     the runtime record
  M  (--evidence) every manifest target field equals the recorded value
  R  (--artifact) the tarball has the recorded name, size and SHA-256
  J  (--checker, needs --artifact) the official checker passes in full mode

  D  (schema /3, needs --rc-repo; v1.15.0, docs/design/v1.15.0-release-and-
     acceptance.md §4.3) the docs commit D: META docs_commit and docs_tree are
     full ids; D is a commit in --rc-repo with exactly one parent, rc_commit;
     its tree is docs_tree; docs-commit/D.patch is `git format-patch -1 D` of
     D and, applied to rc_tree in a private index, reproduces docs_tree; every
     path D changes is in the docs allow-list; D holds
     release/evidence/v<version>/acceptance-manifest.json byte-identical to
     the approved manifest. Any change of D changes the set digest, so an
     earlier approval never covers it. Recovery (§4.5, main moved before
     17b): META docs_base names a merge commit with exactly two parents, one
     of them rc_commit, whose tree is the clean merge of its parents (git
     merge-tree); D's only parent is then docs_base, the patch applies to
     docs_base's tree and the allow-list is checked against docs_base.

Exit: 0  set valid AND its digest equals --approved-digest
      3  set valid, no approved digest given: PENDING_OWNER_APPROVAL (never GO)
      1  set invalid, or its digest differs from --approved-digest
      2  usage error
"""
import argparse
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

sys.dont_write_bytecode = True  # keep the evidence directories free of caches

SCHEMA = "sinter-approval-set/2"
SCHEMA3 = "sinter-approval-set/3"
DOCS_PATCH = "docs-commit/D.patch"
LIST = "APPROVAL-SET.sha256"
META = "APPROVAL-SET-META.json"
CR = "collector-record/"
LABELS = ["ubuntu2404", "ubuntu2604", "rocky9", "rocky10", "rhel9", "rhel10", "alma9", "alma10"]
ALL_LABELS = list(LABELS)


# The acceptance end line. Harnesses up to v1.14 end it at `skipped=<n>`; the
# v1.15.0 harness always appends ` not_applicable=<n>` (DESIGN §47.3). Both
# forms are read by the one pattern below, with no trailing text allowed, so
# checks G, K and M cannot disagree about what an end line is.
_END_COUNTS = r"passed=(\d+) failed=(\d+) skipped=(\d+)(?: not_applicable=(\d+))?"
END_LINE_RE = re.compile(r"(?m)^== acceptance end \S+ " + _END_COUNTS + r"$")
# A PASS row of collect.txt: every count but `passed` and `not_applicable`
# must be zero.
G_ROW_RE = re.compile(r"^[a-z0-9]+\t\S+\tPASS\tPASS\tyes\tyes\t"
                      r"== acceptance end \S+ passed=\d+ failed=0 skipped=0(?: not_applicable=\d+)?$")


def end_line_checks(groups):
    """The manifest `checks` object one end line stands for.

    An end line without the field stands for the four-key object, one with
    the field for the five-key object whose total includes it. The two are
    never interchangeable: a manifest that adds or drops `not_applicable`
    against its raw log does not match.
    """
    p_, f_, s_ = (int(x) for x in groups[:3])
    if groups[3] == "":
        return {"total": p_ + f_ + s_, "passed": p_, "failed": f_, "skipped": s_}
    n_ = int(groups[3])
    return {"total": p_ + f_ + s_ + n_, "passed": p_, "failed": f_, "skipped": s_, "not_applicable": n_}


def docs_allowed(path, version):
    """The paths the post-publish docs commit D may change (§4.3)."""
    return (path.startswith("docs-site/") or path in ("README.md", "README.ja.md",
            ".devcontainer/install-sinter.sh", ".github/workflows/start.yml",
            f"release/evidence/v{version}/acceptance-manifest.json")
            or re.fullmatch(r"examples/start/README[^/]*\.md", path) is not None)
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
VERSION = re.compile(r"^\d+\.\d+\.\d+$")
RUN_ID = re.compile(r"^\d{2}$")
HARNESS_DIR = "release/acceptance-harness/"
# Post-acceptance tools and helpers that do not run in steps 7-9: the only
# runtime-record files that may be absent from the bundle.
MAY_BE_NOT_INCLUDED = {"collect-evidence.py", "finalize-verdict.sh", "derive-expected-checks.sh"}
SAFE_MEMBER = re.compile(r"^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$")


class Fail(Exception):
    pass


def H(b):
    return hashlib.sha256(b).hexdigest()


def rd(root, rel):
    with open(os.path.join(root, rel), "rb") as f:
        return f.read()


def last(text, prefix):
    val = None
    for line in text.splitlines():
        if line.startswith(prefix):
            val = line[len(prefix):].strip()
    return val


def parse_sums(text, where):
    out = {}
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(r"^([0-9a-f]{64})  (\S.*)$", line)
        if not m:
            raise Fail(f"{where}:{i}: malformed line")
        if m.group(2) in out:
            raise Fail(f"{where}:{i}: duplicate entry {m.group(2)}")
        out[m.group(2)] = m.group(1)
    return out


def git(repo, *args):
    p = subprocess.run(["git", "-C", repo, *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.stdout if p.returncode == 0 else None


class V:
    def __init__(self):
        self.errors = []
        self.passed = []

    def ok(self, cond, label, why=""):
        if cond:
            self.passed.append(label)
        else:
            self.errors.append(f"{label}: {why}" if why else label)
        return bool(cond)


def walk_members(root):
    files = []

    def onerror(e):
        raise Fail(f"A: unreadable directory in approval set: {e}")

    for d, dirs, names in os.walk(root, followlinks=False, onerror=onerror):
        if d != root and not dirs and not names:
            raise Fail(f"A: empty directory in approval set: {os.path.relpath(d, root)}")
        for n in list(dirs) + names:
            p = os.path.join(d, n)
            st = os.lstat(p)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            if stat.S_ISLNK(st.st_mode):
                raise Fail(f"A: symlink in approval set: {rel}")
            if n in names:
                if not stat.S_ISREG(st.st_mode):
                    raise Fail(f"A: not a regular file: {rel}")
                if st.st_nlink != 1:
                    raise Fail(f"A: hard-linked file: {rel}")
                files.append(rel)
            elif not stat.S_ISDIR(st.st_mode):
                raise Fail(f"A: special file: {rel}")
    return files


def verify(a):
    v = V()
    root = a.set
    files = walk_members(root)
    # ---- A: canonical list ----------------------------------------------------
    if LIST not in files:
        raise Fail(f"A: {LIST} missing")
    members = sorted((f for f in files if f != LIST), key=lambda s: s.encode("utf-8"))
    canon = "".join(f"{H(rd(root, p))}  {p}\n" for p in members).encode("utf-8")
    listed = rd(root, LIST)
    if listed != canon:
        lm = parse_sums(listed.decode("utf-8"), LIST)
        cm = parse_sums(canon.decode("utf-8"), "recomputed")
        detail = (f"missing={sorted(set(lm) - set(cm))} unlisted={sorted(set(cm) - set(lm))} "
                  f"changed={sorted(k for k in set(lm) & set(cm) if lm[k] != cm[k])}")
        v.ok(False, "A canonical member list", detail if lm != cm else "same entries, non-canonical bytes")
    else:
        v.ok(True, "A canonical member list")
    digest = H(listed)
    # ---- B: required members --------------------------------------------------
    if META not in members:
        raise Fail(f"B: {META} missing")
    meta = json.loads(rd(root, META))
    if meta.get("schema") not in (SCHEMA, SCHEMA3):
        raise Fail(f"C: META schema is not {SCHEMA} or {SCHEMA3}")
    v3 = meta.get("schema") == SCHEMA3
    if v3 and (not HEX40.match(str(meta.get("docs_commit", ""))) or not HEX40.match(str(meta.get("docs_tree", "")))):
        raise Fail("C: META docs_commit / docs_tree are not full 40-hex ids")
    if "docs_base" in meta and (not v3 or not HEX40.match(str(meta.get("docs_base", "")))):
        raise Fail("C: META docs_base is only allowed in a /3 set, as a full 40-hex id")
    ver = meta.get("version")
    if not isinstance(ver, str) or not VERSION.match(ver):
        raise Fail("C: META version is not X.Y.Z")
    # rc_commit and rc_tree reach git command lines below: refuse anything
    # but full ids before they are used anywhere.
    if not HEX40.match(str(meta.get("rc_commit", ""))) or not HEX40.match(str(meta.get("rc_tree", ""))):
        raise Fail("C: META rc_commit / rc_tree are not full 40-hex ids")
    assets = [f"sinter-v{ver}-acceptance-manifest.json", f"sinter-v{ver}-acceptance-evidence.tar.gz",
              f"sinter-v{ver}-acceptance-SHA256SUMS"]
    v.ok(meta.get("acceptance_assets") == assets, "B acceptance assets are the three named after the version",
         str(meta.get("acceptance_assets")))
    col = meta.get("collector")
    if not isinstance(col, dict) or not isinstance(col.get("runs"), list) or not col["runs"]:
        raise Fail("B: META collector.runs missing or empty")
    run_ids = [r.get("id") for r in col["runs"]]
    if run_ids != [f"{i:02d}" for i in range(1, len(run_ids) + 1)]:
        raise Fail(f"B: collector runs must be numbered 01.. in order, got {run_ids}")
    rec_files = {"collect-evidence.py", "runtime-scripts-SHA256SUMS"}
    for i, rid in enumerate(run_ids, 1):
        rec_files |= {f"runs/{rid}/collect.txt", f"runs/{rid}/summary.txt"}
        if i == len(run_ids):
            rec_files.add(f"runs/{rid}/VERDICT.txt")
    want = {META} | {"acceptance/" + x for x in assets} | {CR + x for x in rec_files} | {CR + "SHA256SUMS"}
    if v3:
        want.add(DOCS_PATCH)
    if set(members) != want:
        raise Fail(f"B: member set differs: missing={sorted(want - set(members))} "
                   f"extra={sorted(set(members) - want)}")
    v.ok(True, "B exactly the required members")
    man_name, bun_name, sums_name = assets
    man_raw = rd(root, "acceptance/" + man_name)
    bun_raw = rd(root, "acceptance/" + bun_name)
    man = json.loads(man_raw)
    c = man["candidate"]
    # The labels this acceptance requires: the eight (schema /1, and /2 full
    # scope) or the approved patch set (/2 patch scope).
    global LABELS
    LABELS = ALL_LABELS
    if man.get("schema") == "sinter-acceptance-manifest/2":
        rt = man.get("required_targets")
        if not isinstance(rt, list) or not rt or not all(x in ALL_LABELS for x in rt) or len(set(rt)) != len(rt):
            raise Fail("C: manifest required_targets is not a list of distinct target labels")
        if man.get("acceptance_scope") not in ("full", "patch"):
            raise Fail("C: manifest acceptance_scope is not full or patch")
        if man.get("acceptance_scope") == "full" and sorted(rt) != sorted(ALL_LABELS):
            raise Fail("C: a full-scope manifest must require the eight targets")
        LABELS = [x for x in ALL_LABELS if x in rt]
        # From v1.15.0 the docs commit D is part of the approval (§4.3).
        v.ok(meta.get("schema") == SCHEMA3, "C a sinter-acceptance-manifest/2 needs a sinter-approval-set/3 (with D)")
    # ---- C: META vs manifest --------------------------------------------------
    v.ok(meta.get("tag") == "v" + ver, "C tag == v<version>")
    for k, mv in (("version", c.get("version")), ("tag", c.get("tag")), ("rc_commit", c.get("source_commit")),
                  ("artifact", c.get("artifact")), ("executable_sha256", c.get("executable_sha256"))):
        v.ok(meta.get(k) == mv, f"C META.{k} == manifest candidate.{k}", "differs")
    v.ok(man.get("evidence_bundle") == bun_name, "C manifest names this bundle")
    v.ok(man.get("verdict") == "GO", "C manifest verdict is GO (the acceptance claim; not the release decision)")
    if a.expect_rc is not None:
        v.ok(meta.get("rc_commit") == a.expect_rc, "C rc_commit == --expect-rc",
             "the set belongs to another release candidate")
    if a.expect_version is not None:
        v.ok(ver == a.expect_version, "C version == --expect-version", "the set belongs to another version")
    # ---- D: acceptance SHA256SUMS ---------------------------------------------
    sums = parse_sums(rd(root, "acceptance/" + sums_name).decode("utf-8"), sums_name)
    v.ok(sums == {man_name: H(man_raw), bun_name: H(bun_raw)}, "D acceptance SHA256SUMS lists exactly manifest + bundle",
         str(sorted(sums)))
    # ---- E: bundle + provenance -----------------------------------------------
    stem = bun_name[:-len(".tar.gz")]
    bundle = {}
    with tarfile.open(fileobj=io.BytesIO(bun_raw), mode="r:gz") as tf:
        ms = tf.getmembers()
        for m in ms:
            if not SAFE_MEMBER.match(m.name) or any(x in (".", "..") for x in m.name.split("/")):
                raise Fail(f"T: member name is not a normalized relative path: {m.name!r}")
            if m.isreg():
                if not m.name.startswith(stem + "/"):
                    raise Fail(f"T: member outside the top-level directory: {m.name}")
                rel = m.name[len(stem) + 1:]
                if rel in bundle:
                    raise Fail(f"T: duplicate bundle member {rel}")
                bundle[rel] = tf.extractfile(m).read()
    # ---- T: tar headers -------------------------------------------------------
    v.ok(all((m.uid, m.gid, m.uname, m.gname) == (0, 0, "root", "root") for m in ms),
         "T every tar member owned by root:root uid/gid 0")
    v.ok(all(m.isreg() or m.isdir() for m in ms), "T regular files and directories only")
    v.ok(not any(m.pax_headers for m in ms), "T no pax extended headers")
    v.ok({m.name.split("/")[0] for m in ms} == {stem}, "T single top-level directory named after the bundle")
    v.ok(bundle.get("acceptance-manifest.json") == man_raw, "E bundle manifest copy byte-identical")
    prov_raw = bundle.get("harness/PROVENANCE.json")
    if prov_raw is None:
        raise Fail("E: harness/PROVENANCE.json missing from the bundle")
    prov = json.loads(prov_raw)
    hf = {x["path"]: x["sha256"] for x in man["harness"]["files"]}
    if len(hf) != len(man["harness"]["files"]):
        raise Fail("E: manifest harness.files lists a path twice")
    v.ok(sorted(t.get("label") for t in man.get("targets", [])) == sorted(LABELS),
         "C manifest has exactly the eight target labels")
    v.ok(prov.get("schema") == "sinter-harness-provenance/1", "E PROVENANCE schema")
    v.ok(hf.get("harness/PROVENANCE.json") == H(prov_raw), "E PROVENANCE listed in harness.files with its hash")
    v.ok(prov.get("source_commit") == c.get("source_commit"), "E PROVENANCE.source_commit == candidate")
    runtime_raw = rd(root, CR + "runtime-scripts-SHA256SUMS")
    runtime = {}
    for k, h in parse_sums(runtime_raw.decode("utf-8"), "runtime record").items():
        n = os.path.basename(k)
        if n in runtime:
            raise Fail(f"E: runtime record names {n} twice")
        runtime[n] = h
    v.ok(prov.get("runtime_record", {}).get("sha256") == H(runtime_raw) == col.get("runtime_record_sha256"),
         "E runtime record digest (PROVENANCE == record == META)")
    names = []
    v.ok(not prov.get("acceptance_time_tools"), "E no acceptance-time tools outside the repository harness",
         "a v1.5.1 set runs only release/acceptance-harness")
    for e in prov.get("files", []):
        n = e.get("name")
        names.append(n)
        v.ok(e.get("runtime_sha256") == runtime.get(n), f"E {n}: runtime_sha256 == runtime record")
        v.ok(isinstance(n, str) and e.get("source_path") == HARNESS_DIR + n, f"E {n}: source_path is {HARNESS_DIR}{n}")
        if e.get("bundle_form") == "not-included":
            v.ok(n in MAY_BE_NOT_INCLUDED, f"E {n}: may be left out of the bundle", "it runs in steps 7-9")
        form, bp = e.get("bundle_form"), e.get("bundle_path")
        if form == "verbatim":
            v.ok(isinstance(bp, str) and bp.startswith("harness/") and bp in bundle
                 and H(bundle[bp]) == e.get("runtime_sha256") == hf.get(bp),
                 f"E {n}: verbatim bundle bytes == executed bytes == harness.files")
        elif form == "not-included":
            v.ok(bp is None, f"E {n}: not-included has no bundle path")
        else:
            # Publication copies are not accepted for a harness kept in the
            # repository: every executed file must be publishable verbatim.
            v.ok(False, f"E {n}: bundle_form", repr(form))
    v.ok(len(names) == len(set(names)) and set(names) == set(runtime), "E PROVENANCE covers exactly the runtime record",
         f"missing={sorted(set(runtime) - set(names))} extra={sorted(set(names) - set(runtime))}")
    covered = {e.get("bundle_path") for e in prov.get("files", []) if e.get("bundle_form") == "verbatim"}
    covered.add("harness/PROVENANCE.json")
    in_bundle_h = {p for p in bundle if p.startswith("harness/")}
    v.ok(in_bundle_h == covered == set(hf), "E bundle harness/ == PROVENANCE paths == harness.files",
         f"bundle={sorted(in_bundle_h)} manifest={sorted(hf)}")
    cr = lambda rel: rd(root, CR + rel)  # noqa: E731
    col_bytes = cr("collect-evidence.py")
    pc = prov.get("post_acceptance_collector", {})
    v.ok(pc.get("sha256") == col.get("sha256") == H(col_bytes) == runtime.get("collect-evidence.py"),
         "E collector (PROVENANCE == META == record) is the runtime-record collector")
    v.ok(any(e.get("name") == "collect-evidence.py" and e.get("bundle_form") == "not-included"
             for e in prov.get("files", [])), "E collector is not bundled as a harness file")
    v.ok(pc.get("collector_record_sha256sums_sha256") == col.get("record_sha256sums_sha256") == H(cr("SHA256SUMS")),
         "E collector record digest (PROVENANCE == META == record)")
    v.ok([r.get("result") for r in pc.get("results", [])] == [r.get("verdict") for r in col["runs"]],
         "E collector results (PROVENANCE == META)")
    # ---- F: collector record sums ---------------------------------------------
    crs = parse_sums(cr("SHA256SUMS").decode("utf-8"), "collector-record/SHA256SUMS")
    v.ok(set(crs) == rec_files, "F collector SHA256SUMS lists exactly the record files",
         f"missing={sorted(rec_files - set(crs))} extra={sorted(set(crs) - rec_files)}")
    v.ok(all(H(cr(k)) == h for k, h in crs.items() if k in rec_files), "F collector SHA256SUMS hashes verify")
    # ---- G: collector results -------------------------------------------------
    for i, r in enumerate(col["runs"], 1):
        rid = r["id"]
        out_t = cr(f"runs/{rid}/collect.txt").decode("utf-8")
        sum_t = cr(f"runs/{rid}/summary.txt").decode("utf-8")
        verdict = last(out_t, "overall verdict: ")
        v.ok(verdict == last(sum_t, "overall verdict: ") == r.get("verdict"),
             f"G run {rid}: verdict consistent (collect.txt == summary.txt == META)")
        if i < len(col["runs"]):
            v.ok(verdict in ("NO-GO", "PENDING_OWNER_APPROVAL"), f"G run {rid}: an earlier run is never GO", repr(verdict))
            continue
        v.ok(verdict == "PENDING_OWNER_APPROVAL" and cr(f"runs/{rid}/VERDICT.txt").decode("utf-8").strip() == verdict,
             f"G run {rid} (last): PENDING_OWNER_APPROVAL in collect.txt, summary.txt and VERDICT.txt", repr(verdict))
        plines = [ln for ln in out_t.splitlines() if ln.startswith("problems:")]
        v.ok(plines == ["problems: none"] and not any(ln.startswith("  - ") for ln in out_t.splitlines()),
             f"G run {rid} (last): no problems")
        rows = [ln.split("\t") for ln in out_t.splitlines()
                if G_ROW_RE.match(ln)]
        v.ok(sorted(x[0] for x in rows) == sorted(LABELS), f"G run {rid} (last): one PASS row per label",
             str(sorted(x[0] for x in rows)))
        dig = {last(out_t, "evidence_digest: "), last(sum_t, "evidence_digest: "),
               col.get("evidence_digest"), pc.get("evidence_digest")}
        v.ok(len(dig) == 1 and None not in dig, f"G run {rid} (last): one evidence_digest across output, META, PROVENANCE")
    # ---- K: logs vs manifest counts ---------------------------------------------
    for t in man.get("targets", []):
        lp = t.get("log", {}).get("path")
        ends = END_LINE_RE.findall(bundle.get(lp, b"").decode("utf-8", "replace"))
        ch = t.get("checks", {})
        want_k = [ch.get("passed"), ch.get("failed"), ch.get("skipped"), ch.get("not_applicable", 0)]
        v.ok(len(ends) == 1 and [int(x) if x else 0 for x in ends[0]] == want_k,
             f"K {t.get('label')}: bundle log end line == manifest checks")
    if a.gate_log:
        with open(a.gate_log, "rb") as f:
            v.ok(bundle.get("validation/linux-gate.log") == f.read(), "K bundle gate log == recorded step-4 gate log")
    # ---- H: release candidate ---------------------------------------------------
    if a.rc_repo:
        rc = meta.get("rc_commit", "")
        typ = git(a.rc_repo, "cat-file", "-t", rc)
        v.ok(typ is not None and typ.strip() == b"commit", "H rc_commit is a commit in --rc-repo")
        tree = git(a.rc_repo, "rev-parse", rc + "^{tree}")
        v.ok(tree is not None and tree.decode().strip() == meta.get("rc_tree"), "H rc_tree == git tree of rc_commit")
        cargo = git(a.rc_repo, "show", f"{rc}:Cargo.toml")
        m = re.search(rb'(?m)^version = "([^"]+)"', cargo or b"")
        v.ok(m is not None and m.group(1).decode() == ver, "H Cargo.toml version at rc_commit == META version")
        for e in prov.get("files", []):
            sp = e.get("source_path")
            orig = git(a.rc_repo, "show", f"{rc}:{sp}") if isinstance(sp, str) else None
            v.ok(orig is not None and H(orig) == e.get("runtime_sha256"),
                 f"H {e.get('name')}: source_path at rc_commit == executed bytes")
        orig = git(a.rc_repo, "show", f"{rc}:release/acceptance-harness/collect-evidence.py")
        v.ok(orig is not None and orig == col_bytes, "H collector == release/acceptance-harness/collect-evidence.py at rc_commit")
    # ---- D: the docs commit (schema /3) -------------------------------------------
    if v3:
        check_docs_commit(v, a, root, meta, ver, man_raw)
    # ---- I / M: recorded evidence -------------------------------------------------
    if a.evidence:
        index_matches_runs(v, a.evidence, [cr(f"runs/{r['id']}/collect.txt").decode("utf-8") for r in col["runs"]])
        rc_col = git(a.rc_repo, "show", f"{meta['rc_commit']}:{HARNESS_DIR}collect-evidence.py")
        if v.ok(rc_col is not None and rc_col == col_bytes, "I the collector to run is the RC collector"):
            reproduce(v, a, root, meta, col, rc_col)
        resanitize(v, a, meta, bundle, runtime_raw)
        record_fields(v, a.evidence, man)
    # ---- R: artifact ----------------------------------------------------------------
    if a.artifact:
        art = meta.get("artifact", {})
        st = os.stat(a.artifact)
        with open(a.artifact, "rb") as f:
            ah = H(f.read())
        v.ok(os.path.basename(a.artifact) == art.get("filename") and st.st_size == art.get("size_bytes")
             and ah == art.get("sha256"), "R artifact name, size and SHA-256 == META")
    # ---- J: official checker --------------------------------------------------------
    if a.checker:
        p = subprocess.run([sys.executable, "-I", a.checker, os.path.join(root, "acceptance", man_name),
                            "--bundle-archive", os.path.join(root, "acceptance", bun_name),
                            "--artifact", a.artifact, "--sums", os.path.join(root, "acceptance", sums_name),
                            "--repo", a.rc_repo], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        v.ok(p.returncode == 0 and b"(verdict GO)" in p.stdout, "J official checker full mode",
             f"exit={p.returncode} {p.stderr.decode(errors='replace').strip()[:400]}")
    return v, digest


def check_docs_commit(v, a, root, meta, ver, man_raw):
    if not a.rc_repo:
        raise Fail("D: a sinter-approval-set/3 needs --rc-repo to check the docs commit")
    d, rc = meta["docs_commit"], meta["rc_commit"]
    typ = git(a.rc_repo, "cat-file", "-t", d)
    if not v.ok(typ is not None and typ.strip() == b"commit", "D docs_commit is a commit in --rc-repo"):
        return
    base = meta.get("docs_base", rc)
    if base != rc:
        bp = (git(a.rc_repo, "rev-list", "--parents", "-n", "1", base) or b"").decode().split()
        if v.ok(len(bp) == 3 and rc in bp[1:], "D docs_base is a merge with two parents, one of them rc_commit",
                str(bp[1:])):
            # the merge must be the clean merge of its parents: it carries
            # main's and the RC's changes and nothing else
            mt = git(a.rc_repo, "merge-tree", "--write-tree", bp[1], bp[2])
            bt = git(a.rc_repo, "rev-parse", base + "^{tree}")
            v.ok(mt is not None and bt is not None and mt.split(b"\n", 1)[0].strip() == bt.strip(),
                 "D docs_base's tree is the clean merge of its two parents (git merge-tree)")
    parents = (git(a.rc_repo, "rev-list", "--parents", "-n", "1", d) or b"").decode().split()
    v.ok(parents[1:] == [base], "D the docs commit has exactly one parent, rc_commit (or docs_base)", str(parents[1:]))
    tree = git(a.rc_repo, "rev-parse", d + "^{tree}")
    v.ok(tree is not None and tree.decode().strip() == meta.get("docs_tree"), "D docs_tree == git tree of docs_commit")
    base_tree = meta["rc_tree"] if base == rc else (git(a.rc_repo, "rev-parse", base + "^{tree}") or b"").decode().strip()
    patch = rd(root, DOCS_PATCH)
    first = patch.split(b"\n", 1)[0].decode("utf-8", "replace")
    v.ok(re.fullmatch(r"From " + d + r" Mon Sep 17 00:00:00 2001", first) is not None,
         "D docs-commit/D.patch is format-patch output of docs_commit")
    v.ok(len(re.findall(rb"(?m)^From [0-9a-f]{40} Mon Sep 17 00:00:00 2001$", patch)) == 1,
         "D docs-commit/D.patch holds exactly one commit")
    with tempfile.TemporaryDirectory(prefix="approval-set-docs-") as t:
        idx = os.path.join(t, "index")
        pf = os.path.join(t, "D.patch")
        with open(pf, "wb") as f:
            f.write(patch)
        env = minimal_env(GIT_INDEX_FILE=idx)
        def g(*args):
            return subprocess.run(["git", "-C", a.rc_repo, *args], env=env, capture_output=True)
        ok = bool(base_tree) and g("read-tree", base_tree).returncode == 0
        ok = ok and g("apply", "--cached", "--whitespace=nowarn", pf).returncode == 0
        w = g("write-tree") if ok else None
        v.ok(ok and w is not None and w.returncode == 0 and w.stdout.decode().strip() == meta.get("docs_tree"),
             "D the patch applied to the base tree reproduces docs_tree")
    names = git(a.rc_repo, "diff", "--name-only", "-z", "--no-renames", base, d)
    paths = [p for p in (names or b"").decode("utf-8", "replace").split("\0") if p]
    bad = [p for p in paths if not docs_allowed(p, ver)]
    v.ok(names is not None and paths and not bad, "D every path the docs commit changes is in the docs allow-list",
         str(bad[:5]))
    mp = f"release/evidence/v{ver}/acceptance-manifest.json"
    copy = git(a.rc_repo, "show", f"{d}:{mp}")
    v.ok(copy is not None and copy == man_raw, f"D {mp} in the docs commit == the approved acceptance manifest")


def minimal_env(**extra):
    """Only what the tools need: no inherited credentials or tool settings."""
    env = {k: os.environ[k] for k in ("PATH", "LANG", "LC_ALL", "TZ") if k in os.environ}
    env.update(extra)
    return env


def index_matches_runs(v, ev, tallies):
    """I: the append-only INDEX.tsv lists exactly the recorded runs, one per
    label, and every run any tally saw is still recorded (a failed run cannot
    be deleted and re-run unnoticed)."""
    runs = os.path.join(ev, "runs")
    rows = []
    with open(os.path.join(ev, "INDEX.tsv"), encoding="utf-8") as f:
        for line in f:
            if line.strip():
                rows.append(line.rstrip("\n").split("\t"))
    recorded = {}
    for d in sorted(os.listdir(runs)):
        rj = json.loads(rd(os.path.join(runs, d), "run.json"))
        recorded[d] = (rj.get("label"), rj.get("verdict"), rj.get("raw_log_sha256"))
    v.ok(all(len(r) == 6 for r in rows), "I INDEX.tsv rows are well-formed")
    v.ok(sorted(r[1] for r in rows if len(r) == 6) == sorted(recorded)
         and all(recorded.get(r[1]) == (r[2], r[3], r[5]) for r in rows if len(r) == 6),
         "I INDEX.tsv lists exactly the recorded runs (id, label, verdict, raw SHA-256)")
    labels = [r[2] for r in rows if len(r) == 6]
    v.ok(sorted(labels) == sorted(LABELS), "I INDEX.tsv: one run per target label (no failed run removed)", str(labels))
    seen = set()
    for t in tallies:
        for ln in t.splitlines():
            f = ln.split("\t")
            if len(f) == 7 and f[0] in LABELS:
                seen.add(f[1])
    v.ok(seen <= set(recorded), "I every run an earlier or last tally saw is still recorded",
         f"missing={sorted(seen - set(recorded))}")


def reproduce(v, a, root, meta, col, collector):
    """I: the RC collector reproduces the last run byte for byte."""
    rc = meta["rc_commit"]
    last_id = col["runs"][-1]["id"]
    with tempfile.TemporaryDirectory(prefix="approval-set-repro-") as t:
        hd = os.path.join(t, "harness")
        os.makedirs(hd)
        for n in ("raw-verdict.py", "expected-check-ids.txt"):
            g = git(a.rc_repo, "show", f"{rc}:release/acceptance-harness/{n}")
            if not v.ok(g is not None, f"I {n} available at rc_commit"):
                return
            with open(os.path.join(hd, n), "wb") as f:
                f.write(g)
        with open(os.path.join(hd, "collect-evidence.py"), "wb") as f:
            f.write(collector)
        ev = os.path.join(t, "evidence")
        shutil.copytree(a.evidence, ev, symlinks=True)
        for n in ("summary.txt", "VERDICT.txt"):
            if os.path.exists(os.path.join(ev, n)):
                os.remove(os.path.join(ev, n))
        env = minimal_env(SINTER_RC_COMMIT=rc, SINTER_EXP_ART=meta["artifact"]["sha256"],
                          SINTER_EXP_VER="sinter " + meta["version"])
        if LABELS != ALL_LABELS:
            # a patch-scope set (manifest /2): the collector gates on the
            # approved target set, never on the runs it finds
            env.update(SINTER_ACCEPTANCE_SCOPE="patch", SINTER_P5_TARGETS=",".join(LABELS))
        p = subprocess.run([sys.executable, "-I", os.path.join(hd, "collect-evidence.py"), ev, "--write-verdict"],
                           env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        v.ok(p.returncode == 0 and p.stdout == rd(root, CR + f"runs/{last_id}/collect.txt"),
             "I collector reproduces the last run's output")
        v.ok(os.path.exists(os.path.join(ev, "summary.txt"))
             and rd(ev, "summary.txt") == rd(root, CR + f"runs/{last_id}/summary.txt"),
             "I collector reproduces summary.txt")
        v.ok(os.path.exists(os.path.join(ev, "VERDICT.txt"))
             and rd(ev, "VERDICT.txt") == rd(root, CR + f"runs/{last_id}/VERDICT.txt"),
             "I collector reproduces VERDICT.txt")


def resanitize(v, a, meta, bundle, runtime_raw):
    """I: RC sanitize.py reproduces every bundle log; one run per label."""
    g = git(a.rc_repo, "show", f"{meta['rc_commit']}:release/acceptance-harness/sanitize.py")
    if not v.ok(g is not None, "I sanitize.py available at rc_commit"):
        return
    runs = os.path.join(a.evidence, "runs")
    seen = {}
    with tempfile.TemporaryDirectory(prefix="approval-set-sanitize-") as t:
        sp = os.path.join(t, "sanitize.py")
        with open(sp, "wb") as f:
            f.write(g)
        env = minimal_env(**{k: os.environ[k] for k in ("SINTER_PROJECT", "SINTER_ZONE", "SINTER_SPECS",
                                                         "SINTER_SANITIZE_PATTERNS") if k in os.environ})
        for d in sorted(os.listdir(runs)):
            label = json.loads(rd(os.path.join(runs, d), "run.json")).get("label")
            if not v.ok(label in LABELS, f"I run {d}: label is a target label", repr(label)):
                continue
            seen[label] = seen.get(label, 0) + 1
            out = os.path.join(t, f"{label}.log")
            p = subprocess.run([sys.executable, "-I", sp, label, os.path.join(runs, d, "raw.log"), out],
                               env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            v.ok(p.returncode == 0 and os.path.exists(out) and bundle.get(f"logs/{label}.log") == rd(t, f"{label}.log"),
                 f"I {label}: bundle log == RC sanitize.py applied to the recorded raw log",
                 p.stderr.decode(errors="replace").strip()[:200])
    v.ok(sorted(seen) == sorted(LABELS) and set(seen.values()) == {1}, "I exactly one recorded run per target label",
         str(seen))
    v.ok(all(rd(os.path.join(runs, d, "scripts"), "SHA256SUMS") == runtime_raw for d in os.listdir(runs)),
         "I every recorded run's scripts/SHA256SUMS == the runtime record in the set")


def record_fields(v, ev, man):
    """M: manifest target and run fields == the recorded values."""
    runs = os.path.join(ev, "runs")
    by_label = {}
    for d in sorted(os.listdir(runs)):
        rj = json.loads(rd(os.path.join(runs, d), "run.json"))
        by_label.setdefault(rj.get("label"), []).append((d, rj))
    starts, ends = [], []
    for t in man.get("targets", []):
        lb = t.get("label")
        recs = by_label.get(lb, [])
        if not v.ok(len(recs) == 1, f"M {lb}: exactly one recorded run"):
            continue
        d, rj = recs[0]
        with open(os.path.join(runs, d, "raw.log"), encoding="utf-8", errors="replace") as f:
            raw = f.read()

        def g(k):
            m = re.search(r"(?m)^%s=(.*)$" % k, raw)
            return m.group(1) if m else None

        osl = re.search(r"(?m)^OS_NAME=(.*) OS_VERSION=(\S+) ARCH=(\S+)$", raw)
        end = END_LINE_RE.findall(raw)
        want = {"os_name": osl and osl.group(1), "os_version": osl and osl.group(2), "arch": osl and osl.group(3),
                "artifact_sha256": g("OBSERVED_ARTIFACT_SHA"), "executable_sha256": g("OBSERVED_EXECUTABLE_SHA"),
                "version_output": g("OBSERVED_VERSION"), "started_at": rj.get("started_at"),
                "finished_at": rj.get("finished_at"), "image": rj.get("source_image") or None}
        for k, w in want.items():
            v.ok(w is not None and t.get(k) == w, f"M {lb}: {k} == recorded value")
        v.ok(rj.get("verdict") == "PASS" and t.get("verdict") == "PASS", f"M {lb}: recorded run and manifest PASS")
        if len(end) == 1:
            v.ok(t.get("checks") == end_line_checks(end[0]), f"M {lb}: checks == raw end line")
        else:
            v.ok(False, f"M {lb}: checks == raw end line", "no single end line")
        starts.append(rj.get("started_at") or "")
        ends.append(rj.get("finished_at") or "")
    if starts and ends:
        v.ok(man.get("run", {}).get("started_at") <= min(starts) and man.get("run", {}).get("finished_at") >= max(ends),
             "M run bounds enclose every recorded target run")


def main(argv):
    ap = argparse.ArgumentParser(description="Verify a sinter-approval-set/2 or /3 directory.")
    ap.add_argument("set")
    ap.add_argument("--approved-digest", help="the APPROVAL_SET_DIGEST the Owner approved")
    ap.add_argument("--expect-rc", help="the RC_COMMIT this set must belong to")
    ap.add_argument("--expect-version", help="the version this set must belong to")
    ap.add_argument("--rc-repo", help="git repository containing rc_commit (enables H; needed by --evidence)")
    ap.add_argument("--evidence", help="the recorded acceptance OUT directory (enables I and M)")
    ap.add_argument("--checker", help="release/check_acceptance_manifest.py (enables J; needs --artifact)")
    ap.add_argument("--artifact", help="the frozen release tarball (enables R)")
    ap.add_argument("--gate-log", help="the recorded step-4 linux-gate.log")
    try:
        a = ap.parse_args(argv)
    except SystemExit:
        return 2
    if a.approved_digest is not None and not HEX64.match(a.approved_digest):
        print("usage: --approved-digest must be 64 lowercase hex", file=sys.stderr)
        return 2
    if a.expect_rc is not None and not HEX40.match(a.expect_rc):
        print("usage: --expect-rc must be a full 40-hex commit id", file=sys.stderr)
        return 2
    if a.expect_version is not None and not VERSION.match(a.expect_version):
        print("usage: --expect-version must be X.Y.Z", file=sys.stderr)
        return 2
    if (a.evidence and not a.rc_repo) or (a.checker and not (a.artifact and a.rc_repo)):
        print("usage: --evidence needs --rc-repo; --checker needs --artifact and --rc-repo", file=sys.stderr)
        return 2
    if not os.path.isdir(a.set):
        print(f"usage: {a.set} is not a directory", file=sys.stderr)
        return 2
    try:
        v, digest = verify(a)
    except (Fail, OSError, ValueError, KeyError, TypeError, AttributeError, IndexError,
            tarfile.TarError, UnicodeDecodeError) as e:
        print(f"FAIL {type(e).__name__}: {e}", file=sys.stderr)
        print("RESULT: APPROVAL SET INVALID")
        return 1
    for p in v.passed:
        print(f"PASS {p}")
    for e in v.errors:
        print(f"FAIL {e}", file=sys.stderr)
    print(f"APPROVAL_SET_DIGEST {digest}")
    if v.errors:
        print("RESULT: APPROVAL SET INVALID")
        return 1
    if a.approved_digest is None:
        print("RESULT: PENDING_OWNER_APPROVAL (set valid; no Owner-approved digest supplied; this is not GO)")
        return 3
    if a.approved_digest != digest:
        print(f"FAIL approved digest {a.approved_digest} != current {digest}", file=sys.stderr)
        print("RESULT: APPROVAL SET DIFFERS FROM THE OWNER-APPROVED SET")
        return 1
    print("RESULT: APPROVAL SET MATCHES THE OWNER-APPROVED DIGEST (release GO still requires RELEASE.md steps 13-17)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
