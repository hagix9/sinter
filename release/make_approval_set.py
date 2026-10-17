#!/usr/bin/env python3
"""Assemble an Owner approval set (schema sinter-approval-set/2) and print its digest.

RELEASE.md step 13. The set binds the three acceptance assets, the collector
that tallied the acceptance runs and every result it produced, and the
release candidate's identity to one digest, APPROVAL_SET_DIGEST.

Layout (every file is a member except APPROVAL-SET.sha256 itself):

  APPROVAL-SET-META.json                     candidate identity + collector facts
  acceptance/<the three acceptance assets>   byte copies of the files to be staged
  collector-record/collect-evidence.py       the collector that produced the results
  collector-record/runtime-scripts-SHA256SUMS
                                             the runtime record every run carried
  collector-record/runs/NN/collect.txt       stdout of collector run NN (in order,
  collector-record/runs/NN/summary.txt       a failed first result included); the
  collector-record/runs/NN/VERDICT.txt       last run also has VERDICT.txt
  collector-record/SHA256SUMS                the record files and their SHA-256
  APPROVAL-SET.sha256                        canonical member list

Canonical member list: one "<sha256>  <path>" line per member, paths relative
to the set root with "/", sorted by their UTF-8 bytes, nothing else; it
verifies with `shasum -a 256 -c`. APPROVAL_SET_DIGEST is the SHA-256 of that
file. Nothing here approves anything: release/verify_approval_set.py checks
the set and reports PENDING_OWNER_APPROVAL until the Owner names the digest.

Usage:
  make_approval_set.py <out-dir> --acceptance DIR --evidence DIR \
      --collector FILE --collector-run DIR [--collector-run DIR ...] --rc-tree TREE
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import sys

LIST = "APPROVAL-SET.sha256"
META = "APPROVAL-SET-META.json"
SCHEMA = "sinter-approval-set/2"


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 16), b""):
            h.update(b)
    return h.hexdigest()


def last(path, prefix):
    val = None
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.startswith(prefix):
                val = line[len(prefix):].strip()
    return val


def members(root):
    out = []
    for d, _, names in os.walk(root):
        for n in names:
            rel = os.path.relpath(os.path.join(d, n), root).replace(os.sep, "/")
            if rel != LIST:
                out.append(rel)
    return sorted(out, key=lambda s: s.encode("utf-8"))


def canonical(root, names):
    return "".join(f"{sha(os.path.join(root, p))}  {p}\n" for p in names).encode("utf-8")


def die(msg):
    sys.stderr.write(msg + "\n")
    sys.exit(1)


def main(argv):
    ap = argparse.ArgumentParser(description="Assemble a sinter-approval-set/2 directory.")
    ap.add_argument("out")
    ap.add_argument("--acceptance", required=True, help="directory with the three acceptance assets")
    ap.add_argument("--evidence", required=True, help="the acceptance OUT directory (runs/<id>/...)")
    ap.add_argument("--collector", required=True, help="collect-evidence.py that produced the runs")
    ap.add_argument("--collector-run", action="append", required=True,
                    help="directory with collect.txt and summary.txt of one collector run (in order)")
    ap.add_argument("--rc-tree", required=True)
    a = ap.parse_args(argv)
    if os.path.exists(a.out):
        die(f"refusing to overwrite {a.out}")
    if not re.fullmatch(r"[0-9a-f]{40}", a.rc_tree):
        die("--rc-tree must be a 40-hex tree id")
    mans = [n for n in os.listdir(a.acceptance) if re.fullmatch(r"sinter-v\d+\.\d+\.\d+-acceptance-manifest\.json", n)]
    if len(mans) != 1:
        die("the acceptance directory must hold exactly one acceptance manifest")
    with open(os.path.join(a.acceptance, mans[0]), encoding="utf-8") as f:
        c = json.load(f)["candidate"]
    v = c["version"]
    assets = [f"sinter-v{v}-acceptance-manifest.json", f"sinter-v{v}-acceptance-evidence.tar.gz",
              f"sinter-v{v}-acceptance-SHA256SUMS"]
    for n in assets:
        if not os.path.isfile(os.path.join(a.acceptance, n)):
            die(f"missing acceptance asset {n}")
    # Every run must carry the same runtime record.
    runs = os.path.join(a.evidence, "runs")
    records = {}
    for rid in sorted(os.listdir(runs)):
        p = os.path.join(runs, rid, "scripts", "SHA256SUMS")
        with open(p, "rb") as f:
            records[rid] = f.read()
    if not records or len(set(records.values())) != 1:
        die("the runs do not carry one common runtime record")
    finals = a.collector_run
    for d in finals:
        for n in ("collect.txt", "summary.txt"):
            if not os.path.isfile(os.path.join(d, n)):
                die(f"{d}: missing {n}")
    if not os.path.isfile(os.path.join(finals[-1], "VERDICT.txt")):
        die("the last collector run must include VERDICT.txt")

    cr = os.path.join(a.out, "collector-record")
    os.makedirs(os.path.join(a.out, "acceptance"))
    os.makedirs(cr)
    for n in assets:
        shutil.copyfile(os.path.join(a.acceptance, n), os.path.join(a.out, "acceptance", n))
    shutil.copyfile(a.collector, os.path.join(cr, "collect-evidence.py"))
    with open(os.path.join(cr, "runtime-scripts-SHA256SUMS"), "wb") as f:
        f.write(next(iter(records.values())))
    run_meta = []
    for i, d in enumerate(finals, 1):
        rid = f"{i:02d}"
        dst = os.path.join(cr, "runs", rid)
        os.makedirs(dst)
        names = ["collect.txt", "summary.txt"] + (["VERDICT.txt"] if i == len(finals) else [])
        for n in names:
            shutil.copyfile(os.path.join(d, n), os.path.join(dst, n))
        run_meta.append({"id": rid, "verdict": last(os.path.join(dst, "collect.txt"), "overall verdict: ")})
    rec = [n for n in members(cr) if n != "SHA256SUMS"]
    with open(os.path.join(cr, "SHA256SUMS"), "wb") as f:
        f.write(canonical(cr, rec))
    final_collect = os.path.join(cr, "runs", run_meta[-1]["id"], "collect.txt")
    meta = {
        "schema": SCHEMA,
        "version": v, "tag": c["tag"],
        "rc_commit": c["source_commit"], "rc_tree": a.rc_tree,
        "artifact": c["artifact"], "executable_sha256": c["executable_sha256"],
        "acceptance_assets": assets,
        "collector": {
            "sha256": sha(os.path.join(cr, "collect-evidence.py")),
            "runtime_record_sha256": sha(os.path.join(cr, "runtime-scripts-SHA256SUMS")),
            "record_sha256sums_sha256": sha(os.path.join(cr, "SHA256SUMS")),
            "runs": run_meta,
            "evidence_digest": last(final_collect, "evidence_digest: "),
        },
    }
    with open(os.path.join(a.out, META), "w", encoding="utf-8", newline="\n") as f:
        json.dump(meta, f, indent=2, sort_keys=True)
        f.write("\n")
    data = canonical(a.out, members(a.out))
    with open(os.path.join(a.out, LIST), "wb") as f:
        f.write(data)
    print(hashlib.sha256(data).hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
