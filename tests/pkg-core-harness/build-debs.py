#!/usr/bin/env python3
"""Build the synthetic .deb packages of the SA-3 / Multi-Arch real-host scenarios (stdlib only, no dpkg needed).

Safety design (2026-10-24 incident): packages whose scripts fail do so ONLY while a flag file exists
(/var/tmp/sinter-h-flags/<package>, created by the harness, root-owned directory).  The harness disarms the flag
before the cleanup, so an ordinary purge works and no force option is ever needed.
No package is Essential.  Every package only touches /usr/share/sinter-test/<name> (and /etc/sinter-test/ for
conffile packages).  Usage: build-debs.py OUTDIR [sa3|multiarch|all]  -> prints "<file> <sha256> <name>:<arch>" lines.
"""
import gzip, hashlib, io, os, sys, tarfile

FLAGDIR = "/var/tmp/sinter-h-flags"

def spoof(name):
    """Lines a maintainer script could print that look like dpkg's own refusals (SA-3)."""
    return ("echo 'dpkg: dependency problems prevent removal of %s:' >&2\n"
            "echo 'dpkg: error: dpkg frontend lock was locked by another process with pid 4242' >&2\n"
            "echo 'dpkg: error: requested operation requires superuser privilege' >&2\n"
            "echo \"dpkg: error: ambiguous package name '%s' with more than one installed instance\" >&2\n" % (name, name))

def flag(name):
    return 'F=%s/%s\n' % (FLAGDIR, name)

SLEEP = "#!/bin/sh\nsleep ${SINTER_T_SLEEP:-40}\nexit 0\n"
SP_PRERM = ("#!/bin/sh\n" + flag("sinter-t-sp-prerm") + '[ -e "$F" ] || exit 0\n'
            'if [ -e "$F.wait" ]; then\n'
            '  i=0; while [ $i -lt 80 ] && [ ! -e "$F.seen" ]; do sleep 0.1; i=$((i+1)); done\n'
            '  if [ -e "$F.seen" ]; then echo saw > "$F.order"; else echo notseen > "$F.order"; fi\n'
            'fi\n' + spoof("sinter-t-sp-prerm") + "exit 1\n")
SP_POSTRM = "#!/bin/sh\n" + flag("sinter-t-sp-postrm") + '[ -e "$F" ] || exit 0\n' + spoof("sinter-t-sp-postrm") + "exit 1\n"
TRG_B_POSTRM = ("#!/bin/sh\n"
                'case "$1" in remove|purge) dpkg-trigger --no-await sinter-t-trg || true ;; esac\n'
                + spoof("sinter-t-trg-b") + "exit 0\n")
TRG_T_POSTINST = ("#!/bin/sh\n" + flag("sinter-t-trg-t") + 'case "$1" in triggered)\n  if [ -e "$F" ]; then\n'
                  + "".join("    " + l + "\n" for l in spoof("sinter-t-trg-b").splitlines())
                  + "    exit 1\n  fi ;;\nesac\nexit 0\n")
TRG_T_TRIGGERS = "interest-noawait sinter-t-trg\n"
MAB_I386_PRERM = "#!/bin/sh\n" + flag("sinter-t-mab") + '[ -e "$F" ] && exit 1\nexit 0\n'

PKGS = {  # (name, arch): (version, depends, extra control fields, maintainer scripts, conffile)
    ("sinter-t-base", "all"): ("1.0", "", {}, {}, False),
    ("sinter-t-app", "all"): ("1.0", "sinter-t-base", {}, {}, False),
    ("sinter-t-leaf-a", "all"): ("1.0", "", {}, {}, False),
    ("sinter-t-slow-install", "all"): ("1.0", "", {}, {"postinst": SLEEP}, False),
    ("sinter-t-sp-prerm", "all"): ("1.0", "", {}, {"prerm": SP_PRERM}, False),
    ("sinter-t-sp-postrm", "all"): ("1.0", "", {}, {"postrm": SP_POSTRM}, False),
    ("sinter-t-trg-b", "all"): ("1.0", "", {}, {"postrm": TRG_B_POSTRM}, False),
    ("sinter-t-trg-t", "all"): ("1.0", "", {}, {"postinst": TRG_T_POSTINST, "triggers": TRG_T_TRIGGERS}, False),
    ("sinter-t-ma", "amd64"): ("1.0", "", {"Multi-Arch": "same"}, {}, True),
    ("sinter-t-ma", "i386"): ("1.0", "", {"Multi-Arch": "same"}, {}, True),
    ("sinter-t-mab", "amd64"): ("1.0", "", {"Multi-Arch": "same"}, {}, False),
    ("sinter-t-mab", "i386"): ("1.0", "", {"Multi-Arch": "same"}, {"prerm": MAB_I386_PRERM}, False),
}
SETS = {
    "sa3": ["sinter-t-base", "sinter-t-app", "sinter-t-leaf-a", "sinter-t-slow-install", "sinter-t-sp-prerm",
            "sinter-t-sp-postrm", "sinter-t-trg-b", "sinter-t-trg-t"],
    "multiarch": ["sinter-t-ma", "sinter-t-mab"],
    "stageb1": ["sinter-t-leaf-a"],
    "stageb2": ["sinter-t-base", "sinter-t-app", "sinter-t-leaf-a"],
}

def tar_bytes(entries):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for name, data, mode, is_dir in entries:
            info = tarfile.TarInfo(name)
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = "root"
            info.mode = mode
            if is_dir:
                info.type = tarfile.DIRTYPE
                tf.addfile(info)
            else:
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
    return gzip.compress(buf.getvalue(), mtime=0)

def ar_member(name, data):
    header = "%-16s%-12d%-6d%-6d%-8s%-10d`\n" % (name + "/", 0, 0, 0, "100644", len(data))
    body = header.encode() + data
    if len(data) % 2:
        body += b"\n"
    return body

def build(name, arch, spec, outdir):
    version, depends, extra, scripts, conf = spec
    control = "Package: %s\nVersion: %s\nSection: misc\nPriority: optional\nArchitecture: %s\n" % (name, version, arch)
    control += "Maintainer: Sinter Test <test@example.invalid>\n"
    if depends:
        control += "Depends: %s\n" % depends
    for k, v in extra.items():
        control += "%s: %s\n" % (k, v)
    assert "Essential" not in extra, "no synthetic package may be Essential"
    control += "Description: synthetic package for Sinter removal tests\n"
    ctl = [("./", b"", 0o755, True), ("./control", control.encode(), 0o644, False)]
    for sname, body in scripts.items():
        ctl.append(("./" + sname, body.encode(), 0o644 if sname == "triggers" else 0o755, False))
    if conf:
        ctl.append(("./conffiles", b"/etc/sinter-test/%s.conf\n" % name.encode(), 0o644, False))
    data = [("./", b"", 0o755, True), ("./usr/", b"", 0o755, True), ("./usr/share/", b"", 0o755, True),
            ("./usr/share/sinter-test/", b"", 0o755, True), ("./usr/share/sinter-test/%s" % name, b"synthetic\n", 0o644, False)]
    if conf:
        data += [("./etc/", b"", 0o755, True), ("./etc/sinter-test/", b"", 0o755, True),
                 ("./etc/sinter-test/%s.conf" % name, b"setting=1\n", 0o644, False)]
    deb = b"!<arch>\n" + ar_member("debian-binary", b"2.0\n") + ar_member("control.tar.gz", tar_bytes(ctl)) + ar_member("data.tar.gz", tar_bytes(data))
    path = os.path.join(outdir, "%s_%s_%s.deb" % (name, version, arch))
    with open(path, "wb") as f:
        f.write(deb)
    return path, hashlib.sha256(deb).hexdigest()

def main():
    outdir = sys.argv[1]
    which = sys.argv[2] if len(sys.argv) > 2 else "all"
    names = sorted({n for ns in SETS.values() for n in ns}) if which == "all" else SETS[which]
    os.makedirs(outdir, exist_ok=True)
    for (name, arch), spec in sorted(PKGS.items()):
        if name in names:
            path, digest = build(name, arch, spec, outdir)
            print("%s %s %s:%s" % (os.path.basename(path), digest, name, arch))

if __name__ == "__main__":
    main()
