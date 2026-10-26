#!/usr/bin/env python3
"""Mock of dpkg / dpkg-query / dpkg-deb for the harness safety tests.

Never touches a real package database: the state is a JSON file ($MOCK_DB).  Every call is appended to
$MOCK_LOG (one line: tool, uid, argv).  Fault injection through environment variables (MOCK_*).
Invoked through the tiny launchers in this directory (they pass the tool name as argv[1]).
"""
import fnmatch, json, os, sys, re

tool = sys.argv[1]
argv = sys.argv[2:]
db_path = os.environ["MOCK_DB"]
log_path = os.environ["MOCK_LOG"]

with open(log_path, "a") as lf:
    lf.write("%s\tuid=%d\t%s\n" % (tool, os.getuid(), " ".join(argv)))

def read_fields(path):
    """Fields of a fixture "deb" (text) or of a real .deb (ar archive with control.tar.gz)."""
    with open(path, "rb") as f:
        data = f.read()
    fields = {}
    if data.startswith(b"!<arch>\n"):
        import io as _io, tarfile
        pos = 8
        while pos < len(data):
            hdr = data[pos:pos + 60]
            name = hdr[:16].decode().strip().rstrip("/")
            size = int(hdr[48:58].decode().strip())
            body = data[pos + 60:pos + 60 + size]
            pos += 60 + size + (size % 2)
            if name == "control.tar.gz":
                with tarfile.open(fileobj=_io.BytesIO(body), mode="r:gz") as tf:
                    member = [m for m in tf.getmembers() if m.name in ("./control", "control")][0]
                    text = tf.extractfile(member).read().decode()
                for line in text.splitlines():
                    if ": " in line:
                        k, v = line.split(": ", 1)
                        fields[k] = v
        return fields
    for line in data.decode().splitlines():
        if ": " in line:
            k, v = line.split(": ", 1)
            fields[k] = v
    return fields

def load():
    with open(db_path) as f:
        return json.load(f)

def save(db):
    with open(db_path, "w") as f:
        json.dump(db, f)

def die(msg, code=2):
    sys.stderr.write(msg + "\n")
    sys.exit(code)

env = os.environ.get

def render(fmt, rec):
    fmt = fmt.replace("\\t", "\t").replace("\\n", "\n")
    out = fmt
    for key, val in (("${db:Status-Abbrev}", rec["abbr"]), ("${Package}", rec["name"]), ("${Architecture}", rec["arch"]),
                     ("${Version}", rec["ver"]), ("${Maintainer}", rec.get("maint", "")), ("${Essential}", rec.get("ess", "")), ("${Status}", rec.get("status", "install ok installed"))):
        out = out.replace(key, val)
    return out

if argv and argv[0] == "--version":
    sys.stdout.write("Debian '%s' package management program version 1.22.6 (amd64). [mock]\n" % tool)
    sys.exit(0)

if tool == "dpkg-query":
    mode = env("MOCK_Q_MODE", "ok")
    fmt = None
    pats = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "-W":
            pass
        elif a.startswith("-f="):
            fmt = a[3:]
        elif a == "--":
            pats += argv[i + 1:]
            break
        else:
            pats.append(a)
        i += 1
    if mode == "rc3":
        die("dpkg-query: error: simulated failure", 3)
    if mode == "rc1other":
        die("dpkg-query: error: some other failure", 1)
    if mode == "warn":
        sys.stderr.write("dpkg-query: warning: simulated warning\n")
    if mode == "stale":
        sys.stdout.write(env("MOCK_STALE", "install ok installed\tbash\tamd64\n"))
        sys.exit(0)
    if mode == "empty":
        sys.exit(0)
    db = load()
    recs = db["pkgs"]
    sel = []
    if pats:
        for p in pats:
            hit = [r for r in recs if fnmatch.fnmatchcase(r["name"], p)]
            if not hit:
                die("dpkg-query: no packages found matching %s" % p, 1)
            sel += hit
    else:
        sel = list(recs)
    if mode == "all":           # the listing is returned whatever the pattern said (the incident symptom)
        sel = list(recs)
    out = "".join(render(fmt or "${Package}\\n", r) for r in sel)
    if mode == "truncate":
        out = out[: max(0, len(out) // 2)]
    if mode == "nonl":
        out = out.rstrip("\n")
    if mode == "crlf":
        out = out.replace("\n", "\r\n")
    if mode == "nul":
        out = out[:10] + "\0" + out[10:]
    if mode == "badfield":
        out = out.replace("\t", "\t\t", 1)
    if mode == "garbage":
        out = "this is not a record\n"
    if mode == "highbit":
        out = out.replace("sinter", "sinteü", 1)
    if mode == "bigerr":
        sys.stderr.write("x" * 200000)
    if mode == "dup":
        out = out + out.splitlines(True)[0] if out else out
    if mode == "rc1-with-data":
        sys.stdout.write(out); sys.exit(1)
    sys.stdout.write(out)
    sys.exit(0)

if tool == "dpkg-deb":
    # -f FILE Package Architecture : the "deb" is a text fixture with those fields
    if len(argv) >= 2 and argv[0] == "-f":
        path = argv[1]
        fields = read_fields(path)
        want = argv[2:]
        if len(want) == 1:                      # like the real dpkg-deb 1.22.6: one field is printed without its label,
            k = want[0]                         # an absent Essential prints "no", any other absent field an empty line
            sys.stdout.write("%s\n" % (fields.get(k) or ("no" if k == "Essential" else "")))
        else:
            for k in want:
                if fields.get(k):               # several fields: "Name: value" lines, absent or empty fields are left out
                    sys.stdout.write("%s: %s\n" % (k, fields[k]))
        sys.exit(0)
    if len(argv) >= 2 and argv[0] in ("-I", "-c"):      # --info / --contents (informational text only)
        fields = read_fields(argv[1])
        if argv[0] == "-I":
            sys.stdout.write(" new Debian package, version 2.0.\n Package: %s\n Version: %s\n Architecture: %s\n" % (fields.get("Package"), fields.get("Version"), fields.get("Architecture")))
        else:
            sys.stdout.write("drwxr-xr-x root/root 0 1970-01-01 00:00 ./\n")
        sys.exit(0)
    die("mock dpkg-deb: unsupported", 2)

if tool == "dpkg":
    db = load()
    recs = db["pkgs"]
    def find(spec):
        if ":" in spec:
            n, a = spec.split(":", 1)
        else:
            n, a = spec, None
        return [r for r in recs if r["name"] == n and (a is None or r["arch"] == a)]
    if argv and argv[0] == "--audit":
        # "pre" = while a synthetic package is still installed, "post" = after it is gone (separate knobs: MOCK_AUDIT_{PRE,POST}_{OUT,ERR,RC})
        phase = "PRE" if any(r["name"].startswith("sinter-t-") for r in recs) else "POST"
        _o = env("MOCK_AUDIT_%s_OUT" % phase, "")
        sys.stdout.write(_o + ("" if _o == "" or _o.endswith("\n") else "\n"))     # a real dpkg ends its lines (shell variables lose trailing newlines)
        sys.stderr.write(env("MOCK_AUDIT_%s_ERR" % phase, ""))
        sys.exit(int(env("MOCK_AUDIT_%s_RC" % phase, "0")))
    if argv and argv[0] == "--print-foreign-architectures":
        sys.stdout.write("".join(a + "\n" for a in db.get("foreign", [])))
        sys.exit(0)
    if argv and argv[0] in ("--add-architecture", "--remove-architecture"):
        a = argv[1]
        if argv[0] == "--add-architecture" and a not in db["foreign"]:
            db["foreign"].append(a)
        if argv[0] == "--remove-architecture":
            if any(r["arch"] == a for r in recs):
                die("dpkg: error: cannot remove architecture '%s' currently in use by the database" % a, 2)
            db["foreign"] = [x for x in db["foreign"] if x != a]
        save(db)
        sys.exit(0)
    if argv and argv[0] == "--set-selections":
        for ln in sys.stdin.read().splitlines():
            parts = ln.split()
            if len(parts) == 2 and parts[1] == "install":
                for r in find(parts[0]):
                    if r["abbr"][0] != "i":
                        r["abbr"] = "i" + r["abbr"][1:]
        save(db)
        sys.exit(0)
    dry = "--dry-run" in argv
    if "--purge" in argv or "--remove" in argv:
        specs = [a for a in argv if not a.startswith("-")]
        for a in argv:
            if a.startswith("--force"):
                die("mock dpkg: force options must never be used by the harness (got %s)" % a, 99)
        db.setdefault("purges", [])
        n_call = db.get("n_purge", 0) + (0 if dry else 1)
        if env("MOCK_P_FAIL_ON") and not dry and str(n_call) == env("MOCK_P_FAIL_ON"):
            db["n_purge"] = n_call; save(db)
            die("dpkg: error: simulated purge failure", 1)
        if dry:
            sys.stdout.write("(Reading database ... 100 files and directories currently installed.)\n")
        for s in specs:      # dpkg refuses to remove a package another installed package depends on
            for r in find(s):
                deps = [x for x in recs if x is not r and r["name"] in [d.strip().split(" ")[0] for d in x.get("dep", "").split(",") if d.strip()]]
                if deps:
                    if not dry:                 # like the real dpkg: the selection is changed before the dependency check
                        r["abbr"] = "ri "; save(db)
                    shown = r["name"] if r["arch"] == "all" else "%s:%s" % (r["name"], r["arch"])
                    die("dpkg: dependency problems prevent removal of %s:\n %s depends on %s." % (shown, deps[0]["name"], r["name"]), 1)
        for s in specs:
            hit = find(s)
            if not hit:        # real dpkg 1.22.6: warning on stderr, exit status 0, nothing on stdout
                sys.stderr.write("dpkg: warning: ignoring request to remove %s which isn't installed\n" % s)
            for r in hit:
                if env("MOCK_P_DRY_EXTRA") and dry:
                    sys.stdout.write("Would remove or purge %s (%s) ...\n" % (env("MOCK_P_DRY_EXTRA"), "1.0"))
                if dry:
                    if env("MOCK_P_DRY_EMPTY"):      # fault: the dry-run prints nothing at all for an installed package
                        continue
                    shown = env("MOCK_P_DRY_VER") or r["ver"]
                    sys.stdout.write("Would remove or purge %s (%s) ...\n" % (r["name"], shown))
                    if env("MOCK_P_DRY_TWICE"):
                        sys.stdout.write("Would remove or purge %s (%s) ...\n" % (r["name"], shown))
                    if env("MOCK_P_DRY_WARN"):
                        sys.stderr.write("dpkg: warning: simulated diagnostic\n")
                    if env("MOCK_P_DRY_ODD"):
                        sys.stdout.write("Removing %s (%s) ...\n" % (r["name"], shown))
                else:
                    if env("MOCK_P_CREATE_MARK"):        # fault: a wrapper mount appears during the purge
                        open(env("MOCK_P_CREATE_MARK"), "w").close()
                    if env("MOCK_P_CHMOD"):              # fault: "PATH:MODE" (octal) is changed during the purge
                        _p, _m = env("MOCK_P_CHMOD").rsplit(":", 1); import glob as _g
                        for _x in _g.glob(_p):
                            os.chmod(_x, int(_m, 8))
                    if env("MOCK_P_WRITE"):              # fault: "PATH:CONTENT" is written during the purge (another actor)
                        _p, _c = env("MOCK_P_WRITE").split("::", 1)
                        with open(_p, "w") as _f:
                            _f.write(_c)
                    if env("MOCK_P_RELINK"):             # fault: "PATH::TARGET": the symlink PATH is replaced by another one during the purge
                        _p, _t = env("MOCK_P_RELINK").split("::", 1)
                        os.unlink(_p); os.symlink(_t, _p)
                    if env("MOCK_P_SLEEP"):              # slow purge (for the concurrency test)
                        import time as _time; _time.sleep(float(env("MOCK_P_SLEEP")))
                    if env("MOCK_P_FOREIGN"):            # fault: the foreign-architecture list changes during the purge
                        db["foreign"] = env("MOCK_P_FOREIGN").split(",")
                    if env("MOCK_P_NOOP"):               # fault: exit 0 but the package stays
                        db["n_purge"] = n_call; save(db); sys.exit(0)
                    db["purges"].append("%s:%s" % (r["name"], r["arch"]))
                    if r.get("ess") == "yes" and not env("MOCK_ALLOW_ESS"):
                        die("dpkg: error processing package %s (--purge):\n this is an essential package" % r["name"], 1)
                    recs[:] = [x for x in recs if x is not r and not (x["name"] == r["name"] and x["arch"] == r["arch"])]
                    if env("MOCK_P_RC_AFTER_REMOVE"):
                        db["n_purge"] = n_call; save(db)
                        die("dpkg: error: simulated failure after the package was removed", 1)
                    if env("MOCK_P_ALSO") and not dry:   # a tool that removes more than asked
                        recs[:] = [x for x in recs if x["name"] != env("MOCK_P_ALSO")]
        if not dry:
            db["n_purge"] = n_call
            save(db)
        sys.exit(0)
    if argv and argv[0] == "--configure":
        if env("MOCK_C_FAIL"):
            die("dpkg: error: simulated configure failure", 1)
        for s in [a for a in argv[1:] if not a.startswith("-")]:
            for r in find(s):
                r["abbr"] = "ii "
        save(db)
        sys.exit(0)
    if argv and argv[0] == "-i":
        path = argv[1]
        fields = read_fields(path)
        st = fields.get("State", "ii ")
        recs[:] = [x for x in recs if not (x["name"] == fields["Package"] and x["arch"] == fields["Architecture"])]   # re-install replaces
        recs.append({"name": fields["Package"], "arch": fields["Architecture"], "ver": env("MOCK_I_VER") or fields.get("Version", "1.0"),
                     "ess": fields.get("Essential") or "no", "dep": fields.get("Depends", ""), "maint": fields.get("Maintainer", ""), "abbr": st})
        save(db)
        sys.exit(0)
    die("mock dpkg: unsupported arguments: %s" % " ".join(argv), 2)

die("unknown tool %s" % tool, 2)
