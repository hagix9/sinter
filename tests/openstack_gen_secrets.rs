//! `examples/openstack/tools/gen-secrets.sh`, the helper that writes `secrets/controller.yaml` and
//! `secrets/compute.yaml`. Run under `/bin/sh` (and `dash` when it is installed) with a stand-in
//! `openssl` that prints synthetic values or fails in a chosen way. The checks: no file is written
//! unless every value is 32 characters of A-Za-z0-9, existing files and symbolic links are never
//! replaced, a failed or raced run leaves nothing behind, concurrent runs leave one complete pair,
//! and no value reaches stdout or stderr. The old script (`openssl … | tr | cut` without a check)
//! wrote empty values and exited 0 when openssl was missing or failed.
#![cfg(unix)]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SCRIPT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/examples/openstack/tools/gen-secrets.sh"
);

const ALL_KEYS: [&str; 14] = [
    "mysql_root_pass",
    "keystone_db_pass",
    "glance_db_pass",
    "placement_db_pass",
    "neutron_db_pass",
    "nova_db_pass",
    "rabbit_pass",
    "admin_password",
    "glance_service_pass",
    "placement_service_pass",
    "neutron_service_pass",
    "nova_service_pass",
    "metadata_proxy_secret",
    "horizon_secret_key",
];
const COMPUTE_KEYS: [&str; 5] = [
    "rabbit_pass",
    "nova_service_pass",
    "placement_service_pass",
    "neutron_service_pass",
    "metadata_proxy_secret",
];

// The stand-in openssl. FAKE_MODE: ok | fail | empty | invalid | short | failafter (FAKE_N good
// calls, then exit 1) | race (on call FAKE_N, create FAKE_RACE_FILE as another run would) | racedir (the
// same with a directory) | slow.
// A good call prints a synthetic, base64-like line that is unique per call and per FAKE_TAG.
const FAKE_OPENSSL: &str = r#"#!/bin/sh
[ "$1 $2 $3" = "rand -base64 192" ] || { echo "fake openssl: unexpected arguments: $*" >&2; exit 2; }
n=$(cat "$FAKE_COUNTER" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$FAKE_COUNTER"
good() { printf '%sSyntheticValue%02dXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX+/=\nmore+/=\n' "${FAKE_TAG:-T}" "$n"; }
case "$FAKE_MODE" in
  ok) good ;;
  fail) echo "fake openssl: failure" >&2; exit 1 ;;
  empty) ;;
  invalid) printf '!!!!@@@@####$$$$%%%%^^^^&&&&****((((\n' ;;
  short) printf 'abc123\n' ;;
  failafter) [ "$n" -le "$FAKE_N" ] || { echo "fake openssl: failure" >&2; exit 1; }; good ;;
  race) [ "$n" -eq "$FAKE_N" ] && printf 'from another run\n' > "$FAKE_RACE_FILE"; good ;;
  racedir) [ "$n" -eq "$FAKE_N" ] && mkdir "$FAKE_RACE_FILE"; good ;;
  slow) sleep 0.02; good ;;
  *) exit 3 ;;
esac
"#;

// A stand-in ln for the signal tests: it links, then sends SIGTERM to the script when the link it made
// is named FAKE_LN_KILL, the moment between a successful link and the script noticing it.
const FAKE_LN: &str = r#"#!/bin/sh
"$REAL_LN" "$@"; st=$?
case "$2" in */"$FAKE_LN_KILL") [ "$st" -eq 0 ] && kill -TERM "$PPID" ;; esac
exit "$st"
"#;

/// The tools the script and the stand-in need, linked into one directory, so PATH can leave
/// openssl out entirely.
const TOOLS: [&str; 15] = [
    "dirname", "mkdir", "chmod", "tr", "cut", "date", "mktemp", "ln", "rm", "cat", "sleep",
    "printf", "pwd", "env", "wc",
];

fn which(tool: &str) -> Option<PathBuf> {
    ["/usr/bin", "/bin", "/usr/local/bin"]
        .iter()
        .map(|d| Path::new(d).join(tool))
        .find(|p| p.is_file())
}

fn shells() -> Vec<PathBuf> {
    let mut out = vec![PathBuf::from("/bin/sh")];
    if let Some(d) = which("dash") {
        out.push(d);
    }
    out
}

/// The value the stand-in's call `n` turns into after `tr -dc A-Za-z0-9 | cut -c1-32`.
fn synthetic(tag: &str, n: usize) -> String {
    let line = format!("{tag}SyntheticValue{n:02}{}", "X".repeat(30));
    line[..32].to_string()
}

struct Fx {
    dir: tempfile::TempDir,
}

impl Fx {
    fn new() -> Fx {
        let dir = tempfile::Builder::new()
            .prefix("sinter-gensecrets-")
            .tempdir_in("/tmp")
            .unwrap();
        let d = dir.path();
        // the recipe layout the script resolves `secrets/` from: <root>/tools/gen-secrets.sh
        fs::create_dir_all(d.join("os/tools")).unwrap();
        fs::copy(SCRIPT, d.join("os/tools/gen-secrets.sh")).unwrap();
        fs::create_dir_all(d.join("fake")).unwrap();
        fs::write(d.join("fake/openssl"), FAKE_OPENSSL).unwrap();
        fs::set_permissions(d.join("fake/openssl"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir_all(d.join("tools")).unwrap();
        for t in TOOLS {
            let p = which(t).unwrap_or_else(|| panic!("{t} not found"));
            symlink(p, d.join("tools").join(t)).unwrap();
        }
        Fx { dir }
    }
    fn p(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }
    fn secrets(&self) -> PathBuf {
        self.p("os/secrets")
    }
    /// Run the script under `shell` with the stand-in openssl (or none) on PATH.
    fn run_with(&self, shell: &Path, fake: bool, env: &[(&str, &str)]) -> Output {
        let path = if fake {
            format!("{}:{}", self.p("fake").display(), self.p("tools").display())
        } else {
            self.p("tools").display().to_string()
        };
        let mut c = Command::new(shell);
        c.arg(self.p("os/tools/gen-secrets.sh"))
            .env_clear()
            .env("PATH", path)
            .env("FAKE_COUNTER", self.p("counter"));
        for (k, v) in env {
            c.env(k, v);
        }
        c.output().unwrap()
    }
    fn run(&self, shell: &Path, mode: &str) -> Output {
        self.run_with(shell, true, &[("FAKE_MODE", mode)])
    }
    /// Names under secrets/ (empty when the directory does not exist).
    fn entries(&self) -> Vec<String> {
        let mut v: Vec<String> = match fs::read_dir(self.secrets()) {
            Ok(rd) => rd
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect(),
            Err(_) => vec![],
        };
        v.sort();
        v
    }
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

/// key -> value of a generated file, checking the exact layout the recipes include.
fn parse(path: &Path) -> BTreeMap<String, String> {
    let s = fs::read_to_string(path).unwrap();
    let lines: Vec<&str> = s.lines().collect();
    assert!(lines[0].starts_with("# "), "{s}");
    assert_eq!(lines[1], "version: 1");
    assert_eq!(lines[2], "vars:");
    let mut out = BTreeMap::new();
    for chunk in lines[3..].chunks(3) {
        let key = chunk[0]
            .strip_prefix("  ")
            .and_then(|k| k.strip_suffix(':'))
            .unwrap();
        let value = chunk[1]
            .strip_prefix("    value: \"")
            .and_then(|v| v.strip_suffix('"'))
            .unwrap();
        assert_eq!(chunk[2], "    sensitive: true");
        out.insert(key.to_string(), value.to_string());
    }
    assert_eq!(out.len(), 14, "{s}");
    out
}

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

fn assert_nothing_written(fx: &Fx, out: &Output) {
    assert!(!out.status.success(), "{}", text(out));
    let e = fx.entries();
    assert!(
        e.is_empty(),
        "a failed run left {e:?} in secrets/: {}",
        text(out)
    );
}

#[test]
fn writes_both_files_with_checked_values_shared_with_compute() {
    for sh in shells() {
        let fx = Fx::new();
        let out = fx.run(&sh, "ok");
        assert!(out.status.success(), "{}: {}", sh.display(), text(&out));
        assert_eq!(fx.entries(), ["compute.yaml", "controller.yaml"]);
        let ctl = parse(&fx.secrets().join("controller.yaml"));
        let cmp = parse(&fx.secrets().join("compute.yaml"));
        for (i, k) in ALL_KEYS.iter().enumerate() {
            // values in key order, one openssl call each
            assert_eq!(ctl[*k], synthetic("T", i + 1), "{k}");
            if COMPUTE_KEYS.contains(k) {
                assert_eq!(cmp[*k], ctl[*k], "{k} must be shared");
            } else {
                assert_eq!(cmp[*k], "", "{k} must be empty on a compute node");
            }
        }
        assert_eq!(mode(&fx.secrets()), 0o700);
        assert_eq!(mode(&fx.secrets().join("controller.yaml")), 0o600);
        assert_eq!(mode(&fx.secrets().join("compute.yaml")), 0o600);
        assert!(
            text(&out).contains("controller.yaml and "),
            "{}",
            text(&out)
        );
    }
}

#[test]
fn no_value_reaches_stdout_or_stderr() {
    let fx = Fx::new();
    let ok = fx.run(Path::new("/bin/sh"), "ok");
    assert!(ok.status.success(), "{}", text(&ok));
    let all = text(&ok);
    for v in parse(&fx.secrets().join("controller.yaml")).values() {
        assert!(!all.contains(v.as_str()), "a secret value was printed");
    }
    // a run that fails after some values were generated prints none of them either
    let fx = Fx::new();
    let out = fx.run_with(
        Path::new("/bin/sh"),
        true,
        &[("FAKE_MODE", "failafter"), ("FAKE_N", "7")],
    );
    assert_nothing_written(&fx, &out);
    for n in 1..=7 {
        assert!(!text(&out).contains(&synthetic("T", n)));
    }
}

#[test]
fn missing_openssl_writes_nothing() {
    for sh in shells() {
        let fx = Fx::new();
        let out = fx.run_with(&sh, false, &[]);
        assert_nothing_written(&fx, &out);
        assert!(text(&out).contains("openssl is required"), "{}", text(&out));
    }
}

#[test]
fn failing_empty_invalid_or_short_openssl_output_writes_nothing() {
    for sh in shells() {
        for m in ["fail", "empty", "invalid", "short"] {
            let fx = Fx::new();
            let out = fx.run(&sh, m);
            assert_nothing_written(&fx, &out);
            assert!(
                text(&out).contains("could not generate a secret"),
                "{} {m}: {}",
                sh.display(),
                text(&out)
            );
        }
    }
}

#[test]
fn a_failure_part_way_leaves_no_partial_file() {
    for n in ["1", "5", "13"] {
        let fx = Fx::new();
        let out = fx.run_with(
            Path::new("/bin/sh"),
            true,
            &[("FAKE_MODE", "failafter"), ("FAKE_N", n)],
        );
        assert_nothing_written(&fx, &out);
    }
}

#[test]
fn existing_files_and_links_are_never_replaced() {
    let synthetic_old = "# SYNTHETIC EXISTING FILE\n";
    for existing in ["controller.yaml", "compute.yaml"] {
        let fx = Fx::new();
        fs::create_dir_all(fx.secrets()).unwrap();
        fs::write(fx.secrets().join(existing), synthetic_old).unwrap();
        let out = fx.run(Path::new("/bin/sh"), "ok");
        assert!(!out.status.success(), "{existing}: {}", text(&out));
        assert!(text(&out).contains("not overwritten"), "{}", text(&out));
        assert_eq!(
            fs::read_to_string(fx.secrets().join(existing)).unwrap(),
            synthetic_old
        );
        assert_eq!(fx.entries(), [existing], "nothing else may appear");
        assert!(!fx.p("counter").exists(), "openssl must not even run");
    }
    // a symbolic link in place of a file is not followed (dangling or not)
    for target_exists in [true, false] {
        let fx = Fx::new();
        fs::create_dir_all(fx.secrets()).unwrap();
        let target = fx.p("elsewhere.yaml");
        if target_exists {
            fs::write(&target, synthetic_old).unwrap();
        }
        symlink(&target, fx.secrets().join("controller.yaml")).unwrap();
        let out = fx.run(Path::new("/bin/sh"), "ok");
        assert!(!out.status.success(), "{}", text(&out));
        assert_eq!(fx.entries(), ["controller.yaml"]);
        if target_exists {
            assert_eq!(fs::read_to_string(&target).unwrap(), synthetic_old);
        } else {
            assert!(!target.exists());
        }
    }
    // nor is a secrets/ directory that is a symbolic link
    let fx = Fx::new();
    fs::create_dir_all(fx.p("real-secrets")).unwrap();
    symlink(fx.p("real-secrets"), fx.secrets()).unwrap();
    let out = fx.run(Path::new("/bin/sh"), "ok");
    assert!(!out.status.success(), "{}", text(&out));
    assert!(fs::read_dir(fx.p("real-secrets")).unwrap().next().is_none());
}

#[test]
fn a_file_that_appears_during_the_run_is_kept_and_the_run_takes_its_own_back() {
    // controller.yaml appears after the start check (another run): the compute.yaml this run already
    // placed is removed again and the other file is untouched
    let fx = Fx::new();
    let foreign = fx.secrets().join("controller.yaml");
    let out = fx.run_with(
        Path::new("/bin/sh"),
        true,
        &[
            ("FAKE_MODE", "race"),
            ("FAKE_N", "14"),
            ("FAKE_RACE_FILE", foreign.to_str().unwrap()),
        ],
    );
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("cannot place secrets/controller.yaml"));
    assert_eq!(fx.entries(), ["controller.yaml"]);
    assert_eq!(fs::read_to_string(&foreign).unwrap(), "from another run\n");
    // the same for compute.yaml: nothing of this run is placed
    let fx = Fx::new();
    let foreign = fx.secrets().join("compute.yaml");
    let out = fx.run_with(
        Path::new("/bin/sh"),
        true,
        &[
            ("FAKE_MODE", "race"),
            ("FAKE_N", "3"),
            ("FAKE_RACE_FILE", foreign.to_str().unwrap()),
        ],
    );
    assert!(!out.status.success(), "{}", text(&out));
    assert_eq!(fx.entries(), ["compute.yaml"]);
    assert_eq!(fs::read_to_string(&foreign).unwrap(), "from another run\n");
}

#[test]
fn concurrent_runs_leave_one_complete_pair() {
    let fx = Fx::new();
    let tags = ["A", "B", "C", "D", "E", "F"];
    let children: Vec<_> = tags
        .iter()
        .map(|t| {
            let path = format!("{}:{}", fx.p("fake").display(), fx.p("tools").display());
            Command::new("/bin/sh")
                .arg(fx.p("os/tools/gen-secrets.sh"))
                .env_clear()
                .env("PATH", path)
                .env("FAKE_MODE", "slow")
                .env("FAKE_TAG", t)
                .env("FAKE_COUNTER", fx.p(&format!("counter-{t}")))
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    let outs: Vec<Output> = children
        .into_iter()
        .map(|c| c.wait_with_output().unwrap())
        .collect();
    let ok = outs.iter().filter(|o| o.status.success()).count();
    assert!(ok <= 1, "{ok} runs claim success");
    assert_eq!(fx.entries(), ["compute.yaml", "controller.yaml"]);
    let ctl = parse(&fx.secrets().join("controller.yaml"));
    let cmp = parse(&fx.secrets().join("compute.yaml"));
    // both files come from the same run: one tag throughout, shared values equal
    let tag = &ctl["mysql_root_pass"][..1];
    for (i, k) in ALL_KEYS.iter().enumerate() {
        assert_eq!(ctl[*k], synthetic(tag, i + 1), "{k}");
        if COMPUTE_KEYS.contains(k) {
            assert_eq!(cmp[*k], ctl[*k], "{k}");
        }
    }
    assert_eq!(ok, 1, "exactly the run that placed the pair succeeds");
}

#[test]
fn the_real_openssl_gives_distinct_values_of_the_checked_shape() {
    let Some(real) = which("openssl") else {
        eprintln!("skip: no openssl on this host");
        return;
    };
    let fx = Fx::new();
    symlink(&real, fx.p("tools/openssl")).unwrap();
    let out = fx.run_with(Path::new("/bin/sh"), false, &[]);
    assert!(out.status.success(), "{}", text(&out));
    let ctl = parse(&fx.secrets().join("controller.yaml"));
    let mut seen = std::collections::BTreeSet::new();
    for v in ctl.values() {
        assert_eq!(v.len(), 32);
        assert!(v.bytes().all(|b| b.is_ascii_alphanumeric()));
        assert!(seen.insert(v.clone()), "values must differ");
        assert!(!text(&out).contains(v.as_str()));
    }
}

#[test]
fn a_signal_right_after_a_link_never_leaves_a_lone_file() {
    for (name, both) in [("compute.yaml", false), ("controller.yaml", true)] {
        let fx = Fx::new();
        fs::write(fx.p("fake/ln"), FAKE_LN).unwrap();
        fs::set_permissions(fx.p("fake/ln"), fs::Permissions::from_mode(0o755)).unwrap();
        let real_ln = fx.p("tools/ln");
        let out = fx.run_with(
            Path::new("/bin/sh"),
            true,
            &[
                ("FAKE_MODE", "ok"),
                ("FAKE_LN_KILL", name),
                ("REAL_LN", real_ln.to_str().unwrap()),
            ],
        );
        assert!(!out.status.success(), "{name}: {}", text(&out));
        if both {
            // killed after the last link: the pair is complete and stays
            assert_eq!(fx.entries(), ["compute.yaml", "controller.yaml"], "{name}");
            let ctl = parse(&fx.secrets().join("controller.yaml"));
            let cmp = parse(&fx.secrets().join("compute.yaml"));
            for k in COMPUTE_KEYS {
                assert_eq!(cmp[k], ctl[k]);
            }
        } else {
            // killed after the first link: this run takes its compute.yaml back
            assert!(fx.entries().is_empty(), "{name}: {:?}", fx.entries());
        }
    }
}

#[test]
fn a_directory_that_appears_under_the_name_gets_no_secret() {
    let fx = Fx::new();
    let foreign = fx.secrets().join("controller.yaml");
    let out = fx.run_with(
        Path::new("/bin/sh"),
        true,
        &[
            ("FAKE_MODE", "racedir"),
            ("FAKE_N", "14"),
            ("FAKE_RACE_FILE", foreign.to_str().unwrap()),
        ],
    );
    assert!(!out.status.success(), "{}", text(&out));
    assert_eq!(fx.entries(), ["controller.yaml"]);
    assert!(foreign.is_dir());
    assert!(
        fs::read_dir(&foreign).unwrap().next().is_none(),
        "a secret was linked into the directory"
    );
}

#[test]
fn a_temporary_directory_left_by_a_killed_run_is_reported_and_kept() {
    let fx = Fx::new();
    fs::create_dir_all(fx.secrets().join(".gen-secrets.left")).unwrap();
    let out = fx.run(Path::new("/bin/sh"), "ok");
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("secrets/.gen-secrets.left is left from an interrupted run"),
        "{}",
        text(&out)
    );
    assert_eq!(
        fx.entries(),
        [".gen-secrets.left", "compute.yaml", "controller.yaml"]
    );
}
