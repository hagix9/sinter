//! WP-PROGRESS S5: what the CLI binary prints with `SINTER_PROGRESS=plain`.
//!
//! Plain progress is an explicit opt-in. Without it (unset, empty or any value
//! but `plain`) a run prints exactly what it printed before progress existed.
//! With it a text-format `plan`/`apply`/`audit` adds bounded `progress:` lines
//! to **stderr only**: stdout, the exit status and every other stderr byte are
//! unchanged and in the same order. JSON never gets progress, `validate` and
//! recipes that reference secrets get none, and nothing depends on whether
//! stderr is a terminal or on `TERM`.
//!
//! The real binary is run on pipes and with stderr on a pty. Only target-free
//! failures are used (a closed loopback port, a bad host argument, a bad
//! recipe), so the comparison is the same on every OS; success output is
//! covered by the pinned suites, which are unchanged.
#![cfg(unix)]
mod common;
use common::ClosedPorts;

use std::fs::File;
use std::io::Read;
use std::os::fd::FromRawFd;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sinter")
}

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

struct Fx {
    dir: tempfile::TempDir,
}

impl Fx {
    fn new() -> Self {
        Fx {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn write(&self, name: &str, body: &str) -> String {
        let p = self.path(name);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&p, body).unwrap();
        p.display().to_string()
    }

    /// Hosts web01/web02 at closed loopback ports.
    fn inventory(&self, ports: &[u16]) -> String {
        let kh = self.write("known_hosts", "");
        self.write(
            "hosts.yaml",
            &format!(
                "hosts:\n  web01:\n    address: 127.0.0.1\n    port: {}\n    user: u\n    known_hosts: {kh}\n  web02:\n    address: 127.0.0.1\n    port: {}\n    user: u\n    known_hosts: {kh}\ngroups:\n  web:\n    hosts: [web01, web02]\n",
                ports[0], ports[1]
            ),
        )
    }

    /// A scripted `ssh` on PATH answering every `-G` with `g`.
    fn fake_ssh(&self, g: &str) {
        let bin_dir = self.path("fakebin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let out = self.write("ssh_g.txt", g);
        let p = bin_dir.join("ssh");
        std::fs::write(&p, format!("#!/bin/sh\ncat '{out}'\n")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn path_env(&self) -> String {
        format!(
            "{}:{}",
            self.path("fakebin").display(),
            std::env::var("PATH").unwrap_or_default()
        )
    }
}

const RECIPE: &str = "version: 1\ntargets:\n  groups: [web]\nresources:\n  - id: a\n    type: file\n    with:\n      path: /tmp/sinter-progress-s5/a\n      content: x\n";

#[derive(Clone)]
struct Setup {
    term: &'static str,
    /// `SINTER_PROGRESS`; `None` removes it from the environment.
    progress: Option<&'static str>,
    /// stderr is a pty (stdout is always a pipe).
    stderr_tty: bool,
    /// Directory holding a scripted `ssh`, prepended to PATH.
    path: Option<String>,
}

impl Setup {
    fn piped(progress: Option<&'static str>) -> Setup {
        Setup {
            term: "xterm",
            progress,
            stderr_tty: false,
            path: None,
        }
    }

    fn tty(progress: Option<&'static str>) -> Setup {
        Setup {
            stderr_tty: true,
            ..Setup::piped(progress)
        }
    }

    fn with_path(self, path: Option<String>) -> Setup {
        Setup { path, ..self }
    }
}

struct Run {
    stdout: String,
    stderr: String,
    code: i32,
}

fn open_pty() -> (File, File) {
    let (mut m, mut s) = (0i32, 0i32);
    let mut ws = libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: openpty fills two descriptors; the pointers are live locals.
    let rc = unsafe {
        libc::openpty(
            &mut m,
            &mut s,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut ws,
        )
    };
    assert_eq!(rc, 0, "openpty");
    // SAFETY: both descriptors are fresh and owned here.
    unsafe { (File::from_raw_fd(m), File::from_raw_fd(s)) }
}

/// Run the binary; a pty's CRLF is folded to LF so both kinds compare.
fn run(args: &[&str], s: &Setup) -> Run {
    let mut cmd = Command::new(bin());
    cmd.args(args)
        .env("TERM", s.term)
        .env_remove("CI")
        // Colour is the persistent output's own business (a terminal stderr
        // paints the `sinter:` token); it is off here so both kinds compare.
        .env("NO_COLOR", "1")
        .env_remove("SINTER_PROGRESS")
        .stdin(Stdio::null())
        .stdout(Stdio::piped());
    if let Some(v) = s.progress {
        cmd.env("SINTER_PROGRESS", v);
    }
    if let Some(p) = &s.path {
        cmd.env("PATH", p);
    }
    let reader = if s.stderr_tty {
        let (master, slave) = open_pty();
        cmd.stderr(Stdio::from(slave));
        let mut master = master;
        Some(std::thread::spawn(move || {
            let mut out = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                match master.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => out.extend_from_slice(&buf[..n]),
                }
            }
            out
        }))
    } else {
        cmd.stderr(Stdio::piped());
        None
    };
    let child = cmd.spawn().unwrap();
    // Our copy of the slave end goes with `cmd`, so the reader sees EOF at exit.
    drop(cmd);
    let output = child.wait_with_output().unwrap();
    let stderr = match reader {
        Some(h) => String::from_utf8_lossy(&h.join().unwrap()).replace("\r\n", "\n"),
        None => String::from_utf8_lossy(&output.stderr).into_owned(),
    };
    Run {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr,
        code: output.status.code().unwrap(),
    }
}

fn refused<'a>(
    phase: &'a str,
    r: &'a str,
    kh: &'a str,
    port: &'a str,
    format: &'a str,
) -> Vec<&'a str> {
    vec![
        phase,
        r,
        "--host",
        "127.0.0.1",
        "--port",
        port,
        "--no-ssh-config",
        "--known-hosts",
        kh,
        "--format",
        format,
    ]
}

fn is_progress(line: &str) -> bool {
    line.starts_with("progress: ")
}

/// stderr with every progress line removed.
fn without_progress(stderr: &str) -> String {
    stderr
        .split_inclusive('\n')
        .filter(|l| !is_progress(l))
        .collect()
}

fn progress_lines(stderr: &str) -> Vec<&str> {
    stderr.lines().filter(|l| is_progress(l)).collect()
}

/// Plain progress is only whole, bounded ASCII lines: no escape sequence, no
/// carriage return, no colour, and never the red `sinter:` token.
fn assert_clean_lines(stderr: &str) {
    for line in progress_lines(stderr) {
        assert!(line.bytes().all(|b| (0x20..=0x7e).contains(&b)), "{line:?}");
        assert!(line.len() < 120, "{line:?}");
        assert!(!line.contains("sinter:"), "{line:?}");
    }
    assert!(!stderr.contains('\x1b'), "{stderr:?}");
    assert!(!stderr.contains('\r'), "{stderr:?}");
}

// ---------------------------------------------------------------------------
// the opt-in adds progress lines to stderr and changes nothing else
// ---------------------------------------------------------------------------

#[test]
fn plain_progress_only_adds_progress_lines_to_stderr() {
    let f = Fx::new();
    let r = f.write("web.yaml", RECIPE);
    let kh = f.write("known_hosts", "");
    let held = ClosedPorts::reserve(2);
    let ports = held.ports();
    let port = ports[0].to_string();
    let inv = f.inventory(ports);
    f.fake_ssh("hostname 127.0.0.1\n");
    let path = Some(f.path_env());
    for phase in ["plan", "apply", "audit"] {
        // Apply stops at the first failing execution; plan and audit try both.
        let hosts_run = if phase == "apply" { 1 } else { 2 };
        // (args, runs that reached progress, runs that failed)
        let cases: Vec<(Vec<&str>, usize, usize)> = vec![
            // single execution, connection refused
            (refused(phase, &r, &kh, &port, "text"), 1, 1),
            // resolve failure before any connection
            (vec![phase, &r, "--host=-bad", "--no-ssh-config"], 1, 1),
            // several executions: a resolution scope (it completes), then one
            // scope per host that was attempted (each is refused)
            (
                vec![phase, &r, "--hosts", &inv, "--no-ssh-config"],
                1 + hosts_run,
                hosts_run,
            ),
            // the same with a scripted `ssh -G`: the resolution scope has a
            // Resolve stage
            (vec![phase, &r, "--hosts", &inv], 1 + hosts_run, hosts_run),
        ];
        for (args, runs, failed_runs) in cases {
            let s = Setup::piped(None).with_path(path.clone());
            let want = run(&args, &s);
            assert!(want.code != 0, "{args:?} should fail");
            let got = run(
                &args,
                &Setup {
                    progress: Some("plain"),
                    ..s
                },
            );
            assert_eq!(got.code, want.code, "{args:?}: exit status");
            assert_eq!(
                got.stdout, want.stdout,
                "{args:?}: stdout is the report only"
            );
            assert_eq!(
                without_progress(&got.stderr),
                want.stderr,
                "{args:?}: every other stderr byte is unchanged"
            );
            assert_clean_lines(&got.stderr);

            let lines = progress_lines(&got.stderr);
            let count = |what: &str| {
                lines
                    .iter()
                    .filter(|l| l.starts_with(&format!("progress: run: {phase} {what}")))
                    .count()
            };
            assert_eq!(count("started"), runs, "{args:?}: {lines:?}");
            assert_eq!(
                count("completed") + count("failed"),
                runs,
                "{args:?}: every run ends: {lines:?}"
            );
            assert_eq!(count("failed"), failed_runs, "{args:?}: {lines:?}");
            assert!(lines.len() <= 12 * runs, "{args:?}: bounded: {lines:?}");
            // A run's error line comes after the lines of that run, never
            // between them: the last stderr line is whatever the run printed
            // last without progress.
            if let Some(last) = want.stderr.lines().last() {
                assert_eq!(got.stderr.lines().last(), Some(last), "{args:?}");
            }
            if args.contains(&"--port") {
                assert!(
                    lines
                        .iter()
                        .any(|l| l.starts_with("progress: connect: failed")),
                    "{args:?}: {lines:?}"
                );
            }
        }
    }
}

#[test]
fn a_scripted_resolution_shows_a_resolve_stage_and_a_failed_one_ends_failed() {
    let f = Fx::new();
    let r = f.write("web.yaml", RECIPE);
    f.fake_ssh("hostname 127.0.0.1\n");
    let path = Some(f.path_env());
    let s = Setup::piped(Some("plain")).with_path(path);
    let got = run(&["plan", &r, "--host=-bad"], &s);
    let lines = progress_lines(&got.stderr);
    // The host argument is refused after `ssh -G` was asked: the one host that
    // was queried is the whole stage, and it ends failed.
    assert_eq!(lines.len(), 4, "{lines:?}");
    assert!(lines[0].starts_with("progress: run: plan started"));
    assert_eq!(lines[1], "progress: resolve: start 0/1");
    assert!(
        lines[2].starts_with("progress: resolve: failed 1/1"),
        "{lines:?}"
    );
    assert!(lines[3].starts_with("progress: run: plan failed"));
    assert_clean_lines(&got.stderr);

    // Without `ssh -G` there is no resolve stage: only the run's own lines.
    let got = run(
        &["plan", &r, "--host=-bad", "--no-ssh-config"],
        &Setup::piped(Some("plain")),
    );
    let lines = progress_lines(&got.stderr);
    assert_eq!(lines.len(), 2, "no stage ever started: {lines:?}");
}

#[test]
fn an_invalid_recipe_starts_nothing_and_prints_no_progress() {
    let f = Fx::new();
    let bad = f.write("bad.yaml", "version: 2\n");
    for phase in ["plan", "apply", "audit"] {
        let args = [phase, bad.as_str()];
        let want = run(&args, &Setup::piped(None));
        let got = run(&args, &Setup::piped(Some("plain")));
        assert_eq!(got.stderr, want.stderr, "{phase}");
        assert_eq!(got.stdout, want.stdout, "{phase}");
        assert_eq!(got.code, want.code, "{phase}");
    }
}

#[test]
fn validate_never_shows_progress() {
    let f = Fx::new();
    let r = f.write("web.yaml", RECIPE);
    let got = run(&["validate", &r], &Setup::piped(Some("plain")));
    assert_eq!(got.stderr, "");
    assert_eq!(got.code, 0);
    let got = run(&["validate", &r], &Setup::tty(Some("plain")));
    assert_eq!(got.stderr, "");
}

// ---------------------------------------------------------------------------
// the switch is exact; nothing else turns plain progress on
// ---------------------------------------------------------------------------

#[test]
fn only_the_exact_value_plain_changes_anything() {
    let f = Fx::new();
    let r = f.write("web.yaml", RECIPE);
    let kh = f.write("known_hosts", "");
    let held = ClosedPorts::reserve(1);
    let port = held.port(0).to_string();
    let args = refused("plan", &r, &kh, &port, "text");
    let want = run(&args, &Setup::piped(None));
    assert!(progress_lines(&want.stderr).is_empty());
    for value in [
        "", "1", "true", "Plain", "PLAIN", "auto", "tty", "off", "plain ", "yes",
    ] {
        for setup in [Setup::piped(Some(value)), Setup::tty(Some(value))] {
            let tty = setup.stderr_tty;
            let got = run(&args, &setup);
            if tty {
                // On a terminal the automatic transient line may appear (S4);
                // the persistent output is what it always was, and no progress
                // line exists.
                assert!(progress_lines(&got.stderr).is_empty(), "{value:?}");
            } else {
                assert_eq!(
                    got.stderr, want.stderr,
                    "SINTER_PROGRESS={value:?} must change nothing on a pipe"
                );
            }
            assert_eq!(got.stdout, want.stdout, "{value:?}");
            assert_eq!(got.code, want.code, "{value:?}");
        }
    }
}

#[test]
fn json_is_byte_identical_with_plain_requested_on_every_stream() {
    let f = Fx::new();
    let r = f.write("web.yaml", RECIPE);
    let kh = f.write("known_hosts", "");
    let held = ClosedPorts::reserve(2);
    let ports = held.ports();
    let port = ports[0].to_string();
    let inv = f.inventory(ports);
    for phase in ["plan", "apply", "audit"] {
        let cases: Vec<Vec<&str>> = vec![
            refused(phase, &r, &kh, &port, "json"),
            vec![
                phase,
                &r,
                "--hosts",
                &inv,
                "--no-ssh-config",
                "--format",
                "json",
            ],
            vec![
                phase,
                &r,
                "--host=-bad",
                "--no-ssh-config",
                "--format",
                "json",
            ],
        ];
        for args in cases {
            for tty in [false, true] {
                let base = if tty {
                    Setup::tty(None)
                } else {
                    Setup::piped(None)
                };
                let want = run(&args, &base);
                let got = run(
                    &args,
                    &Setup {
                        progress: Some("plain"),
                        ..base
                    },
                );
                assert_eq!(got.stdout, want.stdout, "{args:?} tty={tty}");
                assert_eq!(got.stderr, want.stderr, "{args:?} tty={tty}");
                assert_eq!(got.code, want.code, "{args:?} tty={tty}");
                assert!(progress_lines(&got.stderr).is_empty());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// terminals: persistent lines, never a transient one, no TERM dependency
// ---------------------------------------------------------------------------

#[test]
fn on_a_terminal_plain_progress_is_persistent_lines_and_replaces_the_transient_line() {
    let f = Fx::new();
    let r = f.write("web.yaml", RECIPE);
    let kh = f.write("known_hosts", "");
    let held = ClosedPorts::reserve(1);
    let port = held.port(0).to_string();
    for phase in ["plan", "apply", "audit"] {
        let args = refused(phase, &r, &kh, &port, "text");
        let want = run(&args, &Setup::piped(None));
        for term in ["xterm", "dumb"] {
            let got = run(
                &args,
                &Setup {
                    term,
                    ..Setup::tty(Some("plain"))
                },
            );
            assert_eq!(got.code, want.code, "{phase} TERM={term}");
            assert_eq!(got.stdout, want.stdout, "{phase} TERM={term}");
            // No escape sequence at all (not even the S4 erase), no `\r`: the
            // transient renderer did not run, and plain lines are the same
            // lines a pipe gets.
            assert_clean_lines(&got.stderr);
            assert_eq!(
                without_progress(&got.stderr),
                want.stderr,
                "{phase} TERM={term}"
            );
            let lines = progress_lines(&got.stderr);
            assert!(lines.len() >= 4, "{phase} TERM={term}: {lines:?}");
            let piped_plain = run(&args, &Setup::piped(Some("plain")));
            assert_eq!(
                got.stderr, piped_plain.stderr,
                "{phase} TERM={term}: a terminal and a pipe get the same lines"
            );
        }
        // And without the request TERM=dumb still prints nothing extra.
        let dumb = run(
            &args,
            &Setup {
                term: "dumb",
                ..Setup::tty(None)
            },
        );
        assert_eq!(dumb.stderr, want.stderr, "{phase}");
    }
}

// ---------------------------------------------------------------------------
// secrets
// ---------------------------------------------------------------------------

#[test]
fn a_secret_bearing_recipe_has_no_plain_progress_at_all() {
    let f = Fx::new();
    std::fs::create_dir_all(f.path("secrets")).unwrap();
    let id = sinter::secrets::generate_identity();
    let ct = sinter::secrets::encrypt_to_recipients(
        b"S5-PLAIN-CANARY-PLAINTEXT",
        std::slice::from_ref(&id.recipient),
    )
    .unwrap();
    std::fs::write(f.path("secrets/S5PLAINREF.age"), ct).unwrap();
    let r = f.write(
        "secret.yaml",
        "version: 1\nresources:\n  - id: acct\n    type: user\n    with:\n      name: app\n      password_hash: { secret: secrets/S5PLAINREF.age }\n",
    );
    let kh = f.write("known_hosts", "");
    let held = ClosedPorts::reserve(1);
    let port = held.port(0).to_string();
    for phase in ["plan", "apply", "audit"] {
        let args = refused(phase, &r, &kh, &port, "text");
        let want = run(&args, &Setup::piped(None));
        for setup in [Setup::piped(Some("plain")), Setup::tty(Some("plain"))] {
            let got = run(&args, &setup);
            assert_eq!(got.code, want.code, "{phase}");
            assert_eq!(got.stdout, want.stdout, "{phase}");
            assert_eq!(
                got.stderr, want.stderr,
                "{phase}: not one progress line for a recipe that references secrets"
            );
            for canary in ["S5PLAINREF", "S5-PLAIN-CANARY", "password"] {
                assert!(!got.stderr.contains(canary), "{phase}: {canary}");
                assert!(!got.stdout.contains(canary), "{phase}: {canary}");
            }
        }
    }
}
