//! WP-PROGRESS S4: the TTY transient renderer, observed from outside.
//!
//! These tests run the real `sinter` binary with **only stderr on a
//! pseudo-terminal** (`openpty`), so stream separation is provable: stdout is a
//! pipe, stderr is the terminal, and what the terminal receives is parsed into
//! transient frames (`CR ESC[2K <text>`) and persistent text.
//!
//! Only target-free failures are used (a closed loopback port, a scripted
//! `ssh -G`, a bad recipe), so the same assertions hold on every OS:
//!
//! * the persistent output of a terminal run, with the transient bytes removed,
//!   is exactly what the piped run of the same command line prints;
//! * progress is drawn only on a text-mode run whose stderr is a terminal with
//!   `TERM != dumb`, and never for a recipe that references secrets;
//! * every frame is one printable-ASCII line within the terminal width.
//!
//! The renderer itself (formatting, sanitization, elapsed, width, teardown) is
//! unit-tested in `src/progress_tty/tests.rs`; success-path equivalence on a real
//! host belongs to the later full WP-PROGRESS gate.
#![cfg(unix)]

use std::fs::File;
use std::io::Read;
use std::os::fd::FromRawFd;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const CLEAR: &str = "\r\x1b[2K";

mod common;
use common::ClosedPorts;

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

const RECIPE: &str = "version: 1\ntargets:\n  groups: [web]\nresources:\n  - id: a\n    type: file\n    with:\n      path: /tmp/sinter-progress-s4/a\n      content: x\n";

#[derive(Clone, Copy, PartialEq)]
enum Stream {
    Pipe,
    Pty,
}

#[derive(Clone)]
struct Setup {
    term: &'static str,
    /// `Some("1")` sets NO_COLOR, `None` removes it.
    no_color: Option<&'static str>,
    stdout: Stream,
    stderr: Stream,
    /// Terminal width reported on the pty(s); 0 is what a fresh pty reports.
    cols: u16,
    /// Directory holding a scripted `ssh`, prepended to PATH.
    path: Option<String>,
}

impl Setup {
    fn tty() -> Setup {
        Setup {
            term: "xterm",
            no_color: Some("1"),
            stdout: Stream::Pipe,
            stderr: Stream::Pty,
            cols: 0,
            path: None,
        }
    }

    fn piped() -> Setup {
        Setup {
            stderr: Stream::Pipe,
            ..Setup::tty()
        }
    }
}

struct Pty {
    master: File,
    slave: File,
}

fn open_pty(cols: u16) -> Pty {
    let mut master = -1;
    let mut slave = -1;
    let mut ws = libc::winsize {
        ws_row: 24,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: openpty fills two descriptors; the pointers are live locals.
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut ws,
        )
    };
    assert_eq!(rc, 0, "openpty failed");
    // SAFETY: both descriptors are fresh and owned by nobody else.
    unsafe {
        Pty {
            master: File::from_raw_fd(master),
            slave: File::from_raw_fd(slave),
        }
    }
}

struct Run {
    stdout: String,
    stderr: String,
    code: i32,
}

/// Run the binary; whatever is on a pty comes back with CRLF folded to LF.
fn run(args: &[&str], s: &Setup) -> Run {
    let mut cmd = Command::new(bin());
    cmd.args(args)
        .env("TERM", s.term)
        .env_remove("CI")
        .env_remove("NO_COLOR")
        .stdin(Stdio::null());
    if let Some(v) = s.no_color {
        cmd.env("NO_COLOR", v);
    }
    if let Some(p) = &s.path {
        cmd.env("PATH", p);
    }
    let mut readers: Vec<(bool, std::thread::JoinHandle<Vec<u8>>)> = Vec::new();
    for (is_err, stream) in [(false, s.stdout), (true, s.stderr)] {
        if stream == Stream::Pty {
            let pty = open_pty(s.cols);
            let stdio = Stdio::from(pty.slave.try_clone().unwrap());
            if is_err {
                cmd.stderr(stdio);
            } else {
                cmd.stdout(stdio);
            }
            let mut master = pty.master;
            // Keep our slave end open until the child is gone is not needed: the
            // child holds its own copy; ours is dropped with `pty.slave` below.
            drop(pty.slave);
            readers.push((
                is_err,
                std::thread::spawn(move || {
                    let mut out = Vec::new();
                    let mut buf = [0u8; 4096];
                    loop {
                        match master.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => out.extend_from_slice(&buf[..n]),
                        }
                    }
                    out
                }),
            ));
        } else if is_err {
            cmd.stderr(Stdio::piped());
        } else {
            cmd.stdout(Stdio::piped());
        }
    }
    let child = cmd.spawn().unwrap();
    // Close our copies of the slave ends so the readers see EOF at exit.
    drop(cmd);
    let output = child.wait_with_output().unwrap();
    let mut stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let mut stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    for (is_err, h) in readers {
        let bytes = h.join().unwrap();
        let text = String::from_utf8_lossy(&bytes).replace("\r\n", "\n");
        if is_err {
            stderr = text;
        } else {
            stdout = text;
        }
    }
    Run {
        stdout,
        stderr,
        code: output.status.code().unwrap(),
    }
}

/// Split a terminal stream into persistent text and transient frames.
/// A draw is `CLEAR text`, an erase is `CLEAR`; a frame never contains a
/// newline and persistent text always ends with one.
fn split_transient(stream: &str) -> (String, Vec<String>) {
    let mut persistent = String::new();
    let mut frames = Vec::new();
    for seg in stream.split(CLEAR) {
        if seg.is_empty() {
            continue;
        }
        if seg.contains('\n') {
            persistent.push_str(seg);
        } else {
            frames.push(seg.to_string());
        }
    }
    (persistent, frames)
}

fn assert_clean_frames(frames: &[String], max: usize) {
    for f in frames {
        assert!(
            f.bytes().all(|b| (0x20..=0x7e).contains(&b)),
            "frame is not printable ASCII: {f:?}"
        );
        assert!(f.chars().count() <= max, "frame wider than {max}: {f:?}");
    }
}

fn strip_sgr(s: &str) -> String {
    let mut out = String::new();
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\x1b' && it.peek() == Some(&'[') {
            for d in it.by_ref() {
                if d.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn refused_args<'a>(r: &'a str, kh: &'a str, port: &'a str, phase: &'a str) -> Vec<&'a str> {
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
    ]
}

// ---------------------------------------------------------------------------
// eligible: a terminal on stderr
// ---------------------------------------------------------------------------

#[test]
fn an_eligible_run_draws_on_stderr_only_and_its_persistent_output_is_unchanged() {
    let f = Fx::new();
    let r = f.write("web.yaml", RECIPE);
    let kh = f.write("known_hosts", "");
    let held = ClosedPorts::reserve(1);
    let port = held.port(0).to_string();
    for phase in ["plan", "apply", "audit"] {
        let args = refused_args(&r, &kh, &port, phase);
        let want = run(&args, &Setup::piped());
        assert_ne!(want.code, 0);
        let got = run(&args, &Setup::tty());
        assert_eq!(got.code, want.code, "{phase}: exit status");
        assert_eq!(
            got.stdout, want.stdout,
            "{phase}: stdout is the report only"
        );
        assert!(
            !got.stdout.contains('\x1b'),
            "{phase}: no control byte on stdout"
        );
        let (persistent, frames) = split_transient(&got.stderr);
        assert_eq!(persistent, want.stderr, "{phase}: persistent stderr");
        assert!(
            !frames.is_empty(),
            "{phase}: nothing was drawn: {:?}",
            got.stderr
        );
        assert_eq!(frames[0], "connect", "{phase}");
        assert_clean_frames(&frames, 59);
        // The terminal is left clean: the last transient write is an erase.
        let before_error = got.stderr.split_once("sinter:").unwrap().0;
        assert!(before_error.ends_with(CLEAR), "{phase}: {:?}", got.stderr);
        assert!(got.stderr.starts_with(CLEAR), "{phase}");
    }
}

#[test]
fn colour_settings_never_change_the_persistent_output() {
    let f = Fx::new();
    let r = f.write("web.yaml", RECIPE);
    let kh = f.write("known_hosts", "");
    let held = ClosedPorts::reserve(1);
    let port = held.port(0).to_string();
    let args = refused_args(&r, &kh, &port, "plan");
    let plain = run(&args, &Setup::piped());
    // NO_COLOR: no colour, only the transient sequence appears.
    let got = run(&args, &Setup::tty());
    let (persistent, _) = split_transient(&got.stderr);
    assert_eq!(persistent, plain.stderr);
    assert!(!persistent.contains('\x1b'));
    // Colour on (as before progress existed): the error token is painted, the
    // text is the same, and the progress does not change what is painted.
    let coloured = run(
        &args,
        &Setup {
            no_color: None,
            ..Setup::tty()
        },
    );
    let (persistent, frames) = split_transient(&coloured.stderr);
    assert!(
        persistent.starts_with("\x1b[31msinter:\x1b[0m "),
        "{persistent:?}"
    );
    assert_eq!(strip_sgr(&persistent), plain.stderr);
    assert_clean_frames(&frames, 59);
    assert!(!frames.is_empty());
}

#[test]
fn the_terminal_width_bounds_every_frame() {
    let f = Fx::new();
    let r = f.write("web.yaml", RECIPE);
    let kh = f.write("known_hosts", "");
    let held = ClosedPorts::reserve(1);
    let port = held.port(0).to_string();
    let args = refused_args(&r, &kh, &port, "plan");
    let want = run(&args, &Setup::piped());
    // (reported width, widest frame allowed, "connect" shown whole?)
    for (cols, max, whole) in [
        (80u16, 79usize, true),
        (10, 9, true),
        (8, 7, true),
        (6, 5, false),
        (2, 1, false),
    ] {
        let got = run(
            &args,
            &Setup {
                cols,
                ..Setup::tty()
            },
        );
        let (persistent, frames) = split_transient(&got.stderr);
        assert_eq!(persistent, want.stderr, "cols={cols}");
        assert_eq!(got.code, want.code);
        assert!(!frames.is_empty(), "cols={cols}: {:?}", got.stderr);
        assert_clean_frames(&frames, max);
        assert_eq!(frames[0] == "connect", whole, "cols={cols}: {frames:?}");
    }
}

#[test]
fn a_terminal_one_column_wide_has_no_room_for_a_line_and_nothing_breaks() {
    let f = Fx::new();
    let r = f.write("web.yaml", RECIPE);
    let kh = f.write("known_hosts", "");
    let held = ClosedPorts::reserve(1);
    let port = held.port(0).to_string();
    let args = refused_args(&r, &kh, &port, "plan");
    let want = run(&args, &Setup::piped());
    let got = run(
        &args,
        &Setup {
            cols: 1,
            ..Setup::tty()
        },
    );
    assert_eq!(
        got.stderr, want.stderr,
        "no frame, no erase: byte-identical"
    );
    assert_eq!(got.code, want.code);
}

#[test]
fn an_unknown_width_uses_the_documented_fallback() {
    // A fresh pty reports 0 columns, which means "unknown": 60 columns, 59 usable.
    let f = Fx::new();
    let r = f.write("web.yaml", RECIPE);
    let kh = f.write("known_hosts", "");
    let held = ClosedPorts::reserve(1);
    let port = held.port(0).to_string();
    let args = refused_args(&r, &kh, &port, "plan");
    let got = run(
        &args,
        &Setup {
            cols: 0,
            ..Setup::tty()
        },
    );
    let (_, frames) = split_transient(&got.stderr);
    assert_eq!(frames[0], "connect");
}

// ---------------------------------------------------------------------------
// ineligible: no byte of progress
// ---------------------------------------------------------------------------

#[test]
fn json_on_a_terminal_has_no_progress_on_any_stream() {
    let f = Fx::new();
    let r = f.write("web.yaml", RECIPE);
    let kh = f.write("known_hosts", "");
    let held = ClosedPorts::reserve(1);
    let port = held.port(0).to_string();
    for phase in ["plan", "apply", "audit"] {
        let mut args = refused_args(&r, &kh, &port, phase);
        args.extend(["--format", "json"]);
        let want = run(&args, &Setup::piped());
        let got = run(&args, &Setup::tty());
        assert_eq!(got.stderr, want.stderr, "{phase}");
        assert_eq!(got.stdout, want.stdout, "{phase}");
        assert_eq!(got.code, want.code, "{phase}");
        assert!(!got.stderr.contains('\x1b'), "{phase}");
        assert_eq!(got.stderr.lines().count(), 1, "{phase}: one sinter: line");
    }
}

#[test]
fn term_dumb_has_no_progress() {
    let f = Fx::new();
    let r = f.write("web.yaml", RECIPE);
    let kh = f.write("known_hosts", "");
    let held = ClosedPorts::reserve(1);
    let port = held.port(0).to_string();
    let args = refused_args(&r, &kh, &port, "plan");
    let want = run(&args, &Setup::piped());
    for no_color in [Some("1"), None] {
        let got = run(
            &args,
            &Setup {
                term: "dumb",
                no_color,
                ..Setup::tty()
            },
        );
        assert_eq!(got.stderr, want.stderr, "NO_COLOR={no_color:?}");
        assert_eq!(got.stdout, want.stdout);
    }
}

#[test]
fn a_non_terminal_stderr_has_no_progress_even_when_stdout_is_a_terminal() {
    let f = Fx::new();
    let r = f.write("web.yaml", RECIPE);
    let kh = f.write("known_hosts", "");
    let held = ClosedPorts::reserve(1);
    let port = held.port(0).to_string();
    let args = refused_args(&r, &kh, &port, "plan");
    let want = run(&args, &Setup::piped());
    let got = run(
        &args,
        &Setup {
            stdout: Stream::Pty,
            stderr: Stream::Pipe,
            ..Setup::tty()
        },
    );
    assert_eq!(got.stderr, want.stderr);
    assert!(!got.stderr.contains('\x1b'));
    assert!(!got.stdout.contains('\x1b'));
    // CI-style pipes, with CI set: still nothing.
    let o = Command::new(bin())
        .args(&args)
        .env("TERM", "xterm")
        .env("CI", "1")
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&o.stderr), want.stderr);
}

#[test]
fn validate_never_shows_progress() {
    let f = Fx::new();
    let r = f.write("web.yaml", RECIPE);
    let got = run(&["validate", &r], &Setup::tty());
    assert_eq!(got.stderr, "");
    assert_eq!(got.code, 0);
}

#[test]
fn a_secret_bearing_recipe_has_no_progress_at_all() {
    let f = Fx::new();
    std::fs::create_dir_all(f.path("secrets")).unwrap();
    let id = sinter::secrets::generate_identity();
    let ct = sinter::secrets::encrypt_to_recipients(
        b"S4-PTY-CANARY-PLAINTEXT",
        std::slice::from_ref(&id.recipient),
    )
    .unwrap();
    std::fs::write(f.path("secrets/S4PTYREF.age"), ct).unwrap();
    let r = f.write(
        "secret.yaml",
        "version: 1\nresources:\n  - id: acct\n    type: user\n    with:\n      name: app\n      password_hash: { secret: secrets/S4PTYREF.age }\n",
    );
    let kh = f.write("known_hosts", "");
    let held = ClosedPorts::reserve(1);
    let port = held.port(0).to_string();
    for phase in ["plan", "apply", "audit"] {
        let args = refused_args(&r, &kh, &port, phase);
        let want = run(&args, &Setup::piped());
        let got = run(&args, &Setup::tty());
        assert_eq!(got.code, want.code, "{phase}");
        assert_eq!(
            got.stderr, want.stderr,
            "{phase}: not a frame, not even an erase"
        );
        assert!(!got.stderr.contains('\x1b'), "{phase}");
        for canary in ["S4PTYREF", "S4-PTY-CANARY", "acct", "password"] {
            assert!(!got.stdout.contains(canary), "{phase}: {canary} on stdout");
            assert!(
                !got.stderr.replace(&want.stderr, "").contains(canary),
                "{phase}: {canary} in the progress bytes"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// several scopes
// ---------------------------------------------------------------------------

#[test]
fn every_scope_draws_and_erases_its_own_line_and_nothing_accumulates() {
    let f = Fx::new();
    let r = f.write("web.yaml", RECIPE);
    let held = ClosedPorts::reserve(2);
    let ports = held.ports();
    let inv = f.inventory(ports);
    // `ssh -G` is scripted, so the resolution scope has a Resolve stage.
    f.fake_ssh("hostname 127.0.0.1\n");
    let path = Some(f.path_env());
    for phase in ["plan", "apply", "audit"] {
        let args = [phase, r.as_str(), "--hosts", inv.as_str()];
        let want = run(
            &args,
            &Setup {
                path: path.clone(),
                ..Setup::piped()
            },
        );
        let got = run(
            &args,
            &Setup {
                path: path.clone(),
                ..Setup::tty()
            },
        );
        assert_eq!(got.code, want.code, "{phase}");
        assert_eq!(
            got.stdout, want.stdout,
            "{phase}: stdout is the report only"
        );
        let (persistent, frames) = split_transient(&got.stderr);
        assert_eq!(persistent, want.stderr, "{phase}: persistent stderr");
        assert_clean_frames(&frames, 59);
        let joined = frames.join("|");
        assert!(joined.contains("resolve 0/2"), "{phase}: {joined}");
        assert!(joined.contains("connect"), "{phase}: {joined}");
        // A draw is always followed by an erase before any persistent text, and
        // the stream ends with the terminal clean.
        for (i, _) in got.stderr.match_indices("sinter:") {
            assert!(
                got.stderr[..i].ends_with(CLEAR),
                "{phase}: error line not at column 0"
            );
        }
        assert!(
            got.stderr
                .rsplit_once(CLEAR)
                .is_some_and(|(_, tail)| tail.is_empty() || tail.ends_with('\n')),
            "{phase}: a frame is left behind"
        );
        // Apply stops at the first failing execution; plan and audit try both.
        let connects = frames.iter().filter(|f| *f == "connect").count();
        let want_connects = if phase == "apply" { 1 } else { 2 };
        assert_eq!(connects, want_connects, "{phase}: {frames:?}");
    }
}

#[test]
fn a_resolve_failure_leaves_no_line_behind() {
    let f = Fx::new();
    let r = f.write("web.yaml", RECIPE);
    f.fake_ssh("hostname 127.0.0.1\n");
    let args = ["plan", r.as_str(), "--host=-bad"];
    let path = Some(f.path_env());
    let want = run(
        &args,
        &Setup {
            path: path.clone(),
            ..Setup::piped()
        },
    );
    let got = run(
        &args,
        &Setup {
            path,
            ..Setup::tty()
        },
    );
    let (persistent, frames) = split_transient(&got.stderr);
    assert_eq!(persistent, want.stderr);
    assert_eq!(got.code, want.code);
    assert!(
        frames.iter().all(|f| f.starts_with("resolve")),
        "{frames:?}"
    );
}

#[test]
fn an_invalid_recipe_starts_nothing() {
    let f = Fx::new();
    let bad = f.write("bad.yaml", "version: 2\n");
    for phase in ["plan", "apply", "audit"] {
        let args = [phase, bad.as_str()];
        let want = run(&args, &Setup::piped());
        let got = run(&args, &Setup::tty());
        assert_eq!(got.stderr, want.stderr, "{phase}");
        assert_eq!(got.code, want.code, "{phase}");
    }
}

// ---------------------------------------------------------------------------
// the fixture's own premise (S4-L1)
// ---------------------------------------------------------------------------

#[test]
fn closed_ports_are_refused_and_no_two_live_reservations_overlap() {
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    // Closed: a connection is refused, not accepted and not hung.
    {
        let held = ClosedPorts::reserve(4);
        let mut distinct = held.ports().to_vec();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), 4, "the ports are distinct");
        for &port in held.ports() {
            let err = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused, "{port}");
        }
    }

    // The old fixture's failure: while one test still had to connect to its
    // port, a sibling's `bind(0)` was handed the same number. Here many threads
    // reserve and "connect later" (a pause stands for the child's spawn) and a
    // registry of live reservations must never see a port twice, nor see any
    // port that another reservation could have taken.
    let live: Arc<Mutex<HashSet<u16>>> = Arc::default();
    let handles: Vec<_> = (0..6)
        .map(|_| {
            let live = live.clone();
            std::thread::spawn(move || {
                for _ in 0..50 {
                    let held = ClosedPorts::reserve(2);
                    {
                        let mut live = live.lock().unwrap();
                        for &p in held.ports() {
                            assert!(live.insert(p), "port {p} is in two live reservations");
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    // Nothing took them in the meantime: still refused.
                    for &p in held.ports() {
                        let err = std::net::TcpStream::connect(("127.0.0.1", p)).unwrap_err();
                        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused, "{p}");
                    }
                    let mut live = live.lock().unwrap();
                    for &p in held.ports() {
                        live.remove(&p);
                    }
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}
