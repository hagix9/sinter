//! WP-PROGRESS S3: what the CLI binary prints.
//!
//! S3 ships a null renderer, so progress must be invisible everywhere: on a
//! terminal (where progress is automatic and the plumbing is active) the bytes
//! are exactly what a pipe receives, and in JSON mode no progress can exist on
//! any stream. These tests run the real binary under a pseudo-terminal
//! (`script(1)`, as `cli_multihost.rs` does) and compare it with the piped
//! run of the same command line, stdout and stderr merged in the same order.
//!
//! Only target-free failures are used (a closed loopback port, a bad recipe),
//! so the comparison is the same on every OS. Success output is covered by the
//! pinned suites (`json_contract`, `cli`, `cli_multihost`), which are unchanged.
#![cfg(unix)]
mod common;

use std::io::Write as _;
use std::process::{Command, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sinter")
}

struct Fx {
    dir: tempfile::TempDir,
    ports: Vec<u16>,
}

impl Fx {
    fn new() -> Self {
        let ls: Vec<_> = (0..2)
            .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let ports = ls.iter().map(|l| l.local_addr().unwrap().port()).collect();
        Fx {
            dir: tempfile::tempdir().unwrap(),
            ports,
        }
    }

    fn write(&self, name: &str, body: &str) -> String {
        let p = self.dir.path().join(name);
        std::fs::write(&p, body).unwrap();
        p.display().to_string()
    }
}

const RECIPE: &str = "version: 1\ntargets:\n  groups: [web]\nresources:\n  - id: a\n    type: file\n    with:\n      path: /tmp/sinter-progress-s3/a\n      content: x\n";

fn normalized(bytes: Vec<u8>) -> String {
    // A pty turns every newline into CRLF.
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\r' && bytes.get(i + 1) == Some(&b'\n') {
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    let text = String::from_utf8_lossy(&out).into_owned();
    // macOS `script` echoes the EOF it sends on its closed stdin as "^D" plus
    // two backspaces; it is the harness, not the binary.
    text.strip_prefix("^D\u{8}\u{8}")
        .map(str::to_string)
        .unwrap_or(text)
}

/// The binary under a pty (stdout and stderr are the terminal), plain output.
fn on_a_terminal(args: &[&str], term: &str) -> Option<String> {
    let mut c = if cfg!(target_os = "linux") {
        let quote = |a: &str| format!("'{}'", a.replace('\'', "'\\''"));
        let line = std::iter::once(bin())
            .chain(args.iter().copied())
            .map(quote)
            .collect::<Vec<_>>()
            .join(" ");
        let mut c = Command::new("script");
        c.args(["-qec", &line, "/dev/null"]);
        c
    } else {
        let mut c = Command::new("script");
        c.arg("-q").arg("/dev/null").arg(bin()).args(args);
        c
    };
    c.env("TERM", term)
        .env("NO_COLOR", "1")
        .env_remove("CI")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().ok()?;
    drop(child.stdin.take().map(|mut i| i.flush()));
    Some(normalized(child.wait_with_output().ok()?.stdout))
}

/// The same command line with stdout and stderr on pipes, merged in order.
fn piped(args: &[&str]) -> (String, i32) {
    let o = Command::new("sh")
        .arg("-c")
        .arg("exec \"$0\" \"$@\" 2>&1")
        .arg(bin())
        .args(args)
        .env("TERM", "xterm")
        .env("NO_COLOR", "1")
        .env_remove("CI")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        o.status.code().unwrap(),
    )
}

#[test]
fn a_terminal_run_prints_exactly_what_a_piped_run_prints() {
    let f = Fx::new();
    let r = f.write("web.yaml", RECIPE);
    let bad = f.write("bad.yaml", "version: 2\n");
    let kh = f.write("known_hosts", "");
    let inv = f.write(
        "hosts.yaml",
        &format!(
            "hosts:\n  web01:\n    address: 127.0.0.1\n    port: {}\n    user: u\n    known_hosts: {kh}\n  web02:\n    address: 127.0.0.1\n    port: {}\n    user: u\n    known_hosts: {kh}\ngroups:\n  web:\n    hosts: [web01, web02]\n",
            f.ports[0], f.ports[1]
        ),
    );
    let port = f.ports[0].to_string();
    for phase in ["plan", "apply", "audit"] {
        for fmt in ["text", "json"] {
            let cases: Vec<Vec<&str>> = vec![
                // single execution, connection refused (exit 3)
                vec![
                    phase,
                    &r,
                    "--host",
                    "127.0.0.1",
                    "--port",
                    &port,
                    "--no-ssh-config",
                    "--known-hosts",
                    &kh,
                    "--format",
                    fmt,
                ],
                // resolve failure before any connection
                vec![phase, &r, "--host=-bad", "--no-ssh-config", "--format", fmt],
                // several executions, every one refused
                vec![
                    phase,
                    &r,
                    "--hosts",
                    &inv,
                    "--no-ssh-config",
                    "--format",
                    fmt,
                ],
                // invalid recipe: nothing starts
                vec![phase, &bad, "--format", fmt],
            ];
            for args in cases {
                let (want, code) = piped(&args);
                assert!(code != 0, "{args:?} should fail: {want}");
                for term in ["xterm", "dumb"] {
                    let Some(got) = on_a_terminal(&args, term) else {
                        common::skip_or_fail("script(1) unavailable");
                        return;
                    };
                    assert_eq!(
                        got, want,
                        "{args:?} on a terminal (TERM={term}) differs from the piped run"
                    );
                    assert!(
                        !got.contains('\x1b'),
                        "{args:?}: no escape sequence on a terminal: {got:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn json_mode_on_a_terminal_adds_nothing_to_any_stream() {
    let f = Fx::new();
    let r = f.write("web.yaml", RECIPE);
    let kh = f.write("known_hosts", "");
    let port = f.ports[0].to_string();
    let args = [
        "plan",
        r.as_str(),
        "--host",
        "127.0.0.1",
        "--port",
        &port,
        "--no-ssh-config",
        "--known-hosts",
        &kh,
        "--format",
        "json",
    ];
    // Pre-report failure: stdout empty, exactly one `sinter:` line on stderr.
    let Some(got) = on_a_terminal(&args, "xterm") else {
        common::skip_or_fail("script(1) unavailable");
        return;
    };
    assert_eq!(got.lines().count(), 1, "{got:?}");
    assert!(
        got.starts_with("sinter: cannot connect to 127.0.0.1:"),
        "{got:?}"
    );
}
