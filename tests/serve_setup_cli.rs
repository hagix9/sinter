//! `sinter serve init | check | rotate-key` end to end (ADR 0002 r6, Phase 1A).
//!
//! The key is typed into a real pseudo-terminal (a small Python `pty` driver),
//! so these tests see exactly what an operator's terminal would show. Only an
//! obviously synthetic key is used; a scripted stand-in replaces
//! `tunnel-client` (no OpenAI contact).
#![cfg(unix)]

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

const KEY: &str = "sk-SYNTHETIC-SETUP-CLI-0123456789";
const NEW_KEY: &str = "sk-SYNTHETIC-SETUP-ROTATED-9876543210";
const ID: &str = "tunnel_0123456789abcdef0123456789abcdef";

/// Runs `argv` in a new session on a pseudo-terminal. `answers` are typed one
/// per prompt line (a prompt ends with ": "). Prints everything the terminal
/// showed, then `EXIT <code>`.
const PTY_DRIVER: &str = r#"
import os, pty, sys, select, json
argv = json.loads(sys.argv[1]); answers = json.loads(sys.argv[2])
pid, fd = pty.fork()
if pid == 0:
    os.execv(argv[0], argv)
out = b""; i = 0
while True:
    r, _, _ = select.select([fd], [], [], 20)
    if not r:
        break
    try:
        data = os.read(fd, 4096)
    except OSError:
        break
    if not data:
        break
    out += data
    while i < len(answers) and out.count(b": ") > i:
        try:
            os.write(fd, answers[i].encode() + b"\n")
        except OSError:
            pass
        i += 1
_, status = os.waitpid(pid, 0)
sys.stdout.write(out.decode("utf-8", "replace"))
sys.stdout.write("\nEXIT %d\n" % (os.waitstatus_to_exitcode(status)))
"#;

/// Runs `argv` with no controlling terminal at all (new session, no tty).
const NOTTY_DRIVER: &str = r#"
import os, sys, json, subprocess
argv = json.loads(sys.argv[1])
p = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, start_new_session=True)
sys.stdout.write(p.stdout.decode() + p.stderr.decode() + "\nEXIT %d\n" % p.returncode)
"#;

fn json_list(v: &[String]) -> String {
    serde_json::to_string(v).unwrap()
}

fn base_tmp() -> PathBuf {
    let t = std::env::temp_dir();
    if t.to_string_lossy().contains(' ') {
        PathBuf::from("/tmp")
    } else {
        t
    }
}

struct Env {
    d: tempfile::TempDir,
}

impl Env {
    fn new(client_body: &str) -> Self {
        let d = tempfile::Builder::new()
            .prefix("serve-setup-")
            .tempdir_in(base_tmp())
            .unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let e = Env { d };
        let c = e.p("tunnel-client");
        std::fs::write(&c, client_body).unwrap();
        std::fs::set_permissions(&c, std::fs::Permissions::from_mode(0o755)).unwrap();
        e
    }
    fn p(&self, n: &str) -> PathBuf {
        self.d.path().join(n)
    }
    fn args(&self, sub: &[&str]) -> Vec<String> {
        let mut v = vec![
            env!("CARGO_BIN_EXE_sinter").to_string(),
            "serve".to_string(),
        ];
        v.extend(sub.iter().map(|s| s.to_string()));
        v
    }
}

/// A stand-in that records its arguments and environment, and answers like
/// `doctor` and `admin tunnels get` would.
const CLIENT_OK: &str = "#!/bin/sh\nd=$(dirname \"$0\")\n{ for a in \"$@\"; do printf 'ARG %s\\n' \"$a\"; done; env | sed 's/^/ENV /'; } >> \"$d/calls\"\ncase \"$1\" in doctor) echo 'CHECK control_plane_api_key PASS file:x'; echo 'RESULT ok';; admin) echo '{\"id\":\"tunnel_x\",\"organization_ids\":[\"org-SYNTHETIC-ORG\"]}';; esac\nexit 0\n";

fn pty(argv: &[String], answers: &[&str]) -> (i32, String) {
    let a: Vec<String> = answers.iter().map(|s| s.to_string()).collect();
    let o = Command::new("python3")
        .args(["-c", PTY_DRIVER, &json_list(argv), &json_list(&a)])
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&o.stdout).into_owned();
    let code = s
        .lines()
        .rev()
        .find_map(|l| l.strip_prefix("EXIT ").map(|c| c.trim().parse().unwrap()))
        .expect(&s);
    (code, s)
}

fn notty(argv: &[String]) -> (i32, String) {
    let o = Command::new("python3")
        .args(["-c", NOTTY_DRIVER, &json_list(argv)])
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&o.stdout).into_owned();
    let code = s
        .lines()
        .rev()
        .find_map(|l| l.strip_prefix("EXIT ").map(|c| c.trim().parse().unwrap()))
        .expect(&s);
    (code, s)
}

/// The path of this sinter is placed into `--mcp.command`, so `init` refuses
/// it when it holds a space (as the macOS development tree does). The CLI
/// tests then report a skip; they run on Linux CI and in the Linux VM.
fn exe_is_command_safe() -> bool {
    let exe = std::fs::canonicalize(env!("CARGO_BIN_EXE_sinter")).unwrap();
    let ok = sinter::serve::path_is_command_safe(&exe);
    if !ok {
        eprintln!(
            "SKIP: the test binary path is not command-safe: {}",
            exe.display()
        );
    }
    ok
}

fn mode(p: &Path) -> u32 {
    std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
}

fn init_ok(e: &Env, extra: &[&str]) -> String {
    let client = e.p("tunnel-client");
    let config = e.p("conf/serve.toml");
    let mut sub = vec![
        "init",
        "--config",
        config.to_str().unwrap(),
        "--client",
        client.to_str().unwrap(),
    ];
    sub.extend_from_slice(extra);
    let (code, out) = pty(&e.args(&sub), &[ID, KEY]);
    assert_eq!(code, 0, "{out}");
    out
}

#[test]
fn init_on_a_terminal_never_shows_the_key_and_writes_private_files() {
    if !exe_is_command_safe() {
        return;
    }
    let e = Env::new(CLIENT_OK);
    let out = init_ok(&e, &[]);
    assert!(out.contains("Tunnel ID"), "{out}");
    assert!(out.contains(ID), "the tunnel ID is echoed as typed: {out}");
    assert!(out.contains("input is not shown"), "{out}");
    assert!(
        !out.contains(KEY),
        "the key was shown on the terminal:\n{out}"
    );
    let key = e.p("conf/runtime-key");
    assert_eq!(std::fs::read_to_string(&key).unwrap(), KEY);
    assert_eq!(mode(&key), 0o600);
    assert_eq!(mode(&e.p("conf/serve.toml")), 0o600);
    assert_eq!(mode(&e.p("conf")), 0o700);
    assert_eq!(std::fs::metadata(&key).unwrap().uid(), unsafe {
        libc::geteuid()
    });
    assert!(!std::fs::read_to_string(e.p("conf/serve.toml"))
        .unwrap()
        .contains(KEY));
    // doctor ran with the key as a file: reference, never in argv or env.
    let calls = std::fs::read_to_string(e.p("calls")).unwrap();
    assert!(calls.contains("ARG doctor"), "{calls}");
    assert!(
        calls.contains(&format!("ARG file:{}", key.display())),
        "{calls}"
    );
    assert!(
        !calls.contains(KEY),
        "the key reached the client's argv or environment"
    );
    assert!(
        !calls.contains("ARG admin"),
        "no online lookup without --check-online"
    );
    assert!(out.contains("tunnel-client doctor: OK"), "{out}");
}

#[test]
fn check_online_uses_a_file_reference_and_shows_no_identifiers() {
    if !exe_is_command_safe() {
        return;
    }
    let e = Env::new(CLIENT_OK);
    let out = init_ok(&e, &["--check-online"]);
    let calls = std::fs::read_to_string(e.p("calls")).unwrap();
    assert!(
        calls.contains("ARG admin\nARG --admin-key\nARG file:"),
        "{calls}"
    );
    assert!(calls.contains(&format!("ARG get\nARG {ID}")), "{calls}");
    assert!(
        out.contains("online lookup of the tunnel with this key: OK"),
        "{out}"
    );
    assert!(
        !out.contains("org-SYNTHETIC-ORG"),
        "organization identifiers are not shown: {out}"
    );
    assert!(!calls.contains(KEY));
}

#[test]
fn init_without_a_terminal_is_refused_and_writes_nothing() {
    let e = Env::new(CLIENT_OK);
    let config = e.p("conf/serve.toml");
    let (code, out) = notty(&e.args(&[
        "init",
        "--config",
        config.to_str().unwrap(),
        "--tunnel-id",
        ID,
    ]));
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("terminal"), "{out}");
    assert!(!e.p("conf").exists());
}

#[test]
fn init_does_not_replace_an_existing_setup() {
    if !exe_is_command_safe() {
        return;
    }
    let e = Env::new(CLIENT_OK);
    init_ok(&e, &[]);
    let before = std::fs::read(e.p("conf/runtime-key")).unwrap();
    let client = e.p("tunnel-client");
    let config = e.p("conf/serve.toml");
    let (code, out) = pty(
        &e.args(&[
            "init",
            "--config",
            config.to_str().unwrap(),
            "--client",
            client.to_str().unwrap(),
        ]),
        &[ID, NEW_KEY],
    );
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("already exists"), "{out}");
    assert!(
        !out.contains("input is not shown"),
        "the key is not even asked for: {out}"
    );
    assert_eq!(std::fs::read(e.p("conf/runtime-key")).unwrap(), before);
}

#[test]
fn interrupting_the_key_prompt_leaves_nothing_behind() {
    if !exe_is_command_safe() {
        return;
    }
    let e = Env::new(CLIENT_OK);
    let client = e.p("tunnel-client");
    let config = e.p("conf/serve.toml");
    // Ctrl-D (end of input) at the key prompt.
    let (code, out) = pty(
        &e.args(&[
            "init",
            "--config",
            config.to_str().unwrap(),
            "--client",
            client.to_str().unwrap(),
        ]),
        &[ID, "\u{4}"],
    );
    assert_ne!(code, 0, "{out}");
    assert!(
        !e.p("conf").exists(),
        "the directory created by this run is removed: {out}"
    );
}

#[test]
fn ctrl_c_at_the_key_prompt_leaves_nothing_and_restores_the_terminal() {
    if !exe_is_command_safe() {
        return;
    }
    let e = Env::new(CLIENT_OK);
    let client = e.p("tunnel-client");
    let config = e.p("conf/serve.toml");
    // Ctrl-C (the terminal's interrupt character) at the key prompt.
    let (code, out) = pty(
        &e.args(&[
            "init",
            "--config",
            config.to_str().unwrap(),
            "--client",
            client.to_str().unwrap(),
        ]),
        &[ID, "\u{3}"],
    );
    assert_ne!(code, 0, "{out}");
    assert!(
        !e.p("conf").exists(),
        "nothing may remain after Ctrl-C: {out}"
    );
}

#[test]
fn a_failing_doctor_is_exit_3_with_the_files_kept() {
    if !exe_is_command_safe() {
        return;
    }
    let e = Env::new("#!/bin/sh\necho 'CHECK control_plane_api_key FAIL unreadable'\nexit 2\n");
    let client = e.p("tunnel-client");
    let config = e.p("conf/serve.toml");
    let (code, out) = pty(
        &e.args(&[
            "init",
            "--config",
            config.to_str().unwrap(),
            "--client",
            client.to_str().unwrap(),
        ]),
        &[ID, KEY],
    );
    assert_eq!(code, 3, "{out}");
    assert!(out.contains("doctor FAILED"), "{out}");
    assert!(e.p("conf/serve.toml").exists() && e.p("conf/runtime-key").exists());
}

#[test]
fn check_and_rotate_key() {
    if !exe_is_command_safe() {
        return;
    }
    let e = Env::new(CLIENT_OK);
    init_ok(&e, &[]);
    let config = e.p("conf/serve.toml");
    let (code, out) = notty(&e.args(&["check", "--config", config.to_str().unwrap()]));
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("tunnel-client doctor: OK"), "{out}");
    let (code, out) = pty(
        &e.args(&["rotate-key", "--config", config.to_str().unwrap()]),
        &[NEW_KEY],
    );
    assert_eq!(code, 0, "{out}");
    assert!(!out.contains(NEW_KEY) && !out.contains(KEY), "{out}");
    assert_eq!(
        std::fs::read_to_string(e.p("conf/runtime-key")).unwrap(),
        NEW_KEY
    );
    assert_eq!(mode(&e.p("conf/runtime-key")), 0o600);
    assert_eq!(
        std::fs::read_dir(e.p("conf")).unwrap().count(),
        2,
        "no backup or temporary file"
    );
    // A broken configuration is exit 2 for check.
    std::fs::write(&config, "[tunnel]\nid = \"x\"\n").unwrap();
    let (code, _) = notty(&e.args(&["check", "--config", config.to_str().unwrap()]));
    assert_eq!(code, 2);
}

#[test]
fn serve_without_a_subcommand_still_starts_and_conflicting_use_is_refused() {
    let o = Command::new(env!("CARGO_BIN_EXE_sinter"))
        .args(["serve", "--help"])
        .output()
        .unwrap();
    let h = String::from_utf8_lossy(&o.stdout);
    for s in ["init", "check", "rotate-key", "--max-duration"] {
        assert!(h.contains(s), "{s} missing in help:\n{h}");
    }
    let o = Command::new(env!("CARGO_BIN_EXE_sinter"))
        .args(["serve", "--max-duration", "1h", "check"])
        .output()
        .unwrap();
    assert_eq!(
        o.status.code(),
        Some(2),
        "options of serve do not combine with a subcommand"
    );
}
