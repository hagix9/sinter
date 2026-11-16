//! `sinter serve` (ADR 0002 §6): end-to-end tests of the real binary with a
//! scripted stand-in for the official `tunnel-client`. Nothing here contacts
//! OpenAI or any network: the stand-in is a POSIX sh script that records its
//! arguments and environment and then behaves as the test asks (run until
//! stopped, ignore SIGTERM, exit by itself, or run the `--mcp.command` it was
//! given against the real `sinter mcp`).
//!
//! Platform-independent tests cover the checks that end with exit 2 before
//! any process starts. The process tests (signals, the time limit, the SIGKILL
//! escalation, the death signal, start failures, the environment allowlist and
//! the MCP pass-through) need Linux and are compiled only there.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};

/// A synthetic value in the key file. It must never appear in any output,
/// argument or environment.
const KEY_MARKER: &str = "sk-SYNTHETIC-SERVE-TEST-0000";
const ID: &str = "tunnel_0123456789abcdefghijklmnopqrstuv";

const FAKE_CLIENT: &str = r#"#!/bin/sh
d=$(dirname "$0")
mode=$(cat "$d/mode")
{
  for a in "$@"; do printf 'ARG %s\n' "$a"; done
  env | sed 's/^/ENV /'
  echo "PID $$"
} > "$d/record.tmp"
mv "$d/record.tmp" "$d/record"
case "$mode" in
  run)
    trap 'echo TERM > "$d/got"; exit 0' TERM
    trap 'echo INT > "$d/got"; exit 0' INT
    while :; do sleep 0.1; done ;;
  ignore)
    trap 'echo TERM >> "$d/got"' TERM
    trap '' INT
    while :; do sleep 0.1; done ;;
  exit0) exit 0 ;;
  exit1) echo "stand-in: failing on purpose" >&2; exit 1 ;;
  mcp)
    cmd=""
    take=0
    for a in "$@"; do
      if [ "$take" = 1 ]; then cmd="$a"; take=0; fi
      if [ "$a" = "--mcp.command" ]; then take=1; fi
    done
    printf '%s\n' \
      '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"stand-in","version":"0"}}}' \
      '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
      '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
      '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sinter_list_targets","arguments":{}}}' \
      '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"sinter_apply","arguments":{}}}' \
      | $cmd > "$d/mcp-out" 2> "$d/mcp-err"
    echo "MCP_RC $?" >> "$d/mcp-out"
    exit 0 ;;
esac
"#;

struct Env {
    dir: tempfile::TempDir,
}

impl Env {
    fn new(mode: &str) -> Self {
        let dir = tempfile::Builder::new()
            .prefix("serve-")
            .tempdir_in(base_tmp())
            .unwrap();
        let e = Env { dir };
        e.file("mode", mode, 0o644);
        e.file("tunnel-client", FAKE_CLIENT, 0o755);
        e.file("runtime-key", &format!("{KEY_MARKER}\n"), 0o600);
        e.file(
            "targets.toml",
            "[targets.web]\nhost = \"web.invalid\"\nuser = \"reader\"\nknown_hosts = \"/nonexistent/known_hosts\"\n",
            0o644,
        );
        e
    }
    fn p(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
    fn file(&self, name: &str, body: &str, mode: u32) -> PathBuf {
        let p = self.p(name);
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    }
    fn config(&self, targets: bool) -> PathBuf {
        let mut t = format!(
            "[tunnel]\nid = \"{ID}\"\napi_key_file = \"{}\"\nclient = \"{}\"\n",
            self.p("runtime-key").display(),
            self.p("tunnel-client").display()
        );
        if targets {
            t.push_str(&format!(
                "[mcp]\ntargets_file = \"{}\"\n",
                self.p("targets.toml").display()
            ));
        }
        self.file("serve.toml", &t, 0o644)
    }
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.p(name)).unwrap_or_default()
    }
}

/// The base directory of the test's files. Paths placed into `--mcp.command`
/// (the targets file) must be free of spaces, so `/tmp` is used when TMPDIR
/// contains one; the files are a few bytes each.
fn base_tmp() -> PathBuf {
    let t = std::env::temp_dir();
    if t.to_string_lossy().contains(' ') {
        PathBuf::from("/tmp")
    } else {
        t
    }
}

fn serve_cmd(args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_sinter"));
    c.arg("serve").args(args);
    c
}

fn run(args: &[&str]) -> Output {
    serve_cmd(args).output().unwrap()
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn assert_no_secret(s: &str) {
    assert!(
        !s.contains(KEY_MARKER),
        "the key file's content leaked:\n{s}"
    );
}

// ---------------------------------------------------------------------------
// checks before anything starts (exit 2), every platform
// ---------------------------------------------------------------------------

#[test]
fn missing_configuration_is_exit_2() {
    let e = Env::new("run");
    let o = run(&["--config", e.p("none.toml").to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(
        text(&o).contains("cannot read configuration file"),
        "{}",
        text(&o)
    );
    assert!(!e.p("record").exists(), "nothing may start");
}

#[test]
fn unknown_key_with_a_secret_like_value_is_exit_2_and_not_echoed() {
    let e = Env::new("run");
    let c = e.file(
        "serve.toml",
        &format!(
            "[tunnel]\nid = \"{ID}\"\napi_key = \"{KEY_MARKER}\"\napi_key_file = \"{}\"\nclient = \"{}\"\n",
            e.p("runtime-key").display(),
            e.p("tunnel-client").display()
        ),
        0o644,
    );
    let o = run(&["--config", c.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains("unknown key \"api_key\""), "{}", text(&o));
    assert_no_secret(&text(&o));
    assert!(!e.p("record").exists());
}

#[test]
fn invalid_tunnel_id_is_exit_2() {
    let e = Env::new("run");
    let c = e.file(
        "serve.toml",
        &format!(
            "[tunnel]\nid = \"tunnel-ABC\"\napi_key_file = \"{}\"\nclient = \"{}\"\n",
            e.p("runtime-key").display(),
            e.p("tunnel-client").display()
        ),
        0o644,
    );
    let o = run(&["--config", c.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(
        text(&o).contains("tunnel.id must start with"),
        "{}",
        text(&o)
    );
}

#[test]
fn key_file_problems_are_exit_2_and_never_show_the_key() {
    // missing
    let e = Env::new("run");
    std::fs::remove_file(e.p("runtime-key")).unwrap();
    let o = run(&["--config", e.config(false).to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains("tunnel.api_key_file"), "{}", text(&o));
    // readable by others
    let e = Env::new("run");
    std::fs::set_permissions(e.p("runtime-key"), std::fs::Permissions::from_mode(0o644)).unwrap();
    let o = run(&["--config", e.config(false).to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(
        text(&o).contains("group or other permissions"),
        "{}",
        text(&o)
    );
    assert_no_secret(&text(&o));
    assert!(!e.p("record").exists());
}

#[test]
fn client_problems_are_exit_2() {
    let e = Env::new("run");
    std::fs::remove_file(e.p("tunnel-client")).unwrap();
    let o = run(&["--config", e.config(false).to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains("tunnel.client"), "{}", text(&o));
    let e = Env::new("run");
    std::fs::set_permissions(e.p("tunnel-client"), std::fs::Permissions::from_mode(0o644)).unwrap();
    let o = run(&["--config", e.config(false).to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains("not executable"), "{}", text(&o));
}

#[test]
fn invalid_targets_file_is_exit_2() {
    let e = Env::new("run");
    e.file(
        "targets.toml",
        "[targets.web]\nhost = \"\"\nuser = \"u\"\n",
        0o644,
    );
    let o = run(&["--config", e.config(true).to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains("mcp.targets_file"), "{}", text(&o));
    assert!(!e.p("record").exists());
}

#[test]
fn invalid_max_duration_is_refused() {
    let e = Env::new("run");
    let o = run(&[
        "--config",
        e.config(false).to_str().unwrap(),
        "--max-duration",
        "0s",
    ]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(!e.p("record").exists());
}

#[test]
fn help_says_what_serve_is_not() {
    let o = Command::new(env!("CARGO_BIN_EXE_sinter"))
        .args(["serve", "--help"])
        .output()
        .unwrap();
    let t = text(&o);
    assert!(t.contains("Opens no listener"), "{t}");
    assert!(t.contains("--max-duration"), "{t}");
    let o = Command::new(env!("CARGO_BIN_EXE_sinter"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(text(&o).contains("Run a read-only MCP"), "{}", text(&o));
}

#[cfg(not(target_os = "linux"))]
#[test]
fn valid_configuration_is_refused_off_linux_without_starting() {
    let e = Env::new("run");
    let o = run(&["--config", e.config(false).to_str().unwrap()]);
    // exit 2 when the path of the test binary contains a space (it is placed
    // into --mcp.command), else exit 3 (Linux only). Nothing starts either way.
    assert!(matches!(o.status.code(), Some(2) | Some(3)), "{}", text(&o));
    assert!(!e.p("record").exists(), "nothing may start off Linux");
    assert_no_secret(&text(&o));
}

// ---------------------------------------------------------------------------
// process tests (Linux)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::process::{Child, Stdio};
    use std::time::{Duration, Instant};

    fn exe_is_command_safe() {
        let exe = std::fs::canonicalize(env!("CARGO_BIN_EXE_sinter")).unwrap();
        assert!(
            sinter::serve::path_is_command_safe(&exe),
            "these tests need a CARGO_TARGET_DIR without spaces or shell characters: {}",
            exe.display()
        );
    }

    fn spawn(e: &Env, extra: &[&str], envs: &[(&str, &str)]) -> Child {
        spawn_with(e, extra, envs, |_| {})
    }

    fn spawn_with(
        e: &Env,
        extra: &[&str],
        envs: &[(&str, &str)],
        adjust: impl FnOnce(&mut Command),
    ) -> Child {
        exe_is_command_safe();
        let cfg = e.config(true);
        let mut c = serve_cmd(&["--config", cfg.to_str().unwrap()]);
        c.args(extra);
        for (k, v) in envs {
            c.env(k, v);
        }
        adjust(&mut c);
        c.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }

    fn wait_for(cond: impl Fn() -> bool, secs: u64) -> bool {
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(secs) {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        cond()
    }

    fn started(e: &Env) -> bool {
        wait_for(|| e.p("record").exists(), 10)
    }

    fn client_pid(e: &Env) -> i32 {
        e.read("record")
            .lines()
            .find_map(|l| l.strip_prefix("PID ").map(|p| p.trim().parse().unwrap()))
            .expect("the stand-in records its pid")
    }

    fn alive(pid: i32) -> bool {
        // A zombie still answers kill(0); check its state as well.
        if unsafe { libc::kill(pid, 0) } != 0 {
            return false;
        }
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(s) => !s
                .rsplit(')')
                .next()
                .unwrap_or("")
                .trim_start()
                .starts_with('Z'),
            Err(_) => false,
        }
    }

    fn finish(c: Child) -> (Option<i32>, String) {
        let o = c.wait_with_output().unwrap();
        (o.status.code(), text(&o))
    }

    fn signal(c: &Child, sig: i32) {
        unsafe { libc::kill(c.id() as i32, sig) };
    }

    #[test]
    fn sigterm_stops_the_client_and_exits_0() {
        let e = Env::new("run");
        let c = spawn(&e, &[], &[]);
        assert!(started(&e));
        let pid = client_pid(&e);
        signal(&c, libc::SIGTERM);
        let (code, out) = finish(c);
        assert_eq!(code, Some(0), "{out}");
        assert_eq!(e.read("got").trim(), "TERM", "{out}");
        assert!(out.contains("started tunnel-client"), "{out}");
        assert!(out.contains("stop requested (SIGTERM)"), "{out}");
        assert!(wait_for(|| !alive(pid), 5), "no tunnel-client may remain");
        assert_no_secret(&out);
    }

    #[test]
    fn sigint_and_sighup_to_serve_are_passed_on_as_sigterm() {
        for (sig, name) in [(libc::SIGINT, "SIGINT"), (libc::SIGHUP, "SIGHUP")] {
            let e = Env::new("run");
            let c = spawn(&e, &[], &[]);
            assert!(started(&e));
            signal(&c, sig);
            let (code, out) = finish(c);
            assert_eq!(code, Some(0), "{name}: {out}");
            assert_eq!(e.read("got").trim(), "TERM", "{name}: {out}");
            assert!(out.contains(&format!("stop requested ({name})")), "{out}");
        }
    }

    /// Ctrl+C reaches the whole foreground process group: the client may end
    /// before serve's loop sees its own signal. That is still a requested stop
    /// (exit 0), never "exited by itself" (independent audit M-1).
    #[test]
    fn a_signal_to_the_whole_process_group_is_a_requested_stop() {
        use std::os::unix::process::CommandExt;
        for (sig, name) in [
            (libc::SIGINT, "SIGINT"),
            (libc::SIGHUP, "SIGHUP"),
            (libc::SIGTERM, "SIGTERM"),
        ] {
            for round in 0..5 {
                let e = Env::new("run");
                let c = spawn_with(&e, &[], &[], |cmd| {
                    cmd.process_group(0);
                });
                assert!(started(&e));
                let pid = client_pid(&e);
                unsafe { libc::kill(-(c.id() as i32), sig) };
                let (code, out) = finish(c);
                assert_eq!(code, Some(0), "{name} round {round}: {out}");
                assert!(
                    out.contains(&format!("stop requested ({name})")),
                    "{name} round {round}: {out}"
                );
                assert!(!out.contains("exited by itself"), "{out}");
                assert!(wait_for(|| !alive(pid), 5));
            }
        }
    }

    /// An inherited `SIGCHLD = SIG_IGN` must not make waiting fail or let serve
    /// signal a reaped PID (independent audit L-1).
    #[test]
    fn an_inherited_ignored_sigchld_is_restored() {
        use std::os::unix::process::CommandExt;
        let e = Env::new("run");
        let c = spawn_with(&e, &[], &[], |cmd| unsafe {
            cmd.pre_exec(|| {
                libc::signal(libc::SIGCHLD, libc::SIG_IGN);
                Ok(())
            });
        });
        assert!(started(&e));
        signal(&c, libc::SIGTERM);
        let (code, out) = finish(c);
        assert_eq!(code, Some(0), "{out}");
        assert!(!out.contains("cannot wait"), "{out}");
        assert_eq!(e.read("got").trim(), "TERM", "{out}");
        // And a client that ends by itself is still reported correctly.
        let e = Env::new("exit1");
        let c = spawn_with(&e, &[], &[], |cmd| unsafe {
            cmd.pre_exec(|| {
                libc::signal(libc::SIGCHLD, libc::SIG_IGN);
                Ok(())
            });
        });
        let (code, out) = finish(c);
        assert_eq!(code, Some(3), "{out}");
        assert!(out.contains("exited by itself (exit status 1)"), "{out}");
    }

    #[test]
    fn time_limit_stops_and_exits_0() {
        let e = Env::new("run");
        let t = Instant::now();
        let c = spawn(&e, &["--max-duration", "2s"], &[]);
        let (code, out) = finish(c);
        assert_eq!(code, Some(0), "{out}");
        assert!(out.contains("time limit reached"), "{out}");
        assert_eq!(e.read("got").trim(), "TERM");
        assert!(
            t.elapsed() >= Duration::from_secs(2) && t.elapsed() < Duration::from_secs(9),
            "{:?}",
            t.elapsed()
        );
    }

    #[test]
    fn a_client_that_ignores_sigterm_is_killed_after_10_seconds() {
        let e = Env::new("ignore");
        let c = spawn(&e, &[], &[]);
        assert!(started(&e));
        let pid = client_pid(&e);
        let t = Instant::now();
        signal(&c, libc::SIGTERM);
        let (code, out) = finish(c);
        let took = t.elapsed();
        assert_eq!(code, Some(0), "{out}");
        assert!(
            took >= Duration::from_secs(10) && took < Duration::from_secs(16),
            "{took:?}"
        );
        assert!(out.contains("was killed"), "{out}");
        assert!(e.read("got").contains("TERM"));
        assert!(
            wait_for(|| !alive(pid), 5),
            "the killed client must be gone"
        );
    }

    #[test]
    fn a_client_that_exits_by_itself_is_exit_3() {
        for mode in ["exit0", "exit1"] {
            let e = Env::new(mode);
            let c = spawn(&e, &[], &[]);
            let (code, out) = finish(c);
            assert_eq!(code, Some(3), "{mode}: {out}");
            assert!(out.contains("tunnel-client exited by itself"), "{out}");
        }
    }

    #[test]
    fn a_client_that_cannot_start_is_exit_3() {
        let e = Env::new("run");
        e.file("tunnel-client", "#!/nonexistent/interpreter\n", 0o755);
        let c = spawn(&e, &[], &[]);
        let (code, out) = finish(c);
        assert_eq!(code, Some(3), "{out}");
        assert!(out.contains("cannot start tunnel-client"), "{out}");
        assert_no_secret(&out);
    }

    #[test]
    fn arguments_and_environment_carry_no_key() {
        let e = Env::new("run");
        let c = spawn(
            &e,
            &[],
            &[
                ("OPENAI_API_KEY", KEY_MARKER),
                ("OPENAI_ADMIN_KEY", KEY_MARKER),
                ("CONTROL_PLANE_API_KEY", KEY_MARKER),
                ("TUNNEL_CLIENT_CONFIG", "/nonexistent/override.yaml"),
                ("MCP_STDIO_FAILURE_POLICY", "exit"),
                ("HTTPS_PROXY", "http://proxy.invalid:3128"),
                ("LC_ALL", "C"),
            ],
        );
        assert!(started(&e));
        signal(&c, libc::SIGTERM);
        let (code, out) = finish(c);
        assert_eq!(code, Some(0), "{out}");
        let rec = e.read("record");
        assert_no_secret(&rec);
        assert_no_secret(&out);
        let args: Vec<&str> = rec.lines().filter_map(|l| l.strip_prefix("ARG ")).collect();
        let exe = std::fs::canonicalize(env!("CARGO_BIN_EXE_sinter")).unwrap();
        assert_eq!(
            args,
            vec![
                "run".to_string(),
                "--control-plane.tunnel-id".into(),
                ID.into(),
                "--control-plane.api-key".into(),
                format!("file:{}", e.p("runtime-key").display()),
                "--mcp.command".into(),
                format!(
                    "{} mcp --targets-file {}",
                    exe.display(),
                    e.p("targets.toml").display()
                ),
                "--health.listen-addr".into(),
                "127.0.0.1:0".into(),
            ]
        );
        let keys: Vec<&str> = rec
            .lines()
            .filter_map(|l| l.strip_prefix("ENV "))
            .map(|kv| kv.split('=').next().unwrap())
            .collect();
        for forbidden in [
            "OPENAI_API_KEY",
            "OPENAI_ADMIN_KEY",
            "CONTROL_PLANE_API_KEY",
            "TUNNEL_CLIENT_CONFIG",
            "MCP_STDIO_FAILURE_POLICY",
        ] {
            assert!(
                !keys.contains(&forbidden),
                "{forbidden} reached the client: {keys:?}"
            );
        }
        for allowed in ["HTTPS_PROXY", "LC_ALL"] {
            assert!(keys.contains(&allowed), "{allowed} must pass: {keys:?}");
        }
        // sh adds PWD/SHLVL/_ itself; nothing else outside the allowlist.
        for k in &keys {
            let ok = sinter::serve::ENV_ALLOWLIST.contains(k)
                || k.starts_with("LC_")
                || ["PWD", "SHLVL", "_", "OLDPWD"].contains(k);
            assert!(ok, "unexpected variable {k} in the client's environment");
        }
    }

    #[test]
    fn the_death_signal_stops_the_client_when_serve_is_killed() {
        let e = Env::new("run");
        let c = spawn(&e, &[], &[]);
        assert!(started(&e));
        let pid = client_pid(&e);
        signal(&c, libc::SIGKILL);
        let (code, _) = finish(c);
        assert_eq!(code, None, "serve was killed");
        assert!(
            wait_for(|| e.read("got").trim() == "TERM", 5),
            "the client must receive SIGTERM from PR_SET_PDEATHSIG"
        );
        assert!(
            wait_for(|| !alive(pid), 5),
            "no orphaned tunnel-client may remain (pid {pid})"
        );
    }

    #[test]
    fn the_mcp_command_runs_the_unchanged_read_only_sinter_mcp() {
        let e = Env::new("mcp");
        let c = spawn(&e, &[], &[]);
        let (code, out) = finish(c);
        // The stand-in exits by itself after the exchange: exit 3 by design.
        assert_eq!(code, Some(3), "{out}");
        let mcp = e.read("mcp-out");
        assert!(mcp.contains("MCP_RC 0"), "{mcp}\n{}", e.read("mcp-err"));
        let frames: Vec<serde_json::Value> = mcp
            .lines()
            .filter(|l| l.starts_with('{'))
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let list = frames
            .iter()
            .find(|f| f["id"] == 2)
            .expect("tools/list answered");
        let mut names: Vec<String> = list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect();
        names.sort();
        let mut want: Vec<String> = sinter::mcp::tool_names()
            .into_iter()
            .map(String::from)
            .collect();
        want.sort();
        assert_eq!(
            names, want,
            "the tunnel exposes exactly the existing read-only tools"
        );
        let targets = frames
            .iter()
            .find(|f| f["id"] == 3)
            .expect("list_targets answered");
        let s = targets.to_string();
        assert!(s.contains("web"), "{s}");
        assert!(
            !s.contains("web.invalid") && !s.contains("reader"),
            "connection details never leave: {s}"
        );
        let apply = frames
            .iter()
            .find(|f| f["id"] == 4)
            .expect("unknown tool answered");
        assert!(
            apply.get("error").is_some() || apply["result"]["isError"] == true,
            "an unlisted tool is refused: {apply}"
        );
        assert_no_secret(&mcp);
    }
}
