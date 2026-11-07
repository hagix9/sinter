mod common;

use common::*;
use sinter::engine::{Mode, SshSpec};
use sinter::result::{Change, Execution, Verification};

fn ssh() -> Option<SshSpec> {
    ssh_spec()
}

macro_rules! require_ssh {
    () => {
        match ssh() {
            Some(s) => s,
            None => {
                skip_or_fail("SINTER_TEST_SSH_HOST not set");
                return;
            }
        }
    };
}

/// Create a recipe on the controller whose output path is under the target
/// user's HOME, so the unprivileged trust boundary is satisfied.
fn controller_recipe(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
    write_recipe(
        dir,
        "r.yaml",
        &format!("version: 1\nresources:\n{}\n", body),
    )
}

#[test]
fn ssh_known_host_success() {
    let _s = require_ssh!();
    let dir = controller_dir("ssh-known");
    let recipe = controller_recipe(
        &dir,
        r#"  - id: who
    type: command
    with:
      program: /usr/bin/id
      args: ["-u"]
      register: uid
  - id: show
    type: command
    with:
      program: /bin/echo
      args: ["uid={{ registers.uid.stdout }}"]
    depends_on: [who]"#,
    );
    let r = run_recipe_target(&recipe, Mode::Apply, false, ssh());
    assert_success(&r);
    assert_eq!(find(&r, "who").execution, Execution::Succeeded);
}

#[test]
fn ssh_unknown_host_fails() {
    let mut s = require_ssh!();
    // Point at a known_hosts file that has no entry for the host.
    let dir = trusted_root("ssh-unknown");
    let empty = dir.join("known_hosts");
    std::fs::write(&empty, "").unwrap();
    s.known_hosts = empty;
    let recipe = controller_recipe(
        &trusted_root("ssh-unknown-recipe"),
        r#"  - id: c
    type: command
    with:
      program: /bin/true"#,
    );
    let model = sinter::model::load_model(&recipe).unwrap();
    let opts = sinter::engine::RunOptions {
        mode: Mode::Plan,
        sudo: false,
        target: sinter::engine::TargetSpec { ssh: Some(s) },
        verbose: false,
        fault: None,
        fake_target: None,
    };
    let res = sinter::engine::Engine::new(model, opts);
    assert!(res.is_err(), "unknown host key must fail the connection");
    let err = res.err().unwrap();
    assert_eq!(err.kind, sinter::error::ErrorKind::Connect);
}

#[test]
fn ssh_changed_host_key_fails() {
    let mut s = require_ssh!();
    let dir = trusted_root("ssh-changed");
    let bad = dir.join("known_hosts");
    // A syntactically valid but wrong key for [host]:port.
    let bogus = format!(
        "[{}]:{} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
        s.host, s.port
    );
    std::fs::write(&bad, bogus).unwrap();
    s.known_hosts = bad;
    let recipe = controller_recipe(
        &trusted_root("ssh-changed-recipe"),
        r#"  - id: c
    type: command
    with:
      program: /bin/true"#,
    );
    let model = sinter::model::load_model(&recipe).unwrap();
    let opts = sinter::engine::RunOptions {
        mode: Mode::Plan,
        sudo: false,
        target: sinter::engine::TargetSpec { ssh: Some(s) },
        verbose: false,
        fault: None,
        fake_target: None,
    };
    let res = sinter::engine::Engine::new(model, opts);
    assert!(res.is_err(), "changed host key must fail the connection");
    assert_eq!(res.err().unwrap().kind, sinter::error::ErrorKind::Connect);
}

/// The non-default port a `[host]:port` identity test needs. Only a real
/// secondary sshd qualifies: the DESIGN §19 identity for port 22 is the bare
/// `host`, so silently falling back to the default port would make these tests
/// assert the wrong identity (and pass or fail for reasons unrelated to the
/// `[host]:port` form they exist to cover).
fn non_default_port() -> Option<u16> {
    if std::net::TcpStream::connect(("127.0.0.1", 2222u16)).is_ok() {
        Some(2222u16)
    } else {
        None
    }
}

/// Non-default/qualified port identity: an explicit `[host]:port` Mismatch must
/// reject even when a portless host entry matches (Astra-reproduced defect).
#[test]
fn ssh_host_port_mismatch_rejects_despite_portless_match() {
    let _s = require_ssh!();
    let Some(port) = non_default_port() else {
        skip("requires secondary sshd on non-default port 2222");
        return;
    };
    let mut s = ssh().unwrap();
    s.port = port;
    let dir = trusted_root("ssh-hostport-mismatch");
    let kh = dir.join("known_hosts");
    // Collect the real host key via ssh-keyscan so the portless entry matches.
    let scan = std::process::Command::new("ssh-keyscan")
        .args(["-p", &port.to_string(), &s.host])
        .output()
        .expect("ssh-keyscan must run");
    let real = String::from_utf8_lossy(&scan.stdout);
    assert!(
        real.contains(&s.host),
        "ssh-keyscan must produce a real host key: {real}"
    );
    // Rewrite keyscan lines into a true portless `host keytype key` form.
    let portless: String = real
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let mut parts = l.splitn(3, ' ');
            let _h = parts.next().unwrap_or("");
            let ktype = parts.next().unwrap_or("");
            let key = parts.next().unwrap_or("");
            format!("{} {} {}", s.host, ktype, key)
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let bogus = format!(
        "[{}]:{} ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
        s.host, s.port
    );
    let mut body = bogus;
    body.push_str(&portless);
    std::fs::write(&kh, body).unwrap();
    s.known_hosts = kh;
    let recipe = controller_recipe(
        &trusted_root("ssh-hostport-mismatch-recipe"),
        r#"  - id: c
    type: command
    with:
      program: /bin/true"#,
    );
    let model = sinter::model::load_model(&recipe).unwrap();
    let opts = sinter::engine::RunOptions {
        mode: Mode::Plan,
        sudo: false,
        target: sinter::engine::TargetSpec { ssh: Some(s) },
        verbose: false,
        fault: None,
        fake_target: None,
    };
    let res = sinter::engine::Engine::new(model, opts);
    assert!(
        res.is_err(),
        "host+port mismatch must reject despite portless match"
    );
    let e = res.err().unwrap();
    assert_eq!(e.kind, sinter::error::ErrorKind::Connect);
    assert!(
        e.message.contains("host key mismatch"),
        "expected mismatch error, got: {}",
        e.message
    );
}

/// Explicit host+port with a matching key must accept.
#[test]
fn ssh_host_port_match_accepts() {
    let _s = require_ssh!();
    let Some(port) = non_default_port() else {
        skip("requires secondary sshd on non-default port 2222");
        return;
    };
    let mut s = ssh().unwrap();
    s.port = port;
    let dir = trusted_root("ssh-hostport-match");
    let kh = dir.join("known_hosts");
    let scan = std::process::Command::new("ssh-keyscan")
        .args(["-p", &port.to_string(), &s.host])
        .output()
        .expect("ssh-keyscan must run");
    let real = String::from_utf8_lossy(&scan.stdout);
    // Only the host+port form.
    let qualified: String = real
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let mut parts = l.splitn(3, ' ');
            let _h = parts.next().unwrap_or("");
            let ktype = parts.next().unwrap_or("");
            let key = parts.next().unwrap_or("");
            format!("[{}]:{} {} {}", s.host, s.port, ktype, key)
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    std::fs::write(&kh, &qualified).unwrap();
    s.known_hosts = kh;
    let recipe = controller_recipe(
        &trusted_root("ssh-hostport-match-recipe"),
        r#"  - id: c
    type: command
    with:
      program: /bin/true"#,
    );
    let model = sinter::model::load_model(&recipe).unwrap();
    let opts = sinter::engine::RunOptions {
        mode: Mode::Plan,
        sudo: false,
        target: sinter::engine::TargetSpec { ssh: Some(s) },
        verbose: false,
        fault: None,
        fake_target: None,
    };
    let res = sinter::engine::Engine::new(model, opts);
    assert!(
        res.is_ok(),
        "matching host+port must accept: {:?}",
        res.err()
    );
}

/// A matching portless `host` entry must NOT authorize a non-default-port
/// connection (DESIGN §19). Prefer the secondary sshd on 2222.
#[test]
fn ssh_portless_only_non_default_port_rejects() {
    let _s = require_ssh!();
    let Some(port) = non_default_port() else {
        skip("requires secondary sshd on non-default port 2222");
        return;
    };
    let mut s = ssh().unwrap();
    s.port = port;
    let dir = trusted_root("ssh-portless-only");
    let kh = dir.join("known_hosts");
    let scan = std::process::Command::new("ssh-keyscan")
        .args(["-p", &port.to_string(), &s.host])
        .output()
        .expect("ssh-keyscan must run");
    let real = String::from_utf8_lossy(&scan.stdout);
    // Rewrite keyscan lines into a true portless `host keytype key` form.
    let portless: String = real
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let mut parts = l.splitn(3, ' ');
            let _h = parts.next().unwrap_or("");
            let ktype = parts.next().unwrap_or("");
            let key = parts.next().unwrap_or("");
            format!("{} {} {}", s.host, ktype, key)
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    std::fs::write(&kh, &portless).unwrap();
    s.known_hosts = kh;
    let recipe = controller_recipe(
        &trusted_root("ssh-portless-only-recipe"),
        r#"  - id: c
    type: command
    with:
      program: /bin/true"#,
    );
    let model = sinter::model::load_model(&recipe).unwrap();
    let opts = sinter::engine::RunOptions {
        mode: Mode::Plan,
        sudo: false,
        target: sinter::engine::TargetSpec { ssh: Some(s) },
        verbose: false,
        fault: None,
        fake_target: None,
    };
    let res = sinter::engine::Engine::new(model, opts);
    assert!(
        res.is_err(),
        "portless host entry must not authorize non-default port"
    );
    let e = res.err().unwrap();
    assert_eq!(e.kind, sinter::error::ErrorKind::Connect);
    assert!(
        e.message.contains("not present") || e.message.contains("host key"),
        "expected enrollment/mismatch error, got: {}",
        e.message
    );
}

/// Port 22 + matching portless host entry must ACCEPT (normal default-port
/// identity).
#[test]
fn ssh_default_port_portless_match_accepts() {
    let _s = require_ssh!();
    let mut s = ssh().unwrap();
    assert_eq!(s.port, 22, "this test covers the default port identity");
    let dir = trusted_root("ssh-default-portless");
    let kh = dir.join("known_hosts");
    let scan = std::process::Command::new("ssh-keyscan")
        .args(["-p", &s.port.to_string(), &s.host])
        .output()
        .expect("ssh-keyscan must run");
    let real = String::from_utf8_lossy(&scan.stdout);
    std::fs::write(&kh, real.as_bytes()).unwrap();
    s.known_hosts = kh;
    let recipe = controller_recipe(
        &trusted_root("ssh-default-portless-recipe"),
        r#"  - id: c
    type: command
    with:
      program: /bin/true"#,
    );
    let model = sinter::model::load_model(&recipe).unwrap();
    let opts = sinter::engine::RunOptions {
        mode: Mode::Plan,
        sudo: false,
        target: sinter::engine::TargetSpec { ssh: Some(s) },
        verbose: false,
        fault: None,
        fake_target: None,
    };
    let res = sinter::engine::Engine::new(model, opts);
    assert!(
        res.is_ok(),
        "default port + matching portless host must accept: {:?}",
        res.err()
    );
}

#[test]
fn ssh_argv_exactness_verification_command() {
    let _s = require_ssh!();
    let dir = controller_dir("ssh-argv-verify");
    let target_home = target_user_home().expect("target home must resolve");
    let out = format!("{}/sinter-argv-{}", target_home, std::process::id());
    // One program invocation prints every argv element as `[arg]` on its own
    // line; comparing the whole blob cannot hide an early failure behind a
    // later success. Includes empty, spaces, both quote types, newline, `$()`,
    // backticks, semicolon, leading hyphen, glob, and Unicode.
    let recipe = controller_recipe(
        &dir,
        &format!(
            r#"  - id: emit
    type: command
    with:
      program: /bin/sh
      args:
        - "-c"
        - "for a in \"$@\"; do printf '[%s]\\n' \"$a\"; done"
        - "argv0"
        - ""
        - "a b"
        - "it's"
        - 'he said "hi"'
        - "$(id)"
        - "`id`"
        - "a;b"
        - "-leading"
        - "a*b"
        - "line1\nline2"
        - "unicode: λ"
      register: r
  - id: save
    type: file
    with:
      path: {out}
      content: "{{{{ registers.r.stdout }}}}"
      mode: "0644"
    depends_on: [emit]
"#,
            out = out
        ),
    );
    let r = run_recipe_target(&recipe, Mode::Apply, false, ssh());
    assert_success(&r);
    assert_eq!(find(&r, "emit").execution, Execution::Succeeded);
    // Exact expected output. If quoting mis-handled any argument, this differs.
    let expected = "[]\n[a b]\n[it's]\n[he said \"hi\"]\n[$(id)]\n[`id`]\n[a;b]\n[-leading]\n[a*b]\n[line1\nline2]\n[unicode: λ]\n";
    assert_eq!(target_read_file(&out, false), expected);
    let _ = target_run("/bin/rm", &["-f", "--", &out], false);
}

#[test]
fn ssh_non_utf8_and_signal_and_timeout() {
    let _s = require_ssh!();
    let dir = controller_dir("ssh-signals");
    let recipe = controller_recipe(
        &dir,
        r#"  - id: nonutf8
    type: command
    with:
      program: /bin/sh
      args: ["-c", "printf '\\377\\376'"]
      register: n
  - id: signal
    type: command
    with:
      program: /bin/sh
      args: ["-c", "kill -TERM $$"]"#,
    );
    let r = run_recipe_target(&recipe, Mode::Apply, false, ssh());
    // nonutf8 succeeds (exit 0) but its stdout is not usable; the signal then
    // fails and stops execution.
    let n = find(&r, "nonutf8");
    assert_eq!(n.execution, Execution::Succeeded);
    let sig = find(&r, "signal");
    assert_eq!(sig.execution, Execution::Failed);
    assert!(!n.diff.as_ref().map(|_| true).unwrap_or(false));
}

#[test]
fn ssh_timeout_after_dispatch_is_indeterminate_and_not_retried() {
    let _s = require_ssh!();
    let dir = controller_dir("ssh-timeout");
    let recipe = controller_recipe(
        &dir,
        r#"  - id: slow
    type: command
    with:
      program: /bin/sleep
      args: ["30"]
      timeout_seconds: 1
  - id: after
    type: command
    with:
      program: /bin/true"#,
    );
    let r = run_recipe_target(&recipe, Mode::Apply, false, ssh());
    let slow = find(&r, "slow");
    assert_eq!(slow.execution, Execution::Indeterminate);
    assert_eq!(slow.change, Change::Possible);
    // no automatic retry: the command appears exactly once
    let count = r
        .commands
        .iter()
        .filter(|c| c.program.ends_with("sleep"))
        .count();
    assert_eq!(count, 1, "indeterminate mutation must not be retried");
    assert_eq!(
        find(&r, "after").execution,
        Execution::NotRun,
        "fail-fast stops later resources"
    );

    // Operation deadline must be enforced independent of connect/setup time.
    // Measure only Executor::run after the session is established.
    let Some(mut ex) = executor_for(&require_ssh!(), false) else {
        skip("could not connect executor");
        return;
    };
    let mut req = sinter::executor::ExecRequest::new("/bin/sleep");
    req.args = vec!["30".into()];
    req.timeout_secs = 1;
    req.env.insert(
        "PATH".to_string(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
    );
    req.env.insert("HOME".to_string(), "/tmp".to_string());
    let started = std::time::Instant::now();
    let out = ex.run(&req).expect("sleep must complete as indeterminate");
    let elapsed = started.elapsed();
    assert!(
        elapsed <= std::time::Duration::from_secs(3),
        "timeout=1s operation (post-connect) must return within 3s, took {:?}",
        elapsed
    );
    assert!(
        matches!(
            out.completion,
            sinter::executor::Completion::Indeterminate { .. }
        ),
        "expected indeterminate completion"
    );
}

/// SSH must resolve `localhost` (not only IP literals).
#[test]
fn ssh_localhost_hostname_connects() {
    let _s = require_ssh!();
    let mut s = ssh().unwrap();
    s.host = "localhost".to_string();
    let dir = controller_dir("ssh-localhost");
    let recipe = controller_recipe(
        &dir,
        r#"  - id: who
    type: command
    with:
      program: /usr/bin/id
      args: ["-u"]"#,
    );
    let model = sinter::model::load_model(&recipe).unwrap();
    let opts = sinter::engine::RunOptions {
        mode: Mode::Apply,
        sudo: false,
        target: sinter::engine::TargetSpec { ssh: Some(s) },
        verbose: false,
        fault: None,
        fake_target: None,
    };
    let engine_result = sinter::engine::Engine::new(model, opts);
    match engine_result {
        Err(e) => {
            // Resolution succeeded: the failure must not be address parsing.
            assert!(
                !e.message.contains("invalid SSH address"),
                "localhost must resolve: {}",
                e.message
            );
            assert!(
                e.message.contains("host key")
                    || e.message.contains("known_hosts")
                    || e.message.contains("handshake")
                    || e.message.contains("authentication"),
                "expected host-key/auth outcome after resolution, got: {}",
                e.message
            );
        }
        Ok(engine) => {
            let r = engine.run().unwrap();
            assert_success(&r);
        }
    }
}

/// SSH IP literal still works after hostname fix.
#[test]
fn ssh_ip_literal_still_connects() {
    let _s = require_ssh!();
    let dir = controller_dir("ssh-ip");
    let recipe = controller_recipe(
        &dir,
        r#"  - id: who
    type: command
    with:
      program: /usr/bin/id
      args: ["-u"]"#,
    );
    let r = run_recipe_target(&recipe, Mode::Apply, false, ssh());
    assert_success(&r);
}

/// stdin supplied to a command that consumes it must complete with correct output.
#[test]
fn ssh_stdin_supplied_consumed() {
    let _s = require_ssh!();
    let Some(mut ex) = executor_for(&require_ssh!(), false) else {
        skip("could not connect executor");
        return;
    };
    let mut req = sinter::executor::ExecRequest::new("/bin/cat");
    req.timeout_secs = 5;
    req.stdin = Some(b"r5-stdin-payload\n".to_vec());
    req.env.insert(
        "PATH".to_string(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
    );
    req.env.insert("HOME".to_string(), "/tmp".to_string());
    let started = std::time::Instant::now();
    let out = ex.run(&req).expect("ssh cat with stdin must complete");
    let elapsed = started.elapsed();
    assert_eq!(out.completion, sinter::executor::Completion::Exited(0));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "r5-stdin-payload\n");
    assert!(
        elapsed <= std::time::Duration::from_secs(3),
        "stdin cat must finish promptly, took {:?}",
        elapsed
    );
}

/// SSH must send stdin EOF even when stdin is unspecified, so `/bin/cat`
/// terminates just like local `/dev/null` semantics.
#[test]
fn ssh_stdin_none_sends_eof_and_cat_exits_cleanly() {
    let _s = require_ssh!();
    let dir = controller_dir("ssh-stdin-eof");
    let recipe = controller_recipe(
        &dir,
        r#"  - id: cat
    type: command
    with:
      program: /bin/cat
      timeout_seconds: 5"#,
    );
    let r = run_recipe_target(&recipe, Mode::Apply, false, ssh());
    let cat = find(&r, "cat");
    assert_eq!(
        cat.execution,
        Execution::Succeeded,
        "cat with no stdin must exit cleanly via EOF: {:?}",
        cat
    );

    // Post-connect operation timing (connect/setup is a separate budget).
    let Some(mut ex) = executor_for(&require_ssh!(), false) else {
        skip("could not connect executor");
        return;
    };
    let mut req = sinter::executor::ExecRequest::new("/bin/cat");
    req.timeout_secs = 5;
    req.env.insert(
        "PATH".to_string(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
    );
    req.env.insert("HOME".to_string(), "/tmp".to_string());
    let started = std::time::Instant::now();
    let out = ex.run(&req).expect("cat must complete");
    let elapsed = started.elapsed();
    assert_eq!(
        out.completion,
        sinter::executor::Completion::Exited(0),
        "cat with no stdin must exit 0"
    );
    assert!(
        elapsed <= std::time::Duration::from_secs(3),
        "cat-with-EOF operation (post-connect) must finish promptly, took {:?}",
        elapsed
    );
}

/// Continuous stdout must still honor the operation deadline.
#[test]
fn ssh_continuous_stdout_timeout_bounded() {
    let _s = require_ssh!();
    let dir = controller_dir("ssh-stdout-loop");
    let recipe = controller_recipe(
        &dir,
        r#"  - id: flood
    type: command
    with:
      program: /bin/sh
      args: ["-c", "while true; do echo r6-flood; done"]
      timeout_seconds: 1
"#,
    );
    let r = run_recipe_target(&recipe, Mode::Apply, false, ssh());
    let flood = find(&r, "flood");
    assert_eq!(flood.execution, Execution::Indeterminate);

    // Post-connect operation timing (connect/setup is a separate budget).
    let Some(mut ex) = executor_for(&require_ssh!(), false) else {
        skip("could not connect executor");
        return;
    };
    let mut req = sinter::executor::ExecRequest::new("/bin/sh");
    req.args = vec!["-c".into(), "while true; do echo r6-flood; done".into()];
    req.timeout_secs = 1;
    req.env.insert(
        "PATH".to_string(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
    );
    req.env.insert("HOME".to_string(), "/tmp".to_string());
    let started = std::time::Instant::now();
    let out = ex.run(&req).expect("flood must complete as indeterminate");
    let elapsed = started.elapsed();
    assert!(
        elapsed <= std::time::Duration::from_secs(3),
        "continuous stdout timeout (post-connect) must stay near 1s, took {:?}",
        elapsed
    );
    assert!(
        matches!(
            out.completion,
            sinter::executor::Completion::Indeterminate { .. }
        ),
        "expected indeterminate completion"
    );
}

/// Large stdin to /bin/cat must full-duplex (write while reading) and not
/// deadlock until the timeout. Payload exceeds typical SSH channel windows.
#[test]
fn ssh_large_stdin_cat_full_duplex_no_deadlock() {
    let _s = require_ssh!();
    let Some(mut ex) = executor_for(&require_ssh!(), false) else {
        skip("could not connect executor");
        return;
    };
    // 256 KiB is large enough to fill default SSH channel windows while
    // remaining under the 1 MiB capture cap.
    let payload_size = 256 * 1024;
    let mut payload = Vec::with_capacity(payload_size);
    for i in 0..payload_size {
        payload.push(b'a' + (i % 26) as u8);
    }
    let mut req = sinter::executor::ExecRequest::new("/bin/cat");
    req.timeout_secs = 10;
    req.stdin = Some(payload.clone());
    req.env.insert(
        "PATH".to_string(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
    );
    req.env.insert("HOME".to_string(), "/tmp".to_string());
    let started = std::time::Instant::now();
    let out = ex.run(&req).expect("large stdin cat must complete");
    let elapsed = started.elapsed();
    assert_eq!(
        out.completion,
        sinter::executor::Completion::Exited(0),
        "cat must exit 0"
    );
    assert_eq!(out.stdout.len(), payload_size, "payload must round-trip");
    assert_eq!(out.stdout, payload, "payload bytes must match");
    assert!(
        !out.stdout_truncated,
        "256KiB payload must fit under capture cap"
    );
    // Must finish well before the 10s timeout under localhost conditions.
    assert!(
        elapsed <= std::time::Duration::from_secs(5),
        "large stdin cat must not approach timeout; took {:?}",
        elapsed
    );
}

/// Direct executor probe: same /bin/cat command must exit 0 over SSH with no
/// stdin, matching local semantics (not exit 6 / indeterminate).
#[test]
fn ssh_direct_cat_stdin_none_exit_zero() {
    let _s = require_ssh!();
    let Some(mut ex) = executor_for(&require_ssh!(), false) else {
        skip("could not connect executor");
        return;
    };
    let mut req = sinter::executor::ExecRequest::new("/bin/cat");
    req.timeout_secs = 5;
    req.env.insert(
        "PATH".to_string(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
    );
    req.env.insert("HOME".to_string(), "/tmp".to_string());
    let started = std::time::Instant::now();
    let out = ex.run(&req).expect("ssh cat must complete");
    let elapsed = started.elapsed();
    assert_eq!(
        out.completion,
        sinter::executor::Completion::Exited(0),
        "SSH cat with no stdin must exit 0"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(8),
        "cat EOF path must be bounded, took {:?}",
        elapsed
    );
}

#[test]
fn ssh_sudo_effective_uid_root() {
    let _s = require_ssh!();
    if !target_sudo_available() {
        skip("target does not provide passwordless sudo -n");
        return;
    }
    let dir = controller_dir("ssh-sudo-uid");
    let outdir = target_private_dir("ssh-sudo-uid-out", true);
    let out = format!("{}/uid", outdir);
    let recipe = controller_recipe(
        &dir,
        &format!(
            r#"  - id: who
    type: command
    with:
      program: /usr/bin/id
      args: ["-u"]
      register: uid
  - id: save
    type: file
    with:
      path: {out}
      content: "{{{{ registers.uid.stdout }}}}"
      mode: "0600"
    depends_on: [who]
"#,
            out = out
        ),
    );
    let r = run_recipe_target(&recipe, Mode::Apply, true, ssh());
    assert_success(&r);
    assert_eq!(target_read_file(&out, true).trim(), "0");
    target_cleanup_dir(&outdir, true);
}

#[test]
fn ssh_no_sudo_effective_uid_target_user() {
    let _s = require_ssh!();
    let dir = controller_dir("ssh-nosudo-uid");
    // The target-side home is resolved on the target, and the output is written
    // under it so the unprivileged trust boundary holds.
    let target_home = target_user_home().expect("target home must resolve");
    let out = format!("{}/sinter-uid-test-{}", target_home, std::process::id());
    let recipe = controller_recipe(
        &dir,
        &format!(
            r#"  - id: who
    type: command
    with:
      program: /usr/bin/id
      args: ["-u"]
      register: uid
  - id: save
    type: file
    with:
      path: {out}
      content: "{{{{ registers.uid.stdout }}}}"
      mode: "0600"
    depends_on: [who]
"#,
            out = out
        ),
    );
    let r = run_recipe_target(&recipe, Mode::Apply, false, ssh());
    assert_success(&r);
    // Read the result ON THE TARGET and compare against the TARGET UID, never
    // the controller UID.
    let uid_written = target_read_file(&out, false).trim().to_string();
    let target_uid = target_uid().expect("target uid must resolve").to_string();
    assert_eq!(
        uid_written, target_uid,
        "non-sudo execution must use the target user's UID"
    );
    let _ = target_run("/bin/rm", &["-f", "--", &out], false);
}

#[test]
fn ssh_file_created_with_expected_owner() {
    let _s = require_ssh!();
    let dir = controller_dir("ssh-owner");
    let target_home = target_user_home().expect("target home must resolve");
    let out = format!("{}/sinter-owner-test-{}", target_home, std::process::id());
    let recipe = controller_recipe(
        &dir,
        &format!(
            r#"  - id: f
    type: file
    with:
      path: {out}
      content: x
      mode: "0644"
"#,
            out = out
        ),
    );
    let r = run_recipe_target(&recipe, Mode::Apply, false, ssh());
    assert_success(&r);
    // Stat ON THE TARGET and compare to the target user's UID.
    let (_mode, uid, _gid, kind) = target_stat(&out, false);
    assert_eq!(kind, "regular file");
    assert_eq!(uid, target_uid().expect("target uid must resolve"));
    let _ = target_run("/bin/rm", &["-f", "--", &out], false);
}

#[test]
fn ssh_special_argv_file_roundtrip() {
    let _s = require_ssh!();
    let dir = controller_dir("ssh-roundtrip");
    let target_home = target_user_home().expect("target home must resolve");
    let out = format!("{}/sinter-roundtrip-{}", target_home, std::process::id());
    let recipe = controller_recipe(
        &dir,
        &format!(
            r#"  - id: emit
    type: command
    with:
      program: /usr/bin/printf
      args:
        - "%s"
        - "a b;c$(d)'e\"f"
      register: r
  - id: save
    type: file
    with:
      path: {out}
      content: "{{{{ registers.r.stdout }}}}"
      mode: "0644"
    depends_on: [emit]
"#,
            out = out
        ),
    );
    let r = run_recipe_target(&recipe, Mode::Apply, false, ssh());
    assert_success(&r);
    // Read the file ON THE TARGET.
    assert_eq!(target_read_file(&out, false), "a b;c$(d)'e\"f");
    let _ = target_run("/bin/rm", &["-f", "--", &out], false);
}

fn nosudo_ssh() -> Option<SshSpec> {
    let mut s = ssh_spec()?;
    s.user = std::env::var("SINTER_TEST_SSH_NOSUDO_USER")
        .unwrap_or_else(|_| "sinter-nosudo".to_string());
    Some(s)
}

#[test]
fn ssh_sudo_denied_is_hard_error() {
    let _s = require_ssh!();
    let Some(s) = nosudo_ssh() else {
        skip("no SSH target configured");
        return;
    };
    // Verify ON THE TARGET that this user genuinely lacks passwordless sudo;
    // otherwise the test premise is false and must not be treated as passing.
    let probe = spec_run(&s, "/usr/bin/sudo", &["-n", "/usr/bin/id", "-u"], false);
    match probe {
        Ok((0, ref out, _)) if out.trim() == "0" => {
            skip("nosudo user unexpectedly has passwordless sudo; premise invalid");
            return;
        }
        Err(e) => {
            // The nosudo user is not provisioned or unreachable; the premise
            // cannot be established. Report truthfully rather than silently pass.
            skip_or_fail(&format!(
                "could not probe nosudo user sudo capability: {}",
                e
            ));
            return;
        }
        _ => {}
    }
    let dir = controller_dir("ssh-sudo-denied");
    let recipe = controller_recipe(
        &dir,
        r#"  - id: who
    type: command
    with:
      program: /usr/bin/id
      args: ["-u"]"#,
    );
    let model = sinter::model::load_model(&recipe).unwrap();
    let opts = sinter::engine::RunOptions {
        mode: Mode::Apply,
        sudo: true,
        target: sinter::engine::TargetSpec { ssh: Some(s) },
        verbose: false,
        fault: None,
        fake_target: None,
    };
    let engine = match sinter::engine::Engine::new(model, opts) {
        // Failure to obtain root privilege is a hard error before any
        // privileged mutation. This is the expected contract.
        Err(e) => {
            assert_eq!(
                e.kind,
                sinter::error::ErrorKind::Connect,
                "sudo denial must be a connect/capability error, got {:?}",
                e
            );
            return;
        }
        Ok(engine) => engine,
    };
    let res = engine.run();
    // If construction somehow succeeded, the first privileged operation must
    // still fail hard; it must never silently fall back to unprivileged.
    match res {
        Err(e) => assert_ne!(e.kind, sinter::error::ErrorKind::Schema),
        Ok(report) => {
            let who = find(&report, "who");
            assert_ne!(who.execution, Execution::Succeeded);
        }
    }
}

#[test]
fn ssh_sudo_privileged_file_replace_read_verify() {
    let _s = require_ssh!();
    if !target_sudo_available() {
        skip("target does not provide passwordless sudo -n");
        return;
    }
    // Destination lives under a root-owned private directory, requiring root
    // for both read and replace.
    let outdir = target_private_dir("ssh-priv-file", true);
    let out = format!("{}/conf", outdir);
    // Seed initial root-owned content and prove it is there: the property is
    // that existing root-owned content gets replaced, which a missing seed
    // would not exercise.
    target_seed_file(&out, "initial root content", true);

    let ctrl = controller_dir("ssh-priv-file-recipe");
    let recipe = controller_recipe(
        &ctrl,
        &format!(
            r#"  - id: f
    type: file
    with:
      path: {out}
      content: "replaced by root"
      mode: "0600"
"#,
            out = out
        ),
    );
    let r = run_recipe_target(&recipe, Mode::Apply, true, ssh());
    assert_success(&r);
    let f = find(&r, "f");
    assert_eq!(f.verification, Verification::Verified);
    assert_eq!(target_read_file(&out, true), "replaced by root");

    // Second apply with root observation of the root-owned file: no mutation.
    let r2 = run_recipe_target(&recipe, Mode::Apply, true, ssh());
    assert_success(&r2);
    assert_eq!(find(&r2, "f").change, Change::None);
    assert_eq!(mutation_command_count(&r2), 0, "{:?}", r2.commands);
    target_cleanup_dir(&outdir, true);
}

// ---------------------------------------------------------------------------
// SSH stdout loss regression (stdout discarded before stdin EOF).
//
// The deterministic forced-timing cases T-2a/b/c are unit tests next to the
// executor (`executor::ssh_stdout_race_tests`), because they need the
// test-only seam. These cases exercise the unmodified product path end to end.
// Exit status 0 alone is never a pass: content, length and SHA-256 are checked.
// ---------------------------------------------------------------------------

fn sha256_hex(b: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(b)
        .iter()
        .map(|x| format!("{:02x}", x))
        .collect()
}

/// T-9: a wrong observation behind exit 0 is reported precisely (empty, head
/// or tail missing, capture truncation, or other mismatch).
fn assert_exact_stream(label: &str, stream: &str, got: &[u8], truncated: bool, want: &[u8]) {
    if got == want && !truncated {
        return;
    }
    let kind = if truncated {
        "TRUNCATED(capture cap)"
    } else if got.is_empty() {
        "EMPTY"
    } else if want.ends_with(got) {
        "HEAD-MISSING"
    } else if want.starts_with(got) {
        "TAIL-MISSING"
    } else {
        "MISMATCH"
    };
    let first_diff = got
        .iter()
        .zip(want.iter())
        .position(|(a, b)| a != b)
        .unwrap_or(got.len().min(want.len()));
    panic!(
        "{}: exit 0 but wrong {} observation {}: got {} bytes sha256={}, want {} bytes sha256={}, first difference at offset {}",
        label,
        stream,
        kind,
        got.len(),
        sha256_hex(got),
        want.len(),
        sha256_hex(want),
        first_diff
    );
}

fn sh_request(script: &str, timeout: u64) -> sinter::executor::ExecRequest {
    let mut req = sinter::executor::ExecRequest::new("/bin/sh");
    req.args = vec!["-c".into(), script.into()];
    req.timeout_secs = timeout;
    req.env.insert(
        "PATH".to_string(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
    );
    req.env.insert("LC_ALL".to_string(), "C".to_string());
    req
}

fn executed(label: &str) {
    eprintln!("SINTER_SSH_TEST_EXECUTED: {}", label);
}

/// T-1: short stdout over the product path, repeated on one session.
#[test]
fn ssh_stdout_short_exact_repeated() {
    let _s = require_ssh!();
    let Some(mut ex) = executor_for(&require_ssh!(), false) else {
        skip_or_fail("could not connect executor");
        return;
    };
    let mut req = sinter::executor::ExecRequest::new("/bin/echo");
    req.args = vec!["R-MARK".into()];
    req.timeout_secs = 10;
    for i in 0..200 {
        let out = ex.run(&req).expect("echo must complete");
        assert_eq!(
            out.completion,
            sinter::executor::Completion::Exited(0),
            "T-1 run {}",
            i
        );
        assert_exact_stream(
            &format!("T-1 run {}", i),
            "stdout",
            &out.stdout,
            out.stdout_truncated,
            b"R-MARK\n",
        );
    }
    executed("T-1 x200");
}

/// T-3: exactly 1 MiB of non-periodic stdout (the capture cap), repeated.
#[test]
fn ssh_stdout_1mib_exact_repeated() {
    let _s = require_ssh!();
    let Some(mut ex) = executor_for(&require_ssh!(), false) else {
        skip_or_fail("could not connect executor");
        return;
    };
    let lines = 131072usize;
    let mut want = Vec::with_capacity(lines * 8);
    for i in 0..lines {
        want.extend_from_slice(format!("{:07}\n", i).as_bytes());
    }
    assert_eq!(want.len(), 1024 * 1024);
    let req = sh_request(
        "awk 'BEGIN { for (i = 0; i < 131072; i++) printf \"%07d\\n\", i }'",
        20,
    );
    for i in 0..20 {
        let out = ex.run(&req).expect("1 MiB stdout must complete");
        assert_eq!(
            out.completion,
            sinter::executor::Completion::Exited(0),
            "T-3 run {}",
            i
        );
        assert_exact_stream(
            &format!("T-3 run {}", i),
            "stdout",
            &out.stdout,
            out.stdout_truncated,
            &want,
        );
    }
    // One byte over the cap is reported as truncation, not as loss.
    let over = sh_request(
        "awk 'BEGIN { for (i = 0; i < 131072; i++) printf \"%07d\\n\", i }'; printf X",
        20,
    );
    let out = ex.run(&over).expect("over-cap stdout must complete");
    assert_eq!(out.completion, sinter::executor::Completion::Exited(0));
    assert!(
        out.stdout_truncated,
        "T-3 over-cap must set stdout_truncated"
    );
    assert_eq!(
        out.stdout, want,
        "T-3 over-cap keeps exactly the first 1 MiB"
    );
    executed("T-3 x20 + over-cap");
}

/// T-4: interleaved stdout and stderr are both complete and exact.
#[test]
fn ssh_stdout_stderr_interleaved_exact() {
    let _s = require_ssh!();
    let Some(mut ex) = executor_for(&require_ssh!(), false) else {
        skip_or_fail("could not connect executor");
        return;
    };
    let req = sh_request(
        "i=0; while [ $i -lt 2000 ]; do printf 'o%d\\n' $i; printf 'e%d\\n' $i >&2; i=$((i+1)); done",
        20,
    );
    let mut want_out = Vec::new();
    let mut want_err = Vec::new();
    for i in 0..2000 {
        want_out.extend_from_slice(format!("o{}\n", i).as_bytes());
        want_err.extend_from_slice(format!("e{}\n", i).as_bytes());
    }
    for i in 0..10 {
        let out = ex.run(&req).expect("interleaved output must complete");
        assert_eq!(
            out.completion,
            sinter::executor::Completion::Exited(0),
            "T-4 run {}",
            i
        );
        let label = format!("T-4 run {}", i);
        assert_exact_stream(
            &label,
            "stdout",
            &out.stdout,
            out.stdout_truncated,
            &want_out,
        );
        assert_exact_stream(
            &label,
            "stderr",
            &out.stderr,
            out.stderr_truncated,
            &want_err,
        );
    }
    executed("T-4 x10");
}

/// T-7: more than 4 MiB of stdin is delivered completely, exactly once and
/// before EOF: the remote digest is only printed after EOF, and any lost,
/// duplicated or reordered byte changes it.
#[test]
fn ssh_large_stdin_4mib_digest_exact() {
    let _s = require_ssh!();
    let Some(mut ex) = executor_for(&require_ssh!(), false) else {
        skip_or_fail("could not connect executor");
        return;
    };
    let size = 4 * 1024 * 1024 + 12345;
    let payload: Vec<u8> = (0..size)
        .map(|i| (i as u32).wrapping_mul(2654435761).to_be_bytes()[0])
        .collect();
    let want = format!("{} {}\n", sha256_hex(&payload), size);
    let mut req = sh_request(
        "f=$(mktemp) || exit 3; cat >\"$f\"; \
         if command -v sha256sum >/dev/null 2>&1; then d=$(sha256sum <\"$f\"); else d=$(shasum -a 256 <\"$f\"); fi; \
         n=$(wc -c <\"$f\"); rm -f \"$f\"; printf '%s %s\\n' \"${d%% *}\" $n",
        30,
    );
    req.env.insert("TMPDIR".to_string(), "/tmp".to_string());
    req.stdin = Some(payload);
    for i in 0..3 {
        let out = ex.run(&req).expect("large stdin must complete");
        assert_eq!(
            out.completion,
            sinter::executor::Completion::Exited(0),
            "T-7 run {}: stderr={}",
            i,
            String::from_utf8_lossy(&out.stderr)
        );
        // `wc -c` may pad with spaces on some platforms.
        let got = String::from_utf8_lossy(&out.stdout)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            + "\n";
        assert_exact_stream(
            &format!("T-7 run {}", i),
            "stdout",
            got.as_bytes(),
            out.stdout_truncated,
            want.as_bytes(),
        );
    }
    executed("T-7 4MiB x3");
}

/// T-8: stdin backpressure against a command that never reads it ends as
/// Indeterminate (started) within the deadline, and the command is not run
/// again.
#[test]
fn ssh_stdin_backpressure_deadline_indeterminate_once() {
    let _s = require_ssh!();
    let Some(mut ex) = executor_for(&require_ssh!(), false) else {
        skip_or_fail("could not connect executor");
        return;
    };
    let marker = format!(
        ".sinter-t8-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let mut req = sh_request(&format!("echo run >> {}; exec sleep 30", marker), 3);
    req.stdin = Some(vec![b'z'; 4 * 1024 * 1024]);
    let started = std::time::Instant::now();
    let out = ex.run(&req).expect("backpressure run must return");
    let elapsed = started.elapsed();
    match &out.completion {
        sinter::executor::Completion::Indeterminate { started, reason } => {
            assert!(*started, "dispatch happened: started must be true");
            assert!(
                reason.contains("timed out") || reason.contains("deadline"),
                "T-8 reason must be a deadline: {}",
                reason
            );
        }
        other => panic!("T-8 expected Indeterminate, got {:?}", other),
    }
    assert!(
        elapsed <= std::time::Duration::from_secs(5),
        "T-8 must stay near the 3 s deadline, took {:?}",
        elapsed
    );
    drop(ex);
    // Count how many times the remote command started (fresh session).
    let Some(mut check) = executor_for(&require_ssh!(), false) else {
        skip_or_fail("could not reconnect executor");
        return;
    };
    let read = sh_request(&format!("cat {m}; rm -f {m}", m = marker), 10);
    let out = check.run(&read).expect("marker read must complete");
    assert_eq!(out.completion, sinter::executor::Completion::Exited(0));
    assert_exact_stream(
        "T-8 run count",
        "stdout",
        &out.stdout,
        out.stdout_truncated,
        b"run\n",
    );
    executed("T-8");
}

/// T-10 (executor level, runs on any POSIX target): failure classification is
/// unchanged. A non-zero exit keeps its exact stdout, a signal is reported as
/// a signal, and a timeout after dispatch is Indeterminate (started) with the
/// stdout read so far preserved. The engine-level variants above need a Linux
/// target.
#[test]
fn ssh_exec_failure_classification_exact() {
    let _s = require_ssh!();
    let Some(mut ex) = executor_for(&require_ssh!(), false) else {
        skip_or_fail("could not connect executor");
        return;
    };
    let out = ex
        .run(&sh_request("printf 'partial-out\\n'; exit 7", 10))
        .expect("exit 7 must complete");
    assert_eq!(out.completion, sinter::executor::Completion::Exited(7));
    assert_exact_stream(
        "T-10 exit 7",
        "stdout",
        &out.stdout,
        out.stdout_truncated,
        b"partial-out\n",
    );

    let out = ex
        .run(&sh_request("kill -TERM $$", 10))
        .expect("signal must complete");
    assert!(
        matches!(
            out.completion,
            sinter::executor::Completion::Signaled(_) | sinter::executor::Completion::Exited(143)
        ),
        "T-10 signal must not look like success: {:?}",
        out.completion
    );
    assert_ne!(out.completion, sinter::executor::Completion::Exited(0));

    let started = std::time::Instant::now();
    let out = ex
        .run(&sh_request("printf 'before-timeout\\n'; exec sleep 30", 1))
        .expect("timeout must return");
    let elapsed = started.elapsed();
    match &out.completion {
        sinter::executor::Completion::Indeterminate { started, .. } => assert!(*started),
        other => panic!("T-10 expected Indeterminate, got {:?}", other),
    }
    assert!(
        elapsed <= std::time::Duration::from_secs(3),
        "took {:?}",
        elapsed
    );
    assert_exact_stream(
        "T-10 timeout keeps stdout read so far",
        "stdout",
        &out.stdout,
        out.stdout_truncated,
        b"before-timeout\n",
    );
    executed("T-10 executor");
}
