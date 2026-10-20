//! `--limit` against real OpenSSH: two throwaway unprivileged `sshd` instances
//! on loopback act as the inventory hosts `web01` and `db01`, and the real
//! `ssh` client evaluates a configuration with a `Match exec` that records the
//! port it was evaluated for. "Which host was contacted" is observed from the
//! server side (the sshd logs), and "for which host was `ssh -G` evaluated" from
//! the marker the `Match exec` writes, so a fake `ssh` proves nothing here.
//!
//! The `ssh` found first on `PATH` is a two-line shim that records its arguments
//! and runs the real `ssh` with `-F <lab config>` (OpenSSH reads `~/.ssh/config`
//! from the passwd entry, not from `$HOME`, so the lab cannot redirect it any
//! other way). Everything else, the `Match exec` included, is the real client.
//!
//! Opt-in and Linux-only like `multihost_lab`: `SINTER_TEST_LOCAL_SSHD=1`;
//! without it the tests skip, and under `SINTER_TEST_STRICT=1` they fail.
#![cfg(target_os = "linux")]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/// A fictitious value that must never be printed.
const CANARY: &str = "SINTER_LIMIT_LAB_CANARY_DO_NOT_PRINT_20261020";

struct Kill(Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Server {
    port: u16,
    log: PathBuf,
    /// How many connections and authentications the log already held when the
    /// current check began (the readiness probe is itself a connection). The
    /// log is never truncated, so a late line cannot be lost or miscounted.
    conn_base: std::cell::Cell<usize>,
    auth_base: std::cell::Cell<usize>,
    _child: Kill,
}

impl Server {
    fn count(&self, what: &str) -> usize {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .matches(what)
            .count()
    }

    /// Start counting from now.
    fn mark(&self) {
        self.conn_base.set(self.count("Connection from"));
        self.auth_base.set(self.count("Accepted publickey"));
    }

    /// Whether anything connected to this sshd since the last `mark`,
    /// authenticated or not.
    fn connected(&self) -> bool {
        self.count("Connection from") > self.conn_base.get()
    }

    fn authenticated(&self) -> bool {
        self.count("Accepted publickey") > self.auth_base.get()
    }
}

struct Lab {
    dir: tempfile::TempDir,
    web: Server,
    db: Server,
}

fn keygen(path: &Path) {
    assert!(Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(path)
        .status()
        .unwrap()
        .success());
}

fn start(dir: &Path, name: &str) -> Server {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let cfg = dir.join(format!("sshd_{name}"));
    std::fs::write(
        &cfg,
        format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {d}/hostkey\nAuthorizedKeysFile {d}/authorized_keys\n\
             PidFile {d}/{name}.pid\nUsePAM no\nStrictModes no\nPasswordAuthentication no\n\
             KbdInteractiveAuthentication no\nLogLevel VERBOSE\n",
            d = dir.display()
        ),
    )
    .unwrap();
    let log = dir.join(format!("{name}.log"));
    let child = Command::new("/usr/sbin/sshd")
        .args(["-D", "-f"])
        .arg(&cfg)
        .arg("-E")
        .arg(&log)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let guard = Kill(child);
    for _ in 0..200 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            let server = Server {
                port,
                log,
                conn_base: std::cell::Cell::new(0),
                auth_base: std::cell::Cell::new(0),
                _child: guard,
            };
            // The probe above is itself a connection: wait until sshd has
            // logged it, then count only what comes after.
            for _ in 0..200 {
                if server.count("Connection from") > 0 {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            server.mark();
            return server;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    panic!("sshd {name} did not start");
}

/// The real `ssh` on `PATH` (the first one that is not the lab's shim).
fn real_ssh() -> PathBuf {
    for d in std::env::var("PATH").unwrap_or_default().split(':') {
        let p = Path::new(d).join("ssh");
        if p.is_file() {
            return p;
        }
    }
    panic!("SINTER_TEST_REQUIRED: no OpenSSH client (ssh) on PATH");
}

impl Lab {
    fn start() -> Option<Lab> {
        if std::env::var("SINTER_TEST_LOCAL_SSHD").ok().as_deref() != Some("1") {
            common::skip_or_fail("SINTER_TEST_LOCAL_SSHD not set");
            return None;
        }
        let base = PathBuf::from(std::env::var("HOME").unwrap()).join(".sinter-tests");
        std::fs::create_dir_all(&base).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = tempfile::Builder::new()
            .prefix("ll-")
            .tempdir_in(&base)
            .unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let d = dir.path();
        keygen(&d.join("hostkey"));
        keygen(&d.join("id"));
        std::fs::copy(d.join("id.pub"), d.join("authorized_keys")).unwrap();
        let web = start(d, "web");
        let db = start(d, "db");
        let hk = std::fs::read_to_string(d.join("hostkey.pub")).unwrap();
        let mut f = hk.split_whitespace();
        let (t, k) = (f.next().unwrap(), f.next().unwrap());
        std::fs::write(
            d.join("known_hosts"),
            format!(
                "[127.0.0.1]:{} {t} {k}\n[127.0.0.1]:{} {t} {k}\n",
                web.port, db.port
            ),
        )
        .unwrap();
        std::fs::write(
            d.join("hosts.yaml"),
            format!(
                "hosts:\n  web01:\n    address: 127.0.0.1\n    port: {}\n  db01:\n    address: 127.0.0.1\n    port: {}\n\
                 groups:\n  web:\n    hosts: [web01]\n  db:\n    hosts: [db01]\n  all-linux:\n    hosts: [web01, db01]\n",
                web.port, db.port
            ),
        )
        .unwrap();
        // The real client's configuration: `Match exec` runs on every
        // evaluation (`ssh -G` included) and records the port it saw.
        std::fs::write(
            d.join("ssh_config"),
            format!(
                "Match exec \"echo %p >> {}/match-exec.marker\"\n",
                d.display()
            ),
        )
        .unwrap();
        let shim_dir = d.join("shim");
        std::fs::create_dir(&shim_dir).unwrap();
        let shim = shim_dir.join("ssh");
        std::fs::write(
            &shim,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}/ssh-calls.log'\nexec '{}' -F '{}/ssh_config' \"$@\"\n",
                d.display(),
                real_ssh().display(),
                d.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();
        Some(Lab { dir, web, db })
    }

    fn p(&self, n: &str) -> PathBuf {
        self.dir.path().join(n)
    }

    /// Run `sinter` with the lab inventory and the real OpenSSH client (its
    /// configuration is evaluated: no `--no-ssh-config`).
    fn run(&self, args: &[&str]) -> std::process::Output {
        let path = format!(
            "{}:{}",
            self.p("shim").display(),
            std::env::var("PATH").unwrap_or_default()
        );
        Command::new(env!("CARGO_BIN_EXE_sinter"))
            .args(args)
            .args([
                "--inventory",
                self.p("hosts.yaml").to_str().unwrap(),
                "--known-hosts",
                self.p("known_hosts").to_str().unwrap(),
                "--identity",
                self.p("id").to_str().unwrap(),
                "--format",
                "json",
            ])
            .env("PATH", path)
            .env("NO_COLOR", "1")
            .env("SINTER_PROGRESS", "never")
            .env_remove("SSH_AUTH_SOCK")
            .output()
            .unwrap()
    }

    /// The ports the `Match exec` ran for, one entry per evaluation.
    fn evaluated_ports(&self) -> Vec<u16> {
        std::fs::read_to_string(self.p("match-exec.marker"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.trim().parse().ok())
            .collect()
    }

    /// The arguments of every `ssh` invocation (the shim's log).
    fn ssh_calls(&self) -> Vec<String> {
        std::fs::read_to_string(self.p("ssh-calls.log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn reset(&self) {
        for n in ["match-exec.marker", "ssh-calls.log"] {
            std::fs::write(self.p(n), "").ok();
        }
        self.web.mark();
        self.db.mark();
    }

    /// Nothing happened at all: no evaluation, no connection to either host.
    fn assert_untouched(&self, what: &str) {
        assert!(self.evaluated_ports().is_empty(), "{what}: Match exec ran");
        assert!(self.ssh_calls().is_empty(), "{what}: ssh ran");
        assert!(!self.web.connected(), "{what}: web01 was contacted");
        assert!(!self.db.connected(), "{what}: db01 was contacted");
    }
}

fn json(o: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| {
        panic!(
            "{e}: stdout={} stderr={}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        )
    })
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).to_string()
}

/// A recipe for the `all-linux` group that writes `file`, with a root variable.
fn recipe(lab: &Lab, file: &Path) -> String {
    let p = lab.p("r.yaml");
    std::fs::write(
        &p,
        format!(
            "version: 1\ntargets:\n  groups: [all-linux]\nvars:\n  body: {{ value: new }}\n  tok: {{ value: {CANARY}, sensitive: true }}\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: \"{{{{ vars.body }}}}\"\n",
            file.display()
        ),
    )
    .unwrap();
    p.display().to_string()
}

#[test]
fn ssh_g_and_connections_are_for_the_selected_host_only() {
    let Some(lab) = Lab::start() else { return };
    let file = lab.p("conf");
    let r = recipe(&lab, &file);
    for phase in ["plan", "audit", "apply"] {
        lab.reset();
        let o = lab.run(&[phase, &r, "--limit", "web01"]);
        let v = json(&o);
        // `audit` runs before `apply`: the file is missing, which is drift (7).
        let want = if phase == "audit" { 7 } else { 0 };
        assert_eq!(
            o.status.code(),
            Some(want),
            "{phase}: {v} {}",
            text(&o.stderr)
        );
        let ex = v["executions"].as_array().unwrap();
        assert_eq!(ex.len(), 1, "{phase}: {v}");
        assert_eq!(ex[0]["target"]["name"], "web01");
        // The real client was evaluated for web01's port, and never for db01's.
        let ports = lab.evaluated_ports();
        assert!(ports.contains(&lab.web.port), "{phase}: {ports:?}");
        assert!(!ports.contains(&lab.db.port), "{phase}: {ports:?}");
        for call in lab.ssh_calls() {
            assert!(call.starts_with("-G "), "{phase}: {call}");
            assert!(
                call.contains(&format!("-p {} --", lab.web.port)),
                "{phase}: {call}"
            );
        }
        // Only web01 was connected to and authenticated against.
        assert!(lab.web.authenticated(), "{phase}: web01 not reached");
        assert!(!lab.db.connected(), "{phase}: db01 was contacted");
    }
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "new");
}

#[test]
fn a_group_and_several_items_select_only_what_they_name() {
    let Some(lab) = Lab::start() else { return };
    let r = recipe(&lab, &lab.p("conf"));
    for (limit, web, db) in [
        ("group:web", true, false),
        ("host:db01", false, true),
        ("web01,db01", true, true),
        ("group:web,group:db", true, true),
        ("web*", true, false),
    ] {
        lab.reset();
        let o = lab.run(&["plan", &r, "--limit", limit]);
        assert_eq!(o.status.code(), Some(0), "{limit}: {}", text(&o.stderr));
        let ports = lab.evaluated_ports();
        assert_eq!(ports.contains(&lab.web.port), web, "{limit}: {ports:?}");
        assert_eq!(ports.contains(&lab.db.port), db, "{limit}: {ports:?}");
        assert_eq!(lab.web.connected(), web, "{limit}");
        assert_eq!(lab.db.connected(), db, "{limit}");
    }
}

#[test]
fn a_refused_limit_and_validate_touch_nothing() {
    let Some(lab) = Lab::start() else { return };
    let r = recipe(&lab, &lab.p("conf"));
    let vars = lab.p("vars.yaml");
    std::fs::write(&vars, "version: 1\nvars: { body: other }\n").unwrap();
    // Refused before anything is evaluated or contacted.
    for limit in ["nosuch", "", "web01,", "bad name", "host:nosuch", "*zzz"] {
        for phase in ["plan", "audit", "apply", "validate"] {
            lab.reset();
            let o = lab.run(&[phase, &r, "--limit", limit]);
            assert_eq!(
                o.status.code(),
                Some(2),
                "{phase} {limit:?}: {}",
                text(&o.stderr)
            );
            lab.assert_untouched(&format!("{phase} --limit {limit:?}"));
        }
    }
    // `validate` checks the selection without evaluating or connecting.
    for extra in [&[][..], &["--vars-file", vars.to_str().unwrap()][..]] {
        lab.reset();
        let mut args = vec!["validate", &r, "--limit", "web01"];
        args.extend_from_slice(extra);
        let o = lab.run(&args);
        assert_eq!(o.status.code(), Some(0), "{extra:?}: {}", text(&o.stderr));
        lab.assert_untouched(&format!("validate {extra:?}"));
    }
}

#[test]
fn without_a_limit_every_target_is_evaluated_and_contacted_as_before() {
    let Some(lab) = Lab::start() else { return };
    let r = recipe(&lab, &lab.p("conf"));
    lab.reset();
    let o = lab.run(&["plan", &r]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let ports = lab.evaluated_ports();
    assert!(
        ports.contains(&lab.web.port) && ports.contains(&lab.db.port),
        "{ports:?}"
    );
    assert!(lab.web.authenticated() && lab.db.authenticated());
}

#[test]
fn an_unselected_hosts_variable_error_does_not_stop_the_selected_host() {
    let Some(lab) = Lab::start() else { return };
    let file = lab.p("conf");
    let r = recipe(&lab, &file);
    // db01's layer names a variable the recipe does not declare.
    let vars = lab.p("vars.yaml");
    std::fs::write(
        &vars,
        "version: 1\nhosts:\n  db01: { nosuchvariable: 1 }\n  web01: { body: from-web01 }\n",
    )
    .unwrap();
    lab.reset();
    let o = lab.run(&["apply", &r, "--vars-file", vars.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(2), "without --limit it is an error");
    lab.assert_untouched("apply without --limit, db01 layer wrong");
    lab.reset();
    let o = lab.run(&[
        "apply",
        &r,
        "--vars-file",
        vars.to_str().unwrap(),
        "--limit",
        "web01",
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "from-web01");
    assert!(!lab.evaluated_ports().contains(&lab.db.port));
    assert!(!lab.db.connected());
}

#[test]
fn a_sensitive_override_is_refused_for_an_unselected_host_too() {
    let Some(lab) = Lab::start() else { return };
    let file = lab.p("conf");
    let r = recipe(&lab, &file);
    for layer in [
        format!("hosts:\n  db01: {{ tok: {CANARY} }}\n"),
        format!("hosts:\n  web01: {{ tok: {CANARY} }}\n"),
        format!("groups:\n  db: {{ tok: {CANARY} }}\n"),
        format!("vars: {{ tok: {CANARY} }}\n"),
    ] {
        let vars = lab.p("vars.yaml");
        std::fs::write(&vars, format!("version: 1\n{layer}")).unwrap();
        for phase in ["plan", "apply", "validate"] {
            lab.reset();
            let o = lab.run(&[
                phase,
                &r,
                "--vars-file",
                vars.to_str().unwrap(),
                "--limit",
                "web01",
            ]);
            assert_eq!(o.status.code(), Some(2), "{phase} {layer}");
            let all = format!("{}{}", text(&o.stdout), text(&o.stderr));
            assert!(all.contains("sensitive"), "{phase}: {all}");
            assert!(!all.contains(CANARY), "LEAK {phase}");
            lab.assert_untouched(&format!("{phase} {layer}"));
        }
    }
    assert!(!file.exists(), "nothing was written");
}

#[test]
fn a_recipe_no_host_runs_is_skipped_but_still_held_to_its_structure() {
    let Some(lab) = Lab::start() else { return };
    let file = lab.p("conf");
    std::fs::write(
        lab.p("web.yaml"),
        format!(
            "version: 1\ntargets:\n  groups: [web]\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: web\n",
            file.display()
        ),
    )
    .unwrap();
    let db = |resource: &str| {
        std::fs::write(
            lab.p("db.yaml"),
            format!(
                "version: 1\ntargets:\n  groups: [db]\nvars:\n  root: {{ value: CHANGE_ME }}\nresources:\n{resource}"
            ),
        )
        .unwrap();
    };
    std::fs::write(
        lab.p("b.yaml"),
        "version: 1\nrecipes: [web.yaml, db.yaml]\n",
    )
    .unwrap();
    let b = lab.p("b.yaml").display().to_string();
    // A placeholder default alone does not stop the selected host ...
    db("  - { id: d, type: file, with: { path: \"{{ vars.root }}/x\", content: y } }\n");
    lab.reset();
    let o = lab.run(&["apply", &b, "--limit", "web01"]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let v = json(&o);
    assert_eq!(v["resolution"][1]["excluded_by"], "limit", "{v}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "web");
    assert!(!lab.evaluated_ports().contains(&lab.db.port));
    assert!(!lab.db.connected());
    // ... but a defect that no variable decides does, before any contact.
    db("  - { id: d, type: file, with: { path: \"{{ vars.root }}/x\", owner: \"\", content: y } }\n");
    std::fs::write(&file, "old").unwrap();
    lab.reset();
    let o = lab.run(&["apply", &b, "--limit", "web01"]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o.stderr));
    assert!(
        text(&o.stderr).contains("invalid owner"),
        "{}",
        text(&o.stderr)
    );
    lab.assert_untouched("a defect in the skipped recipe");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "old");
}
