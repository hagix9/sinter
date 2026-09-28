//! End-to-end multi-host apply over SSH: two throwaway unprivileged sshd
//! instances on loopback act as two inventory hosts.
//!
//! Opt-in and Linux-only (the target must be a supported Linux system):
//! `SINTER_TEST_LOCAL_SSHD=1`. Each sshd writes its own log, so "which host
//! was contacted" is observed from the server side.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

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
    _child: Kill,
}

impl Server {
    fn contacted(&self) -> bool {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .contains("Accepted publickey")
    }
}

struct Lab {
    dir: tempfile::TempDir,
    a: Server,
    b: Server,
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
            return Server {
                port,
                log,
                _child: guard,
            };
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    panic!("sshd {name} did not start");
}

impl Lab {
    fn start() -> Option<Lab> {
        if std::env::var("SINTER_TEST_LOCAL_SSHD").ok().as_deref() != Some("1") {
            eprintln!("SINTER_TEST_SKIPPED: SINTER_TEST_LOCAL_SSHD not set");
            return None;
        }
        // Files the recipes touch live under HOME, inside a private (0700)
        // directory so the §23 trust check passes for the target user.
        let base = PathBuf::from(std::env::var("HOME").unwrap()).join(".sinter-tests");
        std::fs::create_dir_all(&base).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = tempfile::Builder::new()
            .prefix("mh-")
            .tempdir_in(&base)
            .unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let d = dir.path();
        keygen(&d.join("hostkey"));
        keygen(&d.join("id"));
        std::fs::copy(d.join("id.pub"), d.join("authorized_keys")).unwrap();
        let a = start(d, "a");
        let b = start(d, "b");
        let hk = std::fs::read_to_string(d.join("hostkey.pub")).unwrap();
        let mut f = hk.split_whitespace();
        let (t, k) = (f.next().unwrap(), f.next().unwrap());
        std::fs::write(
            d.join("known_hosts"),
            format!(
                "[127.0.0.1]:{} {t} {k}\n[127.0.0.1]:{} {t} {k}\n",
                a.port, b.port
            ),
        )
        .unwrap();
        std::fs::write(
            d.join("hosts.yaml"),
            format!(
                "hosts:\n  web01:\n    address: 127.0.0.1\n    port: {}\n  db01:\n    address: 127.0.0.1\n    port: {}\n\
                 groups:\n  web:\n    hosts: [web01]\n  all-linux:\n    hosts: [web01, db01]\n",
                a.port, b.port
            ),
        )
        .unwrap();
        Some(Lab { dir, a, b })
    }

    fn p(&self, n: &str) -> PathBuf {
        self.dir.path().join(n)
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_sinter"))
            .args(args)
            .args([
                "--inventory",
                self.p("hosts.yaml").to_str().unwrap(),
                "--known-hosts",
                self.p("known_hosts").to_str().unwrap(),
                "--identity",
                self.p("id").to_str().unwrap(),
                "--no-ssh-config",
                "--format",
                "json",
            ])
            .env_remove("SSH_AUTH_SOCK")
            .output()
            .unwrap()
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

fn recipe(lab: &Lab, name: &str, targets: &str, file: &Path, backup: &[&Path]) -> String {
    let list: String = backup
        .iter()
        .map(|p| format!("    - {}\n", p.display()))
        .collect();
    let backup = if backup.is_empty() {
        String::new()
    } else {
        format!("backup:\n  paths:\n{list}")
    };
    let p = lab.p(name);
    std::fs::write(
        &p,
        format!(
            "version: 1\n{targets}{backup}resources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: new\n",
            file.display()
        ),
    )
    .unwrap();
    p.display().to_string()
}

#[test]
fn only_selected_hosts_are_contacted_and_backed_up() {
    let Some(lab) = Lab::start() else { return };
    let file = lab.p("conf");
    std::fs::write(&file, "old SECRET_CANARY_MH").unwrap();
    let r = recipe(
        &lab,
        "r.yaml",
        "targets:\n  groups: [web]\n",
        &file,
        &[&file],
    );
    let o = lab.run(&["apply", &r]);
    let v = json(&o);
    assert_eq!(o.status.code(), Some(0), "{v}");
    let ex = v["executions"].as_array().unwrap();
    assert_eq!(ex.len(), 1);
    assert_eq!(ex[0]["target"]["name"], "web01");
    assert!(lab.a.contacted(), "web01 must be contacted");
    assert!(
        !lab.b.contacted(),
        "db01 is not a target and must be untouched"
    );
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "new");
    let dir = ex[0]["result"]["backup"]["directory"].as_str().unwrap();
    let copy = format!("{}{}", dir, file.display());
    assert_eq!(
        std::fs::read_to_string(copy).unwrap(),
        "old SECRET_CANARY_MH"
    );
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(!all.contains("SECRET_CANARY_MH"), "backup content leaked");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn backup_failure_on_one_host_stops_every_later_change() {
    let Some(lab) = Lab::start() else { return };
    let file = lab.p("conf");
    std::fs::write(&file, "old").unwrap();
    let loose = lab.p("loose");
    std::fs::create_dir(&loose).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o777)).unwrap();
    std::fs::write(loose.join("x"), "x").unwrap();
    let r = recipe(
        &lab,
        "r.yaml",
        "targets:\n  groups: [all-linux]\n",
        &file,
        &[&loose.join("x")],
    );
    let o = lab.run(&["apply", &r]);
    assert_eq!(o.status.code(), Some(5), "{o:?}");
    let v = json(&o);
    let ex = v["executions"].as_array().unwrap();
    // Name order: db01 first; its backup fails, web01 is never attempted.
    assert_eq!(ex[0]["target"]["name"], "db01");
    assert_eq!(ex[0]["status"], "error");
    assert_eq!(ex[0]["error"]["kind"], "apply");
    assert_eq!(ex[1]["status"], "not_run");
    assert!(
        !lab.a.contacted(),
        "web01 must not be contacted after the failure"
    );
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        "old",
        "no change anywhere"
    );
}

#[test]
fn same_machine_under_two_names_collides_instead_of_mixing_backups() {
    // Both inventory hosts are this machine, so both executions would write
    // the same run directory. The second must fail rather than merge.
    let Some(lab) = Lab::start() else { return };
    let file = lab.p("conf");
    std::fs::write(&file, "old").unwrap();
    let r = recipe(
        &lab,
        "r.yaml",
        "targets:\n  groups: [all-linux]\n",
        &file,
        &[&file],
    );
    let o = lab.run(&["apply", &r]);
    let v = json(&o);
    assert_eq!(o.status.code(), Some(5), "{v}");
    let ex = v["executions"].as_array().unwrap();
    assert_eq!(ex[0]["status"], "success");
    assert_eq!(ex[1]["status"], "error");
    assert!(
        ex[1]["error"]["message"]
            .as_str()
            .unwrap()
            .contains("collision"),
        "{v}"
    );
    // Execution-level backup records stay with their own execution: db01
    // completed into its directory, web01 failed without claiming it.
    let (a, b) = (&ex[0]["backup"], &ex[1]["backup"]);
    assert_eq!(a["status"], "completed", "{v}");
    assert_eq!(a["directory"], ex[0]["result"]["backup"]["directory"]);
    assert_eq!(a["entries"][0]["status"], "backed_up");
    assert_eq!(b["status"], "failed", "{v}");
    assert!(
        b["directory"].is_null(),
        "a collided directory is not ours: {v}"
    );
    assert_eq!(b["entries"][0]["status"], "not_run");
    assert_eq!(a["run_id"], b["run_id"]);
    if let Some(d) = ex[0]["result"]["backup"]["directory"].as_str() {
        let _ = std::fs::remove_dir_all(d);
    }
}

#[test]
fn backup_failure_record_lists_each_path_outcome() {
    let Some(lab) = Lab::start() else { return };
    let file = lab.p("conf");
    std::fs::write(&file, "old SECRET_CANARY_FAIL").unwrap();
    let loose = lab.p("loose");
    std::fs::create_dir(&loose).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o777)).unwrap();
    std::fs::write(loose.join("x"), "x").unwrap();
    let later = lab.p("later");
    std::fs::write(&later, "later").unwrap();
    let r = recipe(
        &lab,
        "r.yaml",
        "targets:\n  hosts: [web01]\n",
        &file,
        &[&file, &loose.join("x"), &later],
    );
    let o = lab.run(&["apply", &r]);
    assert_eq!(o.status.code(), Some(5), "{o:?}");
    let v = json(&o);
    let b = &v["executions"][0]["backup"];
    assert_eq!(b["status"], "failed", "{v}");
    let dir = b["directory"].as_str().expect("run directory was created");
    let st: Vec<_> = b["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["status"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(st, vec!["backed_up", "failed", "not_run"]);
    // The backup failure stopped the apply: the managed file is untouched.
    assert!(
        std::fs::read_to_string(&file)
            .unwrap()
            .contains("SECRET_CANARY_FAIL"),
        "no resource may run after a backup failure"
    );
    let out = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(!out.contains("SECRET_CANARY_FAIL"), "backup content leaked");
    assert!(!o.stdout.contains(&0x1b), "no ANSI in JSON");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn bundle_backups_are_recorded_per_recipe() {
    let Some(lab) = Lab::start() else { return };
    let f1 = lab.p("one");
    let f2 = lab.p("two");
    std::fs::write(&f1, "one SECRET_CANARY_B1").unwrap();
    std::fs::write(&f2, "two SECRET_CANARY_B2").unwrap();
    recipe(
        &lab,
        "first.yaml",
        "targets:\n  hosts: [web01]\n",
        &f1,
        &[&f1],
    );
    recipe(
        &lab,
        "second.yaml",
        "targets:\n  hosts: [web01]\n",
        &f2,
        &[&f2],
    );
    let b = lab.p("stack.yaml");
    std::fs::write(&b, "version: 1\nrecipes: [first.yaml, second.yaml]\n").unwrap();
    let o = lab.run(&["apply", b.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    let v = json(&o);
    let ex = v["executions"].as_array().unwrap();
    let rec = |i: usize| (&ex[i]["recipe"], &ex[i]["backup"]);
    let (r1, b1) = rec(0);
    let (r2, b2) = rec(1);
    assert_eq!((r1.as_str(), r2.as_str()), (Some("first"), Some("second")));
    assert_eq!(b1["status"], "completed");
    assert_eq!(b2["status"], "completed");
    let d1 = b1["directory"].as_str().unwrap();
    let d2 = b2["directory"].as_str().unwrap();
    assert!(
        d1.ends_with("-01-first") && d2.ends_with("-02-second"),
        "{d1} {d2}"
    );
    assert_eq!(b1["entries"][0]["path"], f1.to_str().unwrap());
    assert_eq!(b2["entries"][0]["path"], f2.to_str().unwrap());
    // Each recipe's directory holds only its own path.
    assert!(std::path::Path::new(&format!("{d1}{}", f1.display())).exists());
    assert!(!std::path::Path::new(&format!("{d1}{}", f2.display())).exists());
    assert!(std::path::Path::new(&format!("{d2}{}", f2.display())).exists());
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(!out.contains("SECRET_CANARY_B"), "backup content leaked");
    let _ = std::fs::remove_dir_all(d1);
    let _ = std::fs::remove_dir_all(d2);
}

#[test]
fn apply_failure_on_one_host_stops_later_hosts() {
    // F-02: any non-zero apply execution (here apply_failed, exit 5) stops
    // the sequence; later hosts are not_run and never contacted.
    let Some(lab) = Lab::start() else { return };
    let r = lab.p("fail.yaml");
    std::fs::write(
        &r,
        "version: 1\ntargets:\n  groups: [all-linux]\nresources:\n  - id: boom\n    type: command\n    with:\n      program: /bin/false\n",
    )
    .unwrap();
    let o = lab.run(&["apply", r.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(5), "{o:?}");
    let v = json(&o);
    let ex = v["executions"].as_array().unwrap();
    assert_eq!(ex[0]["target"]["name"], "db01");
    assert_eq!(ex[0]["status"], "apply_failed");
    assert_eq!(ex[0]["exit_code"], 5);
    assert_eq!(ex[1]["status"], "not_run");
    assert!(ex[1]["exit_code"].is_null());
    assert_eq!(v["exit_code"], 5);
    assert!(lab.b.contacted() && !lab.a.contacted());
}

#[test]
fn plan_and_audit_report_every_selected_host() {
    let Some(lab) = Lab::start() else { return };
    let file = lab.p("conf");
    std::fs::write(&file, "new").unwrap();
    let r = recipe(
        &lab,
        "r.yaml",
        "targets:\n  groups: [all-linux]\n",
        &file,
        &[&file],
    );
    let o = lab.run(&["plan", &r]);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    let v = json(&o);
    for e in v["executions"].as_array().unwrap() {
        assert_eq!(e["result"]["backup"]["entries"][0]["status"], "planned");
    }
    let o = lab.run(&["audit", &r]);
    assert_eq!(o.status.code(), Some(0), "{o:?}");
    let v = json(&o);
    let names: Vec<_> = v["executions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["target"]["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, vec!["db01", "web01"]);
    assert!(lab.a.contacted() && lab.b.contacted());
}
