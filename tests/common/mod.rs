#![allow(dead_code)]
use sinter::engine::{AggregateStatus, Engine, Mode, RunOptions, SshSpec, TargetSpec};
use sinter::model::load_model;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// Create a private, trusted test root directory. It lives under $HOME (mode
/// 0700) so it satisfies the parent-path trust boundary check without
/// privileges on either a controller or target.
pub fn trusted_root(label: &str) -> PathBuf {
    let base = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/root"));
    let root_container = base.join(".sinter-tests");
    let _ = std::fs::create_dir_all(&root_container);
    // The whole ancestry must be demonstrably non-writable by untrusted
    // principals, so force 0700 on the container regardless of umask.
    set_mode(&root_container, 0o700);
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = root_container.join(format!("{}-{}-{}", label, std::process::id(), n));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    set_mode(&root_container, 0o700);
    set_mode(&dir, 0o700);
    dir
}

pub fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let mut p = std::fs::metadata(path).unwrap().permissions();
    p.set_mode(mode);
    std::fs::set_permissions(path, p).unwrap();
}

pub fn write_recipe(dir: &Path, name: &str, content: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, content).unwrap();
    p
}

pub fn run_recipe(recipe: &Path, mode: Mode, sudo: bool) -> sinter::engine::RunReport {
    run_recipe_target(recipe, mode, sudo, None)
}

pub fn try_run_recipe(
    recipe: &Path,
    mode: Mode,
    sudo: bool,
) -> Result<sinter::engine::RunReport, sinter::error::SinterError> {
    try_run_recipe_target(recipe, mode, sudo, None)
}

pub fn run_recipe_target(
    recipe: &Path,
    mode: Mode,
    sudo: bool,
    ssh: Option<SshSpec>,
) -> sinter::engine::RunReport {
    let model = load_model(recipe).unwrap();
    let opts = RunOptions {
        mode,
        sudo,
        target: TargetSpec { ssh },
        verbose: false,
        fault: None,
        fake_target: None,
    };
    let engine = Engine::new(model, opts).unwrap();
    engine.run().unwrap()
}

pub fn run_recipe_fault(recipe: &Path, mode: Mode, fault: &str) -> sinter::engine::RunReport {
    run_recipe_fault_sudo(recipe, mode, fault, false)
}

pub fn run_recipe_fault_sudo(
    recipe: &Path,
    mode: Mode,
    fault: &str,
    sudo: bool,
) -> sinter::engine::RunReport {
    let model = load_model(recipe).unwrap();
    let opts = RunOptions {
        mode,
        sudo,
        target: TargetSpec { ssh: None },
        verbose: false,
        fault: Some(fault.to_string()),
        fake_target: None,
    };
    let engine = Engine::new(model, opts).unwrap();
    engine.run().unwrap()
}

pub fn try_run_recipe_target(
    recipe: &Path,
    mode: Mode,
    sudo: bool,
    ssh: Option<SshSpec>,
) -> Result<sinter::engine::RunReport, sinter::error::SinterError> {
    let model = load_model(recipe)?;
    let opts = RunOptions {
        mode,
        sudo,
        target: TargetSpec { ssh },
        verbose: false,
        fault: None,
        fake_target: None,
    };
    let engine = Engine::new(model, opts)?;
    engine.run()
}

/// Run a recipe against a scripted in-process target (platform-detection and
/// package/service behavior tests that must not depend on a real host).
/// Everything above the command transport runs production code.
pub fn run_recipe_fake(
    recipe: &Path,
    mode: Mode,
    sudo: bool,
    fake: sinter::executor::FakeTarget,
) -> sinter::engine::RunReport {
    try_run_recipe_fake(recipe, mode, sudo, fake)
        .unwrap_or_else(|e| panic!("fake run failed: {}", e.message))
}

pub fn try_run_recipe_fake(
    recipe: &Path,
    mode: Mode,
    sudo: bool,
    fake: sinter::executor::FakeTarget,
) -> Result<sinter::engine::RunReport, sinter::error::SinterError> {
    let model = load_model(recipe)?;
    let opts = RunOptions {
        mode,
        sudo,
        target: TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(fake),
    };
    let engine = Engine::new(model, opts)?;
    engine.run()
}

/// A fake-target run with a resource-layer fault injection.
pub fn run_recipe_fake_fault(
    recipe: &Path,
    mode: Mode,
    sudo: bool,
    fake: sinter::executor::FakeTarget,
    fault: &str,
) -> sinter::engine::RunReport {
    let model = load_model(recipe).unwrap();
    let opts = RunOptions {
        mode,
        sudo,
        target: TargetSpec { ssh: None },
        verbose: false,
        fault: Some(fault.to_string()),
        fake_target: Some(fake),
    };
    let engine = Engine::new(model, opts).unwrap();
    engine.run().unwrap()
}

pub fn find<'a>(
    report: &'a sinter::engine::RunReport,
    id: &str,
) -> &'a sinter::result::ResourceResult {
    report
        .resources
        .iter()
        .find(|r| r.id == id)
        .unwrap_or_else(|| panic!("resource {} not found in report", id))
}

/// Count raw mutation commands in the execution audit log.
pub fn mutation_command_count(report: &sinter::engine::RunReport) -> usize {
    report
        .commands
        .iter()
        .filter(|c| is_mutation_command(&c.program, &c.args))
        .count()
}

pub fn is_mutation_command(program: &str, args: &[String]) -> bool {
    let prog = program.rsplit('/').next().unwrap_or(program);
    match prog {
        "chmod" | "chown" | "chgrp" | "mkdir" | "rmdir" | "rm" | "mv" | "ln" | "mktemp"
        | "setfattr" | "setfacl" | "tee" => true,
        "sh" => {
            // A shell invocation mutates if its command line contains a mutation tool.
            args.iter().any(|a| {
                a.contains("/bin/rm ")
                    || a.contains("/bin/mv ")
                    || a.contains("/bin/chmod ")
                    || a.contains("/bin/chown ")
                    || a.contains("/bin/mkdir ")
                    || a.contains("/bin/rmdir ")
                    || a.contains("/bin/ln ")
                    || a.contains("base64 -d")
            })
        }
        "apt-get" | "dnf" | "yum" => args
            .iter()
            .any(|a| a == "install" || a == "remove" || a == "purge"),
        "systemctl" => args.iter().any(|a| {
            matches!(
                a.as_str(),
                "start" | "stop" | "restart" | "reload" | "enable" | "disable" | "reset-failed"
            )
        }),
        _ => false,
    }
}

pub fn assert_success(report: &sinter::engine::RunReport) {
    assert_eq!(
        report.status,
        AggregateStatus::Success,
        "expected success report"
    );
}

/// The SSH daemon's systemd unit name on this controller's local host:
/// Debian/Ubuntu ships `ssh.service`, the RHEL family ships `sshd.service`.
/// Tests that observe a real unit must not hardcode one family's spelling —
/// both are supported targets, and a wrong name fails the recipe instead of
/// the behavior under test.
pub fn local_ssh_unit() -> String {
    for name in ["ssh", "sshd"] {
        let loaded = std::process::Command::new("/usr/bin/systemctl")
            .args(["show", &format!("{name}.service"), "--property=LoadState"])
            .output();
        if let Ok(o) = loaded {
            if String::from_utf8_lossy(&o.stdout).trim() == "LoadState=loaded" {
                return name.to_string();
            }
        }
    }
    "ssh".to_string()
}

/// The OS family this controller's local host reports, so a test can assert
/// the family-appropriate branch of a `when: facts.os.family` recipe instead
/// of assuming the family it happens to run on.
pub fn local_os_family() -> String {
    match std::fs::read_to_string("/etc/os-release") {
        Ok(c) => {
            let id = c
                .lines()
                .find_map(|l| l.trim().strip_prefix("ID="))
                .map(|v| v.trim().trim_matches('"').to_ascii_lowercase())
                .unwrap_or_default();
            let id_like = c
                .lines()
                .find_map(|l| l.trim().strip_prefix("ID_LIKE="))
                .map(|v| v.trim().trim_matches('"').to_ascii_lowercase())
                .unwrap_or_default();
            sinter::facts::derive_family(&id, &id_like)
        }
        Err(_) => String::new(),
    }
}

/// Build an SSH target spec from environment variables. Returns None when
/// SINTER_TEST_SSH_HOST is unset, so SSH tests can be skipped on controllers
/// without a disposable target.
pub fn ssh_spec() -> Option<SshSpec> {
    let host = std::env::var("SINTER_TEST_SSH_HOST").ok()?;
    let port = std::env::var("SINTER_TEST_SSH_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(22);
    let user = std::env::var("SINTER_TEST_SSH_USER").unwrap_or_else(|_| "a0000".to_string());
    let known_hosts = std::env::var_os("SINTER_TEST_SSH_KNOWN_HOSTS")
        .map(PathBuf::from)
        .expect("SINTER_TEST_SSH_KNOWN_HOSTS must be set when SSH tests run");
    let identity_files = std::env::var_os("SINTER_TEST_SSH_IDENTITY")
        .map(|i| vec![PathBuf::from(i)])
        .unwrap_or_default();
    Some(SshSpec {
        host,
        port,
        user,
        known_hosts,
        identity_files,
    })
}

/// A private trusted directory owned by root, for `--sudo` integration tests.
/// Requires working passwordless `sudo -n` on the target.
pub fn trusted_root_sudo(label: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = PathBuf::from(format!(
        "/root/.sinter-tests/{}-{}-{}",
        label,
        std::process::id(),
        n
    ));
    let _ = std::process::Command::new("sudo")
        .args(["-n", "rm", "-rf"])
        .arg(&dir)
        .status();
    let status = std::process::Command::new("sudo")
        .args(["-n", "install", "-d", "-m", "0700"])
        .arg(&dir)
        .status()
        .expect("failed to run sudo");
    assert!(status.success(), "could not create sudo test root");
    dir
}

pub fn sudo_available() -> bool {
    std::process::Command::new("sudo")
        .args(["-n", "true"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn read_file_sudo(path: &std::path::Path) -> String {
    let out = std::process::Command::new("sudo")
        .args(["-n", "cat"])
        .arg(path)
        .output()
        .expect("sudo cat failed");
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// Create a controller-side recipe directory that is readable by the current
/// (unprivileged) test process but whose outputs may live elsewhere.
pub fn controller_dir(label: &str) -> PathBuf {
    trusted_root(&format!("ctrl-{}", label))
}

// ---------------------------------------------------------------------------
// Target-side helpers for genuine controller/target separation.
//
// These operate explicitly on the *target* via SSH so tests never read a remote
// path through the controller filesystem, never compare a target UID to the
// controller UID, and never infer target sudo capability from the controller.
// ---------------------------------------------------------------------------

use sinter::executor::{ExecRequest, Executor, SshConfig, SshExecutor};

/// Connect an executor to an explicit SSH target spec.
pub fn executor_for(spec: &SshSpec, sudo: bool) -> Option<Executor> {
    let cfg = SshConfig {
        host: spec.host.clone(),
        port: spec.port,
        user: spec.user.clone(),
        known_hosts: spec.known_hosts.clone(),
        identity_files: spec.identity_files.clone(),
    };
    SshExecutor::connect(&cfg, sudo).ok().map(Executor::Ssh)
}

/// Run a program on an explicit SSH target spec. Returns (exit, stdout, stderr).
pub fn spec_run(
    spec: &SshSpec,
    program: &str,
    args: &[&str],
    sudo: bool,
) -> std::result::Result<(i32, String, String), String> {
    let mut ex =
        executor_for(spec, sudo).ok_or_else(|| "could not connect to target".to_string())?;
    let mut req = ExecRequest::new(program);
    req.args = args.iter().map(|s| s.to_string()).collect();
    req.env = target_baseline_env(sudo);
    let out = ex.run(&req).map_err(|e| e.message)?;
    match out.completion {
        sinter::executor::Completion::Exited(c) => Ok((
            c,
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )),
        other => Err(format!("target command did not complete: {:?}", other)),
    }
}

/// Connect an executor to the SSH target. Returns None when no SSH target is
/// configured.
pub fn target_executor(sudo: bool) -> Option<Executor> {
    let s = ssh_spec()?;
    executor_for(&s, sudo)
}

/// Run a program on the target with exact argv. Returns (exit_code, stdout, stderr).
pub fn target_run(
    program: &str,
    args: &[&str],
    sudo: bool,
) -> std::result::Result<(i32, String, String), String> {
    let mut ex = target_executor(sudo).ok_or_else(|| "no SSH target configured".to_string())?;
    let mut req = ExecRequest::new(program);
    req.args = args.iter().map(|s| s.to_string()).collect();
    req.env = target_baseline_env(sudo);
    let out = ex.run(&req).map_err(|e| e.message)?;
    match out.completion {
        sinter::executor::Completion::Exited(c) => Ok((
            c,
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )),
        other => Err(format!("target command did not complete: {:?}", other)),
    }
}

fn target_baseline_env(sudo: bool) -> std::collections::BTreeMap<String, String> {
    let mut env = std::collections::BTreeMap::new();
    env.insert(
        "PATH".to_string(),
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
    );
    env.insert("LANG".to_string(), "C.UTF-8".to_string());
    env.insert("LC_ALL".to_string(), "C.UTF-8".to_string());
    // HOME for the unprivileged case is left for the executor's own clean
    // environment handling; here it only needs to be a valid, non-recursive
    // value. The executor never inherits it from the controller.
    env.insert(
        "HOME".to_string(),
        if sudo {
            "/root".to_string()
        } else {
            "/tmp".to_string()
        },
    );
    env
}

/// The target user's home directory, resolved on the target.
pub fn target_user_home() -> Option<String> {
    let user = std::env::var("SINTER_TEST_SSH_USER").unwrap_or_else(|_| "a0000".to_string());
    let (code, stdout, _) = target_run("/usr/bin/getent", &["passwd", &user], false).ok()?;
    if code != 0 {
        return None;
    }
    let line = stdout.lines().next().unwrap_or("");
    let parts: Vec<&str> = line.trim().split(':').collect();
    if parts.len() >= 6 && !parts[5].is_empty() {
        Some(parts[5].to_string())
    } else {
        None
    }
}

/// The target execution user's UID, resolved on the target.
pub fn target_uid() -> Option<u32> {
    let (code, stdout, _) = target_run("/usr/bin/id", &["-u"], false).ok()?;
    if code != 0 {
        return None;
    }
    stdout.trim().parse().ok()
}

/// Whether passwordless sudo works on the target (probed on the target).
pub fn target_sudo_available() -> bool {
    matches!(target_run("/usr/bin/id", &["-u"], true), Ok((0, ref s, _)) if s.trim() == "0")
}

/// Create a private (0700) directory on the target and return its absolute path.
/// The parent chain is made non-writable by untrusted principals.
pub fn target_private_dir(label: &str, sudo: bool) -> String {
    let base = if sudo {
        "/root".to_string()
    } else {
        target_user_home().expect("target home must be resolvable for tests")
    };
    let root = format!("{}/.sinter-tests", base);
    let dir = format!("{}/{}-{}", root, label, std::process::id());
    // Create parent then child with restrictive modes. install -d is used
    // because it creates parents and sets the mode atomically.
    let root_status = target_run("/usr/bin/install", &["-d", "-m", "0700", &root], sudo);
    assert!(
        root_status.is_ok(),
        "could not create target test root: {:?}",
        root_status
    );
    let child = target_run("/usr/bin/install", &["-d", "-m", "0700", &dir], sudo);
    assert!(
        child.is_ok(),
        "could not create target test dir: {:?}",
        child
    );
    dir
}

/// Read a file *on the target* via SSH. Never uses the controller filesystem.
pub fn target_read_file(path: &str, sudo: bool) -> String {
    let (code, stdout, stderr) =
        target_run("/bin/cat", &["--", path], sudo).expect("target cat failed to run");
    assert_eq!(code, 0, "target cat {} failed: {}", path, stderr);
    stdout
}

/// Stat a target object and return (mode, uid, gid, kind) read on the target.
pub fn target_stat(path: &str, sudo: bool) -> (u32, u32, u32, String) {
    let (code, stdout, stderr) =
        target_run("/usr/bin/stat", &["-c", "%a|%u|%g|%F", "--", path], sudo)
            .expect("target stat failed to run");
    assert_eq!(code, 0, "target stat {} failed: {}", path, stderr);
    let parts: Vec<&str> = stdout.trim().split('|').collect();
    assert_eq!(parts.len(), 4, "unexpected stat output: {}", stdout);
    (
        u32::from_str_radix(parts[0], 8).unwrap(),
        parts[1].parse().unwrap(),
        parts[2].parse().unwrap(),
        parts[3].to_string(),
    )
}

/// Remove a target-side test directory.
pub fn target_cleanup_dir(path: &str, sudo: bool) {
    let _ = target_run("/bin/rm", &["-rf", "--", path], sudo);
}

/// Truthful skip/fail helper.
///
/// When `SINTER_TEST_STRICT=1` is set (used for the reference acceptance run),
/// a missing prerequisite is a hard failure: a required test can never silently
/// pass. Otherwise the test is reported as an explicit skip via a structured
/// marker so it is distinguishable from a genuine pass.
pub fn skip_or_fail(reason: &str) {
    if std::env::var("SINTER_TEST_STRICT").ok().as_deref() == Some("1") {
        panic!("SINTER_TEST_REQUIRED: {}", reason);
    }
    eprintln!("SINTER_TEST_SKIPPED: {}", reason);
}

/// Skip explicitly with a truthful reason. Prefer `skip_or_fail` for anything
/// the reference acceptance run must exercise.
pub fn skip(reason: &str) {
    skip_or_fail(reason);
}

/// A cross-process advisory lock protecting tests that mutate the shared
/// systemd `ssh` service. Tests running in parallel (within or across test
/// binaries) would otherwise interfere by restarting/stopping the same unit.
pub struct ServiceGuard {
    file: std::fs::File,
}

impl Drop for ServiceGuard {
    fn drop(&mut self) {
        unsafe {
            libc::flock(std::os::fd::AsRawFd::as_raw_fd(&self.file), libc::LOCK_UN);
        }
    }
}

/// Acquire the shared-service lock, blocking until available.
pub fn lock_service() -> ServiceGuard {
    use std::os::fd::AsRawFd;
    let path = std::env::temp_dir().join(".sinter-test-service.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .expect("could not open service lock file");
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    assert_eq!(rc, 0, "could not acquire service lock");
    ServiceGuard { file }
}
