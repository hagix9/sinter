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
        "apt-get" | "dnf" | "yum" => {
            // `dnf install --downloadonly` transports payload files without
            // mutating the rpmdb — only the later `dnf -C install` mutates.
            !args.iter().any(|a| a == "--downloadonly")
                && args
                    .iter()
                    .any(|a| a == "install" || a == "remove" || a == "purge")
        }
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
        ..Default::default()
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
    let cfg = SshConfig::from(spec);
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

/// What `target_run` returns: `Ok` means the command ran to completion (with
/// any exit code), `Err` that it could not be run or did not complete.
pub type TargetRunResult = std::result::Result<(i32, String, String), String>;

/// Require that a target command ran *and* exited 0, returning its
/// `(stdout, stderr)`. `target_run`'s `Ok` alone is not success: a fixture step
/// that exited non-zero is still `Ok((code, ..))`, so checking `is_ok()` lets a
/// failed setup pass. Setup steps must go through this instead.
pub fn require_target_success(what: &str, result: TargetRunResult) -> (String, String) {
    match result {
        Ok((0, stdout, stderr)) => (stdout, stderr),
        Ok((code, stdout, stderr)) => {
            panic!("{what} failed with exit {code}: stdout={stdout:?} stderr={stderr:?}")
        }
        Err(e) => panic!("{what} could not run: {e}"),
    }
}

/// Create a private (0700) directory on the target and return its absolute path.
/// The parent chain is made non-writable by untrusted principals.
pub fn target_private_dir(label: &str, sudo: bool) -> String {
    target_private_dir_with(label, sudo, &mut target_run)
}

/// `target_private_dir` over an explicit command runner, so its failure
/// handling can be exercised without a target.
pub fn target_private_dir_with(
    label: &str,
    sudo: bool,
    run: &mut dyn FnMut(&str, &[&str], bool) -> TargetRunResult,
) -> String {
    let base = if sudo {
        "/root".to_string()
    } else {
        target_user_home().expect("target home must be resolvable for tests")
    };
    let root = format!("{}/.sinter-tests", base);
    let dir = format!("{}/{}-{}", root, label, std::process::id());
    // Create parent then child with restrictive modes. install -d is used
    // because it creates parents and sets the mode atomically.
    require_target_success(
        "creating the target test root",
        run("/usr/bin/install", &["-d", "-m", "0700", &root], sudo),
    );
    require_target_success(
        "creating the target test dir",
        run("/usr/bin/install", &["-d", "-m", "0700", &dir], sudo),
    );
    dir
}

/// Put `content` at `path` on the target, then read it back and require an
/// exact match. A fixture that "was seeded" without this proof would let the
/// test pass from an unprepared initial state.
pub fn target_seed_file(path: &str, content: &str, sudo: bool) {
    target_seed_file_with(path, content, sudo, &mut target_run)
}

/// `target_seed_file` over an explicit command runner.
pub fn target_seed_file_with(
    path: &str,
    content: &str,
    sudo: bool,
    run: &mut dyn FnMut(&str, &[&str], bool) -> TargetRunResult,
) {
    let script = format!(
        "printf '%s' {} > {}",
        sh_single_quote(content),
        sh_single_quote(path)
    );
    require_target_success(
        "seeding the target fixture file",
        run("/bin/sh", &["-c", &script], sudo),
    );
    let (stdout, _) = require_target_success(
        "reading the seeded target fixture file back",
        run("/bin/cat", &["--", path], sudo),
    );
    assert_eq!(
        stdout, content,
        "the target fixture file must hold the seeded content"
    );
}

/// POSIX single-quote `s` for use inside a `sh -c` script.
pub fn sh_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
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

/// Check how `test` (a test of the running test binary) handles a missing
/// prerequisite, by rerunning it in a child process whose environment is
/// changed by `set` and `remove`: without strict mode (`SINTER_TEST_STRICT`
/// unset, `0`, or `true`) it must skip with `reason` and pass; with
/// `SINTER_TEST_STRICT=1` it must fail with `reason`.
pub fn assert_skips_unless_strict(test: &str, reason: &str, set: &[(&str, &str)], remove: &[&str]) {
    for strict in [None, Some("0"), Some("true"), Some("1")] {
        let mut c = std::process::Command::new(std::env::current_exe().unwrap());
        c.args([test, "--exact", "--nocapture", "--test-threads=1"]);
        c.env_remove("SINTER_TEST_STRICT");
        for k in remove {
            c.env_remove(k);
        }
        for (k, v) in set {
            c.env(k, v);
        }
        if let Some(v) = strict {
            c.env("SINTER_TEST_STRICT", v);
        }
        let out = c.output().expect("could not rerun the test binary");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            text.contains("running 1 test"),
            "{test} must run on its own: {text}"
        );
        if strict == Some("1") {
            assert!(
                !out.status.success(),
                "{test} passed under strict mode: {text}"
            );
            assert!(
                text.contains(&format!("SINTER_TEST_REQUIRED: {reason}")),
                "{test}: {text}"
            );
        } else {
            assert!(out.status.success(), "{test} (strict={strict:?}): {text}");
            assert!(
                text.contains(&format!("SINTER_TEST_SKIPPED: {reason}")),
                "{test} (strict={strict:?}): {text}"
            );
        }
    }
}

/// A cross-process advisory lock protecting tests that mutate systemd
/// services (a `ServiceFixture`, or `ssh` in the package/service test).
/// Tests running in parallel (within or across test binaries) would
/// otherwise interfere by restarting/stopping units and reloading systemd.
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

/// A dedicated, disposable systemd service for service and handler lifecycle
/// tests, so they never stop, restart, disable or re-enable the host's own
/// SSH service. On the Linux gate that service is the host's control plane
/// and SSH reference target, and on Ubuntu 24.04 `ssh.service` carries
/// `Alias=sshd.service`: disabling and re-enabling it can leave the unit
/// inactive while sshd keeps its ports, after which it cannot start again.
///
/// The fixture is a plain long-running unit with a reload action and no
/// alias, created running and enabled (the state these tests start from) and
/// removed on drop. Hold `lock_service()` for its whole lifetime.
pub struct ServiceFixture {
    name: String,
}

impl ServiceFixture {
    /// Create `sinter-test-<label>.service`, running and enabled. `label`
    /// must be a plain `[a-z0-9-]` word.
    pub fn create(label: &str) -> ServiceFixture {
        assert!(
            !label.is_empty()
                && label
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
            "invalid fixture label {label:?}"
        );
        let name = format!("sinter-test-{label}");
        let setup = std::process::Command::new("sudo")
            .args(["-n", "/bin/sh", "-c"])
            .arg(format!(
                "printf '%s\\n' '[Unit]' 'Description=Sinter test fixture {name}' '[Service]' 'Type=simple' 'ExecStart=/bin/sleep infinity' 'ExecReload=/bin/true' '[Install]' 'WantedBy=multi-user.target' > /etc/systemd/system/{name}.service && systemctl daemon-reload && systemctl reset-failed {name}.service >/dev/null 2>&1; systemctl enable {name}.service && systemctl restart {name}.service"
            ))
            .status();
        assert!(
            setup.map(|s| s.success()).unwrap_or(false),
            "could not create service fixture {name}"
        );
        let fixture = ServiceFixture { name };
        assert_eq!(fixture.property("ActiveState"), "active");
        assert_eq!(fixture.property("UnitFileState"), "enabled");
        fixture
    }

    /// The unit name as a recipe refers to it (no `.service` suffix, like
    /// `local_ssh_unit()`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// One `systemctl show` property of the fixture unit.
    pub fn property(&self, property: &str) -> String {
        let out = std::process::Command::new("/usr/bin/systemctl")
            .args([
                "show",
                "-p",
                property,
                "--value",
                &format!("{}.service", self.name),
            ])
            .output()
            .expect("systemctl show");
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }
}

impl Drop for ServiceFixture {
    fn drop(&mut self) {
        let _ = std::process::Command::new("sudo")
            .args(["-n", "/bin/sh", "-c"])
            .arg(format!(
                "systemctl stop {n}.service >/dev/null 2>&1; systemctl disable {n}.service >/dev/null 2>&1; systemctl reset-failed {n}.service >/dev/null 2>&1; rm -f /etc/systemd/system/{n}.service; systemctl daemon-reload",
                n = self.name
            ))
            .status();
    }
}

/// A cross-process advisory lock protecting tests that mutate the shared
/// apt/dpkg package database. Real `apt-get` invocations take
/// `/var/lib/dpkg/lock-frontend`: two such tests running in parallel (within
/// one test binary or across binaries) contend on that lock, and apt then
/// fails the loser. This is test infrastructure only (RA2-02) — it serializes
/// the tests and never alters product behavior.
pub struct PackageDatabaseGuard {
    file: std::fs::File,
}

impl Drop for PackageDatabaseGuard {
    fn drop(&mut self) {
        unsafe {
            libc::flock(std::os::fd::AsRawFd::as_raw_fd(&self.file), libc::LOCK_UN);
        }
    }
}

/// Acquire the shared apt/dpkg mutation lock, blocking until available.
///
/// The guard must be held for the *whole* critical section: every real
/// apt-get invocation a test performs — pre-test `apt-get remove` cleanup,
/// the install/remove mutation itself, and post-test cleanup — takes the dpkg
/// frontend lock, so the advisory guard has to outlive all of them. Acquire it
/// first, before any apt-get call, and let it drop only at the end of the
/// test. Do not acquire the service lock while holding this one in reverse
/// order elsewhere (lock ordering is package-database, then service).
pub fn lock_package_database() -> PackageDatabaseGuard {
    use std::os::fd::AsRawFd;
    let path = std::env::temp_dir().join(".sinter-test-package-db.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .expect("could not open package database lock file");
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    assert_eq!(rc, 0, "could not acquire package database lock");
    PackageDatabaseGuard { file }
}

/// A cross-process advisory lock protecting tests that use the per-user
/// Sinter backup store (`$HOME/.sinter/backups`). Every non-sudo apply with a
/// `backup` section creates or traverses that shared store; when two such
/// tests create it for the first time concurrently, one can observe the
/// directory between its creation and its `chmod 0700` and (correctly)
/// refuse it as group-writable under a permissive umask. This is test
/// infrastructure only — it serializes those tests and never alters product
/// behavior.
pub struct BackupStoreGuard {
    file: std::fs::File,
}

impl Drop for BackupStoreGuard {
    fn drop(&mut self) {
        unsafe {
            libc::flock(std::os::fd::AsRawFd::as_raw_fd(&self.file), libc::LOCK_UN);
        }
    }
}

/// Acquire the backup-store lock, blocking until available.
pub fn lock_backup_store() -> BackupStoreGuard {
    use std::os::fd::AsRawFd;
    let path = std::env::temp_dir().join(".sinter-test-backup-store.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .expect("could not open backup store lock file");
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    assert_eq!(rc, 0, "could not acquire backup store lock");
    BackupStoreGuard { file }
}

// ---------------------------------------------------------------------------
// Verified fixture preconditions
// ---------------------------------------------------------------------------

/// The programs that put a systemd unit into the "not-found" state and prove
/// it got there. Tests use `UnitSetupTools::host()`; the two
/// `SINTER_TEST_UNIT_*` variables let a test substitute a failing program only
/// to prove that a setup failure fails the test under `SINTER_TEST_STRICT=1`
/// instead of leaving an unprepared fixture behind.
pub struct UnitSetupTools {
    /// Privilege wrapper: the removal script runs as `<sudo> -n /bin/sh -c <script>`.
    pub sudo: String,
    /// `systemctl` as the removal script (running as root) invokes it.
    pub admin_systemctl: String,
    /// `systemctl` for the read-only state query that proves the result.
    pub query_systemctl: String,
}

impl UnitSetupTools {
    pub fn host() -> Self {
        UnitSetupTools {
            sudo: std::env::var("SINTER_TEST_UNIT_SUDO").unwrap_or_else(|_| "sudo".to_string()),
            admin_systemctl: "systemctl".to_string(),
            query_systemctl: std::env::var("SINTER_TEST_UNIT_QUERY")
                .unwrap_or_else(|_| "/usr/bin/systemctl".to_string()),
        }
    }
}

/// Why "the unit is not-found" could not be established. Each variant's
/// message starts with a fixed phrase so a test can name the failing step.
#[derive(Debug, PartialEq, Eq)]
pub enum UnitPreconditionError {
    /// The removal command could not be started.
    RemovalNotRun(String),
    /// The removal command ran and exited unsuccessfully.
    RemovalFailed(String),
    /// The removal reported success but the unit file is still there.
    UnitFileStillPresent(String),
    /// The state could not be read, so absence is unproven (never "absent").
    StateUnknown(String),
    /// The state was read and the unit is not not-found/inactive.
    NotAbsent(String),
}

impl std::fmt::Display for UnitPreconditionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnitPreconditionError::RemovalNotRun(m) => {
                write!(f, "unit removal could not run: {m}")
            }
            UnitPreconditionError::RemovalFailed(m) => write!(f, "unit removal failed: {m}"),
            UnitPreconditionError::UnitFileStillPresent(m) => {
                write!(f, "unit file still present after removal: {m}")
            }
            UnitPreconditionError::StateUnknown(m) => {
                write!(f, "unit state could not be determined: {m}")
            }
            UnitPreconditionError::NotAbsent(m) => {
                write!(f, "unit not absent after removal: {m}")
            }
        }
    }
}

/// Put `unit` (`<name>.service`, installed at `unit_path`) into the state
/// "not-found and inactive", and *prove* that state before returning `Ok`.
///
/// `stop`/`disable`/`reset-failed` legitimately fail for a unit that is already
/// not-found, so their exit status is not the setup result; removing the file
/// and reloading systemd are, and the resulting state is then read back
/// independently: the unit file must be gone and systemd must report
/// `LoadState=not-found`, `ActiveState=inactive`. A state that cannot be read
/// is an error, never "absent".
pub fn establish_unit_not_found(
    tools: &UnitSetupTools,
    unit: &str,
    unit_path: &str,
) -> Result<(), UnitPreconditionError> {
    use UnitPreconditionError::*;
    let (sc, u, p) = (
        sh_single_quote(&tools.admin_systemctl),
        sh_single_quote(unit),
        sh_single_quote(unit_path),
    );
    let script = format!(
        "{sc} stop {u} >/dev/null 2>&1; {sc} disable {u} >/dev/null 2>&1; {sc} reset-failed {u} >/dev/null 2>&1; rm -f {p} && {sc} daemon-reload"
    );
    let status = std::process::Command::new(&tools.sudo)
        .args(["-n", "/bin/sh", "-c"])
        .arg(script)
        .status()
        .map_err(|e| RemovalNotRun(format!("{}: {e}", tools.sudo)))?;
    if !status.success() {
        return Err(RemovalFailed(format!("{unit}: {status}")));
    }
    match std::fs::symlink_metadata(unit_path) {
        Ok(_) => return Err(UnitFileStillPresent(unit_path.to_string())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(StateUnknown(format!("{unit_path}: {e}"))),
    }
    let out = std::process::Command::new(&tools.query_systemctl)
        .args(["show", "-p", "LoadState", "-p", "ActiveState", unit])
        .output()
        .map_err(|e| StateUnknown(format!("{}: {e}", tools.query_systemctl)))?;
    if !out.status.success() {
        return Err(StateUnknown(format!(
            "systemctl show {unit}: {}",
            out.status
        )));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let prop = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{key}=")))
            .map(|v| v.trim().to_string())
    };
    let (Some(load), Some(active)) = (prop("LoadState"), prop("ActiveState")) else {
        return Err(StateUnknown(format!(
            "systemctl show {unit} printed no LoadState/ActiveState: {text:?}"
        )));
    };
    if load != "not-found" || active != "inactive" {
        return Err(NotAbsent(format!(
            "{unit}: LoadState={load} ActiveState={active}"
        )));
    }
    Ok(())
}

/// Establish the not-found precondition on the host. Returns `true` when it is
/// proven and the test may continue; otherwise the test must return, having
/// been skipped with a marker or, under `SINTER_TEST_STRICT=1`, failed.
pub fn require_unit_not_found(unit: &str, unit_path: &str) -> bool {
    match establish_unit_not_found(&UnitSetupTools::host(), unit, unit_path) {
        Ok(()) => true,
        Err(e) => {
            skip_or_fail(&format!("unit precondition not established ({unit}): {e}"));
            false
        }
    }
}
