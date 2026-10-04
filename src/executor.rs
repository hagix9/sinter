use crate::error::{Result, SinterError};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const MAX_CAPTURE: usize = 1024 * 1024;

#[derive(Clone)]
pub struct ExecRequest {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Option<String>,
    pub env: BTreeMap<String, String>,
    /// Bytes sent to the command's standard input. They may be a decrypted
    /// secret: zeroized when the request is dropped and never printed.
    pub stdin: Option<Vec<u8>>,
    pub timeout_secs: u64,
    /// When true, the command line (program/args/cwd/env values) may contain
    /// sensitive material. Internal audit records must never store the raw form.
    pub sensitive: bool,
}

impl Drop for ExecRequest {
    fn drop(&mut self) {
        if let Some(b) = self.stdin.as_mut() {
            zeroize::Zeroize::zeroize(b);
        }
    }
}

impl std::fmt::Debug for ExecRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The command line is shown as the request carries it; standard input
        // is never shown, only whether it is present.
        f.debug_struct("ExecRequest")
            .field("program", &self.program)
            .field("args", &self.args)
            .field("cwd", &self.cwd)
            .field("env", &self.env)
            .field("stdin", &self.stdin.as_ref().map(|_| "[redacted]"))
            .field("timeout_secs", &self.timeout_secs)
            .field("sensitive", &self.sensitive)
            .finish()
    }
}

impl ExecRequest {
    pub fn new(program: &str) -> Self {
        ExecRequest {
            program: program.to_string(),
            args: Vec::new(),
            cwd: None,
            env: BTreeMap::new(),
            stdin: None,
            timeout_secs: 300,
            sensitive: false,
        }
    }

    pub fn arg(mut self, a: impl Into<String>) -> Self {
        self.args.push(a.into());
        self
    }

    pub fn args<I, S>(mut self, items: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for a in items {
            self.args.push(a.into());
        }
        self
    }

    pub fn cwd(mut self, c: impl Into<String>) -> Self {
        self.cwd = Some(c.into());
        self
    }

    pub fn env(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.env.insert(k.into(), v.into());
        self
    }

    pub fn stdin(mut self, b: Vec<u8>) -> Self {
        self.stdin = Some(b);
        self
    }

    pub fn timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    pub fn sensitive(mut self, sensitive: bool) -> Self {
        self.sensitive = sensitive;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Completion {
    Exited(i32),
    Signaled(i32),
    /// Completion cannot be established. `started` indicates whether dispatch
    /// was confirmed to have begun.
    Indeterminate {
        started: bool,
        reason: String,
    },
}

#[derive(Debug, Clone)]
pub struct Output {
    pub completion: Completion,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

impl Output {
    pub fn exit_code(&self) -> Option<i32> {
        match self.completion {
            Completion::Exited(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_success(&self) -> bool {
        matches!(self.completion, Completion::Exited(0))
    }

    pub fn stdout_string(&self) -> Option<String> {
        if self.stdout_truncated {
            return None;
        }
        std::str::from_utf8(&self.stdout)
            .ok()
            .map(|s| s.to_string())
    }

    pub fn stderr_string(&self) -> Option<String> {
        if self.stderr_truncated {
            return None;
        }
        std::str::from_utf8(&self.stderr)
            .ok()
            .map(|s| s.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct CommandRecord {
    pub program: String,
    pub args: Vec<String>,
    /// Environment passed to the target process. Sensitive requests retain
    /// only a redacted marker, just like program and argv.
    pub env: BTreeMap<String, String>,
    pub sudo: bool,
    /// True when the recorded invocation may carry sensitive values. The stored
    /// program/args are then a redacted placeholder, never the raw command line.
    pub sensitive: bool,
}

// ---------------------------------------------------------------------------
// Command statistics (performance measurement, WP-P0)
// ---------------------------------------------------------------------------
//
// Why this exists: every observation Sinter makes is one target command (one
// SSH exec channel when the target is remote), and those round trips dominate
// wall-clock time. These statistics let tests and later work answer "how many
// commands, caused by what, taking how long" without guessing.
//
// What one command is: one request submitted to a concrete executor's `run`
// (`SshExecutor` = one exec channel, `LocalExecutor` = one child process,
// `FakeExecutor` = one scripted request). That entry point is the only way a
// command reaches a target, so counting there is authoritative. It also sees
// the three target execs that never pass through `Executor::run` and are
// therefore absent from the `CommandRecord` log: the SSH `getent passwd`
// HOME lookup made while connecting, and `id -u` / `id -g`. Not counted: the
// local `ssh -G` subprocess, the local `getent` that finds the controller's
// own home for a *local* target, TCP connect/handshake/authentication (no
// exec), and anything that is not a target command. A command that fails or
// times out still counts (it was submitted); its outcome is recorded.
//
// Safety: a `CommandStat` holds only a coarse label (program basename, or
// "[redacted]" for a sensitive request, exactly like `CommandRecord`), the
// sudo flag, a fixed scope label, the elapsed time and a coarse outcome. It
// never holds argv, environment, standard input, output or any value derived
// from them, and it is diagnostic only: nothing reads it to decide anything.

/// Coarse result of one target command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandOutcome {
    /// Exited with status 0.
    Success,
    /// Exited with a non-zero status.
    NonZeroExit,
    /// Terminated by a signal.
    Signaled,
    /// Completion could not be established (for example a timeout).
    Indeterminate,
    /// The transport returned an error instead of a completion.
    TransportError,
}

/// One target command. See the module comment above for what is (not) held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandStat {
    /// What the run was doing: `setup`, `connect`, `backup`, a resource type
    /// (`file`, `directory`, `link`, `template`, `command`, `package`,
    /// `service`, `group`, `user`), `handler` or `manager`.
    pub scope: &'static str,
    /// Program basename, or `[redacted]` for a sensitive request.
    pub program: String,
    pub sudo: bool,
    pub elapsed: Duration,
    pub outcome: CommandOutcome,
}

/// A snapshot of the commands submitted to one target, in submission order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecStats {
    pub commands: Vec<CommandStat>,
}

impl ExecStats {
    /// Total commands submitted.
    pub fn total(&self) -> usize {
        self.commands.len()
    }

    /// Commands whose program basename is `program` (for example `getent`).
    pub fn count_program(&self, program: &str) -> usize {
        self.commands
            .iter()
            .filter(|c| c.program == program)
            .count()
    }

    /// Commands issued while `scope` was current.
    pub fn count_scope(&self, scope: &str) -> usize {
        self.commands.iter().filter(|c| c.scope == scope).count()
    }

    /// Commands per program basename.
    pub fn by_program(&self) -> BTreeMap<String, usize> {
        let mut m = BTreeMap::new();
        for c in &self.commands {
            *m.entry(c.program.clone()).or_insert(0) += 1;
        }
        m
    }

    /// Commands per scope.
    pub fn by_scope(&self) -> BTreeMap<&'static str, usize> {
        let mut m = BTreeMap::new();
        for c in &self.commands {
            *m.entry(c.scope).or_insert(0) += 1;
        }
        m
    }

    /// Commands that did not exit 0.
    pub fn not_successful(&self) -> usize {
        self.commands
            .iter()
            .filter(|c| c.outcome != CommandOutcome::Success)
            .count()
    }

    /// Commands run under sudo.
    pub fn sudo_commands(&self) -> usize {
        self.commands.iter().filter(|c| c.sudo).count()
    }

    /// Sum of the commands' elapsed times (time spent waiting on the target).
    pub fn elapsed(&self) -> Duration {
        self.commands.iter().map(|c| c.elapsed).sum()
    }
}

#[derive(Debug)]
struct StatsInner {
    scope: &'static str,
    commands: Vec<CommandStat>,
}

/// A shared handle to one executor's statistics. It stays valid after the
/// engine that owns the executor has been consumed by `run`, so callers take
/// it first (`Engine::exec_stats`) and read it afterwards.
#[derive(Debug, Clone)]
pub struct ExecStatsHandle(Arc<Mutex<StatsInner>>);

/// The scope before anything sets one: executor construction and the
/// capability/fact probes of `Engine::new`.
const SCOPE_SETUP: &str = "setup";

impl Default for ExecStatsHandle {
    fn default() -> Self {
        ExecStatsHandle(Arc::new(Mutex::new(StatsInner {
            scope: SCOPE_SETUP,
            commands: Vec::new(),
        })))
    }
}

impl ExecStatsHandle {
    fn lock(&self) -> std::sync::MutexGuard<'_, StatsInner> {
        // Diagnostic data only: a poisoned lock is still readable.
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Label the commands that follow. Only fixed labels are accepted.
    pub fn set_scope(&self, scope: &'static str) {
        self.lock().scope = scope;
    }

    /// A copy of the commands submitted so far.
    pub fn snapshot(&self) -> ExecStats {
        ExecStats {
            commands: self.lock().commands.clone(),
        }
    }

    /// Record one command that went through an executor's `run`.
    fn note(&self, req: &ExecRequest, sudo: bool, elapsed: Duration, out: Option<&Output>) {
        let outcome = match out.map(|o| &o.completion) {
            Some(Completion::Exited(0)) => CommandOutcome::Success,
            Some(Completion::Exited(_)) => CommandOutcome::NonZeroExit,
            Some(Completion::Signaled(_)) => CommandOutcome::Signaled,
            Some(Completion::Indeterminate { .. }) => CommandOutcome::Indeterminate,
            None => CommandOutcome::TransportError,
        };
        let program = if req.sensitive {
            "[redacted]".to_string()
        } else {
            req.program
                .rsplit('/')
                .next()
                .unwrap_or(&req.program)
                .to_string()
        };
        let mut g = self.lock();
        let scope = g.scope;
        g.commands.push(CommandStat {
            scope,
            program,
            sudo,
            elapsed,
            outcome,
        });
    }

    /// Record the SSH HOME lookup made while connecting (it is a target exec
    /// that has no `ExecRequest`).
    fn note_connect(&self, program: &'static str, elapsed: Duration, ok: bool) {
        self.lock().commands.push(CommandStat {
            scope: "connect",
            program: program.to_string(),
            sudo: false,
            elapsed,
            outcome: if ok {
                CommandOutcome::Success
            } else {
                CommandOutcome::TransportError
            },
        });
    }
}

pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub known_hosts: PathBuf,
    pub identity_files: Vec<PathBuf>,
    pub host_key_alias: Option<String>,
    pub agent: crate::engine::AgentSource,
    pub identities_only: bool,
}

impl From<&crate::engine::SshSpec> for SshConfig {
    fn from(s: &crate::engine::SshSpec) -> Self {
        SshConfig {
            host: s.host.clone(),
            port: s.port,
            user: s.user.clone(),
            known_hosts: s.known_hosts.clone(),
            identity_files: s.identity_files.clone(),
            host_key_alias: s.host_key_alias.clone(),
            agent: s.agent.clone(),
            identities_only: s.identities_only,
        }
    }
}

pub enum Executor {
    Local(LocalExecutor),
    Ssh(SshExecutor),
    /// Deterministic in-process scripted target used by tests only. It is
    /// constructed exclusively through `RunOptions::fake_target`; the CLI
    /// never builds it. Everything above the transport boundary (engine,
    /// model, targetfs, result classification, command recording) still runs
    /// production code.
    Fake(Box<FakeExecutor>),
}

impl Executor {
    pub fn is_sudo(&self) -> bool {
        match self {
            Executor::Local(l) => l.sudo,
            Executor::Ssh(s) => s.sudo,
            Executor::Fake(f) => f.sudo,
        }
    }

    pub fn sudo(&self) -> bool {
        self.is_sudo()
    }

    pub fn run(&mut self, req: &ExecRequest) -> Result<Output> {
        self.record(req);
        match self {
            Executor::Local(l) => l.run(req),
            Executor::Ssh(s) => s.run(req),
            Executor::Fake(f) => Ok(f.run(req)),
        }
    }

    /// The statistics handle of the active executor (see [`ExecStatsHandle`]).
    pub fn stats_handle(&self) -> ExecStatsHandle {
        match self {
            Executor::Local(l) => l.stats.clone(),
            Executor::Ssh(s) => s.stats.clone(),
            Executor::Fake(f) => f.stats.clone(),
        }
    }

    /// The full audit log of raw command invocations performed by this executor.
    /// This is an internal facility used to verify that plan performs no
    /// mutation operations.
    pub fn log(&self) -> Vec<CommandRecord> {
        match self {
            Executor::Local(l) => l.log.clone(),
            Executor::Ssh(s) => s.log.clone(),
            Executor::Fake(f) => f.log.clone(),
        }
    }

    fn record(&mut self, req: &ExecRequest) {
        let sudo = self.is_sudo();
        // DESIGN §31.4: no logger may receive raw sensitive values. When the
        // request is sensitive, store only a non-reconstructable placeholder.
        let rec = if req.sensitive {
            CommandRecord {
                program: "[redacted]".to_string(),
                args: vec!["[redacted]".to_string()],
                env: BTreeMap::from([("[redacted]".to_string(), "[redacted]".to_string())]),
                sudo,
                sensitive: true,
            }
        } else {
            CommandRecord {
                program: req.program.clone(),
                args: req.args.clone(),
                env: req.env.clone(),
                sudo,
                sensitive: false,
            }
        };
        match self {
            Executor::Local(l) => l.log.push(rec),
            Executor::Ssh(s) => s.log.push(rec),
            Executor::Fake(f) => f.log.push(rec),
        }
    }

    /// Run a command and require a zero exit status. Used for target-side
    /// helper operations where a non-zero status is an error.
    pub fn run_ok(&mut self, req: &ExecRequest) -> Result<Output> {
        let out = self.run(req)?;
        match out.completion {
            Completion::Exited(0) => Ok(out),
            Completion::Exited(c) => Err(SinterError::apply(format!(
                "target command {} failed with exit code {}",
                req.program, c
            ))),
            Completion::Signaled(s) => Err(SinterError::apply(format!(
                "target command {} terminated by signal {}",
                req.program, s
            ))),
            Completion::Indeterminate { reason, .. } => Err(SinterError::indeterminate(format!(
                "target command {} did not complete: {}",
                req.program, reason
            ))),
        }
    }

    /// The effective target execution identity for the invocation.
    /// With --sudo this is root. Otherwise it is the connected/local target user.
    pub fn target_identity(&mut self) -> Result<(u32, u32, String)> {
        if self.is_sudo() {
            return Ok((0, 0, "/root".to_string()));
        }
        match self {
            Executor::Local(l) => {
                let uid = unsafe { libc::getuid() };
                let gid = unsafe { libc::getgid() };
                // Resolve HOME from the account database using argv-only
                // operations; never trust the ambient controller environment.
                let home = resolve_local_home(uid)?;
                l.home = home.clone();
                Ok((uid, gid, home))
            }
            Executor::Fake(f) => Ok((f.target.uid, f.target.gid, f.target.home.clone())),
            Executor::Ssh(s) => {
                let uid = run_simple(s, "/usr/bin/id", &["-u"])?
                    .trim()
                    .parse::<u32>()
                    .map_err(|_| SinterError::connect("could not determine target uid"))?;
                let gid = run_simple(s, "/usr/bin/id", &["-g"])?
                    .trim()
                    .parse::<u32>()
                    .map_err(|_| SinterError::connect("could not determine target gid"))?;
                Ok((uid, gid, s.home.clone()))
            }
        }
    }
}

/// Resolve a local uid's home directory from the account database without
/// consulting `$HOME`. Uses `getent passwd <uid>`.
pub fn resolve_local_home(uid: u32) -> Result<String> {
    let out = std::process::Command::new("/usr/bin/getent")
        .args(["passwd", &uid.to_string()])
        .env_clear()
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .output()
        .map_err(|e| SinterError::connect(format!("cannot query account database: {}", e)))?;
    if !out.status.success() {
        return Err(SinterError::connect(format!(
            "could not resolve account record for uid {}",
            uid
        )));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let fields: Vec<&str> = text.trim().split(':').collect();
    if fields.len() >= 6 && !fields[5].is_empty() {
        Ok(fields[5].to_string())
    } else {
        Err(SinterError::connect(format!(
            "could not resolve home directory for uid {}",
            uid
        )))
    }
}

fn run_simple(s: &mut SshExecutor, program: &str, args: &[&str]) -> Result<String> {
    let mut req = ExecRequest::new(program);
    req.args = args.iter().map(|s| s.to_string()).collect();
    let out = s.run(&req)?;
    match out.completion {
        Completion::Exited(0) => Ok(String::from_utf8_lossy(&out.stdout).to_string()),
        _ => Err(SinterError::connect(format!(
            "target command {} did not complete successfully",
            program
        ))),
    }
}

// ---------------------------------------------------------------------------
// Local execution
// ---------------------------------------------------------------------------

pub struct LocalExecutor {
    pub sudo: bool,
    pub home: String,
    pub log: Vec<CommandRecord>,
    stats: ExecStatsHandle,
}

impl LocalExecutor {
    pub fn new(sudo: bool) -> Result<Self> {
        // Resolve the default working directory before capability probes run.
        // The controller environment is never used for target execution.
        let home = if sudo {
            "/root".to_string()
        } else {
            resolve_local_home(unsafe { libc::getuid() })?
        };
        Ok(LocalExecutor {
            sudo,
            home,
            log: Vec::new(),
            stats: ExecStatsHandle::default(),
        })
    }

    fn run(&mut self, req: &ExecRequest) -> Result<Output> {
        let started = Instant::now();
        let result = self.exec_local(req);
        self.stats
            .note(req, self.sudo, started.elapsed(), result.as_ref().ok());
        result
    }

    fn exec_local(&mut self, req: &ExecRequest) -> Result<Output> {
        let deadline = Instant::now() + Duration::from_secs(req.timeout_secs.max(1));
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};
        let (program, args) = self.wrap(req);
        let mut cmd = Command::new(&program);
        cmd.args(&args);
        cmd.env_clear();
        for (k, v) in &req.env {
            cmd.env(k, v);
        }
        let cwd = req.cwd.clone().unwrap_or_else(|| {
            if self.sudo {
                "/root".to_string()
            } else {
                self.home.clone()
            }
        });
        // The controller process must not be forced into a target-only cwd
        // (e.g. /root) that it cannot access; the target-side `env -i -C`
        // establishes the child working directory. When a recipe supplies an
        // explicit cwd the controller runs from a root directory it can access.
        if self.sudo {
            cmd.current_dir("/");
        } else {
            // An explicit cwd is part of the command contract. Do not silently
            // replace an unusable requested directory with a fallback.
            cmd.current_dir(&cwd);
        }
        cmd.stdin(if req.stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        // Put the child in its own process group so a timeout can terminate the
        // entire descendant tree, not only the direct child.
        cmd.process_group(0);

        let mut child = cmd
            .spawn()
            .map_err(|e| SinterError::apply(format!("failed to start {}: {}", req.program, e)))?;
        let pgid = child.id() as i32;

        if let Some(input) = &req.stdin {
            if let Some(mut si) = child.stdin.take() {
                let data = zeroize::Zeroizing::new(input.clone());
                std::thread::spawn(move || {
                    let _ = si.write_all(&data);
                });
            }
        }

        let stdout_pipe = child.stdout.take();
        let stderr_pipe = child.stderr.take();
        let cap = MAX_CAPTURE;
        let out_handle = std::thread::spawn(move || read_capped(stdout_pipe, cap));
        let err_handle = std::thread::spawn(move || read_capped(stderr_pipe, cap));

        // One bounded deadline covers spawn, execution, pipe drain, and wait.
        let mut timed_out = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break Some(s),
                Ok(None) => {
                    if Instant::now() >= deadline {
                        // Kill the whole process group; a direct-child kill may
                        // leave grandchildren holding the pipes open.
                        unsafe {
                            libc::kill(-pgid, libc::SIGKILL);
                        }
                        let _ = child.kill();
                        let _ = child.wait();
                        timed_out = true;
                        break None;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => {
                    return Err(SinterError::apply(format!(
                        "failed to wait for child: {}",
                        e
                    )))
                }
            }
        };

        // Join the reader threads with a bounded grace period. If a descendant
        // escaped the process group and still holds a pipe, we must not block
        // past the deadline: detach the reader and report indeterminate.
        let mut join_budget = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::from_millis(200))
            .min(Duration::from_secs(2));
        if join_budget.is_zero() {
            join_budget = Duration::from_millis(200);
        }
        let (stdout, out_trunc) = join_with_budget(out_handle, join_budget);
        let (stderr, err_trunc) = join_with_budget(err_handle, join_budget);

        let completion = match status {
            Some(s) => classify_status(&s),
            None => {
                let _ = timed_out;
                Completion::Indeterminate {
                    started: true,
                    reason: format!("timeout of {}s elapsed after dispatch", req.timeout_secs),
                }
            }
        };

        Ok(Output {
            completion,
            stdout,
            stderr,
            stdout_truncated: out_trunc,
            stderr_truncated: err_trunc,
        })
    }
}

/// Join a reader thread, but never block longer than `budget`. If the budget
/// elapses, the thread is detached and we return what was collected so far.
fn join_with_budget(
    handle: std::thread::JoinHandle<(Vec<u8>, bool)>,
    budget: Duration,
) -> (Vec<u8>, bool) {
    use std::sync::mpsc;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let result = handle.join().unwrap_or_default();
        let _ = tx.send(result);
    });
    match rx.recv_timeout(budget) {
        Ok(v) => v,
        Err(_) => (Vec::new(), true),
    }
}

fn classify_status(status: &std::process::ExitStatus) -> Completion {
    use std::os::unix::process::ExitStatusExt;
    if let Some(code) = status.code() {
        Completion::Exited(code)
    } else if let Some(sig) = status.signal() {
        Completion::Signaled(sig)
    } else {
        Completion::Indeterminate {
            started: true,
            reason: "child exited without a status code".to_string(),
        }
    }
}

impl LocalExecutor {
    /// Build the argv actually invoked. When sudo is enabled the program is run
    /// through non-interactive sudo and a clean `env -i` baseline so the
    /// effective UID is 0 and the environment contract is identical to SSH.
    fn wrap(&self, req: &ExecRequest) -> (String, Vec<String>) {
        if self.sudo {
            let cwd = req.cwd.clone().unwrap_or_else(|| "/root".to_string());
            let mut args = vec!["-n".to_string(), "--".to_string()];
            args.push("/usr/bin/env".to_string());
            args.push("-i".to_string());
            args.push("-C".to_string());
            args.push(cwd);
            for (k, v) in &req.env {
                args.push(format!("{}={}", k, v));
            }
            args.push(req.program.clone());
            args.extend(req.args.clone());
            ("/usr/bin/sudo".to_string(), args)
        } else {
            (req.program.clone(), req.args.clone())
        }
    }
}

fn read_capped<R: Read + Send + 'static>(pipe: Option<R>, cap: usize) -> (Vec<u8>, bool) {
    let mut buf = Vec::new();
    let mut truncated = false;
    if let Some(mut r) = pipe {
        let mut tmp = [0u8; 8192];
        loop {
            match r.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    if buf.len() >= cap {
                        truncated = true;
                        continue;
                    }
                    let room = cap - buf.len();
                    let take = n.min(room);
                    buf.extend_from_slice(&tmp[..take]);
                    if take < n {
                        truncated = true;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    // A read error is not a clean EOF: the capture is incomplete
                    // and must fail closed rather than be treated as complete.
                    truncated = true;
                    break;
                }
            }
        }
    }
    (buf, truncated)
}

// ---------------------------------------------------------------------------
// SSH execution
// ---------------------------------------------------------------------------

/// Finite setup budget covering TCP connect, handshake, auth, and HOME
/// resolution. DESIGN §22 requires every remote operation to be bounded; setup
/// is a separate finite budget from the per-command operation deadline.
const SSH_SETUP_BUDGET_SECS: u64 = 60;
/// Maximum captured bytes for HOME detection output.
const DETECT_HOME_MAX: usize = 4096;

pub struct SshExecutor {
    pub sudo: bool,
    session: ssh2::Session,
    pub home: String,
    pub log: Vec<CommandRecord>,
    stats: ExecStatsHandle,
}

impl SshExecutor {
    pub fn connect(cfg: &SshConfig, sudo: bool) -> Result<Self> {
        let setup_deadline = Instant::now() + Duration::from_secs(SSH_SETUP_BUDGET_SECS);
        let tcp = connect_tcp_bounded(&cfg.host, cfg.port, setup_deadline)?;
        let remaining = setup_remaining(setup_deadline)?;
        let sock_timeout = Some(remaining.min(Duration::from_secs(30)));
        tcp.set_read_timeout(sock_timeout).map_err(|e| {
            SinterError::connect(format!("cannot set SSH socket read timeout: {}", e))
        })?;
        tcp.set_write_timeout(sock_timeout).map_err(|e| {
            SinterError::connect(format!("cannot set SSH socket write timeout: {}", e))
        })?;
        let mut session = ssh2::Session::new()
            .map_err(|e| SinterError::connect(format!("cannot create SSH session: {}", e)))?;
        session.set_tcp_stream(tcp);
        // Restrict every negotiated algorithm category to Sinter's SSH
        // policy before the handshake. Fails closed: if the policy cannot
        // be installed, no connection is attempted.
        apply_ssh_algorithm_policy(&session, cfg)?;
        // Configure the libssh2 timeout before any blocking handshake call so
        // the handshake itself cannot hang past the setup budget.
        let handshake_timeout = setup_remaining(setup_deadline)?;
        session.set_timeout(handshake_timeout.as_millis().clamp(1, u32::MAX as u128) as u32);
        session.handshake().map_err(|e| {
            SinterError::connect(format!(
                "SSH handshake with {}:{} failed: {}",
                cfg.host, cfg.port, e
            ))
        })?;

        // Host-key identity is the requested host string (or the OpenSSH
        // HostKeyAlias), never a resolved IP (SSH known_hosts semantics).
        verify_host_key(&session, cfg)?;

        let auth_timeout = setup_remaining(setup_deadline)?;
        session.set_timeout(auth_timeout.as_millis().clamp(1, u32::MAX as u128) as u32);
        let identities = identity_candidates(cfg);
        let mut attempts = AuthAttempts::default();
        let mut authed = try_agent_auth(&session, cfg, &identities, &mut attempts);
        if !authed {
            for id in &identities {
                let auth_timeout = setup_remaining(setup_deadline)?;
                session.set_timeout(auth_timeout.as_millis().clamp(1, u32::MAX as u128) as u32);
                if !id.exists() {
                    continue;
                }
                attempts.files.push(id.display().to_string());
                // No passphrase is ever supplied: Sinter is non-interactive.
                // An encrypted key is usable only through ssh-agent.
                if session
                    .userauth_pubkey_file(&cfg.user, None, id, None)
                    .is_ok()
                    && session.authenticated()
                {
                    authed = true;
                    break;
                }
            }
        }
        if !authed {
            return Err(SinterError::connect(format!(
                "SSH authentication failed for {}@{} ({})",
                cfg.user,
                cfg.host,
                attempts.describe()
            )));
        }

        let stats = ExecStatsHandle::default();
        let home = if sudo {
            "/root".to_string()
        } else {
            let started = Instant::now();
            let looked_up = detect_home(&session, &cfg.user, setup_deadline);
            stats.note_connect("getent", started.elapsed(), looked_up.is_ok());
            looked_up?
        };

        Ok(SshExecutor {
            sudo,
            session,
            home,
            log: Vec::new(),
            stats,
        })
    }

    fn run(&mut self, req: &ExecRequest) -> Result<Output> {
        let started = Instant::now();
        let result = self.exec_ssh(req);
        self.stats
            .note(req, self.sudo, started.elapsed(), result.as_ref().ok());
        result
    }

    fn exec_ssh(&mut self, req: &ExecRequest) -> Result<Output> {
        let deadline = Instant::now() + Duration::from_secs(req.timeout_secs.max(1));
        let line = build_remote_command(req, self.sudo, &self.home);
        self.session.set_blocking(false);
        let mut channel = match channel_session_until(&mut self.session, deadline) {
            Ok(ch) => ch,
            Err(e) => {
                // Channel open failed before exec dispatch. The remote command
                // was never started: this is a definite non-mutation, not
                // indeterminate completion.
                self.session.set_blocking(true);
                return Err(e);
            }
        };
        channel
            .handle_extended_data(ssh2::ExtendedData::Normal)
            .ok();
        if let Err(e) = exec_until(&mut channel, &line, deadline) {
            // Bound teardown by the residual deadline before any close/Drop
            // that could re-enter a blocking wait with a stale timeout.
            let residual = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or(Duration::from_millis(100))
                .min(Duration::from_millis(500));
            self.session
                .set_timeout(residual.as_millis().clamp(1, u32::MAX as u128) as u32);
            let _ = channel.close();
            drop(channel);
            return Err(e);
        }

        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut out_trunc = false;
        let mut err_trunc = false;
        let mut stdout_eof = false;
        let mut stderr_eof = false;
        // Incremental stdin state for full-duplex progress. Writing all stdin
        // before draining can deadlock once the SSH channel window fills
        // (e.g. large payload to /bin/cat).
        let stdin_data = req
            .stdin
            .as_ref()
            .map(|b| zeroize::Zeroizing::new(b.clone()));
        let mut stdin_off = 0usize;
        let mut stdin_eof_sent = false;

        let result: Result<()> = (|| {
            while !(stdout_eof && stderr_eof) {
                if Instant::now() >= deadline {
                    return Err(SinterError::indeterminate(format!(
                        "remote command timed out after {}s after dispatch",
                        req.timeout_secs
                    )));
                }
                let mut progressed = false;

                // Drain stdout/stderr while writing so backpressure cannot stall
                // a full-duplex command.
                if !stdout_eof {
                    match drain_stream(
                        &mut channel,
                        &mut out,
                        &mut out_trunc,
                        MAX_CAPTURE,
                        deadline,
                    ) {
                        Ok(0) => {
                            stdout_eof = true;
                            progressed = true;
                        }
                        Ok(_) => progressed = true,
                        Err(StreamErr::WouldBlock) => {}
                        Err(StreamErr::Other(e)) => {
                            return Err(SinterError::indeterminate(format!(
                                "SSH stdout read failed after dispatch: {}",
                                e
                            )));
                        }
                    }
                }
                if !stderr_eof {
                    let mut st = channel.stderr();
                    match drain_stream(&mut st, &mut err, &mut err_trunc, MAX_CAPTURE, deadline) {
                        Ok(0) => {
                            stderr_eof = true;
                            progressed = true;
                        }
                        Ok(_) => progressed = true,
                        Err(StreamErr::WouldBlock) => {}
                        Err(StreamErr::Other(e)) => {
                            return Err(SinterError::indeterminate(format!(
                                "SSH stderr read failed after dispatch: {}",
                                e
                            )))
                        }
                    }
                }

                // Incremental stdin write / EOF under the same deadline.
                if !stdin_eof_sent {
                    match stdin_data.as_ref() {
                        Some(data) if stdin_off < data.len() => {
                            if Instant::now() >= deadline {
                                return Err(SinterError::indeterminate(format!(
                                    "SSH stdin write timed out after {}s",
                                    req.timeout_secs
                                )));
                            }
                            match channel.write(&data[stdin_off..]) {
                                Ok(0) => {
                                    return Err(SinterError::indeterminate(
                                        "SSH stdin write returned zero bytes after dispatch",
                                    ))
                                }
                                Ok(n) => {
                                    stdin_off += n;
                                    progressed = true;
                                    if stdin_off >= data.len() {
                                        flush_and_eof(&mut channel, deadline).map_err(|e| {
                                            SinterError::indeterminate(format!(
                                                "SSH stdin EOF failed after dispatch: {}",
                                                e
                                            ))
                                        })?;
                                        stdin_eof_sent = true;
                                    }
                                }
                                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                    // Channel window full: drain first, then retry.
                                }
                                Err(e) => {
                                    return Err(SinterError::indeterminate(format!(
                                        "SSH stdin write failed after dispatch: {}",
                                        e
                                    )))
                                }
                            }
                        }
                        _ => {
                            // No stdin payload (or already fully written path
                            // handled above): send EOF so commands like /bin/cat
                            // can terminate, matching local /dev/null semantics.
                            flush_and_eof(&mut channel, deadline).map_err(|e| {
                                SinterError::indeterminate(format!(
                                    "SSH stdin EOF failed after dispatch: {}",
                                    e
                                ))
                            })?;
                            stdin_eof_sent = true;
                            progressed = true;
                        }
                    }
                }

                if stdout_eof && stderr_eof {
                    break;
                }
                if Instant::now() >= deadline {
                    return Err(SinterError::indeterminate(format!(
                        "remote command timed out after {}s after dispatch",
                        req.timeout_secs
                    )));
                }
                if !progressed {
                    wait_readable_until(self.session.as_raw_fd(), deadline);
                }
            }
            Ok(())
        })();

        if let Err(e) = result {
            if e.kind == crate::error::ErrorKind::Indeterminate {
                let _ = channel.close();
                // Keep non-blocking so Channel Drop cannot re-enter an
                // unbounded blocking wait past the operation deadline.
                return Ok(Output {
                    completion: Completion::Indeterminate {
                        started: true,
                        reason: e.message,
                    },
                    stdout: out,
                    stderr: err,
                    stdout_truncated: out_trunc,
                    stderr_truncated: err_trunc,
                });
            }
            let _ = channel.close();
            self.session.set_blocking(true);
            return Err(e);
        }

        // Bound channel close and exit-status collection by the same deadline.
        self.session.set_blocking(false);
        let mut close_confirmed = false;
        while Instant::now() < deadline {
            match channel.wait_close() {
                Ok(()) => {
                    close_confirmed = true;
                    break;
                }
                Err(e) if e.code() == ssh2::ErrorCode::Session(-37) => {
                    wait_readable_until(self.session.as_raw_fd(), deadline);
                }
                Err(_) => break,
            }
        }
        let (completion, _close_note) = if !close_confirmed {
            (
                Completion::Indeterminate {
                    started: true,
                    reason: format!(
                        "SSH channel close was not confirmed within {}s after dispatch",
                        req.timeout_secs
                    ),
                },
                Some("close unconfirmed".to_string()),
            )
        } else {
            let c = remote_completion_until(&mut channel, self.session.as_raw_fd(), deadline);
            (c, None)
        };
        // Restore a short residual timeout for Drop/teardown rather than an
        // unbounded blocking wait that could outlive the operation deadline.
        let residual = deadline
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::from_millis(100))
            .min(Duration::from_millis(500));
        self.session
            .set_timeout(residual.as_millis().clamp(1, u32::MAX as u128) as u32);
        self.session.set_blocking(true);
        drop(channel);

        Ok(Output {
            completion,
            stdout: out,
            stderr: err,
            stdout_truncated: out_trunc,
            stderr_truncated: err_trunc,
        })
    }
}

fn setup_remaining(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| SinterError::connect("SSH setup budget exceeded before operation completed"))
}

/// Connect to host:port with a finite remaining setup budget. Supports IPv4
/// literals, IPv6 literals, `localhost`, and DNS hostnames. Multiple resolved
/// addresses share ONE budget; the budget is not reset per address.
fn connect_tcp_bounded(
    host: &str,
    port: u16,
    setup_deadline: Instant,
) -> Result<std::net::TcpStream> {
    use std::net::ToSocketAddrs;
    let addr = format!("{}:{}", host, port);
    // Fast path: literal socket address (IPv4/IPv6).
    if let Ok(sock) = addr.parse::<std::net::SocketAddr>() {
        let remaining = setup_remaining(setup_deadline)?;
        return std::net::TcpStream::connect_timeout(&sock, remaining)
            .map_err(|e| SinterError::connect(format!("cannot connect to {}: {}", addr, e)));
    }
    // Hostname path: resolve then try each address under the same budget.
    let addrs: Vec<std::net::SocketAddr> = addr
        .to_socket_addrs()
        .map_err(|e| SinterError::connect(format!("cannot resolve SSH address {}: {}", addr, e)))?
        .collect();
    if addrs.is_empty() {
        return Err(SinterError::connect(format!(
            "SSH address {} resolved to no endpoints",
            addr
        )));
    }
    let mut last_err: Option<std::io::Error> = None;
    for sock in addrs {
        let remaining = setup_remaining(setup_deadline)?;
        match std::net::TcpStream::connect_timeout(&sock, remaining) {
            Ok(tcp) => return Ok(tcp),
            Err(e) => last_err = Some(e),
        }
    }
    Err(SinterError::connect(format!(
        "cannot connect to {}: {}",
        addr,
        last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "all resolved addresses failed".to_string())
    )))
}

fn remote_completion_until(
    channel: &mut ssh2::Channel,
    fd: std::os::raw::c_int,
    deadline: Instant,
) -> Completion {
    loop {
        if Instant::now() >= deadline {
            return Completion::Indeterminate {
                started: true,
                reason: "SSH exit-status collection deadline exceeded".to_string(),
            };
        }
        match channel.exit_signal() {
            Ok(sig) => {
                if let Some(signal) = sig.exit_signal.as_deref().and_then(parse_signal) {
                    return Completion::Signaled(signal);
                }
                return exit_status_until(channel, fd, deadline);
            }
            Err(e) if e.code() == ssh2::ErrorCode::Session(-37) => {
                wait_readable_until(fd, deadline);
            }
            Err(_) => return exit_status_until(channel, fd, deadline),
        }
    }
}

fn exit_status_until(
    channel: &mut ssh2::Channel,
    fd: std::os::raw::c_int,
    deadline: Instant,
) -> Completion {
    loop {
        match channel.exit_status() {
            Ok(code) => return Completion::Exited(code),
            Err(e) if e.code() == ssh2::ErrorCode::Session(-37) => {
                if Instant::now() >= deadline {
                    return Completion::Indeterminate {
                        started: true,
                        reason: "SSH exit-status collection deadline exceeded".to_string(),
                    };
                }
                wait_readable_until(fd, deadline);
            }
            Err(e) => {
                return Completion::Indeterminate {
                    started: true,
                    reason: format!("remote exit status unavailable: {}", e),
                }
            }
        }
    }
}

fn detect_home(session: &ssh2::Session, user: &str, setup_deadline: Instant) -> Result<String> {
    // Resolve via the account database without relying on inherited HOME.
    // Bounded by the remaining setup budget and a finite capture size.
    let remaining = setup_remaining(setup_deadline)?;
    session.set_timeout(remaining.as_millis().clamp(1, u32::MAX as u128) as u32);
    let mut ch = session
        .channel_session()
        .map_err(|e| SinterError::connect(format!("cannot open SSH channel: {}", e)))?;
    let cmd = format!("getent passwd {}", shell_quote(user));
    ch.exec(&cmd)
        .map_err(|e| SinterError::connect(format!("cannot query account database: {}", e)))?;
    let mut s = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        if Instant::now() >= setup_deadline {
            let _ = ch.close();
            return Err(SinterError::connect(
                "SSH setup budget exceeded while resolving HOME",
            ));
        }
        match ch.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                if s.len() + n > DETECT_HOME_MAX {
                    let _ = ch.close();
                    return Err(SinterError::connect(
                        "HOME detection output exceeded the capture bound",
                    ));
                }
                s.extend_from_slice(&tmp[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                let remaining = setup_remaining(setup_deadline)?;
                wait_readable_until(session.as_raw_fd(), setup_deadline);
                let _ = remaining;
            }
            Err(e) => {
                let _ = ch.close();
                return Err(SinterError::connect(format!(
                    "HOME detection read failed: {}",
                    e
                )));
            }
        }
    }
    ch.wait_close()
        .map_err(|e| SinterError::connect(format!("HOME detection channel close failed: {}", e)))?;
    let code = ch.exit_status().map_err(|e| {
        SinterError::connect(format!("HOME detection exit status unavailable: {}", e))
    })?;
    if code != 0 {
        return Err(SinterError::connect(format!(
            "could not resolve home directory for target user {} (exit {})",
            user, code
        )));
    }
    let text = String::from_utf8(s)
        .map_err(|_| SinterError::connect("HOME detection output was not valid UTF-8"))?;
    let fields: Vec<&str> = text.trim().split(':').collect();
    if fields.len() >= 6 && !fields[5].is_empty() {
        Ok(fields[5].to_string())
    } else {
        Err(SinterError::connect(format!(
            "could not resolve home directory for target user {}",
            user
        )))
    }
}

enum StreamErr {
    WouldBlock,
    Other(String),
}

fn drain_stream<R: Read>(
    r: &mut R,
    sink: &mut Vec<u8>,
    truncated: &mut bool,
    cap: usize,
    deadline: Instant,
) -> std::result::Result<usize, StreamErr> {
    let mut total = 0;
    let mut tmp = [0u8; 8192];
    loop {
        // A successful-progress read loop must still honor the operation
        // deadline; continuous output must not extend the bound.
        if Instant::now() >= deadline {
            return Err(StreamErr::Other("SSH operation deadline exceeded".into()));
        }
        match r.read(&mut tmp) {
            Ok(0) => return Ok(total),
            Ok(n) => {
                total += n;
                if sink.len() >= cap {
                    *truncated = true;
                } else {
                    let room = cap - sink.len();
                    let take = n.min(room);
                    sink.extend_from_slice(&tmp[..take]);
                    if take < n {
                        *truncated = true;
                    }
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    if total == 0 {
                        return Err(StreamErr::WouldBlock);
                    }
                    return Ok(total);
                }
                return Err(StreamErr::Other(e.to_string()));
            }
        }
    }
}

/// Flush pending stdin bytes and send EOF under the operation deadline.
/// EAGAIN retries; other failures are reported, never silently ignored.
fn flush_and_eof(channel: &mut ssh2::Channel, deadline: Instant) -> std::io::Result<()> {
    loop {
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "SSH stdin flush deadline exceeded",
            ));
        }
        match channel.flush() {
            Ok(()) => break,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(e),
        }
    }
    loop {
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "SSH stdin EOF deadline exceeded",
            ));
        }
        match channel.send_eof() {
            Ok(()) => return Ok(()),
            Err(e) if e.code() == ssh2::ErrorCode::Session(-37) => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                return Err(std::io::Error::other(format!(
                    "SSH stdin EOF failed: {}",
                    e
                )))
            }
        }
    }
}

fn wait_readable(fd: std::os::raw::c_int, timeout: Duration) {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ms = timeout.as_millis() as i32;
    unsafe {
        libc::poll(&mut pfd, 1, ms);
    }
}

fn wait_readable_until(fd: std::os::raw::c_int, deadline: Instant) {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .unwrap_or_default();
    if !remaining.is_zero() {
        wait_readable(fd, remaining.min(Duration::from_millis(200)));
    }
}

fn refresh_session_timeout(session: &ssh2::Session, deadline: Instant) -> Result<()> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| {
            // Callers distinguish pre-dispatch (apply/none) from post-dispatch
            // (indeterminate). Channel-open helpers use apply errors.
            SinterError::apply("SSH operation deadline exceeded before command dispatch")
        })?;
    let millis = remaining.as_millis().clamp(1, u32::MAX as u128) as u32;
    session.set_timeout(millis);
    Ok(())
}

fn channel_session_until(session: &mut ssh2::Session, deadline: Instant) -> Result<ssh2::Channel> {
    loop {
        if Instant::now() >= deadline {
            return Err(SinterError::apply(
                "SSH channel open timed out before command dispatch",
            ));
        }
        refresh_session_timeout(session, deadline)?;
        match session.channel_session() {
            Ok(channel) => return Ok(channel),
            Err(e) if e.code() == ssh2::ErrorCode::Session(-37) => {
                wait_readable_until(session.as_raw_fd(), deadline);
            }
            Err(e) => {
                return Err(SinterError::apply(format!(
                    "cannot open SSH channel: {}",
                    e
                )))
            }
        }
    }
}

fn exec_until(channel: &mut ssh2::Channel, command: &str, deadline: Instant) -> Result<()> {
    loop {
        if Instant::now() >= deadline {
            return Err(SinterError::indeterminate(
                "SSH command dispatch deadline exceeded after channel open",
            ));
        }
        match channel.exec(command) {
            Ok(()) => return Ok(()),
            Err(e) if e.code() == ssh2::ErrorCode::Session(-37) => {
                if deadline <= Instant::now() {
                    return Err(SinterError::indeterminate(
                        "SSH command dispatch deadline exceeded",
                    ));
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => {
                return Err(SinterError::indeterminate(format!(
                    "SSH command dispatch failed after connection: {}",
                    e
                )))
            }
        }
    }
}

fn parse_signal(name: &str) -> Option<i32> {
    let n = name.trim().to_ascii_uppercase();
    let n = n.strip_prefix("SIG").unwrap_or(&n);
    let table: &[(&str, i32)] = &[
        ("HUP", 1),
        ("INT", 2),
        ("QUIT", 3),
        ("ILL", 4),
        ("TRAP", 5),
        ("ABRT", 6),
        ("BUS", 7),
        ("FPE", 8),
        ("KILL", 9),
        ("USR1", 10),
        ("SEGV", 11),
        ("USR2", 12),
        ("PIPE", 13),
        ("ALRM", 14),
        ("TERM", 15),
        ("STKFLT", 16),
        ("CHLD", 17),
        ("CONT", 18),
        ("STOP", 19),
        ("TSTP", 20),
        ("TTIN", 21),
        ("TTOU", 22),
        ("URG", 23),
        ("XCPU", 24),
        ("XFSZ", 25),
        ("VTALRM", 26),
        ("PROF", 27),
        ("WINCH", 28),
        ("IO", 29),
        ("PWR", 30),
        ("SYS", 31),
    ];
    table.iter().find(|(k, _)| *k == n).map(|(_, v)| *v)
}

/// Load the selected known_hosts file into a libssh2 collection.
fn load_known_hosts(session: &ssh2::Session, cfg: &SshConfig) -> Result<ssh2::KnownHosts> {
    let mut known = session
        .known_hosts()
        .map_err(|e| SinterError::connect(format!("cannot read known hosts: {}", e)))?;
    known
        .read_file(&cfg.known_hosts, ssh2::KnownHostFileKind::OpenSSH)
        .map_err(|e| {
            SinterError::connect(format!(
                "cannot read known_hosts file {}: {}",
                cfg.known_hosts.display(),
                e
            ))
        })?;
    Ok(known)
}

/// The exact known_hosts identity for a connection (DESIGN §19): default
/// port uses `host`; a non-default port uses `[host]:port` only. `host` is the
/// OpenSSH `HostKeyAlias` when one is configured.
pub fn known_hosts_identity(host: &str, port: u16, alias: Option<&str>) -> String {
    let name = alias.unwrap_or(host);
    if port == 22 {
        name.to_string()
    } else {
        format!("[{}]:{}", name, port)
    }
}

fn cfg_identity(cfg: &SshConfig) -> String {
    known_hosts_identity(&cfg.host, cfg.port, cfg.host_key_alias.as_deref())
}

/// SSH wire key type (`ssh-ed25519`, `ecdsa-sha2-nistp256`, `ssh-rsa`, ...)
/// from a public key blob.
pub fn ssh_key_type(blob: &[u8]) -> Option<&str> {
    let len = u32::from_be_bytes(blob.get(0..4)?.try_into().ok()?) as usize;
    std::str::from_utf8(blob.get(4..4 + len)?).ok()
}

/// Host-key algorithm names that can present a key of `key_type`.
fn hostkey_algorithms_for(key_type: &str) -> Vec<&str> {
    match key_type {
        "ssh-rsa" => vec!["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"],
        other => vec![other],
    }
}

/// Order the allowed host-key algorithms so those for already-known key
/// types come first (OpenSSH behavior), keeping the policy order within
/// each group. Without this, libssh2 negotiates ECDSA first and a host
/// enrolled only with its Ed25519 or RSA key is reported as a key mismatch.
/// Ordering never widens trust: the presented key must still match
/// known_hosts exactly, and nothing outside `allowed` is ever offered.
pub fn hostkey_preference(known_types: &[String], allowed: &[&str]) -> String {
    let mut first: Vec<&str> = Vec::new();
    for t in known_types {
        for alg in hostkey_algorithms_for(t) {
            if allowed.contains(&alg) && !first.contains(&alg) {
                first.push(alg);
            }
        }
    }
    let rest = allowed.iter().copied().filter(|a| !first.contains(a));
    first
        .iter()
        .copied()
        .chain(rest)
        .collect::<Vec<_>>()
        .join(",")
}

// SSH algorithm policy. This is security policy, not tuning.
//
// Each negotiated category gets a positive allowlist, so the legacy
// algorithms that the bundled libssh2 still offers by default (1024-bit
// and SHA-1 key exchange, SHA-1 `ssh-rsa` host-key signatures, CBC, RC4,
// Blowfish, CAST and 3DES ciphers, MD5, SHA-1 and RIPEMD-160 MACs) can
// never be negotiated. There is deliberately no option to re-enable them.
//
// Every name must be supported by the linked libssh2 (a unit test checks
// this): libssh2 silently drops names it does not know. The supported
// targets run OpenSSH 8.7 or later, whose default configurations offer
// algorithms from every list. Changing a list needs a security and
// interoperability review.
//
// libssh2 adds its own KEX extensions (`ext-info-c` and the Terrapin
// countermeasure `kex-strict-c-v00@openssh.com`) to any KEX preference, so
// they are not listed here. Compression is not configured: the build
// supports only `none`.

/// Key exchange. Group exchange requests at least 2048-bit groups.
pub const SSH_KEX_ALGORITHMS: &[&str] = &[
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group14-sha256",
];

/// Host-key signature algorithms. RSA host keys use rsa-sha2-*, never the
/// SHA-1 `ssh-rsa` signature. Certificate types are omitted: known_hosts
/// verification cannot validate host certificates.
pub const SSH_HOSTKEY_ALGORITHMS: &[&str] = &[
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-ed25519",
    "rsa-sha2-512",
    "rsa-sha2-256",
];

/// Ciphers (both directions): AEAD first, then CTR. No CBC or stream ciphers.
pub const SSH_CIPHERS: &[&str] = &[
    "chacha20-poly1305@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
    "aes256-ctr",
    "aes192-ctr",
    "aes128-ctr",
];

/// MACs (both directions), used with the CTR ciphers: encrypt-then-MAC
/// first, SHA-2 only.
pub const SSH_MACS: &[&str] = &[
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
];

/// Install one category's preference list. Any failure is an error; the
/// session must then not be used.
fn set_algorithm_pref(
    session: &ssh2::Session,
    method: ssh2::MethodType,
    category: &str,
    prefs: &str,
) -> Result<()> {
    session.method_pref(method, prefs).map_err(|e| {
        SinterError::connect(format!(
            "cannot apply the SSH {} algorithm policy: {}",
            category, e
        ))
    })
}

/// Restrict key exchange, host key, cipher and MAC negotiation to the
/// allowlists above, with host-key types already in known_hosts first.
fn apply_ssh_algorithm_policy(session: &ssh2::Session, cfg: &SshConfig) -> Result<()> {
    let known = load_known_hosts(session, cfg)?;
    let types = known_key_types(&known, &cfg_identity(cfg))?;
    let hostkeys = hostkey_preference(&types, SSH_HOSTKEY_ALGORITHMS);
    set_algorithm_pref(session, ssh2::MethodType::HostKey, "host key", &hostkeys)?;
    apply_fixed_algorithm_policy(session)
}

/// The categories whose lists do not depend on known_hosts.
fn apply_fixed_algorithm_policy(session: &ssh2::Session) -> Result<()> {
    let ciphers = SSH_CIPHERS.join(",");
    let macs = SSH_MACS.join(",");
    set_algorithm_pref(
        session,
        ssh2::MethodType::Kex,
        "key exchange",
        &SSH_KEX_ALGORITHMS.join(","),
    )?;
    set_algorithm_pref(session, ssh2::MethodType::CryptCs, "cipher", &ciphers)?;
    set_algorithm_pref(session, ssh2::MethodType::CryptSc, "cipher", &ciphers)?;
    set_algorithm_pref(session, ssh2::MethodType::MacCs, "MAC", &macs)?;
    set_algorithm_pref(session, ssh2::MethodType::MacSc, "MAC", &macs)
}

/// Key types recorded in known_hosts for the connection identity, including
/// hashed (`|1|...`) entries: each distinct stored key is tested against the
/// exact identity through libssh2's own matcher.
fn known_key_types(known: &ssh2::KnownHosts, identity: &str) -> Result<Vec<String>> {
    let entries = known
        .iter()
        .map_err(|e| SinterError::connect(format!("cannot enumerate known hosts: {}", e)))?;
    let mut seen_keys: Vec<String> = Vec::new();
    let mut types: Vec<String> = Vec::new();
    for h in &entries {
        let k = h.key().to_string();
        if seen_keys.contains(&k) {
            continue;
        }
        seen_keys.push(k.clone());
        let Some(blob) = crate::targetfs::b64_decode(&k) else {
            continue;
        };
        let Some(t) = ssh_key_type(&blob) else {
            continue;
        };
        if types.iter().any(|x| x == t) {
            continue;
        }
        if matches!(known.check(identity, &blob), ssh2::CheckResult::Match) {
            types.push(t.to_string());
        }
    }
    Ok(types)
}

/// Base64 keys listed on `@revoked` marker lines. libssh2 has no marker
/// support, so revocation is enforced here: a presented key that appears on
/// any `@revoked` line is refused regardless of its host pattern (stricter
/// than, never weaker than, OpenSSH).
pub fn revoked_keys(known_hosts_text: &str) -> Vec<String> {
    known_hosts_text
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            if f.next()? != "@revoked" {
                return None;
            }
            let _hosts = f.next()?;
            let _type = f.next()?;
            Some(f.next()?.to_string())
        })
        .collect()
}

fn verify_host_key(session: &ssh2::Session, cfg: &SshConfig) -> Result<()> {
    let known = load_known_hosts(session, cfg)?;
    let (key, _key_type) = session
        .host_key()
        .ok_or_else(|| SinterError::connect("server did not present a host key"))?;
    let identity = cfg_identity(cfg);
    let presented = crate::targetfs::b64_encode(key);

    let raw = std::fs::read(&cfg.known_hosts).map_err(|e| {
        SinterError::connect(format!(
            "cannot read known_hosts file {}: {}",
            cfg.known_hosts.display(),
            e
        ))
    })?;
    let text = String::from_utf8_lossy(&raw);
    if revoked_keys(&text).contains(&presented) {
        return Err(SinterError::connect(format!(
            "SSH host key for {} is marked @revoked in {}",
            identity,
            cfg.known_hosts.display()
        )));
    }

    // Exact-identity lookup (libssh2 `check` without a port performs no
    // portless fallback), covering plain and hashed entries alike. A
    // portless `host` entry therefore never authorizes a non-default port,
    // and an explicit matching-identity mismatch is never bypassed by
    // another host form (DESIGN §19).
    match known.check(&identity, key) {
        ssh2::CheckResult::Match => Ok(()),
        ssh2::CheckResult::Mismatch => {
            let presented_type = ssh_key_type(key).unwrap_or("unknown");
            let known_types = known_key_types(&known, &identity).unwrap_or_default();
            let detail = if known_types.iter().any(|t| t == presented_type) {
                String::new()
            } else {
                format!(
                    "; the server presented a {} key and known_hosts only records {} for this host",
                    presented_type,
                    known_types.join(", ")
                )
            };
            Err(SinterError::connect(format!(
                "SSH host key mismatch for {} (possible man-in-the-middle){}",
                identity, detail
            )))
        }
        ssh2::CheckResult::NotFound => Err(SinterError::connect(format!(
            "SSH host key for {} is not present in {}; enrollment is not automatic",
            identity,
            cfg.known_hosts.display()
        ))),
        ssh2::CheckResult::Failure => Err(SinterError::connect(format!(
            "cannot check SSH host key for {} against {}",
            identity,
            cfg.known_hosts.display()
        ))),
    }
}

/// Private key files to try: the configured list, or the built-in defaults.
fn identity_candidates(cfg: &SshConfig) -> Vec<PathBuf> {
    if !cfg.identity_files.is_empty() {
        return cfg.identity_files.clone();
    }
    match std::env::var_os("HOME") {
        Some(home) => {
            let h = PathBuf::from(home);
            DEFAULT_IDENTITY_FILES
                .iter()
                .map(|n| h.join(".ssh").join(n))
                .collect()
        }
        None => Vec::new(),
    }
}

/// Built-in default key files when neither the CLI, a targets file, nor the
/// OpenSSH client configuration names any.
pub const DEFAULT_IDENTITY_FILES: &[&str] = &["id_ed25519", "id_ecdsa", "id_rsa"];

/// What authentication tried, for a truthful failure message. Never holds
/// key material or the agent socket path.
#[derive(Default)]
struct AuthAttempts {
    agent: Option<String>,
    files: Vec<String>,
}

impl AuthAttempts {
    fn describe(&self) -> String {
        let agent = self
            .agent
            .clone()
            .unwrap_or_else(|| "agent: not used".to_string());
        let files = if self.files.is_empty() {
            "no key file found".to_string()
        } else {
            format!("key files tried: {}", self.files.join(", "))
        };
        format!(
            "{}; {}; encrypted private keys are usable only through ssh-agent (ssh-add)",
            agent, files
        )
    }
}

/// Public key blob of `<identity>.pub`, when present and well-formed.
fn identity_public_blob(identity: &Path) -> Option<Vec<u8>> {
    let mut p = identity.as_os_str().to_owned();
    p.push(".pub");
    let text = std::fs::read_to_string(PathBuf::from(p)).ok()?;
    let b64 = text.split_whitespace().nth(1)?;
    crate::targetfs::b64_decode(b64)
}

/// ssh-agent authentication. Agent keys matching a configured identity file
/// are offered first (OpenSSH order); with `identities_only`, only those.
fn try_agent_auth(
    session: &ssh2::Session,
    cfg: &SshConfig,
    identities: &[PathBuf],
    attempts: &mut AuthAttempts,
) -> bool {
    use crate::engine::AgentSource;
    if cfg.agent == AgentSource::Disabled {
        attempts.agent = Some("agent: disabled by IdentityAgent none".to_string());
        return false;
    }
    let Ok(mut agent) = session.agent() else {
        attempts.agent = Some("agent: unavailable".to_string());
        return false;
    };
    if let AgentSource::Socket(p) = &cfg.agent {
        if agent.set_identity_path(p).is_err() {
            attempts.agent = Some("agent: unavailable".to_string());
            return false;
        }
    }
    if agent.connect().is_err() {
        attempts.agent = Some("agent: unavailable".to_string());
        return false;
    }
    let keys = match agent.list_identities().and_then(|_| agent.identities()) {
        Ok(k) => k,
        Err(_) => {
            let _ = agent.disconnect();
            attempts.agent = Some("agent: unavailable".to_string());
            return false;
        }
    };
    let wanted: Vec<Vec<u8>> = identities
        .iter()
        .filter_map(|p| identity_public_blob(p))
        .collect();
    let (preferred, others): (Vec<_>, Vec<_>) = keys
        .into_iter()
        .partition(|k| wanted.iter().any(|w| w.as_slice() == k.blob()));
    let order: Vec<_> = if cfg.identities_only {
        preferred
    } else {
        preferred.into_iter().chain(others).collect()
    };
    let mut offered = 0usize;
    let mut authed = false;
    for key in &order {
        offered += 1;
        if agent.userauth(&cfg.user, key).is_ok() && session.authenticated() {
            authed = true;
            break;
        }
    }
    let _ = agent.disconnect();
    attempts.agent = Some(format!(
        "agent: {} key(s) offered{}",
        offered,
        if cfg.identities_only {
            " (IdentitiesOnly)"
        } else {
            ""
        }
    ));
    authed
}

pub fn build_remote_command(req: &ExecRequest, sudo: bool, home: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    let cwd = req.cwd.clone().unwrap_or_else(|| {
        if sudo {
            "/root".to_string()
        } else {
            home.to_string()
        }
    });
    parts.push(shell_quote("/usr/bin/env"));
    parts.push("-i".to_string());
    parts.push("-C".to_string());
    parts.push(shell_quote(&cwd));
    for (k, v) in &req.env {
        parts.push(shell_quote(&format!("{}={}", k, v)));
    }
    parts.push(shell_quote(&req.program));
    for a in &req.args {
        parts.push(shell_quote(a));
    }
    let env_cmd = parts.join(" ");
    if sudo {
        format!("/usr/bin/sudo -n -- {}", env_cmd)
    } else {
        env_cmd
    }
}

/// POSIX single-quote escaping: exact argv preservation, no shell evaluation.
pub fn shell_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    let mut out = String::from("'");
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

// ---------------------------------------------------------------------------
// Scripted fake target (test support only)
// ---------------------------------------------------------------------------

/// A scripted in-process target used by tests. Selected through
/// `RunOptions::fake_target`; the CLI never constructs it.
///
/// The fake sits below the real execution boundary: platform detection,
/// backend selection, resource logic, result classification, sensitivity
/// redaction, and command recording all run production code. It answers only
/// the fixed command vocabulary the engine needs; filesystem helpers are not
/// modeled and fail honestly rather than fabricating state.
#[derive(Debug, Clone)]
pub struct FakeTarget {
    /// Content served for `/bin/cat /etc/os-release`.
    pub os_release: String,
    pub hostname: String,
    pub arch: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    /// Executables reported present by `test -x` capability probes.
    pub executables: std::collections::BTreeSet<String>,
    /// Installed package set as reported by `rpm -q`/`dpkg-query`; mutated
    /// by `dnf`/`apt-get` install/remove operations.
    pub packages: std::collections::BTreeSet<String>,
    /// unit name -> (LoadState, ActiveState, UnitFileState)
    pub services: BTreeMap<String, (String, String, String)>,
    /// Forced dnf/apt-get mutation completion, overriding the state
    /// transition. Does not apply to the dnf metadata-cache probe.
    pub manager_completion: Option<Completion>,
    /// Forced completion for the `dnf -C repoquery` metadata-snapshot
    /// usability check; `None` derives the outcome from `dnf_repos`
    /// (DESIGN §27 fail-closed path tests).
    pub probe_completion: Option<Completion>,
    /// Overrides the complete output of the `dnf -C repoquery`
    /// metadata-snapshot usability check, so tests can model benign or
    /// unexpected stderr content on a successful check (R5-F04). Wins over
    /// `probe_completion`.
    pub dnf_probe_output: Option<Output>,
    /// Forced package-query completion.
    pub query_completion: Option<Completion>,
    /// Ordered complete package-query results (stdout, stderr, truncation
    /// flags included). Each query pops the front entry; when the queue is
    /// empty the configured `query_completion` or the package state applies.
    pub query_results: std::collections::VecDeque<Output>,
    /// Enabled dnf repositories as the fake models them — whether each
    /// repo's repodata and resolved mirror list are present in the local
    /// metadata cache snapshot.
    pub dnf_repos: Vec<DnfRepo>,
    /// Overrides the `dnf repolist -v` output, so tests can model truncated or
    /// malformed repository enumeration (R2-03).
    pub dnf_repolist_output: Option<Output>,
    /// Overrides the cache-only `dnf install --assumeno` transaction table,
    /// so tests can model truncated, malformed, or ambiguous transactions
    /// (R2-03/R2-04).
    pub dnf_dry_run_output: Option<Output>,
    /// Overrides the `dnf install --downloadonly` payload-transport answer
    /// as a whole, so tests can model a failed download — the payload set
    /// the run leaves behind is then whatever `snap_rpm_listing` reports.
    pub dnf_downloadonly_output: Option<Output>,
    /// Overrides the `find <snap> -name '*.rpm'` payload listing, so tests
    /// can model a missing, unexpected or misplaced payload file. When
    /// unset, the listing is the payloads the fake's download-only
    /// invocation placed in the snapshot.
    pub snap_rpm_listing: Option<String>,
    /// Ordered `rpm -qp` answers (payload identity queries). Each query
    /// pops the front entry; when the queue is empty the identity is
    /// derived from the queried file's own name.
    pub rpm_qp_results: std::collections::VecDeque<Output>,
    /// Overrides the `find <snap> -mindepth 1 -maxdepth 2` listing, so tests
    /// can model similar repository IDs or multiple cached hash directories
    /// (R2-04).
    pub snapshot_listing: Option<String>,
    /// Overrides the `find /var/cache/dnf -mindepth 1 -maxdepth 1 -print0`
    /// answer — the raw stdout bytes the live-cache enumeration yields, so
    /// tests can model NUL-framing defects, invalid UTF-8, duplicate entries
    /// and non-child paths through the production control path (R4-F01).
    pub live_cache_find_output: Option<Output>,
    /// Overrides the `mktemp -d` answer — the raw output the snapshot helper
    /// yields, so tests can model a path outside the private snapshot
    /// namespace, an extra line, or malformed output (R4-F01).
    pub mktemp_output: Option<Output>,
    /// Mode reported for the private dnf snapshot root by `stat -c %a`
    /// before the metadata cache is copied into it (snapshot-permission
    /// hardening).
    pub snapshot_mode: String,
    /// Mode reported for the snapshot root by `stat -c %a` AFTER the
    /// metadata cache copy, modeling a root that is not 0700 once content
    /// has been placed in it (snapshot-permission hardening). `None` keeps
    /// the copy honest: the copy brings each child of the live cache root
    /// into the existing directory and never makes the root itself a copy
    /// target, so the root's own mode survives the copy unchanged (R4-A04).
    pub snapshot_mode_after_copy: Option<String>,
    /// When true, the snapshot-root `chmod 700` fails (permission hardening
    /// fail-closed tests).
    pub snapshot_chmod_fails: bool,
    /// When true, the snapshot-root `stat -c %a %u` verification fails
    /// (permission hardening fail-closed tests).
    pub snapshot_stat_fails: bool,
    /// When true, the snapshot-root `rm -rf` fails (R2-05 cleanup-truth
    /// tests).
    pub snapshot_rm_fails: bool,
    /// Adversarial observation overrides, keyed by program basename
    /// (`stat`, `readlink`, `sha256sum`, ...). Each invocation pops the front
    /// queued result for that program, so a test can feed a truncated,
    /// malformed, or contradictory capture straight into the production
    /// observation contract (IA-01 false-PASS regression suite).
    pub observation_overrides:
        std::collections::BTreeMap<String, std::collections::VecDeque<Output>>,
    /// Scripted systemd manager state (disk / loaded / NeedDaemonReload /
    /// reload behavior). Inert unless a test drives it.
    pub manager: crate::fakesys::FakeManager,
    /// Scripted local account databases and the shadow-utils commands that
    /// change them (`user`/`group` resources).
    pub accounts: crate::fakesys::FakeAccounts,
    /// Opt-in scripted filesystem. `None` keeps the historical behavior:
    /// filesystem helpers are not modeled and fail honestly.
    pub fs: Option<crate::fakesys::FakeFs>,
}

/// One enabled dnf repository in the fake model.
#[derive(Debug, Clone)]
pub struct DnfRepo {
    pub id: String,
    /// The repo resolves via a mirror list (`Repo-mirrors` in repolist -v).
    pub mirrors: bool,
    /// repodata is present in the local metadata cache.
    pub repodata_cached: bool,
    /// The resolved mirror list is present in the local cache (when
    /// `mirrors` is set).
    pub mirrorlist_cached: bool,
}

impl FakeTarget {
    /// A Rocky Linux 9 x86_64 target: dnf backend, rpm query, systemd.
    pub fn rocky9() -> Self {
        FakeTarget {
            os_release: "NAME=\"Rocky Linux\"\nVERSION=\"9.4 (Blue Onyx)\"\nID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.4\"\nPLATFORM_ID=\"platform:el9\"\n".to_string(),
            hostname: "rocky9.test".to_string(),
            arch: "x86_64".to_string(),
            uid: 1000,
            gid: 1000,
            home: "/home/fake".to_string(),
            executables: [
                "/usr/bin/dnf",
                "/usr/bin/rpm",
                "/usr/bin/systemctl",
                "/usr/bin/curl",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            packages: std::collections::BTreeSet::new(),
            services: BTreeMap::new(),
            manager_completion: None,
            probe_completion: None,
            dnf_probe_output: None,
            query_completion: None,
            query_results: std::collections::VecDeque::new(),
            dnf_repos: vec![DnfRepo {
                id: "baseos".to_string(),
                mirrors: true,
                repodata_cached: true,
                mirrorlist_cached: true,
            }],
            dnf_repolist_output: None,
            dnf_dry_run_output: None,
            dnf_downloadonly_output: None,
            snap_rpm_listing: None,
            rpm_qp_results: std::collections::VecDeque::new(),
            snapshot_listing: None,
            live_cache_find_output: None,
            mktemp_output: None,
            snapshot_mode: "700".to_string(),
            snapshot_mode_after_copy: None,
            snapshot_chmod_fails: false,
            snapshot_stat_fails: false,
            snapshot_rm_fails: false,
            observation_overrides: Default::default(),
            manager: Default::default(),
            accounts: Default::default(),
            fs: None,
        }
    }

    /// A Rocky Linux 10 x86_64 target: dnf 4.20 backend, rpm 4.19 query,
    /// systemd 257. Ships no `acl` package (`getfacl` absent), which is
    /// safe: `getfattr` still reports `system.posix_acl_*` itself, so an
    /// ACL-bearing object is disqualified rather than silently copied over.
    pub fn rocky10() -> Self {
        FakeTarget {
            os_release: "NAME=\"Rocky Linux\"\nVERSION=\"10.2 (Red Quartz)\"\nRELEASE_TYPE=\"stable\"\nID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"10.2\"\nPLATFORM_ID=\"platform:el10\"\n".to_string(),
            hostname: "rocky10.test".to_string(),
            arch: "x86_64".to_string(),
            uid: 1000,
            gid: 1000,
            home: "/home/fake".to_string(),
            executables: [
                "/usr/bin/dnf",
                "/usr/bin/rpm",
                "/usr/bin/systemctl",
                "/usr/bin/curl",
                "/usr/bin/getfattr",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            packages: std::collections::BTreeSet::new(),
            services: BTreeMap::new(),
            manager_completion: None,
            probe_completion: None,
            dnf_probe_output: None,
            query_completion: None,
            query_results: std::collections::VecDeque::new(),
            dnf_repos: vec![DnfRepo {
                id: "baseos".to_string(),
                mirrors: true,
                repodata_cached: true,
                mirrorlist_cached: true,
            }],
            dnf_repolist_output: None,
            dnf_dry_run_output: None,
            dnf_downloadonly_output: None,
            snap_rpm_listing: None,
            rpm_qp_results: std::collections::VecDeque::new(),
            snapshot_listing: None,
            live_cache_find_output: None,
            mktemp_output: None,
            snapshot_mode: "700".to_string(),
            snapshot_mode_after_copy: None,
            snapshot_chmod_fails: false,
            snapshot_stat_fails: false,
            snapshot_rm_fails: false,
            observation_overrides: Default::default(),
            manager: Default::default(),
            accounts: Default::default(),
            fs: None,
        }
    }

    /// An Ubuntu 24.04 amd64 target: apt backend, dpkg-query, systemd.
    pub fn ubuntu2404() -> Self {
        FakeTarget {
            os_release: "NAME=\"Ubuntu\"\nVERSION=\"24.04 LTS\"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\n".to_string(),
            hostname: "ubuntu2404.test".to_string(),
            arch: "x86_64".to_string(),
            uid: 1000,
            gid: 1000,
            home: "/home/fake".to_string(),
            executables: ["/usr/bin/apt-get", "/usr/bin/dpkg-query", "/usr/bin/systemctl"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            packages: std::collections::BTreeSet::new(),
            services: BTreeMap::new(),
            manager_completion: None,
            probe_completion: None,
            dnf_probe_output: None,
            query_completion: None,
            query_results: std::collections::VecDeque::new(),
            dnf_repos: Vec::new(),
            dnf_repolist_output: None,
            dnf_dry_run_output: None,
            dnf_downloadonly_output: None,
            snap_rpm_listing: None,
            rpm_qp_results: std::collections::VecDeque::new(),
            snapshot_listing: None,
            live_cache_find_output: None,
            mktemp_output: None,
            snapshot_mode: "700".to_string(),
            snapshot_mode_after_copy: None,
            snapshot_chmod_fails: false,
            snapshot_stat_fails: false,
            snapshot_rm_fails: false,
            observation_overrides: Default::default(),
            manager: Default::default(),
            accounts: Default::default(),
            fs: None,
        }
    }

    /// An Ubuntu 26.04 amd64 target: apt backend, dpkg-query, systemd.
    /// `attr`/`acl` are absent from the default install (the stock Ubuntu
    /// cloud image ships neither), so a stock target cannot inspect xattrs
    /// and filesystem resources must fail closed — modeled exactly.
    pub fn ubuntu2604() -> Self {
        FakeTarget {
            os_release: "NAME=\"Ubuntu\"\nVERSION=\"26.04.1 LTS (Resolute Raccoon)\"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"26.04\"\nVERSION_CODENAME=resolute\nUBUNTU_CODENAME=resolute\n".to_string(),
            hostname: "ubuntu2604.test".to_string(),
            arch: "x86_64".to_string(),
            uid: 1000,
            gid: 1000,
            home: "/home/fake".to_string(),
            executables: ["/usr/bin/apt-get", "/usr/bin/dpkg-query", "/usr/bin/systemctl"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            packages: std::collections::BTreeSet::new(),
            services: BTreeMap::new(),
            manager_completion: None,
            probe_completion: None,
            dnf_probe_output: None,
            query_completion: None,
            query_results: std::collections::VecDeque::new(),
            dnf_repos: Vec::new(),
            dnf_repolist_output: None,
            dnf_dry_run_output: None,
            dnf_downloadonly_output: None,
            snap_rpm_listing: None,
            rpm_qp_results: std::collections::VecDeque::new(),
            snapshot_listing: None,
            live_cache_find_output: None,
            mktemp_output: None,
            snapshot_mode: "700".to_string(),
            snapshot_mode_after_copy: None,
            snapshot_chmod_fails: false,
            snapshot_stat_fails: false,
            snapshot_rm_fails: false,
            observation_overrides: Default::default(),
            manager: Default::default(),
            accounts: Default::default(),
            fs: None,
        }
    }

    /// A target whose /etc/os-release declares an unsupported OS.
    pub fn unsupported() -> Self {
        FakeTarget {
            os_release: "NAME=\"Mystery Linux\"\nID=mysteryos\nVERSION_ID=\"1\"\n".to_string(),
            hostname: "mystery.test".to_string(),
            arch: "x86_64".to_string(),
            uid: 1000,
            gid: 1000,
            home: "/home/fake".to_string(),
            executables: std::collections::BTreeSet::new(),
            packages: std::collections::BTreeSet::new(),
            services: BTreeMap::new(),
            manager_completion: None,
            probe_completion: None,
            dnf_probe_output: None,
            query_completion: None,
            query_results: std::collections::VecDeque::new(),
            dnf_repos: Vec::new(),
            dnf_repolist_output: None,
            dnf_dry_run_output: None,
            dnf_downloadonly_output: None,
            snap_rpm_listing: None,
            rpm_qp_results: std::collections::VecDeque::new(),
            snapshot_listing: None,
            live_cache_find_output: None,
            mktemp_output: None,
            snapshot_mode: "700".to_string(),
            snapshot_mode_after_copy: None,
            snapshot_chmod_fails: false,
            snapshot_stat_fails: false,
            snapshot_rm_fails: false,
            observation_overrides: Default::default(),
            manager: Default::default(),
            accounts: Default::default(),
            fs: None,
        }
    }

    pub fn with_package(mut self, name: &str) -> Self {
        self.packages.insert(name.to_string());
        self
    }

    /// Declare an executable present on the target (used by `test -x`
    /// capability probes and by command-resource dispatch: only declared
    /// programs may run).
    pub fn with_executable(mut self, path: &str) -> Self {
        self.executables.insert(path.to_string());
        self
    }

    /// Queue complete package-query results consumed in order by
    /// `rpm -q`/`dpkg-query` invocations.
    pub fn with_query_results(mut self, results: Vec<Output>) -> Self {
        self.query_results = results.into();
        self
    }

    /// Declare a systemd unit. `state` is (LoadState, ActiveState, UnitFileState).
    pub fn with_service(mut self, name: &str, state: (&str, &str, &str)) -> Self {
        self.services.insert(
            name.to_string(),
            (
                state.0.to_string(),
                state.1.to_string(),
                state.2.to_string(),
            ),
        );
        self
    }

    /// Enable the scripted filesystem (standard systemd directories) and the
    /// attribute-inspection tool the file resources require.
    pub fn with_fake_fs(mut self) -> Self {
        self.executables.insert("/usr/bin/getfattr".to_string());
        self.fs = Some(crate::fakesys::FakeFs::default());
        self
    }

    /// Add a local group (no members).
    pub fn with_group(mut self, name: &str, gid: u32) -> Self {
        self.accounts.groups.push(crate::fakesys::FakeGroup {
            name: name.to_string(),
            gid,
            members: Vec::new(),
        });
        self
    }

    /// Add a local user with its primary group already present.
    pub fn with_user(mut self, name: &str, uid: u32, gid: u32, home: &str, shell: &str) -> Self {
        self.accounts.users.push(crate::fakesys::FakeUser {
            name: name.to_string(),
            uid,
            gid,
            home: home.to_string(),
            shell: shell.to_string(),
        });
        self
    }

    /// Make an existing local group list `user` as a supplementary member.
    pub fn with_membership(mut self, group: &str, user: &str) -> Self {
        if let Some(g) = self.accounts.groups.iter_mut().find(|g| g.name == group) {
            g.members.push(user.to_string());
        }
        self
    }

    /// Set the stored shadow password field of a local user (`$6$…`, `!`,
    /// `!$6$…` for a locked account, ...).
    pub fn with_shadow(mut self, user: &str, field: &str) -> Self {
        self.accounts
            .shadows
            .insert(user.to_string(), field.to_string());
        self
    }

    /// Create a directory on the scripted filesystem (root-owned 0755).
    pub fn with_fs_dir(mut self, path: &str) -> Self {
        let fs = self.fs.get_or_insert_with(Default::default);
        fs.mkdir_node(path, 0o755, 0, 0);
        self
    }

    /// Put a regular file on the scripted filesystem (root-owned 0644).
    pub fn with_fs_file(mut self, path: &str, content: &str) -> Self {
        let fs = self.fs.get_or_insert_with(Default::default);
        fs.put_file(path, content.as_bytes(), 0o644, 0, 0);
        self
    }

    /// Declare a unit that exists on disk AND is loaded by the manager, with
    /// the given (LoadState, ActiveState, UnitFileState). The unit file is
    /// placed at `/etc/systemd/system/<name>`.
    pub fn with_loaded_unit(
        mut self,
        name: &str,
        content: &str,
        state: (&str, &str, &str),
    ) -> Self {
        let path = format!("/etc/systemd/system/{}", name);
        let fs = self.fs.get_or_insert_with(Default::default);
        fs.put_file(&path, content.as_bytes(), 0o644, 0, 0);
        self.executables.insert("/usr/bin/getfattr".to_string());
        self.manager.disk_changed(name, true);
        let rev = self.manager.disk[name];
        self.manager.loaded.insert(name.to_string(), rev);
        self.services.insert(
            name.to_string(),
            (
                state.0.to_string(),
                state.1.to_string(),
                state.2.to_string(),
            ),
        );
        self
    }

    /// Queue adversarial captures for an observation program (`stat`,
    /// `readlink`, `sha256sum`, ...). Each queued result is served verbatim,
    /// in order, to the next invocation of that program, so a test can drive
    /// a truncated, malformed, or contradictory capture through the real
    /// observation contract instead of a mock of it (IA-01).
    pub fn with_observations(mut self, program: &str, results: Vec<Output>) -> Self {
        self.observation_overrides
            .insert(program.to_string(), results.into());
        self
    }
}

/// The private snapshot root the scripted target hands out via `mktemp`.
const FAKE_SNAP: &str = "/var/tmp/sinter-dnf.fakesnap";

/// The rpm payload file name a `name-[epoch:]version-release.arch` NEVRA
/// operand downloads as (without the `.rpm` suffix): the epoch is never
/// part of the file name.
fn nevra_payload_basename(nevra: &str) -> Option<String> {
    let (body, arch) = nevra.rsplit_once('.')?;
    if arch.is_empty() {
        return None;
    }
    // An epoch sits between the name-EVR separator and the version:
    // `name-<epoch>:<version-release>` → the file name drops `<epoch>:`.
    let body = match body.split_once(':') {
        Some((pre, post)) => match pre.rsplit_once('-') {
            Some((name, ep)) if !ep.is_empty() && ep.bytes().all(|b| b.is_ascii_digit()) => {
                format!("{}-{}", name, post)
            }
            _ => return None,
        },
        None => body.to_string(),
    };
    if body.is_empty() {
        return None;
    }
    Some(format!("{}.{}", body, arch))
}

/// The live DNF metadata cache root the scripted target copies a snapshot
/// from (R4-A04).
const LIVE_CACHE_ROOT: &str = "/var/cache/dnf";

pub struct FakeExecutor {
    pub log: Vec<CommandRecord>,
    pub sudo: bool,
    pub home: String,
    target: FakeTarget,
    /// Whether the metadata cache copy into the private snapshot root has
    /// run, so the post-copy `stat` can report a copy that widened the root.
    snap_copied: bool,
    /// Payload file paths the download-only `dnf install` placed in the
    /// snapshot's package caches — what `find <snap> -name '*.rpm'` then
    /// reports.
    snap_payloads: Vec<String>,
    stats: ExecStatsHandle,
}

impl FakeExecutor {
    pub fn new(target: FakeTarget, sudo: bool) -> Self {
        let home = target.home.clone();
        FakeExecutor {
            log: Vec::new(),
            sudo,
            home,
            target,
            snap_copied: false,
            snap_payloads: Vec::new(),
            stats: ExecStatsHandle::default(),
        }
    }

    fn exited(code: i32, stdout: String, stderr: String) -> Output {
        Output {
            completion: Completion::Exited(code),
            stdout: stdout.into_bytes(),
            stderr: stderr.into_bytes(),
            stdout_truncated: false,
            stderr_truncated: false,
        }
    }

    fn run(&mut self, req: &ExecRequest) -> Output {
        let started = Instant::now();
        let out = self.exec_fake(req);
        self.stats
            .note(req, self.sudo, started.elapsed(), Some(&out));
        out
    }

    fn exec_fake(&mut self, req: &ExecRequest) -> Output {
        let prog = req
            .program
            .rsplit('/')
            .next()
            .unwrap_or(&req.program)
            .to_string();
        // An adversarial override for an observation program wins over the
        // modeled behavior; the queued capture is served verbatim.
        if let Some(o) = self.target.observation_overrides.get_mut(&prog) {
            if let Some(o) = o.pop_front() {
                return o;
            }
        }
        if let Some(o) = self.run_fake_fs(&prog, req) {
            return o;
        }
        match prog.as_str() {
            "test" => self.run_test(&req.args),
            "hostname" => Self::exited(0, format!("{}\n", self.target.hostname), String::new()),
            "cat" => self.run_cat(&req.args),
            "uname" => Self::exited(0, format!("{}\n", self.target.arch), String::new()),
            "id" => self.run_id(&req.args),
            "getent" => self.run_getent(&req.args),
            "useradd" | "usermod" | "userdel" | "groupadd" | "groupdel" | "chpasswd" => {
                let target = (self.target.uid, self.target.gid, self.target.home.clone());
                let t = (target.0, target.1, target.2.as_str());
                let root = self.sudo;
                match self
                    .target
                    .accounts
                    .command(&prog, &req.args, req.stdin.as_deref(), root, t)
                {
                    Some(o) => o,
                    None => Self::exited(127, String::new(), "fake target: unmodeled".into()),
                }
            }
            "rpm" => self.run_rpm(&req.args),
            "dpkg-query" => self.run_dpkg_query(&req.args),
            "dnf" | "apt-get" => self.run_manager(&prog, &req.args),
            "systemctl" => self.run_systemctl(&req.args),
            "mktemp" => self
                .target
                .mktemp_output
                .clone()
                .unwrap_or_else(|| Self::exited(0, format!("{}\n", FAKE_SNAP), String::new())),
            "chmod" => {
                // The private dnf snapshot root permission enforcement
                // (0700). Only the snapshot root is modeled; any other
                // chmod is an unmodeled no-op that succeeds.
                let is_snap = req.args.iter().any(|a| a == FAKE_SNAP);
                if is_snap && self.target.snapshot_chmod_fails {
                    Self::exited(
                        1,
                        String::new(),
                        "injected snapshot chmod failure".to_string(),
                    )
                } else {
                    Self::exited(0, String::new(), String::new())
                }
            }
            "stat" => self.run_stat(&req.args),
            "cp" => {
                // The metadata cache copy into the private snapshot root:
                // `cp -a -- <child> <snap>/`, one child of the live cache root
                // at a time. Copying children into the existing directory
                // never rewrites the destination root's own mode (R4-A04), so
                // an override is the only way a post-copy root is not 0700.
                let is_snap_copy = req
                    .args
                    .iter()
                    .any(|a| a.starts_with(FAKE_SNAP) || a.starts_with(LIVE_CACHE_ROOT));
                if is_snap_copy {
                    self.snap_copied = true;
                }
                Self::exited(0, String::new(), String::new())
            }
            "mkdir" => Self::exited(0, String::new(), String::new()),
            "rm" => {
                // `rm -rf <snap>` cleans up the private dnf metadata
                // snapshot. Only the snapshot root is modeled; any other rm
                // is an unmodeled no-op that succeeds.
                let is_snap = req.args.iter().any(|a| a == FAKE_SNAP);
                if is_snap && self.target.snapshot_rm_fails {
                    Self::exited(
                        1,
                        String::new(),
                        "injected snapshot removal failure".to_string(),
                    )
                } else {
                    Self::exited(0, String::new(), String::new())
                }
            }
            "curl" | "wget" => Self::exited(0, String::new(), String::new()),
            "find" => self.run_find(&req.args),
            // Anything else (e.g. user command resources): an unmodeled
            // operation is only a definite success when the program was
            // explicitly declared present on the target; otherwise it fails
            // deterministically so a missing model can never masquerade as
            // a successful observation.
            _ => {
                if self.target.executables.contains(&req.program) {
                    Self::exited(0, String::new(), String::new())
                } else {
                    Self::exited(
                        127,
                        String::new(),
                        format!("fake target: unmodeled program {}", req.program),
                    )
                }
            }
        }
    }

    fn run_test(&self, args: &[String]) -> Output {
        match args.first().map(|s| s.as_str()) {
            Some("-r") => {
                let exists = args.iter().any(|a| a == "/etc/os-release");
                Self::exited(if exists { 0 } else { 1 }, String::new(), String::new())
            }
            Some("-x") => {
                let present = args
                    .last()
                    .map(|p| self.target.executables.contains(p))
                    .unwrap_or(false);
                Self::exited(if present { 0 } else { 1 }, String::new(), String::new())
            }
            _ => Self::exited(1, String::new(), "fake test: unsupported args".to_string()),
        }
    }

    fn run_cat(&self, args: &[String]) -> Output {
        if args.iter().any(|a| a == "/etc/os-release") {
            Self::exited(0, self.target.os_release.clone(), String::new())
        } else {
            Self::exited(
                1,
                String::new(),
                "fake target has no modeled filesystem".to_string(),
            )
        }
    }

    fn run_id(&self, args: &[String]) -> Output {
        match args.first().map(|s| s.as_str()) {
            Some("-u") => {
                let uid = if self.sudo { 0 } else { self.target.uid };
                Self::exited(0, format!("{}\n", uid), String::new())
            }
            Some("-g") => {
                let gid = if self.sudo { 0 } else { self.target.gid };
                Self::exited(0, format!("{}\n", gid), String::new())
            }
            _ => Self::exited(1, String::new(), "fake id: unsupported args".to_string()),
        }
    }

    fn run_getent(&self, args: &[String]) -> Output {
        let target = (self.target.uid, self.target.gid, self.target.home.as_str());
        // `getent -s files <db> [key]`: the local-database lookup of the
        // user/group resources.
        if args.first().map(|s| s.as_str()) == Some("-s") {
            if args.get(1).map(|s| s.as_str()) != Some("files") || args.len() < 3 {
                return Self::exited(1, String::new(), "getent: unsupported service".to_string());
            }
            if args[2] == "shadow" {
                return self.target.accounts.shadow_getent(
                    args.get(3).map(|s| s.as_str()),
                    self.sudo,
                    target,
                );
            }
            return self.target.accounts.getent(
                true,
                &args[2],
                args.get(3).map(|s| s.as_str()),
                target,
            );
        }
        let db = args.first().map(|s| s.as_str()).unwrap_or("");
        let key = args.get(1).map(|s| s.as_str()).unwrap_or("");
        // Names the scripted accounts add are answered after the built-in
        // fake identity (below) has had its chance.
        let extra = |this: &Self| {
            if key.is_empty() {
                Self::exited(2, String::new(), String::new())
            } else {
                this.target.accounts.getent(false, db, Some(key), target)
            }
        };
        match db {
            "passwd" => {
                let (uid, gid, home) = if self.sudo {
                    (0, 0, "/root")
                } else {
                    (self.target.uid, self.target.gid, self.target.home.as_str())
                };
                if key == "root" || key == "0" {
                    return Self::exited(
                        0,
                        "root:x:0:0:root:/root:/bin/sh\n".to_string(),
                        String::new(),
                    );
                }
                if key == uid.to_string() || key == "fakeuser" {
                    return Self::exited(
                        0,
                        format!("fakeuser:x:{}:{}:fake:{}:/bin/sh\n", uid, gid, home),
                        String::new(),
                    );
                }
                extra(self)
            }
            "group" => {
                let gid = if self.sudo { 0 } else { self.target.gid };
                if key == "root" || key == "0" {
                    return Self::exited(0, "root:x:0:\n".to_string(), String::new());
                }
                if key == gid.to_string() || key == "fakegroup" {
                    return Self::exited(0, format!("fakegroup:x:{}:\n", gid), String::new());
                }
                extra(self)
            }
            _ => Self::exited(2, String::new(), String::new()),
        }
    }

    fn next_query_result(&mut self) -> Option<Output> {
        if let Some(o) = self.target.query_results.pop_front() {
            return Some(o);
        }
        self.target.query_completion.as_ref().map(|c| Output {
            completion: c.clone(),
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        })
    }

    fn run_rpm(&mut self, args: &[String]) -> Output {
        // `rpm -qp --queryformat <fmt> <file>` — a payload identity query,
        // not an installed-package observation: queued answers are popped
        // from `rpm_qp_results`, and otherwise the identity is derived
        // from the file's own `<name>-<version-release>.<arch>.rpm` name.
        if args.iter().any(|a| a == "-qp" || a == "-p") {
            if let Some(o) = self.target.rpm_qp_results.pop_front() {
                return o;
            }
            let file = args.last().cloned().unwrap_or_default();
            let base = file.rsplit('/').next().unwrap_or("");
            let Some(stem) = base.strip_suffix(".rpm") else {
                return Self::exited(
                    1,
                    String::new(),
                    format!("fake rpm: {} is not a payload file", file),
                );
            };
            // `<name>-<version>-<release>.<arch>`: the name may contain
            // '-', so version and release split from the right.
            let Some((noarch, arch)) = stem.rsplit_once('.') else {
                return Self::exited(
                    1,
                    String::new(),
                    format!("fake rpm: {} is not a payload file", file),
                );
            };
            let Some((nover, rel)) = noarch.rsplit_once('-') else {
                return Self::exited(
                    1,
                    String::new(),
                    format!("fake rpm: {} is not a payload file", file),
                );
            };
            let Some((name, ver)) = nover.rsplit_once('-') else {
                return Self::exited(
                    1,
                    String::new(),
                    format!("fake rpm: {} is not a payload file", file),
                );
            };
            return Self::exited(
                0,
                format!("{}|(none)|{}|{}|{}\n", name, ver, rel, arch),
                String::new(),
            );
        }
        if let Some(o) = self.next_query_result() {
            return o;
        }
        // The fixed `--queryformat %{NAME}` contract: exit 0 with exactly the
        // package NAME on stdout when installed; otherwise reference rpm 4.16
        // prints the absent marker to stdout (not stderr) and exits 1.
        let name = args.last().cloned().unwrap_or_default();
        if self.target.packages.contains(&name) {
            Self::exited(0, name, String::new())
        } else {
            Self::exited(
                1,
                format!("package {} is not installed\n", name),
                String::new(),
            )
        }
    }

    fn run_dpkg_query(&mut self, args: &[String]) -> Output {
        if let Some(o) = self.next_query_result() {
            return o;
        }
        let name = args.last().cloned().unwrap_or_default();
        if self.target.packages.contains(&name) {
            // Reference dpkg 1.21/1.22: one status record on stdout, nothing
            // on stderr, exit 0.
            Self::exited(0, "install ok installed".to_string(), String::new())
        } else {
            // Reference dpkg: the absence answer is exactly one diagnostic
            // line on stderr naming the package, with stdout empty, exit 1.
            Self::exited(
                1,
                String::new(),
                format!("dpkg-query: no packages found matching {}\n", name),
            )
        }
    }

    /// `find <snap> -type f -name '*.rpm'` — the payload enumeration after
    /// the download-only transport: every `.rpm` that landed in the
    /// snapshot. An explicit listing override wins so tests can model a
    /// missing, unexpected or misplaced payload.
    ///
    /// `find <snap> -mindepth 1 -maxdepth 2` — lists the snapshot's
    /// per-repo cache dirs (`<repoid>-<hash>`), repodata, and cached
    /// mirror lists for every modeled repo. An explicit listing override
    /// wins so tests can model ambiguous cache layouts.
    ///
    /// `find /var/cache/dnf -mindepth 1 -maxdepth 1 -print0` — lists the
    /// live cache root's own entries (NUL-separated, hidden ones included),
    /// which the snapshot copy copies one at a time (R4-A04).
    fn run_find(&mut self, args: &[String]) -> Output {
        let root = args.first().cloned().unwrap_or_default();
        if args.iter().any(|a| a == "-name") {
            if let Some(listing) = self.target.snap_rpm_listing.clone() {
                return Self::exited(0, listing, String::new());
            }
            let mut out = String::new();
            for p in &self.snap_payloads {
                out.push_str(p);
                out.push('\n');
            }
            return Self::exited(0, out, String::new());
        }
        if root == LIVE_CACHE_ROOT {
            // The live metadata cache: one directory per repository whose
            // repodata is cached. A repo with no cached repodata has no
            // directory here at all. An explicit raw-byte override wins so
            // tests can model NUL-framing and path-domain defects (R4-F01).
            if let Some(o) = self.target.live_cache_find_output.clone() {
                return o;
            }
            let mut out = String::new();
            for r in &self.target.dnf_repos {
                if r.repodata_cached {
                    out.push_str(&format!("{}/{}-cafebabecafebabe\0", root, r.id));
                }
            }
            return Self::exited(0, out, String::new());
        }
        if let Some(listing) = self.target.snapshot_listing.clone() {
            return Self::exited(0, listing, String::new());
        }
        let mut out = String::new();
        for r in &self.target.dnf_repos {
            if r.repodata_cached {
                out.push_str(&format!("{}/{}-cafebabecafebabe\n", root, r.id));
                out.push_str(&format!("{}/{}-cafebabecafebabe/repodata\n", root, r.id));
                out.push_str(&format!(
                    "{}/{}-cafebabecafebabe/repodata/repomd.xml\n",
                    root, r.id
                ));
                if r.mirrors && r.mirrorlist_cached {
                    out.push_str(&format!("{}/{}-cafebabecafebabe/mirrorlist\n", root, r.id));
                }
            }
        }
        Self::exited(0, out, String::new())
    }

    /// `stat -c %a %u -- <snap>` — verifies the private snapshot root stays
    /// 0700 and is owned by the effective execution identity. Any other
    /// stat shape is an unmodeled filesystem query and fails honestly.
    fn run_stat(&mut self, args: &[String]) -> Output {
        let is_snap_verify = args.iter().any(|a| a == "%a %u")
            && args.last().map(|p| p == FAKE_SNAP).unwrap_or(false);
        if is_snap_verify {
            if self.target.snapshot_stat_fails {
                return Self::exited(
                    1,
                    String::new(),
                    "injected snapshot stat failure".to_string(),
                );
            }
            // A root that is not 0700 after content was placed in it is
            // reported by the post-copy verification; before the copy the
            // mktemp/chmod mode applies. The copy itself cannot widen the
            // root (R4-A04), so an override models some other cause.
            let mode = if self.snap_copied {
                self.target
                    .snapshot_mode_after_copy
                    .as_deref()
                    .unwrap_or(&self.target.snapshot_mode)
            } else {
                &self.target.snapshot_mode
            };
            let uid = if self.sudo { 0 } else { self.target.uid };
            return Self::exited(0, format!("{} {}\n", mode, uid), String::new());
        }
        Self::exited(
            1,
            String::new(),
            "fake target has no modeled filesystem".to_string(),
        )
    }

    fn run_manager(&mut self, prog: &str, args: &[String]) -> Output {
        let name = args.last().cloned().unwrap_or_default();
        if prog == "dnf" && args.iter().any(|a| a == "repolist") {
            // repolist -v: the real dnf 4.14 stream layout (R5-F04). stdout
            // opens with the native preamble — `Loaded plugins:`, then the
            // `-v` debug lines `DNF version:`/`cachedir:` — then one block
            // per enabled repo in the shape
            // `dnf/cli/commands/repolist.py::RepoListCommand.run` prints:
            // blocks joined by a blank line, each opened by `Repo-id` and
            // always showing `Repo-name`, closed by the `Total packages: N`
            // footer. `Repo-status` is deliberately absent — plain
            // `repolist -v` prints it only for `--all` or explicit repo
            // arguments, never for this invocation (R4-F04). repolist
            // redirects INFO to stderr, so the informational metadata-age
            // line lands there — exactly once — on a successful run. An
            // explicit override wins so tests can model truncated or
            // malformed enumeration.
            if let Some(o) = self.target.dnf_repolist_output.clone() {
                return o;
            }
            let mut blocks: Vec<String> = Vec::new();
            let mut total_pkgs = 0usize;
            for r in &self.target.dnf_repos {
                let mut fields: Vec<String> = vec![
                    format!("Repo-id            : {}", r.id),
                    format!("Repo-name          : {}", r.id),
                ];
                if r.mirrors {
                    fields.push("Repo-mirrors       : https://mirrors.example/?repo=x".into());
                }
                fields.push("Repo-expire        : Never (last: unknown)".into());
                fields.push("Repo-filename      : /etc/yum.repos.d/fake.repo".into());
                total_pkgs += 1;
                blocks.push(fields.join("\n"));
            }
            let mut s = String::from(
                "Loaded plugins: builddep, changelog, config-manager, copr, debug, \
                 debuginfo-install, download, generate_completion_cache, groups-manager, \
                 needs-restarting, playground, repoclosure, repodiff, repograph, repomanage, \
                 reposync, system-upgrade\n\
                 DNF version: 4.14.0\n\
                 cachedir: /var/cache/dnf\n",
            );
            if !blocks.is_empty() {
                s.push_str(&blocks.join("\n\n"));
                s.push_str(&format!("\nTotal packages: {}\n", total_pkgs));
            }
            return Self::exited(
                0,
                s,
                "Last metadata expiration check: 0:30:00 ago on Wed Sep 16 10:28:01 2026.\n"
                    .to_string(),
            );
        }
        if prog == "dnf" && args.iter().any(|a| a == "repoquery") {
            // DESIGN §27 snapshot-usability check: a full-output override
            // wins, then a forced completion; otherwise the check fails iff
            // any enabled repo lacks cached repodata ("Cache-only enabled but
            // no cache"). A real `dnf -C repoquery` emits the metadata-age
            // INFO line on stderr for a successful check (R5-F04).
            if let Some(o) = self.target.dnf_probe_output.clone() {
                return o;
            }
            if let Some(c) = &self.target.probe_completion {
                return Output {
                    completion: c.clone(),
                    stdout: Vec::new(),
                    stderr: b"Cache-only enabled but no cache for 'baseos'\n".to_vec(),
                    stdout_truncated: false,
                    stderr_truncated: false,
                };
            }
            if self.target.dnf_repos.iter().all(|r| r.repodata_cached) {
                return Self::exited(
                    0,
                    format!("{}\n", name),
                    "Last metadata expiration check: 0:30:00 ago on Wed Sep 16 10:28:01 2026.\n"
                        .to_string(),
                );
            }
            let missing = self
                .target
                .dnf_repos
                .iter()
                .find(|r| !r.repodata_cached)
                .map(|r| r.id.clone())
                .unwrap_or_else(|| "baseos".to_string());
            return Self::exited(
                1,
                String::new(),
                format!("Error: Cache-only enabled but no cache for '{}'\n", missing),
            );
        }
        if prog == "dnf"
            && args.iter().any(|a| a == "install")
            && args.iter().any(|a| a == "--assumeno")
        {
            // Cache-only dry run: the transaction table naming the exact
            // payload set, in the real dnf 4.14 stream layout (R5-F04):
            // stdout carries the `Last metadata expiration check` INFO line,
            // the table, `Total download size:` and `Installed size:`;
            // stderr carries `Operation aborted.` — the `CliError` the
            // assumeno abort raises, logged at ERROR (real dnf exits 1). An
            // explicit override wins so tests can model truncated, malformed,
            // or ambiguous transactions.
            if let Some(o) = self.target.dnf_dry_run_output.clone() {
                return o;
            }
            let repoid = self
                .target
                .dnf_repos
                .first()
                .map(|r| r.id.clone())
                .unwrap_or_else(|| "baseos".to_string());
            let table = format!(
                "Last metadata expiration check: 0:30:00 ago on Wed Sep 16 10:28:01 2026.\n\
                 Dependencies resolved.\n\
                 ================================================================================\n \
                 Package                Architecture     Version                 Repository        Size\n\
                 ================================================================================\n\
                 Installing:\n \
                 {n:<15}x86_64           1.0-1.el9             {r:<16} 1 k\n\n\
                 Transaction Summary\n\
                 ================================================================================\n\
                 Install  1 Package\n\n\
                 Total download size: 1 k\n\
                 Installed size: 2 k\n",
                n = name,
                r = repoid
            );
            return Self::exited(1, table, "Operation aborted.\n".to_string());
        }
        if prog == "dnf"
            && args.iter().any(|a| a == "install")
            && args.iter().any(|a| a == "--downloadonly")
        {
            // Native payload transport: dnf places one
            // `<name>-<version-release>.<arch>.rpm` per resolved NEVRA
            // operand into the repository's snapshot package dir — no
            // rpmdb mutation. An explicit override wins so tests can model
            // a failed transport; the payload set the run reports is then
            // whatever `snap_rpm_listing` says landed.
            if let Some(o) = self.target.dnf_downloadonly_output.clone() {
                return o;
            }
            let repoid = self
                .target
                .dnf_repos
                .first()
                .map(|r| r.id.clone())
                .unwrap_or_else(|| "baseos".to_string());
            self.snap_payloads.clear();
            for a in args
                .iter()
                .skip_while(|x| x.as_str() != "--downloadonly")
                .skip(1)
            {
                if let Some(base) = nevra_payload_basename(a) {
                    self.snap_payloads.push(format!(
                        "{}/{}-cafebabecafebabe/packages/{}.rpm",
                        FAKE_SNAP, repoid, base
                    ));
                }
            }
            return Self::exited(0, String::new(), String::new());
        }
        if let Some(c) = &self.target.manager_completion {
            return Output {
                completion: c.clone(),
                stdout: Vec::new(),
                stderr: Vec::new(),
                stdout_truncated: false,
                stderr_truncated: false,
            };
        }
        if args.iter().any(|a| a == "install") {
            self.target.packages.insert(name);
        } else if args.iter().any(|a| a == "remove") {
            self.target.packages.remove(&name);
        } else {
            return Self::exited(
                1,
                String::new(),
                format!("fake {}: unsupported operation", prog),
            );
        }
        Self::exited(0, String::new(), String::new())
    }

    /// Route a filesystem command to the scripted filesystem when one is
    /// enabled. Returns `None` for anything the scripted filesystem does not
    /// model (so the historical behavior is unchanged) and for the dnf
    /// snapshot paths the existing package model owns.
    fn run_fake_fs(&mut self, prog: &str, req: &ExecRequest) -> Option<Output> {
        self.target.fs.as_ref()?;
        if req.args.iter().any(|a| a.starts_with(FAKE_SNAP)) {
            return None;
        }
        if prog == "cat" && req.args.iter().any(|a| a == "/etc/os-release") {
            return None;
        }
        let (uid, gid) = if self.sudo {
            (0, 0)
        } else {
            (self.target.uid, self.target.gid)
        };
        let fs = self.target.fs.as_mut()?;
        let (out, touched) = fs.run(prog, &req.args, req.stdin.as_deref(), uid, gid)?;
        if out.completion == Completion::Exited(0) {
            for (path, link, present) in touched {
                if let Some(unit) = crate::fakesys::FakeFs::unit_of_touched(&path, link) {
                    self.target.manager.disk_changed(&unit, present);
                }
            }
        }
        Some(out)
    }

    fn show_need_record(&self, unit: &str) -> Vec<String> {
        use crate::fakesys::NeedOverride;
        // A unit the manager has not loaded reports no staleness.
        let loaded = self.target.services.contains_key(unit);
        match self.target.manager.need_override.get(unit) {
            Some(NeedOverride::Missing) => vec![],
            Some(NeedOverride::Duplicate) => {
                vec![
                    "NeedDaemonReload=no".to_string(),
                    "NeedDaemonReload=no".to_string(),
                ]
            }
            Some(NeedOverride::Value(v)) => vec![format!("NeedDaemonReload={}", v)],
            None => vec![format!(
                "NeedDaemonReload={}",
                if loaded
                    && (self.target.manager.need_daemon_reload(unit)
                        || self.target.manager.forced_stale.contains(unit))
                {
                    "yes"
                } else {
                    "no"
                }
            )],
        }
    }

    fn run_systemctl(&mut self, args: &[String]) -> Output {
        let verb = args.first().map(|s| s.as_str()).unwrap_or("");
        if verb == "show" && args.iter().any(|a| a == "--property=UnitPath") {
            return match self.target.manager.unit_path_output.clone() {
                Some(o) => o,
                None => Self::exited(
                    0,
                    crate::fakesys::FAKE_UNIT_PATH_OUTPUT.to_string(),
                    String::new(),
                ),
            };
        }
        if verb == "daemon-reload" {
            if args.len() != 1 {
                return Self::exited(1, String::new(), "fake systemctl: unexpected argv".into());
            }
            self.target.manager.reload_count += 1;
            if let Some(c) = self.target.manager.reload_completion.clone() {
                return Output {
                    completion: c,
                    stdout: Vec::new(),
                    stderr: self.target.manager.reload_stderr.clone().into_bytes(),
                    stdout_truncated: false,
                    stderr_truncated: false,
                };
            }
            self.target.manager.sync(&mut self.target.services);
            self.target.manager.show_failures_left = self.target.manager.show_fail_after_reload;
            self.target.manager.forced_stale = self.target.manager.stale_after_reload.clone();
            return Self::exited(0, String::new(), String::new());
        }
        if verb == "show" {
            // Observation argv is `show --property=... -- <unit>`: the unit
            // name is the operand after `--`.
            let name = args.last().cloned().unwrap_or_default();
            if self.target.manager.show_failures_left > 0 {
                self.target.manager.show_failures_left -= 1;
                let stderr = self
                    .target
                    .manager
                    .show_fail_stderr
                    .clone()
                    .unwrap_or_else(|| "Failed to get properties: connection lost".into());
                return match self.target.manager.show_fail_completion.clone() {
                    None => Self::exited(1, String::new(), stderr),
                    Some(completion) => Output {
                        completion,
                        stdout: Vec::new(),
                        stderr: stderr.into_bytes(),
                        stdout_truncated: false,
                        stderr_truncated: false,
                    },
                };
            }
            self.target
                .manager
                .lazy_load(&name, &mut self.target.services, true);
            return match self.target.services.get(&name) {
                Some((load, active, unitfile)) => {
                    let mut lines = vec![
                        format!("LoadState={}", load),
                        format!("ActiveState={}", active),
                        format!("UnitFileState={}", unitfile),
                    ];
                    lines.extend(self.show_need_record(&name));
                    Self::exited(0, format!("{}\n", lines.join("\n")), String::new())
                }
                None => {
                    let mut lines = vec![
                        "LoadState=not-found".to_string(),
                        "ActiveState=inactive".to_string(),
                        "UnitFileState=".to_string(),
                    ];
                    lines.extend(self.show_need_record(&name));
                    Self::exited(0, format!("{}\n", lines.join("\n")), String::new())
                }
            };
        }
        // Mutating argv is `<verb> -- <unit>`; any other shape is refused so
        // a unit name can never be dispatched where systemctl parses options.
        let name = match args {
            [_, sep, unit] if sep == "--" => unit.clone(),
            _ => {
                return Self::exited(
                    1,
                    String::new(),
                    format!("fake systemctl: expected `{} -- <unit>`", verb),
                )
            }
        };
        if matches!(verb, "enable" | "disable") {
            // enable/disable read the unit from disk even when it was never
            // loaded (or only a stale not-found stub is cached).
            self.target
                .manager
                .lazy_load(&name, &mut self.target.services, false);
        }
        if let Some(forced) = self.target.manager.verb_override.get(verb) {
            return forced.clone();
        }
        let Some(entry) = self.target.services.get_mut(&name) else {
            if verb == "reset-failed" {
                // systemd's answer for a unit that is not in memory.
                return Self::exited(
                    1,
                    String::new(),
                    format!(
                        "Failed to reset failed state of unit {}: Unit {} not loaded.\n",
                        name, name
                    ),
                );
            }
            return Self::exited(1, String::new(), format!("Unit {} not found", name));
        };
        match verb {
            "start" | "restart" => entry.1 = "active".to_string(),
            "stop" => {
                entry.1 = "inactive".to_string();
                if self.target.manager.show_fail_after_stop > 0 {
                    self.target.manager.show_failures_left =
                        self.target.manager.show_fail_after_stop;
                }
                if self.target.manager.unload_on_stop.contains(&name) {
                    self.target.services.remove(&name);
                }
            }
            "reset-failed" => {
                if entry.1 == "failed" {
                    entry.1 = "inactive".to_string();
                }
            }
            "enable" => {
                entry.2 = "enabled".to_string();
                if self.target.manager.enable_starts.contains(&name) {
                    entry.1 = "active".to_string();
                }
            }
            "disable" => entry.2 = "disabled".to_string(),
            "reload" => {}
            _ => {
                return Self::exited(
                    1,
                    String::new(),
                    format!("fake systemctl: unsupported verb {}", verb),
                )
            }
        }
        if matches!(verb, "enable" | "disable") && self.target.manager.implicit_reload_on_enable {
            // Native implicit daemon-reload after the unit-file link change.
            self.target.manager.implicit_reload_count += 1;
            self.target.manager.sync(&mut self.target.services);
        }
        Self::exited(0, String::new(), String::new())
    }
}

#[cfg(test)]
mod hostkey_tests {
    use super::*;

    fn blob(t: &str) -> Vec<u8> {
        let mut b = (t.len() as u32).to_be_bytes().to_vec();
        b.extend_from_slice(t.as_bytes());
        b.extend_from_slice(&[0, 0, 0, 1, 7]);
        b
    }

    #[test]
    fn key_type_from_blob() {
        assert_eq!(ssh_key_type(&blob("ssh-ed25519")), Some("ssh-ed25519"));
        assert_eq!(
            ssh_key_type(&blob("ecdsa-sha2-nistp256")),
            Some("ecdsa-sha2-nistp256")
        );
        assert_eq!(ssh_key_type(&[0, 0, 0, 9, b'x']), None);
        assert_eq!(ssh_key_type(&[]), None);
    }

    #[test]
    fn identity_is_port_scoped_and_alias_aware() {
        assert_eq!(known_hosts_identity("h", 22, None), "h");
        assert_eq!(known_hosts_identity("h", 2222, None), "[h]:2222");
        assert_eq!(known_hosts_identity("10.0.0.1", 22, Some("web01")), "web01");
        assert_eq!(
            known_hosts_identity("10.0.0.1", 2222, Some("web01")),
            "[web01]:2222"
        );
    }

    #[test]
    fn known_types_are_preferred_within_the_allowlist() {
        let p = hostkey_preference(&["ssh-ed25519".to_string()], SSH_HOSTKEY_ALGORITHMS);
        assert_eq!(
            p,
            "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256"
        );
        // An RSA host key is reached through rsa-sha2-*, never SHA-1 ssh-rsa.
        let p = hostkey_preference(&["ssh-rsa".to_string()], SSH_HOSTKEY_ALGORITHMS);
        assert!(
            p.starts_with("rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256"),
            "{p}"
        );
        assert!(!p.split(',').any(|a| a == "ssh-rsa"), "{p}");
        // Nothing known, or an unsupported known type: the allowlist order.
        let all = SSH_HOSTKEY_ALGORITHMS.join(",");
        assert_eq!(hostkey_preference(&[], SSH_HOSTKEY_ALGORITHMS), all);
        assert_eq!(
            hostkey_preference(&["ssh-dss".to_string()], SSH_HOSTKEY_ALGORITHMS),
            all
        );
    }

    const POLICY: &[(&str, &[&str])] = &[
        ("kex", SSH_KEX_ALGORITHMS),
        ("hostkey", SSH_HOSTKEY_ALGORITHMS),
        ("cipher", SSH_CIPHERS),
        ("mac", SSH_MACS),
    ];

    #[test]
    fn ssh_policy_lists_are_well_formed() {
        for (cat, list) in POLICY {
            assert!(!list.is_empty(), "{cat}: empty");
            for (i, a) in list.iter().enumerate() {
                assert!(
                    !a.is_empty() && !a.contains(',') && !a.contains(char::is_whitespace),
                    "{cat}: bad name {a:?}"
                );
                assert!(!list[..i].contains(a), "{cat}: duplicate {a}");
            }
        }
    }

    /// Every policy name is supported by the linked libssh2 (which silently
    /// drops unknown names), and every supported name left out of the
    /// policy is one of the known legacy algorithms, never a modern one
    /// dropped by accident.
    #[test]
    fn ssh_policy_matches_the_linked_libssh2() {
        let s = ssh2::Session::new().unwrap();
        let cats = [
            (ssh2::MethodType::Kex, SSH_KEX_ALGORITHMS),
            (ssh2::MethodType::HostKey, SSH_HOSTKEY_ALGORITHMS),
            (ssh2::MethodType::CryptCs, SSH_CIPHERS),
            (ssh2::MethodType::CryptSc, SSH_CIPHERS),
            (ssh2::MethodType::MacCs, SSH_MACS),
            (ssh2::MethodType::MacSc, SSH_MACS),
        ];
        // Supported names deliberately excluded. `ext-info-c` and
        // `kex-strict-c-v00@openssh.com` are KEX extensions that libssh2
        // adds to any KEX preference itself.
        let excluded = [
            "diffie-hellman-group1-sha1",
            "diffie-hellman-group14-sha1",
            "diffie-hellman-group-exchange-sha1",
            "ext-info-c",
            "kex-strict-c-v00@openssh.com",
            "ssh-rsa",
            "aes256-cbc",
            "rijndael-cbc@lysator.liu.se",
            "aes192-cbc",
            "aes128-cbc",
            "blowfish-cbc",
            "arcfour128",
            "arcfour",
            "cast128-cbc",
            "3des-cbc",
            "hmac-sha1",
            "hmac-sha1-etm@openssh.com",
            "hmac-sha1-96",
            "hmac-md5",
            "hmac-md5-96",
            "hmac-ripemd160",
            "hmac-ripemd160@openssh.com",
        ];
        for (t, list) in cats {
            let supported = s.supported_algs(t).unwrap();
            for a in list {
                assert!(
                    supported.contains(a),
                    "{a} not supported by the linked libssh2"
                );
            }
            for a in &supported {
                if !list.contains(a) {
                    assert!(
                        excluded.contains(a) || a.ends_with("-cert-v01@openssh.com"),
                        "{a} is supported but neither allowed nor a known exclusion"
                    );
                }
            }
        }
    }

    #[test]
    fn ssh_policy_excludes_legacy_and_keeps_modern_algorithms() {
        let all: Vec<&str> = POLICY.iter().flat_map(|(_, l)| l.iter().copied()).collect();
        for weak in [
            "diffie-hellman-group1-sha1",
            "diffie-hellman-group14-sha1",
            "diffie-hellman-group-exchange-sha1",
            "ssh-rsa",
            "3des-cbc",
            "aes128-cbc",
            "aes256-cbc",
            "blowfish-cbc",
            "cast128-cbc",
            "arcfour",
            "arcfour128",
            "hmac-md5",
            "hmac-sha1",
            "hmac-ripemd160",
        ] {
            assert!(!all.contains(&weak), "{weak} must not be allowed");
        }
        assert!(!all.iter().any(|a| a.ends_with("-cbc") || a.contains("md5")));
        for (cat, list, want) in [
            ("kex", SSH_KEX_ALGORITHMS, "curve25519-sha256"),
            ("kex", SSH_KEX_ALGORITHMS, "ecdh-sha2-nistp256"),
            ("kex", SSH_KEX_ALGORITHMS, "diffie-hellman-group14-sha256"),
            ("hostkey", SSH_HOSTKEY_ALGORITHMS, "ssh-ed25519"),
            ("hostkey", SSH_HOSTKEY_ALGORITHMS, "ecdsa-sha2-nistp256"),
            ("hostkey", SSH_HOSTKEY_ALGORITHMS, "rsa-sha2-256"),
            ("cipher", SSH_CIPHERS, "chacha20-poly1305@openssh.com"),
            ("cipher", SSH_CIPHERS, "aes256-gcm@openssh.com"),
            ("cipher", SSH_CIPHERS, "aes128-ctr"),
            ("mac", SSH_MACS, "hmac-sha2-256-etm@openssh.com"),
            ("mac", SSH_MACS, "hmac-sha2-256"),
        ] {
            assert!(list.contains(&want), "{cat}: {want} missing");
        }
    }

    #[test]
    fn ssh_policy_installs_on_a_session() {
        let s = ssh2::Session::new().unwrap();
        apply_fixed_algorithm_policy(&s).unwrap();
        let hostkeys = hostkey_preference(&[], SSH_HOSTKEY_ALGORITHMS);
        set_algorithm_pref(&s, ssh2::MethodType::HostKey, "host key", &hostkeys).unwrap();
    }

    #[test]
    fn ssh_policy_failure_is_an_error() {
        let s = ssh2::Session::new().unwrap();
        let e = set_algorithm_pref(&s, ssh2::MethodType::CryptCs, "cipher", "no-such-cipher")
            .unwrap_err();
        assert_eq!(e.kind, crate::error::ErrorKind::Connect);
        assert!(
            e.message
                .contains("cannot apply the SSH cipher algorithm policy"),
            "{}",
            e.message
        );
    }

    #[test]
    fn revoked_marker_lines_are_collected() {
        let text = "# c\n@revoked * ssh-ed25519 AAAAREVOKED c\nh ssh-ed25519 AAAAOK\n@cert-authority * ssh-rsa AAAACA\n";
        assert_eq!(revoked_keys(text), vec!["AAAAREVOKED".to_string()]);
        assert!(revoked_keys("h ssh-ed25519 AAAA\n").is_empty());
    }

    #[test]
    fn auth_failure_message_never_names_agent_socket() {
        let a = AuthAttempts {
            agent: Some("agent: 3 key(s) offered".to_string()),
            files: vec!["/home/u/.ssh/id_rsa".to_string()],
        };
        let d = a.describe();
        assert!(d.contains("3 key(s) offered"));
        assert!(d.contains("/home/u/.ssh/id_rsa"));
        assert!(d.contains("ssh-agent"));
        assert!(!d.contains("SSH_AUTH_SOCK"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_is_exact() {
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote("$(rm)"), "'$(rm)'");
        assert_eq!(shell_quote("a;b"), "'a;b'");
        assert_eq!(shell_quote("-x"), "'-x'");
        assert_eq!(shell_quote("μ"), "'μ'");
    }

    #[test]
    fn remote_command_contains_quoted_argv() {
        let req = ExecRequest::new("/usr/bin/printf")
            .arg("%s")
            .arg("a b")
            .arg("$(x)");
        let line = build_remote_command(&req, false, "/home/u");
        assert!(line.contains("'/usr/bin/printf'"));
        assert!(line.contains("'a b'"));
        assert!(line.contains("'$(x)'"));
    }
}

#[cfg(test)]
mod stats_tests {
    use super::*;

    fn out(completion: Completion) -> Output {
        Output {
            completion,
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        }
    }

    #[test]
    fn outcomes_programs_scopes_and_order_are_recorded() {
        let h = ExecStatsHandle::default();
        let d = Duration::from_millis(3);
        h.note(
            &ExecRequest::new("/usr/bin/stat"),
            false,
            d,
            Some(&out(Completion::Exited(0))),
        );
        h.set_scope("file");
        h.note(
            &ExecRequest::new("/usr/bin/getent"),
            true,
            d,
            Some(&out(Completion::Exited(2))),
        );
        h.note(
            &ExecRequest::new("/bin/dd"),
            true,
            d,
            Some(&out(Completion::Signaled(9))),
        );
        h.note(
            &ExecRequest::new("/usr/bin/sha256sum"),
            true,
            d,
            Some(&out(Completion::Indeterminate {
                started: true,
                reason: "timed out".into(),
            })),
        );
        h.note(&ExecRequest::new("/usr/bin/id"), false, d, None);
        let s = h.snapshot();
        assert_eq!(s.total(), 5);
        let programs: Vec<&str> = s.commands.iter().map(|c| c.program.as_str()).collect();
        assert_eq!(programs, ["stat", "getent", "dd", "sha256sum", "id"]);
        let outcomes: Vec<CommandOutcome> = s.commands.iter().map(|c| c.outcome).collect();
        assert_eq!(
            outcomes,
            [
                CommandOutcome::Success,
                CommandOutcome::NonZeroExit,
                CommandOutcome::Signaled,
                CommandOutcome::Indeterminate,
                CommandOutcome::TransportError,
            ]
        );
        assert_eq!(s.count_scope("setup"), 1);
        assert_eq!(s.count_scope("file"), 4);
        assert_eq!(s.sudo_commands(), 3);
        assert_eq!(s.not_successful(), 4);
        assert_eq!(s.elapsed(), d * 5);
        assert_eq!(s.count_program("getent"), 1);
    }

    #[test]
    fn a_sensitive_request_keeps_no_program_name() {
        let h = ExecStatsHandle::default();
        let mut req = ExecRequest::new("/opt/SECRET-PROGRAM-NAME");
        req.args = vec!["SECRET-ARG".to_string()];
        req.stdin = Some(b"SECRET-STDIN".to_vec());
        req.env.insert("K".into(), "SECRET-ENV".into());
        req.sensitive = true;
        h.note(
            &req,
            false,
            Duration::ZERO,
            Some(&out(Completion::Exited(0))),
        );
        let shown = format!("{:?}", h.snapshot());
        assert!(!shown.contains("SECRET"), "{shown}");
        assert_eq!(h.snapshot().commands[0].program, "[redacted]");
    }

    #[test]
    fn a_clone_shares_the_same_statistics() {
        let h = ExecStatsHandle::default();
        let c = h.clone();
        c.note(&ExecRequest::new("/bin/true"), false, Duration::ZERO, None);
        assert_eq!(h.snapshot().total(), 1);
    }

    #[test]
    fn the_connect_lookup_is_counted_without_a_request() {
        let h = ExecStatsHandle::default();
        h.note_connect("getent", Duration::from_millis(1), true);
        let s = h.snapshot();
        assert_eq!(
            (
                s.total(),
                s.count_scope("connect"),
                s.count_program("getent")
            ),
            (1, 1, 1)
        );
    }
}
