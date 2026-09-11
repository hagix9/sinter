use crate::error::{Result, SinterError};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub const MAX_CAPTURE: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ExecRequest {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Option<String>,
    pub env: BTreeMap<String, String>,
    pub stdin: Option<Vec<u8>>,
    pub timeout_secs: u64,
    /// When true, the command line (program/args/cwd/env values) may contain
    /// sensitive material. Internal audit records must never store the raw form.
    pub sensitive: bool,
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
    pub sudo: bool,
    /// True when the recorded invocation may carry sensitive values. The stored
    /// program/args are then a redacted placeholder, never the raw command line.
    pub sensitive: bool,
}

pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub known_hosts: PathBuf,
    pub identity_files: Vec<PathBuf>,
}

pub enum Executor {
    Local(LocalExecutor),
    Ssh(SshExecutor),
}

impl Executor {
    pub fn is_sudo(&self) -> bool {
        match self {
            Executor::Local(l) => l.sudo,
            Executor::Ssh(s) => s.sudo,
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
        }
    }

    /// The full audit log of raw command invocations performed by this executor.
    /// This is an internal facility used to verify that plan performs no
    /// mutation operations.
    pub fn log(&self) -> Vec<CommandRecord> {
        match self {
            Executor::Local(l) => l.log.clone(),
            Executor::Ssh(s) => s.log.clone(),
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
                sudo,
                sensitive: true,
            }
        } else {
            CommandRecord {
                program: req.program.clone(),
                args: req.args.clone(),
                sudo,
                sensitive: false,
            }
        };
        match self {
            Executor::Local(l) => l.log.push(rec),
            Executor::Ssh(s) => s.log.push(rec),
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
        })
    }

    fn run(&mut self, req: &ExecRequest) -> Result<Output> {
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
                let data = input.clone();
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

        // Host-key identity is always the originally requested host string,
        // never a resolved IP (SSH known_hosts semantics).
        verify_host_key(&session, cfg)?;

        let auth_timeout = setup_remaining(setup_deadline)?;
        session.set_timeout(auth_timeout.as_millis().clamp(1, u32::MAX as u128) as u32);
        let mut authed = false;
        if session.userauth_agent(&cfg.user).is_ok() && session.authenticated() {
            authed = true;
        }
        if !authed {
            let mut identities = cfg.identity_files.clone();
            if identities.is_empty() {
                if let Some(home) = std::env::var_os("HOME") {
                    let h = PathBuf::from(home);
                    identities.push(h.join(".ssh/id_ed25519"));
                    identities.push(h.join(".ssh/id_rsa"));
                }
            }
            for id in &identities {
                let auth_timeout = setup_remaining(setup_deadline)?;
                session.set_timeout(auth_timeout.as_millis().clamp(1, u32::MAX as u128) as u32);
                if id.exists()
                    && session
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
                "SSH authentication failed for {}@{}",
                cfg.user, cfg.host
            )));
        }

        let home = if sudo {
            "/root".to_string()
        } else {
            detect_home(&session, &cfg.user, setup_deadline)?
        };

        Ok(SshExecutor {
            sudo,
            session,
            home,
            log: Vec::new(),
        })
    }

    fn run(&mut self, req: &ExecRequest) -> Result<Output> {
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
        let mut stdin = req.stdin.clone();
        let mut stdin_closed = false;

        let result: Result<()> = (|| {
            while !(stdout_eof && stderr_eof) {
                if Instant::now() >= deadline {
                    return Err(SinterError::indeterminate(format!(
                        "remote command timed out after {}s after dispatch",
                        req.timeout_secs
                    )));
                }
                let mut progressed = false;
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

                // Always terminate stdin exactly once after dispatch, matching
                // local `/dev/null` semantics so commands waiting on EOF (e.g.
                // `/bin/cat`) can exit. EOF is also bounded by the deadline.
                if !stdin_closed {
                    match stdin.take() {
                        Some(data) => {
                            write_all_nonblocking(&mut channel, &data, deadline).map_err(|e| {
                                SinterError::indeterminate(format!(
                                    "SSH stdin write failed after dispatch: {}",
                                    e
                                ))
                            })?;
                            stdin_closed = true;
                            progressed = true;
                        }
                        None => {
                            flush_and_eof(&mut channel, deadline).map_err(|e| {
                                SinterError::indeterminate(format!(
                                    "SSH stdin EOF failed after dispatch: {}",
                                    e
                                ))
                            })?;
                            stdin_closed = true;
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

fn write_all_nonblocking(
    channel: &mut ssh2::Channel,
    data: &[u8],
    deadline: Instant,
) -> std::io::Result<()> {
    let mut off = 0;
    while off < data.len() {
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "SSH operation deadline exceeded",
            ));
        }
        match channel.write(&data[off..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "wrote zero bytes",
                ))
            }
            Ok(n) => off += n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "SSH operation deadline exceeded",
                    ));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(e),
        }
    }
    flush_and_eof(channel, deadline)
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

fn verify_host_key(session: &ssh2::Session, cfg: &SshConfig) -> Result<()> {
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
    let (key, _key_type) = session
        .host_key()
        .ok_or_else(|| SinterError::connect("server did not present a host key"))?;
    let r1 = known.check_port(&cfg.host, cfg.port, key);
    let r2 = known.check(&cfg.host, key);

    // Only an explicit successful Match may authorize the connection. Mismatch,
    // NotFound, and API Failure all fail closed; there is no insecure fallback.
    let matched = matches!(r1, ssh2::CheckResult::Match) || matches!(r2, ssh2::CheckResult::Match);
    if matched {
        return Ok(());
    }
    if matches!(r1, ssh2::CheckResult::Mismatch) || matches!(r2, ssh2::CheckResult::Mismatch) {
        return Err(SinterError::connect(format!(
            "SSH host key mismatch for {} (possible man-in-the-middle)",
            cfg.host
        )));
    }
    if matches!(r1, ssh2::CheckResult::Failure) || matches!(r2, ssh2::CheckResult::Failure) {
        return Err(SinterError::connect(format!(
            "SSH host key verification failed for {} (known_hosts check could not be completed)",
            cfg.host
        )));
    }
    Err(SinterError::connect(format!(
        "SSH host key for {} is not present in {}; enrollment is not automatic",
        cfg.host,
        cfg.known_hosts.display()
    )))
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
