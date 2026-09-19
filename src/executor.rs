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
    /// Environment passed to the target process. Sensitive requests retain
    /// only a redacted marker, just like program and argv.
    pub env: BTreeMap<String, String>,
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
        // Incremental stdin state for full-duplex progress. Writing all stdin
        // before draining can deadlock once the SSH channel window fills
        // (e.g. large payload to /bin/cat).
        let stdin_data = req.stdin.clone();
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

    // OpenSSH identity (DESIGN §19): default port uses `host`; non-default
    // port uses `[host]:port` only. A portless host entry must not authorize
    // a non-default-port connection. Identity-scoped matching prevents a
    // conflicting explicit entry from being bypassed by another host form.
    let identity = if cfg.port == 22 {
        cfg.host.clone()
    } else {
        format!("[{}]:{}", cfg.host, cfg.port)
    };
    let presented = crate::targetfs::b64_encode(key);
    let entries = known
        .iter()
        .map_err(|e| SinterError::connect(format!("cannot enumerate known hosts: {}", e)))?;

    let mut saw_identity = false;
    let mut identity_match = false;
    for h in &entries {
        let Some(name) = h.name() else { continue };
        if name != identity {
            continue;
        }
        saw_identity = true;
        if h.key() == presented {
            identity_match = true;
            break;
        }
    }
    if saw_identity {
        if identity_match {
            return Ok(());
        }
        return Err(SinterError::connect(format!(
            "SSH host key mismatch for {} (possible man-in-the-middle)",
            identity
        )));
    }

    // No entry for the required identity. For non-default ports a portless
    // `host` entry is a different identity and must not authorize the
    // connection (DESIGN §19).
    Err(SinterError::connect(format!(
        "SSH host key for {} is not present in {}; enrollment is not automatic",
        identity,
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
    /// When set, `repoquery --location` resolves no payload URLs — the
    /// transaction payload set cannot be satisfied from the local cache.
    pub dnf_no_locations: bool,
    /// Overrides the `dnf repolist -v` output, so tests can model truncated or
    /// malformed repository enumeration (R2-03).
    pub dnf_repolist_output: Option<Output>,
    /// Overrides the cache-only `dnf install --assumeno` transaction table,
    /// so tests can model truncated, malformed, or ambiguous transactions
    /// (R2-03/R2-04).
    pub dnf_dry_run_output: Option<Output>,
    /// Overrides the `repoquery --location` output, so tests can model
    /// duplicate or ambiguous payload URLs (R2-04).
    pub dnf_location_output: Option<Output>,
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
            dnf_no_locations: false,
            dnf_repolist_output: None,
            dnf_dry_run_output: None,
            dnf_location_output: None,
            snapshot_listing: None,
            live_cache_find_output: None,
            mktemp_output: None,
            snapshot_mode: "700".to_string(),
            snapshot_mode_after_copy: None,
            snapshot_chmod_fails: false,
            snapshot_stat_fails: false,
            snapshot_rm_fails: false,
            observation_overrides: Default::default(),
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
            dnf_no_locations: false,
            dnf_repolist_output: None,
            dnf_dry_run_output: None,
            dnf_location_output: None,
            snapshot_listing: None,
            live_cache_find_output: None,
            mktemp_output: None,
            snapshot_mode: "700".to_string(),
            snapshot_mode_after_copy: None,
            snapshot_chmod_fails: false,
            snapshot_stat_fails: false,
            snapshot_rm_fails: false,
            observation_overrides: Default::default(),
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
            dnf_no_locations: false,
            dnf_repolist_output: None,
            dnf_dry_run_output: None,
            dnf_location_output: None,
            snapshot_listing: None,
            live_cache_find_output: None,
            mktemp_output: None,
            snapshot_mode: "700".to_string(),
            snapshot_mode_after_copy: None,
            snapshot_chmod_fails: false,
            snapshot_stat_fails: false,
            snapshot_rm_fails: false,
            observation_overrides: Default::default(),
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
            dnf_no_locations: false,
            dnf_repolist_output: None,
            dnf_dry_run_output: None,
            dnf_location_output: None,
            snapshot_listing: None,
            live_cache_find_output: None,
            mktemp_output: None,
            snapshot_mode: "700".to_string(),
            snapshot_mode_after_copy: None,
            snapshot_chmod_fails: false,
            snapshot_stat_fails: false,
            snapshot_rm_fails: false,
            observation_overrides: Default::default(),
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
            dnf_no_locations: false,
            dnf_repolist_output: None,
            dnf_dry_run_output: None,
            dnf_location_output: None,
            snapshot_listing: None,
            live_cache_find_output: None,
            mktemp_output: None,
            snapshot_mode: "700".to_string(),
            snapshot_mode_after_copy: None,
            snapshot_chmod_fails: false,
            snapshot_stat_fails: false,
            snapshot_rm_fails: false,
            observation_overrides: Default::default(),
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
        match prog.as_str() {
            "test" => self.run_test(&req.args),
            "hostname" => Self::exited(0, format!("{}\n", self.target.hostname), String::new()),
            "cat" => self.run_cat(&req.args),
            "uname" => Self::exited(0, format!("{}\n", self.target.arch), String::new()),
            "id" => self.run_id(&req.args),
            "getent" => self.run_getent(&req.args),
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
        let db = args.first().map(|s| s.as_str()).unwrap_or("");
        let key = args.get(1).map(|s| s.as_str()).unwrap_or("");
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
                Self::exited(2, String::new(), String::new())
            }
            "group" => {
                let gid = if self.sudo { 0 } else { self.target.gid };
                if key == "root" || key == "0" {
                    return Self::exited(0, "root:x:0:\n".to_string(), String::new());
                }
                if key == gid.to_string() || key == "fakegroup" {
                    return Self::exited(0, format!("fakegroup:x:{}:\n", gid), String::new());
                }
                Self::exited(2, String::new(), String::new())
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
            // `repoquery --location`: payload URLs composed from the cached
            // mirror lists — one per name argument. An explicit override
            // wins so tests can model duplicate/ambiguous URLs.
            if args.iter().any(|a| a == "--location") {
                if let Some(o) = self.target.dnf_location_output.clone() {
                    return o;
                }
                let repoid = self
                    .target
                    .dnf_repos
                    .first()
                    .map(|r| r.id.clone())
                    .unwrap_or_else(|| "baseos".to_string());
                let mut out = String::new();
                if !self.target.dnf_no_locations {
                    for a in args
                        .iter()
                        .skip_while(|x| x.as_str() != "--location")
                        .skip(1)
                    {
                        out.push_str(&format!(
                            "https://mirror.example/{}/Packages/{}-1.0-1.el9.x86_64.rpm\n",
                            repoid, a
                        ));
                    }
                }
                // repoquery redirects INFO to stderr: a successful answer
                // carries the native metadata-age line there (R5-F04).
                return Self::exited(
                    0,
                    out,
                    "Last metadata expiration check: 0:30:00 ago on Wed Sep 16 10:28:01 2026.\n"
                        .to_string(),
                );
            }
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

    fn run_systemctl(&mut self, args: &[String]) -> Output {
        let verb = args.first().map(|s| s.as_str()).unwrap_or("");
        if verb == "show" {
            let name = args.get(1).cloned().unwrap_or_default();
            return match self.target.services.get(&name) {
                Some((load, active, unitfile)) => Self::exited(
                    0,
                    format!(
                        "LoadState={}\nActiveState={}\nUnitFileState={}\n",
                        load, active, unitfile
                    ),
                    String::new(),
                ),
                None => Self::exited(
                    0,
                    "LoadState=not-found\nActiveState=inactive\nUnitFileState=\n".to_string(),
                    String::new(),
                ),
            };
        }
        let name = args.get(1).cloned().unwrap_or_default();
        let Some(entry) = self.target.services.get_mut(&name) else {
            return Self::exited(1, String::new(), format!("Unit {} not found", name));
        };
        match verb {
            "start" | "restart" => entry.1 = "active".to_string(),
            "stop" => entry.1 = "inactive".to_string(),
            "reset-failed" => {
                if entry.1 == "failed" {
                    entry.1 = "inactive".to_string();
                }
            }
            "enable" => entry.2 = "enabled".to_string(),
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
        Self::exited(0, String::new(), String::new())
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
