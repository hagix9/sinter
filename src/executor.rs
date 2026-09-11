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
        let rec = CommandRecord {
            program: req.program.clone(),
            args: req.args.clone(),
            sudo,
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
                Err(_) => break,
            }
        }
    }
    (buf, truncated)
}

// ---------------------------------------------------------------------------
// SSH execution
// ---------------------------------------------------------------------------

pub struct SshExecutor {
    pub sudo: bool,
    session: ssh2::Session,
    pub home: String,
    pub log: Vec<CommandRecord>,
}

impl SshExecutor {
    pub fn connect(cfg: &SshConfig, sudo: bool) -> Result<Self> {
        let addr = format!("{}:{}", cfg.host, cfg.port);
        let tcp = std::net::TcpStream::connect(&addr)
            .map_err(|e| SinterError::connect(format!("cannot connect to {}: {}", addr, e)))?;
        tcp.set_read_timeout(Some(Duration::from_secs(600))).ok();
        tcp.set_write_timeout(Some(Duration::from_secs(600))).ok();
        let mut session = ssh2::Session::new()
            .map_err(|e| SinterError::connect(format!("cannot create SSH session: {}", e)))?;
        session.set_tcp_stream(tcp);
        session.handshake().map_err(|e| {
            SinterError::connect(format!("SSH handshake with {} failed: {}", addr, e))
        })?;

        verify_host_key(&session, cfg)?;

        session.set_timeout(300_000);
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
            detect_home(&session, &cfg.user)?
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
        let mut channel = self
            .session
            .channel_session()
            .map_err(|e| SinterError::apply(format!("cannot open SSH channel: {}", e)))?;
        channel
            .handle_extended_data(ssh2::ExtendedData::Normal)
            .ok();
        channel
            .exec(&line)
            .map_err(|e| SinterError::apply(format!("cannot execute remote command: {}", e)))?;

        let mut out = Vec::new();
        let mut err = Vec::new();
        let mut out_trunc = false;
        let mut err_trunc = false;
        let mut stdout_eof = false;
        let mut stderr_eof = false;
        let mut stdin = req.stdin.clone();

        self.session.set_blocking(false);

        let result: Result<()> = (|| {
            while !(stdout_eof && stderr_eof) {
                let mut progressed = false;
                if !stdout_eof {
                    match drain_stream(&mut channel, &mut out, &mut out_trunc, MAX_CAPTURE) {
                        Ok(0) => {
                            stdout_eof = true;
                            progressed = true;
                        }
                        Ok(_) => progressed = true,
                        Err(StreamErr::WouldBlock) => {}
                        Err(StreamErr::Other(e)) => {
                            // A read failure after the remote process was
                            // dispatched may mean the connection dropped before
                            // completion: completion is indeterminate, never a
                            // clean failure.
                            return Err(SinterError::indeterminate(format!(
                                "SSH stdout read failed after dispatch: {}",
                                e
                            )));
                        }
                    }
                }
                if !stderr_eof {
                    let mut st = channel.stderr();
                    match drain_stream(&mut st, &mut err, &mut err_trunc, MAX_CAPTURE) {
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

                if !stdout_eof || !stderr_eof {
                    if let Some(data) = stdin.take() {
                        write_all_nonblocking(&mut channel, &data, deadline).map_err(|e| {
                            SinterError::indeterminate(format!(
                                "SSH stdin write failed after dispatch: {}",
                                e
                            ))
                        })?;
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
                    wait_readable(self.session.as_raw_fd(), Duration::from_millis(200));
                }
            }
            Ok(())
        })();

        if let Err(e) = result {
            if e.kind == crate::error::ErrorKind::Indeterminate {
                let _ = channel.close();
                self.session.set_blocking(true);
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
        // A blocking `wait_close` could otherwise hang indefinitely if the
        // remote side keeps the channel open.
        self.session.set_blocking(false);
        let mut close_confirmed = false;
        while Instant::now() < deadline {
            match channel.wait_close() {
                Ok(()) => {
                    close_confirmed = true;
                    break;
                }
                Err(e) if e.code() == ssh2::ErrorCode::Session(-37) => {
                    // LIBSSH2_ERROR_EAGAIN: not ready yet; keep waiting.
                    wait_readable(self.session.as_raw_fd(), Duration::from_millis(50));
                }
                Err(_) => break,
            }
        }
        self.session.set_blocking(true);

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
            let c = match channel.exit_signal() {
                Ok(sig) => match sig.exit_signal.as_deref().and_then(parse_signal) {
                    Some(n) => Completion::Signaled(n),
                    None => match channel.exit_status() {
                        Ok(code) => Completion::Exited(code),
                        Err(e) => Completion::Indeterminate {
                            started: true,
                            reason: format!("remote exit status unavailable: {}", e),
                        },
                    },
                },
                Err(_) => match channel.exit_status() {
                    Ok(code) => Completion::Exited(code),
                    Err(e) => Completion::Indeterminate {
                        started: true,
                        reason: format!("remote exit status unavailable: {}", e),
                    },
                },
            };
            (c, None)
        };

        Ok(Output {
            completion,
            stdout: out,
            stderr: err,
            stdout_truncated: out_trunc,
            stderr_truncated: err_trunc,
        })
    }
}

fn detect_home(session: &ssh2::Session, user: &str) -> Result<String> {
    // Resolve via the account database without relying on inherited HOME.
    let mut ch = session
        .channel_session()
        .map_err(|e| SinterError::connect(format!("cannot open SSH channel: {}", e)))?;
    let cmd = format!("getent passwd {}", shell_quote(user));
    ch.exec(&cmd)
        .map_err(|e| SinterError::connect(format!("cannot query account database: {}", e)))?;
    let mut s = String::new();
    let _ = ch.read_to_string(&mut s);
    let _ = ch.wait_close();
    if ch.exit_status().map(|c| c == 0).unwrap_or(false) {
        let fields: Vec<&str> = s.trim().split(':').collect();
        if fields.len() >= 6 && !fields[5].is_empty() {
            return Ok(fields[5].to_string());
        }
    }
    Err(SinterError::connect(format!(
        "could not resolve home directory for target user {}",
        user
    )))
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
) -> std::result::Result<usize, StreamErr> {
    let mut total = 0;
    let mut tmp = [0u8; 8192];
    loop {
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
    let _ = channel.flush();
    let _ = channel.send_eof();
    Ok(())
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
