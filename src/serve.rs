//! `sinter serve` (ADR 0002 §6, Option B): a thin foreground launcher for one
//! official OpenAI `tunnel-client` process, which starts `sinter mcp` as its
//! stdio child.
//!
//! It is not a web server, a supervisor or a daemon. It opens no listener, has
//! no HTTP client, implements no part of the tunnel protocol and restarts
//! nothing. What it adds to running the official client directly:
//!
//! * fail-closed checks of its own inputs before anything starts (§6.3), with
//!   no network traffic and without ever reading the runtime key's content;
//! * a cleared environment for the client with an allowlist only (§6.4), so
//!   neither the client nor its `sinter mcp` child carries an OpenAI key in its
//!   environment, and the client cannot fall back to `OPENAI_API_KEY`;
//! * passing SIGINT/SIGTERM/SIGHUP and an optional time limit on to the client
//!   as SIGTERM, with SIGKILL after 10 seconds (§6.6);
//! * on Linux, `PR_SET_PDEATHSIG(SIGTERM)` for the client, so that the client
//!   is asked to stop when `serve` dies without running its stop routine.
//!
//! The read-only MCP surface is unchanged: the client runs the same
//! `sinter mcp [--targets-file <path>]` an administrator would run by hand.

use crate::error::SinterError;
use serde::Deserialize;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Exit code: stopped on request or at the time limit.
pub const EXIT_STOPPED: u8 = 0;
/// Exit code: the configuration or an input it names is invalid (nothing started).
pub const EXIT_CONFIG: u8 = 2;
/// Exit code: `tunnel-client` could not be started, or exited without being asked to.
pub const EXIT_CLIENT: u8 = 3;

/// How long `serve` waits for `tunnel-client` after SIGTERM before SIGKILL.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(10);
/// Upper bound of `--max-duration`.
pub const MAX_DURATION_LIMIT: Duration = Duration::from_secs(30 * 24 * 3600);
/// Upper bound of the configuration file size.
const CONFIG_MAX_BYTES: u64 = 64 * 1024;
/// Upper bound of the runtime key file size (the content is never read).
const KEY_MAX_BYTES: u64 = 4096;
/// Upper bound of the tunnel ID length (the exact form is the client's business).
const TUNNEL_ID_MAX: usize = 128;

/// Environment variables passed to `tunnel-client` (and by it to `sinter mcp`).
/// Everything else is removed: notably `OPENAI_API_KEY`, `OPENAI_ADMIN_KEY`
/// and `CONTROL_PLANE_API_KEY` (key fallbacks), `TUNNEL_CLIENT_CONFIG` and
/// `TUNNEL_CLIENT_PROFILE*` (a configuration file that could override the
/// arguments), `CONTROL_PLANE_AWS_*` (another credential path) and
/// `MCP_STDIO_FAILURE_POLICY`. `LC_*` is matched by prefix. The two network
/// variables `TUNNEL_CLIENT_HTTP_PROXY` and `CONTROL_PLANE_RESIDENCY` are
/// documented client settings added after v0.0.16 (read at v0.0.21).
pub const ENV_ALLOWLIST: &[&str] = &[
    "TUNNEL_CLIENT_HTTP_PROXY",
    "CONTROL_PLANE_RESIDENCY",
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "TMPDIR",
    "SSH_AUTH_SOCK",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "https_proxy",
    "http_proxy",
    "no_proxy",
    "CONTROL_PLANE_HTTP_PROXY",
    "CA_BUNDLE",
];

/// A validated `serve` configuration (ADR 0002 §6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeConfig {
    pub tunnel_id: String,
    pub api_key_file: PathBuf,
    pub client: PathBuf,
    pub targets_file: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    tunnel: TunnelSection,
    #[serde(default)]
    mcp: McpSection,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TunnelSection {
    id: String,
    api_key_file: PathBuf,
    client: PathBuf,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct McpSection {
    targets_file: Option<PathBuf>,
}

fn invalid(msg: impl Into<String>) -> SinterError {
    SinterError::schema(format!("serve: {}", msg.into()))
}

/// The default configuration path: `$XDG_CONFIG_HOME/sinter/serve.toml` when
/// `XDG_CONFIG_HOME` is an absolute path, else `$HOME/.config/sinter/serve.toml`
/// (the rule of the default identity path of `sinter secrets`).
pub fn default_config_path(
    xdg_config_home: Option<OsString>,
    home: Option<OsString>,
) -> Result<PathBuf, SinterError> {
    if let Some(x) = xdg_config_home.map(PathBuf::from) {
        if x.is_absolute() {
            return Ok(x.join("sinter").join("serve.toml"));
        }
    }
    match home.map(PathBuf::from) {
        Some(h) if h.is_absolute() => Ok(h.join(".config").join("sinter").join("serve.toml")),
        _ => Err(invalid(
            "no --config given and neither XDG_CONFIG_HOME nor HOME is an absolute path",
        )),
    }
}

/// Parse `--max-duration`: one or more `<digits><unit>` parts with units `h`,
/// `m` and `s` (for example `90s`, `30m`, `1h`, `1h30m`); at least one second,
/// at most 30 days.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let bad = || {
        format!(
            "invalid duration {s:?}: use e.g. 90s, 30m, 1h or 1h30m (at least 1s, at most 720h)"
        )
    };
    if s.is_empty() || s.len() > 32 {
        return Err(bad());
    }
    let mut total: u64 = 0;
    let mut digits = String::new();
    let mut seen_unit = false;
    for c in s.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        let mult = match c {
            'h' => 3600,
            'm' => 60,
            's' => 1,
            _ => return Err(bad()),
        };
        if digits.is_empty() {
            return Err(bad());
        }
        let n: u64 = digits.parse().map_err(|_| bad())?;
        total = n
            .checked_mul(mult)
            .and_then(|v| total.checked_add(v))
            .ok_or_else(bad)?;
        digits.clear();
        seen_unit = true;
    }
    if !digits.is_empty() || !seen_unit {
        return Err(bad());
    }
    let d = Duration::from_secs(total);
    if d < Duration::from_secs(1) || d > MAX_DURATION_LIMIT {
        return Err(bad());
    }
    Ok(d)
}

/// The tunnel ID is checked only loosely (ADR 0002 §6.3 item 1): it starts
/// with `tunnel_` and contains only lowercase ASCII letters, digits and `_`.
/// The exact form is left to `tunnel-client`, which rejects an invalid ID.
pub fn tunnel_id_is_wellformed(id: &str) -> bool {
    id.len() > "tunnel_".len()
        && id.len() <= TUNNEL_ID_MAX
        && id.starts_with("tunnel_")
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// A path placed into `--mcp.command`, which `tunnel-client` splits with
/// shell-like rules, must consist of characters that no such rule treats
/// specially. Stricter than ADR 0002 §6.3 item 5 (which names whitespace,
/// quotes and backslashes): only ASCII letters, digits and `/ . _ - + , @ = :`.
pub fn path_is_command_safe(p: &Path) -> bool {
    let Some(s) = p.to_str() else { return false };
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'/' | b'.' | b'_' | b'-' | b'+' | b',' | b'@' | b'=' | b':'
                )
        })
}

/// Read and validate the configuration file (ADR 0002 §6.2, §6.3 item 1).
/// Error messages never repeat a value from the file: a value in the wrong
/// place could be a key that was pasted by mistake.
pub fn load_config(path: &Path) -> Result<ServeConfig, SinterError> {
    let meta = std::fs::metadata(path).map_err(|e| {
        invalid(format!(
            "cannot read configuration file {}: {e}",
            path.display()
        ))
    })?;
    if !meta.is_file() {
        return Err(invalid(format!(
            "configuration file {} is not a regular file",
            path.display()
        )));
    }
    if meta.len() > CONFIG_MAX_BYTES {
        return Err(invalid(format!(
            "configuration file {} is larger than {} bytes",
            path.display(),
            CONFIG_MAX_BYTES
        )));
    }
    let text = std::fs::read_to_string(path).map_err(|e| {
        invalid(format!(
            "cannot read configuration file {}: {e}",
            path.display()
        ))
    })?;
    parse_config(&text).map_err(|m| invalid(format!("configuration file {}: {m}", path.display())))
}

/// Parse configuration text. Returned messages contain field names and line
/// numbers only, never values.
pub fn parse_config(text: &str) -> Result<ServeConfig, String> {
    let raw: FileConfig = toml::from_str(text).map_err(|e| describe_toml_error(text, &e))?;
    let t = raw.tunnel;
    if !tunnel_id_is_wellformed(&t.id) {
        return Err(format!(
            "tunnel.id must start with \"tunnel_\" and contain only a-z, 0-9 and _ (at most {TUNNEL_ID_MAX} characters)"
        ));
    }
    for (name, p) in [
        ("tunnel.api_key_file", &t.api_key_file),
        ("tunnel.client", &t.client),
    ] {
        if !p.is_absolute() {
            return Err(format!("{name} must be an absolute path"));
        }
    }
    if let Some(p) = &raw.mcp.targets_file {
        if !p.is_absolute() {
            return Err("mcp.targets_file must be an absolute path".into());
        }
    }
    Ok(ServeConfig {
        tunnel_id: t.id,
        api_key_file: t.api_key_file,
        client: t.client,
        targets_file: raw.mcp.targets_file,
    })
}

fn describe_toml_error(text: &str, e: &toml::de::Error) -> String {
    let line = e
        .span()
        .map(|s| text.get(..s.start).unwrap_or(text).matches('\n').count() + 1);
    let msg = e.message();
    // Field names are safe to show; anything else may quote a value.
    let what = if let Some(rest) = msg.strip_prefix("unknown field `") {
        let field: String = rest.chars().take_while(|c| *c != '`').collect();
        // A key name is shown only if it looks like a configuration name
        // (lowercase, digits and `_`, at most 40 characters): a pasted key,
        // used by mistake as a key or table name, is never repeated.
        let plausible = !field.is_empty()
            && field.len() <= 40
            && field.starts_with(|c: char| c.is_ascii_lowercase())
            && field
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        if plausible {
            format!("unknown key \"{field}\" (allowed: [tunnel] id, api_key_file, client; [mcp] targets_file)")
        } else {
            "unknown key (its name is not shown) (allowed: [tunnel] id, api_key_file, client; [mcp] targets_file)".to_string()
        }
    } else if let Some(rest) = msg.strip_prefix("missing field `") {
        let field: String = rest.chars().take_while(|c| *c != '`').collect();
        format!("missing key \"{field}\"")
    } else {
        "invalid TOML or a value of the wrong type".to_string()
    };
    match line {
        Some(l) => format!("{what} (line {l})"),
        None => what,
    }
}

#[cfg(unix)]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o7777
}

/// Check the runtime key file without reading its content (ADR 0002 §6.3
/// item 2): a regular file (not a symbolic link), non-empty, at most 4096
/// bytes, owned by the user running `serve`, with no group or other
/// permission bits, and readable.
#[cfg(unix)]
pub fn check_key_file(p: &Path) -> Result<(), SinterError> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(p).map_err(|e| {
        invalid(format!(
            "cannot use tunnel.api_key_file {}: {e}",
            p.display()
        ))
    })?;
    if meta.file_type().is_symlink() {
        return Err(invalid(format!(
            "tunnel.api_key_file {} is a symbolic link; name the file itself",
            p.display()
        )));
    }
    if !meta.is_file() {
        return Err(invalid(format!(
            "tunnel.api_key_file {} is not a regular file",
            p.display()
        )));
    }
    if meta.len() == 0 {
        return Err(invalid(format!(
            "tunnel.api_key_file {} is empty",
            p.display()
        )));
    }
    if meta.len() > KEY_MAX_BYTES {
        return Err(invalid(format!(
            "tunnel.api_key_file {} is larger than {} bytes",
            p.display(),
            KEY_MAX_BYTES
        )));
    }
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(invalid(format!(
            "tunnel.api_key_file {} is not owned by the user running sinter serve",
            p.display()
        )));
    }
    if mode_of(&meta) & 0o077 != 0 {
        return Err(invalid(format!(
            "tunnel.api_key_file {} has group or other permissions (mode {:04o}); use chmod 600",
            p.display(),
            mode_of(&meta)
        )));
    }
    // Opened only to prove it is readable; not a single byte is read.
    std::fs::File::open(p).map_err(|e| {
        invalid(format!(
            "cannot open tunnel.api_key_file {}: {e}",
            p.display()
        ))
    })?;
    Ok(())
}

/// `tunnel.client`: an executable regular file (a symbolic link to one is
/// accepted) that is not writable by group or others. `serve` never searches
/// `PATH` and never downloads the client.
#[cfg(unix)]
pub fn check_client(p: &Path) -> Result<(), SinterError> {
    let meta = std::fs::metadata(p)
        .map_err(|e| invalid(format!("cannot use tunnel.client {}: {e}", p.display())))?;
    if !meta.is_file() {
        return Err(invalid(format!(
            "tunnel.client {} is not a regular file",
            p.display()
        )));
    }
    let mode = mode_of(&meta);
    if mode & 0o111 == 0 {
        return Err(invalid(format!(
            "tunnel.client {} is not executable",
            p.display()
        )));
    }
    if mode & 0o022 != 0 {
        return Err(invalid(format!(
            "tunnel.client {} is writable by group or others (mode {:04o})",
            p.display(),
            mode
        )));
    }
    Ok(())
}

/// The `--mcp.command` value: `<sinter> mcp [--targets-file <path>]`.
pub fn mcp_command(sinter_exe: &Path, targets_file: Option<&Path>) -> Result<String, SinterError> {
    if !path_is_command_safe(sinter_exe) {
        return Err(invalid(format!(
            "the path of this sinter executable ({}) contains characters that cannot be passed safely in --mcp.command (allowed: A-Z a-z 0-9 / . _ - + , @ = :); install it under such a path",
            sinter_exe.display()
        )));
    }
    let mut cmd = format!("{} mcp", sinter_exe.display());
    if let Some(t) = targets_file {
        if !path_is_command_safe(t) {
            return Err(invalid(format!(
                "mcp.targets_file {} contains characters that cannot be passed safely in --mcp.command (allowed: A-Z a-z 0-9 / . _ - + , @ = :)",
                t.display()
            )));
        }
        cmd.push_str(" --targets-file ");
        cmd.push_str(&t.display().to_string());
    }
    Ok(cmd)
}

/// The arguments given to `tunnel-client` (ADR 0002 §6.4). The key travels
/// only as a `file:` reference.
pub fn client_args(cfg: &ServeConfig, mcp_command: &str) -> Vec<OsString> {
    let mut key_ref = OsString::from("file:");
    key_ref.push(cfg.api_key_file.as_os_str());
    vec![
        "run".into(),
        "--control-plane.tunnel-id".into(),
        cfg.tunnel_id.clone().into(),
        "--control-plane.api-key".into(),
        key_ref,
        "--mcp.command".into(),
        mcp_command.into(),
        "--health.listen-addr".into(),
        "127.0.0.1:0".into(),
    ]
}

/// The client's environment: the allowlisted variables of `vars`, nothing else.
pub fn client_env<I>(vars: I) -> Vec<(OsString, OsString)>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    let mut out: Vec<(OsString, OsString)> = vars
        .into_iter()
        .filter(|(k, _)| match k.to_str() {
            Some(k) => ENV_ALLOWLIST.contains(&k) || (k.starts_with("LC_") && k.len() > 3),
            None => false,
        })
        .collect();
    out.sort();
    out
}

/// Everything checked before the client starts (ADR 0002 §6.3). Returns the
/// `--mcp.command` value. Nothing is contacted and no process is started.
#[cfg(unix)]
pub fn preflight(cfg: &ServeConfig, sinter_exe: &Path) -> Result<String, SinterError> {
    check_key_file(&cfg.api_key_file)?;
    if let Some(t) = &cfg.targets_file {
        crate::targets::TargetRegistry::load(t)
            .map_err(|e| invalid(format!("mcp.targets_file: {}", e.message)))?;
    }
    check_client(&cfg.client)?;
    mcp_command(sinter_exe, cfg.targets_file.as_deref())
}

/// Why `serve` ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndReason {
    /// A signal asked `serve` to stop (its number).
    Signal(i32),
    /// `--max-duration` expired.
    TimeLimit,
    /// The client ended by itself with this wait status description.
    ClientExited(String),
}

/// The exit code for an end reason (ADR 0002 §6.1, §6.6 step 3): a client that
/// ends after a stop request counts as a requested stop.
pub fn exit_code_for(reason: &EndReason) -> u8 {
    match reason {
        EndReason::Signal(_) | EndReason::TimeLimit => EXIT_STOPPED,
        EndReason::ClientExited(_) => EXIT_CLIENT,
    }
}

pub fn signal_name(sig: i32) -> &'static str {
    match sig {
        libc::SIGINT => "SIGINT",
        libc::SIGTERM => "SIGTERM",
        libc::SIGHUP => "SIGHUP",
        _ => "signal",
    }
}

#[cfg(target_os = "linux")]
mod run_linux {
    use super::*;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::time::Instant;

    static STOP_SIGNAL: AtomicI32 = AtomicI32::new(0);

    extern "C" fn on_signal(sig: libc::c_int) {
        // Only an atomic store: async-signal-safe.
        let _ = STOP_SIGNAL.compare_exchange(0, sig, Ordering::SeqCst, Ordering::SeqCst);
    }

    fn install_handlers() -> std::io::Result<()> {
        // An inherited `SIGCHLD = SIG_IGN` would make the kernel reap the
        // client by itself, so that waiting fails and its PID could be reused
        // while serve still signals it. Restore the default first.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = libc::SIG_DFL;
            libc::sigemptyset(&mut sa.sa_mask);
            if libc::sigaction(libc::SIGCHLD, &sa, std::ptr::null_mut()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        for sig in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            unsafe {
                let mut sa: libc::sigaction = std::mem::zeroed();
                sa.sa_sigaction = on_signal as extern "C" fn(libc::c_int) as usize;
                sa.sa_flags = libc::SA_RESTART;
                libc::sigemptyset(&mut sa.sa_mask);
                if libc::sigaction(sig, &sa, std::ptr::null_mut()) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
        }
        Ok(())
    }

    fn describe(status: std::process::ExitStatus) -> String {
        match (status.code(), status.signal()) {
            (Some(c), _) => format!("exit status {c}"),
            (None, Some(s)) => format!("signal {s}"),
            _ => "unknown status".to_string(),
        }
    }

    pub fn run(cfg: &ServeConfig, mcp_command: &str, max: Option<Duration>) -> u8 {
        // Handlers first: a stop signal that arrives while the client is being
        // started is recorded and acted on as soon as the client runs.
        if let Err(e) = install_handlers() {
            eprintln!("sinter serve: cannot install signal handlers: {e}");
            return EXIT_CLIENT;
        }
        let parent = unsafe { libc::getpid() };
        let mut cmd = Command::new(&cfg.client);
        cmd.args(client_args(cfg, mcp_command))
            .env_clear()
            .envs(client_env(std::env::vars_os()))
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        // SAFETY: only async-signal-safe calls between fork and exec.
        unsafe {
            cmd.pre_exec(move || {
                if libc::prctl(
                    libc::PR_SET_PDEATHSIG,
                    libc::SIGTERM as libc::c_ulong,
                    0,
                    0,
                    0,
                ) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                // serve died between fork and prctl: the death signal was not
                // armed in time, so do not start an unsupervised client.
                if libc::getppid() != parent {
                    return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
                }
                Ok(())
            });
        }
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "sinter serve: cannot start tunnel-client {}: {e}; exit {EXIT_CLIENT}",
                    cfg.client.display()
                );
                return EXIT_CLIENT;
            }
        };
        let pid = child.id() as libc::pid_t;
        let started = Instant::now();
        let deadline = max.map(|d| started + d);
        match max {
            Some(d) => eprintln!(
                "sinter serve: started tunnel-client (pid {pid}) for {}; stops on Ctrl+C, SIGTERM, SIGHUP or after {}s",
                cfg.tunnel_id,
                d.as_secs()
            ),
            None => eprintln!(
                "sinter serve: started tunnel-client (pid {pid}) for {}; stops on Ctrl+C, SIGTERM or SIGHUP",
                cfg.tunnel_id
            ),
        }
        let mut reason: Option<EndReason> = None;
        let mut term_sent: Option<Instant> = None;
        let mut killed = false;
        let status = loop {
            match child.try_wait() {
                Ok(Some(st)) => break Some(st),
                Ok(None) => {}
                Err(e) => {
                    // ECHILD: the client is already gone (and reaped), so its
                    // PID must not be signalled. Otherwise it was not reaped
                    // and the PID is still its own: ask it to stop before
                    // leaving (the death signal also follows).
                    if e.raw_os_error() != Some(libc::ECHILD) {
                        unsafe { libc::kill(pid, libc::SIGTERM) };
                    }
                    eprintln!("sinter serve: cannot wait for tunnel-client: {e}");
                    break None;
                }
            }
            if reason.is_none() {
                let sig = STOP_SIGNAL.load(Ordering::SeqCst);
                if sig != 0 {
                    reason = Some(EndReason::Signal(sig));
                } else if deadline.is_some_and(|d| Instant::now() >= d) {
                    reason = Some(EndReason::TimeLimit);
                }
            }
            if reason.is_some() && term_sent.is_none() {
                // The client is not reaped yet (try_wait above), so the PID is
                // still its own.
                unsafe { libc::kill(pid, libc::SIGTERM) };
                term_sent = Some(Instant::now());
            }
            if let Some(t) = term_sent {
                if !killed && t.elapsed() >= STOP_TIMEOUT {
                    let _ = child.kill();
                    killed = true;
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        // A stop request that arrived while the client was already ending (for
        // example Ctrl+C, which the terminal sends to the whole process group,
        // so the client may exit before the loop sees serve's own signal) is
        // still a requested stop.
        let reason = reason.or_else(|| match STOP_SIGNAL.load(Ordering::SeqCst) {
            0 => None,
            sig => Some(EndReason::Signal(sig)),
        });
        let reason = match (reason, status) {
            (Some(r), _) => r,
            (None, Some(st)) => EndReason::ClientExited(describe(st)),
            (None, None) => EndReason::ClientExited("unknown status".to_string()),
        };
        let code = exit_code_for(&reason);
        let what = match &reason {
            EndReason::Signal(s) => format!("stop requested ({})", signal_name(*s)),
            EndReason::TimeLimit => "time limit reached".to_string(),
            EndReason::ClientExited(d) => format!("tunnel-client exited by itself ({d})"),
        };
        let kill_note = if killed {
            "; tunnel-client did not stop within 10s and was killed (a sinter mcp child may remain; see the guide)"
        } else {
            ""
        };
        eprintln!("sinter serve: ended: {what}{kill_note}; exit {code}");
        code
    }
}

/// Run `serve`: check everything, start the client, pass stop requests on,
/// and return the exit code (ADR 0002 §6.1).
pub fn serve(config_path: &Path, max: Option<Duration>) -> Result<u8, SinterError> {
    let cfg = load_config(config_path)?;
    #[cfg(unix)]
    {
        let exe = std::env::current_exe()
            .and_then(|p| p.canonicalize())
            .map_err(|e| {
                invalid(format!(
                    "cannot determine the path of this sinter executable: {e}"
                ))
            })?;
        let mcp = preflight(&cfg, &exe)?;
        #[cfg(target_os = "linux")]
        {
            Ok(run_linux::run(&cfg, &mcp, max))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (mcp, max);
            eprintln!(
                "sinter serve: the configuration is valid, but sinter serve runs on Linux only; exit {EXIT_CLIENT}"
            );
            Ok(EXIT_CLIENT)
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (cfg, max);
        Err(invalid("sinter serve runs on Linux only"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "tunnel_0123456789abcdefghijklmnopqrstuv";

    fn cfg_text(extra: &str) -> String {
        format!(
            "[tunnel]\nid = \"{ID}\"\napi_key_file = \"/etc/sinter/tunnel/runtime-key\"\nclient = \"/opt/tunnel-client/tunnel-client\"\n{extra}"
        )
    }

    #[test]
    fn parses_a_valid_configuration() {
        let c = parse_config(&cfg_text(
            "[mcp]\ntargets_file = \"/etc/sinter/targets.toml\"\n",
        ))
        .unwrap();
        assert_eq!(c.tunnel_id, ID);
        assert_eq!(
            c.api_key_file,
            PathBuf::from("/etc/sinter/tunnel/runtime-key")
        );
        assert_eq!(c.client, PathBuf::from("/opt/tunnel-client/tunnel-client"));
        assert_eq!(
            c.targets_file,
            Some(PathBuf::from("/etc/sinter/targets.toml"))
        );
        let c = parse_config(&cfg_text("")).unwrap();
        assert_eq!(c.targets_file, None);
    }

    #[test]
    fn rejects_unknown_keys_and_a_key_value_field() {
        let e = parse_config(&cfg_text("api_key = \"sk-SYNTHETIC-NOT-A-KEY\"\n")).unwrap_err();
        assert!(e.contains("unknown key \"api_key\""), "{e}");
        assert!(
            !e.contains("SYNTHETIC"),
            "a value must never be repeated: {e}"
        );
        let e = parse_config(&cfg_text("[extra]\nx = 1\n")).unwrap_err();
        assert!(e.contains("unknown key \"extra\""), "{e}");
        // A key pasted by mistake as a key name or a table name is not repeated.
        let e = parse_config(&cfg_text("sk-proj-SYNTHETIC-PASTED = \"x\"\n")).unwrap_err();
        assert!(
            e.contains("its name is not shown") && !e.contains("SYNTHETIC"),
            "{e}"
        );
        let e = parse_config(&cfg_text("[sk-SYNTHETIC-PASTED]\nx = 1\n")).unwrap_err();
        assert!(!e.contains("SYNTHETIC"), "{e}");
        let e = parse_config(&cfg_text("[mcp]\ntargets = \"/x\"\n")).unwrap_err();
        assert!(e.contains("unknown key \"targets\""), "{e}");
    }

    #[test]
    fn never_repeats_values_in_type_errors() {
        let t = "[tunnel]\nid = \"tunnel_abc\"\napi_key_file = 12345678901\nclient = \"/c\"\n";
        let e = parse_config(t).unwrap_err();
        assert!(!e.contains("12345678901"), "{e}");
        assert!(e.contains("line 3"), "{e}");
        let t = "[tunnel]\nid = \"sk-SYNTHETIC\nbroken";
        let e = parse_config(t).unwrap_err();
        assert!(!e.contains("SYNTHETIC"), "{e}");
    }

    #[test]
    fn rejects_missing_fields_and_relative_paths() {
        let e = parse_config("[tunnel]\nid = \"tunnel_abc\"\nclient = \"/c\"\n").unwrap_err();
        assert!(e.contains("missing key \"api_key_file\""), "{e}");
        let e = parse_config("[mcp]\n").unwrap_err();
        assert!(e.contains("missing key \"tunnel\""), "{e}");
        let t = format!("[tunnel]\nid = \"{ID}\"\napi_key_file = \"key\"\nclient = \"/c\"\n");
        assert!(parse_config(&t)
            .unwrap_err()
            .contains("tunnel.api_key_file must be an absolute path"));
        let t = format!("[tunnel]\nid = \"{ID}\"\napi_key_file = \"/k\"\nclient = \"bin/tc\"\n");
        assert!(parse_config(&t)
            .unwrap_err()
            .contains("tunnel.client must be an absolute path"));
        let e = parse_config(&cfg_text("[mcp]\ntargets_file = \"t.toml\"\n")).unwrap_err();
        assert!(
            e.contains("mcp.targets_file must be an absolute path"),
            "{e}"
        );
    }

    #[test]
    fn tunnel_id_is_checked_loosely() {
        for ok in [
            ID,
            "tunnel_0123456789abcdef0123456789abcdef",
            "tunnel_abcd_0123456789abcdefghijklmnopqrstuv",
            "tunnel_x",
        ] {
            assert!(tunnel_id_is_wellformed(ok), "{ok}");
        }
        let long = format!("tunnel_{}", "a".repeat(200));
        for bad in [
            "",
            "tunnel_",
            "tunnel-abc",
            "TUNNEL_abc",
            "tunnel_ABC",
            "tunnel_abc def",
            "tunnel_abc;rm",
            "x_tunnel_abc",
            "sk-proj-abc",
            long.as_str(),
        ] {
            assert!(!tunnel_id_is_wellformed(bad), "{bad}");
        }
        let t = "[tunnel]\nid = \"sk-SYNTHETIC-123\"\napi_key_file = \"/k\"\nclient = \"/c\"\n";
        let e = parse_config(t).unwrap_err();
        assert!(e.starts_with("tunnel.id must start with"), "{e}");
        assert!(!e.contains("SYNTHETIC"), "{e}");
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("1h30m").unwrap(), Duration::from_secs(5400));
        assert_eq!(parse_duration("720h").unwrap(), MAX_DURATION_LIMIT);
        for bad in [
            "",
            "0s",
            "10",
            "h",
            "1x",
            "1h 30m",
            "-1s",
            "721h",
            "1.5h",
            "99999999999999999999h",
        ] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn command_safe_paths() {
        assert!(path_is_command_safe(Path::new("/usr/local/bin/sinter")));
        assert!(path_is_command_safe(Path::new(
            "/opt/sinter-1.13.0/bin/sinter"
        )));
        for bad in [
            "/opt/my tools/sinter",
            "/opt/a\"b",
            "/opt/a'b",
            "/opt/a\\b",
            "/opt/$HOME/x",
            "/opt/a;b",
            "/opt/a*b",
            "/opt/~x",
            "/opt/a\tb",
            "/opt/a`b`",
            "",
        ] {
            assert!(!path_is_command_safe(Path::new(bad)), "{bad:?}");
        }
    }

    #[test]
    fn builds_the_mcp_command_and_client_arguments() {
        let m = mcp_command(
            Path::new("/usr/local/bin/sinter"),
            Some(Path::new("/etc/sinter/targets.toml")),
        )
        .unwrap();
        assert_eq!(
            m,
            "/usr/local/bin/sinter mcp --targets-file /etc/sinter/targets.toml"
        );
        assert_eq!(
            mcp_command(Path::new("/usr/local/bin/sinter"), None).unwrap(),
            "/usr/local/bin/sinter mcp"
        );
        assert!(mcp_command(Path::new("/opt/my tools/sinter"), None).is_err());
        assert!(mcp_command(
            Path::new("/usr/bin/sinter"),
            Some(Path::new("/etc/my targets.toml"))
        )
        .is_err());
        let cfg = parse_config(&cfg_text("")).unwrap();
        let a = client_args(&cfg, &m);
        let a: Vec<String> = a.into_iter().map(|s| s.into_string().unwrap()).collect();
        assert_eq!(
            a,
            vec![
                "run",
                "--control-plane.tunnel-id",
                ID,
                "--control-plane.api-key",
                "file:/etc/sinter/tunnel/runtime-key",
                "--mcp.command",
                "/usr/local/bin/sinter mcp --targets-file /etc/sinter/targets.toml",
                "--health.listen-addr",
                "127.0.0.1:0",
            ]
        );
    }

    #[test]
    fn environment_is_an_allowlist() {
        let input: Vec<(OsString, OsString)> = [
            ("PATH", "/usr/bin"),
            ("HOME", "/home/x"),
            ("OPENAI_API_KEY", "sk-SYNTHETIC"),
            ("OPENAI_ADMIN_KEY", "sk-admin-SYNTHETIC"),
            ("CONTROL_PLANE_API_KEY", "sk-SYNTHETIC"),
            ("CONTROL_PLANE_API_KEY_FILE", "/x"),
            ("LC_ALL", "C"),
            ("LC_", "x"),
            ("HTTPS_PROXY", "http://proxy.invalid:3128"),
            ("no_proxy", "localhost"),
            ("CA_BUNDLE", "/etc/ca.pem"),
            ("SSH_AUTH_SOCK", "/run/agent"),
            ("AWS_SECRET_ACCESS_KEY", "SYNTHETIC"),
            ("LD_PRELOAD", "/tmp/x.so"),
            ("SINTER_TEST_SSH_HOST", "h"),
            ("TUNNEL_CLIENT_CONFIG", "/tmp/override.yaml"),
            ("TUNNEL_CLIENT_PROFILE", "x"),
            ("CONTROL_PLANE_AWS_ROLE_ARN", "arn"),
            ("MCP_STDIO_FAILURE_POLICY", "exit"),
            ("TUNNEL_CLIENT_HTTP_PROXY", "http://proxy.invalid:3128"),
        ]
        .iter()
        .map(|(k, v)| (OsString::from(k), OsString::from(v)))
        .collect();
        let out = client_env(input);
        let keys: Vec<String> = out
            .iter()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            keys,
            vec![
                "CA_BUNDLE",
                "HOME",
                "HTTPS_PROXY",
                "LC_ALL",
                "PATH",
                "SSH_AUTH_SOCK",
                "TUNNEL_CLIENT_HTTP_PROXY",
                "no_proxy"
            ]
        );
    }

    #[test]
    fn exit_codes() {
        assert_eq!(exit_code_for(&EndReason::Signal(libc::SIGINT)), 0);
        assert_eq!(exit_code_for(&EndReason::TimeLimit), 0);
        assert_eq!(
            exit_code_for(&EndReason::ClientExited("exit status 0".into())),
            3
        );
    }

    #[test]
    fn default_config_path_rule() {
        let p = default_config_path(Some("/xdg".into()), Some("/home/u".into())).unwrap();
        assert_eq!(p, PathBuf::from("/xdg/sinter/serve.toml"));
        let p = default_config_path(Some("relative".into()), Some("/home/u".into())).unwrap();
        assert_eq!(p, PathBuf::from("/home/u/.config/sinter/serve.toml"));
        let p = default_config_path(None, Some("/home/u".into())).unwrap();
        assert_eq!(p, PathBuf::from("/home/u/.config/sinter/serve.toml"));
        assert!(default_config_path(None, None).is_err());
        assert!(default_config_path(None, Some("rel".into())).is_err());
    }

    #[cfg(unix)]
    mod files {
        use super::super::*;
        use std::os::unix::fs::PermissionsExt;

        fn write(dir: &Path, name: &str, body: &[u8], mode: u32) -> PathBuf {
            let p = dir.join(name);
            std::fs::write(&p, body).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            p
        }

        #[test]
        fn key_file_checks() {
            let d = tempfile::tempdir().unwrap();
            let ok = write(d.path(), "key", b"sk-SYNTHETIC-NOT-A-KEY\n", 0o600);
            check_key_file(&ok).unwrap();
            let e = check_key_file(&d.path().join("missing")).unwrap_err();
            assert_eq!(e.kind.exit_code(), 2);
            let empty = write(d.path(), "empty", b"", 0o600);
            assert!(check_key_file(&empty)
                .unwrap_err()
                .message
                .contains("is empty"));
            let wide = write(d.path(), "wide", b"sk-SYNTHETIC", 0o640);
            let e = check_key_file(&wide).unwrap_err();
            assert!(
                e.message.contains("group or other permissions"),
                "{}",
                e.message
            );
            assert!(!e.message.contains("SYNTHETIC"));
            let big = write(d.path(), "big", &vec![b'x'; 5000], 0o600);
            assert!(check_key_file(&big)
                .unwrap_err()
                .message
                .contains("larger than"));
            let link = d.path().join("link");
            std::os::unix::fs::symlink(&ok, &link).unwrap();
            assert!(check_key_file(&link)
                .unwrap_err()
                .message
                .contains("symbolic link"));
            assert!(check_key_file(d.path())
                .unwrap_err()
                .message
                .contains("not a regular file"));
        }

        #[test]
        fn client_checks() {
            let d = tempfile::tempdir().unwrap();
            let ok = write(d.path(), "tc", b"#!/bin/sh\n", 0o755);
            check_client(&ok).unwrap();
            assert!(check_client(&d.path().join("missing")).is_err());
            let noexec = write(d.path(), "noexec", b"#!/bin/sh\n", 0o644);
            assert!(check_client(&noexec)
                .unwrap_err()
                .message
                .contains("not executable"));
            let gw = write(d.path(), "gw", b"#!/bin/sh\n", 0o775);
            assert!(check_client(&gw)
                .unwrap_err()
                .message
                .contains("writable by group or others"));
            assert!(check_client(d.path())
                .unwrap_err()
                .message
                .contains("not a regular file"));
        }

        #[test]
        fn preflight_checks_the_targets_file() {
            let d = tempfile::tempdir().unwrap();
            let key = write(d.path(), "key", b"sk-SYNTHETIC", 0o600);
            let tc = write(d.path(), "tc", b"#!/bin/sh\n", 0o755);
            let bad = write(
                d.path(),
                "targets.toml",
                b"[targets.web]\nhost = \"\"\nuser = \"u\"\nknown_hosts = \"/k\"\n",
                0o644,
            );
            let cfg = ServeConfig {
                tunnel_id: "tunnel_abc".into(),
                api_key_file: key.clone(),
                client: tc.clone(),
                targets_file: Some(bad),
            };
            let e = preflight(&cfg, Path::new("/usr/local/bin/sinter")).unwrap_err();
            assert_eq!(e.kind.exit_code(), 2);
            assert!(e.message.contains("mcp.targets_file"), "{}", e.message);
            let missing = ServeConfig {
                targets_file: Some(d.path().join("none.toml")),
                ..cfg.clone()
            };
            assert_eq!(
                preflight(&missing, Path::new("/usr/local/bin/sinter"))
                    .unwrap_err()
                    .kind
                    .exit_code(),
                2
            );
            let none = ServeConfig {
                targets_file: None,
                ..cfg
            };
            assert_eq!(
                preflight(&none, Path::new("/usr/local/bin/sinter")).unwrap(),
                "/usr/local/bin/sinter mcp"
            );
        }
    }
}
