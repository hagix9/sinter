//! `sinter serve init`, `sinter serve check` and `sinter serve rotate-key`
//! (ADR 0002 r6, Phase 1A): first-time setup and maintenance for an EXISTING
//! OpenAI Secure MCP Tunnel.
//!
//! What only the operator can do stays manual (creating the tunnel and the
//! Restricted key in the OpenAI Platform, registering the custom MCP app in
//! ChatGPT, installing `tunnel-client`): no official API covers those with a
//! least-privilege key. What these commands do:
//!
//! * `init` asks for the tunnel ID (shown) and the Restricted key (NOT shown,
//!   read from `/dev/tty` with echo off by the existing `TtyPrompter`), writes
//!   the key file and the configuration with the symlink-safe, no-replace
//!   writes of `crate::securefile`, rolls back what it created if anything
//!   fails, then runs the `serve` preflight and the official `tunnel-client
//!   doctor` (and, only with `--check-online`, `tunnel-client admin tunnels get`
//!   with the key passed as a `file:` reference).
//! * `check` runs the same diagnosis for an existing configuration and writes
//!   nothing.
//! * `rotate-key` replaces the key file atomically after checking it.
//!
//! Sinter holds the key in memory only between reading it and writing it
//! (zeroized), never prints it, never puts it in an argument or an environment
//! variable, and never reads the key file. Nothing here opens a network
//! connection itself; `--check-online` lets the official client do it.
#![cfg(unix)]

use crate::error::SinterError;
use crate::secrets_cli::Prompter;
use crate::serve::{
    check_client, client_env, load_config, mcp_command, parse_config, preflight, ServeConfig,
};
use serde::Serialize;
use std::ffi::OsString;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

/// Shortest and longest key accepted (an OpenAI key is far inside this range).
pub const KEY_MIN: usize = 20;
pub const KEY_MAX: usize = 1024;
/// The default client location offered by `init`.
pub const DEFAULT_CLIENT: &str = "/opt/tunnel-client/tunnel-client";
/// How long `doctor` or the online check may take.
const CLIENT_CHECK_TIMEOUT: Duration = Duration::from_secs(60);
/// The unit template shipped in the repository, rendered by `init --systemd`.
const UNIT_TEMPLATE: &str = include_str!("../contrib/systemd/sinter-tunnel.service");

fn invalid(msg: impl Into<String>) -> SinterError {
    SinterError::schema(format!("serve: {}", msg.into()))
}

/// Check a key the operator typed. Errors and warnings never contain the key.
/// Returns an optional warning (the key is still accepted).
pub fn check_key_value(key: &str) -> Result<Option<&'static str>, &'static str> {
    if key.is_empty() {
        return Err("the key is empty; nothing was stored");
    }
    if key
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || !b.is_ascii())
    {
        return Err("the key contains whitespace, control or non-ASCII characters; nothing was stored (paste the key alone)");
    }
    if key.len() < KEY_MIN || key.len() > KEY_MAX {
        return Err("the key length is not plausible (20 to 1024 characters); nothing was stored");
    }
    if !key.starts_with("sk-") {
        return Ok(Some("the key does not start with \"sk-\"; check that it is the Restricted key from the Platform"));
    }
    Ok(None)
}

/// The form `tunnel-client` v0.0.21 accepts: `tunnel_<32>` or
/// `tunnel_<4>_<32>` (lowercase letters and digits). Sinter's own check stays
/// loose (`crate::serve::tunnel_id_is_wellformed`); this one only decides
/// whether `init` warns.
pub fn tunnel_id_matches_client_form(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("tunnel_") else {
        return false;
    };
    let alnum = |s: &str| {
        s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    };
    match rest.len() {
        32 => alnum(rest),
        37 => rest.as_bytes()[4] == b'_' && alnum(&rest[..4]) && alnum(&rest[5..]),
        _ => false,
    }
}

/// A plausible Linux user name for the systemd unit.
pub fn service_user_is_wellformed(u: &str) -> bool {
    !u.is_empty()
        && u.len() <= 32
        && u.starts_with(|c: char| c.is_ascii_lowercase() || c == '_')
        && u.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

#[derive(Serialize)]
struct OutConfig<'a> {
    tunnel: OutTunnel<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mcp: Option<OutMcp<'a>>,
}
#[derive(Serialize)]
struct OutTunnel<'a> {
    id: &'a str,
    api_key_file: &'a Path,
    client: &'a Path,
}
#[derive(Serialize)]
struct OutMcp<'a> {
    targets_file: &'a Path,
}

/// The configuration text `init` writes (serialized, so paths are escaped);
/// it is parsed back with the `serve` parser before it is written.
pub fn render_config(cfg: &ServeConfig) -> Result<String, SinterError> {
    let out = OutConfig {
        tunnel: OutTunnel {
            id: &cfg.tunnel_id,
            api_key_file: &cfg.api_key_file,
            client: &cfg.client,
        },
        mcp: cfg
            .targets_file
            .as_deref()
            .map(|t| OutMcp { targets_file: t }),
    };
    let body = toml::to_string(&out)
        .map_err(|e| invalid(format!("cannot render the configuration: {e}")))?;
    let text = format!(
        "# sinter serve configuration, written by `sinter serve init`.\n# It holds no key: api_key_file names the file that does.\n{body}"
    );
    let back = parse_config(&text).map_err(|m| {
        invalid(format!(
            "the rendered configuration does not parse back: {m}"
        ))
    })?;
    if &back != cfg {
        return Err(invalid("the rendered configuration does not round-trip"));
    }
    Ok(text)
}

/// The shipped unit template with every placeholder filled. Contains no key:
/// the key file is named, and systemd hands it over as a credential.
pub fn render_unit(
    cfg: &ServeConfig,
    sinter_exe: &Path,
    service_user: &str,
) -> Result<String, SinterError> {
    if !service_user_is_wellformed(service_user) {
        return Err(invalid("--service-user is not a plausible user name"));
    }
    // Validates the paths placed into --mcp.command as `serve` does.
    mcp_command(sinter_exe, cfg.targets_file.as_deref())?;
    for (what, p) in [
        ("tunnel.api_key_file", &cfg.api_key_file),
        ("tunnel.client", &cfg.client),
    ] {
        if !crate::serve::path_is_command_safe(p) {
            return Err(invalid(format!(
                "{what} contains characters that cannot be placed in a unit file safely"
            )));
        }
    }
    let mut u = UNIT_TEMPLATE.to_string();
    match &cfg.targets_file {
        Some(t) => u = u.replace("<TARGETS_FILE>", &t.display().to_string()),
        None => u = u.replace(" --targets-file <TARGETS_FILE>", ""),
    }
    u = u
        .replace("<SERVICE_USER>", service_user)
        .replace("<KEY_FILE>", &cfg.api_key_file.display().to_string())
        .replace("<TUNNEL_CLIENT>", &cfg.client.display().to_string())
        .replace("<TUNNEL_ID>", &cfg.tunnel_id)
        .replace("<SINTER_BIN>", &sinter_exe.display().to_string());
    // The header comment explains the placeholders; drop the lines that would
    // now read oddly (the explanation and the targets placeholder line).
    let u: String = u
        .lines()
        .filter(|l| {
            !l.starts_with("# Replace every <PLACEHOLDER>")
                && !(l.starts_with("#   <TARGETS_FILE>") && cfg.targets_file.is_none())
        })
        .map(|l| format!("{l}\n"))
        .collect();
    let left: Vec<&str> = [
        "<SERVICE_USER>",
        "<KEY_FILE>",
        "<TUNNEL_CLIENT>",
        "<TUNNEL_ID>",
        "<SINTER_BIN>",
        "<TARGETS_FILE>",
    ]
    .into_iter()
    .filter(|p| u.lines().any(|l| !l.starts_with('#') && l.contains(p)))
    .collect();
    if !left.is_empty() {
        return Err(invalid(format!(
            "the unit template still has placeholders {left:?}"
        )));
    }
    Ok(u)
}

/// Options of `sinter serve init`.
#[derive(Debug, Clone)]
pub struct InitOptions {
    pub config: PathBuf,
    pub key_file: Option<PathBuf>,
    pub client: Option<PathBuf>,
    pub targets_file: Option<PathBuf>,
    pub tunnel_id: Option<String>,
    pub systemd: bool,
    pub service_user: String,
    pub check_online: bool,
}

fn euid() -> u32 {
    unsafe { libc::geteuid() }
}

fn exists_no_follow(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok()
}

/// A directory `init` may write into: an existing directory (not a symbolic
/// link) owned by the effective user (or root), not writable by group or
/// others. Returns `true` when it is missing and its parent passes the same
/// check, so that it can be created (0700) once the key has been read.
fn check_dir_or_parent(dir: &Path) -> Result<bool, SinterError> {
    match std::fs::symlink_metadata(dir) {
        Ok(_) => check_dir(dir).map(|_| false),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let parent = dir
                .parent()
                .ok_or_else(|| invalid(format!("{} has no parent directory", dir.display())))?;
            check_dir(parent)?;
            Ok(true)
        }
        Err(e) => Err(invalid(format!("cannot inspect {}: {e}", dir.display()))),
    }
}

/// Create a directory checked by [`check_dir_or_parent`] with mode 0700 and
/// record it for the rollback; then check it again.
fn create_private_dir(dir: &Path, created: &mut Vec<PathBuf>) -> Result<(), SinterError> {
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(dir)
        .map_err(|e| invalid(format!("cannot create {}: {e}", dir.display())))?;
    created.push(dir.to_path_buf());
    check_dir(dir)
}

fn check_dir(dir: &Path) -> Result<(), SinterError> {
    let m = std::fs::symlink_metadata(dir)
        .map_err(|e| invalid(format!("cannot inspect {}: {e}", dir.display())))?;
    if m.file_type().is_symlink() {
        return Err(invalid(format!(
            "{} is a symbolic link; name the real directory",
            dir.display()
        )));
    }
    if !m.is_dir() {
        return Err(invalid(format!("{} is not a directory", dir.display())));
    }
    if m.uid() != euid() && m.uid() != 0 {
        return Err(invalid(format!(
            "{} is owned by another user; use a directory owned by you (or by root)",
            dir.display()
        )));
    }
    if m.permissions().mode() & 0o022 != 0 {
        return Err(invalid(format!(
            "{} is writable by group or others",
            dir.display()
        )));
    }
    Ok(())
}

/// Files and directories created by this run, removed if it fails.
struct Rollback {
    files: Vec<PathBuf>,
    dirs: Vec<PathBuf>,
    armed: bool,
}

impl Drop for Rollback {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        for f in self.files.iter().rev() {
            let _ = std::fs::remove_file(f);
        }
        for d in self.dirs.iter().rev() {
            let _ = std::fs::remove_dir(d); // only if empty
        }
    }
}

fn ask_line(p: &mut dyn Prompter, prompt: &str) -> Result<String, SinterError> {
    p.read_line(prompt)
        .map(|s| s.trim().to_string())
        .map_err(|e| invalid(format!("cannot read from the terminal: {}", e.kind())))
}

/// Run `tunnel-client` with `args`, the cleared environment of `serve` and no
/// stdin; capture its output; give up after `CLIENT_CHECK_TIMEOUT`.
fn run_client(client: &Path, args: &[OsString]) -> Result<(Option<i32>, String, String), String> {
    let child = Command::new(client)
        .args(args)
        .env_clear()
        .envs(client_env(std::env::vars_os()))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|e| format!("cannot start {}: {e}", client.display()))?;
    // The output is drained by one thread while this one keeps the deadline,
    // so a client that writes more than a pipe holds cannot block on a full
    // pipe. The child is reaped only by that thread, so its PID stays its own
    // until the kill below.
    let pid = child.id() as libc::pid_t;
    let (tx, rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    let out = match rx.recv_timeout(CLIENT_CHECK_TIMEOUT) {
        Ok(r) => r.map_err(|e| format!("cannot read the output: {e}"))?,
        Err(_) => {
            // The client runs in its own process group, so anything it
            // started (which could hold the pipes open) goes with it.
            unsafe { libc::kill(-pid, libc::SIGKILL) };
            let _ = reader.join();
            return Err(format!("{} did not finish within 60 s", client.display()));
        }
    };
    let _ = reader.join();
    Ok((
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

/// The `doctor` arguments: the same options `serve` passes to `run`.
pub fn doctor_args(cfg: &ServeConfig, mcp_command: &str) -> Vec<OsString> {
    let mut v = crate::serve::client_args(cfg, mcp_command);
    v[0] = "doctor".into();
    v
}

/// The online lookup: `tunnel-client admin --admin-key file:<key> tunnels get <id>`.
/// The Restricted key is enough for this read-only lookup (tunnel-client
/// v0.0.21, `admin tunnels get`); it travels as a `file:` reference only.
pub fn online_args(cfg: &ServeConfig) -> Vec<OsString> {
    let mut key_ref = OsString::from("file:");
    key_ref.push(cfg.api_key_file.as_os_str());
    vec![
        "admin".into(),
        "--admin-key".into(),
        key_ref,
        "tunnels".into(),
        "get".into(),
        cfg.tunnel_id.clone().into(),
    ]
}

/// A failure summary that never repeats client output: an API error message
/// can quote part of the key (masked or not), so only an HTTP status found in
/// the output, if any, and the exit status are shown.
fn failure_reason(code: Option<i32>, so: &str, se: &str) -> String {
    let status = match code {
        Some(c) => format!("exit status {c}"),
        None => "ended by a signal".to_string(),
    };
    let http = http_status(&format!("{se}\n{so}")).map(|n| match n {
        401 => "HTTP 401: the key was not accepted (wrong, revoked or expired key?)".to_string(),
        403 => "HTTP 403: the key lacks Tunnels Read + Use for this tunnel".to_string(),
        404 => "HTTP 404: no such tunnel for this key (wrong tunnel ID?)".to_string(),
        n => format!("HTTP {n}"),
    });
    match http {
        Some(h) => format!("{status}; {h}; run tunnel-client directly for its own message"),
        None => format!("{status}; run tunnel-client directly for its own message"),
    }
}

/// The HTTP status (400–599) of a failed request, read only where a status is
/// written: right after one of the markers `failed:`, `failed with`,
/// `status code`, `status:`, `status=`, `status`, `HTTP/<version>`, `HTTP`
/// or `error:` (case-insensitive), as exactly three digits followed by a
/// non-digit. Numbers anywhere else (a URL path, a tunnel ID such as
/// `…dd490ee`, a request ID, a body) are never read. The earliest marker in
/// the text wins; `None` when no marker carries a status.
fn http_status(text: &str) -> Option<u16> {
    // The text is lowercased once; markers are ASCII, so byte offsets agree.
    let lower = text.to_ascii_lowercase();
    let b = lower.as_bytes();
    const MARKERS: &[&str] = &[
        "failed:",
        "failed with",
        "status code",
        "status:",
        "status=",
        "status",
        "http/",
        "http",
        "error:",
    ];
    let mut best: Option<(usize, u16)> = None;
    for m in MARKERS {
        let mut from = 0;
        while let Some(off) = lower[from..].find(m) {
            let start = from + off;
            from = start + m.len();
            // The marker must start a word (not "nonhttp", not "xstatus").
            if start > 0 && b[start - 1].is_ascii_alphanumeric() {
                continue;
            }
            let mut k = start + m.len();
            if *m == "http/" {
                // Skip the protocol version: digits and dots.
                while k < b.len() && (b[k].is_ascii_digit() || b[k] == b'.') {
                    k += 1;
                }
            } else if m.ends_with(|c: char| c.is_ascii_alphabetic())
                && k < b.len()
                && b[k].is_ascii_alphanumeric()
            {
                // "status" must not be the start of "statusbar", "http" not of "https".
                continue;
            }
            while k < b.len() && (b[k] == b' ' || b[k] == b'\t' || b[k] == b':' || b[k] == b'=') {
                k += 1;
            }
            if k + 3 > b.len() || !b[k..k + 3].iter().all(u8::is_ascii_digit) {
                continue;
            }
            if k + 3 < b.len() && b[k + 3].is_ascii_digit() {
                continue;
            }
            let n: u16 = lower[k..k + 3].parse().ok()?;
            if (400..=599).contains(&n) && best.is_none_or(|(p, _)| start < p) {
                best = Some((start, n));
            }
        }
    }
    best.map(|(_, n)| n)
}

/// From doctor's output, only the name and verdict of a check (`CHECK <name>
/// <verdict>`): the detail column can hold values.
fn check_name_and_verdict(line: &str) -> Option<String> {
    let mut it = line.split_whitespace();
    if it.next()? != "CHECK" {
        return None;
    }
    let name = it.next()?;
    let verdict = it.next()?;
    let name_ok = name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    let verdict_ok = verdict.bytes().all(|b| b.is_ascii_uppercase());
    (name_ok && verdict_ok).then(|| format!("CHECK {name} {verdict}"))
}

/// The diagnosis shared by `init` and `check`: the `serve` preflight, then the
/// official `doctor`, then (optionally) the online lookup. Returns the exit code.
fn diagnose(
    cfg: &ServeConfig,
    sinter_exe: &Path,
    online: bool,
    out: &mut dyn Write,
) -> Result<u8, SinterError> {
    let mcp = preflight(cfg, sinter_exe)?;
    let _ = writeln!(
        out,
        "check: configuration, key file (not read), client and targets file: OK"
    );
    match run_client(&cfg.client, &doctor_args(cfg, &mcp)) {
        Ok((Some(0), so, _)) => {
            let _ = writeln!(out, "check: tunnel-client doctor: OK");
            for l in so.lines().filter_map(check_name_and_verdict) {
                let _ = writeln!(out, "  {l}");
            }
        }
        Ok((code, so, se)) => {
            let _ = writeln!(
                out,
                "check: tunnel-client doctor FAILED ({})",
                failure_reason(code, &so, &se)
            );
            for l in so
                .lines()
                .filter_map(check_name_and_verdict)
                .filter(|l| !l.ends_with(" PASS") && !l.ends_with(" SKIP"))
            {
                let _ = writeln!(out, "  {l}");
            }
            return Ok(crate::serve::EXIT_CLIENT);
        }
        Err(m) => {
            let _ = writeln!(out, "check: tunnel-client doctor could not run: {m}");
            return Ok(crate::serve::EXIT_CLIENT);
        }
    }
    if online {
        match run_client(&cfg.client, &online_args(cfg)) {
            // The lookup's output carries organization/workspace identifiers:
            // only the outcome is shown.
            Ok((Some(0), _, _)) => {
                let _ = writeln!(out, "check: online lookup of the tunnel with this key: OK (via tunnel-client, api.openai.com)");
            }
            Ok((code, so, se)) => {
                let _ = writeln!(
                    out,
                    "check: online lookup FAILED ({})",
                    failure_reason(code, &so, &se)
                );
                return Ok(crate::serve::EXIT_CLIENT);
            }
            Err(m) => {
                let _ = writeln!(out, "check: online lookup could not run: {m}");
                return Ok(crate::serve::EXIT_CLIENT);
            }
        }
    }
    Ok(crate::serve::EXIT_STOPPED)
}

/// `sinter serve check`: diagnose an existing configuration; writes nothing.
pub fn check(
    config: &Path,
    sinter_exe: &Path,
    online: bool,
    out: &mut dyn Write,
) -> Result<u8, SinterError> {
    let cfg = load_config(config)?;
    diagnose(&cfg, sinter_exe, online, out)
}

/// `sinter serve init`.
pub fn init(
    opts: &InitOptions,
    p: &mut dyn Prompter,
    sinter_exe: &Path,
    out: &mut dyn Write,
) -> Result<u8, SinterError> {
    // 1. Preconditions; nothing is written before all of them hold.
    if !p.interactive() {
        return Err(invalid(
            "serve init reads the key on a terminal only (/dev/tty); none is available",
        ));
    }
    if opts.systemd && euid() != 0 {
        return Err(invalid("serve init --systemd stores the key for systemd's LoadCredential= and must run as root"));
    }
    let key_file = match &opts.key_file {
        Some(k) => k.clone(),
        None => opts
            .config
            .parent()
            .map(|d| d.join("runtime-key"))
            .ok_or_else(|| invalid("--config has no parent directory"))?,
    };
    for (what, path) in [("--config", &opts.config), ("--key-file", &key_file)] {
        if !path.is_absolute() {
            return Err(invalid(format!("{what} must be an absolute path")));
        }
        if exists_no_follow(path) {
            return Err(invalid(format!(
                "{} already exists; init never replaces a file (use `sinter serve rotate-key` for a new key, or remove the old setup first)",
                path.display()
            )));
        }
    }
    if key_file == opts.config {
        return Err(invalid("--key-file and --config must differ"));
    }
    if let Some(t) = &opts.targets_file {
        if !t.is_absolute() {
            return Err(invalid("--targets-file must be an absolute path"));
        }
    }
    if opts.systemd && !service_user_is_wellformed(&opts.service_user) {
        return Err(invalid("--service-user is not a plausible user name"));
    }

    // 2. The tunnel ID (an identifier, shown) and the client.
    let tunnel_id = match &opts.tunnel_id {
        Some(t) => t.trim().to_string(),
        None => ask_line(p, "Tunnel ID (starts with tunnel_): ")?,
    };
    if !crate::serve::tunnel_id_is_wellformed(&tunnel_id) {
        return Err(invalid(
            "the tunnel ID must start with \"tunnel_\" and contain only a-z, 0-9 and _",
        ));
    }
    if !tunnel_id_matches_client_form(&tunnel_id) {
        let _ = writeln!(out, "warning: the tunnel ID does not have the form tunnel-client v0.0.21 accepts (tunnel_ + 32, or tunnel_ + 4 + _ + 32 lowercase letters and digits)");
        let a = ask_line(p, "Use it anyway? [y/N]: ")?;
        if !matches!(a.as_str(), "y" | "Y" | "yes") {
            return Err(invalid("stopped; nothing was written"));
        }
    }
    let client = match &opts.client {
        Some(c) => c.clone(),
        None => {
            let a = ask_line(
                p,
                &format!("Path of the official tunnel-client [{DEFAULT_CLIENT}]: "),
            )?;
            PathBuf::from(if a.is_empty() {
                DEFAULT_CLIENT
            } else {
                a.as_str()
            })
        }
    };
    if !client.is_absolute() {
        return Err(invalid(
            "the tunnel-client path must be absolute (PATH is never searched)",
        ));
    }
    check_client(&client)?;
    let cfg = ServeConfig {
        tunnel_id,
        api_key_file: key_file.clone(),
        client,
        targets_file: opts.targets_file.clone(),
    };
    if let Some(t) = &cfg.targets_file {
        crate::targets::TargetRegistry::load(t)
            .map_err(|e| invalid(format!("--targets-file: {}", e.message)))?;
    }
    mcp_command(sinter_exe, cfg.targets_file.as_deref())?;
    let config_text = render_config(&cfg)?;
    let unit = if opts.systemd {
        Some(render_unit(&cfg, sinter_exe, &opts.service_user)?)
    } else {
        None
    };

    // 3. Directories (created with 0700 only where missing).
    let mut rb = Rollback {
        files: Vec::new(),
        dirs: Vec::new(),
        armed: true,
    };
    // Checked before the key is asked for; created only after it was read, so
    // that interrupting the prompt (Ctrl-C ends the process) leaves nothing.
    let mut to_create: Vec<PathBuf> = Vec::new();
    for d in [key_file.parent(), opts.config.parent()]
        .into_iter()
        .flatten()
    {
        if !to_create.iter().any(|x| x == d) && check_dir_or_parent(d)? {
            to_create.push(d.to_path_buf());
        }
    }

    // 4. The key: read on the terminal with echo off, checked, written, dropped.
    let key = p
        .read_secret("Restricted API key (Tunnels Read + Use; input is not shown): ")
        .map_err(|e| {
            invalid(format!(
                "cannot read the key from the terminal: {}",
                e.kind()
            ))
        })?;
    let warning = check_key_value(&key).map_err(invalid)?;
    if let Some(w) = warning {
        let _ = writeln!(out, "warning: {w}");
    }
    for d in &to_create {
        create_private_dir(d, &mut rb.dirs)?;
    }
    match crate::securefile::publish_new(&key_file, key.as_bytes(), 0o600) {
        Ok(()) => rb.files.push(key_file.clone()),
        Err(e) => {
            return Err(invalid(format!(
                "cannot write {}: {}",
                key_file.display(),
                e.kind()
            )))
        }
    }
    drop(key);
    crate::securefile::publish_new(&opts.config, config_text.as_bytes(), 0o600).map_err(|e| {
        invalid(format!(
            "cannot write {}: {}",
            opts.config.display(),
            e.kind()
        ))
    })?;
    rb.files.push(opts.config.clone());
    if opts.systemd {
        // A setgid parent directory would hand its group to the new files.
        for f in [&key_file, &opts.config] {
            std::os::unix::fs::chown(f, Some(0), Some(0))
                .map_err(|e| invalid(format!("cannot set root:root on {}: {e}", f.display())))?;
        }
    }

    // 5. The written setup must pass the serve preflight; otherwise undo it.
    let back = load_config(&opts.config)?;
    preflight(&back, sinter_exe)?;
    rb.armed = false;
    for f in [&key_file, &opts.config] {
        if let Ok(m) = std::fs::symlink_metadata(f) {
            let _ = writeln!(
                out,
                "wrote {} (owner uid {}, mode {:04o}, {} bytes)",
                f.display(),
                m.uid(),
                m.permissions().mode() & 0o7777,
                m.len()
            );
        }
    }

    // 6. Diagnosis (files are kept whatever it says: they are valid).
    let code = diagnose(&back, sinter_exe, opts.check_online, out)?;

    // 7. Next steps.
    let _ = writeln!(out, "\nnext steps:");
    match &unit {
        None => {
            let _ = writeln!(
                out,
                "  start the connection:  sinter serve --config {}",
                opts.config.display()
            );
        }
        Some(u) => {
            let _ = writeln!(out, "  the key is root-owned for systemd's LoadCredential=; install the unit below as root:");
            let _ = writeln!(out, "    install -m 0644 sinter-tunnel.service /etc/systemd/system/ && systemctl daemon-reload && systemctl start sinter-tunnel");
            let _ = writeln!(out, "  (sinter serve --config {} is for foreground use and would refuse this root-owned key as another user)\n", opts.config.display());
            let _ = write!(
                out,
                "----- sinter-tunnel.service -----\n{u}----- end -----\n"
            );
        }
    }
    let _ = writeln!(out, "  in ChatGPT: Add custom MCP server -> Connection: Tunnel -> this tunnel (the workspace admin must allow custom MCP servers)");
    let _ = writeln!(out, "  to revoke the key: delete it in the OpenAI Platform (removing the file does not revoke it)");
    Ok(code)
}

/// `sinter serve rotate-key`: replace the key file of an existing configuration.
pub fn rotate_key(
    config: &Path,
    p: &mut dyn Prompter,
    sinter_exe: &Path,
    online: bool,
    out: &mut dyn Write,
) -> Result<u8, SinterError> {
    let cfg = load_config(config)?;
    if !p.interactive() {
        return Err(invalid(
            "serve rotate-key reads the key on a terminal only (/dev/tty); none is available",
        ));
    }
    // The current key file must be the one serve accepts (regular, not a link,
    // owned by this user, 0600): nothing else is ever replaced.
    crate::serve::check_key_file(&cfg.api_key_file)?;
    if let Some(d) = cfg.api_key_file.parent() {
        check_dir(d)?;
    }
    let key = p
        .read_secret("New Restricted API key (Tunnels Read + Use; input is not shown): ")
        .map_err(|e| {
            invalid(format!(
                "cannot read the key from the terminal: {}",
                e.kind()
            ))
        })?;
    let warning = check_key_value(&key).map_err(invalid)?;
    if let Some(w) = warning {
        let _ = writeln!(out, "warning: {w}");
    }
    crate::securefile::replace(&cfg.api_key_file, key.as_bytes(), 0o600).map_err(|e| {
        invalid(format!(
            "cannot replace {}: {}",
            cfg.api_key_file.display(),
            e.kind()
        ))
    })?;
    drop(key);
    let _ = writeln!(
        out,
        "replaced {} (mode 0600); the old key is not kept",
        cfg.api_key_file.display()
    );
    let code = diagnose(&cfg, sinter_exe, online, out)?;
    let _ = writeln!(out, "next: restart a running `sinter serve` (or `systemctl restart`), then revoke the old key in the OpenAI Platform");
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use zeroize::Zeroizing;

    const KEY: &str = "sk-SYNTHETIC-SETUP-TEST-0123456789";
    const ID: &str = "tunnel_0123456789abcdef0123456789abcdef";

    struct Fake {
        tty: bool,
        lines: Vec<String>,
        secret: Option<String>,
        asked_secret: bool,
    }
    impl Prompter for Fake {
        fn interactive(&self) -> bool {
            self.tty
        }
        fn read_secret(&mut self, _p: &str) -> std::io::Result<Zeroizing<String>> {
            self.asked_secret = true;
            self.secret
                .take()
                .map(Zeroizing::new)
                .ok_or_else(|| std::io::ErrorKind::UnexpectedEof.into())
        }
        fn read_line(&mut self, _p: &str) -> std::io::Result<String> {
            if self.lines.is_empty() {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            Ok(self.lines.remove(0))
        }
    }
    fn fake(lines: &[&str], secret: Option<&str>) -> Fake {
        Fake {
            tty: true,
            lines: lines.iter().map(|s| s.to_string()).collect(),
            secret: secret.map(String::from),
            asked_secret: false,
        }
    }

    struct Env {
        d: tempfile::TempDir,
    }
    impl Env {
        fn new() -> Self {
            let d = tempfile::Builder::new()
                .prefix("setup-")
                .tempdir_in("/tmp")
                .unwrap();
            std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let c = d.path().join("tc");
            std::fs::write(
                &c,
                "#!/bin/sh\necho 'CHECK x PASS y'\necho 'RESULT ok'\nexit 0\n",
            )
            .unwrap();
            std::fs::set_permissions(&c, std::fs::Permissions::from_mode(0o755)).unwrap();
            Env { d }
        }
        fn p(&self, n: &str) -> PathBuf {
            self.d.path().join(n)
        }
        fn opts(&self) -> InitOptions {
            InitOptions {
                config: self.p("conf/serve.toml"),
                key_file: None,
                client: Some(self.p("tc")),
                targets_file: None,
                tunnel_id: None,
                systemd: false,
                service_user: "sinter-tunnel".into(),
                check_online: false,
            }
        }
    }
    const EXE: &str = "/usr/local/bin/sinter";

    #[test]
    fn key_values() {
        assert_eq!(check_key_value(KEY), Ok(None));
        assert!(check_key_value("").is_err());
        assert!(check_key_value("sk-abc def0123456789012345").is_err());
        assert!(check_key_value("sk-abc\t0123456789012345678").is_err());
        assert!(check_key_value("sk-short").is_err());
        assert!(check_key_value(&"s".repeat(2000)).is_err());
        assert!(check_key_value("sk-ünicode0123456789012345").is_err());
        assert!(check_key_value("xx-0123456789012345678901")
            .unwrap()
            .is_some());
        let e = check_key_value("sk-abc def0123456789012345").unwrap_err();
        assert!(!e.contains("abc"), "an error never repeats the key");
    }

    #[test]
    fn client_form() {
        assert!(tunnel_id_matches_client_form(ID));
        assert!(tunnel_id_matches_client_form(
            "tunnel_abcd_0123456789abcdef0123456789abcdef"
        ));
        assert!(!tunnel_id_matches_client_form("tunnel_short"));
        assert!(!tunnel_id_matches_client_form(
            "tunnel_0123456789ABCDEF0123456789abcdef"
        ));
        assert!(!tunnel_id_matches_client_form(
            "tunnel_abcd-0123456789abcdef0123456789abcdef"
        ));
    }

    #[test]
    fn init_writes_both_files_privately_and_never_prints_the_key() {
        let e = Env::new();
        let mut p = fake(&[ID], Some(KEY));
        let mut out = Vec::new();
        let code = init(&e.opts(), &mut p, Path::new(EXE), &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert_eq!(code, 0, "{out}");
        let key = e.p("conf/runtime-key");
        assert_eq!(
            std::fs::read_to_string(&key).unwrap(),
            KEY,
            "no newline, exact bytes"
        );
        let km = std::fs::metadata(&key).unwrap();
        assert_eq!(km.permissions().mode() & 0o777, 0o600);
        assert_eq!(km.uid(), euid());
        let cfg = load_config(&e.p("conf/serve.toml")).unwrap();
        assert_eq!(cfg.tunnel_id, ID);
        assert_eq!(cfg.api_key_file, key);
        assert_eq!(
            std::fs::metadata(e.p("conf/serve.toml"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(e.p("conf")).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(!std::fs::read_to_string(e.p("conf/serve.toml"))
            .unwrap()
            .contains(KEY));
        assert!(!out.contains(KEY), "{out}");
        assert!(out.contains("tunnel-client doctor: OK"), "{out}");
        assert!(out.contains("sinter serve --config"), "{out}");
    }

    #[test]
    fn init_refuses_without_a_terminal_and_writes_nothing() {
        let e = Env::new();
        let mut p = fake(&[ID], Some(KEY));
        p.tty = false;
        let err = init(&e.opts(), &mut p, Path::new(EXE), &mut Vec::new()).unwrap_err();
        assert_eq!(err.kind.exit_code(), 2);
        assert!(!e.p("conf").exists());
        assert!(!p.asked_secret);
    }

    #[test]
    fn init_never_replaces_an_existing_file() {
        let e = Env::new();
        std::fs::create_dir(e.p("conf")).unwrap();
        std::fs::set_permissions(e.p("conf"), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(e.p("conf/runtime-key"), "old").unwrap();
        let mut p = fake(&[ID], Some(KEY));
        let err = init(&e.opts(), &mut p, Path::new(EXE), &mut Vec::new()).unwrap_err();
        assert!(err.message.contains("already exists"), "{}", err.message);
        assert_eq!(
            std::fs::read_to_string(e.p("conf/runtime-key")).unwrap(),
            "old"
        );
        assert!(!e.p("conf/serve.toml").exists());
        assert!(
            !p.asked_secret,
            "the key is not asked for when nothing can be written"
        );
        // A symbolic link at the configuration path counts as existing.
        std::fs::remove_file(e.p("conf/runtime-key")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", e.p("conf/serve.toml")).unwrap();
        let err = init(
            &e.opts(),
            &mut fake(&[ID], Some(KEY)),
            Path::new(EXE),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(err.message.contains("already exists"), "{}", err.message);
        assert!(!e.p("conf/runtime-key").exists());
    }

    #[test]
    fn init_rejects_a_bad_key_and_rolls_back_the_created_directory() {
        let e = Env::new();
        let mut p = fake(&[ID], Some("sk-bad key with spaces 123456"));
        let err = init(&e.opts(), &mut p, Path::new(EXE), &mut Vec::new()).unwrap_err();
        assert!(err.message.contains("whitespace"), "{}", err.message);
        assert!(!err.message.contains("spaces"), "the key is never repeated");
        assert!(
            !e.p("conf").exists(),
            "the directory created by this run is removed again"
        );
    }

    #[test]
    fn init_rejects_unsafe_directories() {
        let e = Env::new();
        std::fs::create_dir(e.p("open")).unwrap();
        std::fs::set_permissions(e.p("open"), std::fs::Permissions::from_mode(0o777)).unwrap();
        let mut o = e.opts();
        o.config = e.p("open/serve.toml");
        let err = init(
            &o,
            &mut fake(&[ID], Some(KEY)),
            Path::new(EXE),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(
            err.message.contains("writable by group or others"),
            "{}",
            err.message
        );
        std::fs::create_dir(e.p("real")).unwrap();
        std::os::unix::fs::symlink(e.p("real"), e.p("link")).unwrap();
        let mut o = e.opts();
        o.config = e.p("link/serve.toml");
        let err = init(
            &o,
            &mut fake(&[ID], Some(KEY)),
            Path::new(EXE),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(err.message.contains("symbolic link"), "{}", err.message);
    }

    #[test]
    fn init_asks_before_accepting_an_unusual_tunnel_id() {
        let e = Env::new();
        let mut p = fake(&["tunnel_x", "n"], Some(KEY));
        let err = init(&e.opts(), &mut p, Path::new(EXE), &mut Vec::new()).unwrap_err();
        assert!(err.message.contains("nothing was written"));
        assert!(!e.p("conf").exists());
        let mut p = fake(&["tunnel_x", "y"], Some(KEY));
        assert_eq!(
            init(&e.opts(), &mut p, Path::new(EXE), &mut Vec::new()).unwrap(),
            0
        );
    }

    #[test]
    fn init_reports_a_failing_doctor_but_keeps_the_valid_files() {
        let e = Env::new();
        std::fs::write(
            e.p("tc"),
            "#!/bin/sh\necho 'CHECK control_plane_api_key FAIL missing'\nexit 2\n",
        )
        .unwrap();
        let mut out = Vec::new();
        let code = init(
            &e.opts(),
            &mut fake(&[ID], Some(KEY)),
            Path::new(EXE),
            &mut out,
        )
        .unwrap();
        let out = String::from_utf8(out).unwrap();
        assert_eq!(code, 3, "{out}");
        assert!(out.contains("doctor FAILED"), "{out}");
        assert!(e.p("conf/runtime-key").exists() && e.p("conf/serve.toml").exists());
    }

    /// Regression for the real-key check V-4 (2026-11-16): the tunnel ID in
    /// the request URL contained "490", which was shown as the HTTP status of
    /// a 401. Only a number at a status position may be read.
    #[test]
    fn http_status_is_read_only_at_a_status_position() {
        let id_490 = "tunnel_0abc1234def5678aa9bb0cc1dd490ee2ff34";
        let cases: &[(&str, Option<u16>)] = &[
            // tunnel-client v0.0.21's format, with "490" inside the tunnel ID
            (&*format!("Request GET /v1/tunnels/{id_490} failed: 401 invalid_api_key: Incorrect API key provided: sk-SYNT***************WXYZ. (x-request-id: req_4904abc)"), Some(401)),
            (&*format!("Request GET /v1/tunnels/{id_490} failed: 400 invalid_request_error: bad tunnel id"), Some(400)),
            (&*format!("Request GET /v1/tunnels/{id_490} failed: 404 not_found"), Some(404)),
            (&*format!("Request GET /v1/tunnels/{id_490} failed: 500 server_error (x-request-id: req_499z)"), Some(500)),
            ("HTTP/1.1 403 Forbidden", Some(403)),
            ("HTTP/2 502 Bad Gateway", Some(502)),
            ("status code 429", Some(429)),
            ("request failed with status: 503", Some(503)),
            ("error: 401 Unauthorized", Some(401)),
            // no status position: only identifiers, durations, bodies
            (&*format!("Request GET /v1/tunnels/{id_490} timed out after 450 ms (x-request-id: req_404)"), None),
            ("connection reset by peer; retried 404 times", None),
            ("dial tcp 10.0.0.1:443: connect: connection refused", None),
            ("https://example.invalid/490/v1 unreachable", None),
            ("statusbar 401 failedx: 402", None),
            ("failed: 4011 bytes", None),
            ("failed: 200 ok", None),
            ("", None),
        ];
        for (text, want) in cases {
            assert_eq!(
                http_status(text),
                *want,
                "case {:?}",
                text.chars()
                    .take(60)
                    .collect::<String>()
                    .replace("sk-", "<k>")
            );
        }
        // The earliest status position wins.
        assert_eq!(http_status("failed: 401 x\nstatus 500"), Some(401));
        // The summary for the V-4 shape names 401 and never 490.
        let se = format!("Request GET /v1/tunnels/{id_490} failed: 401 invalid_api_key: Incorrect API key provided: sk-SYNT***************WXYZ.");
        let r = failure_reason(Some(1), "", &se);
        assert!(
            r.contains("HTTP 401: the key was not accepted") && !r.contains("490"),
            "summary: {}",
            r.replace("sk-", "<k>")
        );
        for leak in ["sk-", "SYNT", "WXYZ", "Incorrect", "tunnel_"] {
            assert!(!r.contains(leak), "the summary repeats client text");
        }
        let r = failure_reason(
            Some(1),
            "",
            &format!("Request GET /v1/tunnels/{id_490} timed out"),
        );
        assert_eq!(
            r,
            "exit status 1; run tunnel-client directly for its own message"
        );
    }

    #[test]
    fn a_failing_client_is_summarised_without_its_text() {
        let so = "CHECK control_plane_api_key FAIL sk-proj-****SYNTH";
        let se = "error: 401 Unauthorized: Incorrect API key provided: sk-SYNT***************1234. org-SYNTHETIC";
        let r = failure_reason(Some(1), so, se);
        assert!(r.contains("exit status 1") && r.contains("HTTP 401"), "{r}");
        for leak in ["sk-", "SYNT", "1234", "org-", "Incorrect"] {
            assert!(!r.contains(leak), "{leak} in {r}");
        }
        assert_eq!(
            failure_reason(None, "", ""),
            "ended by a signal; run tunnel-client directly for its own message"
        );
        assert_eq!(
            check_name_and_verdict("CHECK control_plane_api_key FAIL sk-proj-SYNTHETIC"),
            Some("CHECK control_plane_api_key FAIL".to_string())
        );
        assert_eq!(check_name_and_verdict("RESULT ok"), None);
        assert_eq!(check_name_and_verdict("CHECK sk-SYNTH/x FAIL"), None);
    }

    #[test]
    fn init_output_never_contains_client_text_on_failure() {
        let e = Env::new();
        std::fs::write(e.p("tc"), "#!/bin/sh\necho 'CHECK control_plane_api_key FAIL sk-SYNTHETIC-LEAK'\necho 'error: 401 Incorrect API key provided: sk-SYNT****LEAK org-SYNTHETIC' >&2\nexit 1\n").unwrap();
        let mut out = Vec::new();
        let code = init(
            &e.opts(),
            &mut fake(&[ID], Some(KEY)),
            Path::new(EXE),
            &mut out,
        )
        .unwrap();
        let out = String::from_utf8(out).unwrap();
        assert_eq!(code, 3, "{out}");
        assert!(
            out.contains("HTTP 401") && out.contains("CHECK control_plane_api_key FAIL"),
            "{out}"
        );
        assert!(
            !out.contains("LEAK") && !out.contains("org-SYNTHETIC") && !out.contains(KEY),
            "{out}"
        );
    }

    #[test]
    fn a_client_with_a_lot_of_output_does_not_block() {
        let e = Env::new();
        std::fs::write(e.p("tc"), "#!/bin/sh\ni=0\nwhile [ $i -lt 4000 ]; do echo \"CHECK filler_$i PASS xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"; i=$((i+1)); done\necho 'RESULT ok'\nexit 0\n").unwrap();
        let t = std::time::Instant::now();
        let r = run_client(&e.p("tc"), &[OsString::from("doctor")]).unwrap();
        assert_eq!(r.0, Some(0));
        assert!(r.1.len() > 200_000);
        assert!(t.elapsed() < Duration::from_secs(30), "{:?}", t.elapsed());
    }

    #[test]
    fn online_and_doctor_arguments_pass_the_key_by_reference_only() {
        let cfg = ServeConfig {
            tunnel_id: ID.into(),
            api_key_file: "/k/runtime-key".into(),
            client: "/c".into(),
            targets_file: None,
        };
        let a: Vec<String> = online_args(&cfg)
            .into_iter()
            .map(|s| s.into_string().unwrap())
            .collect();
        assert_eq!(
            a,
            vec![
                "admin",
                "--admin-key",
                "file:/k/runtime-key",
                "tunnels",
                "get",
                ID
            ]
        );
        let d: Vec<String> = doctor_args(&cfg, "/usr/local/bin/sinter mcp")
            .into_iter()
            .map(|s| s.into_string().unwrap())
            .collect();
        assert_eq!(d[0], "doctor");
        assert!(d.contains(&"file:/k/runtime-key".to_string()));
    }

    #[test]
    fn rendered_unit_has_no_placeholder_and_no_key() {
        let cfg = ServeConfig {
            tunnel_id: ID.into(),
            api_key_file: "/etc/sinter/tunnel/runtime-key".into(),
            client: "/opt/tunnel-client/tunnel-client".into(),
            targets_file: Some("/etc/sinter/targets.toml".into()),
        };
        let u = render_unit(&cfg, Path::new(EXE), "sinter-tunnel").unwrap();
        assert!(u.contains("User=sinter-tunnel"));
        assert!(u.contains("LoadCredential=runtime-key:/etc/sinter/tunnel/runtime-key"));
        assert!(u.contains(&format!("--control-plane.tunnel-id {ID}")));
        assert!(u.contains(
            "--mcp.command \"/usr/local/bin/sinter mcp --targets-file /etc/sinter/targets.toml\""
        ));
        assert!(
            !u.lines().any(|l| l.trim() == "[Install]"),
            "no [Install] section"
        );
        let cfg2 = ServeConfig {
            targets_file: None,
            ..cfg.clone()
        };
        let u2 = render_unit(&cfg2, Path::new(EXE), "sinter-tunnel").unwrap();
        assert!(
            u2.contains("--mcp.command \"/usr/local/bin/sinter mcp\""),
            "{u2}"
        );
        assert!(render_unit(&cfg, Path::new(EXE), "Bad User").is_err());
    }

    #[test]
    fn rotate_key_replaces_only_a_checked_key_file() {
        let e = Env::new();
        assert_eq!(
            init(
                &e.opts(),
                &mut fake(&[ID], Some(KEY)),
                Path::new(EXE),
                &mut Vec::new()
            )
            .unwrap(),
            0
        );
        let new = "sk-SYNTHETIC-ROTATED-KEY-9876543210";
        let mut out = Vec::new();
        let code = rotate_key(
            &e.p("conf/serve.toml"),
            &mut fake(&[], Some(new)),
            Path::new(EXE),
            false,
            &mut out,
        )
        .unwrap();
        let out = String::from_utf8(out).unwrap();
        assert_eq!(code, 0, "{out}");
        assert_eq!(
            std::fs::read_to_string(e.p("conf/runtime-key")).unwrap(),
            new
        );
        assert!(!out.contains(new) && !out.contains(KEY));
        assert_eq!(
            std::fs::read_dir(e.p("conf")).unwrap().count(),
            2,
            "no backup or temporary file"
        );
        // A widened key file is not replaced.
        std::fs::set_permissions(
            e.p("conf/runtime-key"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let err = rotate_key(
            &e.p("conf/serve.toml"),
            &mut fake(&[], Some(KEY)),
            Path::new(EXE),
            false,
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(err.message.contains("group or other"), "{}", err.message);
        assert_eq!(
            std::fs::read_to_string(e.p("conf/runtime-key")).unwrap(),
            new
        );
    }

    #[test]
    fn check_writes_nothing() {
        let e = Env::new();
        assert_eq!(
            init(
                &e.opts(),
                &mut fake(&[ID], Some(KEY)),
                Path::new(EXE),
                &mut Vec::new()
            )
            .unwrap(),
            0
        );
        let before: Vec<_> = std::fs::read_dir(e.p("conf"))
            .unwrap()
            .map(|x| x.unwrap().file_name())
            .collect();
        let mut out = Vec::new();
        assert_eq!(
            check(&e.p("conf/serve.toml"), Path::new(EXE), false, &mut out).unwrap(),
            0
        );
        let after: Vec<_> = std::fs::read_dir(e.p("conf"))
            .unwrap()
            .map(|x| x.unwrap().file_name())
            .collect();
        assert_eq!(before.len(), after.len());
        assert!(!String::from_utf8(out).unwrap().contains(KEY));
    }
}
