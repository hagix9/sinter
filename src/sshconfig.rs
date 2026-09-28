//! OpenSSH client-configuration inheritance for CLI targets.
//!
//! Sinter keeps its own SSH transport (libssh2 through the `ssh2` crate),
//! host-key policy and timeouts. What it borrows from the operator's OpenSSH
//! client is *connection parameters*: `ssh -G <host>` asks the installed
//! OpenSSH client to evaluate `~/.ssh/config` and `/etc/ssh/ssh_config`
//! exactly as `ssh <host>` would, without connecting. Sinter never parses
//! ssh_config itself.
//!
//! Inherited: `HostName`, `User`, `Port`, `IdentityFile`, `IdentitiesOnly`,
//! `IdentityAgent`, `HostKeyAlias`, the first `UserKnownHostsFile`.
//!
//! Never inherited (Sinter policy wins): `StrictHostKeyChecking`,
//! `UpdateHostKeys`, `CheckHostIP`, `GlobalKnownHostsFile` — host keys must
//! already be present in the selected known_hosts file (DESIGN §19).
//!
//! Refused (fail closed): `ProxyJump` / `ProxyCommand`. Connecting directly
//! instead would silently bypass the path the operator configured.
//!
//! Precedence, per field (first present wins):
//!
//! 1. explicit CLI option (`--user`, `--port`, `--known-hosts`, `--identity`)
//! 2. targets-file field
//! 3. OpenSSH client configuration (`ssh -G`), unless `--no-ssh-config`
//! 4. built-in default (`$USER`, 22, `~/.ssh/known_hosts`, default keys)
//!
//! This is used only by the CLI. `sinter mcp` target profiles are
//! administrator policy and are never merged with a personal ssh_config.

use crate::engine::{AgentSource, SshSpec};
use crate::error::{Result, SinterError};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// A connection request before OpenSSH inheritance: what the operator
/// stated explicitly (CLI option or targets-file field).
#[derive(Debug, Clone, Default)]
pub struct TargetRequest {
    /// Display name: the targets-file entry name, or the `--host` value.
    pub label: String,
    /// Host as given; may be an `~/.ssh/config` `Host` alias.
    pub host: String,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub known_hosts: Option<PathBuf>,
    /// Empty means "not specified".
    pub identity_files: Vec<PathBuf>,
}

/// The subset of `ssh -G` output Sinter consumes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpenSshView {
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    /// Raw `identityfile` values (may start with `~` or contain `%` tokens).
    pub identity_files: Vec<String>,
    /// First `userknownhostsfile` entry.
    pub user_known_hosts: Option<String>,
    pub host_key_alias: Option<String>,
    pub identities_only: bool,
    pub identity_agent: Option<String>,
    pub proxy_jump: Option<String>,
    pub proxy_command: Option<String>,
}

/// Parse `ssh -G` output (`keyword value...` per line, lowercase keywords).
pub fn parse_ssh_g(text: &str) -> OpenSshView {
    let mut v = OpenSshView::default();
    for line in text.lines() {
        let line = line.trim();
        let (key, value) = match line.split_once(' ') {
            Some((k, val)) => (k, val.trim()),
            None => continue,
        };
        match key {
            "hostname" => v.hostname = Some(value.to_string()),
            "user" => v.user = Some(value.to_string()),
            "port" => v.port = value.parse().ok(),
            "identityfile" => v.identity_files.push(value.to_string()),
            "userknownhostsfile" => {
                v.user_known_hosts = value.split_whitespace().next().map(str::to_string)
            }
            "hostkeyalias" => v.host_key_alias = Some(value.to_string()),
            "identitiesonly" => v.identities_only = value == "yes",
            "identityagent" => v.identity_agent = Some(value.to_string()),
            "proxyjump" if value != "none" => v.proxy_jump = Some(value.to_string()),
            "proxycommand" if value != "none" => v.proxy_command = Some(value.to_string()),
            _ => {}
        }
    }
    v
}

/// Reject host strings that could be read as options or carry a user part.
pub fn validate_host_arg(host: &str) -> Result<()> {
    if host.is_empty() {
        return Err(SinterError::schema("host must not be empty"));
    }
    if host.starts_with('-') {
        return Err(SinterError::schema(format!(
            "invalid host {:?}: must not start with '-'",
            host
        )));
    }
    if host.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(SinterError::schema(format!(
            "invalid host {:?}: whitespace and control characters are not allowed",
            host
        )));
    }
    if host.contains('@') {
        return Err(SinterError::schema(format!(
            "invalid host {:?}: give the user with --user (or a targets-file user field), not user@host",
            host
        )));
    }
    Ok(())
}

/// Bound for the local `ssh -G` evaluation (a `Match exec` could block).
const SSH_G_TIMEOUT: Duration = Duration::from_secs(10);

/// Evaluate the OpenSSH client configuration for `host` with the installed
/// `ssh` client (found on `PATH`, as `ssh <host>` in a shell would be).
/// Returns `Ok(None)` when no `ssh` client is installed, so Sinter keeps
/// working with its built-in defaults on hosts without OpenSSH.
pub fn query_openssh(
    host: &str,
    user: Option<&str>,
    port: Option<u16>,
) -> Result<Option<OpenSshView>> {
    validate_host_arg(host)?;
    let mut cmd = Command::new("ssh");
    cmd.arg("-G");
    if let Some(u) = user {
        cmd.arg("-l").arg(u);
    }
    if let Some(p) = port {
        cmd.arg("-p").arg(p.to_string());
    }
    cmd.arg("--").arg(host);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(SinterError::connect(format!(
                "cannot run the OpenSSH client to read its configuration: {}",
                e
            )))
        }
    };
    let deadline = Instant::now() + SSH_G_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(SinterError::connect(format!(
                    "evaluating the OpenSSH client configuration for {} timed out; use --no-ssh-config to skip it",
                    host
                )));
            }
            Err(e) => {
                return Err(SinterError::connect(format!(
                    "cannot evaluate the OpenSSH client configuration: {}",
                    e
                )))
            }
        }
    };
    let out = child.wait_with_output().map_err(|e| {
        SinterError::connect(format!(
            "cannot read the OpenSSH client configuration: {}",
            e
        ))
    })?;
    if !status.success() {
        let first = String::from_utf8_lossy(&out.stderr)
            .lines()
            .find(|l| !l.contains("Pseudo-terminal will not be allocated"))
            .unwrap_or("")
            .trim()
            .to_string();
        return Err(SinterError::connect(format!(
            "the OpenSSH client configuration for {} could not be evaluated (ssh -G: {}); use --no-ssh-config to skip it",
            host,
            crate::diff::sanitize_line(&first)
        )));
    }
    Ok(Some(parse_ssh_g(&String::from_utf8_lossy(&out.stdout))))
}

/// Expand a leading `~/` and the common OpenSSH `%` tokens of a path value.
fn expand_path(raw: &str, home: Option<&Path>, host: &str, user: &str, port: u16) -> PathBuf {
    let mut s = String::new();
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '%' {
            match chars.next() {
                Some('%') => s.push('%'),
                Some('d') => s.push_str(&home.map(|h| h.display().to_string()).unwrap_or_default()),
                Some('h') => s.push_str(host),
                Some('r') => s.push_str(user),
                Some('p') => s.push_str(&port.to_string()),
                Some('u') => s.push_str(&std::env::var("USER").unwrap_or_default()),
                Some(other) => {
                    s.push('%');
                    s.push(other);
                }
                None => s.push('%'),
            }
        } else {
            s.push(c);
        }
    }
    match (s.strip_prefix("~/"), home) {
        (Some(rest), Some(h)) => h.join(rest),
        _ if s == "~" => home
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from(s)),
        _ => PathBuf::from(s),
    }
}

/// Merge a request with the OpenSSH view and built-in defaults into a
/// connection spec. Pure: environment values are passed in.
pub fn resolve(
    req: &TargetRequest,
    view: Option<&OpenSshView>,
    env_user: Option<String>,
    home: Option<&Path>,
) -> Result<SshSpec> {
    validate_host_arg(&req.host)?;
    if let Some(v) = view {
        if let Some(j) = &v.proxy_jump {
            return Err(SinterError::connect(format!(
                "target {}: the OpenSSH client configuration routes this host through ProxyJump {}, which Sinter's built-in SSH transport does not support; connect directly (e.g. with --no-ssh-config)",
                req.label,
                crate::diff::sanitize_line(j)
            )));
        }
        if v.proxy_command.is_some() {
            return Err(SinterError::connect(format!(
                "target {}: the OpenSSH client configuration sets a ProxyCommand for this host, which Sinter's built-in SSH transport does not support; connect directly (e.g. with --no-ssh-config)",
                req.label
            )));
        }
    }
    let host = view
        .and_then(|v| v.hostname.clone())
        .unwrap_or_else(|| req.host.clone());
    let port = req.port.or(view.and_then(|v| v.port)).unwrap_or(22);
    let user = match req.user.clone().or(view.and_then(|v| v.user.clone())) {
        Some(u) => u,
        None => env_user
            .ok_or_else(|| SinterError::connect("--user is required when USER is not set"))?,
    };
    let known_hosts = match &req.known_hosts {
        Some(p) => p.clone(),
        None => match view.and_then(|v| v.user_known_hosts.as_deref()) {
            Some(raw) => expand_path(raw, home, &host, &user, port),
            None => home
                .ok_or_else(|| SinterError::connect("HOME is not set"))?
                .join(".ssh/known_hosts"),
        },
    };
    let identity_files = if !req.identity_files.is_empty() {
        req.identity_files.clone()
    } else {
        view.map(|v| {
            v.identity_files
                .iter()
                .map(|raw| expand_path(raw, home, &host, &user, port))
                .collect()
        })
        .unwrap_or_default()
    };
    let agent = match view.and_then(|v| v.identity_agent.as_deref()) {
        None | Some("SSH_AUTH_SOCK") => AgentSource::Env,
        Some("none") => AgentSource::Disabled,
        Some(var) if var.starts_with('$') => match std::env::var_os(&var[1..]) {
            Some(p) => AgentSource::Socket(PathBuf::from(p)),
            None => AgentSource::Disabled,
        },
        Some(p) => AgentSource::Socket(expand_path(p, home, &host, &user, port)),
    };
    Ok(SshSpec {
        host,
        port,
        user,
        known_hosts,
        identity_files,
        host_key_alias: view.and_then(|v| v.host_key_alias.clone()),
        agent,
        identities_only: view.is_some_and(|v| v.identities_only),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const G_DEFAULT: &str = "user alice\nhostname web01.example.com\nport 22\nidentitiesonly no\n\
        stricthostkeychecking ask\nidentityfile ~/.ssh/id_rsa\nidentityfile ~/.ssh/id_ecdsa\n\
        identityfile ~/.ssh/id_ed25519\nuserknownhostsfile /home/alice/.ssh/known_hosts /home/alice/.ssh/known_hosts2\n";

    const G_ALIAS: &str = "user ubuntu\nhostname 10.0.0.11\nport 2200\nidentitiesonly yes\n\
        hostkeyalias web01-key\nidentityagent /home/alice/agent.sock\nidentityfile ~/.ssh/work_ed25519\n\
        userknownhostsfile /home/alice/.ssh/kh_work /etc/kh2\n";

    fn home() -> PathBuf {
        PathBuf::from("/home/alice")
    }

    fn req(host: &str) -> TargetRequest {
        TargetRequest {
            label: host.to_string(),
            host: host.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn parses_ssh_g_output() {
        let v = parse_ssh_g(G_ALIAS);
        assert_eq!(v.hostname.as_deref(), Some("10.0.0.11"));
        assert_eq!(v.user.as_deref(), Some("ubuntu"));
        assert_eq!(v.port, Some(2200));
        assert!(v.identities_only);
        assert_eq!(v.host_key_alias.as_deref(), Some("web01-key"));
        assert_eq!(v.identity_agent.as_deref(), Some("/home/alice/agent.sock"));
        assert_eq!(v.identity_files, vec!["~/.ssh/work_ed25519"]);
        assert_eq!(
            v.user_known_hosts.as_deref(),
            Some("/home/alice/.ssh/kh_work")
        );
        assert!(v.proxy_jump.is_none() && v.proxy_command.is_none());
    }

    #[test]
    fn ssh_config_supplies_connection_parameters() {
        let v = parse_ssh_g(G_ALIAS);
        let s = resolve(&req("web01"), Some(&v), Some("local".into()), Some(&home())).unwrap();
        assert_eq!(s.host, "10.0.0.11");
        assert_eq!(s.port, 2200);
        assert_eq!(s.user, "ubuntu");
        assert_eq!(s.known_hosts, PathBuf::from("/home/alice/.ssh/kh_work"));
        assert_eq!(
            s.identity_files,
            vec![PathBuf::from("/home/alice/.ssh/work_ed25519")]
        );
        assert_eq!(s.host_key_alias.as_deref(), Some("web01-key"));
        assert_eq!(
            s.agent,
            AgentSource::Socket(PathBuf::from("/home/alice/agent.sock"))
        );
        assert!(s.identities_only);
    }

    #[test]
    fn explicit_values_override_ssh_config() {
        let v = parse_ssh_g(G_ALIAS);
        let r = TargetRequest {
            label: "web01".into(),
            host: "web01".into(),
            port: Some(22),
            user: Some("deploy".into()),
            known_hosts: Some(PathBuf::from("/secure/kh")),
            identity_files: vec![PathBuf::from("/secure/key")],
        };
        let s = resolve(&r, Some(&v), Some("local".into()), Some(&home())).unwrap();
        // HostName still maps the alias; everything stated explicitly wins.
        assert_eq!(s.host, "10.0.0.11");
        assert_eq!(s.port, 22);
        assert_eq!(s.user, "deploy");
        assert_eq!(s.known_hosts, PathBuf::from("/secure/kh"));
        assert_eq!(s.identity_files, vec![PathBuf::from("/secure/key")]);
    }

    #[test]
    fn builtin_defaults_without_ssh_config() {
        let s = resolve(&req("h.example"), None, Some("local".into()), Some(&home())).unwrap();
        assert_eq!(s.host, "h.example");
        assert_eq!(s.port, 22);
        assert_eq!(s.user, "local");
        assert_eq!(s.known_hosts, PathBuf::from("/home/alice/.ssh/known_hosts"));
        assert!(s.identity_files.is_empty());
        assert_eq!(s.agent, AgentSource::Env);
        assert!(s.host_key_alias.is_none());
        assert!(!s.identities_only);
    }

    #[test]
    fn missing_user_without_env_is_an_error() {
        let e = resolve(&req("h"), None, None, Some(&home())).unwrap_err();
        assert_eq!(e.kind, crate::error::ErrorKind::Connect);
    }

    #[test]
    fn default_ssh_g_keeps_known_hosts_default_and_expands_keys() {
        let v = parse_ssh_g(G_DEFAULT);
        let s = resolve(&req("web01.example.com"), Some(&v), None, Some(&home())).unwrap();
        assert_eq!(s.user, "alice");
        assert_eq!(s.known_hosts, PathBuf::from("/home/alice/.ssh/known_hosts"));
        assert_eq!(
            s.identity_files,
            ["id_rsa", "id_ecdsa", "id_ed25519"]
                .iter()
                .map(|n| home().join(".ssh").join(n))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn proxy_settings_fail_closed() {
        let mut v = parse_ssh_g(G_DEFAULT);
        v.proxy_jump = Some("bastion".into());
        let e = resolve(&req("web01"), Some(&v), None, Some(&home())).unwrap_err();
        assert_eq!(e.kind, crate::error::ErrorKind::Connect);
        assert!(e.message.contains("ProxyJump"), "{}", e.message);
        let v = parse_ssh_g("hostname x\nproxycommand nc %h %p\n");
        let e = resolve(&req("web01"), Some(&v), None, Some(&home())).unwrap_err();
        assert!(e.message.contains("ProxyCommand"), "{}", e.message);
        // `none` is the explicit absence of a proxy.
        let v = parse_ssh_g("hostname x\nproxycommand none\nproxyjump none\n");
        assert!(resolve(&req("web01"), Some(&v), Some("u".into()), Some(&home())).is_ok());
    }

    #[test]
    fn identity_agent_forms() {
        let agent = |line: &str| {
            let v = parse_ssh_g(&format!("hostname h\n{}\n", line));
            resolve(&req("h"), Some(&v), Some("u".into()), Some(&home()))
                .unwrap()
                .agent
        };
        assert_eq!(agent("identityagent none"), AgentSource::Disabled);
        assert_eq!(agent("identityagent SSH_AUTH_SOCK"), AgentSource::Env);
        assert_eq!(
            agent("identityagent ~/a.sock"),
            AgentSource::Socket(PathBuf::from("/home/alice/a.sock"))
        );
    }

    #[test]
    fn percent_tokens_expand() {
        let p = expand_path("%d/.ssh/%r@%h:%p%%", Some(&home()), "h", "u", 2222);
        assert_eq!(p, PathBuf::from("/home/alice/.ssh/u@h:2222%"));
    }

    #[test]
    fn host_argument_validation() {
        for bad in ["", "-oProxyCommand=x", "a b", "u@h", "h\n"] {
            assert!(validate_host_arg(bad).is_err(), "{bad:?}");
        }
        for good in ["web01", "10.0.0.1", "::1", "web-01.example.com"] {
            assert!(validate_host_arg(good).is_ok(), "{good:?}");
        }
    }
}
