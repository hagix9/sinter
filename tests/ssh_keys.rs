//! Key-type / known_hosts / agent compatibility of the built-in SSH
//! transport against a throwaway unprivileged OpenSSH server.
//!
//! Opt-in: `SINTER_TEST_LOCAL_SSHD=1` (needs `sshd`, `ssh-keygen`,
//! `ssh-agent`, `ssh-add`); without it the tests skip, and under
//! `SINTER_TEST_STRICT=1` they fail. The server runs as the invoking user on a
//! free loopback port with generated host and user keys; nothing outside a
//! temporary directory is touched.
//!
//! Success means "authenticated and host key verified": on a macOS server
//! the later HOME probe fails (not a Linux target), so that specific error
//! also counts as success.

mod common;

use sinter::engine::AgentSource;
use sinter::executor::{SshConfig, SshExecutor};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

struct Kill(Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Lab {
    dir: tempfile::TempDir,
    port: u16,
    _sshd: Kill,
}

fn sshd_path() -> Option<PathBuf> {
    ["/usr/sbin/sshd", "/usr/bin/sshd"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
}

fn keygen(path: &Path, args: &[&str]) {
    let st = Command::new("ssh-keygen")
        .args(["-q", "-f"])
        .arg(path)
        .args(args)
        .status()
        .unwrap();
    assert!(st.success(), "ssh-keygen {args:?}");
}

const PASS: &str = "correct-horse-1";

impl Lab {
    fn start() -> Option<Lab> {
        Self::start_with("")
    }

    /// Like `start`, with extra `sshd_config` lines (e.g. an algorithm list).
    fn start_with(extra: &str) -> Option<Lab> {
        if std::env::var("SINTER_TEST_LOCAL_SSHD").ok().as_deref() != Some("1") {
            common::skip_or_fail("SINTER_TEST_LOCAL_SSHD not set");
            return None;
        }
        let sshd = sshd_path().expect("sshd binary required");
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        for (t, extra) in [
            ("ed25519", vec![]),
            ("ecdsa", vec![]),
            ("rsa", vec!["-b", "3072"]),
        ] {
            let mut a = vec!["-t", t, "-N", ""];
            a.extend(extra);
            keygen(&d.join(format!("hk_{t}")), &a);
        }
        let users: &[(&str, &[&str])] = &[
            ("ed25519", &["-t", "ed25519", "-N", ""]),
            ("ecdsa", &["-t", "ecdsa", "-N", ""]),
            ("rsa_openssh", &["-t", "rsa", "-b", "3072", "-N", ""]),
            (
                "rsa_pem",
                &["-t", "rsa", "-b", "3072", "-m", "PEM", "-N", ""],
            ),
            ("ed25519_enc", &["-t", "ed25519", "-N", PASS]),
            ("rsa_enc", &["-t", "rsa", "-b", "3072", "-N", PASS]),
        ];
        let mut auth = String::new();
        for (n, a) in users {
            keygen(&d.join(n), a);
            auth.push_str(&std::fs::read_to_string(d.join(format!("{n}.pub"))).unwrap());
        }
        std::fs::write(d.join("authorized_keys"), auth).unwrap();
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let cfg = format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {d}/hk_ed25519\nHostKey {d}/hk_ecdsa\nHostKey {d}/hk_rsa\n\
             AuthorizedKeysFile {d}/authorized_keys\nPidFile {d}/sshd.pid\nUsePAM no\nStrictModes no\n\
             PasswordAuthentication no\nKbdInteractiveAuthentication no\n{extra}",
            d = d.display()
        );
        std::fs::write(d.join("sshd_config"), cfg).unwrap();
        let child = Command::new(sshd)
            .args(["-D", "-e", "-f"])
            .arg(d.join("sshd_config"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let guard = Kill(child);
        for _ in 0..200 {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return Some(Lab {
                    dir,
                    port,
                    _sshd: guard,
                });
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        panic!("sshd did not start");
    }

    fn p(&self, n: &str) -> PathBuf {
        self.dir.path().join(n)
    }

    fn host_line(&self, t: &str) -> String {
        let pubkey = std::fs::read_to_string(self.p(&format!("hk_{t}.pub"))).unwrap();
        let mut f = pubkey.split_whitespace();
        format!(
            "[127.0.0.1]:{} {} {}\n",
            self.port,
            f.next().unwrap(),
            f.next().unwrap()
        )
    }

    fn known_hosts(&self, name: &str, body: &str) -> PathBuf {
        let p = self.p(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    fn cfg(&self, kh: &Path, ids: &[&str]) -> SshConfig {
        SshConfig {
            host: "127.0.0.1".into(),
            port: self.port,
            user: std::env::var("USER").unwrap(),
            known_hosts: kh.to_path_buf(),
            identity_files: ids.iter().map(|n| self.p(n)).collect(),
            host_key_alias: None,
            agent: AgentSource::Disabled,
            identities_only: false,
        }
    }
}

fn connected(r: Result<SshExecutor, sinter::error::SinterError>) -> Result<(), String> {
    match r {
        Ok(_) => Ok(()),
        Err(e) if e.message.contains("could not resolve home directory") => Ok(()),
        Err(e) => Err(e.message),
    }
}

#[test]
fn every_common_key_format_authenticates() {
    let Some(lab) = Lab::start() else { return };
    let kh = lab.known_hosts(
        "kh_all",
        &(lab.host_line("ed25519") + &lab.host_line("ecdsa")),
    );
    for k in ["ed25519", "ecdsa", "rsa_openssh", "rsa_pem"] {
        connected(SshExecutor::connect(&lab.cfg(&kh, &[k]), false))
            .unwrap_or_else(|e| panic!("{k}: {e}"));
    }
}

#[test]
fn encrypted_key_file_needs_the_agent() {
    let Some(lab) = Lab::start() else { return };
    let kh = lab.known_hosts("kh", &lab.host_line("ed25519"));
    for k in ["ed25519_enc", "rsa_enc"] {
        let e = connected(SshExecutor::connect(&lab.cfg(&kh, &[k]), false)).unwrap_err();
        assert!(
            e.contains("authentication failed") && e.contains("ssh-agent"),
            "{e}"
        );
        assert!(!e.contains(PASS));
    }
    // Loaded into an agent, the same keys work.
    let sockdir = tempfile::Builder::new()
        .prefix("sa")
        .tempdir_in("/tmp")
        .unwrap();
    let sock = sockdir.path().join("a");
    let _agent = Kill(
        Command::new("ssh-agent")
            .arg("-D")
            .arg("-a")
            .arg(&sock)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    for _ in 0..200 {
        if sock.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    let askpass = lab.p("askpass.sh");
    std::fs::write(&askpass, format!("#!/bin/sh\necho {PASS}\n")).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&askpass, std::fs::Permissions::from_mode(0o700)).unwrap();
    for k in ["ed25519_enc", "rsa_enc"] {
        let st = Command::new("ssh-add")
            .arg(lab.p(k))
            .env("SSH_AUTH_SOCK", &sock)
            .env("SSH_ASKPASS", &askpass)
            .env("SSH_ASKPASS_REQUIRE", "force")
            .env("DISPLAY", "x")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(st.success(), "ssh-add {k}");
    }
    let mut cfg = lab.cfg(&kh, &[]);
    cfg.identity_files = vec![lab.p("does-not-exist")];
    cfg.agent = AgentSource::Socket(sock.clone());
    connected(SshExecutor::connect(&cfg, false)).unwrap();
    // IdentitiesOnly: agent keys that do not match the identity file are
    // not offered; the (unencrypted) file key is used instead.
    cfg.identity_files = vec![lab.p("ecdsa")];
    cfg.identities_only = true;
    connected(SshExecutor::connect(&cfg, false)).unwrap();
    // IdentityAgent none: the agent is not consulted at all.
    cfg.identity_files = vec![lab.p("ed25519_enc")];
    cfg.identities_only = false;
    cfg.agent = AgentSource::Disabled;
    let e = connected(SshExecutor::connect(&cfg, false)).unwrap_err();
    assert!(e.contains("agent: disabled"), "{e}");
}

#[test]
fn host_enrolled_with_any_single_key_type_is_accepted() {
    let Some(lab) = Lab::start() else { return };
    for t in ["ed25519", "ecdsa", "rsa"] {
        let kh = lab.known_hosts(&format!("kh_{t}"), &lab.host_line(t));
        connected(SshExecutor::connect(&lab.cfg(&kh, &["ed25519"]), false))
            .unwrap_or_else(|e| panic!("known_hosts with only {t}: {e}"));
    }
}

#[test]
fn hashed_known_hosts_entries_are_honored() {
    let Some(lab) = Lab::start() else { return };
    let kh = lab.known_hosts("kh_hashed", &lab.host_line("ed25519"));
    let st = Command::new("ssh-keygen")
        .args(["-q", "-H", "-f"])
        .arg(&kh)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(st.success());
    assert!(std::fs::read_to_string(&kh).unwrap().starts_with("|1|"));
    connected(SshExecutor::connect(&lab.cfg(&kh, &["ed25519"]), false)).unwrap();
}

#[test]
fn host_key_policy_still_fails_closed() {
    let Some(lab) = Lab::start() else { return };
    // Wrong key of the same type.
    let other = std::fs::read_to_string(lab.p("ed25519.pub")).unwrap();
    let mut f = other.split_whitespace();
    let wrong = format!(
        "[127.0.0.1]:{} {} {}\n",
        lab.port,
        f.next().unwrap(),
        f.next().unwrap()
    );
    let kh = lab.known_hosts("kh_wrong", &wrong);
    let e = connected(SshExecutor::connect(&lab.cfg(&kh, &["ed25519"]), false)).unwrap_err();
    assert!(e.contains("mismatch"), "{e}");
    // Unknown host.
    let kh = lab.known_hosts("kh_empty", "");
    let e = connected(SshExecutor::connect(&lab.cfg(&kh, &["ed25519"]), false)).unwrap_err();
    assert!(e.contains("not present"), "{e}");
    // Portless entry must not authorize a non-default port.
    let portless = lab
        .host_line("ed25519")
        .replace(&format!("[127.0.0.1]:{}", lab.port), "127.0.0.1");
    let kh = lab.known_hosts("kh_portless", &portless);
    let e = connected(SshExecutor::connect(&lab.cfg(&kh, &["ed25519"]), false)).unwrap_err();
    assert!(e.contains("not present"), "{e}");
    // A revoked key is refused even when also listed as trusted.
    let line = lab.host_line("ed25519");
    let revoked = format!("@revoked {}{}", line, line);
    let kh = lab.known_hosts("kh_revoked", &revoked);
    let e = connected(SshExecutor::connect(&lab.cfg(&kh, &["ed25519"]), false)).unwrap_err();
    assert!(e.contains("@revoked"), "{e}");
}

#[test]
fn host_key_alias_selects_the_known_hosts_name() {
    let Some(lab) = Lab::start() else { return };
    let line = lab
        .host_line("ed25519")
        .replace("[127.0.0.1]", "[web01-key]");
    let kh = lab.known_hosts("kh_alias", &line);
    let mut cfg = lab.cfg(&kh, &["ed25519"]);
    assert!(connected(SshExecutor::connect(&cfg, false)).is_err());
    cfg.host_key_alias = Some("web01-key".into());
    connected(SshExecutor::connect(&cfg, false)).unwrap();
}

/// A server that offers only an algorithm outside Sinter's SSH policy
/// cannot establish a session: the handshake fails before any
/// authentication. Each case restricts exactly one negotiated category.
#[test]
fn server_offering_only_legacy_algorithms_is_refused() {
    for (what, extra, host_key) in [
        (
            "kex group1-sha1",
            "KexAlgorithms diffie-hellman-group1-sha1\n",
            "ed25519",
        ),
        (
            "kex group14-sha1",
            "KexAlgorithms diffie-hellman-group14-sha1\n",
            "ed25519",
        ),
        (
            "kex gex-sha1",
            "KexAlgorithms diffie-hellman-group-exchange-sha1\n",
            "ed25519",
        ),
        ("cipher 3des-cbc", "Ciphers 3des-cbc\n", "ed25519"),
        ("cipher aes256-cbc", "Ciphers aes256-cbc\n", "ed25519"),
        (
            "mac hmac-md5",
            "Ciphers aes128-ctr\nMACs hmac-md5\n",
            "ed25519",
        ),
        (
            "mac hmac-sha1",
            "Ciphers aes128-ctr\nMACs hmac-sha1\n",
            "ed25519",
        ),
        ("host key ssh-rsa", "HostKeyAlgorithms ssh-rsa\n", "rsa"),
    ] {
        let Some(lab) = Lab::start_with(extra) else {
            return;
        };
        let kh = lab.known_hosts("kh", &lab.host_line(host_key));
        let e =
            connected(SshExecutor::connect(&lab.cfg(&kh, &["ed25519"]), false)).expect_err(what);
        assert!(e.contains("handshake"), "{what}: {e}");
    }
}

/// A server restricted to algorithms inside the policy is accepted, for the
/// AEAD path, the CTR + HMAC-SHA2 path, and RSA host keys via rsa-sha2.
#[test]
fn server_offering_only_modern_algorithms_is_accepted() {
    for (what, extra, host_key) in [
        (
            "curve25519 + chacha20-poly1305",
            "KexAlgorithms curve25519-sha256\nCiphers chacha20-poly1305@openssh.com\n",
            "ed25519",
        ),
        (
            "group14-sha256 + aes128-ctr + hmac-sha2-256",
            "KexAlgorithms diffie-hellman-group14-sha256\nCiphers aes128-ctr\nMACs hmac-sha2-256\n",
            "ecdsa",
        ),
        (
            "rsa-sha2-512 host key",
            "HostKeyAlgorithms rsa-sha2-512\n",
            "rsa",
        ),
    ] {
        let Some(lab) = Lab::start_with(extra) else {
            return;
        };
        let kh = lab.known_hosts("kh", &lab.host_line(host_key));
        connected(SshExecutor::connect(&lab.cfg(&kh, &["ed25519"]), false))
            .unwrap_or_else(|e| panic!("{what}: {e}"));
    }
}

/// Without `SINTER_TEST_LOCAL_SSHD=1` the lab does not start: the tests skip,
/// and fail under `SINTER_TEST_STRICT=1` (the release gate) instead of
/// passing without a server.
#[test]
fn missing_local_sshd_fails_under_strict_mode() {
    common::assert_skips_unless_strict(
        "every_common_key_format_authenticates",
        "SINTER_TEST_LOCAL_SSHD not set",
        &[],
        &["SINTER_TEST_LOCAL_SSHD"],
    );
}
