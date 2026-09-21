//! Administrator-controlled named SSH target profiles.
//!
//! A `TargetRegistry` is loaded once at `sinter mcp --targets-file <path>`
//! startup, validated before the server accepts requests, and immutable for
//! the process lifetime. The MCP client may reference a target only by its
//! opaque profile name — host, port, user, known_hosts, identity files and
//! sudo are exclusively administrator-owned profile policy and never appear
//! in tool arguments.
//!
//! Profile format (TOML):
//!
//! ```toml
//! [targets.web01]
//! host = "web01.example.com"
//! port = 22
//! user = "deploy"
//! known_hosts = "/secure/path/known_hosts"
//! identity_files = ["/secure/path/id_ed25519"]
//! sudo = false
//! ```
//!
//! Loading fails closed: a missing, unreadable, malformed, or structurally
//! invalid file aborts `sinter mcp` startup with a CLI-facing error — the
//! server never runs with a partially parsed registry.

use crate::engine::SshSpec;
use crate::error::SinterError;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Conservative profile-name rule: ASCII alphanumerics, `-` and `_`, must
/// start with an alphanumeric, at most 64 chars. Names are opaque registry
/// keys — never interpreted as hostnames or filesystem paths.
fn valid_target_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileToml {
    host: String,
    #[serde(default = "default_port")]
    port: u16,
    user: String,
    known_hosts: PathBuf,
    #[serde(default)]
    identity_files: Vec<PathBuf>,
    #[serde(default)]
    sudo: bool,
}

fn default_port() -> u16 {
    22
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetsFile {
    targets: BTreeMap<String, ProfileToml>,
}

/// A validated administrator-owned target profile.
#[derive(Debug)]
pub struct TargetProfile {
    pub spec: SshSpec,
    pub sudo: bool,
}

/// Immutable startup-loaded registry keyed by opaque profile name.
/// `BTreeMap` keeps enumeration deterministic (sorted names).
#[derive(Debug, Default)]
pub struct TargetRegistry {
    targets: BTreeMap<String, TargetProfile>,
}

impl TargetRegistry {
    /// Load and validate a targets file. Any failure aborts startup.
    pub fn load(path: &Path) -> Result<Self, SinterError> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            SinterError::connect(format!("cannot read targets file {}: {e}", path.display()))
        })?;
        let parsed: TargetsFile = toml::from_str(&text).map_err(|e| {
            SinterError::schema(format!("invalid targets file {}: {e}", path.display()))
        })?;
        let mut targets = BTreeMap::new();
        for (name, p) in parsed.targets {
            if !valid_target_name(&name) {
                return Err(SinterError::schema(format!(
                    "invalid target name \"{name}\" in {} (allowed: [A-Za-z0-9_-], start alphanumeric, max 64 chars)",
                    path.display()
                )));
            }
            if p.host.trim().is_empty() {
                return Err(SinterError::schema(format!(
                    "target \"{name}\" in {}: host must not be empty",
                    path.display()
                )));
            }
            if p.user.trim().is_empty() {
                return Err(SinterError::schema(format!(
                    "target \"{name}\" in {}: user must not be empty",
                    path.display()
                )));
            }
            targets.insert(
                name,
                TargetProfile {
                    spec: SshSpec {
                        host: p.host,
                        port: p.port,
                        user: p.user,
                        known_hosts: p.known_hosts,
                        identity_files: p.identity_files,
                    },
                    sudo: p.sudo,
                },
            );
        }
        Ok(Self { targets })
    }

    /// Opaque names only — deterministic sorted order.
    pub fn names(&self) -> Vec<&str> {
        self.targets.keys().map(String::as_str).collect()
    }

    /// Resolve an opaque name to its immutable profile. No fallback: an
    /// unknown name is never interpreted as a hostname.
    pub fn get(&self, name: &str) -> Option<&TargetProfile> {
        self.targets.get(name)
    }

    /// True when the supplied string is a syntactically valid name. Used by
    /// the MCP layer to decide whether an echo is safe.
    pub fn name_is_wellformed(name: &str) -> bool {
        valid_target_name(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_tmp(body: &str) -> tempfile::NamedTempFile {
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), body).unwrap();
        f
    }

    #[test]
    fn loads_sorted_names() {
        let f = write_tmp(
            "[targets.web01]\nhost=\"h1\"\nuser=\"u\"\nknown_hosts=\"/kh\"\n\
             [targets.db01]\nhost=\"h2\"\nuser=\"u\"\nknown_hosts=\"/kh\"\nsudo=true\n",
        );
        let reg = TargetRegistry::load(f.path()).unwrap();
        assert_eq!(reg.names(), vec!["db01", "web01"]);
        assert_eq!(reg.get("web01").unwrap().spec.port, 22);
        assert!(!reg.get("web01").unwrap().sudo);
        assert!(reg.get("db01").unwrap().sudo);
        assert!(reg.get("nope").is_none());
    }

    #[test]
    fn missing_file_fails_closed() {
        assert!(TargetRegistry::load(Path::new("/nonexistent/targets.toml")).is_err());
    }

    #[test]
    fn malformed_toml_fails_closed() {
        let f = write_tmp("[targets.x\nhost=");
        assert!(TargetRegistry::load(f.path()).is_err());
    }

    #[test]
    fn invalid_profile_fails_closed() {
        for body in [
            // missing required fields
            "[targets.a]\nuser=\"u\"\nknown_hosts=\"/k\"\n",
            "[targets.a]\nhost=\"h\"\nknown_hosts=\"/k\"\n",
            "[targets.a]\nhost=\"h\"\nuser=\"u\"\n",
            // empty host/user
            "[targets.a]\nhost=\"\"\nuser=\"u\"\nknown_hosts=\"/k\"\n",
            "[targets.a]\nhost=\"h\"\nuser=\"\"\nknown_hosts=\"/k\"\n",
            // unknown profile field
            "[targets.a]\nhost=\"h\"\nuser=\"u\"\nknown_hosts=\"/k\"\npassword=\"x\"\n",
            // unknown top-level field
            "[targets.a]\nhost=\"h\"\nuser=\"u\"\nknown_hosts=\"/k\"\nextra=1\n",
            // invalid names
            "[targets.\"bad/name\"]\nhost=\"h\"\nuser=\"u\"\nknown_hosts=\"/k\"\n",
            "[targets.\"-lead\"]\nhost=\"h\"\nuser=\"u\"\nknown_hosts=\"/k\"\n",
        ] {
            let f = write_tmp(body);
            assert!(
                TargetRegistry::load(f.path()).is_err(),
                "must fail closed: {body:?}"
            );
        }
    }
}
