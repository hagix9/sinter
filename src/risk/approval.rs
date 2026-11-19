//! Approval requests, approvals, use markers and the ledger (DESIGN §43.4).
//!
//! Layout under the state directory (`$XDG_STATE_HOME/sinter`, else
//! `~/.local/state/sinter`; every directory 0700, every file 0600, owned by
//! the invoking user, never a symbolic link):
//!
//! ```text
//! approval.key                    32 random bytes; keys every digest
//! approvals/<id>.json             approval records (with an HMAC)
//! approvals/by-request/<digest>   one approval per request
//! used/<request digest>           an approval that has been used
//! approval-ledger.jsonl           append-only, hash-chained events
//! ```
//!
//! Every digest of resource content is keyed with the controller key, so no
//! unkeyed digest of a secret exists in any request, record or report. The
//! records resist mistakes, stale reviews and replay; a process running as
//! the same local account can read the key and write records (DESIGN §43.4,
//! ADR 0003 §6).

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde_json::{json, Value as J};
use sha2::{Digest, Sha256};

use crate::error::{Result, SinterError};

pub const REQUEST_SCHEMA: &str = "sinter-approval-request/1";
pub const RECORD_SCHEMA: &str = "sinter-approval/1";
/// Default and maximum validity of an approval.
pub const DEFAULT_EXPIRY_SECS: u64 = 30 * 60;
pub const MAX_EXPIRY_SECS: u64 = 24 * 60 * 60;

fn err(msg: impl Into<String>) -> SinterError {
    SinterError::schema(msg.into())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// HMAC-SHA256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let ih = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(ih);
    let mut out = [0u8; 32];
    out.copy_from_slice(&outer.finalize());
    out
}

/// Keyed digest (hex) of canonical JSON.
pub fn keyed(key: &[u8], v: &J) -> String {
    hex(&hmac_sha256(key, canonical(v).as_bytes()))
}

/// Constant-time comparison of two hex digests.
pub fn same_digest(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

/// Canonical JSON: object keys sorted by their UTF-8 bytes, no whitespace,
/// serde_json's escaping of strings, integers as written.
pub fn canonical(v: &J) -> String {
    let mut s = String::new();
    write_canonical(v, &mut s);
    s
}

fn write_canonical(v: &J, out: &mut String) {
    match v {
        J::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).unwrap());
                out.push(':');
                write_canonical(&m[*k], out);
            }
            out.push('}');
        }
        J::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(x, out);
            }
            out.push(']');
        }
        other => out.push_str(&serde_json::to_string(other).unwrap()),
    }
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .map_err(|e| err(format!("cannot read random bytes: {}", e)))?;
    Ok(b)
}

/// The approval store of one controller account.
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    /// `$XDG_STATE_HOME/sinter` when `XDG_STATE_HOME` is absolute, else
    /// `$HOME/.local/state/sinter`.
    pub fn default_location() -> Result<Store> {
        let base = match std::env::var_os("XDG_STATE_HOME") {
            Some(x) if Path::new(&x).is_absolute() => PathBuf::from(x),
            _ => match std::env::var_os("HOME") {
                Some(h) if Path::new(&h).is_absolute() => PathBuf::from(h).join(".local/state"),
                _ => {
                    return Err(err(
                        "cannot locate the approval store: HOME is not absolute",
                    ))
                }
            },
        };
        Ok(Store {
            root: base.join("sinter"),
        })
    }

    pub fn at(root: &Path) -> Store {
        Store {
            root: root.to_path_buf(),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Create (0700) or check a private directory: a real directory owned
    /// by this user with no group or other permission bits.
    fn private_dir(&self, p: &Path) -> Result<()> {
        match std::fs::symlink_metadata(p) {
            Ok(m) => check_private(p, &m, true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::DirBuilder::new()
                    .recursive(false)
                    .mode(0o700)
                    .create(p)
                    .map_err(|e| err(format!("cannot create {}: {}", p.display(), e)))?;
                let m = std::fs::symlink_metadata(p)
                    .map_err(|e| err(format!("cannot inspect {}: {}", p.display(), e)))?;
                check_private(p, &m, true)
            }
            Err(e) => Err(err(format!("cannot inspect {}: {}", p.display(), e))),
        }
    }

    fn ensure(&self) -> Result<()> {
        if let Some(parent) = self.root.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| err(format!("cannot create {}: {}", parent.display(), e)))?;
        }
        self.private_dir(&self.root)?;
        for sub in ["approvals", "approvals/by-request", "used"] {
            self.private_dir(&self.root.join(sub))?;
        }
        Ok(())
    }

    /// The controller key, created on first use.
    pub fn key(&self) -> Result<Vec<u8>> {
        self.ensure()?;
        let p = self.root.join("approval.key");
        match std::fs::symlink_metadata(&p) {
            Ok(m) => {
                check_private(&p, &m, false)?;
                if m.len() != 32 {
                    return Err(err(format!("{} is not a 32-byte key", p.display())));
                }
                let mut b = Vec::new();
                File::open(&p)
                    .and_then(|mut f| f.read_to_end(&mut b))
                    .map_err(|e| err(format!("cannot read {}: {}", p.display(), e)))?;
                if b.len() != 32 {
                    return Err(err(format!("{} is not a 32-byte key", p.display())));
                }
                Ok(b)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let k = random_bytes::<32>()?;
                write_exclusive(&p, &k)?;
                Ok(k.to_vec())
            }
            Err(e) => Err(err(format!("cannot inspect {}: {}", p.display(), e))),
        }
    }

    /// Keyed digest (hex) of canonical JSON.
    pub fn keyed(&self, key: &[u8], v: &J) -> String {
        keyed(key, v)
    }

    fn record_path(&self, id: &str) -> Result<PathBuf> {
        if id.len() != 32
            || !id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(err("an approval id is 32 lowercase hex digits"));
        }
        Ok(self.root.join("approvals").join(format!("{}.json", id)))
    }

    /// Append one event to the ledger (hash-chained, under a lock).
    pub fn ledger(&self, event: &str, fields: J) -> Result<()> {
        self.ensure()?;
        let lock = open_private(&self.root.join("ledger.lock"), true)?;
        // SAFETY: flock on a file descriptor we own; released on drop.
        if unsafe { libc::flock(std::os::unix::io::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX) } != 0
        {
            return Err(err("cannot lock the approval ledger"));
        }
        let p = self.root.join("approval-ledger.jsonl");
        let prev = match std::fs::symlink_metadata(&p) {
            Ok(m) => {
                check_private(&p, &m, false)?;
                let mut s = String::new();
                File::open(&p)
                    .and_then(|mut f| f.read_to_string(&mut s))
                    .map_err(|e| err(format!("cannot read {}: {}", p.display(), e)))?;
                s.lines()
                    .last()
                    .map(|l| sha256_hex(l.as_bytes()))
                    .unwrap_or_default()
            }
            Err(_) => String::new(),
        };
        let mut obj = match fields {
            J::Object(m) => m,
            _ => serde_json::Map::new(),
        };
        obj.insert("event".into(), J::String(event.into()));
        obj.insert("time".into(), json!(now_secs()));
        obj.insert("prev_sha256".into(), J::String(prev));
        let line = canonical(&J::Object(obj));
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&p)
            .map_err(|e| err(format!("cannot open {}: {}", p.display(), e)))?;
        writeln!(f, "{}", line).map_err(|e| err(format!("cannot write the ledger: {}", e)))?;
        f.sync_all().ok();
        Ok(())
    }

    /// Ledger lines (for `sinter approvals list`).
    pub fn ledger_lines(&self) -> Result<Vec<J>> {
        let p = self.root.join("approval-ledger.jsonl");
        let mut s = String::new();
        match File::open(&p) {
            Ok(mut f) => {
                f.read_to_string(&mut s)
                    .map_err(|e| err(format!("cannot read {}: {}", p.display(), e)))?;
            }
            Err(_) => return Ok(Vec::new()),
        }
        Ok(s.lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect())
    }

    /// Write an approval request (DESIGN §43.4) for one host.
    pub fn write_request(&self, dir: &Path, host: &str, content: J, summary: J) -> Result<PathBuf> {
        if !valid_host_label(host) {
            return Err(err("the host name cannot be used in a request file name"));
        }
        std::fs::create_dir_all(dir)
            .map_err(|e| err(format!("cannot create {}: {}", dir.display(), e)))?;
        let nonce = hex(&random_bytes::<16>()?);
        let content_digest = sha256_hex(canonical(&content).as_bytes());
        let req = json!({
            "schema": REQUEST_SCHEMA,
            "content": content,
            "content_digest": content_digest,
            "summary": summary,
            "created_at": now_secs(),
            "nonce": nonce,
        });
        let p = dir.join(format!("{}.request.json", host));
        let text = serde_json::to_string_pretty(&req).unwrap() + "\n";
        crate::securefile::publish_new(&p, text.as_bytes(), 0o600)
            .map_err(|e| err(format!("cannot write {}: {}", p.display(), e)))?;
        self.ledger(
            "requested",
            json!({"host": host, "content_digest": content_digest, "request_sha256": sha256_hex(canonical(&req).as_bytes())}),
        )?;
        Ok(p)
    }

    /// Approve a request: one approval per request (exclusive marker), a
    /// record with an HMAC. `confirm` gets the request and decides (the CLI
    /// asks on a terminal for the digest prefix).
    pub fn approve(
        &self,
        request: &Path,
        expires: u64,
        approver: &str,
        confirm: impl FnOnce(&J) -> Result<bool>,
    ) -> Result<J> {
        if expires == 0 || expires > MAX_EXPIRY_SECS {
            return Err(err("an approval expires after 1 second to 24 hours"));
        }
        let key = self.key()?;
        let text = read_small(request, 4 * 1024 * 1024)?;
        let req: J =
            serde_json::from_str(&text).map_err(|_| err("the request is not valid JSON"))?;
        if req["schema"] != REQUEST_SCHEMA {
            return Err(err("not an approval request"));
        }
        let content = &req["content"];
        let content_digest = sha256_hex(canonical(content).as_bytes());
        if !same_digest(
            req["content_digest"].as_str().unwrap_or(""),
            &content_digest,
        ) {
            return Err(err(
                "the request's content digest does not match its content (edited?)",
            ));
        }
        let host = content["host"].as_str().unwrap_or("").to_string();
        if !valid_host_label(&host) {
            return Err(err("the request names no valid host"));
        }
        let request_digest = sha256_hex(canonical(&req).as_bytes());
        if !confirm(&req)? {
            return Err(err("not approved"));
        }
        let marker = self.root.join("approvals/by-request").join(&request_digest);
        write_exclusive(&marker, b"").map_err(|_| {
            err("this request has already been approved; make a new plan to approve again")
        })?;
        let resources: Vec<J> = content["resources"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter(|r| r["class"] == "R" || r["class"] == "C")
                    .map(|r| r["id"].clone())
                    .collect()
            })
            .unwrap_or_default();
        let id = hex(&random_bytes::<16>()?);
        let now = now_secs();
        let mut rec = json!({
            "schema": RECORD_SCHEMA,
            "approval_id": id,
            "request_digest": request_digest,
            "content_digest": content_digest,
            "nonce": req["nonce"],
            "host": host,
            "resources": resources,
            "changes": content["resources"].as_array().map(|a| a.iter().filter(|r| r["class"] == "R" || r["class"] == "C").map(|r| json!({"id": r["id"], "change_digest": r["change_digest"]})).collect::<Vec<_>>()).unwrap_or_default(),
            "approved_at": now,
            "expires_at": now + expires,
            "approver": approver,
        });
        let mac = self.keyed(&key, &rec);
        rec["mac"] = J::String(mac);
        let text = serde_json::to_string_pretty(&rec).unwrap() + "\n";
        write_exclusive(&self.record_path(&id)?, text.as_bytes())?;
        self.ledger(
            "approved",
            json!({"approval_id": id, "host": rec["host"], "request_digest": request_digest, "content_digest": content_digest}),
        )?;
        Ok(rec)
    }

    /// Load and authenticate one approval record.
    pub fn load(&self, id: &str) -> Result<J> {
        let key = self.key()?;
        let p = self.record_path(id)?;
        let m = std::fs::symlink_metadata(&p).map_err(|_| err(format!("no approval {}", id)))?;
        check_private(&p, &m, false)?;
        let text = read_small(&p, 1024 * 1024)?;
        let mut rec: J = serde_json::from_str(&text)
            .map_err(|_| err(format!("approval {} is not valid JSON", id)))?;
        let mac = rec["mac"].as_str().unwrap_or("").to_string();
        if let J::Object(m) = &mut rec {
            m.remove("mac");
        }
        if rec["schema"] != RECORD_SCHEMA
            || rec["approval_id"] != id
            || !same_digest(&mac, &self.keyed(&key, &rec))
        {
            return Err(err(format!(
                "approval {} fails its integrity check (altered or not made here)",
                id
            )));
        }
        rec["mac"] = J::String(mac);
        Ok(rec)
    }

    /// The before-contact use of approvals (DESIGN §43.4, steps 1 and 2):
    /// every record authentic, unexpired, unused, for a selected host, at
    /// most one per host; then every one is marked used before any contact.
    pub fn use_for_run(
        &self,
        ids: &[String],
        hosts: &BTreeSet<String>,
    ) -> Result<BTreeMap<String, J>> {
        let mut by_host: BTreeMap<String, J> = BTreeMap::new();
        let now = now_secs();
        for id in ids {
            let rec = self.load(id)?;
            let host = rec["host"].as_str().unwrap_or("").to_string();
            if !hosts.contains(&host) {
                return Err(err(format!(
                    "approval {} is for host {}, which this run does not select",
                    id, host
                )));
            }
            if rec["expires_at"].as_u64().unwrap_or(0) <= now {
                return Err(err(format!("approval {} has expired", id)));
            }
            let rd = rec["request_digest"].as_str().unwrap_or("").to_string();
            if rd.len() != 64 || !rd.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(err(format!("approval {} names no valid request", id)));
            }
            if self.root.join("used").join(&rd).exists() {
                return Err(err(format!("approval {} has already been used", id)));
            }
            if by_host.insert(host.clone(), rec).is_some() {
                return Err(err(format!("more than one approval for host {}", host)));
            }
        }
        for (host, rec) in &by_host {
            let rd = rec["request_digest"].as_str().unwrap_or("");
            write_exclusive(&self.root.join("used").join(rd), b"").map_err(|_| {
                err(format!(
                    "an approval for host {} was used by another run meanwhile",
                    host
                ))
            })?;
            self.ledger(
                "used",
                json!({"approval_id": rec["approval_id"], "host": host, "request_digest": rd}),
            )?;
        }
        Ok(by_host)
    }

    /// Records with their state (`unused`, `used`, `expired`) for listing.
    pub fn list(&self) -> Result<Vec<(J, &'static str)>> {
        let dir = self.root.join("approvals");
        let mut out = Vec::new();
        let rd = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(_) => return Ok(out),
        };
        let now = now_secs();
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let Some(id) = name.strip_suffix(".json") else {
                continue;
            };
            let Ok(rec) = self.load(id) else { continue };
            let used = self
                .root
                .join("used")
                .join(rec["request_digest"].as_str().unwrap_or("x"))
                .exists();
            let state = if used {
                "used"
            } else if rec["expires_at"].as_u64().unwrap_or(0) <= now {
                "expired"
            } else {
                "unused"
            };
            out.push((rec, state));
        }
        Ok(out)
    }
}

/// Host labels usable in file names and records.
pub fn valid_host_label(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 255
        && !h.starts_with('.')
        && !h.starts_with('-')
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':'))
}

fn check_private(p: &Path, m: &std::fs::Metadata, dir: bool) -> Result<()> {
    if m.file_type().is_symlink() {
        return Err(err(format!("{} is a symbolic link", p.display())));
    }
    if dir != m.is_dir() || (!dir && !m.is_file()) {
        return Err(err(format!("{} has the wrong file type", p.display())));
    }
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if m.uid() != euid {
        return Err(err(format!("{} is not owned by this user", p.display())));
    }
    if m.permissions().mode() & 0o077 != 0 {
        return Err(err(format!(
            "{} is accessible to group or others",
            p.display()
        )));
    }
    Ok(())
}

fn open_private(p: &Path, create: bool) -> Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)
        .map_err(|e| err(format!("cannot open {}: {}", p.display(), e)))?;
    let m = f
        .metadata()
        .map_err(|e| err(format!("cannot inspect {}: {}", p.display(), e)))?;
    check_private(p, &m, false)?;
    Ok(f)
}

fn write_exclusive(p: &Path, data: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)
        .map_err(|e| err(format!("cannot create {}: {}", p.display(), e)))?;
    f.write_all(data)
        .and_then(|_| f.sync_all())
        .map_err(|e| err(format!("cannot write {}: {}", p.display(), e)))
}

fn read_small(p: &Path, max: u64) -> Result<String> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)
        .map_err(|e| err(format!("cannot open {}: {}", p.display(), e)))?;
    let m = f
        .metadata()
        .map_err(|e| err(format!("cannot inspect {}: {}", p.display(), e)))?;
    if !m.is_file() || m.len() > max {
        return Err(err(format!(
            "{} is not a regular file of at most {} bytes",
            p.display(),
            max
        )));
    }
    let mut s = String::new();
    f.take(max)
        .read_to_string(&mut s)
        .map_err(|e| err(format!("cannot read {}: {}", p.display(), e)))?;
    Ok(s)
}
