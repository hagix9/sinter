//! `nm_connection` (DESIGN §45): the declared profile, the strict parsers
//! of NetworkManager's terse escaped output and of `busctl` replies, and the
//! comparison that decides the steps. Everything here is pure; the engine
//! observes and changes (`src/nm_engine.rs`).
//!
//! Every answer is parsed exactly: a missing, repeated or unexpected field,
//! an unknown value or an escape sequence other than `\:` and `\\` is an
//! error, never drift. The forms are the documented ones of `nmcli` and
//! `busctl`; that every supported target answers exactly so is NOT VERIFIED
//! until measured (DESIGN §45.10), and anything else fails closed.

use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::error::{Result, SinterError};
use crate::value::Value;

/// The `with` fields of `nm_connection` (§45.2).
pub const NM_FIELDS: &[&str] = &[
    "name",
    "type",
    "ifname",
    "autoconnect",
    "ipv4",
    "ipv6",
    "state",
    "active",
    "checkpoint_timeout",
];

/// The fields of `with.ipv4`.
pub const IPV4_FIELDS: &[&str] = &["method", "addresses", "gateway", "dns", "dns_search"];
/// The fields of `with.ipv6` (no `dns_search` in v1.15.0).
pub const IPV6_FIELDS: &[&str] = &["method", "addresses", "gateway", "dns"];

pub const NMCLI: &str = "/usr/bin/nmcli";
pub const BUSCTL: &str = "/usr/bin/busctl";
pub const NM_SERVICE: &str = "NetworkManager.service";
pub const NM_BUS: &str = "org.freedesktop.NetworkManager";
pub const NM_PATH: &str = "/org/freedesktop/NetworkManager";

/// The profile settings Sinter reads, in this order (`-f`).
pub const PROFILE_FIELDS: &[&str] = &[
    "connection.id",
    "connection.uuid",
    "connection.type",
    "connection.interface-name",
    "connection.autoconnect",
    "connection.master",
    "ipv4.method",
    "ipv4.addresses",
    "ipv4.gateway",
    "ipv4.dns",
    "ipv4.dns-search",
    "ipv6.method",
    "ipv6.addresses",
    "ipv6.gateway",
    "ipv6.dns",
];

/// `connection.type` of an Ethernet profile as NetworkManager stores it.
pub const ETHERNET_SETTING: &str = "802-3-ethernet";

/// Checkpoint creation flags: DELETE_NEW_CONNECTIONS (0x2) and
/// DISCONNECT_NEW_DEVICES (0x4). Never DESTROY_ALL: another checkpoint is
/// left alone (an overlapping one makes creation fail, so nothing changes).
pub const CHECKPOINT_FLAGS: u32 = 0x2 | 0x4;

pub const DEFAULT_CHECKPOINT_TIMEOUT: u32 = 90;

const IPV4_METHODS: &[&str] = &["auto", "manual", "disabled"];
const IPV6_METHODS: &[&str] = &["auto", "manual", "ignore", "disabled", "link-local"];
/// Methods NetworkManager may report for a profile Sinter did not write.
const IPV4_OBSERVED: &[&str] = &["auto", "manual", "disabled", "link-local", "shared"];
const IPV6_OBSERVED: &[&str] = &[
    "auto",
    "dhcp",
    "manual",
    "ignore",
    "disabled",
    "link-local",
    "shared",
];

fn bad(ctx: &str, msg: &str) -> SinterError {
    SinterError::schema(format!("{}: nm_connection {}", ctx, msg))
}

fn interpolated(v: &Value) -> bool {
    matches!(v, Value::Str(s) if crate::expressions::has_interpolation(s))
}

/// `name`: 1–64 bytes of printable ASCII, no leading or trailing space, not
/// starting with `-`.
pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.starts_with('-')
        && !s.starts_with(' ')
        && !s.ends_with(' ')
        && s.bytes().all(|b| (0x20..0x7f).contains(&b))
}

/// A DNS name of RFC 1123 labels (lower case, at most 253 bytes, no
/// trailing dot).
pub fn valid_dns_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// A canonical address of one family (the text Rust prints for it).
fn canonical_addr(s: &str, v6: bool) -> Option<IpAddr> {
    let a: IpAddr = s.parse().ok()?;
    if a.is_ipv6() != v6 || a.to_string() != s {
        return None;
    }
    Some(a)
}

/// A canonical interface address with prefix of one family.
fn canonical_ifaddr(s: &str, v6: bool) -> bool {
    crate::plugin::ifaddr_ok(s, 43)
        && s.split_once('/')
            .and_then(|(a, _)| a.parse::<IpAddr>().ok())
            .is_some_and(|a| a.is_ipv6() == v6)
}

/// Desired present or absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NmState {
    Present,
    Absent,
}

/// The declared IP settings of one family; `None` = not declared.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpSpec {
    pub method: Option<String>,
    pub addresses: Option<Vec<String>>,
    /// `Some("")`: no gateway.
    pub gateway: Option<String>,
    pub dns: Option<Vec<String>>,
    pub dns_search: Option<Vec<String>>,
}

/// A checked `nm_connection`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NmSpec {
    pub name: String,
    pub ifname: Option<String>,
    pub autoconnect: Option<bool>,
    pub ipv4: IpSpec,
    pub ipv6: IpSpec,
    pub state: NmState,
    pub active: Option<bool>,
    pub checkpoint_timeout: u32,
}

impl NmSpec {
    /// Check the fields. With `literal_only` (validation) an interpolated
    /// value is left for later and `None` is returned when one was found;
    /// otherwise every value must be final.
    pub fn check(
        map: &BTreeMap<String, Value>,
        ctx: &str,
        literal_only: bool,
    ) -> Result<Option<NmSpec>> {
        for k in map.keys() {
            if !NM_FIELDS.contains(&k.as_str()) {
                return Err(bad(
                    ctx,
                    &format!(
                        "has unknown field {} (802.1X, Wi-Fi and settings with secrets are not supported)",
                        k
                    ),
                ));
            }
        }
        let mut deferred = false;
        let name = match map.get("name") {
            Some(Value::Str(s)) if !interpolated(&Value::Str(s.clone())) && valid_name(s) => {
                s.clone()
            }
            Some(Value::Str(s)) if interpolated(&Value::Str(s.clone())) => {
                return Err(bad(ctx, "name must be a static string"))
            }
            Some(_) => {
                return Err(bad(
                    ctx,
                    "name must be 1-64 bytes of printable ASCII, not starting with - and without leading or trailing space",
                ))
            }
            None => return Err(bad(ctx, "requires name")),
        };
        let state = match map.get("state") {
            None | Some(Value::Null) => NmState::Present,
            Some(v) if literal_only && interpolated(v) => {
                deferred = true;
                NmState::Present
            }
            Some(Value::Str(s)) if s == "present" => NmState::Present,
            Some(Value::Str(s)) if s == "absent" => NmState::Absent,
            Some(_) => return Err(bad(ctx, "state must be present or absent")),
        };
        if state == NmState::Absent {
            if let Some(k) = map.keys().find(|k| *k != "name" && *k != "state") {
                return Err(bad(
                    ctx,
                    &format!("with state absent allows only name, not {}", k),
                ));
            }
        }
        match map.get("type") {
            None | Some(Value::Null) => {}
            Some(v) if literal_only && interpolated(v) => deferred = true,
            Some(Value::Str(s)) if s == "ethernet" => {}
            Some(_) => return Err(bad(ctx, "type must be ethernet (the only type in v1.15.0)")),
        }
        let ifname = match map.get("ifname") {
            None | Some(Value::Null) => None,
            Some(v) if literal_only && interpolated(v) => {
                deferred = true;
                None
            }
            Some(Value::Str(s)) if crate::plugin::ifname_ok(s, 15) => Some(s.clone()),
            Some(_) => {
                return Err(bad(
                    ctx,
                    "ifname must be an interface name (1-15 bytes, [A-Za-z0-9_.-], not starting with -)",
                ))
            }
        };
        let boolean = |key: &str, deferred: &mut bool| -> Result<Option<bool>> {
            match map.get(key) {
                None | Some(Value::Null) => Ok(None),
                Some(v) if literal_only && interpolated(v) => {
                    *deferred = true;
                    Ok(None)
                }
                Some(Value::Bool(b)) => Ok(Some(*b)),
                Some(_) => Err(bad(ctx, &format!("{} must be a boolean", key))),
            }
        };
        let autoconnect = boolean("autoconnect", &mut deferred)?;
        let active = boolean("active", &mut deferred)?;
        let checkpoint_timeout = match map.get("checkpoint_timeout") {
            None | Some(Value::Null) => DEFAULT_CHECKPOINT_TIMEOUT,
            Some(v) if literal_only && interpolated(v) => {
                deferred = true;
                DEFAULT_CHECKPOINT_TIMEOUT
            }
            Some(Value::Int(n)) if (30..=600).contains(n) => *n as u32,
            Some(_) => {
                return Err(bad(
                    ctx,
                    "checkpoint_timeout must be an integer from 30 to 600 (seconds)",
                ))
            }
        };
        let ipv4 = ip_spec(map.get("ipv4"), false, ctx, literal_only, &mut deferred)?;
        let ipv6 = ip_spec(map.get("ipv6"), true, ctx, literal_only, &mut deferred)?;
        if deferred {
            return Ok(None);
        }
        Ok(Some(NmSpec {
            name,
            ifname,
            autoconnect,
            ipv4,
            ipv6,
            state,
            active,
            checkpoint_timeout,
        }))
    }
}

fn ip_spec(
    v: Option<&Value>,
    v6: bool,
    ctx: &str,
    literal_only: bool,
    deferred: &mut bool,
) -> Result<IpSpec> {
    let fam = if v6 { "ipv6" } else { "ipv4" };
    let map = match v {
        None | Some(Value::Null) => return Ok(IpSpec::default()),
        Some(Value::Map(m)) => m,
        Some(_) => return Err(bad(ctx, &format!("{} must be a mapping", fam))),
    };
    let allowed = if v6 { IPV6_FIELDS } else { IPV4_FIELDS };
    for k in map.keys() {
        if !allowed.contains(&k.as_str()) {
            return Err(bad(ctx, &format!("has unknown field {}.{}", fam, k)));
        }
    }
    let mut s = IpSpec::default();
    let methods = if v6 { IPV6_METHODS } else { IPV4_METHODS };
    match map.get("method") {
        None | Some(Value::Null) => {}
        Some(x) if literal_only && interpolated(x) => *deferred = true,
        Some(Value::Str(m)) if methods.contains(&m.as_str()) => s.method = Some(m.clone()),
        Some(_) => {
            return Err(bad(
                ctx,
                &format!("{}.method must be one of {}", fam, methods.join(", ")),
            ))
        }
    }
    let list = |key: &str,
                check: &dyn Fn(&str) -> bool,
                what: &str,
                deferred: &mut bool|
     -> Result<Option<Vec<String>>> {
        match map.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(x) if literal_only && interpolated(x) => {
                *deferred = true;
                Ok(None)
            }
            Some(Value::List(items)) => {
                let mut out = Vec::new();
                for i in items {
                    match i {
                        x if literal_only && interpolated(x) => *deferred = true,
                        Value::Str(t) if check(t) => out.push(t.clone()),
                        _ => {
                            return Err(bad(
                                ctx,
                                &format!("{}.{} must be a list of {}", fam, key, what),
                            ))
                        }
                    }
                }
                if out.len() > 32 {
                    return Err(bad(
                        ctx,
                        &format!("{}.{} has more than 32 entries", fam, key),
                    ));
                }
                let mut seen = std::collections::BTreeSet::new();
                if !out.iter().all(|x| seen.insert(x.clone())) {
                    return Err(bad(ctx, &format!("{}.{} has a repeated entry", fam, key)));
                }
                Ok(Some(out))
            }
            Some(_) => Err(bad(
                ctx,
                &format!("{}.{} must be a list of {}", fam, key, what),
            )),
        }
    };
    let ifaddr = move |t: &str| canonical_ifaddr(t, v6);
    let addr = move |t: &str| canonical_addr(t, v6).is_some();
    let addr_what = if v6 {
        "canonical IPv6 addresses (RFC 5952)"
    } else {
        "IPv4 addresses without leading zeros"
    };
    s.addresses = list(
        "addresses",
        &ifaddr,
        &format!("canonical {} addresses with prefix", fam),
        deferred,
    )?;
    s.dns = list("dns", &addr, addr_what, deferred)?;
    if !v6 {
        s.dns_search = list(
            "dns_search",
            &valid_dns_name,
            "DNS names (RFC 1123 labels in lower case, at most 253 bytes)",
            deferred,
        )?;
    }
    match map.get("gateway") {
        None | Some(Value::Null) => {}
        Some(x) if literal_only && interpolated(x) => *deferred = true,
        Some(Value::Str(g)) if g.is_empty() || canonical_addr(g, v6).is_some() => {
            s.gateway = Some(g.clone())
        }
        Some(_) => {
            return Err(bad(
                ctx,
                &format!(
                    "{}.gateway must be {} (or an empty string for none)",
                    fam,
                    if v6 {
                        "a canonical IPv6 address"
                    } else {
                        "an IPv4 address"
                    }
                ),
            ))
        }
    }
    // Consistency (§45.2). Addresses or a gateway are allowed only with
    // `manual`: whether NetworkManager accepts them with `auto` is not
    // measured, so it is refused rather than assumed.
    if let Some(m) = &s.method {
        let has_addr = s.addresses.as_ref().is_some_and(|a| !a.is_empty());
        let has_gw = s.gateway.as_ref().is_some_and(|g| !g.is_empty());
        if m == "manual" && !has_addr && !*deferred {
            return Err(bad(
                ctx,
                &format!("{}.method manual needs at least one address", fam),
            ));
        }
        if m != "manual" && (has_addr || has_gw) {
            return Err(bad(
                ctx,
                &format!(
                    "{}.addresses and {}.gateway are allowed only with method manual (other combinations are not measured)",
                    fam, fam
                ),
            ));
        }
    }
    Ok(s)
}

// ---------------------------------------------------------------------------
// terse escaped output
// ---------------------------------------------------------------------------

/// Split one line of `nmcli -t -e yes` output at unescaped `:` and unescape
/// `\:` and `\\`. Any other backslash sequence, or a trailing backslash, is
/// an error.
pub fn split_terse(line: &str) -> std::result::Result<Vec<String>, String> {
    let mut out = vec![String::new()];
    let mut it = line.chars();
    while let Some(c) = it.next() {
        match c {
            '\\' => match it.next() {
                Some(':') => out.last_mut().unwrap().push(':'),
                Some('\\') => out.last_mut().unwrap().push('\\'),
                _ => return Err("an unexpected escape sequence in nmcli output".into()),
            },
            ':' => out.push(String::new()),
            c if c.is_control() => return Err("a control character in nmcli output".into()),
            c => out.last_mut().unwrap().push(c),
        }
    }
    Ok(out)
}

/// Escape a value as `nmcli -e yes` does (for the scripted target).
pub fn escape_terse(s: &str) -> String {
    s.replace('\\', "\\\\").replace(':', "\\:")
}

fn lines(text: &str) -> std::result::Result<Vec<&str>, String> {
    let body = text.strip_suffix('\n').unwrap_or(text);
    if body.is_empty() {
        return Ok(Vec::new());
    }
    let ls: Vec<&str> = body.split('\n').collect();
    if ls.iter().any(|l| l.is_empty()) {
        return Err("an empty line in nmcli output".into());
    }
    Ok(ls)
}

/// A lower-case UUID as NetworkManager prints it.
pub fn valid_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && [8, 4, 4, 4, 12].iter().zip(&parts).all(|(n, p)| {
            p.len() == *n && p.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
}

/// One profile of `-f NAME,UUID,TYPE connection show`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListEntry {
    pub name: String,
    pub uuid: String,
    pub type_: String,
}

pub fn parse_list(text: &str) -> std::result::Result<Vec<ListEntry>, String> {
    let mut out = Vec::new();
    for l in lines(text)? {
        let f = split_terse(l)?;
        if f.len() != 3 {
            return Err("a profile line without exactly NAME, UUID and TYPE".into());
        }
        if !valid_uuid(&f[1]) {
            return Err("a profile UUID in an unexpected form".into());
        }
        out.push(ListEntry {
            name: f[0].clone(),
            uuid: f[1].clone(),
            type_: f[2].clone(),
        });
    }
    let mut seen = std::collections::BTreeSet::new();
    if !out.iter().all(|e| seen.insert(e.uuid.clone())) {
        return Err("a profile UUID listed twice".into());
    }
    Ok(out)
}

/// One line of `-f NAME,UUID,DEVICE,STATE connection show --active`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveEntry {
    pub name: String,
    pub uuid: String,
    pub device: String,
    pub state: String,
}

pub fn parse_active(text: &str) -> std::result::Result<Vec<ActiveEntry>, String> {
    let mut out = Vec::new();
    for l in lines(text)? {
        let f = split_terse(l)?;
        if f.len() != 4 {
            return Err(
                "an active-profile line without exactly NAME, UUID, DEVICE and STATE".into(),
            );
        }
        if !valid_uuid(&f[1]) {
            return Err("an active-profile UUID in an unexpected form".into());
        }
        if !(f[2].is_empty() || crate::plugin::ifname_ok(&f[2], 15)) {
            return Err("an active-profile device in an unexpected form".into());
        }
        if !matches!(
            f[3].as_str(),
            "activating" | "activated" | "deactivating" | "deactivated"
        ) {
            return Err(format!("an unknown active-profile state {:?}", f[3]));
        }
        out.push(ActiveEntry {
            name: f[0].clone(),
            uuid: f[1].clone(),
            device: f[2].clone(),
            state: f[3].clone(),
        });
    }
    Ok(out)
}

/// The observed IP settings of one family (normalized).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpObs {
    pub method: String,
    pub addresses: Vec<String>,
    pub gateway: String,
    pub dns: Vec<String>,
    pub dns_search: Vec<String>,
}

/// One observed profile (normalized).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Profile {
    pub id: String,
    pub uuid: String,
    pub type_: String,
    /// `connection.master`: non-empty when the profile is a port of a
    /// bridge, bond or team (its device is a lower device of another).
    pub master: String,
    pub ifname: Option<String>,
    pub autoconnect: bool,
    pub ipv4: IpObs,
    pub ipv6: IpObs,
}

fn split_list(v: &str) -> Vec<String> {
    if v.is_empty() {
        Vec::new()
    } else {
        v.split(',').map(|s| s.trim().to_string()).collect()
    }
}

/// Normalize an observed address with prefix to the canonical text.
fn norm_ifaddr(s: &str, v6: bool) -> std::result::Result<String, String> {
    let (a, p) = s
        .split_once('/')
        .ok_or_else(|| "an address without a prefix".to_string())?;
    let ip: IpAddr = a.parse().map_err(|_| "an unreadable address".to_string())?;
    if ip.is_ipv6() != v6 {
        return Err("an address of the other family".into());
    }
    let n: u8 = p.parse().map_err(|_| "an unreadable prefix".to_string())?;
    if n > if v6 { 128 } else { 32 } || p != n.to_string() {
        return Err("an unreadable prefix".into());
    }
    Ok(format!("{}/{}", ip, n))
}

fn norm_addr(s: &str, v6: bool) -> std::result::Result<String, String> {
    let ip: IpAddr = s.parse().map_err(|_| "an unreadable address".to_string())?;
    if ip.is_ipv6() != v6 {
        return Err("an address of the other family".into());
    }
    Ok(ip.to_string())
}

/// Parse `-f <PROFILE_FIELDS> connection show uuid <uuid>`: every field
/// exactly once, nothing else.
pub fn parse_profile(text: &str) -> std::result::Result<Profile, String> {
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for l in lines(text)? {
        let f = split_terse(l)?;
        // `-e yes` escapes every colon of a value (IPv6), so a line is
        // exactly one field name and one value.
        if f.len() != 2 {
            return Err("a profile line that is not exactly one field and one value".into());
        }
        let key = f[0].clone();
        let val = f[1].clone();
        if !PROFILE_FIELDS.contains(&key.as_str()) {
            return Err(format!("an unexpected field {} in nmcli output", key));
        }
        if seen.insert(key.clone(), val).is_some() {
            return Err(format!(
                "the field {} appears more than once (two profiles?)",
                key
            ));
        }
    }
    if let Some(m) = PROFILE_FIELDS.iter().find(|f| !seen.contains_key(**f)) {
        return Err(format!("the field {} is missing in nmcli output", m));
    }
    let g = |k: &str| seen[k].clone();
    let autoconnect = match g("connection.autoconnect").as_str() {
        "yes" => true,
        "no" => false,
        other => return Err(format!("an unknown autoconnect value {:?}", other)),
    };
    let ifname = match g("connection.interface-name") {
        s if s.is_empty() => None,
        s if crate::plugin::ifname_ok(&s, 15) => Some(s),
        _ => return Err("an interface name in an unexpected form".into()),
    };
    let uuid = g("connection.uuid");
    if !valid_uuid(&uuid) {
        return Err("a profile UUID in an unexpected form".into());
    }
    let ip = |fam: &str, v6: bool| -> std::result::Result<IpObs, String> {
        let method = g(&format!("{}.method", fam));
        let known = if v6 { IPV6_OBSERVED } else { IPV4_OBSERVED };
        if !known.contains(&method.as_str()) {
            return Err(format!("an unknown {}.method value {:?}", fam, method));
        }
        let addresses = split_list(&g(&format!("{}.addresses", fam)))
            .iter()
            .map(|a| norm_ifaddr(a, v6))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let gw = g(&format!("{}.gateway", fam));
        let gateway = if gw.is_empty() {
            String::new()
        } else {
            norm_addr(&gw, v6)?
        };
        let dns = split_list(&g(&format!("{}.dns", fam)))
            .iter()
            .map(|a| norm_addr(a, v6))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let dns_search = if v6 {
            Vec::new()
        } else {
            split_list(&g("ipv4.dns-search"))
        };
        if dns_search.iter().any(|d| {
            d.is_empty()
                || d.starts_with('-')
                || !d
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        }) {
            return Err("a DNS search entry in an unexpected form".into());
        }
        Ok(IpObs {
            method,
            addresses,
            gateway,
            dns,
            dns_search,
        })
    };
    Ok(Profile {
        id: g("connection.id"),
        uuid,
        type_: g("connection.type"),
        master: g("connection.master"),
        ifname,
        autoconnect,
        ipv4: ip("ipv4", false)?,
        ipv6: ip("ipv6", true)?,
    })
}

// ---------------------------------------------------------------------------
// busctl replies
// ---------------------------------------------------------------------------

/// Tokens of a `busctl call` reply: bare words and `"…"` strings (with `\"`
/// and `\\`).
pub fn busctl_tokens(text: &str) -> std::result::Result<Vec<String>, String> {
    let t = text.strip_suffix('\n').unwrap_or(text);
    if t.contains('\n') {
        return Err("a busctl reply of more than one line".into());
    }
    let mut out = Vec::new();
    let mut it = t.chars().peekable();
    while let Some(&c) = it.peek() {
        if c == ' ' {
            it.next();
            continue;
        }
        if c == '"' {
            it.next();
            let mut s = String::new();
            loop {
                match it.next() {
                    Some('"') => break,
                    Some('\\') => match it.next() {
                        Some('"') => s.push('"'),
                        Some('\\') => s.push('\\'),
                        _ => return Err("an unexpected escape in a busctl reply".into()),
                    },
                    Some(ch) if ch.is_control() => {
                        return Err("a control character in a busctl reply".into())
                    }
                    Some(ch) => s.push(ch),
                    None => return Err("an unterminated string in a busctl reply".into()),
                }
            }
            out.push(s);
        } else {
            let mut s = String::new();
            while let Some(&ch) = it.peek() {
                if ch == ' ' {
                    break;
                }
                if ch == '"' || ch.is_control() {
                    return Err("an unexpected character in a busctl reply".into());
                }
                s.push(ch);
                it.next();
            }
            out.push(s);
        }
    }
    Ok(out)
}

fn object_path_under(p: &str, prefix: &str) -> bool {
    p.strip_prefix(prefix)
        .is_some_and(|n| !n.is_empty() && n.len() <= 10 && n.bytes().all(|b| b.is_ascii_digit()))
}

pub fn valid_device_path(p: &str) -> bool {
    object_path_under(p, "/org/freedesktop/NetworkManager/Devices/")
}

pub fn valid_checkpoint_path(p: &str) -> bool {
    object_path_under(p, "/org/freedesktop/NetworkManager/Checkpoint/")
}

/// `o "<path>"` with a path the check accepts.
pub fn parse_object_reply(
    text: &str,
    check: fn(&str) -> bool,
) -> std::result::Result<String, String> {
    let t = busctl_tokens(text)?;
    match t.as_slice() {
        [ty, p] if ty == "o" && check(p) => Ok(p.clone()),
        _ => Err("an object reply in an unexpected form".into()),
    }
}

/// `a{ss} N "k" "v" …` as a map.
pub fn parse_permissions(text: &str) -> std::result::Result<BTreeMap<String, String>, String> {
    let t = busctl_tokens(text)?;
    if t.len() < 2 || t[0] != "a{ss}" {
        return Err("a permissions reply in an unexpected form".into());
    }
    let n: usize = t[1]
        .parse()
        .map_err(|_| "a permissions count in an unexpected form".to_string())?;
    if t.len() != 2 + 2 * n {
        return Err("a permissions reply with a wrong count".into());
    }
    let mut m = BTreeMap::new();
    for kv in t[2..].chunks(2) {
        if m.insert(kv[0].clone(), kv[1].clone()).is_some() {
            return Err("a permission listed twice".into());
        }
    }
    Ok(m)
}

/// `a{su} N "<device path>" <result> …`: every device's rollback result.
/// The rollback reply covers exactly the checkpoint's devices and reports
/// result 0 for each.
pub fn rollback_ok(text: &str, devices: &[String]) -> bool {
    parse_rollback(text).is_ok_and(|m| {
        let want: std::collections::BTreeSet<&String> = devices.iter().collect();
        !m.is_empty()
            && m.keys().collect::<std::collections::BTreeSet<_>>() == want
            && m.values().all(|r| *r == 0)
    })
}

pub fn parse_rollback(text: &str) -> std::result::Result<BTreeMap<String, u32>, String> {
    let t = busctl_tokens(text)?;
    if t.len() < 2 || t[0] != "a{su}" {
        return Err("a rollback reply in an unexpected form".into());
    }
    let n: usize = t[1]
        .parse()
        .map_err(|_| "a rollback count in an unexpected form".to_string())?;
    if t.len() != 2 + 2 * n {
        return Err("a rollback reply with a wrong count".into());
    }
    let mut m = BTreeMap::new();
    for kv in t[2..].chunks(2) {
        if !valid_device_path(&kv[0]) {
            return Err("a rollback device in an unexpected form".into());
        }
        let r: u32 = kv[1]
            .parse()
            .map_err(|_| "a rollback result in an unexpected form".to_string())?;
        if m.insert(kv[0].clone(), r).is_some() {
            return Err("a rollback device listed twice".into());
        }
    }
    Ok(m)
}

/// `busctl introspect` of NetworkManager's main interface offers the three
/// checkpoint methods with the signatures Sinter calls.
pub fn introspection_has_checkpoints(text: &str) -> bool {
    let want = [
        (".CheckpointCreate", "aouu", "o"),
        (".CheckpointDestroy", "o", "-"),
        (".CheckpointRollback", "o", "a{su}"),
    ];
    want.iter().all(|(name, sig, res)| {
        text.lines()
            .filter(|l| {
                let w: Vec<&str> = l.split_whitespace().collect();
                w.len() >= 4 && w[0] == *name && w[1] == "method" && w[2] == *sig && w[3] == *res
            })
            .count()
            == 1
    })
}

// ---------------------------------------------------------------------------
// comparison and steps
// ---------------------------------------------------------------------------

/// The observed state of a declared profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    /// `None`: no profile has the name.
    pub profile: Option<Profile>,
    /// The device the profile is active on (`activated`), if any.
    pub active_on: Option<String>,
}

/// One drift item: field, observed, desired.
pub type DriftItem = (String, String, String);

/// What apply would do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Steps {
    pub create: bool,
    pub delete: bool,
    /// `(setting, value)` for `connection add` or `connection modify`.
    pub settings: Vec<(String, String)>,
    pub up: bool,
    pub down: bool,
    pub drift: Vec<DriftItem>,
}

impl Steps {
    pub fn is_empty(&self) -> bool {
        !self.create && !self.delete && self.settings.is_empty() && !self.up && !self.down
    }

    /// Labels for the change digest and the approval prompt.
    pub fn labels(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.create {
            out.push("add".to_string());
        }
        if !self.settings.is_empty() && !self.create {
            out.push("modify".to_string());
        }
        for (k, v) in &self.settings {
            out.push(format!("set {}={}", k, v));
        }
        if self.up {
            out.push("up".into());
        }
        if self.down {
            out.push("down".into());
        }
        if self.delete {
            out.push("delete".into());
        }
        out
    }
}

fn yn(b: bool) -> String {
    if b { "yes" } else { "no" }.to_string()
}

fn show_list(l: &[String]) -> String {
    l.join(",")
}

fn ip_diff(fam: &str, d: &IpSpec, o: Option<&IpObs>, out: &mut Steps) {
    let empty = IpObs::default();
    let o = o.unwrap_or(&empty);
    let created = out.create;
    let mut push = |field: &str, setting: &str, observed: String, desired: String| {
        if observed != desired || created {
            if observed != desired {
                out.drift
                    .push((field.to_string(), observed, desired.clone()));
            }
            out.settings.push((setting.to_string(), desired));
        }
    };
    if let Some(m) = &d.method {
        push(
            &format!("{}.method", fam),
            &format!("{}.method", fam),
            o.method.clone(),
            m.clone(),
        );
    }
    if let Some(a) = &d.addresses {
        push(
            &format!("{}.addresses", fam),
            &format!("{}.addresses", fam),
            show_list(&o.addresses),
            show_list(a),
        );
    }
    if let Some(g) = &d.gateway {
        push(
            &format!("{}.gateway", fam),
            &format!("{}.gateway", fam),
            o.gateway.clone(),
            g.clone(),
        );
    }
    if let Some(x) = &d.dns {
        push(
            &format!("{}.dns", fam),
            &format!("{}.dns", fam),
            show_list(&o.dns),
            show_list(x),
        );
    }
    if let Some(x) = &d.dns_search {
        push(
            &format!("{}.dns_search", fam),
            &format!("{}.dns-search", fam),
            show_list(&o.dns_search),
            show_list(x),
        );
    }
}

/// Compare the declared profile with the observation: drift per declared
/// field and the steps apply runs. Only declared fields are compared and
/// set; lists keep their order.
pub fn steps(spec: &NmSpec, obs: &Observed) -> std::result::Result<Steps, String> {
    let mut out = Steps::default();
    let active = obs.active_on.is_some();
    match (spec.state, &obs.profile) {
        (NmState::Absent, None) => return Ok(out),
        (_, Some(p)) if p.type_ != ETHERNET_SETTING => {
            return Err(format!(
                "the existing profile has type {:?}, not ethernet; Sinter neither changes nor removes a profile of another type",
                p.type_
            ))
        }
        (NmState::Absent, Some(_)) => {
            out.delete = true;
            out.drift
                .push(("state".into(), "present".into(), "absent".into()));
            return Ok(out);
        }
        (NmState::Present, Some(p)) if p.type_ != ETHERNET_SETTING => {
            return Err(format!(
                "the existing profile has type {:?}, not ethernet; Sinter does not change a profile's type",
                p.type_
            ))
        }
        (NmState::Present, None) => {
            out.create = true;
            out.drift
                .push(("state".into(), "absent".into(), "present".into()));
        }
        _ => {}
    }
    let p = obs.profile.as_ref();
    if let Some(i) = &spec.ifname {
        let o = p.and_then(|p| p.ifname.clone()).unwrap_or_default();
        if &o != i {
            out.drift.push(("ifname".into(), o, i.clone()));
            if !out.create {
                out.settings
                    .push(("connection.interface-name".into(), i.clone()));
            }
        }
    }
    if let Some(a) = spec.autoconnect {
        let o = p.map(|p| p.autoconnect);
        if o != Some(a) || out.create {
            if o != Some(a) {
                out.drift
                    .push(("autoconnect".into(), o.map(yn).unwrap_or_default(), yn(a)));
            }
            out.settings.push(("connection.autoconnect".into(), yn(a)));
        }
    }
    ip_diff("ipv4", &spec.ipv4, p.map(|p| &p.ipv4), &mut out);
    ip_diff("ipv6", &spec.ipv6, p.map(|p| &p.ipv6), &mut out);
    // An address or gateway needs the method that results to be manual
    // (other combinations are not measured).
    for (fam, d, o) in [
        ("ipv4", &spec.ipv4, p.map(|p| &p.ipv4)),
        ("ipv6", &spec.ipv6, p.map(|p| &p.ipv6)),
    ] {
        let method = d
            .method
            .clone()
            .or_else(|| o.map(|o| o.method.clone()))
            .unwrap_or_else(|| "auto".into());
        let addr = d.addresses.as_ref().is_some_and(|a| !a.is_empty());
        let gw = d.gateway.as_ref().is_some_and(|g| !g.is_empty());
        if (addr || gw) && method != "manual" {
            return Err(format!(
                "{}.addresses or {}.gateway is declared but the resulting {}.method is {}, not manual",
                fam, fam, fam, method
            ));
        }
    }
    let changed = out.create || !out.settings.is_empty();
    match spec.active {
        Some(true) => {
            if changed || !active {
                out.up = true;
                if !active {
                    out.drift.push(("active".into(), "no".into(), "yes".into()));
                }
            }
        }
        Some(false) if active => {
            out.down = true;
            out.drift.push(("active".into(), "yes".into(), "no".into()));
        }
        Some(false) | None => {}
    }
    Ok(out)
}

/// The effective value after the change, for the management-path rule.
pub struct After {
    pub ifname_before: Option<String>,
    pub ifname_after: Option<String>,
    pub autoconnect: bool,
    pub method4: String,
    pub method6: String,
    pub gateway: bool,
    pub addresses: Vec<String>,
}

pub fn after(spec: &NmSpec, obs: &Observed) -> After {
    let p = obs.profile.as_ref();
    // A created profile gets NetworkManager's defaults for what is not
    // declared; Sinter assumes the worst (autoconnect on, automatic
    // addressing) rather than the measured defaults.
    let m = |d: &Option<String>, o: Option<&IpObs>| {
        d.clone()
            .or_else(|| o.map(|o| o.method.clone()))
            .unwrap_or_else(|| "auto".into())
    };
    let gw4 = spec
        .ipv4
        .gateway
        .clone()
        .or_else(|| p.map(|p| p.ipv4.gateway.clone()))
        .unwrap_or_default();
    let gw6 = spec
        .ipv6
        .gateway
        .clone()
        .or_else(|| p.map(|p| p.ipv6.gateway.clone()))
        .unwrap_or_default();
    let mut addresses = spec
        .ipv4
        .addresses
        .clone()
        .or_else(|| p.map(|p| p.ipv4.addresses.clone()))
        .unwrap_or_default();
    addresses.extend(
        spec.ipv6
            .addresses
            .clone()
            .or_else(|| p.map(|p| p.ipv6.addresses.clone()))
            .unwrap_or_default(),
    );
    After {
        ifname_before: p.and_then(|p| p.ifname.clone()),
        ifname_after: spec
            .ifname
            .clone()
            .or_else(|| p.and_then(|p| p.ifname.clone())),
        autoconnect: spec
            .autoconnect
            .or_else(|| p.map(|p| p.autoconnect))
            .unwrap_or(true),
        method4: m(&spec.ipv4.method, p.map(|p| &p.ipv4)),
        method6: m(&spec.ipv6.method, p.map(|p| &p.ipv6)),
        gateway: !gw4.is_empty() || !gw6.is_empty(),
        addresses,
    }
}

/// The argv of the steps, in order (never through a shell). `uuid` is the
/// observed profile's UUID (`None` for a created profile, whose `up` uses
/// the UUID read after creation and is built by the engine).
pub fn modify_argv(uuid: &str, settings: &[(String, String)]) -> Vec<String> {
    let mut a = vec![
        "connection".to_string(),
        "modify".to_string(),
        "uuid".to_string(),
        uuid.to_string(),
    ];
    for (k, v) in settings {
        a.push(k.clone());
        a.push(v.clone());
    }
    a
}

pub fn add_argv(spec: &NmSpec, settings: &[(String, String)]) -> Vec<String> {
    let mut a = vec![
        "connection".to_string(),
        "add".to_string(),
        "type".to_string(),
        "ethernet".to_string(),
        "con-name".to_string(),
        spec.name.clone(),
    ];
    if let Some(i) = &spec.ifname {
        a.push("ifname".into());
        a.push(i.clone());
    }
    for (k, v) in settings {
        a.push(k.clone());
        a.push(v.clone());
    }
    a
}

pub fn uuid_argv(verb: &str, uuid: &str) -> Vec<String> {
    vec![
        "connection".to_string(),
        verb.to_string(),
        "uuid".to_string(),
        uuid.to_string(),
    ]
}

pub fn list_argv() -> Vec<String> {
    [
        "-t",
        "-e",
        "yes",
        "-f",
        "NAME,UUID,TYPE",
        "connection",
        "show",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

pub fn active_argv() -> Vec<String> {
    [
        "-t",
        "-e",
        "yes",
        "-f",
        "NAME,UUID,DEVICE,STATE",
        "connection",
        "show",
        "--active",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// `-t -e yes -f DEVICE,TYPE device`: the type of every device
/// NetworkManager knows (management interfaces must be plain Ethernet).
pub fn devices_argv() -> Vec<String> {
    ["-t", "-e", "yes", "-f", "DEVICE,TYPE", "device"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

pub fn parse_devices(text: &str) -> std::result::Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    for l in lines(text)? {
        let f = split_terse(l)?;
        if f.len() != 2 || f[0].is_empty() || f[1].is_empty() {
            return Err("a device line without exactly DEVICE and TYPE".into());
        }
        if out.insert(f[0].clone(), f[1].clone()).is_some() {
            return Err("a device listed twice".into());
        }
    }
    Ok(out)
}

pub fn profile_argv(uuid: &str) -> Vec<String> {
    vec![
        "-t".into(),
        "-e".into(),
        "yes".into(),
        "-f".into(),
        PROFILE_FIELDS.join(","),
        "connection".into(),
        "show".into(),
        "uuid".into(),
        uuid.into(),
    ]
}

fn busctl_base(verb: &str) -> Vec<String> {
    vec![
        "--system".into(),
        verb.into(),
        NM_BUS.into(),
        NM_PATH.into(),
        NM_BUS.into(),
    ]
}

pub fn introspect_argv() -> Vec<String> {
    busctl_base("introspect")
}

pub fn call_argv(method: &str, args: &[String]) -> Vec<String> {
    let mut a = busctl_base("call");
    a.push(method.into());
    a.extend(args.iter().cloned());
    a
}

pub fn checkpoint_create_argv(devices: &[String], timeout: u32) -> Vec<String> {
    let mut args = vec!["aouu".to_string(), devices.len().to_string()];
    args.extend(devices.iter().cloned());
    args.push(timeout.to_string());
    args.push(CHECKPOINT_FLAGS.to_string());
    call_argv("CheckpointCreate", &args)
}

/// The observed state as text for the change digest and the diff.
pub fn observed_summary(obs: &Observed) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    match &obs.profile {
        None => {
            m.insert("state".into(), "absent".into());
        }
        Some(p) => {
            m.insert("state".into(), "present".into());
            m.insert("uuid".into(), p.uuid.clone());
            m.insert("master".into(), p.master.clone());
            m.insert("ifname".into(), p.ifname.clone().unwrap_or_default());
            m.insert("autoconnect".into(), yn(p.autoconnect));
            for (fam, o) in [("ipv4", &p.ipv4), ("ipv6", &p.ipv6)] {
                m.insert(format!("{}.method", fam), o.method.clone());
                m.insert(format!("{}.addresses", fam), show_list(&o.addresses));
                m.insert(format!("{}.gateway", fam), o.gateway.clone());
                m.insert(format!("{}.dns", fam), show_list(&o.dns));
                if fam == "ipv4" {
                    m.insert("ipv4.dns_search".into(), show_list(&o.dns_search));
                }
            }
        }
    }
    m.insert(
        "active_on".into(),
        obs.active_on.clone().unwrap_or_default(),
    );
    m
}

/// The declared values as text (change digest, approval prompt).
pub fn desired_summary(spec: &NmSpec) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("name".into(), spec.name.clone());
    m.insert(
        "state".into(),
        match spec.state {
            NmState::Present => "present",
            NmState::Absent => "absent",
        }
        .into(),
    );
    if let Some(i) = &spec.ifname {
        m.insert("ifname".into(), i.clone());
    }
    if let Some(a) = spec.autoconnect {
        m.insert("autoconnect".into(), yn(a));
    }
    if let Some(a) = spec.active {
        m.insert("active".into(), yn(a));
    }
    for (fam, d) in [("ipv4", &spec.ipv4), ("ipv6", &spec.ipv6)] {
        if let Some(x) = &d.method {
            m.insert(format!("{}.method", fam), x.clone());
        }
        if let Some(x) = &d.addresses {
            m.insert(format!("{}.addresses", fam), show_list(x));
        }
        if let Some(x) = &d.gateway {
            m.insert(format!("{}.gateway", fam), x.clone());
        }
        if let Some(x) = &d.dns {
            m.insert(format!("{}.dns", fam), show_list(x));
        }
        if let Some(x) = &d.dns_search {
            m.insert(format!("{}.dns_search", fam), show_list(x));
        }
    }
    m.insert(
        "checkpoint_timeout".into(),
        spec.checkpoint_timeout.to_string(),
    );
    m
}

/// Whether two observations are the same state (rollback verification):
/// every observed setting, the UUID and the active device.
pub fn same_state(a: &Observed, b: &Observed) -> bool {
    a == b
}

#[cfg(test)]
#[path = "nm_tests.rs"]
mod tests;
