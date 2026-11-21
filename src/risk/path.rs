//! Which interfaces and which firewalld zone carry the management connection
//! (DESIGN §43.3). Parsing and decisions only; the engine observes.
//!
//! The four `SSH_CONNECTION` values are read once, without `env -i`, and
//! cross-checked with `ss`: exactly one established TCP socket must have the
//! server address and port as local and the client address and port as
//! peer. The ingress interface holds the server address; the egress
//! interface is the route to the client from the server address. A loopback
//! connection is a path only when the administrator declared a direct local
//! connection. Everything else Sinter cannot establish is unknown.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use super::rules::{canonical, cidr_contains};

/// How the management zone was found (firewalld's own precedence).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneBy {
    Source,
    Interface,
    Default,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZoneState {
    /// firewalld is not running on the target.
    NoFirewalld,
    Known {
        zone: String,
        by: ZoneBy,
    },
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MgmtPath {
    pub client: IpAddr,
    pub client_port: u16,
    pub server: IpAddr,
    pub server_port: u16,
    /// Ingress and egress interfaces (one, or two with asymmetric routing).
    pub ifaces: BTreeSet<String>,
    /// A declared direct local connection over `lo`.
    pub loopback: bool,
    /// Whether it was measured that loopback traffic survives a firewalld
    /// reload on this target (P3 measurement; false until then).
    pub loopback_reload_measured: bool,
    /// The zone the connection is in now (runtime configuration).
    pub zone: ZoneState,
    /// The zone the permanent configuration puts it in (what a reload or a
    /// boot would give). Judges permanent facets and reloads.
    pub perm_zone: ZoneState,
    /// Zones the management interfaces are bound to (runtime, permanent).
    pub bound_zones: BTreeSet<String>,
    pub perm_bound_zones: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathState {
    Known(MgmtPath),
    Unknown(String),
}

/// What the engine read from the target.
#[derive(Debug, Clone, Default)]
pub struct NetFacts {
    /// `None`: no SSH connection (local target) or the probe failed.
    pub ssh_connection: Option<String>,
    pub ss: Option<String>,
    pub ip_addr: Option<String>,
    /// `ip -o route get <client> from <server>`.
    pub route: Option<String>,
    /// The administrator declared a direct local connection.
    pub loopback_declared: bool,
}

/// What the engine read from firewalld (all optional: unknown when missing).
#[derive(Debug, Clone, Default)]
pub struct FwFacts {
    pub running: bool,
    pub version: Option<String>,
    pub default_zone: Option<String>,
    /// (zone, sources, has forward ports, priority answer).
    pub zones: Option<Vec<FwZone>>,
    /// Zone each management interface is bound to (`None` = not bound);
    /// `Err` = the query failed.
    pub iface_zones: Vec<(String, std::result::Result<Option<String>, ()>)>,
    /// Non-default policies or direct rules exist (`None` = unknown).
    pub extra_rules: Option<bool>,
    /// `AllowZoneDrifting=no` is set explicitly in firewalld.conf. Anything
    /// else (yes, absent, unreadable) is not assumed safe (P3; measured per
    /// version before it is relaxed).
    pub drifting_off: bool,
    /// Interfaces NetworkManager manages (their permanent zone may be held
    /// by NetworkManager); `None` = it could not be determined.
    pub nm_managed: Option<BTreeSet<String>>,
    /// Facts of the permanent configuration (permanent facets, reload).
    pub permanent: bool,
}

#[derive(Debug, Clone)]
pub struct FwZone {
    pub name: String,
    pub sources: Vec<String>,
    pub forward_ports: bool,
    /// `Some(n)`: the zone's priority; `None`: the version has no zone
    /// priorities; `Err`: it has them but they could not be read.
    pub priority: std::result::Result<Option<i64>, ()>,
}

/// Parse `client client_port server server_port`.
pub fn parse_ssh_connection(s: &str) -> Option<(IpAddr, u16, IpAddr, u16)> {
    let f: Vec<&str> = s.trim_end_matches('\n').split(' ').collect();
    if f.len() != 4 {
        return None;
    }
    let c: IpAddr = f[0].parse().ok()?;
    let cp: u16 = f[1].parse().ok()?;
    let sv: IpAddr = f[2].parse().ok()?;
    let sp: u16 = f[3].parse().ok()?;
    if cp == 0 || sp == 0 {
        return None;
    }
    Some((canonical(c), cp, canonical(sv), sp))
}

/// Parse `addr:port` or `[v6]:port` (with an optional `%scope`).
fn parse_endpoint(s: &str) -> Option<(IpAddr, u16)> {
    let (host, port) = s.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let host = host.split('%').next()?;
    Some((canonical(host.parse().ok()?), port))
}

/// Count established sockets with this local and peer endpoint in
/// `ss -Htn state established` output (columns: Recv-Q Send-Q Local Peer).
pub fn ss_matches(ss: &str, server: (IpAddr, u16), client: (IpAddr, u16)) -> usize {
    ss.lines()
        .filter(|l| {
            let cols: Vec<&str> = l.split_whitespace().collect();
            if cols.len() < 4 {
                return false;
            }
            let n = cols.len();
            parse_endpoint(cols[n - 2]) == Some(server)
                && parse_endpoint(cols[n - 1]) == Some(client)
        })
        .count()
}

/// Interfaces holding `addr` in `ip -o addr show` output.
pub fn ifaces_with_addr(ip_addr: &str, addr: IpAddr) -> Vec<String> {
    let mut out = Vec::new();
    for l in ip_addr.lines() {
        let cols: Vec<&str> = l.split_whitespace().collect();
        // `2: eth0    inet 192.0.2.5/24 ...`
        let Some(fam) = cols.iter().position(|c| *c == "inet" || *c == "inet6") else {
            continue;
        };
        if fam < 2 {
            continue;
        }
        let name = cols[1]
            .trim_end_matches(':')
            .split('@')
            .next()
            .unwrap_or("");
        let Some(a) = cols.get(fam + 1).and_then(|c| c.split('/').next()) else {
            continue;
        };
        let a = a.split('%').next().unwrap_or(a);
        if a.parse::<IpAddr>().ok().map(canonical) == Some(addr) && !out.contains(&name.to_string())
        {
            out.push(name.to_string());
        }
    }
    out
}

/// The `dev` of `ip -o route get` output.
pub fn route_dev(route: &str) -> Option<String> {
    let cols: Vec<&str> = route.split_whitespace().collect();
    let i = cols.iter().position(|c| *c == "dev")?;
    cols.get(i + 1).map(|s| s.to_string())
}

/// Determine the management interfaces (zone left `NoFirewalld`; see
/// [`with_zone`]).
pub fn determine(n: &NetFacts) -> PathState {
    let Some(raw) = n.ssh_connection.as_deref() else {
        return PathState::Unknown(
            "no SSH_CONNECTION (local target, forced command or restricted shell)".into(),
        );
    };
    let Some((client, cp, server, sp)) = parse_ssh_connection(raw) else {
        return PathState::Unknown("SSH_CONNECTION is not four valid fields".into());
    };
    if n.loopback_declared && !(server.is_loopback() && client.is_loopback()) {
        return PathState::Unknown(
            "a direct local connection was declared, but the connection is not a loopback connection".into(),
        );
    }
    if server.is_loopback() || client.is_loopback() {
        if server.is_loopback() && client.is_loopback() && n.loopback_declared {
            // The declared loopback connection must be an established socket
            // too (P7-R2): the account can set SSH_CONNECTION itself.
            match n.ss.as_deref().map(|ss| ss_matches(ss, (server, sp), (client, cp))) {
                Some(1) => {}
                Some(0) => {
                    return PathState::Unknown(
                        "SSH_CONNECTION does not match an established socket (it may have been set by the account)".into(),
                    )
                }
                Some(_) => {
                    return PathState::Unknown("more than one socket matches SSH_CONNECTION".into())
                }
                None => return PathState::Unknown("ss could not be read".into()),
            }
            return PathState::Known(MgmtPath {
                client,
                client_port: cp,
                server,
                server_port: sp,
                ifaces: ["lo".to_string()].into_iter().collect(),
                loopback: true,
                loopback_reload_measured: false,
                zone: ZoneState::NoFirewalld,
                perm_zone: ZoneState::NoFirewalld,
                bound_zones: BTreeSet::new(),
                perm_bound_zones: BTreeSet::new(),
            });
        }
        return PathState::Unknown(if server.is_loopback() && client.is_loopback() {
            "a loopback connection may be a forward from another session; declare a direct local connection to use it".into()
        } else {
            "mixed loopback and non-loopback addresses".into()
        });
    }
    let Some(ss) = n.ss.as_deref() else {
        return PathState::Unknown("ss could not be read".into());
    };
    match ss_matches(ss, (server, sp), (client, cp)) {
        1 => {}
        0 => {
            return PathState::Unknown(
                "SSH_CONNECTION does not match an established socket (it may have been set by the account)".into(),
            )
        }
        _ => return PathState::Unknown("more than one socket matches SSH_CONNECTION".into()),
    }
    let Some(ip_addr) = n.ip_addr.as_deref() else {
        return PathState::Unknown("interface addresses could not be read".into());
    };
    let ingress = ifaces_with_addr(ip_addr, server);
    if ingress.len() != 1 {
        return PathState::Unknown(if ingress.is_empty() {
            "no interface holds the server address".into()
        } else {
            "more than one interface holds the server address".into()
        });
    }
    let Some(egress) = n.route.as_deref().and_then(route_dev) else {
        return PathState::Unknown("the route to the client could not be read".into());
    };
    let mut ifaces: BTreeSet<String> = BTreeSet::new();
    ifaces.insert(ingress[0].clone());
    ifaces.insert(egress);
    PathState::Known(MgmtPath {
        client,
        client_port: cp,
        server,
        server_port: sp,
        ifaces,
        loopback: false,
        loopback_reload_measured: false,
        zone: ZoneState::NoFirewalld,
        perm_zone: ZoneState::NoFirewalld,
        bound_zones: BTreeSet::new(),
        perm_bound_zones: BTreeSet::new(),
    })
}

/// The firewalld zone of the management connection, in firewalld's own
/// precedence (source, then interface, then default), refusing to guess.
pub fn zone_of(p: &MgmtPath, f: &FwFacts) -> ZoneState {
    if !f.running {
        return ZoneState::NoFirewalld;
    }
    let Some(zones) = &f.zones else {
        return ZoneState::Unknown("zones could not be read".into());
    };
    match f.extra_rules {
        Some(false) => {}
        Some(true) => {
            return ZoneState::Unknown("non-default policies or direct rules exist".into())
        }
        None => return ZoneState::Unknown("policies and direct rules could not be read".into()),
    }
    for z in zones {
        match z.priority {
            Ok(None) | Ok(Some(0)) => {}
            Ok(Some(_)) => {
                return ZoneState::Unknown(format!("zone {} has a non-default priority", z.name))
            }
            Err(()) => {
                return ZoneState::Unknown(format!(
                    "the priority of zone {} could not be read",
                    z.name
                ))
            }
        }
    }
    let mut by_source = Vec::new();
    for z in zones {
        for s in &z.sources {
            match cidr_contains(s, p.client) {
                Some(true) => {
                    if !by_source.contains(&z.name) {
                        by_source.push(z.name.clone())
                    }
                }
                Some(false) => {}
                None => return ZoneState::Unknown(format!("zone {} has a non-IP source", z.name)),
            }
        }
    }
    let chosen = match by_source.len() {
        1 => Some((by_source[0].clone(), ZoneBy::Source)),
        0 => None,
        _ => return ZoneState::Unknown("sources of more than one zone match the client".into()),
    };
    let chosen = match chosen {
        Some(c) => c,
        None => {
            let mut bound: BTreeSet<String> = BTreeSet::new();
            let mut unbound = false;
            for i in &p.ifaces {
                if f.permanent && f.nm_managed.as_ref().is_none_or(|m| m.contains(i)) {
                    return ZoneState::Unknown(format!(
                        "the permanent zone of interface {} may be held by NetworkManager (or that could not be determined)",
                        i
                    ));
                }
                match f.iface_zones.iter().find(|(n, _)| n == i).map(|(_, z)| z) {
                    Some(Ok(Some(z))) => {
                        bound.insert(z.clone());
                    }
                    Some(Ok(None)) => unbound = true,
                    _ => {
                        return ZoneState::Unknown(format!(
                            "the zone of interface {} could not be read",
                            i
                        ))
                    }
                }
            }
            match (bound.len(), unbound) {
                (1, false) => (bound.into_iter().next().unwrap(), ZoneBy::Interface),
                (0, true) => match &f.default_zone {
                    Some(d) => (d.clone(), ZoneBy::Default),
                    None => return ZoneState::Unknown("the default zone could not be read".into()),
                },
                _ => {
                    return ZoneState::Unknown(
                        "the management interfaces are in different zones".into(),
                    )
                }
            }
        }
    };
    if chosen.1 == ZoneBy::Source && !f.drifting_off {
        return ZoneState::Unknown(
            "the zone is decided by a source and AllowZoneDrifting is not explicitly off".into(),
        );
    }
    match zones.iter().find(|z| z.name == chosen.0) {
        Some(z) if z.forward_ports => ZoneState::Unknown(format!(
            "zone {} has forward ports; the management port firewalld sees may differ",
            z.name
        )),
        Some(_) => ZoneState::Known {
            zone: chosen.0,
            by: chosen.1,
        },
        None => ZoneState::Unknown(format!("zone {} is not in the zone list", chosen.0)),
    }
}

/// Attach the runtime and permanent zones to a known path.
pub fn with_zone(state: PathState, rt: Option<&FwFacts>, perm: Option<&FwFacts>) -> PathState {
    match state {
        PathState::Known(mut p) => {
            if !p.loopback {
                p.zone = match rt {
                    Some(f) => zone_of(&p, f),
                    None => ZoneState::Unknown("firewalld facts were not read".into()),
                };
                p.perm_zone = match perm {
                    Some(f) => zone_of(&p, f),
                    None => ZoneState::Unknown("permanent firewalld facts were not read".into()),
                };
                let bound = |f: Option<&FwFacts>| -> BTreeSet<String> {
                    f.map(|f| {
                        f.iface_zones
                            .iter()
                            .filter_map(|(_, z)| z.clone().ok().flatten())
                            .collect()
                    })
                    .unwrap_or_default()
                };
                p.bound_zones = bound(rt);
                p.perm_bound_zones = bound(perm);
            }
            PathState::Known(p)
        }
        u => u,
    }
}

/// The same path judged against the permanent configuration.
pub fn permanent_view(state: &PathState) -> PathState {
    match state {
        PathState::Known(p) => {
            let mut q = p.clone();
            q.zone = p.perm_zone.clone();
            q.bound_zones = p.perm_bound_zones.clone();
            PathState::Known(q)
        }
        u => u.clone(),
    }
}

// ---------------------------------------------------------------------------
// firewalld versions and zone priorities measured on real hosts (v1.15.0
// P7-R1, 2026-11-20: Rocky Linux 9.8 firewalld 1.3.4, Ubuntu 24.04 2.1.1,
// Ubuntu 26.04 2.3.1, Rocky Linux 10.2 2.4.3). Every other version or answer
// is unknown, never assumed.
// ---------------------------------------------------------------------------

/// The measured version without zone priorities: `--get-priority` is a usage
/// error with and without `--permanent`.
pub const FW_NO_ZONE_PRIORITY: &[&str] = &["1.3.4"];
/// The measured versions with zone priorities: the runtime `--get-priority`
/// is a usage error, so both views read `ingress-priority` and
/// `egress-priority` from `--list-all`.
pub const FW_ZONE_PRIORITY_LIST_ALL: &[&str] = &["2.1.1", "2.3.1", "2.4.3"];
/// The versions on which a reload was measured to keep established loopback
/// sessions and to accept new loopback connections once it returned (new
/// connections during the reload failed on 1.3.4, 2.3.1 and 2.4.3; R-2).
pub const FW_LOOPBACK_RELOAD_MEASURED: &[&str] = &["1.3.4", "2.1.1", "2.3.1", "2.4.3"];

/// `firewall-cmd --version`: exactly one line `MAJOR.MINOR.PATCH` (decimal,
/// at most three digits each, no leading zero) and its newline; anything
/// else (empty, extra lines, a suffix such as `-rc1`, a carriage return) is
/// not a version.
pub fn parse_fw_version(stdout: &str) -> Option<String> {
    let line = stdout.strip_suffix('\n')?;
    let parts: Vec<&str> = line.split('.').collect();
    let ok = parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 3
                && p.bytes().all(|b| b.is_ascii_digit())
                && (p.len() == 1 || !p.starts_with('0'))
        });
    ok.then(|| line.to_string())
}

/// A strict decimal integer (an optional `-`, no leading zero, no `+`).
fn strict_int(s: &str) -> Option<i64> {
    let digits = s.strip_prefix('-').unwrap_or(s);
    if digits.is_empty()
        || digits.len() > 6
        || !digits.bytes().all(|b| b.is_ascii_digit())
        || (digits.len() > 1 && digits.starts_with('0'))
        || s == "-0"
    {
        return None;
    }
    s.parse().ok()
}

/// The priority of `zone` from its `--list-all` answer (runtime or
/// permanent, as asked) for a measured `version` (R-5). `Ok(None)`: the
/// version has no zone priorities (and the answer shows none); `Ok(Some(n))`:
/// 0 when both the ingress and the egress priority are 0, otherwise a
/// non-zero one (which the zone decision treats as unknown); `Err`: an
/// unmeasured version, an answer for another zone, a missing, repeated or
/// malformed priority line, or both the old and the new form.
pub(crate) fn parse_zone_priority(
    version: &str,
    zone: &str,
    list_all: &str,
) -> Result<Option<i64>, ()> {
    let mut lines = list_all.lines();
    // The heading names the zone: `public`, `public (active)`,
    // `trusted (default, active)`.
    let head = lines.find(|l| !l.trim().is_empty()).ok_or(())?;
    if head.starts_with(' ') || head.split_whitespace().next() != Some(zone) {
        return Err(());
    }
    let (mut ingress, mut egress, mut legacy) = (Vec::new(), Vec::new(), 0usize);
    for l in list_all.lines() {
        if let Some(v) = l.strip_prefix("  ingress-priority: ") {
            ingress.push(v);
        } else if let Some(v) = l.strip_prefix("  egress-priority: ") {
            egress.push(v);
        } else if l.trim_start().starts_with("priority:")
            || l.trim_start().starts_with("ingress-priority")
            || l.trim_start().starts_with("egress-priority")
        {
            legacy += 1;
        }
    }
    if FW_NO_ZONE_PRIORITY.contains(&version) {
        return if ingress.is_empty() && egress.is_empty() && legacy == 0 {
            Ok(None)
        } else {
            Err(())
        };
    }
    if !FW_ZONE_PRIORITY_LIST_ALL.contains(&version) || legacy != 0 {
        return Err(());
    }
    let (&[i], &[e]) = (ingress.as_slice(), egress.as_slice()) else {
        return Err(());
    };
    let (i, e) = (strict_int(i).ok_or(())?, strict_int(e).ok_or(())?);
    Ok(Some(if i != 0 { i } else { e }))
}

/// Whether a reload on a declared loopback path keeps the management
/// connection for this firewalld (R-2): only a measured version.
pub fn loopback_reload_measured(version: Option<&str>) -> bool {
    version.is_some_and(|v| FW_LOOPBACK_RELOAD_MEASURED.contains(&v))
}

/// The permanent configuration a reload installs must be one the loopback
/// measurement covered (P7-R2 audit B-1, P7-R3): no permanent direct rule,
/// no permanent passthrough, `allow-host-ipv6` with the definition measured
/// for the version, and any further permanent policy disabled by its own
/// definition on 2.4.3 (the Rocky Linux 10.2 image's gateway-* policies).
/// An answer that could not be read, an enabled further policy or another
/// version's further policy is a refusal.
pub fn loopback_reload_config_ok(
    version: &str,
    direct_rules: Option<&str>,
    passthroughs: Option<&str>,
    permanent_policies: Option<&str>,
    policy_definitions: &BTreeMap<String, Option<String>>,
) -> bool {
    let empty = |s: Option<&str>| s.is_some_and(|s| s.trim().is_empty());
    let Some(policies) = permanent_policies.map(|s| s.split_whitespace().collect::<Vec<&str>>())
    else {
        return false;
    };
    let unique: BTreeSet<&str> = policies.iter().copied().collect();
    if !empty(direct_rules)
        || !empty(passthroughs)
        || unique.len() != policies.len()
        || !unique.contains("allow-host-ipv6")
        || policy_definitions.len() != unique.len()
    {
        return false;
    }
    unique.iter().all(|name| {
        let Some(Some(def)) = policy_definitions.get(*name) else {
            return false;
        };
        if *name == "allow-host-ipv6" {
            // the measured definition of this version, byte for byte
            allow_host_ipv6_measured(version).is_some_and(|m| same_policy_definition(m, def))
        } else {
            // P7-R3: a further policy counts only when its permanent
            // definition disables it (`disable: yes`), on a version whose
            // disabled policies were measured not to be applied and not to
            // affect a reload on the loopback path (2.4.3: the Rocky Linux
            // 10.2 image's gateway-* policies, P7-R1 and P7-R2). Its name is
            // never a reason; an enabled or unreadable policy is unknown.
            FW_POLICY_DISABLE_MEASURED.contains(&version) && policy_disabled(name, def)
        }
    })
}

/// The versions on which a policy's `disable: yes` was measured (P7-R2:
/// `--get-active-policies` listed only `allow-host-ipv6` while five further
/// permanent policies were disabled, and P7-R1 measured loopback sessions
/// across reloads with them present).
pub const FW_POLICY_DISABLE_MEASURED: &[&str] = &["2.4.3"];

/// The permanent `--info-policy=allow-host-ipv6` answer measured per version.
fn allow_host_ipv6_measured(version: &str) -> Option<&'static str> {
    match version {
        "1.3.4" => Some(include_str!(
            "fixtures/firewalld-1.3.4-policy-allow-host-ipv6.txt"
        )),
        "2.1.1" => Some(include_str!(
            "fixtures/firewalld-2.1.1-policy-allow-host-ipv6.txt"
        )),
        "2.3.1" => Some(include_str!(
            "fixtures/firewalld-2.3.1-policy-allow-host-ipv6.txt"
        )),
        "2.4.3" => Some(include_str!(
            "fixtures/firewalld-2.4.3-policy-allow-host-ipv6.txt"
        )),
        _ => None,
    }
}

/// The heading of an `--info-policy` answer: the name, optionally followed
/// by ` (active)` (1.3.4 prints it in the permanent view too).
fn policy_heading(def: &str) -> Option<(&str, &str)> {
    let (head, rest) = def.split_once('\n')?;
    let name = head.strip_suffix(" (active)").unwrap_or(head);
    Some((name, rest))
}

/// Two definitions are the same when their headings name the same policy
/// and every following byte is equal.
pub(crate) fn same_policy_definition(measured: &str, observed: &str) -> bool {
    match (policy_heading(measured), policy_heading(observed)) {
        (Some((a, ra)), Some((b, rb))) => a == b && ra == rb,
        _ => false,
    }
}

/// A policy definition that names `name` and has exactly one `disable`
/// line, `  disable: yes`.
pub(crate) fn policy_disabled(name: &str, def: &str) -> bool {
    let Some((head, rest)) = def.split_once('\n') else {
        return false;
    };
    let disables: Vec<&str> = rest
        .lines()
        .filter(|l| l.trim_start().starts_with("disable"))
        .collect();
    head == name && disables == ["  disable: yes"]
}
