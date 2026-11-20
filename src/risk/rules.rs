//! Whether one change touches the management path, and what Sinter then
//! does (DESIGN §43.3, §44.4, §44.6, §45.6).
//!
//! Every function here is pure: it gets the management path and the facts
//! the engine observed, and returns `Clear`, `Affects` or `Unknown`. Anything
//! it cannot decide is `Unknown`, which is always refused.

use std::collections::BTreeSet;
use std::net::IpAddr;

use super::path::{MgmtPath, PathState, ZoneState};
use super::RiskClass;

/// Which rule judges a resource type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    /// Never on the management path (N types).
    None,
    FwServiceAbsent,
    FwPortAbsent,
    FwProtocolAbsent,
    FwInterface,
    FwSource,
    FwZoneAbsent,
    FwReload,
    NmConnection,
}

/// Result of the dynamic check for one resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dynamic {
    Clear,
    Affects(String),
    Unknown(String),
    /// Plan only: an earlier connection-risk change of the run makes this
    /// result unknowable until apply (and unknown, so refused, in apply).
    Deferred,
    /// The resource changes nothing; no check was needed.
    NoChange,
}

impl Dynamic {
    pub fn label(&self) -> &'static str {
        match self {
            Dynamic::Clear => "clear",
            Dynamic::Affects(_) => "affects",
            Dynamic::Unknown(_) => "unknown",
            Dynamic::Deferred => "deferred",
            Dynamic::NoChange => "none",
        }
    }
}

/// A recovery procedure the engine can run for an `affects` change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recovery {
    /// No guarded procedure exists (reload, or not implemented yet).
    None,
    /// firewalld: runtime first, probe, then permanent (§43.6). P3.
    FirewalldRuntimeFirst,
    /// NetworkManager checkpoint (§45.7). P4.
    NmCheckpoint,
}

/// What the engine does with a resource at its turn (§43.3 table).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Proceed,
    /// Proceed only through the guarded procedure.
    Guarded(Recovery),
    Refuse(String),
}

/// The §43.3 decision. `approved` says whether the run's approval covers
/// this resource with a matching change digest; `available` whether the
/// resource's recovery procedure can run on this target.
pub fn decide(
    class: RiskClass,
    dynamic: &Dynamic,
    approved: bool,
    recovery: Recovery,
    available: bool,
) -> Decision {
    match dynamic {
        Dynamic::NoChange => Decision::Proceed,
        Dynamic::Deferred => Decision::Refuse(
            "an earlier connection-risk change of this run makes the effect on the management path unknown; apply such changes in separate runs".into(),
        ),
        Dynamic::Unknown(why) => Decision::Refuse(format!(
            "the effect on the management path is unknown ({}); an approval never authorizes that",
            why
        )),
        Dynamic::Clear => {
            if class == RiskClass::R && !approved {
                Decision::Refuse("an R resource needs an approval".into())
            } else {
                Decision::Proceed
            }
        }
        Dynamic::Affects(why) => {
            if !approved {
                Decision::Refuse(format!(
                    "the change affects the management connection ({}) and has no approval",
                    why
                ))
            } else if recovery == Recovery::None || !available {
                Decision::Refuse(format!(
                    "the change affects the management connection ({}) and no guarded recovery procedure is available on this target, so it is refused even with an approval",
                    why
                ))
            } else {
                Decision::Guarded(recovery)
            }
        }
    }
}

/// The recovery procedure a firewalld rule can use when its change affects
/// the management path (§43.6): runtime first only where the inverse
/// operation restores the previous runtime state exactly (adding back a
/// removed service, port or protocol; removing an added source). Moving an
/// interface, deleting a zone and reloading have no such inverse.
pub fn recovery_for(kind: RuleKind) -> Recovery {
    match kind {
        RuleKind::FwServiceAbsent
        | RuleKind::FwPortAbsent
        | RuleKind::FwProtocolAbsent
        | RuleKind::FwSource => Recovery::FirewalldRuntimeFirst,
        RuleKind::NmConnection => Recovery::NmCheckpoint,
        _ => Recovery::None,
    }
}

/// One `--info-service` answer: `name` then `  key: values` lines.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceDef {
    pub ports: Vec<String>,
    pub protocols: Vec<String>,
    pub includes: Vec<String>,
    /// helpers or modules (conntrack helpers): not judged, so unknown.
    pub helpers: Vec<String>,
}

/// Parse `firewall-cmd --info-service=<s>` output strictly: every key line
/// must be one Sinter knows; anything else is an error (unknown).
pub fn parse_service_def(text: &str) -> std::result::Result<ServiceDef, String> {
    let mut d = ServiceDef::default();
    let mut lines = text.lines();
    let first = lines.next().ok_or("empty service definition")?;
    if first.trim().is_empty() || first.starts_with(' ') {
        return Err("no service name line".into());
    }
    for l in lines {
        if l.trim().is_empty() {
            continue;
        }
        let (k, v) = l.trim().split_once(':').ok_or("unreadable line")?;
        let vals: Vec<String> = v.split_whitespace().map(str::to_string).collect();
        match k {
            "ports" => d.ports = vals,
            "protocols" => d.protocols = vals,
            "includes" => d.includes = vals,
            "helpers" | "modules" => d.helpers.extend(vals),
            // These do not change which ports are allowed to the host.
            "source-ports" | "destination" | "summary" | "description" => {}
            other => return Err(format!("unknown key {}", other)),
        }
    }
    Ok(d)
}

/// What the engine observed about firewalld for one rule.
#[derive(Debug, Clone, Default)]
pub struct FwChange {
    /// The resource's zone (`zone` field), if any.
    pub zone: Option<String>,
    /// Whether the removed service's definition allows the management port
    /// (ports, protocols and included services, judged by the engine);
    /// `None` = not judged, `Err` = the definition cannot be judged.
    pub service_allows: Option<std::result::Result<bool, String>>,
    /// The removed port or range (`22/tcp`).
    pub port: Option<String>,
    /// The removed protocol.
    pub protocol: Option<String>,
    /// The interface of an interface resource.
    pub interface: Option<String>,
    /// The network of a source resource.
    pub source: Option<String>,
    /// Reload only: whether the zone the connection would be in after the
    /// reload allows the management port in the permanent configuration
    /// (`None` = unknown).
    pub permanent_allows: Option<bool>,
}

/// Does `PORT[-PORT]/PROTO` include `port`/tcp? `None` if unparseable.
pub fn port_spec_includes(spec: &str, port: u16) -> Option<bool> {
    let (range, proto) = spec.split_once('/')?;
    let (lo, hi) = match range.split_once('-') {
        Some((a, b)) => (a.parse::<u16>().ok()?, b.parse::<u16>().ok()?),
        None => {
            let p = range.parse::<u16>().ok()?;
            (p, p)
        }
    };
    if lo > hi {
        return None;
    }
    Some(proto == "tcp" && lo <= port && port <= hi)
}

/// Does `net` (`a.b.c.d/n` or IPv6 `/n`) contain `addr`? `None` if `net` is
/// not an IP network (ipset, MAC, unparseable): such a source is unknown.
pub fn cidr_contains(net: &str, addr: IpAddr) -> Option<bool> {
    let (base, len) = match net.split_once('/') {
        Some((b, l)) => (b, l.parse::<u8>().ok()?),
        None => (net, if net.contains(':') { 128 } else { 32 }),
    };
    let base: IpAddr = base.parse().ok()?;
    let addr = canonical(addr);
    match (canonical(base), addr) {
        (IpAddr::V4(b), IpAddr::V4(a)) => {
            if len > 32 {
                return None;
            }
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            Some(u32::from(b) & mask == u32::from(a) & mask)
        }
        (IpAddr::V6(b), IpAddr::V6(a)) => {
            if len > 128 {
                return None;
            }
            let mask = if len == 0 {
                0
            } else {
                u128::MAX << (128 - len)
            };
            Some(u128::from(b) & mask == u128::from(a) & mask)
        }
        _ => Some(false),
    }
}

/// IPv4-mapped IPv6 addresses compare as IPv4.
pub fn canonical(a: IpAddr) -> IpAddr {
    match a {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => a,
        },
        v4 => v4,
    }
}

fn known_path(path: &PathState) -> Result<&MgmtPath, Dynamic> {
    match path {
        PathState::Known(p) => Ok(p),
        PathState::Unknown(why) => Err(Dynamic::Unknown(format!("management path: {}", why))),
    }
}

/// The firewalld rules (§44.4, §44.6).
pub fn firewalld(kind: RuleKind, path: &PathState, change: &FwChange) -> Dynamic {
    let p = match known_path(path) {
        Ok(p) => p,
        Err(d) => return d,
    };
    if p.loopback {
        // A declared direct local connection enters through `lo`; only a
        // change that concerns `lo` can touch it.
        let lo = |s: &Option<String>| s.as_deref() == Some("lo");
        return match kind {
            RuleKind::FwInterface if lo(&change.interface) => {
                Dynamic::Affects("binds the loopback interface the connection uses".into())
            }
            RuleKind::FwSource => {
                match change.source.as_deref().map(|s| cidr_contains(s, p.client)) {
                    Some(Some(true)) => {
                        Dynamic::Affects("the source contains the loopback client address".into())
                    }
                    Some(Some(false)) => Dynamic::Clear,
                    _ => Dynamic::Unknown("source is not an IP network".into()),
                }
            }
            RuleKind::FwReload => {
                if p.loopback_reload_measured {
                    Dynamic::Clear
                } else {
                    Dynamic::Unknown(
                        "that loopback traffic survives a reload is not measured for this firewalld".into(),
                    )
                }
            }
            _ => Dynamic::Clear,
        };
    }
    let zone = match &p.zone {
        ZoneState::NoFirewalld => {
            return match kind {
                // Nothing filters the connection: removing or reloading
                // rules of a firewalld that is not running changes nothing
                // now (a later start is not this run's change).
                RuleKind::FwReload => Dynamic::Unknown("firewalld is not running".into()),
                _ => Dynamic::Clear,
            };
        }
        ZoneState::Unknown(why) => return Dynamic::Unknown(format!("management zone: {}", why)),
        ZoneState::Known { zone, by } => (zone.clone(), *by),
    };
    let in_zone = change.zone.as_deref() == Some(zone.0.as_str());
    match kind {
        RuleKind::None => Dynamic::Clear,
        RuleKind::FwServiceAbsent => {
            if !in_zone {
                return Dynamic::Clear;
            }
            match &change.service_allows {
                None => Dynamic::Unknown("the service definition was not judged".into()),
                Some(Err(why)) => {
                    Dynamic::Unknown(format!("the service definition cannot be judged: {}", why))
                }
                Some(Ok(true)) => Dynamic::Affects(format!(
                    "removes a service of the management zone {} that allows the management port",
                    zone.0
                )),
                Some(Ok(false)) => Dynamic::Clear,
            }
        }
        RuleKind::FwPortAbsent => {
            if !in_zone {
                return Dynamic::Clear;
            }
            match change
                .port
                .as_deref()
                .and_then(|s| port_spec_includes(s, p.server_port))
            {
                Some(true) => Dynamic::Affects(format!(
                    "removes the management port from the management zone {}",
                    zone.0
                )),
                Some(false) => Dynamic::Clear,
                None => Dynamic::Unknown("unreadable port".into()),
            }
        }
        RuleKind::FwProtocolAbsent => {
            if in_zone && change.protocol.as_deref() == Some("tcp") {
                Dynamic::Affects(format!("removes tcp from the management zone {}", zone.0))
            } else {
                Dynamic::Clear
            }
        }
        RuleKind::FwInterface => match change.interface.as_deref() {
            // Moving a management interface affects the connection whatever
            // decided its zone (DESIGN §44.6 calls only a non-management
            // interface clear).
            Some(i) if p.ifaces.contains(i) => Dynamic::Affects(format!(
                "changes the zone of the management interface {}",
                i
            )),
            Some(_) => Dynamic::Clear,
            None => Dynamic::Unknown("no interface".into()),
        },
        RuleKind::FwSource => match change.source.as_deref().map(|s| cidr_contains(s, p.client)) {
            Some(Some(true)) => Dynamic::Affects(
                "the source contains the management client address and decides its zone".into(),
            ),
            Some(Some(false)) => Dynamic::Clear,
            _ => Dynamic::Unknown("the source is not an IP network".into()),
        },
        RuleKind::FwZoneAbsent => {
            let z = change.zone.as_deref().unwrap_or("");
            if in_zone || p.bound_zones.contains(z) {
                Dynamic::Affects(format!(
                    "removes the management zone {} or a zone of a management interface",
                    zone.0
                ))
            } else {
                Dynamic::Clear
            }
        }
        RuleKind::FwReload => match change.permanent_allows {
            Some(true) => Dynamic::Clear,
            Some(false) => Dynamic::Affects(
                "after the reload the management zone would not allow the management port".into(),
            ),
            None => Dynamic::Unknown("the permanent configuration could not be judged".into()),
        },
        RuleKind::NmConnection => Dynamic::Unknown("not a firewalld rule".into()),
    }
}

/// What the engine observed about a NetworkManager change (§45.6).
#[derive(Debug, Clone, Default)]
pub struct NmChange {
    /// `connection.interface-name` after the change (`None` = unset).
    pub ifname: Option<String>,
    /// `connection.interface-name` before the change (an existing profile
    /// moved away from a management interface concerns it too).
    pub ifname_before: Option<String>,
    /// Devices the profile is active on now; `None` = could not be read.
    pub active_on: Option<BTreeSet<String>>,
    pub autoconnect: bool,
    pub deactivates_or_removes: bool,
    /// ipv4/ipv6 method `auto` after the change.
    pub dhcp: bool,
    pub sets_gateway: bool,
    /// Addresses (with prefix) after the change.
    pub addresses: Vec<String>,
    /// Whether routing could be read at all.
    pub routing_readable: bool,
    /// The profile is activated by this change (explicitly, created, or a
    /// changed inactive profile that autoconnects).
    pub activates: bool,
    /// The profile is a port of a bridge, bond or team (`connection.master`).
    pub port: bool,
    /// Why the devices under the management interfaces cannot be judged
    /// (a management interface that is not plain Ethernet, or device types
    /// that could not be read); `None` when they can.
    pub lower_unknown: Option<String>,
}

/// The NetworkManager rule (§45.6).
pub fn nm(path: &PathState, c: &NmChange) -> Dynamic {
    let p = match known_path(path) {
        Ok(p) => p,
        Err(d) => return d,
    };
    let Some(active) = &c.active_on else {
        return Dynamic::Unknown("the active profiles could not be read".into());
    };
    if !c.routing_readable {
        return Dynamic::Unknown("routing could not be read".into());
    }
    if let Some(why) = &c.lower_unknown {
        return Dynamic::Unknown(why.clone());
    }
    if c.port {
        return Dynamic::Unknown(
            "the profile is a port of a bridge, bond or team, whose effect on the management path is not judged".into(),
        );
    }
    for i in c.ifname.iter().chain(c.ifname_before.iter()) {
        if p.ifaces.contains(i) {
            return Dynamic::Affects(format!("concerns the management interface {}", i));
        }
    }
    if active.iter().any(|d| p.ifaces.contains(d)) {
        return Dynamic::Affects("the profile is active on a management interface".into());
    }
    if c.ifname.is_none() && (c.autoconnect || c.activates) {
        return Dynamic::Affects(
            "a profile activated or autoconnecting without an interface may take any Ethernet device".into(),
        );
    }
    if p.loopback {
        return Dynamic::Clear;
    }
    if c.dhcp {
        return Dynamic::Affects("automatic addressing may install a default route".into());
    }
    if c.sets_gateway {
        return Dynamic::Affects("a gateway installs a default route".into());
    }
    for a in &c.addresses {
        match cidr_contains(a, p.client) {
            Some(true) => {
                return Dynamic::Affects(
                    "an address prefix contains the management client address".into(),
                )
            }
            Some(false) => {}
            None => return Dynamic::Unknown(format!("unreadable address {}", a)),
        }
    }
    Dynamic::Clear
}
