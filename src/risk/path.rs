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

use std::collections::BTreeSet;
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
    pub zone: ZoneState,
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
    if server.is_loopback() || client.is_loopback() {
        if server.is_loopback() && client.is_loopback() && n.loopback_declared {
            return PathState::Known(MgmtPath {
                client,
                client_port: cp,
                server,
                server_port: sp,
                ifaces: ["lo".to_string()].into_iter().collect(),
                loopback: true,
                loopback_reload_measured: false,
                zone: ZoneState::NoFirewalld,
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

/// Attach the zone to a known path.
pub fn with_zone(state: PathState, f: Option<&FwFacts>) -> PathState {
    match state {
        PathState::Known(mut p) => {
            if !p.loopback {
                p.zone = match f {
                    Some(f) => zone_of(&p, f),
                    None => ZoneState::Unknown("firewalld facts were not read".into()),
                };
            }
            PathState::Known(p)
        }
        u => u,
    }
}
