//! Connection-risk control (DESIGN §43): parsing, rules, the approval store,
//! and engine runs against a scripted firewalld and network on a FakeTarget.
//!
//! Engine tests use the firewalld 0.2.0 first-party catalog and plugin byte
//! for byte. In production its control is not in force (Owner decision D-13
//! pending); tests that need it enforced install a classification table for
//! their own thread only (`test_table`), which is compiled into tests alone.

use super::approval::{self, Store};
use super::engine::{RiskContext, RiskLog};
use super::path::{self, FwFacts, FwZone, MgmtPath, NetFacts, PathState, ZoneBy, ZoneState};
use super::rules::{self, Decision, Dynamic, FwChange, NmChange, Recovery, RuleKind};
use super::*;
use crate::engine::{AggregateStatus, Engine, Mode, RunOptions, RunReport, TargetSpec};
use crate::executor::FakeTarget;
use crate::fakesys::{FakeFirewalld, FakeNet};
use crate::model::load_model_with_plugins;
use crate::plugin::{FirstPartyCatalog, PluginContext, FIRST_PARTY_CATALOGS};
use crate::result::{Change, Execution};
use serde_json::json;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const CATALOG_020: &str =
    include_str!("../../plugins/first-party/catalogs/firewalld-0.2.0.catalog.toml");
const PLUGIN_020: &str =
    include_str!("../../plugins/first-party/plugins/firewalld-0.2.0.plugin.toml");

const OBSERVE: &[&str] = &[
    "state",
    "zone_defined",
    "service_defined",
    "query_service_runtime",
    "query_service_permanent",
    "query_port_runtime",
    "query_port_permanent",
    "query_protocol_runtime",
    "query_protocol_permanent",
];
const MUTATE: &[&str] = &[
    "add_service_runtime",
    "add_service_permanent",
    "remove_service_runtime",
    "remove_service_permanent",
    "add_port_runtime",
    "add_port_permanent",
    "remove_port_runtime",
    "remove_port_permanent",
    "add_protocol_runtime",
    "add_protocol_permanent",
    "remove_protocol_runtime",
    "remove_protocol_permanent",
];

// ---------------------------------------------------------------------------
// classification tables for tests
// ---------------------------------------------------------------------------

fn always_r(_: &BTreeMap<String, Value>) -> RiskClass {
    RiskClass::R
}

const T020: &[TypeRule] = &[
    TypeRule {
        type_name: "firewalld.service",
        classify: absent_is_c,
        rule: RuleKind::FwServiceAbsent,
    },
    TypeRule {
        type_name: "firewalld.port",
        classify: absent_is_c,
        rule: RuleKind::FwPortAbsent,
    },
    TypeRule {
        type_name: "firewalld.port_range",
        classify: always_n,
        rule: RuleKind::None,
    },
    TypeRule {
        type_name: "firewalld.protocol",
        classify: absent_is_c,
        rule: RuleKind::FwProtocolAbsent,
    },
];
/// firewalld 0.2.0 with the control in force (D-13 as if approved).
static ENFORCED_020: &[CatalogRules] = &[CatalogRules {
    id: "firewalld",
    version: "0.2.0",
    sha256: "d32ac3947279ec2581a7049f9fa931d29c904c91ea2484cafaa6759fe09c3641",
    enforcement: Enforcement::Enforced,
    types: T020,
    ops: OPS_020,
}];
const TR: &[TypeRule] = &[
    TypeRule {
        type_name: "firewalld.port",
        classify: always_r,
        rule: RuleKind::FwPortAbsent,
    },
    TypeRule {
        type_name: "firewalld.service",
        classify: always_n,
        rule: RuleKind::None,
    },
];
/// firewalld 0.2.0 whose port type is R.
static R_020: &[CatalogRules] = &[CatalogRules {
    id: "firewalld",
    version: "0.2.0",
    sha256: "d32ac3947279ec2581a7049f9fa931d29c904c91ea2484cafaa6759fe09c3641",
    enforcement: Enforcement::Enforced,
    types: TR,
    ops: OPS_020,
}];
/// The classified digest is not the catalog's.
static WRONG_DIGEST_020: &[CatalogRules] = &[CatalogRules {
    id: "firewalld",
    version: "0.2.0",
    sha256: "0000000000000000000000000000000000000000000000000000000000000000",
    enforcement: Enforcement::Enforced,
    types: T020,
    ops: OPS_020,
}];
/// No entry at all for 0.2.0.
static EMPTY: &[CatalogRules] = &[];

struct TableGuard;
impl TableGuard {
    fn set(t: &'static [CatalogRules]) -> TableGuard {
        test_table::set(Some(t));
        TableGuard
    }
}
impl Drop for TableGuard {
    fn drop(&mut self) {
        test_table::set(None);
    }
}

// ---------------------------------------------------------------------------
// plugin root, recipes, fake target
// ---------------------------------------------------------------------------

fn list(ops: &[&str]) -> String {
    format!(
        "[{}]",
        ops.iter()
            .map(|o| format!("\"{}\"", o))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn write_mode(p: &Path, body: &str, mode: u32) {
    std::fs::write(p, body).unwrap();
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

struct Setup {
    _tmp: tempfile::TempDir,
    boundary: PathBuf,
    root: PathBuf,
}

impl Setup {
    fn with(catalog: &str) -> Setup {
        Setup::with_plugin(catalog, PLUGIN_020)
    }
    fn with_plugin(catalog: &str, plugin: &str) -> Setup {
        let tmp = tempfile::tempdir().unwrap();
        let boundary = tmp.path().to_path_buf();
        let root = boundary.join("plugins-root");
        for d in [&root, &root.join("catalogs"), &root.join("plugins")] {
            std::fs::create_dir(d).unwrap();
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        write_mode(
            &root.join("catalogs/firewalld-0.2.0.catalog.toml"),
            catalog,
            0o644,
        );
        write_mode(
            &root.join("plugins/firewalld-0.2.0.plugin.toml"),
            plugin,
            0o644,
        );
        let trust = format!(
            "format = 1\n\n[[catalog]]\nid = \"firewalld\"\nversion = \"0.2.0\"\nsha256 = \"{}\"\nattested_observe = {}\nallowed_mutate = {}\n\n[[plugin]]\nid = \"firewalld\"\nversion = \"0.2.0\"\nsha256 = \"{}\"\n",
            approval::sha256_hex(catalog.as_bytes()),
            list(OBSERVE),
            list(MUTATE),
            approval::sha256_hex(plugin.as_bytes())
        );
        write_mode(&root.join("trust.toml"), &trust, 0o600);
        Setup {
            _tmp: tmp,
            boundary,
            root,
        }
    }
    fn new() -> Setup {
        Setup::with(CATALOG_020)
    }
    fn ctx(&self, registry: Vec<FirstPartyCatalog>) -> PluginContext {
        PluginContext::Test {
            root: self.root.clone(),
            boundary: self.boundary.clone(),
            registry,
        }
    }
    fn model(&self, resources: &str) -> crate::error::Result<Model> {
        let p = self.boundary.join("r.yml");
        std::fs::write(
            &p,
            format!(
                "version: 1\nplugins:\n  - id: firewalld\n    version: 0.2.0\nresources:\n{}",
                resources
            ),
        )
        .unwrap();
        load_model_with_plugins(&p, &self.ctx(FIRST_PARTY_CATALOGS.to_vec()))
    }
}

fn port(id: &str, zone: &str, port: &str, state: &str) -> String {
    format!(
        "  - id: {id}\n    type: firewalld.port\n    with: {{ zone: {zone}, port: \"{port}\", state: {state} }}\n"
    )
}

fn service(id: &str, zone: &str, svc: &str, state: &str) -> String {
    format!(
        "  - id: {id}\n    type: firewalld.service\n    with: {{ zone: {zone}, service: {svc}, state: {state} }}\n"
    )
}

/// A firewalld with zones public and internal, 8080/tcp and 2222/tcp open in
/// public (runtime and permanent), eth0 bound to public.
fn fw() -> Arc<Mutex<FakeFirewalld>> {
    let mut f = FakeFirewalld::typical();
    f.zones.insert("internal".into());
    for p in ["8080/tcp", "2222/tcp"] {
        f.ports_runtime.insert(("public".into(), p.into()));
        f.ports_permanent.insert(("public".into(), p.into()));
        f.ports_runtime.insert(("internal".into(), p.into()));
        f.ports_permanent.insert(("internal".into(), p.into()));
    }
    f.services.insert("ssh-alt".into());
    f.runtime.insert(("public".into(), "ssh-alt".into()));
    f.permanent.insert(("public".into(), "ssh-alt".into()));
    f.service_ports
        .insert("ssh-alt".into(), vec!["2222/tcp".into()]);
    f.interfaces.insert("eth0".into(), "public".into());
    Arc::new(Mutex::new(f))
}

/// The network of a connection from 203.0.113.9:50000 to 192.0.2.10:<port>
/// on eth0.
fn net(server_port: u16) -> FakeNet {
    FakeNet {
        ssh_connection: Some(format!("203.0.113.9 50000 192.0.2.10 {}", server_port)),
        host_key_sha256: Some("aa".repeat(32)),
        ssh_user: Some("admin".into()),
        ss: Some(format!(
            "0 0 192.0.2.10:{} 203.0.113.9:50000\n0 0 192.0.2.10:{} 198.51.100.1:40000\n",
            server_port, server_port
        )),
        ip_addr: Some(
            "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n2: eth0    inet 192.0.2.10/24 brd 192.0.2.255 scope global eth0\\       valid_lft forever\n"
                .into(),
        ),
        default_route: Some("203.0.113.9 from 192.0.2.10 via 192.0.2.1 dev eth0 uid 0 \\    cache\n".into()),
        ..Default::default()
    }
}

fn target(fw: &Arc<Mutex<FakeFirewalld>>, n: FakeNet) -> FakeTarget {
    let mut t = FakeTarget::ubuntu2404()
        .as_root()
        .with_firewalld(fw.clone());
    t.manager.net = n;
    t
}

fn engine(model: Model, mode: Mode, t: FakeTarget, ctx: RiskContext) -> Engine {
    let opts = RunOptions {
        mode,
        sudo: false,
        target: TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(t),
    };
    Engine::new(model, opts).unwrap().with_risk(ctx)
}

fn ctx() -> RiskContext {
    RiskContext {
        host: "web01".into(),
        ..Default::default()
    }
}

fn run(
    model: Model,
    mode: Mode,
    t: FakeTarget,
    c: RiskContext,
) -> (crate::error::Result<RunReport>, RiskLog) {
    let e = engine(model, mode, t, c);
    let log = e.risk_log();
    let r = e.run();
    let l = log.lock().unwrap().clone();
    (r, l)
}

fn err_msg(r: crate::error::Result<RunReport>) -> String {
    match r {
        Ok(_) => panic!("the run was not refused"),
        Err(e) => e.message,
    }
}

fn fw_mutations(fw: &Arc<Mutex<FakeFirewalld>>) -> usize {
    fw.lock().unwrap().mutations.len()
}

fn record<'a>(l: &'a RiskLog, id: &str) -> &'a super::engine::RiskRecord {
    l.records
        .iter()
        .find(|r| r.id == id)
        .unwrap_or_else(|| panic!("no record {id}: {l:?}"))
}

fn assert_refused(
    r: &crate::error::Result<RunReport>,
    fw: &Arc<Mutex<FakeFirewalld>>,
    id: &str,
    want: &str,
) {
    match r {
        Ok(rep) => {
            let res = rep.resources.iter().find(|x| x.id == id).unwrap();
            assert_ne!(rep.status, AggregateStatus::Success, "{res:?}");
            assert_eq!(res.change, Change::None, "{res:?}");
            assert_ne!(res.execution, Execution::Succeeded, "{res:?}");
            assert!(
                res.reason.as_deref().unwrap_or("").contains(want),
                "{want}: {res:?}"
            );
        }
        Err(e) => assert!(e.message.contains(want), "{want}: {}", e.message),
    }
    assert_eq!(
        fw_mutations(fw),
        0,
        "a refused change ran a mutation: {:?}",
        fw.lock().unwrap().mutations
    );
}

// ---------------------------------------------------------------------------
// pure: parsing, CIDR, rules, decision
// ---------------------------------------------------------------------------

#[test]
fn parse_ssh_connection_strictly() {
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    assert_eq!(
        path::parse_ssh_connection("203.0.113.9 50000 192.0.2.10 22"),
        Some((ip("203.0.113.9"), 50000, ip("192.0.2.10"), 22))
    );
    assert_eq!(
        path::parse_ssh_connection("::ffff:203.0.113.9 1 ::ffff:192.0.2.10 22").map(|x| x.0),
        Some(ip("203.0.113.9"))
    );
    for bad in [
        "",
        "a b c d",
        "203.0.113.9 50000 192.0.2.10",
        "1.2.3.4 0 5.6.7.8 22",
        "1.2.3.4 1 5.6.7.8 22 x",
        "1.2.3.4  1 5.6.7.8 22",
    ] {
        assert_eq!(path::parse_ssh_connection(bad), None, "{bad:?}");
    }
}

#[test]
fn ss_ip_and_route_parsing() {
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    let ss = "0 0 192.0.2.10:22 203.0.113.9:50000\n0 0 [2001:db8::10]:22 [2001:db8::9]:41000\n0 0 [::ffff:192.0.2.10]:22 [::ffff:198.51.100.7]:5\n";
    assert_eq!(
        path::ss_matches(ss, (ip("192.0.2.10"), 22), (ip("203.0.113.9"), 50000)),
        1
    );
    assert_eq!(
        path::ss_matches(ss, (ip("2001:db8::10"), 22), (ip("2001:db8::9"), 41000)),
        1
    );
    assert_eq!(
        path::ss_matches(ss, (ip("192.0.2.10"), 22), (ip("198.51.100.7"), 5)),
        1
    );
    assert_eq!(
        path::ss_matches(ss, (ip("192.0.2.10"), 22), (ip("203.0.113.9"), 1)),
        0
    );
    let addr = "2: eth0    inet 192.0.2.10/24 brd x scope global eth0\n3: eth1@if7    inet6 2001:db8::10/64 scope global\n4: eth2    inet 192.0.2.10/32 scope global eth2\n";
    assert_eq!(
        path::ifaces_with_addr(addr, ip("2001:db8::10")),
        vec!["eth1".to_string()]
    );
    assert_eq!(path::ifaces_with_addr(addr, ip("192.0.2.10")).len(), 2);
    assert_eq!(
        path::route_dev("203.0.113.9 from 192.0.2.10 via 192.0.2.1 dev eth0 uid 0").as_deref(),
        Some("eth0")
    );
    assert_eq!(path::route_dev("unreachable"), None);
}

#[test]
fn cidr_and_ports() {
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    assert_eq!(
        rules::cidr_contains("203.0.113.0/24", ip("203.0.113.9")),
        Some(true)
    );
    assert_eq!(
        rules::cidr_contains("203.0.113.0/25", ip("203.0.113.200")),
        Some(false)
    );
    assert_eq!(rules::cidr_contains("0.0.0.0/0", ip("8.8.8.8")), Some(true));
    assert_eq!(
        rules::cidr_contains("2001:db8::/32", ip("2001:db8::9")),
        Some(true)
    );
    assert_eq!(
        rules::cidr_contains("2001:db8::/32", ip("203.0.113.9")),
        Some(false)
    );
    assert_eq!(
        rules::cidr_contains("203.0.113.9", ip("203.0.113.9")),
        Some(true)
    );
    assert_eq!(
        rules::cidr_contains("ipset:admins", ip("203.0.113.9")),
        None
    );
    assert_eq!(
        rules::cidr_contains("00:11:22:33:44:55", ip("203.0.113.9")),
        None
    );
    assert_eq!(rules::cidr_contains("10.0.0.0/33", ip("10.0.0.1")), None);
    assert_eq!(rules::port_spec_includes("22/tcp", 22), Some(true));
    assert_eq!(rules::port_spec_includes("20-30/tcp", 22), Some(true));
    assert_eq!(rules::port_spec_includes("22/udp", 22), Some(false));
    assert_eq!(rules::port_spec_includes("30-20/tcp", 22), None);
    assert_eq!(rules::port_spec_includes("x/tcp", 22), None);
}

fn known(zone: ZoneState, ifaces: &[&str]) -> PathState {
    PathState::Known(MgmtPath {
        client: "203.0.113.9".parse().unwrap(),
        client_port: 50000,
        server: "192.0.2.10".parse().unwrap(),
        server_port: 22,
        ifaces: ifaces.iter().map(|s| s.to_string()).collect(),
        loopback: false,
        loopback_reload_measured: false,
        zone,
    })
}

#[test]
fn firewalld_rules() {
    let pub_if = known(
        ZoneState::Known {
            zone: "public".into(),
            by: ZoneBy::Interface,
        },
        &["eth0"],
    );
    let pub_src = known(
        ZoneState::Known {
            zone: "public".into(),
            by: ZoneBy::Source,
        },
        &["eth0"],
    );
    let c = |zone: &str| FwChange {
        zone: Some(zone.into()),
        ..Default::default()
    };
    // service absent
    let mut ch = c("public");
    ch.service_ports = Some(vec!["22/tcp".into()]);
    assert!(matches!(
        rules::firewalld(RuleKind::FwServiceAbsent, &pub_if, &ch),
        Dynamic::Affects(_)
    ));
    ch.service_ports = Some(vec!["80/tcp".into()]);
    assert_eq!(
        rules::firewalld(RuleKind::FwServiceAbsent, &pub_if, &ch),
        Dynamic::Clear
    );
    ch.service_ports = None;
    assert!(matches!(
        rules::firewalld(RuleKind::FwServiceAbsent, &pub_if, &ch),
        Dynamic::Unknown(_)
    ));
    let mut other = c("internal");
    other.service_ports = Some(vec!["22/tcp".into()]);
    assert_eq!(
        rules::firewalld(RuleKind::FwServiceAbsent, &pub_if, &other),
        Dynamic::Clear
    );
    // port / protocol / zone
    let mut ch = c("public");
    ch.port = Some("10-30/tcp".into());
    assert!(matches!(
        rules::firewalld(RuleKind::FwPortAbsent, &pub_if, &ch),
        Dynamic::Affects(_)
    ));
    ch.protocol = Some("tcp".into());
    assert!(matches!(
        rules::firewalld(RuleKind::FwProtocolAbsent, &pub_if, &ch),
        Dynamic::Affects(_)
    ));
    assert!(matches!(
        rules::firewalld(RuleKind::FwZoneAbsent, &pub_if, &ch),
        Dynamic::Affects(_)
    ));
    assert_eq!(
        rules::firewalld(RuleKind::FwZoneAbsent, &pub_if, &c("internal")),
        Dynamic::Clear
    );
    // interface: management interface with an interface-chosen zone affects;
    // with a source-chosen zone it does not.
    let mut ch = c("internal");
    ch.interface = Some("eth0".into());
    assert!(matches!(
        rules::firewalld(RuleKind::FwInterface, &pub_if, &ch),
        Dynamic::Affects(_)
    ));
    assert_eq!(
        rules::firewalld(RuleKind::FwInterface, &pub_src, &ch),
        Dynamic::Clear
    );
    ch.interface = Some("eth9".into());
    assert_eq!(
        rules::firewalld(RuleKind::FwInterface, &pub_if, &ch),
        Dynamic::Clear
    );
    // source containing the client
    let mut ch = c("internal");
    ch.source = Some("203.0.113.0/24".into());
    assert!(matches!(
        rules::firewalld(RuleKind::FwSource, &pub_if, &ch),
        Dynamic::Affects(_)
    ));
    ch.source = Some("198.51.100.0/24".into());
    assert_eq!(
        rules::firewalld(RuleKind::FwSource, &pub_if, &ch),
        Dynamic::Clear
    );
    ch.source = Some("ipset:x".into());
    assert!(matches!(
        rules::firewalld(RuleKind::FwSource, &pub_if, &ch),
        Dynamic::Unknown(_)
    ));
    // reload
    let mut ch = c("public");
    ch.permanent_allows = Some(false);
    assert!(matches!(
        rules::firewalld(RuleKind::FwReload, &pub_if, &ch),
        Dynamic::Affects(_)
    ));
    ch.permanent_allows = None;
    assert!(matches!(
        rules::firewalld(RuleKind::FwReload, &pub_if, &ch),
        Dynamic::Unknown(_)
    ));
    // unknown path / zone
    let unknown = PathState::Unknown("x".into());
    assert!(matches!(
        rules::firewalld(RuleKind::FwPortAbsent, &unknown, &c("public")),
        Dynamic::Unknown(_)
    ));
    let uz = known(ZoneState::Unknown("y".into()), &["eth0"]);
    assert!(matches!(
        rules::firewalld(RuleKind::FwPortAbsent, &uz, &c("public")),
        Dynamic::Unknown(_)
    ));
}

#[test]
fn decision_table_never_lets_an_approval_cover_unknown_or_unrecoverable() {
    use RiskClass::*;
    assert_eq!(
        rules::decide(C, &Dynamic::Clear, false, Recovery::None, false),
        Decision::Proceed
    );
    assert!(matches!(
        rules::decide(R, &Dynamic::Clear, false, Recovery::None, false),
        Decision::Refuse(_)
    ));
    assert_eq!(
        rules::decide(R, &Dynamic::Clear, true, Recovery::None, false),
        Decision::Proceed
    );
    assert!(matches!(
        rules::decide(
            C,
            &Dynamic::Unknown("x".into()),
            true,
            Recovery::NmCheckpoint,
            true
        ),
        Decision::Refuse(_)
    ));
    assert!(matches!(
        rules::decide(C, &Dynamic::Deferred, true, Recovery::NmCheckpoint, true),
        Decision::Refuse(_)
    ));
    assert!(matches!(
        rules::decide(
            C,
            &Dynamic::Affects("x".into()),
            false,
            Recovery::NmCheckpoint,
            true
        ),
        Decision::Refuse(_)
    ));
    // approved, but no recovery procedure (reload) or none available
    // (no NetworkManager checkpoint): refused even with an approval.
    assert!(matches!(
        rules::decide(C, &Dynamic::Affects("x".into()), true, Recovery::None, true),
        Decision::Refuse(_)
    ));
    assert!(matches!(
        rules::decide(
            C,
            &Dynamic::Affects("x".into()),
            true,
            Recovery::NmCheckpoint,
            false
        ),
        Decision::Refuse(_)
    ));
    assert_eq!(
        rules::decide(
            C,
            &Dynamic::Affects("x".into()),
            true,
            Recovery::NmCheckpoint,
            true
        ),
        Decision::Guarded(Recovery::NmCheckpoint)
    );
    assert_eq!(
        rules::decide(R, &Dynamic::NoChange, false, Recovery::None, false),
        Decision::Proceed
    );
}

#[test]
fn networkmanager_rules() {
    let p = known(ZoneState::NoFirewalld, &["eth0"]);
    let base = NmChange {
        ifname: Some("eth1".into()),
        active_on: Some(BTreeSet::new()),
        routing_readable: true,
        ..Default::default()
    };
    assert_eq!(rules::nm(&p, &base), Dynamic::Clear);
    let mut c = base.clone();
    c.ifname = Some("eth0".into());
    assert!(matches!(rules::nm(&p, &c), Dynamic::Affects(_)));
    let mut c = base.clone();
    c.active_on = Some(["eth0".to_string()].into_iter().collect());
    assert!(matches!(rules::nm(&p, &c), Dynamic::Affects(_)));
    let mut c = base.clone();
    c.ifname = None;
    c.autoconnect = true;
    assert!(matches!(rules::nm(&p, &c), Dynamic::Affects(_)));
    let mut c = base.clone();
    c.dhcp = true;
    assert!(matches!(rules::nm(&p, &c), Dynamic::Affects(_)));
    let mut c = base.clone();
    c.sets_gateway = true;
    assert!(matches!(rules::nm(&p, &c), Dynamic::Affects(_)));
    let mut c = base.clone();
    c.addresses = vec!["203.0.113.1/24".into()];
    assert!(matches!(rules::nm(&p, &c), Dynamic::Affects(_)));
    let mut c = base.clone();
    c.addresses = vec!["198.51.100.1/24".into()];
    assert_eq!(rules::nm(&p, &c), Dynamic::Clear);
    let mut c = base.clone();
    c.active_on = None;
    assert!(matches!(rules::nm(&p, &c), Dynamic::Unknown(_)));
    assert!(matches!(
        rules::nm(&PathState::Unknown("x".into()), &base),
        Dynamic::Unknown(_)
    ));
}

fn net_facts(conn: &str, ss: &str, addr: &str, route: &str) -> NetFacts {
    NetFacts {
        ssh_connection: Some(conn.into()),
        ss: Some(ss.into()),
        ip_addr: Some(addr.into()),
        route: Some(route.into()),
        loopback_declared: false,
    }
}

#[test]
fn path_determination_fails_closed() {
    let ok = net_facts(
        "203.0.113.9 50000 192.0.2.10 22",
        "0 0 192.0.2.10:22 203.0.113.9:50000\n",
        "2: eth0    inet 192.0.2.10/24 scope global eth0\n",
        "203.0.113.9 from 192.0.2.10 dev eth0\n",
    );
    match path::determine(&ok) {
        PathState::Known(p) => assert_eq!(p.ifaces, ["eth0".to_string()].into_iter().collect()),
        u => panic!("{u:?}"),
    }
    // asymmetric routing: both interfaces
    let mut asym = ok.clone();
    asym.route = Some("203.0.113.9 from 192.0.2.10 dev eth1\n".into());
    match path::determine(&asym) {
        PathState::Known(p) => assert_eq!(p.ifaces.len(), 2),
        u => panic!("{u:?}"),
    }
    let unknown = |n: &NetFacts| matches!(path::determine(n), PathState::Unknown(_));
    let mut n = ok.clone();
    n.ssh_connection = None;
    assert!(unknown(&n), "no SSH_CONNECTION");
    let mut n = ok.clone();
    n.ss = Some("0 0 192.0.2.10:22 203.0.113.9:1\n".into());
    assert!(unknown(&n), "ss mismatch");
    let mut n = ok.clone();
    n.ss =
        Some("0 0 192.0.2.10:22 203.0.113.9:50000\n0 0 192.0.2.10:22 203.0.113.9:50000\n".into());
    assert!(unknown(&n), "two sockets");
    let mut n = ok.clone();
    n.ip_addr = Some("2: eth0    inet 10.9.9.9/24 scope global eth0\n".into());
    assert!(unknown(&n), "server address on no interface");
    let mut n = ok.clone();
    n.route = Some("unreachable".into());
    assert!(unknown(&n), "no route");
    let mut n = ok.clone();
    n.ss = None;
    assert!(unknown(&n), "ss unreadable");
    // loopback only when declared
    let lo = net_facts("127.0.0.1 40000 127.0.0.1 22", "", "", "");
    assert!(unknown(&lo));
    let mut lo2 = lo.clone();
    lo2.loopback_declared = true;
    assert!(matches!(path::determine(&lo2), PathState::Known(p) if p.loopback));
    let mut mixed = lo2.clone();
    mixed.ssh_connection = Some("203.0.113.9 40000 127.0.0.1 22".into());
    assert!(unknown(&mixed), "loopback server with a remote client");
}

fn zone(name: &str, sources: &[&str]) -> FwZone {
    FwZone {
        name: name.into(),
        sources: sources.iter().map(|s| s.to_string()).collect(),
        forward_ports: false,
        priority: Ok(None),
    }
}

#[test]
fn zone_precedence_source_interface_default() {
    let p = match known(ZoneState::NoFirewalld, &["eth0"]) {
        PathState::Known(p) => p,
        _ => unreachable!(),
    };
    let base = FwFacts {
        running: true,
        version: Some("1.3.4".into()),
        default_zone: Some("public".into()),
        zones: Some(vec![zone("public", &[]), zone("internal", &[])]),
        iface_zones: vec![("eth0".into(), Ok(Some("internal".into())))],
        extra_rules: Some(false),
    };
    assert_eq!(
        path::zone_of(&p, &base),
        ZoneState::Known {
            zone: "internal".into(),
            by: ZoneBy::Interface
        }
    );
    let mut f = base.clone();
    f.zones = Some(vec![
        zone("public", &["203.0.113.0/24"]),
        zone("internal", &[]),
    ]);
    assert_eq!(
        path::zone_of(&p, &f),
        ZoneState::Known {
            zone: "public".into(),
            by: ZoneBy::Source
        }
    );
    let mut f = base.clone();
    f.iface_zones = vec![("eth0".into(), Ok(None))];
    assert_eq!(
        path::zone_of(&p, &f),
        ZoneState::Known {
            zone: "public".into(),
            by: ZoneBy::Default
        }
    );
    let unknown = |f: &FwFacts| matches!(path::zone_of(&p, f), ZoneState::Unknown(_));
    let mut f = base.clone();
    f.zones = Some(vec![
        zone("public", &["203.0.113.0/24"]),
        zone("internal", &["203.0.0.0/8"]),
    ]);
    assert!(unknown(&f), "two source zones");
    let mut f = base.clone();
    f.zones = Some(vec![zone("public", &["ipset:x"]), zone("internal", &[])]);
    assert!(unknown(&f), "non-IP source");
    let mut f = base.clone();
    f.zones.as_mut().unwrap()[1].priority = Ok(Some(-10));
    assert!(unknown(&f), "priority");
    let mut f = base.clone();
    f.zones.as_mut().unwrap()[0].priority = Err(());
    assert!(unknown(&f), "unreadable priority");
    let mut f = base.clone();
    f.zones.as_mut().unwrap()[1].forward_ports = true;
    assert!(unknown(&f), "forward ports");
    let mut f = base.clone();
    f.extra_rules = Some(true);
    assert!(unknown(&f), "policies or direct rules");
    let mut f = base.clone();
    f.extra_rules = None;
    assert!(unknown(&f), "unreadable policies");
    let mut f = base.clone();
    f.iface_zones = vec![("eth0".into(), Err(()))];
    assert!(unknown(&f), "unreadable interface zone");
    let mut f = base.clone();
    f.zones = None;
    assert!(unknown(&f), "unreadable zones");
    let f = FwFacts::default();
    assert_eq!(path::zone_of(&p, &f), ZoneState::NoFirewalld);
}

// ---------------------------------------------------------------------------
// classification and the static gate
// ---------------------------------------------------------------------------

#[test]
fn production_table_classifies_020_but_does_not_enforce_it() {
    let s = Setup::new();
    let m = s.model(&port("p", "public", "8080/tcp", "absent")).unwrap();
    match classify(m.plugins.as_deref(), &m.resources[0]) {
        Classification::Risk {
            class, enforcement, ..
        } => {
            assert_eq!(class, RiskClass::C);
            assert_eq!(enforcement, Enforcement::PendingOwner("D-13"));
        }
        other => panic!("{other:?}"),
    }
    let items = static_gate(&m, Some(&BTreeSet::new())).unwrap();
    assert_eq!(items[0].enforcement, Enforcement::PendingOwner("D-13"));
}

#[test]
fn digest_bound_classification_refuses_other_bytes() {
    let s = Setup::new();
    let m = s.model(&port("p", "public", "8080/tcp", "absent")).unwrap();
    let _g = TableGuard::set(WRONG_DIGEST_020);
    assert!(matches!(
        classify(m.plugins.as_deref(), &m.resources[0]),
        Classification::Refused(_)
    ));
    let e = static_gate(&m, None).unwrap_err();
    assert!(e.message.contains("classified digest"), "{}", e.message);
    drop(_g);
    let _g = TableGuard::set(EMPTY);
    let e = static_gate(&m, None).unwrap_err();
    assert!(
        e.message.contains("no connection-risk classification"),
        "{}",
        e.message
    );
}

#[test]
fn unregistered_connection_catalog_is_refused_before_contact() {
    // A catalog that is not first-party-registered in production but is in
    // this test's registry: it can run firewall-cmd mutate operations and has
    // no classification.
    let catalog = CATALOG_020.replace("NOT registered", "test copy");
    assert_ne!(catalog, CATALOG_020);
    let s = Setup::with(&catalog);
    let registry = vec![FirstPartyCatalog {
        id: "firewalld",
        version: "0.2.0",
        sha256: Box::leak(approval::sha256_hex(catalog.as_bytes()).into_boxed_str()),
    }];
    let p = s.boundary.join("r.yml");
    std::fs::write(
        &p,
        format!(
            "version: 1\nplugins:\n  - id: firewalld\n    version: 0.2.0\nresources:\n{}",
            service("s", "public", "http", "present")
        ),
    )
    .unwrap();
    let m = load_model_with_plugins(&p, &s.ctx(registry)).unwrap();
    let e = static_gate(&m, None).unwrap_err();
    assert!(
        e.message.contains("classified digest") || e.message.contains("classification"),
        "{}",
        e.message
    );
    // The engine refuses it too, before any firewall command.
    let fw = fw();
    let (r, _) = run(m, Mode::Plan, target(&fw, net(22)), ctx());
    assert!(r.is_err());
    assert!(
        fw.lock().unwrap().received.is_empty(),
        "{:?}",
        fw.lock().unwrap().received
    );
}

#[test]
fn r_without_approval_is_refused_by_the_static_gate_and_the_engine() {
    let s = Setup::new();
    let m = s.model(&port("p", "public", "8080/tcp", "absent")).unwrap();
    let _g = TableGuard::set(R_020);
    let e = static_gate(&m, Some(&BTreeSet::new())).unwrap_err();
    assert!(e.message.contains("need an approval"), "{}", e.message);
    // plan never needs one
    assert_eq!(static_gate(&m, None).unwrap()[0].class, RiskClass::R);
    // another resource's approval does not cover it
    let other: BTreeSet<String> = ["q".to_string()].into_iter().collect();
    assert!(static_gate(&m, Some(&other)).is_err());
    let fw = fw();
    let (r, _) = run(m, Mode::Apply, target(&fw, net(22)), ctx());
    assert!(err_msg(r).contains("need an approval"));
    assert!(
        fw.lock().unwrap().received.is_empty(),
        "nothing was observed or changed"
    );
}

#[test]
fn facts_make_a_resource_r_and_registers_are_refused() {
    let s = Setup::new();
    let _g = TableGuard::set(ENFORCED_020);
    let m = s
        .model("  - id: p\n    type: firewalld.port\n    with: { zone: \"{{ facts.hostname }}\", port: \"8080/tcp\", state: absent }\n")
        .unwrap();
    assert_eq!(static_gate(&m, None).unwrap()[0].class, RiskClass::R);
    assert!(static_gate(&m, Some(&BTreeSet::new())).is_err());
    let m = s
        .model("  - id: c\n    type: command\n    with: { program: /usr/bin/true, register: out }\n  - id: p\n    type: firewalld.port\n    depends_on: [c]\n    with: { zone: \"{{ registers.out.stdout }}\", port: \"8080/tcp\", state: absent }\n")
        .unwrap();
    let e = static_gate(&m, None).unwrap_err();
    assert!(e.message.contains("register"), "{}", e.message);
}

// ---------------------------------------------------------------------------
// engine: dynamic checks
// ---------------------------------------------------------------------------

#[test]
fn clear_change_proceeds_and_affecting_change_is_refused() {
    let s = Setup::new();
    let _g = TableGuard::set(ENFORCED_020);
    // 8080 is not the management port (22): clear, applied.
    let fw1 = fw();
    let (r, l) = run(
        s.model(&port("p", "public", "8080/tcp", "absent")).unwrap(),
        Mode::Apply,
        target(&fw1, net(22)),
        ctx(),
    );
    let rep = r.unwrap();
    assert_eq!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
    assert_eq!(record(&l, "p").dynamic, "clear");
    assert!(fw_mutations(&fw1) > 0);
    // The management port is 2222: removing it from the management zone.
    let fw2 = fw();
    let m = s.model(&port("p", "public", "2222/tcp", "absent")).unwrap();
    let (plan, pl) = run(m.clone(), Mode::Plan, target(&fw2, net(2222)), ctx());
    assert!(plan.is_ok());
    assert_eq!(record(&pl, "p").dynamic, "affects");
    assert_eq!(fw_mutations(&fw2), 0, "plan never mutates");
    let (r, l) = run(m, Mode::Apply, target(&fw2, net(2222)), ctx());
    assert_refused(&r, &fw2, "p", "affects the management connection");
    assert!(record(&l, "p").dynamic.contains("refused"));
    // A removed service whose definition holds the management port.
    let fw3 = fw();
    let (r, _) = run(
        s.model(&service("s", "public", "ssh-alt", "absent"))
            .unwrap(),
        Mode::Apply,
        target(&fw3, net(2222)),
        ctx(),
    );
    assert_refused(&r, &fw3, "s", "affects the management connection");
    // The same port in another zone is clear.
    let fw4 = fw();
    let (r, _) = run(
        s.model(&port("p", "internal", "2222/tcp", "absent"))
            .unwrap(),
        Mode::Apply,
        target(&fw4, net(2222)),
        ctx(),
    );
    assert_eq!(r.unwrap().status, AggregateStatus::Success);
}

type Case = (
    &'static str,
    Box<dyn Fn() -> FakeNet>,
    Box<dyn Fn(&mut FakeFirewalld)>,
);

#[test]
fn unknown_paths_are_refused_even_with_an_approval_in_force() {
    let s = Setup::new();
    let _g = TableGuard::set(ENFORCED_020);
    let m = || s.model(&port("p", "public", "8080/tcp", "absent")).unwrap();
    let cases: Vec<Case> = vec![
        (
            "no SSH_CONNECTION",
            Box::new(|| FakeNet {
                ssh_connection: None,
                ..net(22)
            }),
            Box::new(|_| {}),
        ),
        (
            "ss mismatch",
            Box::new(|| FakeNet {
                ss: Some("0 0 192.0.2.10:22 203.0.113.9:1\n".into()),
                ..net(22)
            }),
            Box::new(|_| {}),
        ),
        (
            "ss missing",
            Box::new(|| FakeNet {
                ss: None,
                ..net(22)
            }),
            Box::new(|_| {}),
        ),
        (
            "undeclared loopback",
            Box::new(|| FakeNet {
                ssh_connection: Some("127.0.0.1 40000 127.0.0.1 22".into()),
                ..net(22)
            }),
            Box::new(|_| {}),
        ),
        (
            "two NICs in two zones",
            Box::new(|| FakeNet {
                default_route: Some("203.0.113.9 from 192.0.2.10 dev eth1\n".into()),
                ..net(22)
            }),
            Box::new(|f: &mut FakeFirewalld| {
                f.interfaces.insert("eth1".into(), "internal".into());
            }),
        ),
        (
            "priority",
            Box::new(|| net(22)),
            Box::new(|f: &mut FakeFirewalld| {
                f.priorities = Some([("internal".to_string(), -5)].into_iter().collect());
            }),
        ),
        (
            "modern firewalld without readable priority",
            Box::new(|| net(22)),
            Box::new(|f: &mut FakeFirewalld| {
                f.version = Some("2.1.0".into());
            }),
        ),
        (
            "forward ports",
            Box::new(|| net(22)),
            Box::new(|f: &mut FakeFirewalld| {
                f.forward_ports.insert("public".into());
            }),
        ),
        (
            "extra policy",
            Box::new(|| net(22)),
            Box::new(|f: &mut FakeFirewalld| {
                f.active_policies = vec!["admin-in".into()];
            }),
        ),
        (
            "direct rule",
            Box::new(|| net(22)),
            Box::new(|f: &mut FakeFirewalld| {
                f.direct_rules = vec!["ipv4 filter INPUT 0 -j DROP".into()];
            }),
        ),
    ];
    for (name, n, tweak) in cases {
        let fwx = fw();
        tweak(&mut fwx.lock().unwrap());
        let (r, l) = run(m(), Mode::Apply, target(&fwx, n()), ctx());
        assert_refused(&r, &fwx, "p", "unknown");
        assert!(
            record(&l, "p").dynamic.starts_with("unknown"),
            "{name}: {l:?}"
        );
    }
}

#[test]
fn ipv6_nat_source_and_default_zones() {
    let s = Setup::new();
    let _g = TableGuard::set(ENFORCED_020);
    let m = || s.model(&port("p", "public", "2222/tcp", "absent")).unwrap();
    // IPv6 connection on eth0 (public): removing 2222 from public affects.
    let v6 = FakeNet {
        ssh_connection: Some("2001:db8::9 50000 2001:db8::10 2222".into()),
        ss: Some("0 0 [2001:db8::10]:2222 [2001:db8::9]:50000\n".into()),
        ip_addr: Some("2: eth0    inet6 2001:db8::10/64 scope global\n".into()),
        default_route: Some("2001:db8::9 from 2001:db8::10 dev eth0\n".into()),
        ..net(2222)
    };
    let f = fw();
    let (r, _) = run(m(), Mode::Apply, target(&f, v6), ctx());
    assert_refused(&r, &f, "p", "affects");
    // NAT in front of the host: the client is the NAT address, the server
    // address is the host's own; the path is known.
    let nat = FakeNet {
        ssh_connection: Some("198.51.100.7 61000 10.0.0.5 2222".into()),
        ss: Some("0 0 10.0.0.5:2222 198.51.100.7:61000\n".into()),
        ip_addr: Some("2: eth0    inet 10.0.0.5/24 scope global eth0\n".into()),
        default_route: Some("198.51.100.7 from 10.0.0.5 via 10.0.0.1 dev eth0\n".into()),
        ..net(2222)
    };
    let f = fw();
    let (r, l) = run(m(), Mode::Plan, target(&f, nat), ctx());
    assert!(r.is_ok());
    assert_eq!(record(&l, "p").dynamic, "affects");
    // A source binding the client to internal: public is not the
    // management zone, so removing 2222 from public is clear.
    let f = fw();
    f.lock()
        .unwrap()
        .sources
        .insert("internal".into(), vec!["203.0.113.0/24".into()]);
    let (r, l) = run(m(), Mode::Apply, target(&f, net(2222)), ctx());
    assert_eq!(r.unwrap().status, AggregateStatus::Success, "{l:?}");
    assert_eq!(record(&l, "p").dynamic, "clear");
    // An unbound interface falls to the default zone.
    let f = fw();
    {
        let mut g = f.lock().unwrap();
        g.interfaces.clear();
        g.default_zone = Some("internal".into());
    }
    let (r, l) = run(m(), Mode::Apply, target(&f, net(2222)), ctx());
    assert_eq!(r.unwrap().status, AggregateStatus::Success, "{l:?}");
    assert_eq!(record(&l, "p").dynamic, "clear");
}

#[test]
fn declared_loopback_is_a_path_but_not_a_guarantee() {
    let s = Setup::new();
    let _g = TableGuard::set(ENFORCED_020);
    let lo = FakeNet {
        ssh_connection: Some("127.0.0.1 40000 127.0.0.1 22".into()),
        ..net(22)
    };
    let f = fw();
    let mut c = ctx();
    c.loopback_declared = true;
    let (r, l) = run(
        s.model(&port("p", "public", "8080/tcp", "absent")).unwrap(),
        Mode::Apply,
        target(&f, lo.clone()),
        c.clone(),
    );
    assert_eq!(r.unwrap().status, AggregateStatus::Success);
    assert_eq!(record(&l, "p").dynamic, "clear");
    // No ss/ip observation is made for a loopback connection.
    let t = target(&f, lo);
    let e = engine(
        s.model(&port("q", "public", "2222/tcp", "absent")).unwrap(),
        Mode::Plan,
        t,
        c,
    );
    let rep = e.run().unwrap();
    assert!(!rep
        .commands
        .iter()
        .any(|x| x.program.ends_with("/ss") || x.program.ends_with("/ip")));
}

#[test]
fn an_earlier_risky_change_defers_later_ones() {
    let s = Setup::new();
    let _g = TableGuard::set(ENFORCED_020);
    let body = format!(
        "{}{}",
        port("a", "public", "8080/tcp", "absent"),
        port("b", "internal", "8080/tcp", "absent")
    );
    let f = fw();
    let (r, l) = run(
        s.model(&body).unwrap(),
        Mode::Plan,
        target(&f, net(22)),
        ctx(),
    );
    assert!(r.is_ok());
    assert_eq!(record(&l, "a").dynamic, "clear");
    assert_eq!(record(&l, "b").dynamic, "deferred");
    let f = fw();
    let (r, l) = run(
        s.model(&body).unwrap(),
        Mode::Apply,
        target(&f, net(22)),
        ctx(),
    );
    let rep = r.unwrap();
    assert_ne!(rep.status, AggregateStatus::Success);
    assert_eq!(
        rep.resources.iter().find(|x| x.id == "a").unwrap().change,
        Change::Changed
    );
    let b = rep.resources.iter().find(|x| x.id == "b").unwrap();
    assert_eq!(b.change, Change::None);
    assert!(record(&l, "b").dynamic.starts_with("unknown"));
}

#[test]
fn not_enforced_020_runs_as_before_and_says_so() {
    let s = Setup::new();
    let f = fw();
    let (r, l) = run(
        s.model(&port("p", "public", "2222/tcp", "absent")).unwrap(),
        Mode::Apply,
        target(&f, net(2222)),
        ctx(),
    );
    let rep = r.unwrap();
    assert_eq!(
        rep.status,
        AggregateStatus::Success,
        "unchanged v1.14 behaviour while D-13 is pending"
    );
    assert_eq!(record(&l, "p").dynamic, "not-enforced");
    let res = &rep.resources[0];
    assert!(
        res.notes.iter().any(|n| n.contains("D-13")),
        "{:?}",
        res.notes
    );
    assert!(
        !rep.commands
            .iter()
            .any(|x| x.program.ends_with("/ss") || x.program.ends_with("/ip")),
        "no path observation"
    );
}

#[test]
fn plan_and_audit_observe_only() {
    let s = Setup::new();
    let _g = TableGuard::set(ENFORCED_020);
    let m = s.model(&port("p", "public", "2222/tcp", "absent")).unwrap();
    let f = fw();
    let e = engine(m.clone(), Mode::Plan, target(&f, net(2222)), ctx());
    let rep = e.run().unwrap();
    assert_eq!(fw_mutations(&f), 0);
    for c in &rep.commands {
        assert!(
            !c.args.iter().any(|a| a.starts_with("--add")
                || a.starts_with("--remove")
                || a == "--reload"
                || a.starts_with("--set")
                || a.starts_with("--change")),
            "plan ran {:?} {:?}",
            c.program,
            c.args
        );
    }
    // audit: no connection-risk observation at all
    let f = fw();
    let opts = RunOptions {
        mode: Mode::Plan,
        sudo: false,
        target: TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(target(&f, net(2222))),
    };
    let rep = crate::audit::run_audit(Engine::new(m, opts).unwrap().with_risk(ctx())).unwrap();
    assert_eq!(fw_mutations(&f), 0);
    assert!(!rep
        .commands
        .iter()
        .any(|x| x.program.ends_with("/ss") || x.program.ends_with("/ip")));
}

// ---------------------------------------------------------------------------
// approvals
// ---------------------------------------------------------------------------

fn store() -> (tempfile::TempDir, Store) {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let s = Store::at(&d.path().join("state"));
    (d, s)
}

#[test]
fn hmac_matches_rfc4231_case_2() {
    let mac = approval::hmac_sha256(b"Jefe", b"what do ya want for nothing?");
    let hex: String = mac.iter().map(|b| format!("{:02x}", b)).collect();
    assert_eq!(
        hex,
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
}

#[test]
fn canonical_form_is_sorted_and_compact() {
    let v = json!({"b": 1, "a": {"d": [true, null], "c": "x"}});
    assert_eq!(
        approval::canonical(&v),
        r#"{"a":{"c":"x","d":[true,null]},"b":1}"#
    );
}

fn content(host: &str, ids: &[(&str, &str, &str)]) -> serde_json::Value {
    json!({
        "host": host,
        "sinter_version": "test",
        "resources": ids.iter().map(|(id, class, d)| json!({"id": id, "class": class, "change_digest": d, "type": "firewalld.port", "change": "changed"})).collect::<Vec<_>>(),
    })
}

fn approve(
    s: &Store,
    dir: &Path,
    host: &str,
    ids: &[(&str, &str, &str)],
    expires: u64,
) -> serde_json::Value {
    let p = s
        .write_request(dir, host, content(host, ids), json!({}))
        .unwrap();
    s.approve(&p, expires, "tester", |_| Ok(true)).unwrap()
}

#[test]
fn approval_lifecycle_and_reuse_prevention() {
    let (d, s) = store();
    let rec = approve(
        &s,
        &d.path().join("req"),
        "web01",
        &[("p", "R", "abc")],
        600,
    );
    let id = rec["approval_id"].as_str().unwrap().to_string();
    let hosts: BTreeSet<String> = ["web01".to_string()].into_iter().collect();
    let used = s.use_for_run(std::slice::from_ref(&id), &hosts).unwrap();
    assert_eq!(used["web01"]["resources"], json!(["p"]));
    let e = s
        .use_for_run(std::slice::from_ref(&id), &hosts)
        .unwrap_err();
    assert!(e.message.contains("already been used"), "{}", e.message);
    // The ledger is hash-chained.
    let lines = s.ledger_lines().unwrap();
    assert!(lines.len() >= 3);
    for w in lines.windows(2) {
        assert_eq!(
            w[1]["prev_sha256"],
            json!(approval::sha256_hex(approval::canonical(&w[0]).as_bytes()))
        );
    }
    let list = s.list().unwrap();
    assert_eq!(list[0].1, "used");
}

#[test]
fn approvals_refuse_other_hosts_expiry_tampering_and_double_approval() {
    let (d, s) = store();
    let dir = d.path().join("req");
    let hosts: BTreeSet<String> = ["web01".to_string()].into_iter().collect();
    // other host
    let rec = approve(&s, &dir, "web02", &[("p", "R", "abc")], 600);
    let e = s
        .use_for_run(&[rec["approval_id"].as_str().unwrap().into()], &hosts)
        .unwrap_err();
    assert!(e.message.contains("does not select"), "{}", e.message);
    // expired (1 second, then wait)
    let rec = approve(&s, &d.path().join("req2"), "web01", &[("p", "R", "abc")], 1);
    std::thread::sleep(std::time::Duration::from_millis(2100));
    let e = s
        .use_for_run(&[rec["approval_id"].as_str().unwrap().into()], &hosts)
        .unwrap_err();
    assert!(e.message.contains("expired"), "{}", e.message);
    // tampering with the record: host swapped
    let rec = approve(
        &s,
        &d.path().join("req3"),
        "web03",
        &[("p", "R", "abc")],
        600,
    );
    let id = rec["approval_id"].as_str().unwrap();
    let p = s.root().join("approvals").join(format!("{id}.json"));
    let text = std::fs::read_to_string(&p)
        .unwrap()
        .replace("\"web03\"", "\"web01\"");
    std::fs::write(&p, text).unwrap();
    let e = s.load(id).unwrap_err();
    assert!(e.message.contains("integrity"), "{}", e.message);
    // a record made with another key
    let (_d2, s2) = store();
    let rec2 = approve(
        &s2,
        &_d2.path().join("r"),
        "web01",
        &[("p", "R", "abc")],
        600,
    );
    let id2 = rec2["approval_id"].as_str().unwrap();
    std::fs::copy(
        s2.root().join("approvals").join(format!("{id2}.json")),
        s.root().join("approvals").join(format!("{id2}.json")),
    )
    .unwrap();
    std::fs::set_permissions(
        s.root().join("approvals").join(format!("{id2}.json")),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(s.load(id2).unwrap_err().message.contains("integrity"));
    // a request approved twice
    let p = s
        .write_request(
            &d.path().join("req4"),
            "web01",
            content("web01", &[("p", "R", "x")]),
            json!({}),
        )
        .unwrap();
    s.approve(&p, 600, "t", |_| Ok(true)).unwrap();
    assert!(s
        .approve(&p, 600, "t", |_| Ok(true))
        .unwrap_err()
        .message
        .contains("already been approved"));
    // an edited request
    let p = s
        .write_request(
            &d.path().join("req5"),
            "web01",
            content("web01", &[("p", "R", "x")]),
            json!({}),
        )
        .unwrap();
    let text = std::fs::read_to_string(&p)
        .unwrap()
        .replace("\"x\"", "\"y\"");
    std::fs::write(&p, text).unwrap();
    let e = s.approve(&p, 600, "t", |_| Ok(true)).unwrap_err();
    assert!(e.message.contains("integrity"), "{}", e.message);
    // the summary alone edited (shown to the approver, not digested): also refused
    let p = s
        .write_request(
            &d.path().join("req5b"),
            "web01",
            content("web01", &[("p", "R", "x")]),
            json!({"note": "real"}),
        )
        .unwrap();
    let text = std::fs::read_to_string(&p)
        .unwrap()
        .replace("\"real\"", "\"fake\"");
    std::fs::write(&p, text).unwrap();
    assert!(s
        .approve(&p, 600, "t", |_| Ok(true))
        .unwrap_err()
        .message
        .contains("integrity"));
    // a request file readable by others is refused
    let p = s
        .write_request(
            &d.path().join("req5c"),
            "web01",
            content("web01", &[("p", "R", "x")]),
            json!({}),
        )
        .unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(s.approve(&p, 600, "t", |_| Ok(true)).is_err());
    // refused confirmation
    let p = s
        .write_request(
            &d.path().join("req6"),
            "web01",
            content("web01", &[("p", "R", "x")]),
            json!({}),
        )
        .unwrap();
    assert!(s.approve(&p, 600, "t", |_| Ok(false)).is_err());
    // two approvals for one host in one run
    let a = approve(&s, &d.path().join("req7"), "web01", &[("p", "R", "a")], 600);
    let b = approve(&s, &d.path().join("req8"), "web01", &[("p", "R", "b")], 600);
    let e = s
        .use_for_run(
            &[
                a["approval_id"].as_str().unwrap().into(),
                b["approval_id"].as_str().unwrap().into(),
            ],
            &hosts,
        )
        .unwrap_err();
    assert!(e.message.contains("more than one"), "{}", e.message);
    // nothing was marked used by the refused run
    assert!(s
        .use_for_run(&[a["approval_id"].as_str().unwrap().into()], &hosts)
        .is_ok());
}

#[test]
fn store_refuses_unsafe_files() {
    let (_d, s) = store();
    s.key().unwrap();
    std::fs::set_permissions(
        s.root().join("approval.key"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(s.key().unwrap_err().message.contains("group or others"));
    std::fs::set_permissions(
        s.root().join("approval.key"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    std::fs::set_permissions(s.root(), std::fs::Permissions::from_mode(0o770)).unwrap();
    assert!(s.key().is_err());
    std::fs::set_permissions(s.root(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let k = s.root().join("approval.key");
    std::fs::remove_file(&k).unwrap();
    std::os::unix::fs::symlink("/etc/hosts", &k).unwrap();
    assert!(s.key().unwrap_err().message.contains("symbolic link"));
    assert!(s.load("not-an-id").is_err());
    assert!(s.load("../../../../etc/passwd000000000000").is_err());
}

#[test]
fn approved_r_change_proceeds_and_a_changed_state_is_refused() {
    let s = Setup::new();
    let _g = TableGuard::set(R_020);
    let (d, st) = store();
    let m = s.model(&port("p", "public", "8080/tcp", "absent")).unwrap();
    // plan with the store: the change digest
    let f = fw();
    let mut c = ctx();
    c.store = Some(st.clone());
    let (r, l) = run(m.clone(), Mode::Plan, target(&f, net(22)), c.clone());
    assert!(r.is_ok());
    let digest = record(&l, "p").change_digest.clone().unwrap();
    let rec = approve(
        &st,
        &d.path().join("req"),
        "web01",
        &[("p", "R", &digest)],
        600,
    );
    // apply with the matching approval: clear, proceeds
    let mut ca = c.clone();
    ca.approval = Some(rec.clone());
    let f = fw();
    let (r, l) = run(m.clone(), Mode::Apply, target(&f, net(22)), ca.clone());
    assert_eq!(r.unwrap().status, AggregateStatus::Success);
    assert!(record(&l, "p").approved);
    // the state changed after the approval (permanent already removed): the
    // observed facets differ, so the change differs, nothing is changed
    let f = fw();
    f.lock()
        .unwrap()
        .ports_permanent
        .remove(&("public".to_string(), "8080/tcp".to_string()));
    let (r, _) = run(m.clone(), Mode::Apply, target(&f, net(22)), ca.clone());
    assert_refused(&r, &f, "p", "differs from the approved change");
    // a different resource content (another port) is not covered
    let m2 = s.model(&port("p", "public", "2222/tcp", "absent")).unwrap();
    let f = fw();
    let (r, _) = run(m2, Mode::Apply, target(&f, net(22)), ca.clone());
    assert_refused(&r, &f, "p", "differs from the approved change");
    // an approval for another resource id does not satisfy the static gate
    let m3 = s.model(&port("q", "public", "8080/tcp", "absent")).unwrap();
    let f = fw();
    let (r, _) = run(m3, Mode::Apply, target(&f, net(22)), ca);
    assert!(err_msg(r).contains("need an approval"));
    assert!(f.lock().unwrap().received.is_empty());
}

#[test]
fn content_digest_is_keyed_and_stable() {
    let s = Setup::new();
    let _g = TableGuard::set(ENFORCED_020);
    let (_d, st) = store();
    let key = st.key().unwrap();
    let m = s.model(&port("p", "public", "8080/tcp", "absent")).unwrap();
    let mut c = ctx();
    c.store = Some(st.clone());
    let digest = || {
        let f = fw();
        let (r, l) = run(m.clone(), Mode::Plan, target(&f, net(22)), c.clone());
        let obj = super::engine::content_object(&st, &key, "web01", &m, &r.unwrap(), &l);
        approval::sha256_hex(approval::canonical(&obj).as_bytes())
    };
    assert_eq!(
        digest(),
        digest(),
        "same state, same digest (client port and times are not part of it)"
    );
    let f = fw();
    f.lock()
        .unwrap()
        .ports_runtime
        .remove(&("public".to_string(), "8080/tcp".to_string()));
    let (r, l) = run(m.clone(), Mode::Plan, target(&f, net(22)), c.clone());
    let other = approval::sha256_hex(
        approval::canonical(&super::engine::content_object(
            &st,
            &key,
            "web01",
            &m,
            &r.unwrap(),
            &l,
        ))
        .as_bytes(),
    );
    assert_ne!(
        digest(),
        other,
        "a different observed state gives a different digest"
    );
    // nothing in the content object is the raw key
    let f = fw();
    let (r, l) = run(m.clone(), Mode::Plan, target(&f, net(22)), c.clone());
    let text = approval::canonical(&super::engine::content_object(
        &st,
        &key,
        "web01",
        &m,
        &r.unwrap(),
        &l,
    ));
    let khex: String = key.iter().map(|b| format!("{:02x}", b)).collect();
    assert!(!text.contains(&khex));
}

#[test]
fn a_sensitive_resource_reason_is_withheld() {
    let s = Setup::new();
    let _g = TableGuard::set(ENFORCED_020);
    let m = s
        .model("  - id: p\n    type: firewalld.port\n    sensitive: true\n    with: { zone: public, port: \"2222/tcp\", state: absent }\n")
        .unwrap();
    let f = fw();
    let (r, l) = run(m, Mode::Apply, target(&f, net(2222)), ctx());
    let text = match r {
        Ok(rep) => rep.resources[0].reason.clone().unwrap_or_default(),
        Err(e) => e.message,
    };
    assert!(
        text.contains("[redacted]") || !text.contains("public"),
        "{text}"
    );
    assert!(!text.contains("management zone public"), "{text}");
    assert_eq!(record(&l, "p").reason.as_deref(), Some("[redacted]"));
    assert_eq!(fw_mutations(&f), 0);
}

const TSERVICE_ONLY: &[TypeRule] = &[TypeRule {
    type_name: "firewalld.service",
    classify: absent_is_c,
    rule: RuleKind::FwServiceAbsent,
}];
static SERVICE_ONLY_020: &[CatalogRules] = &[CatalogRules {
    id: "firewalld",
    version: "0.2.0",
    sha256: "d32ac3947279ec2581a7049f9fa931d29c904c91ea2484cafaa6759fe09c3641",
    enforcement: Enforcement::Enforced,
    types: TSERVICE_ONLY,
    ops: OPS_020,
}];

#[test]
fn an_unlisted_type_is_classified_by_the_operations_it_can_run() {
    let s = Setup::new();
    let _g = TableGuard::set(SERVICE_ONLY_020);
    // Only add operations (N): allowed, class N.
    let m = s
        .model(&port("p", "public", "8080/tcp", "present"))
        .unwrap();
    match classify(m.plugins.as_deref(), &m.resources[0]) {
        Classification::Risk { class, rule, .. } => {
            assert_eq!(class, RiskClass::N);
            assert_eq!(rule, RuleKind::None);
        }
        other => panic!("{other:?}"),
    }
    // A remove operation (C) with no rule to judge it: refused.
    let m = s.model(&port("p", "public", "8080/tcp", "absent")).unwrap();
    assert!(matches!(
        classify(m.plugins.as_deref(), &m.resources[0]),
        Classification::Refused(_)
    ));
    // A state from a variable counts as every state, so remove too.
    let m = s
        .model("  - id: p\n    type: firewalld.port\n    with: { zone: public, port: \"8080/tcp\", state: \"{{ vars.st }}\" }\n")
        .unwrap_or_else(|_| s.model(&port("p", "public", "8080/tcp", "absent")).unwrap());
    assert!(matches!(
        classify(m.plugins.as_deref(), &m.resources[0]),
        Classification::Refused(_)
    ));
}

#[test]
fn not_enforced_or_n_resources_keep_v114_behaviour_with_registers_and_facts() {
    // Production table: 0.2.0 is not enforced, so neither registers nor
    // facts change anything (B-1).
    let s = Setup::new();
    let m = s
        .model("  - id: c\n    type: command\n    with: { program: /usr/bin/true, register: out }\n  - id: p\n    type: firewalld.port\n    depends_on: [c]\n    with: { zone: \"{{ registers.out.stdout }}\", port: \"8080/tcp\", state: present }\n")
        .unwrap();
    assert!(static_gate(&m, Some(&BTreeSet::new())).is_ok());
    let m = s
        .model("  - id: p\n    type: firewalld.port\n    with: { zone: \"{{ facts.hostname }}\", port: \"8080/tcp\", state: absent }\n")
        .unwrap();
    let items = static_gate(&m, Some(&BTreeSet::new())).unwrap();
    assert_ne!(items[0].class, RiskClass::R);
    // Enforced, but every operation the resource can run is N: facts do not
    // make it R and registers are not refused.
    let _g = TableGuard::set(ENFORCED_020);
    let m = s
        .model("  - id: p\n    type: firewalld.port\n    with: { zone: \"{{ facts.hostname }}\", port: \"8080/tcp\", state: present }\n")
        .unwrap();
    assert_eq!(
        static_gate(&m, Some(&BTreeSet::new())).unwrap()[0].class,
        RiskClass::N
    );
}

#[test]
fn a_plugin_definition_cannot_make_a_removal_look_n() {
    // B-2: a pinned plugin for the same catalog whose port facets want a
    // separate field. `state: present, mode: absent` runs the remove ops.
    let plugin = PLUGIN_020.replacen(
        "name = \"firewalld.port\"\nfields = { zone = { kind = \"ident\" }, port = { kind = \"port_single\" }, state = { kind = \"enum\", values = [\"present\", \"absent\"] } }",
        "name = \"firewalld.port\"\nfields = { zone = { kind = \"ident\" }, port = { kind = \"port_single\" }, state = { kind = \"enum\", values = [\"present\", \"absent\"] }, mode = { kind = \"enum\", values = [\"present\", \"absent\"] } }",
        1,
    );
    let plugin = plugin.replacen(
        "observe = \"query_port_runtime\"\nwant = \"field:state\"",
        "observe = \"query_port_runtime\"\nwant = \"field:mode\"",
        1,
    );
    let plugin = plugin.replacen(
        "observe = \"query_port_permanent\"\nwant = \"field:state\"",
        "observe = \"query_port_permanent\"\nwant = \"field:mode\"",
        1,
    );
    assert_ne!(plugin, PLUGIN_020, "the variant differs");
    let s = Setup::with_plugin(CATALOG_020, Box::leak(plugin.into_boxed_str()));
    let _g = TableGuard::set(ENFORCED_020);
    let m = s
        .model("  - id: p\n    type: firewalld.port\n    with: { zone: public, port: \"2222/tcp\", state: present, mode: absent }\n")
        .expect("the variant plugin loads");
    match classify(m.plugins.as_deref(), &m.resources[0]) {
        Classification::Risk { class, .. } => assert_eq!(class, RiskClass::C),
        other => panic!("{other:?}"),
    }
    let f = fw();
    let (r, _) = run(m, Mode::Apply, target(&f, net(2222)), ctx());
    assert_refused(&r, &f, "p", "affects the management connection");
}

#[test]
fn a_declared_loopback_on_a_remote_connection_is_unknown() {
    let mut n = net_facts(
        "203.0.113.9 50000 192.0.2.10 22",
        "0 0 192.0.2.10:22 203.0.113.9:50000\n",
        "2: eth0    inet 192.0.2.10/24 scope global eth0\n",
        "203.0.113.9 from 192.0.2.10 dev eth0\n",
    );
    n.loopback_declared = true;
    assert!(matches!(path::determine(&n), PathState::Unknown(_)));
}
