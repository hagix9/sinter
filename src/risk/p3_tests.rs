//! firewalld 0.3.0 and the P3 connection-risk rules (DESIGN §43, §44).
//!
//! The 0.3.0 catalog and plugin are the first-party files of the repository
//! (registered from v1.15.0 after the P7-R1 measurement), loaded through a
//! test registry. The classification table in force is the production one
//! (0.3.0 is classified and enforced there, bound to the same digest).

use super::approval::{self, Store};
use super::engine::{RiskContext, RiskLog};
use crate::engine::{AggregateStatus, Engine, Mode, RunOptions, RunReport, TargetSpec};
use crate::executor::{Completion, FakeTarget, Output};
use crate::fakesys::{FakeFirewalld, FakeNet};
use crate::model::{load_model_with_plugins, Model};
use crate::plugin::{cidr_ok, ifaddr_ok, ifname_ok, FirstPartyCatalog, PluginContext};
use crate::result::{Change, Execution, HandlerOutcomeState};
use serde_json::json;
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const CATALOG_030: &str =
    include_str!("../../plugins/first-party/catalogs/firewalld-0.3.0.catalog.toml");
const PLUGIN_030: &str =
    include_str!("../../plugins/first-party/plugins/firewalld-0.3.0.plugin.toml");

fn observe_ops() -> Vec<String> {
    op_ids("observe")
}
fn mutate_ops() -> Vec<String> {
    op_ids("mutate")
}
fn op_ids(class: &str) -> Vec<String> {
    let v: toml::Value = toml::from_str(CATALOG_030).unwrap();
    v["op"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|o| o["class"].as_str() == Some(class))
        .map(|o| o["id"].as_str().unwrap().to_string())
        .collect()
}

fn list(ops: &[String]) -> String {
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
    fn with(plugin: &str, mutate: &[String]) -> Setup {
        let tmp = tempfile::tempdir().unwrap();
        let boundary = tmp.path().to_path_buf();
        let root = boundary.join("plugins-root");
        for d in [&root, &root.join("catalogs"), &root.join("plugins")] {
            std::fs::create_dir(d).unwrap();
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        write_mode(
            &root.join("catalogs/firewalld-0.3.0.catalog.toml"),
            CATALOG_030,
            0o644,
        );
        write_mode(
            &root.join("plugins/firewalld-0.3.0.plugin.toml"),
            plugin,
            0o644,
        );
        let trust = format!(
            "format = 1\n\n[[catalog]]\nid = \"firewalld\"\nversion = \"0.3.0\"\nsha256 = \"{}\"\nattested_observe = {}\nallowed_mutate = {}\n\n[[plugin]]\nid = \"firewalld\"\nversion = \"0.3.0\"\nsha256 = \"{}\"\n",
            approval::sha256_hex(CATALOG_030.as_bytes()),
            list(&observe_ops()),
            list(mutate),
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
        Setup::with(PLUGIN_030, &mutate_ops())
    }
    fn ctx(&self) -> PluginContext {
        PluginContext::Test {
            root: self.root.clone(),
            boundary: self.boundary.clone(),
            registry: vec![FirstPartyCatalog {
                id: "firewalld",
                version: "0.3.0",
                sha256: Box::leak(approval::sha256_hex(CATALOG_030.as_bytes()).into_boxed_str()),
            }],
        }
    }
    fn model(&self, resources: &str, handlers: &str) -> crate::error::Result<Model> {
        let p = self.boundary.join("r.yml");
        let h = if handlers.is_empty() {
            String::new()
        } else {
            format!("handlers:\n{}", handlers)
        };
        std::fs::write(
            &p,
            format!(
                "version: 1\nplugins:\n  - id: firewalld\n    version: 0.3.0\nresources:\n{}{}",
                resources, h
            ),
        )
        .unwrap();
        load_model_with_plugins(&p, &self.ctx())
    }
}

fn res(id: &str, ty: &str, with: &str) -> String {
    format!("  - id: {id}\n    type: firewalld.{ty}\n    with: {{ {with} }}\n")
}

const RELOAD: &str = "  - id: fwreload\n    type: plugin\n    plugin: firewalld\n    op: reload\n";

/// public (eth0, ssh service, 8080 and 2222 open), internal; priorities 0.
fn fw() -> Arc<Mutex<FakeFirewalld>> {
    let mut f = FakeFirewalld::typical();
    f.zones.insert("internal".into());
    for z in ["public", "internal"] {
        for p in ["8080/tcp", "2222/tcp"] {
            f.ports_runtime.insert((z.into(), p.into()));
            f.ports_permanent.insert((z.into(), p.into()));
        }
    }
    f.interfaces.insert("eth0".into(), "public".into());
    f.priorities = Some(BTreeMap::new());
    f.service_info
        .insert("ssh".into(), "ssh\n  ports: 22/tcp\n  protocols: \n  source-ports: \n  modules: \n  destination: \n  includes: \n  helpers: \n".into());
    Arc::new(Mutex::new(f))
}

fn net(server_port: u16) -> FakeNet {
    FakeNet {
        ssh_connection: Some(format!("203.0.113.9 50000 192.0.2.10 {}", server_port)),
        host_key_sha256: Some("bb".repeat(32)),
        ssh_user: Some("admin".into()),
        ss: Some(format!(
            "0 0 192.0.2.10:{} 203.0.113.9:50000\n",
            server_port
        )),
        ip_addr: Some("2: eth0    inet 192.0.2.10/24 brd 192.0.2.255 scope global eth0\n".into()),
        default_route: Some("203.0.113.9 from 192.0.2.10 via 192.0.2.1 dev eth0\n".into()),
        ..Default::default()
    }
}

fn target(f: &Arc<Mutex<FakeFirewalld>>, n: FakeNet) -> FakeTarget {
    let mut t = FakeTarget::ubuntu2404().as_root().with_firewalld(f.clone());
    t.manager.net = n;
    t
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
    let opts = RunOptions {
        mode,
        sudo: false,
        target: TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(t),
    };
    let e = Engine::new(model, opts).unwrap().with_risk(c);
    let log = e.risk_log();
    let r = e.run();
    let l = log.lock().unwrap().clone();
    (r, l)
}

fn record<'a>(l: &'a RiskLog, id: &str) -> &'a super::engine::RiskRecord {
    l.records
        .iter()
        .find(|r| r.id == id)
        .unwrap_or_else(|| panic!("no record {id}: {l:?}"))
}

fn muts(f: &Arc<Mutex<FakeFirewalld>>) -> usize {
    f.lock().unwrap().mutations.len()
}

fn refused(
    r: &crate::error::Result<RunReport>,
    f: &Arc<Mutex<FakeFirewalld>>,
    id: &str,
    want: &str,
) {
    match r {
        Ok(rep) => {
            let x = rep.resources.iter().find(|x| x.id == id).unwrap();
            assert_eq!(x.change, Change::None, "{x:?}");
            assert_ne!(x.execution, Execution::Succeeded, "{x:?}");
            assert!(
                x.reason.as_deref().unwrap_or("").contains(want),
                "{want}: {x:?}"
            );
        }
        Err(e) => assert!(e.message.contains(want), "{want}: {}", e.message),
    }
    assert_eq!(muts(f), 0, "{:?}", f.lock().unwrap().mutations);
}

/// An approval for exactly what plan saw (the P2 approval primitive).
fn approval_for(
    s: &Setup,
    body: &str,
    handlers: &str,
    t: impl Fn() -> FakeTarget,
) -> (tempfile::TempDir, RiskContext) {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let st = Store::at(&d.path().join("state"));
    let mut c = ctx();
    c.store = Some(st.clone());
    let (r, l) = run(s.model(body, handlers).unwrap(), Mode::Plan, t(), c.clone());
    let rep = r.unwrap();
    let key = st.key().unwrap();
    let content = super::engine::content_object(
        &st,
        &key,
        "web01",
        &s.model(body, handlers).unwrap(),
        &rep,
        &l,
    );
    let p = st
        .write_request(&d.path().join("req"), "web01", content, json!({}))
        .unwrap();
    let rec = st.approve(&p, 600, "tester", |_| Ok(true)).unwrap();
    c.approval = Some(rec);
    (d, c)
}

// ---------------------------------------------------------------------------
// operand classes
// ---------------------------------------------------------------------------

#[test]
fn operand_classes_are_strict() {
    for ok in ["eth0", "ens3", "br-lan", "vlan.10", "a234567890abcde"] {
        assert!(ifname_ok(ok, 15), "{ok}");
    }
    for bad in [
        "",
        "-eth0",
        "eth0:1",
        "eth/0",
        "a234567890abcdef",
        "eth 0",
        "eth0\n",
    ] {
        assert!(!ifname_ok(bad, 15), "{bad:?}");
    }
    for ok in [
        "192.0.2.0/24",
        "0.0.0.0/0",
        "203.0.113.9/32",
        "2001:db8::/32",
        "::/0",
        "fe80::/64",
    ] {
        assert!(cidr_ok(ok, 43), "{ok}");
    }
    for bad in [
        "192.0.2.1/24", // host bits
        "192.0.2.0",    // no prefix
        "192.0.2.0/33",
        "192.0.2.0/024",  // leading zero in prefix
        "192.000.2.0/24", // non-canonical address
        "2001:DB8::/32",  // upper case
        "2001:0db8::/32", // not RFC 5952
        "2001:db8::1/32", // host bits
        "ipset:x",
        "-192.0.2.0/24",
    ] {
        assert!(!cidr_ok(bad, 43), "{bad}");
    }
    assert!(ifaddr_ok("192.0.2.10/24", 43));
    assert!(ifaddr_ok("2001:db8::10/64", 43));
    assert!(!ifaddr_ok("192.0.2.10", 43));
    assert!(!ifaddr_ok("2001:db8:0::10/64", 43));
}

#[test]
fn catalog_030_keeps_020_and_loads_with_handler_role() {
    // Every 0.2.0 operation is in 0.3.0 unchanged.
    let c020 = include_str!("../../plugins/first-party/catalogs/firewalld-0.2.0.catalog.toml");
    let body = |c: &str| c[c.find("[[op]]").unwrap_or(c.len())..].to_string();
    assert!(
        body(CATALOG_030).starts_with(&body(c020)),
        "0.3.0 extends 0.2.0's operations unchanged"
    );
    let s = Setup::new();
    let m = s
        .model(
            &res(
                "i",
                "interface",
                "zone: internal, interface: eth1, state: present",
            ),
            RELOAD,
        )
        .unwrap();
    assert_eq!(
        m.handlers[0].plugin_op,
        Some(("firewalld".into(), "reload".into()))
    );
    // A non-canonical source is refused before anything runs.
    let e = s
        .model(
            &res(
                "s",
                "source",
                "zone: internal, source: \"192.0.2.1/24\", state: present",
            ),
            "",
        )
        .and_then(|m| {
            crate::risk::static_gate(&m, None)?;
            Ok(m)
        });
    let rep = e.and_then(|m| run(m, Mode::Plan, target(&fw(), net(22)), ctx()).0);
    assert!(rep.is_err() || rep.as_ref().unwrap().status != AggregateStatus::Success);
    // A predefined zone cannot be deleted.
    assert!(s
        .model(&res("z", "zone", "zone: public, state: absent"), "")
        .is_err());
    // A handler that names no handler operation is refused at load.
    let bad = "  - id: h\n    type: plugin\n    plugin: firewalld\n    op: add_port_runtime\n";
    assert!(s
        .model(
            &res(
                "p",
                "port",
                "zone: public, port: \"8080/tcp\", state: present"
            ),
            bad
        )
        .unwrap_err()
        .message
        .contains("no handler operation"));
}

#[test]
fn handler_operation_rules_in_catalogs() {
    // role = "handler" with slots, or on an observe operation, is refused.
    let bad = CATALOG_030.replace(
        "argv = [\"--reload\"]\ntimeout_secs = 30\nexit = { \"0\" = \"ok\" }\nrole = \"handler\"",
        "argv = [\"--reload\", \"--zone={zone}\"]\ntimeout_secs = 30\nslots = { zone = { class = \"ident\", max_len = 17 } }\nexit = { \"0\" = \"ok\" }\nrole = \"handler\"",
    );
    assert_ne!(bad, CATALOG_030);
    let r = crate::plugin::verify::verify_catalog_text_for_test(&bad);
    assert!(r.unwrap_err().message.contains("handler operation"));
}

// ---------------------------------------------------------------------------
// resources, handlers, C1
// ---------------------------------------------------------------------------

#[test]
fn interface_source_and_zone_resources_on_a_non_management_path() {
    let s = Setup::new();
    // A new zone is N (an addition): no approval, and it does not defer a
    // later change of the same run.
    let body = format!(
        "{}{}",
        res("z", "zone", "zone: lab, state: present"),
        res(
            "i",
            "interface",
            "zone: internal, interface: eth1, state: present"
        ),
    );
    let f = fw();
    let (_d, c) = approval_for(&s, &body, "", || target(&f, net(22)));
    let f = fw();
    let (r, l) = run(
        s.model(&body, "").unwrap(),
        Mode::Apply,
        target(&f, net(22)),
        c,
    );
    let rep = r.unwrap();
    assert_eq!(
        rep.status,
        AggregateStatus::Success,
        "{:?} {l:?}",
        rep.resources
    );
    {
        let g = f.lock().unwrap();
        assert!(g.perm_only_zones.contains("lab"));
        assert_eq!(
            g.interfaces.get("eth1").map(String::as_str),
            Some("internal")
        );
        assert_eq!(
            g.perm_interfaces
                .as_ref()
                .unwrap()
                .get("eth1")
                .map(String::as_str),
            Some("internal")
        );
    }
    assert_eq!(record(&l, "i").dynamic, "clear", "{l:?}");
    // A source in its own run (R, approved, clear), then idempotent.
    let body = res(
        "s",
        "source",
        "zone: internal, source: \"198.51.100.0/24\", state: present",
    );
    let f = fw();
    let (_d, c) = approval_for(&s, &body, "", || target(&f, net(22)));
    let f = fw();
    let (r, l) = run(
        s.model(&body, "").unwrap(),
        Mode::Apply,
        target(&f, net(22)),
        c,
    );
    assert_eq!(r.unwrap().status, AggregateStatus::Success, "{l:?}");
    assert!(f.lock().unwrap().sources["internal"].contains(&"198.51.100.0/24".to_string()));
    // Two R changes in one run: the second is deferred (plan) and refused
    // (apply), so they belong in separate runs.
    let body = format!(
        "{}{}",
        res(
            "i",
            "interface",
            "zone: internal, interface: eth1, state: present"
        ),
        res(
            "s",
            "source",
            "zone: internal, source: \"198.51.100.0/24\", state: present"
        ),
    );
    let f = fw();
    let (r, l) = run(
        s.model(&body, "").unwrap(),
        Mode::Plan,
        target(&f, net(22)),
        ctx(),
    );
    assert!(r.is_ok());
    assert_eq!(record(&l, "s").dynamic, "deferred");
}

#[test]
fn r_resources_need_an_approval_before_contact() {
    let s = Setup::new();
    let m = s
        .model(
            &res(
                "i",
                "interface",
                "zone: internal, interface: eth1, state: present",
            ),
            "",
        )
        .unwrap();
    let f = fw();
    let (r, _) = run(m, Mode::Apply, target(&f, net(22)), ctx());
    assert!(r.err().unwrap().message.contains("need an approval"));
    assert!(
        f.lock().unwrap().received.is_empty(),
        "nothing was contacted on firewalld"
    );
}

#[test]
fn handler_operations_are_in_the_c1_gate() {
    // The trust file allows every operation but reload.
    let mutate: Vec<String> = mutate_ops().into_iter().filter(|o| o != "reload").collect();
    let s = Setup::with(PLUGIN_030, &mutate);
    let m = s
        .model(
            &format!(
                "{}    notify: [fwreload]\n",
                res(
                    "p",
                    "port",
                    "zone: public, port: \"8080/tcp\", state: present"
                )
            ),
            RELOAD,
        )
        .unwrap();
    let e = crate::plugin::require_allowed_mutations(&m).unwrap_err();
    assert!(
        e.message.contains("not allowed by the trust file"),
        "{}",
        e.message
    );
    for mode in [Mode::Plan, Mode::Apply] {
        let f = fw();
        let (r, _) = run(m.clone(), mode, target(&f, net(22)), ctx());
        assert!(r.is_err());
        assert!(
            f.lock().unwrap().received.is_empty(),
            "refused before any firewalld command"
        );
    }
}

fn notify_reload(body: &str) -> String {
    format!("{}    notify: [fwreload]\n", body)
}

#[test]
fn reload_runs_only_when_the_permanent_configuration_keeps_the_connection() {
    let s = Setup::new();
    let body = notify_reload(&res(
        "p",
        "port",
        "zone: public, port: \"9090/tcp\", state: present",
    ));
    // clear: permanent public allows ssh (22) through the ssh service.
    let f = fw();
    let (r, l) = run(
        s.model(&body, RELOAD).unwrap(),
        Mode::Apply,
        target(&f, net(22)),
        ctx(),
    );
    let rep = r.unwrap();
    assert_eq!(rep.handlers_run.len(), 1);
    assert_eq!(
        rep.handlers_run[0].state,
        HandlerOutcomeState::Succeeded,
        "{:?} {l:?}",
        rep.handlers_run
    );
    assert_eq!(f.lock().unwrap().reloads, 1);
    assert!(rep.handlers_run[0]
        .provenance
        .as_deref()
        .unwrap()
        .contains("op=reload"));
    // affects: the permanent configuration does not allow 22.
    let f = fw();
    f.lock()
        .unwrap()
        .permanent
        .remove(&("public".to_string(), "ssh".to_string()));
    let (r, l) = run(
        s.model(&body, RELOAD).unwrap(),
        Mode::Apply,
        target(&f, net(22)),
        ctx(),
    );
    let rep = r.unwrap();
    assert_eq!(
        rep.handlers_run[0].state,
        HandlerOutcomeState::Failed,
        "{l:?}"
    );
    assert_eq!(f.lock().unwrap().reloads, 0, "the reload was refused");
    assert!(record(&l, "handler:fwreload").dynamic.contains("affects"));
    // unknown: rich rules in the management zone.
    let f = fw();
    f.lock().unwrap().rich_rules.insert("public".into());
    let (r, l) = run(
        s.model(&body, RELOAD).unwrap(),
        Mode::Apply,
        target(&f, net(22)),
        ctx(),
    );
    assert_eq!(
        r.unwrap().handlers_run[0].state,
        HandlerOutcomeState::Failed
    );
    assert_eq!(f.lock().unwrap().reloads, 0);
    assert!(record(&l, "handler:fwreload")
        .dynamic
        .starts_with("unknown"));
    // unknown: the interface is managed by NetworkManager (its permanent
    // zone may live in the NetworkManager profile).
    let f = fw();
    let mut t = target(&f, net(22)).with_executable("/usr/bin/nmcli");
    t.program_outputs.insert(
        "/usr/bin/nmcli".into(),
        Output {
            completion: Completion::Exited(0),
            stdout: b"eth0:connected\nlo:unmanaged\n".to_vec(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        },
    );
    let (r, l) = run(s.model(&body, RELOAD).unwrap(), Mode::Apply, t, ctx());
    assert_eq!(
        r.unwrap().handlers_run[0].state,
        HandlerOutcomeState::Failed
    );
    assert_eq!(f.lock().unwrap().reloads, 0);
    assert!(
        record(&l, "handler:fwreload")
            .dynamic
            .starts_with("unknown"),
        "{l:?}"
    );
}

#[test]
fn runtime_only_resource_notifying_a_reload_warns() {
    let plugin = format!(
        "{}\n[[type]]\nname = \"firewalld.port_runtime\"\nfields = {{ zone = {{ kind = \"ident\" }}, port = {{ kind = \"port_single\" }} }}\nprecheck = [{{ op = \"state\", expect = \"running\" }}]\n\n[[type.facet]]\nname = \"runtime\"\nobserve = \"query_port_runtime\"\nwant = \"present\"\nensure = {{ present = \"add_port_runtime\" }}\n",
        PLUGIN_030
    );
    let s = Setup::with(Box::leak(plugin.into_boxed_str()), &mutate_ops());
    let m = s
        .model(
            "  - id: r\n    type: firewalld.port_runtime\n    with: { zone: public, port: \"9090/tcp\" }\n    notify: [fwreload]\n",
            RELOAD,
        )
        .unwrap();
    assert!(
        m.warnings
            .iter()
            .any(|w| w.contains("a reload would discard that change")),
        "{:?}",
        m.warnings
    );
}

// ---------------------------------------------------------------------------
// service definitions, runtime/permanent, NetworkManager
// ---------------------------------------------------------------------------

#[test]
fn service_definitions_are_judged_fully() {
    let s = Setup::new();
    let cases: &[(&str, &str, &str)] = &[
        (
            "inc",
            "inc\n  ports: \n  protocols: \n  includes: ssh\n  helpers: \n",
            "affects",
        ),
        (
            "proto",
            "proto\n  ports: \n  protocols: tcp\n  includes: \n  helpers: \n",
            "affects",
        ),
        (
            "helper",
            "helper\n  ports: 21/tcp\n  protocols: \n  includes: \n  helpers: ftp\n",
            "unknown",
        ),
        ("odd", "odd\n  ports: 80/tcp\n  newkey: x\n", "unknown"),
        (
            "web",
            "web\n  ports: 80/tcp 443/tcp\n  protocols: \n  includes: \n  helpers: \n",
            "clear",
        ),
    ];
    for (svc, info, want) in cases {
        let f = fw();
        {
            let mut g = f.lock().unwrap();
            g.services.insert(svc.to_string());
            g.runtime.insert(("public".into(), svc.to_string()));
            g.permanent.insert(("public".into(), svc.to_string()));
            g.service_info.insert(svc.to_string(), info.to_string());
        }
        let m = s
            .model(
                &res(
                    "x",
                    "service",
                    &format!("zone: public, service: {svc}, state: absent"),
                ),
                "",
            )
            .unwrap();
        let (r, l) = run(m, Mode::Apply, target(&f, net(22)), ctx());
        assert!(record(&l, "x").dynamic.starts_with(want), "{svc}: {l:?}");
        if *want != "clear" {
            refused(
                &r,
                &f,
                "x",
                if *want == "affects" {
                    "affects"
                } else {
                    "unknown"
                },
            );
        } else {
            assert_eq!(r.unwrap().status, AggregateStatus::Success);
        }
    }
}

#[test]
fn permanent_facets_are_judged_against_the_permanent_configuration() {
    let s = Setup::new();
    // Runtime: eth0 in public. Permanent: eth0 in internal. Removing 2222
    // (the management port) from internal is clear at runtime and affects
    // the permanent configuration.
    let f = fw();
    f.lock().unwrap().perm_interfaces = Some(
        [("eth0".to_string(), "internal".to_string())]
            .into_iter()
            .collect(),
    );
    let m = s
        .model(
            &res(
                "p",
                "port",
                "zone: internal, port: \"2222/tcp\", state: absent",
            ),
            "",
        )
        .unwrap();
    let (r, l) = run(m, Mode::Apply, target(&f, net(2222)), ctx());
    refused(&r, &f, "p", "affects");
    assert!(record(&l, "p").dynamic.starts_with("affects"), "{l:?}");
}

#[test]
fn drifting_priority_and_nm_managed_interfaces_fail_closed() {
    let s = Setup::new();
    let body = res(
        "p",
        "port",
        "zone: internal, port: \"2222/tcp\", state: absent",
    );
    // a source-decided zone without AllowZoneDrifting=no
    let f = fw();
    f.lock()
        .unwrap()
        .sources
        .insert("internal".into(), vec!["203.0.113.0/24".into()]);
    let (r, _) = run(
        s.model(&body, "").unwrap(),
        Mode::Apply,
        target(&f, net(2222)),
        ctx(),
    );
    refused(&r, &f, "p", "unknown");
    // priority not answered by a version that has zone priorities (R-5)
    let f = fw();
    f.lock().unwrap().version = Some("2.4.3".into());
    f.lock().unwrap().priorities = None;
    let (r, _) = run(
        s.model(&body, "").unwrap(),
        Mode::Apply,
        target(&f, net(2222)),
        ctx(),
    );
    refused(&r, &f, "p", "unknown");
    // NetworkManager manages eth0: the permanent facet is unknown
    let f = fw();
    let mut t = target(&f, net(2222)).with_executable("/usr/bin/nmcli");
    t.program_outputs.insert(
        "/usr/bin/nmcli".into(),
        Output {
            completion: Completion::Exited(0),
            stdout: b"eth0:connected\n".to_vec(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        },
    );
    let (r, l) = run(s.model(&body, "").unwrap(), Mode::Apply, t, ctx());
    refused(&r, &f, "p", "unknown");
    assert!(record(&l, "p").dynamic.starts_with("unknown"), "{l:?}");
}

// ---------------------------------------------------------------------------
// runtime first
// ---------------------------------------------------------------------------

#[test]
fn runtime_first_probe_success_then_permanent() {
    let s = Setup::new();
    let body = res(
        "p",
        "port",
        "zone: public, port: \"2222/tcp\", state: absent",
    );
    let mk = |reconnect: Option<bool>| {
        let f = fw();
        let mut n = net(2222);
        n.reconnect = reconnect;
        (f.clone(), target(&f, n))
    };
    let (_d, c) = approval_for(&s, &body, "", || mk(Some(true)).1);
    let (f, t) = mk(Some(true));
    let (r, l) = run(s.model(&body, "").unwrap(), Mode::Apply, t, c);
    let rep = r.unwrap();
    assert_eq!(
        rep.status,
        AggregateStatus::Success,
        "{:?} {l:?}",
        rep.resources
    );
    let g = f.lock().unwrap();
    assert!(!g
        .ports_runtime
        .contains(&("public".into(), "2222/tcp".into())));
    assert!(!g
        .ports_permanent
        .contains(&("public".into(), "2222/tcp".into())));
    let order: Vec<String> = g.mutations.iter().map(|m| m.join(" ")).collect();
    assert!(
        order[0].contains("--remove-port") && !order[0].contains("--permanent"),
        "runtime first: {order:?}"
    );
    assert!(order[1].contains("--permanent"), "{order:?}");
    assert!(rep.resources[0]
        .notes
        .iter()
        .any(|n| n.contains("runtime-first")));
}

#[test]
fn runtime_first_probe_failure_restores_runtime_and_leaves_permanent() {
    let s = Setup::new();
    let body = res(
        "p",
        "port",
        "zone: public, port: \"2222/tcp\", state: absent",
    );
    let mk = |reconnect: Option<bool>| {
        let f = fw();
        let mut n = net(2222);
        n.reconnect = reconnect;
        (f.clone(), target(&f, n))
    };
    let (_d, c) = approval_for(&s, &body, "", || mk(Some(true)).1);
    let (f, t) = mk(Some(false));
    let (r, _) = run(s.model(&body, "").unwrap(), Mode::Apply, t, c.clone());
    let rep = r.unwrap();
    let x = &rep.resources[0];
    assert_eq!(x.execution, Execution::Failed, "{x:?}");
    assert!(
        x.reason
            .as_deref()
            .unwrap()
            .contains("restored and verified"),
        "{x:?}"
    );
    let g = f.lock().unwrap();
    assert!(
        g.ports_runtime
            .contains(&("public".into(), "2222/tcp".into())),
        "runtime restored"
    );
    assert!(
        g.ports_permanent
            .contains(&("public".into(), "2222/tcp".into())),
        "permanent untouched"
    );
    drop(g);
    // The approval is spent by the CLI before contact; here the engine
    // alone shows a second identical run can be refused only by the CLI's
    // use markers (P2). Restore failure: the restoring add is lost.
    let (f, t) = mk(Some(false));
    f.lock().unwrap().forced.push((
        "--add-port=2222/tcp".into(),
        Output {
            completion: Completion::Indeterminate {
                started: true,
                reason: "connection lost".into(),
            },
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        },
    ));
    let (r, _) = run(s.model(&body, "").unwrap(), Mode::Apply, t, c);
    let rep = r.unwrap();
    let x = &rep.resources[0];
    assert_eq!(x.execution, Execution::Indeterminate, "{x:?}");
    assert!(
        x.reason.as_deref().unwrap().contains("not guaranteed"),
        "{x:?}"
    );
}

#[test]
fn affecting_changes_without_an_exact_inverse_are_refused_even_with_approval() {
    let s = Setup::new();
    // Moving the management interface eth0 into internal: no recovery.
    let body = res(
        "i",
        "interface",
        "zone: internal, interface: eth0, state: present",
    );
    let mk = || {
        let f = fw();
        let mut n = net(22);
        n.reconnect = Some(true);
        (f.clone(), target(&f, n))
    };
    let (_d, c) = approval_for(&s, &body, "", || mk().1);
    let (f, t) = mk();
    let (r, l) = run(s.model(&body, "").unwrap(), Mode::Apply, t, c);
    refused(&r, &f, "i", "no guarded recovery procedure");
    assert!(record(&l, "i").approved);
}

#[test]
fn the_030_classification_is_bound_to_the_registered_bytes() {
    let entry = super::CATALOG_RULES
        .iter()
        .find(|c| c.id == "firewalld" && c.version == "0.3.0")
        .expect("0.3.0 is classified");
    assert_eq!(entry.sha256, approval::sha256_hex(CATALOG_030.as_bytes()));
    assert_eq!(entry.enforcement, super::Enforcement::Enforced);
    // Registered from v1.15.0 (measured on real hosts in P7-R1), with the
    // same digest as the classification table (R-1).
    assert!(crate::plugin::FIRST_PARTY_CATALOGS
        .iter()
        .any(|c| c.id == "firewalld" && c.version == "0.3.0" && c.sha256 == entry.sha256));
}

#[test]
fn a_change_that_affects_only_the_permanent_configuration_is_refused_even_approved() {
    // Audit B-1 (E1): runtime eth0 in public, permanent eth0 in internal;
    // removing the management port from internal is clear at runtime and
    // affects the permanent configuration. Runtime first cannot test it.
    let s = Setup::new();
    let body = res(
        "p",
        "port",
        "zone: internal, port: \"2222/tcp\", state: absent",
    );
    let mk = || {
        let f = fw();
        f.lock().unwrap().perm_interfaces = Some(
            [("eth0".to_string(), "internal".to_string())]
                .into_iter()
                .collect(),
        );
        let mut n = net(2222);
        n.reconnect = Some(true);
        (f.clone(), target(&f, n))
    };
    let (_d, c) = approval_for(&s, &body, "", || mk().1);
    let (f, t) = mk();
    let (r, l) = run(s.model(&body, "").unwrap(), Mode::Apply, t, c);
    refused(&r, &f, "p", "no guarded recovery procedure");
    assert!(record(&l, "p").approved);
    assert_eq!(f.lock().unwrap().reloads, 0);
}

#[test]
fn a_permanent_only_change_on_the_path_is_refused_and_says_permanent_only() {
    // M2: the runtime facet already matches (not pending); only the
    // permanent facet would change and it affects the path.
    let s = Setup::new();
    let body = res(
        "p",
        "port",
        "zone: public, port: \"2222/tcp\", state: absent",
    );
    let mk = || {
        let f = fw();
        f.lock()
            .unwrap()
            .ports_runtime
            .remove(&("public".to_string(), "2222/tcp".to_string()));
        let mut n = net(2222);
        n.reconnect = Some(true);
        (f.clone(), target(&f, n))
    };
    let (r, l) = run(s.model(&body, "").unwrap(), Mode::Plan, mk().1, ctx());
    let rep = r.unwrap();
    assert!(
        rep.resources[0]
            .notes
            .iter()
            .any(|n| n.contains("permanent-only")),
        "{:?}",
        rep.resources[0].notes
    );
    assert!(record(&l, "p").dynamic.starts_with("affects"));
    let (_d, c) = approval_for(&s, &body, "", || mk().1);
    let (f, t) = mk();
    let (r, _) = run(s.model(&body, "").unwrap(), Mode::Apply, t, c);
    refused(&r, &f, "p", "no guarded recovery procedure");
}

#[test]
fn a_restore_that_does_not_restore_is_indeterminate() {
    // M1: the restoring add reports success but changes nothing.
    let s = Setup::new();
    let body = res("x", "service", "zone: public, service: alt, state: absent");
    let mk = |reconnect: bool| {
        let f = fw();
        {
            let mut g = f.lock().unwrap();
            g.services.insert("alt".into());
            g.runtime.insert(("public".into(), "alt".into()));
            g.permanent.insert(("public".into(), "alt".into()));
            g.service_info
                .insert("alt".into(), "alt\n  ports: 2222/tcp\n".into());
        }
        let mut n = net(2222);
        n.reconnect = Some(reconnect);
        (f.clone(), target(&f, n))
    };
    let (_d, c) = approval_for(&s, &body, "", || mk(true).1);
    let (f, t) = mk(false);
    f.lock().unwrap().forced.push((
        "--add-service=alt".into(),
        Output {
            completion: Completion::Exited(0),
            stdout: b"success\n".to_vec(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        },
    ));
    let (r, _) = run(s.model(&body, "").unwrap(), Mode::Apply, t, c);
    let rep = r.unwrap();
    let x = &rep.resources[0];
    assert_eq!(x.execution, Execution::Indeterminate, "{x:?}");
    assert!(
        x.reason
            .as_deref()
            .unwrap()
            .contains("could not be verified"),
        "{x:?}"
    );
    assert!(
        f.lock()
            .unwrap()
            .permanent
            .contains(&("public".into(), "alt".into())),
        "permanent untouched"
    );
}

#[test]
fn permanent_policies_are_read_from_the_permanent_configuration() {
    // Audit B-2: a permanent-only policy makes the reload unknown.
    let s = Setup::new();
    let body = notify_reload(&res(
        "p",
        "port",
        "zone: public, port: \"9090/tcp\", state: present",
    ));
    let f = fw();
    f.lock().unwrap().perm_policies = vec!["admin-in".into()];
    let (r, l) = run(
        s.model(&body, RELOAD).unwrap(),
        Mode::Apply,
        target(&f, net(22)),
        ctx(),
    );
    assert_eq!(
        r.unwrap().handlers_run[0].state,
        HandlerOutcomeState::Failed
    );
    assert_eq!(f.lock().unwrap().reloads, 0);
    assert!(
        record(&l, "handler:fwreload")
            .dynamic
            .starts_with("unknown"),
        "{l:?}"
    );
}

#[test]
fn deleting_a_zone_of_a_management_interface_affects_and_work_is_predefined() {
    let s = Setup::new();
    assert!(s
        .model(&res("z", "zone", "zone: work, state: absent"), "")
        .is_err());
    // eth0 is bound to `mgmt`, but a source decides the zone (internal):
    // deleting `mgmt` still affects (a zone of a management interface).
    let body = res("z", "zone", "zone: mgmt, state: absent");
    let f = fw();
    {
        let mut g = f.lock().unwrap();
        g.zones.insert("mgmt".into());
        g.interfaces.insert("eth0".into(), "mgmt".into());
    }
    let (r, l) = run(
        s.model(&body, "").unwrap(),
        Mode::Plan,
        target(&f, net(22)),
        ctx(),
    );
    assert!(r.is_ok());
    assert!(record(&l, "z").dynamic.starts_with("affects"), "{l:?}");
}

// ---------------------------------------------------------------------------
// v1.15.0 P7-R2: R-4 (ss path), R-5 (zone priority), R-2 (loopback reload),
// and the management-path protection on a path that is now judged
// ---------------------------------------------------------------------------

/// `stat -c` records of the `ss` candidates.
fn st(kind: &str, mode: &str, uid: u32) -> Option<String> {
    Some(format!(
        "{kind}|{mode}|{uid}|0|133000|2049|7|2026-11-20 00:00:00.000000000 +0000|2026-11-20 00:00:00.000000000 +0000"
    ))
}

/// The RHEL-family layout measured in P7-R1: `ss` only at `/usr/sbin/ss`.
fn el_net(server_port: u16) -> FakeNet {
    let mut n = net(server_port);
    n.ss_stat = Some(
        [
            ("/usr/bin/ss".to_string(), None),
            ("/usr/sbin/ss".to_string(), st("regular file", "755", 0)),
        ]
        .into_iter()
        .collect(),
    );
    n
}

/// The runtime `--list-all` of zone trusted on Rocky Linux 10.2, firewalld
/// 2.4.3 (P7-R1, measured; only the zone name and interface differ below).
const LIST_ALL_243: &str = "trusted (default, active)\n  target: ACCEPT\n  ingress-priority: 0\n  egress-priority: 0\n  icmp-block-inversion: no\n  interfaces: eth0\n  sources: \n  services: \n  ports: \n  protocols: \n  forward: yes\n  masquerade: no\n  forward-ports: \n  source-ports: \n  icmp-blocks: \n  rich rules: \n";

#[test]
fn r4_ss_is_found_at_the_measured_paths_only_and_fails_closed() {
    let s = Setup::new();
    // removing 8080 from public on a 2222 connection: clear when the path is known
    let body = res(
        "p",
        "port",
        "zone: public, port: \"8080/tcp\", state: absent",
    );
    let ok = |n: FakeNet| {
        let f = fw();
        let (r, l) = run(
            s.model(&body, "").unwrap(),
            Mode::Apply,
            target(&f, n.clone()),
            ctx(),
        );
        (f, r, l)
    };
    // Ubuntu (default fake): /usr/bin/ss
    let (_, r, l) = ok(net(2222));
    assert_eq!(r.unwrap().status, AggregateStatus::Success, "{l:?}");
    assert_eq!(record(&l, "p").dynamic, "clear");
    // RHEL family: /usr/sbin/ss (R-4); before P7-R2 this was unknown
    let (_, r, l) = ok(el_net(2222));
    assert_eq!(r.unwrap().status, AggregateStatus::Success, "{l:?}");
    assert_eq!(record(&l, "p").dynamic, "clear");
    // fail closed: the first existing candidate decides; no PATH, no fallback
    type SsFiles<'a> = Vec<(&'a str, Option<String>)>;
    let bad: Vec<(&str, SsFiles)> = vec![
        ("both absent", vec![]),
        (
            "a link at /usr/bin/ss, a good /usr/sbin/ss",
            vec![
                ("/usr/bin/ss", st("symbolic link", "777", 0)),
                ("/usr/sbin/ss", st("regular file", "755", 0)),
            ],
        ),
        // the kind alone refuses a link (a link's own mode is 777 on Linux; 755 pins the kind check)
        (
            "a link with a restrictive mode",
            vec![("/usr/bin/ss", st("symbolic link", "755", 0))],
        ),
        (
            "group-writable",
            vec![("/usr/bin/ss", st("regular file", "775", 0))],
        ),
        (
            "other-writable",
            vec![("/usr/sbin/ss", st("regular file", "757", 0))],
        ),
        (
            "not owned by root",
            vec![("/usr/bin/ss", st("regular file", "755", 1000))],
        ),
        (
            "not executable",
            vec![("/usr/bin/ss", st("regular file", "644", 0))],
        ),
        (
            "a directory",
            vec![("/usr/bin/ss", st("directory", "755", 0))],
        ),
        (
            "an unreadable stat record",
            vec![("/usr/bin/ss", Some("garbage".to_string()))],
        ),
    ];
    for (name, files) in bad {
        let mut n = net(2222);
        n.ss_stat = Some(files.into_iter().map(|(p, v)| (p.to_string(), v)).collect());
        let (f, r, l) = ok(n);
        refused(&r, &f, "p", "unknown");
        assert!(
            record(&l, "p")
                .reason
                .as_deref()
                .unwrap_or("")
                .contains("ss could not be read"),
            "{name}: {l:?}"
        );
    }
}

#[test]
fn r5_zone_priority_parsers_follow_the_measured_forms() {
    use super::path::{loopback_reload_measured, parse_fw_version, parse_zone_priority};
    for (v, want) in [
        ("1.3.4\n", Some("1.3.4")),
        ("2.4.3\n", Some("2.4.3")),
        ("2.4.3", None),
        ("2.4.3\n\n", None),
        ("2.4.3\r\n", None),
        ("2.4.3-rc1\n", None),
        ("02.4.3\n", None),
        ("2.4\n", None),
        ("2.4.3.1\n", None),
        ("", None),
        ("v2.4.3\n", None),
    ] {
        assert_eq!(parse_fw_version(v).as_deref(), want, "{v:?}");
    }
    // the measured 2.4.3 answer
    assert_eq!(
        parse_zone_priority("2.4.3", "trusted", LIST_ALL_243),
        Ok(Some(0))
    );
    let public = LIST_ALL_243.replacen("trusted (default, active)", "public", 1);
    for v in ["2.1.1", "2.3.1", "2.4.3"] {
        assert_eq!(
            parse_zone_priority(v, "public", &public),
            Ok(Some(0)),
            "{v}"
        );
    }
    let with = |i: &str, e: &str| {
        public
            .replace(
                "  ingress-priority: 0\n",
                &format!("  ingress-priority: {i}\n"),
            )
            .replace(
                "  egress-priority: 0\n",
                &format!("  egress-priority: {e}\n"),
            )
    };
    assert_eq!(
        parse_zone_priority("2.4.3", "public", &with("-1", "0")),
        Ok(Some(-1))
    );
    assert_eq!(
        parse_zone_priority("2.4.3", "public", &with("0", "5")),
        Ok(Some(5))
    );
    for bad in ["+1", "01", "-0", "x", "", "1 2", "9999999"] {
        assert_eq!(
            parse_zone_priority("2.4.3", "public", &with(bad, "0")),
            Err(()),
            "{bad:?}"
        );
    }
    let missing_egress = public.replace("  egress-priority: 0\n", "");
    let twice = public.replace(
        "  ingress-priority: 0\n",
        "  ingress-priority: 0\n  ingress-priority: 0\n",
    );
    let legacy = public.replace(
        "  ingress-priority: 0\n",
        "  ingress-priority: 0\n  priority: 0\n",
    );
    let other_indent = public.replace("  ingress-priority: 0\n", "   ingress-priority: 0\n");
    for (name, text) in [
        ("missing egress", &missing_egress),
        ("twice", &twice),
        ("legacy line", &legacy),
        ("indent", &other_indent),
    ] {
        assert_eq!(
            parse_zone_priority("2.4.3", "public", text),
            Err(()),
            "{name}"
        );
    }
    // another zone's answer, an empty answer, an unmeasured version
    assert_eq!(
        parse_zone_priority("2.4.3", "public", LIST_ALL_243),
        Err(())
    );
    assert_eq!(parse_zone_priority("2.4.3", "public", ""), Err(()));
    for v in ["2.2.0", "2.0.0", "1.3.3", "3.0.0", "0.9.4"] {
        assert_eq!(parse_zone_priority(v, "public", &public), Err(()), "{v}");
    }
    // 1.3.4: no zone priorities (measured); any priority line is a contradiction
    let v1 = "public\n  target: default\n  icmp-block-inversion: no\n  interfaces: \n  sources: \n";
    assert_eq!(parse_zone_priority("1.3.4", "public", v1), Ok(None));
    assert_eq!(parse_zone_priority("1.3.4", "public", &public), Err(()));
    // R-2 versions
    for v in ["1.3.4", "2.1.1", "2.3.1", "2.4.3"] {
        assert!(loopback_reload_measured(Some(v)), "{v}");
    }
    for v in [Some("2.2.0"), Some("2.4.4"), Some("1.3.4 "), None] {
        assert!(!loopback_reload_measured(v), "{v:?}");
    }
}

#[test]
fn r5_the_runtime_and_permanent_views_are_read_separately_and_get_priority_is_not_used() {
    let s = Setup::new();
    let body = res(
        "p",
        "port",
        "zone: public, port: \"8080/tcp\", state: absent",
    );
    // 2.4.3 with every priority 0: the path is judged (before P7-R2 it was unknown)
    let f = fw();
    f.lock().unwrap().version = Some("2.4.3".into());
    let (r, l) = run(
        s.model(&body, "").unwrap(),
        Mode::Apply,
        target(&f, el_net(2222)),
        ctx(),
    );
    assert_eq!(r.unwrap().status, AggregateStatus::Success, "{l:?}");
    let g = f.lock().unwrap();
    assert!(
        !g.received
            .iter()
            .any(|a| a.iter().any(|x| x == "--get-priority")),
        "{:?}",
        g.received
    );
    let rt = g
        .received
        .iter()
        .any(|a| a.len() == 2 && a[0].starts_with("--zone=") && a[1] == "--list-all");
    let pm = g
        .received
        .iter()
        .any(|a| a.len() == 3 && a[0] == "--permanent" && a[2] == "--list-all");
    assert!(rt && pm, "{:?}", g.received);
    drop(g);
    // a non-zero permanent priority on the management zone makes the
    // permanent view unknown, so a reload (judged on it) is refused
    let body_r = notify_reload(&res(
        "p",
        "port",
        "zone: public, port: \"9090/tcp\", state: present",
    ));
    let f = fw();
    f.lock().unwrap().version = Some("2.4.3".into());
    f.lock().unwrap().priorities = Some(BTreeMap::new());
    f.lock().unwrap().perm_list_all.insert(
        "public".into(),
        "public\n  target: default\n  ingress-priority: -1\n  egress-priority: 0\n".into(),
    );
    let (r, l) = run(
        s.model(&body_r, RELOAD).unwrap(),
        Mode::Apply,
        target(&f, el_net(22)),
        ctx(),
    );
    let rep = r.unwrap();
    assert_eq!(
        rep.handlers_run[0].state,
        HandlerOutcomeState::Failed,
        "{l:?}"
    );
    assert_eq!(f.lock().unwrap().reloads, 0);
    assert!(
        record(&l, "handler:fwreload")
            .dynamic
            .starts_with("unknown"),
        "{l:?}"
    );
}

fn loopback_net() -> FakeNet {
    FakeNet {
        ssh_connection: Some("127.0.0.1 40000 127.0.0.1 22".into()),
        // both ends of the loopback session; the server side matches
        ss: Some("0 0 127.0.0.1:22 127.0.0.1:40000\n0 0 127.0.0.1:40000 127.0.0.1:22\n".into()),
        ..net(22)
    }
}

#[test]
fn r2_the_reload_needs_the_measured_permanent_configuration_and_a_real_loopback_socket() {
    // independent audit B-1, B-3 (P7-R2)
    let s = Setup::new();
    let body = notify_reload(&res(
        "p",
        "port",
        "zone: public, port: \"9090/tcp\", state: present",
    ));
    type Tweak = Box<dyn Fn(&mut FakeFirewalld)>;
    let cases: Vec<(&str, Tweak)> = vec![
        (
            "a permanent direct rule",
            Box::new(|f| f.direct_rules = vec!["ipv4 filter INPUT 0 -i lo -j DROP".into()]),
        ),
        (
            "a permanent passthrough",
            Box::new(|f| f.direct_passthroughs = vec!["ipv4 -I INPUT -i lo -j DROP".into()]),
        ),
        (
            "a further permanent policy",
            Box::new(|f| f.perm_policies = vec!["admin-in".into()]),
        ),
        (
            "an unreadable direct answer",
            Box::new(|f| {
                f.forced.push((
                    "--get-all-rules".into(),
                    Output {
                        completion: Completion::Exited(2),
                        stdout: Vec::new(),
                        stderr: b"usage\n".to_vec(),
                        stdout_truncated: false,
                        stderr_truncated: false,
                    },
                ))
            }),
        ),
    ];
    for (name, tweak) in cases {
        let f = fw();
        f.lock().unwrap().version = Some("2.4.3".into());
        tweak(&mut f.lock().unwrap());
        let (r, l) = run(
            s.model(&body, RELOAD).unwrap(),
            Mode::Apply,
            target(&f, loopback_net()),
            loopback_ctx(),
        );
        assert_eq!(
            r.unwrap().handlers_run[0].state,
            HandlerOutcomeState::Failed,
            "{name}: {l:?}"
        );
        assert_eq!(f.lock().unwrap().reloads, 0, "{name}");
        assert!(
            record(&l, "handler:fwreload")
                .dynamic
                .starts_with("unknown"),
            "{name}: {l:?}"
        );
    }
    // the declared loopback connection must be an established socket
    for (name, ss) in [
        (
            "no matching socket",
            Some("0 0 127.0.0.1:22 127.0.0.1:40001\n".to_string()),
        ),
        (
            "two matching sockets",
            Some(
                "0 0 127.0.0.1:22 127.0.0.1:40000\n0 0 127.0.0.1:22 127.0.0.1:40000\n".to_string(),
            ),
        ),
        ("ss unreadable", None),
    ] {
        let f = fw();
        f.lock().unwrap().version = Some("2.4.3".into());
        let n = FakeNet {
            ss,
            ..loopback_net()
        };
        let (r, l) = run(
            s.model(&body, RELOAD).unwrap(),
            Mode::Apply,
            target(&f, n),
            loopback_ctx(),
        );
        assert_eq!(
            r.unwrap().handlers_run[0].state,
            HandlerOutcomeState::Failed,
            "{name}: {l:?}"
        );
        assert_eq!(f.lock().unwrap().reloads, 0, "{name}");
    }
}

fn loopback_ctx() -> RiskContext {
    RiskContext {
        loopback_declared: true,
        ..ctx()
    }
}

#[test]
fn r2_a_loopback_reload_runs_only_for_a_measured_version_on_this_session() {
    let s = Setup::new();
    let body = notify_reload(&res(
        "p",
        "port",
        "zone: public, port: \"9090/tcp\", state: present",
    ));
    for v in ["1.3.4", "2.1.1", "2.3.1", "2.4.3"] {
        let f = fw();
        f.lock().unwrap().version = Some(v.into());
        let t = target(&f, loopback_net());
        let (r, l) = run(
            s.model(&body, RELOAD).unwrap(),
            Mode::Apply,
            t,
            loopback_ctx(),
        );
        let rep = r.unwrap();
        assert_eq!(
            rep.handlers_run[0].state,
            HandlerOutcomeState::Succeeded,
            "{v}: {l:?}"
        );
        assert_eq!(f.lock().unwrap().reloads, 1, "{v}");
        assert_eq!(record(&l, "handler:fwreload").dynamic, "clear", "{v}");
    }
    // refused: an unmeasured version, a malformed answer, no answer
    for (name, v) in [
        ("unmeasured", Some("2.2.0")),
        ("malformed", Some("2.4.3-1")),
        ("absent", None),
    ] {
        let f = fw();
        match v {
            Some(v) => f.lock().unwrap().version = Some(v.into()),
            None => f.lock().unwrap().forced.push((
                "--version".into(),
                Output {
                    completion: Completion::Exited(1),
                    stdout: Vec::new(),
                    stderr: b"Error\n".to_vec(),
                    stdout_truncated: false,
                    stderr_truncated: false,
                },
            )),
        }
        let (r, l) = run(
            s.model(&body, RELOAD).unwrap(),
            Mode::Apply,
            target(&f, loopback_net()),
            loopback_ctx(),
        );
        assert_eq!(
            r.unwrap().handlers_run[0].state,
            HandlerOutcomeState::Failed,
            "{name}: {l:?}"
        );
        assert_eq!(f.lock().unwrap().reloads, 0, "{name}");
        assert!(
            record(&l, "handler:fwreload")
                .dynamic
                .starts_with("unknown"),
            "{name}: {l:?}"
        );
    }
    // a contradiction: measured when the path was determined, another
    // version at the reload's turn
    let f = fw();
    f.lock().unwrap().version = Some("2.4.3".into());
    f.lock().unwrap().forced.push((
        "--version".into(),
        Output {
            completion: Completion::Exited(0),
            stdout: b"2.4.3\n".to_vec(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        },
    ));
    f.lock().unwrap().forced.push((
        "--version".into(),
        Output {
            completion: Completion::Exited(0),
            stdout: b"2.9.0\n".to_vec(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        },
    ));
    let (r, l) = run(
        s.model(&body, RELOAD).unwrap(),
        Mode::Apply,
        target(&f, loopback_net()),
        loopback_ctx(),
    );
    assert_eq!(
        r.unwrap().handlers_run[0].state,
        HandlerOutcomeState::Failed,
        "{l:?}"
    );
    assert_eq!(f.lock().unwrap().reloads, 0);
    // undeclared loopback: unknown whatever the version
    let f = fw();
    f.lock().unwrap().version = Some("2.4.3".into());
    let (r, _) = run(
        s.model(&body, RELOAD).unwrap(),
        Mode::Apply,
        target(&f, loopback_net()),
        ctx(),
    );
    assert_eq!(
        r.unwrap().handlers_run[0].state,
        HandlerOutcomeState::Failed
    );
    assert_eq!(f.lock().unwrap().reloads, 0);
}

#[test]
fn r2_the_reload_opens_no_new_connection_and_does_not_reconnect() {
    // The handler runs on the session of the run: no probe, no reconnect.
    let s = Setup::new();
    let body = notify_reload(&res(
        "p",
        "port",
        "zone: public, port: \"9090/tcp\", state: present",
    ));
    let f = fw();
    f.lock().unwrap().version = Some("2.4.3".into());
    let mut n = loopback_net();
    n.reconnect = Some(false);
    n.reconnect_after_wait = Some(false);
    let counts = Arc::new(Mutex::new((0usize, 0usize)));
    n.shared_counts = Some(counts.clone());
    let t = target(&f, n);
    let e = {
        let opts = RunOptions {
            mode: Mode::Apply,
            sudo: false,
            target: TargetSpec { ssh: None },
            verbose: false,
            fault: None,
            fake_target: Some(t),
        };
        Engine::new(s.model(&body, RELOAD).unwrap(), opts)
            .unwrap()
            .with_risk(loopback_ctx())
    };
    let rep = e.run().unwrap();
    assert_eq!(rep.handlers_run[0].state, HandlerOutcomeState::Succeeded);
    assert_eq!(f.lock().unwrap().reloads, 1);
    assert_eq!(
        *counts.lock().unwrap(),
        (0, 0),
        "no new connection, no reconnect"
    );
}

#[test]
fn management_path_protection_on_a_path_judged_through_usr_sbin_ss() {
    // With R-4 and R-5 a path whose ss is /usr/sbin/ss is judged; the
    // protections of DESIGN §43 must hold there exactly as on the paths
    // judged before. (No NetworkManager here: on a real RHEL host whose eth0
    // NetworkManager manages, the permanent facet stays unknown, so these
    // changes are refused there; audit B-2.)
    let s = Setup::new();
    let mk = |v: &str, reconnect: Option<bool>| {
        let f = fw();
        f.lock().unwrap().version = Some(v.into());
        f.lock().unwrap().priorities = Some(BTreeMap::new());
        let mut n = el_net(2222);
        n.reconnect = reconnect;
        (f.clone(), target(&f, n))
    };
    // moving the management interface (R, approved): no guarded procedure, refused
    let iface = res(
        "i",
        "interface",
        "zone: internal, interface: eth0, state: present",
    );
    let (_d, c) = approval_for(&s, &iface, "", || mk("2.4.3", Some(true)).1);
    let (f, t) = mk("2.4.3", Some(true));
    let (r, l) = run(s.model(&iface, "").unwrap(), Mode::Apply, t, c);
    refused(&r, &f, "i", "affects");
    assert!(record(&l, "i").approved);
    // a source containing the client (R): without an approval refused at the gate
    let src = res(
        "s",
        "source",
        "zone: internal, source: 203.0.113.0/24, state: present",
    );
    let (f, t) = mk("2.4.3", Some(true));
    let (r, _) = run(s.model(&src, "").unwrap(), Mode::Apply, t, ctx());
    refused(&r, &f, "s", "approval");
    // approved, the new connection fails: runtime restored, permanent untouched
    let (_d, c) = approval_for(&s, &src, "", || mk("2.4.3", Some(true)).1);
    let (f, t) = mk("2.4.3", Some(false));
    let (r, _) = run(s.model(&src, "").unwrap(), Mode::Apply, t, c.clone());
    let x = r.unwrap().resources[0].clone();
    assert_eq!(x.execution, Execution::Failed, "{x:?}");
    assert!(
        x.reason
            .as_deref()
            .unwrap()
            .contains("restored and verified"),
        "{x:?}"
    );
    let g = f.lock().unwrap();
    let rt = g.sources.get("internal").cloned().unwrap_or_default();
    let pm = g
        .perm_sources
        .clone()
        .unwrap_or_default()
        .get("internal")
        .cloned()
        .unwrap_or_default();
    assert!(
        !rt.contains(&"203.0.113.0/24".to_string()),
        "runtime restored: {rt:?}"
    );
    assert!(
        !pm.contains(&"203.0.113.0/24".to_string()),
        "permanent untouched: {pm:?}"
    );
    drop(g);
    // approved, the new connection works: runtime first, then permanent
    let (f, t) = mk("2.4.3", Some(true));
    let (r, l) = run(s.model(&src, "").unwrap(), Mode::Apply, t, c);
    let rep = r.unwrap();
    assert_eq!(
        rep.status,
        AggregateStatus::Success,
        "{:?} {l:?}",
        rep.resources
    );
    let order: Vec<String> = f
        .lock()
        .unwrap()
        .mutations
        .iter()
        .map(|m| m.join(" "))
        .collect();
    assert!(
        order[0].contains("--add-source") && !order[0].contains("--permanent"),
        "{order:?}"
    );
    assert!(order[1].contains("--permanent"), "{order:?}");
    // an unmeasured version on the same path: unknown, refused even approved
    let (_d, c) = approval_for(&s, &src, "", || mk("2.4.3", Some(true)).1);
    let (f, t) = mk("2.2.0", Some(true));
    let (r, _) = run(s.model(&src, "").unwrap(), Mode::Apply, t, c);
    refused(&r, &f, "s", "");
}

// ---------------------------------------------------------------------------
// P7-R2 re-measurement (2026-11-20): the measured answers as fixtures
// ---------------------------------------------------------------------------

/// Every `--list-all` answer captured on the four measured versions.
fn measured_list_all(version: &str) -> Vec<(String, String, String)> {
    let text = match version {
        "1.3.4" => include_str!("fixtures/firewalld-1.3.4-list-all.txt"),
        "2.1.1" => include_str!("fixtures/firewalld-2.1.1-list-all.txt"),
        "2.3.1" => include_str!("fixtures/firewalld-2.3.1-list-all.txt"),
        "2.4.3" => include_str!("fixtures/firewalld-2.4.3-list-all.txt"),
        _ => unreachable!(),
    };
    let mut out = Vec::new();
    let text = text.split_once('\n').unwrap().1; // the comment line
    for part in text.split("=== ").skip(1) {
        let (head, body) = part.split_once('\n').unwrap();
        let (view, zone) = head.split_once(' ').unwrap();
        out.push((view.to_string(), zone.to_string(), body.to_string()));
    }
    out
}

#[test]
fn r5_every_measured_list_all_answer_is_read_as_measured() {
    use super::path::parse_zone_priority;
    for (v, zones) in [("1.3.4", 20), ("2.1.1", 18), ("2.3.1", 18), ("2.4.3", 20)] {
        let all = measured_list_all(v);
        assert_eq!(all.len(), zones, "{v}");
        assert!(all.iter().any(|(view, _, _)| view == "runtime"));
        assert!(all.iter().any(|(view, _, _)| view == "permanent"));
        for (view, zone, body) in &all {
            let want = if v == "1.3.4" { Ok(None) } else { Ok(Some(0)) };
            assert_eq!(
                parse_zone_priority(v, zone, body),
                want,
                "{v} {view} {zone}"
            );
            // the same answer read as another measured version's form fails closed
            let other = if v == "1.3.4" { "2.4.3" } else { "1.3.4" };
            assert_eq!(
                parse_zone_priority(other, zone, body),
                Err(()),
                "{v} as {other}: {view} {zone}"
            );
        }
    }
    // the session copy used before the re-measurement equals the measured answer
    let trusted = measured_list_all("2.4.3")
        .into_iter()
        .find(|(view, zone, _)| view == "runtime" && zone == "trusted")
        .unwrap()
        .2;
    assert_eq!(
        trusted
            .replace("trusted (default)", "trusted (default, active)")
            .replace("interfaces: \n", "interfaces: eth0\n"),
        LIST_ALL_243
    );
}

#[test]
fn f7_an_unbound_management_interface_is_read_as_measured() {
    // measured (P7-R2, firewalld 2.3.1, runtime and permanent): exit 2,
    // stdout empty, stderr exactly "no zone"; the management zone is then the
    // default zone. Before the fix the answer was expected on stdout and the
    // zone was unknown on every Ubuntu image.
    let s = Setup::new();
    let body = res(
        "p",
        "port",
        "zone: public, port: \"8080/tcp\", state: absent",
    );
    let unbound = |stdout: &str, stderr: &str| Output {
        completion: Completion::Exited(2),
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    };
    let go = |o: Output| {
        let f = fw();
        f.lock().unwrap().version = Some("2.3.1".into());
        f.lock().unwrap().priorities = Some(BTreeMap::new());
        f.lock().unwrap().interfaces.clear();
        for _ in 0..8 {
            f.lock()
                .unwrap()
                .forced
                .push(("--get-zone-of-interface=eth0".into(), o.clone()));
        }
        let (r, l) = run(
            s.model(&body, "").unwrap(),
            Mode::Apply,
            target(&f, net(2222)),
            ctx(),
        );
        (f, r, l)
    };
    let (_, r, l) = go(unbound("", "no zone\n"));
    assert_eq!(r.unwrap().status, AggregateStatus::Success, "{l:?}");
    assert_eq!(record(&l, "p").dynamic, "clear");
    for (name, o) in [
        ("the old assumption (stdout)", unbound("no zone\n", "")),
        ("other text", unbound("", "no zone at all\n")),
        (
            "another exit status",
            Output {
                completion: Completion::Exited(1),
                ..unbound("", "no zone\n")
            },
        ),
        ("both streams", unbound("x\n", "no zone\n")),
        ("no newline", unbound("", "no zone")),
        (
            "stderr truncated",
            Output {
                stderr_truncated: true,
                ..unbound("", "no zone\n")
            },
        ),
        (
            "stdout truncated",
            Output {
                stdout_truncated: true,
                ..unbound("", "no zone\n")
            },
        ),
        (
            "sudo noise",
            unbound("", "sudo: unable to resolve host x\nno zone\n"),
        ),
    ] {
        let (f, r, l) = go(o);
        refused(&r, &f, "p", "unknown");
        assert!(
            record(&l, "p").dynamic.starts_with("unknown"),
            "{name}: {l:?}"
        );
    }
}
