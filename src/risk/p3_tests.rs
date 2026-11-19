//! firewalld 0.3.0 and the P3 connection-risk rules (DESIGN §43, §44).
//!
//! The 0.3.0 catalog and plugin are the candidate files of the repository
//! (`plugins/first-party/candidates/`), loaded through a test registry: the
//! release's registry does not list 0.3.0 until it is measured on real
//! hosts. The classification table in force is the production one (0.3.0 is
//! classified and enforced there, bound to the candidate's digest).

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
    include_str!("../../plugins/first-party/candidates/firewalld-0.3.0.catalog.toml");
const PLUGIN_030: &str =
    include_str!("../../plugins/first-party/candidates/firewalld-0.3.0.plugin.toml");

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
    // priority not answered
    let f = fw();
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
fn the_030_classification_is_bound_to_the_candidate_bytes_and_030_is_not_registered() {
    let entry = super::CATALOG_RULES
        .iter()
        .find(|c| c.id == "firewalld" && c.version == "0.3.0")
        .expect("0.3.0 is classified");
    assert_eq!(entry.sha256, approval::sha256_hex(CATALOG_030.as_bytes()));
    assert_eq!(entry.enforcement, super::Enforcement::Enforced);
    // Not in the release's registry until measured on real hosts.
    assert!(!crate::plugin::FIRST_PARTY_CATALOGS
        .iter()
        .any(|c| c.id == "firewalld" && c.version == "0.3.0"));
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
