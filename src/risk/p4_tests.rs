//! `nm_connection` and the NetworkManager checkpoint (DESIGN §43, §45),
//! through the engine with a scripted NetworkManager (`FakeNm`) and the
//! P2 approval primitive.

use super::approval::Store;
use super::engine::{RiskContext, RiskLog};
use crate::engine::{Engine, Mode, RunOptions, RunReport, TargetSpec};
use crate::executor::FakeTarget;
use crate::fakesys::{FakeNet, FakeNm, FakeRollback};
use crate::model::{load_model, Model};
use crate::result::{Change, Execution};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};

/// mgmt (eth0, active, 192.0.2.10/24 via 192.0.2.1) and lan (eth1,
/// inactive, 198.51.100.10/24, no gateway).
fn nm() -> Arc<Mutex<FakeNm>> {
    let mut n = FakeNm::default();
    let mut m = FakeNm::profile("mgmt", "eth0");
    m.insert("ipv4.method".into(), "manual".into());
    m.insert("ipv4.addresses".into(), "192.0.2.10/24".into());
    m.insert("ipv4.gateway".into(), "192.0.2.1".into());
    m.insert("ipv6.method".into(), "ignore".into());
    let mu = n.add(m);
    n.activate(&mu, "eth0");
    let mut l = FakeNm::profile("lan", "eth1");
    l.insert("ipv4.method".into(), "manual".into());
    l.insert("ipv4.addresses".into(), "198.51.100.10/24".into());
    l.insert("ipv4.dns-search".into(), "keep.example".into());
    l.insert("ipv6.method".into(), "ignore".into());
    l.insert("connection.autoconnect".into(), "no".into());
    n.add(l);
    Arc::new(Mutex::new(n))
}

fn net() -> FakeNet {
    FakeNet {
        ssh_connection: Some("203.0.113.9 50000 192.0.2.10 22".into()),
        host_key_sha256: Some("bb".repeat(32)),
        ssh_user: Some("admin".into()),
        ss: Some("0 0 192.0.2.10:22 203.0.113.9:50000\n".into()),
        ip_addr: Some("2: eth0    inet 192.0.2.10/24 brd 192.0.2.255 scope global eth0\n".into()),
        default_route: Some("203.0.113.9 from 192.0.2.10 via 192.0.2.1 dev eth0\n".into()),
        reconnect: Some(true),
        ..Default::default()
    }
}

fn target(n: &Arc<Mutex<FakeNm>>, net: FakeNet) -> FakeTarget {
    let mut t = FakeTarget::ubuntu2404().as_root().with_nm(n.clone());
    t.manager.net = net;
    t
}

struct Recipe {
    dir: tempfile::TempDir,
}

impl Recipe {
    fn new() -> Recipe {
        Recipe {
            dir: tempfile::tempdir().unwrap(),
        }
    }
    fn model(&self, body: &str) -> crate::error::Result<Model> {
        let p = self.dir.path().join("r.yml");
        std::fs::write(&p, format!("version: 1\nresources:\n{}", body)).unwrap();
        load_model(&p)
    }
}

fn nmres(id: &str, with: &str) -> String {
    format!("  - id: {id}\n    type: nm_connection\n    with: {{ {with} }}\n")
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

fn audit(model: Model, t: FakeTarget) -> crate::audit::AuditReport {
    let opts = RunOptions {
        mode: Mode::Plan,
        sudo: false,
        target: TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(t),
    };
    crate::audit::run_audit(Engine::new(model, opts).unwrap()).unwrap()
}

/// (execution, change, reason) of one resource, from a report or an error.
fn outcome(r: &crate::error::Result<RunReport>, id: &str) -> (Execution, Change, String) {
    match r {
        Ok(rep) => {
            let x = rep
                .resources
                .iter()
                .find(|x| x.id == id)
                .unwrap_or_else(|| panic!("no {id}"));
            (
                x.execution,
                x.change,
                format!(
                    "{} {}",
                    x.reason.clone().unwrap_or_default(),
                    x.notes.join(" | ")
                ),
            )
        }
        Err(e) => (
            if e.kind == crate::error::ErrorKind::Indeterminate {
                Execution::Indeterminate
            } else {
                Execution::Failed
            },
            Change::None,
            e.message.clone(),
        ),
    }
}

fn muts(n: &Arc<Mutex<FakeNm>>) -> usize {
    n.lock().unwrap().mutations.len()
}

fn cps(n: &Arc<Mutex<FakeNm>>) -> Vec<String> {
    n.lock().unwrap().checkpoint_calls.clone()
}

fn refused(r: &crate::error::Result<RunReport>, n: &Arc<Mutex<FakeNm>>, id: &str, want: &str) {
    let (ex, ch, why) = outcome(r, id);
    assert_ne!(ex, Execution::Succeeded, "{why}");
    assert_eq!(ch, Change::None, "{why}");
    assert!(why.contains(want), "{want}: {why}");
    assert_eq!(muts(n), 0, "{:?}", n.lock().unwrap().mutations);
}

/// An approval for exactly what plan saw.
fn approval_for(
    rc: &Recipe,
    body: &str,
    t: impl Fn() -> FakeTarget,
) -> (tempfile::TempDir, RiskContext, Store) {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let st = Store::at(&d.path().join("state"));
    let mut c = ctx();
    c.store = Some(st.clone());
    let (r, l) = run(rc.model(body).unwrap(), Mode::Plan, t(), c.clone());
    let rep = r.unwrap();
    let key = st.key().unwrap();
    let content =
        super::engine::content_object(&st, &key, "web01", &rc.model(body).unwrap(), &rep, &l);
    let p = st
        .write_request(&d.path().join("req"), "web01", content, json!({}))
        .unwrap();
    let rec = st.approve(&p, 600, "tester", |_| Ok(true)).unwrap();
    c.approval = Some(rec);
    (d, c, st)
}

fn ledger_events(st: &Store) -> Vec<String> {
    st.ledger_lines()
        .unwrap()
        .iter()
        .map(|l| l["event"].as_str().unwrap_or("").to_string())
        .collect()
}

fn lan_dns() -> String {
    nmres(
        "lan",
        "name: lan, ipv4: { dns: [192.0.2.53, 198.51.100.53] }",
    )
}

// ---------------------------------------------------------------------------
// plan, apply, audit
// ---------------------------------------------------------------------------

#[test]
fn plan_apply_audit_agree_and_second_apply_is_unchanged() {
    let rc = Recipe::new();
    let n = nm();
    let body = lan_dns();
    let a = audit(rc.model(&body).unwrap(), target(&n, net()));
    assert_eq!(
        a.resources[0].status,
        crate::audit::AuditResourceStatus::Drift
    );
    assert_eq!(a.resources[0].details[0].dimension, "ipv4.dns");
    assert!(a
        .commands
        .iter()
        .all(|c| !c.args.iter().any(|x| x == "modify")));
    let (r, l) = run(
        rc.model(&body).unwrap(),
        Mode::Plan,
        target(&n, net()),
        ctx(),
    );
    let (ex, ch, why) = outcome(&r, "lan");
    assert_eq!((ex, ch), (Execution::Succeeded, Change::Changed), "{why}");
    assert!(
        why.contains("would_run=modify;set ipv4.dns=192.0.2.53,198.51.100.53"),
        "{why}"
    );
    assert_eq!(l.records[0].dynamic, "clear");
    assert_eq!(muts(&n), 0, "plan changes nothing");
    let (r, _) = run(
        rc.model(&body).unwrap(),
        Mode::Apply,
        target(&n, net()),
        ctx(),
    );
    assert_eq!(
        outcome(&r, "lan").1,
        Change::Changed,
        "{:?}",
        outcome(&r, "lan")
    );
    let m = n.lock().unwrap().mutations.clone();
    assert_eq!(m.len(), 1);
    assert_eq!(m[0][..3], ["connection", "modify", "uuid"]);
    // Undeclared fields are kept.
    let p = n.lock().unwrap().find("lan").unwrap().clone();
    assert_eq!(p["ipv4.dns-search"], "keep.example");
    assert_eq!(p["connection.autoconnect"], "no");
    assert_eq!(p["ipv4.dns"], "192.0.2.53,198.51.100.53");
    let (r, _) = run(
        rc.model(&body).unwrap(),
        Mode::Apply,
        target(&n, net()),
        ctx(),
    );
    assert_eq!(outcome(&r, "lan").1, Change::None, "idempotent");
    assert_eq!(muts(&n), 1);
    let a = audit(rc.model(&body).unwrap(), target(&n, net()));
    assert_eq!(
        a.resources[0].status,
        crate::audit::AuditResourceStatus::Compliant
    );
}

#[test]
fn active_true_false_and_absent() {
    let rc = Recipe::new();
    let n = nm();
    let body = nmres("lan", "name: lan, active: true");
    let (r, _) = run(
        rc.model(&body).unwrap(),
        Mode::Apply,
        target(&n, net()),
        ctx(),
    );
    assert_eq!(
        outcome(&r, "lan").1,
        Change::Changed,
        "{:?}",
        outcome(&r, "lan")
    );
    assert!(n.lock().unwrap().active.iter().any(|(_, d, _)| d == "eth1"));
    let (r, _) = run(
        rc.model(&body).unwrap(),
        Mode::Apply,
        target(&n, net()),
        ctx(),
    );
    assert_eq!(outcome(&r, "lan").1, Change::None);
    let body = nmres("lan", "name: lan, active: false");
    let (r, _) = run(
        rc.model(&body).unwrap(),
        Mode::Apply,
        target(&n, net()),
        ctx(),
    );
    assert_eq!(
        outcome(&r, "lan").1,
        Change::Changed,
        "{:?}",
        outcome(&r, "lan")
    );
    assert!(!n.lock().unwrap().active.iter().any(|(_, d, _)| d == "eth1"));
    let body = nmres("lan", "name: lan, state: absent");
    let (r, _) = run(
        rc.model(&body).unwrap(),
        Mode::Apply,
        target(&n, net()),
        ctx(),
    );
    assert_eq!(
        outcome(&r, "lan").1,
        Change::Changed,
        "{:?}",
        outcome(&r, "lan")
    );
    assert!(n.lock().unwrap().find("lan").is_none());
    let (r, _) = run(
        rc.model(&body).unwrap(),
        Mode::Apply,
        target(&n, net()),
        ctx(),
    );
    assert_eq!(outcome(&r, "lan").1, Change::None);
}

#[test]
fn changing_an_active_profile_without_active_says_it_is_not_reactivated() {
    let rc = Recipe::new();
    let n = nm();
    let u = n.lock().unwrap().find("lan").unwrap()["connection.uuid"].clone();
    n.lock().unwrap().activate(&u, "eth1");
    let (r, _) = run(
        rc.model(&lan_dns()).unwrap(),
        Mode::Plan,
        target(&n, net()),
        ctx(),
    );
    assert!(
        outcome(&r, "lan")
            .2
            .contains("not applied to the running device"),
        "{:?}",
        outcome(&r, "lan")
    );
}

#[test]
fn create_with_settings_then_verify() {
    let rc = Recipe::new();
    let n = nm();
    let body = nmres(
        "new",
        "name: \"db:net\", ifname: eth1, autoconnect: false, ipv4: { method: manual, addresses: [198.51.100.20/24] }, ipv6: { method: ignore }",
    );
    let (r, l) = run(
        rc.model(&body).unwrap(),
        Mode::Apply,
        target(&n, net()),
        ctx(),
    );
    assert_eq!(
        outcome(&r, "new").1,
        Change::Changed,
        "{:?} {l:?}",
        outcome(&r, "new")
    );
    let p = n.lock().unwrap().find("db:net").unwrap().clone();
    assert_eq!(p["ipv4.addresses"], "198.51.100.20/24");
    let (r, _) = run(
        rc.model(&body).unwrap(),
        Mode::Apply,
        target(&n, net()),
        ctx(),
    );
    assert_eq!(
        outcome(&r, "new").1,
        Change::None,
        "escaped name observed again"
    );
}

// ---------------------------------------------------------------------------
// prechecks and observation
// ---------------------------------------------------------------------------

#[test]
fn prechecks_and_strict_observation() {
    let rc = Recipe::new();
    let body = lan_dns();
    // NetworkManager not running.
    let n = nm();
    let mut t = target(&n, net());
    t.services.insert(
        crate::nm::NM_SERVICE.into(),
        ("loaded".into(), "inactive".into(), "disabled".into()),
    );
    let (r, _) = run(rc.model(&body).unwrap(), Mode::Plan, t, ctx());
    assert!(
        outcome(&r, "lan")
            .2
            .contains("NetworkManager is not running"),
        "{:?}",
        outcome(&r, "lan")
    );
    // nmcli missing.
    let mut t = target(&n, net());
    t.executables.remove(crate::nm::NMCLI);
    let (r, _) = run(rc.model(&body).unwrap(), Mode::Plan, t, ctx());
    assert!(
        outcome(&r, "lan").2.contains("/usr/bin/nmcli is missing"),
        "{:?}",
        outcome(&r, "lan")
    );
    // Two profiles with the name.
    let n = nm();
    n.lock().unwrap().add(FakeNm::profile("lan", "eth1"));
    let (r, _) = run(
        rc.model(&body).unwrap(),
        Mode::Plan,
        target(&n, net()),
        ctx(),
    );
    assert!(
        outcome(&r, "lan")
            .2
            .contains("2 NetworkManager profiles have the name"),
        "{:?}",
        outcome(&r, "lan")
    );
    // An unknown field in the profile output.
    let n = nm();
    let u = n.lock().unwrap().find("lan").unwrap()["connection.uuid"].clone();
    let text = crate::nm::PROFILE_FIELDS
        .iter()
        .map(|f| {
            let v = n.lock().unwrap().find("lan").unwrap()[*f].clone();
            format!("{}:{}\n", f, crate::nm::escape_terse(&v))
        })
        .collect::<String>()
        + "802-1x.identity:x\n";
    assert!(text.contains(&u));
    n.lock().unwrap().raw.insert("profile".into(), text);
    let (r, _) = run(
        rc.model(&body).unwrap(),
        Mode::Apply,
        target(&n, net()),
        ctx(),
    );
    refused(&r, &n, "lan", "unexpected field 802-1x.identity");
    // A bad escape in the list.
    let n = nm();
    n.lock()
        .unwrap()
        .raw
        .insert("list".into(), "la\\n:x:y\n".into());
    let (r, _) = run(
        rc.model(&body).unwrap(),
        Mode::Apply,
        target(&n, net()),
        ctx(),
    );
    refused(&r, &n, "lan", "could not be read");
    // An unknown active state.
    let n = nm();
    let u = n.lock().unwrap().find("lan").unwrap()["connection.uuid"].clone();
    n.lock()
        .unwrap()
        .raw
        .insert("active".into(), format!("lan:{u}:eth1:weird\n"));
    let (r, _) = run(
        rc.model(&body).unwrap(),
        Mode::Apply,
        target(&n, net()),
        ctx(),
    );
    refused(&r, &n, "lan", "unknown active-profile state");
    // A profile in transition.
    let n = nm();
    let u = n.lock().unwrap().find("lan").unwrap()["connection.uuid"].clone();
    n.lock()
        .unwrap()
        .active
        .push((u, "eth1".into(), "activating".into()));
    let (r, _) = run(
        rc.model(&body).unwrap(),
        Mode::Apply,
        target(&n, net()),
        ctx(),
    );
    refused(&r, &n, "lan", "in transition");
}

#[test]
fn the_scripted_networkmanager_never_succeeds_implicitly() {
    let mut n = FakeNm::default();
    for args in [
        vec!["connection", "reload"],
        vec!["general", "reload"],
        vec!["-t", "connection", "show"],
        vec!["connection", "modify", "id", "lan", "ipv4.dns", "x"],
    ] {
        let a: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let o = n.run(crate::nm::NMCLI, &a);
        assert_ne!(
            o.completion,
            crate::executor::Completion::Exited(0),
            "{args:?}"
        );
    }
    let o = n.run(crate::nm::BUSCTL, &["--system".into(), "tree".into()]);
    assert_ne!(o.completion, crate::executor::Completion::Exited(0));
}

#[test]
fn model_rules() {
    let rc = Recipe::new();
    let e = rc
        .model(&(nmres("a", "name: lan") + &nmres("b", "name: lan")))
        .unwrap_err();
    assert!(
        e.message
            .contains("conflicting ownership of NetworkManager profile"),
        "{}",
        e.message
    );
    let e = rc.model(&nmres("a", "name: lan, mtu: 9000")).unwrap_err();
    assert!(
        e.message.contains("unknown field") && e.message.contains("mtu"),
        "{}",
        e.message
    );
    let e = rc
        .model(&nmres("a", "name: lan, ipv4: { method: manual }"))
        .unwrap_err();
    assert!(
        e.message.contains("needs at least one address"),
        "{}",
        e.message
    );
    assert!(crate::plugin::verify::BUILTIN_RESOURCE_TYPES.contains(&"nm_connection"));
}

// ---------------------------------------------------------------------------
// management-path rules (§45.6)
// ---------------------------------------------------------------------------

fn dynamic_of(body: &str, n: &Arc<Mutex<FakeNm>>, netf: FakeNet) -> (String, Option<String>) {
    let rc = Recipe::new();
    let (r, l) = run(rc.model(body).unwrap(), Mode::Plan, target(n, netf), ctx());
    r.unwrap();
    let rec = l.records.last().unwrap();
    (rec.dynamic.clone(), rec.reason.clone())
}

#[test]
fn management_path_rules() {
    let n = nm();
    let d = |body: &str| dynamic_of(body, &n, net());
    assert_eq!(d(&lan_dns()).0, "clear", "DNS on a non-management profile");
    let (dy, why) = d(&nmres("m", "name: mgmt, ipv4: { dns: [192.0.2.53] }"));
    assert_eq!(dy, "affects");
    assert!(why.unwrap().contains("management interface eth0"));
    // Moving a profile onto the management interface.
    assert_eq!(d(&nmres("lan", "name: lan, ifname: eth0")).0, "affects");
    // Moving a management profile away.
    assert_eq!(d(&nmres("m", "name: mgmt, ifname: eth1")).0, "affects");
    // Autoconnect without an interface (created: autoconnect is assumed on).
    let (dy, why) = d(&nmres(
        "x",
        "name: x, ipv4: { method: disabled }, ipv6: { method: ignore }",
    ));
    assert_eq!(dy, "affects");
    assert!(why.unwrap().contains("autoconnect"));
    // DHCP / router advertisements.
    let (dy, why) = d(&nmres("lan", "name: lan, ipv4: { method: auto }"));
    assert_eq!(dy, "affects");
    assert!(why.unwrap().contains("automatic addressing"));
    let (dy, _) = d(&nmres("lan", "name: lan, ipv6: { method: auto }"));
    assert_eq!(dy, "affects", "IPv6 RA");
    // A gateway.
    let (dy, why) = d(&nmres(
        "lan",
        "name: lan, ipv4: { method: manual, addresses: [198.51.100.10/24], gateway: 198.51.100.1 }",
    ));
    assert_eq!(dy, "affects");
    assert!(why.unwrap().contains("gateway"));
    // A connected route containing the client address.
    let (dy, why) = d(&nmres(
        "lan",
        "name: lan, ipv4: { method: manual, addresses: [203.0.113.5/24] }",
    ));
    assert_eq!(dy, "affects");
    assert!(why.unwrap().contains("client address"));
    // Turning autoconnect on for an inactive profile with automatic
    // addressing: NetworkManager may activate it by itself.
    {
        let n2 = nm();
        let mut g = n2.lock().unwrap();
        let i = g
            .profiles
            .iter()
            .position(|p| p["connection.id"] == "lan")
            .unwrap();
        g.profiles[i].insert("ipv4.method".into(), "auto".into());
        g.profiles[i].insert("ipv4.addresses".into(), String::new());
        drop(g);
        let (dy, why) = dynamic_of(&nmres("lan", "name: lan, autoconnect: true"), &n2, net());
        assert_eq!(dy, "affects", "{why:?}");
        // The same profile with autoconnect left off: a DNS change is clear.
        assert_eq!(dynamic_of(&lan_dns(), &n2, net()).0, "clear");
    }
    // A manual address elsewhere, no gateway: clear.
    assert_eq!(
        d(&nmres(
            "lan",
            "name: lan, ipv4: { method: manual, addresses: [198.51.100.11/24] }"
        ))
        .0,
        "clear"
    );
    // Deactivating or deleting the active management profile.
    assert_eq!(d(&nmres("m", "name: mgmt, active: false")).0, "affects");
    assert_eq!(d(&nmres("m", "name: mgmt, state: absent")).0, "affects");
    // Unreadable path (no SSH_CONNECTION, as for a local target): unknown.
    let mut local = net();
    local.ssh_connection = None;
    assert_eq!(dynamic_of(&lan_dns(), &n, local).0, "unknown");
}

#[test]
fn local_target_refuses_every_change() {
    let rc = Recipe::new();
    let n = nm();
    let mut local = net();
    local.ssh_connection = None;
    let (r, _) = run(
        rc.model(&lan_dns()).unwrap(),
        Mode::Apply,
        target(&n, local),
        ctx(),
    );
    refused(&r, &n, "lan", "unknown");
}

#[test]
fn affects_without_approval_is_refused() {
    let rc = Recipe::new();
    let n = nm();
    let body = nmres("m", "name: mgmt, active: true, ipv4: { dns: [192.0.2.53] }");
    let (r, _) = run(
        rc.model(&body).unwrap(),
        Mode::Apply,
        target(&n, net()),
        ctx(),
    );
    refused(&r, &n, "m", "has no approval");
    assert!(cps(&n).is_empty());
}

#[test]
fn facts_and_registers_in_nm_connection() {
    let rc = Recipe::new();
    let n = nm();
    // A fact makes it R: apply without approval stops before contact.
    let body = nmres("m", "name: lan, ipv4: { dns: [\"{{ facts.os.id }}\"] }");
    let (r, _) = run(
        rc.model(&body).unwrap(),
        Mode::Apply,
        target(&n, net()),
        ctx(),
    );
    assert!(r.err().unwrap().message.contains("need an approval"));
    assert_eq!(muts(&n), 0);
    let body = "  - id: c\n    type: command\n    with: { argv: [/bin/true] }\n    register: out\n"
        .to_string()
        + &nmres(
            "m",
            "name: lan, ipv4: { dns: [\"{{ registers.out.stdout }}\"] }",
        );
    let e = rc
        .model(&body)
        .and_then(|m| run(m, Mode::Plan, target(&n, net()), ctx()).0);
    assert!(e.is_err(), "register dependent value refused");
}

// ---------------------------------------------------------------------------
// checkpoint (§45.7)
// ---------------------------------------------------------------------------

/// A management change that takes effect now: the gateway of the active
/// management profile, activated again.
fn mgmt_change(extra: &str) -> String {
    nmres(
        "m",
        &format!(
            "name: mgmt, active: true, ipv4: {{ method: manual, addresses: [192.0.2.10/24], gateway: 192.0.2.254 }}{}",
            extra
        ),
    )
}

#[test]
fn checkpoint_success_keeps_the_change() {
    let rc = Recipe::new();
    let n = nm();
    let body = mgmt_change("");
    let (_d, c, st) = approval_for(&rc, &body, || target(&n, net()));
    let (r, l) = run(rc.model(&body).unwrap(), Mode::Apply, target(&n, net()), c);
    let (ex, ch, why) = outcome(&r, "m");
    assert_eq!(
        (ex, ch),
        (Execution::Succeeded, Change::Changed),
        "{why} {l:?}"
    );
    assert!(why.contains("procedure=checkpoint"), "{why}");
    assert!(why.contains("recovery is not guaranteed"), "{why}");
    assert_eq!(cps(&n), ["create", "destroy"]);
    assert_eq!(
        n.lock().unwrap().find("mgmt").unwrap()["ipv4.gateway"],
        "192.0.2.254"
    );
    // The checkpoint covered the management device.
    let rec = n.lock().unwrap().received.clone();
    let create = rec
        .iter()
        .find(|(_, a)| a.iter().any(|x| x == "CheckpointCreate"))
        .unwrap();
    assert!(
        create
            .1
            .iter()
            .any(|x| x == "/org/freedesktop/NetworkManager/Devices/1"),
        "{create:?}"
    );
    assert!(create.1.iter().any(|x| x == "90"));
    let ev = ledger_events(&st);
    for e in [
        "checkpoint-intent",
        "checkpoint-created",
        "checkpoint-destroyed",
    ] {
        assert!(ev.contains(&e.to_string()), "{e}: {ev:?}");
    }
}

#[test]
fn checkpoint_device_set_includes_the_profile_device() {
    let rc = Recipe::new();
    let n = nm();
    // lan moves onto eth0? no: lan gets a gateway on eth1 (affects) and is
    // activated; the checkpoint covers eth0 (management) and eth1.
    let body = nmres(
        "lan",
        "name: lan, active: true, ipv4: { method: manual, addresses: [198.51.100.10/24], gateway: 198.51.100.1 }",
    );
    let (_d, c, _st) = approval_for(&rc, &body, || target(&n, net()));
    let (r, _) = run(rc.model(&body).unwrap(), Mode::Apply, target(&n, net()), c);
    assert_eq!(
        outcome(&r, "lan").1,
        Change::Changed,
        "{:?}",
        outcome(&r, "lan")
    );
    let rec = n.lock().unwrap().received.clone();
    let create = rec
        .iter()
        .find(|(_, a)| a.iter().any(|x| x == "CheckpointCreate"))
        .unwrap()
        .1
        .clone();
    assert_eq!(create[7], "2", "{create:?}");
    assert!(create.contains(&"/org/freedesktop/NetworkManager/Devices/1".to_string()));
    assert!(create.contains(&"/org/freedesktop/NetworkManager/Devices/2".to_string()));
}

#[test]
fn approved_change_that_takes_effect_later_is_refused() {
    let rc = Recipe::new();
    let n = nm();
    // No `active`: the active management profile would change only at its
    // next activation; a checkpoint cannot test that.
    let body = nmres("m", "name: mgmt, ipv4: { dns: [192.0.2.53] }");
    let (_d, c, _st) = approval_for(&rc, &body, || target(&n, net()));
    let (r, _) = run(rc.model(&body).unwrap(), Mode::Apply, target(&n, net()), c);
    refused(&r, &n, "m", "takes effect only at a later activation");
    assert!(cps(&n).is_empty());
}

#[test]
fn approved_autoconnect_without_interface_is_refused() {
    let rc = Recipe::new();
    let n = nm();
    let body = nmres(
        "x",
        "name: x, active: true, ipv4: { method: disabled }, ipv6: { method: ignore }",
    );
    let (_d, c, _st) = approval_for(&rc, &body, || target(&n, net()));
    let (r, _) = run(rc.model(&body).unwrap(), Mode::Apply, target(&n, net()), c);
    refused(&r, &n, "x", "autoconnects without an interface");
    assert!(cps(&n).is_empty());
}

#[test]
fn checkpoint_unavailable_refuses_before_any_change() {
    for (what, set) in [
        ("does not offer the checkpoint methods", 0),
        ("checkpoint permission is auth", 1),
        ("creating the checkpoint was refused", 2),
    ] {
        let rc = Recipe::new();
        let n = nm();
        let body = mgmt_change("");
        let (_d, c, st) = approval_for(&rc, &body, || target(&n, net()));
        {
            let mut g = n.lock().unwrap();
            match set {
                0 => g.checkpoint_api = false,
                1 => g.permission = "auth".into(),
                _ => {
                    g.create_fails = Some((
                        1,
                        "Call failed: Not authorized to perform this operation".into(),
                    ))
                }
            }
        }
        let (r, l) = run(rc.model(&body).unwrap(), Mode::Apply, target(&n, net()), c);
        refused(&r, &n, "m", what);
        assert!(
            l.records.last().unwrap().dynamic.contains("refused"),
            "{l:?}"
        );
        let calls = cps(&n);
        assert_eq!(calls.len(), usize::from(set == 2), "{what}: {calls:?}");
        if set == 2 {
            assert!(ledger_events(&st).contains(&"checkpoint-refused".to_string()));
        }
    }
}

#[test]
fn checkpoint_without_busctl_is_refused() {
    let rc = Recipe::new();
    let n = nm();
    let body = mgmt_change("");
    let (_d, c, _st) = approval_for(&rc, &body, || target(&n, net()));
    let mut t = target(&n, net());
    t.executables.remove(crate::nm::BUSCTL);
    let (r, _) = run(rc.model(&body).unwrap(), Mode::Apply, t, c);
    refused(&r, &n, "m", "/usr/bin/busctl is missing");
}

fn failing_probe(n: &Arc<Mutex<FakeNm>>) -> FakeNet {
    let _ = n;
    let mut f = net();
    f.reconnect = Some(false);
    f
}

#[test]
fn probe_failure_rolls_back_and_verifies() {
    let rc = Recipe::new();
    let n = nm();
    let before = n.lock().unwrap().profiles.clone();
    let body = mgmt_change("");
    let (_d, c, st) = approval_for(&rc, &body, || target(&n, net()));
    let (r, _) = run(
        rc.model(&body).unwrap(),
        Mode::Apply,
        target(&n, failing_probe(&n)),
        c,
    );
    let (ex, _, why) = outcome(&r, "m");
    assert_eq!(ex, Execution::Failed, "{why}");
    assert!(
        why.contains("rolled back and the previous profile and active state were verified"),
        "{why}"
    );
    assert_eq!(cps(&n), ["create", "rollback"]);
    assert_eq!(n.lock().unwrap().profiles, before, "restored");
    let ev = ledger_events(&st);
    assert!(ev.contains(&"checkpoint-rolled-back".to_string()), "{ev:?}");
    assert!(ev.contains(&"rollback-verified".to_string()), "{ev:?}");
    assert!(!ev.contains(&"checkpoint-destroyed".to_string()));
}

#[test]
fn explicit_rollback_failure_waits_for_the_timeout() {
    let rc = Recipe::new();
    let n = nm();
    let before = n.lock().unwrap().profiles.clone();
    let body = mgmt_change(", checkpoint_timeout: 30");
    let (_d, c, _st) = approval_for(&rc, &body, || target(&n, net()));
    n.lock().unwrap().rollback = FakeRollback::Fails;
    let t = target(&n, failing_probe(&n));
    let opts = RunOptions {
        mode: Mode::Apply,
        sudo: false,
        target: TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(t),
    };
    let e = Engine::new(rc.model(&body).unwrap(), opts)
        .unwrap()
        .with_risk(c);
    let r = e.run();
    let (ex, _, why) = outcome(&r, "m");
    assert_eq!(ex, Execution::Failed, "{why}");
    assert!(why.contains("explicit rollback failed"), "{why}");
    assert!(
        why.contains("after the timeout the previous profile"),
        "{why}"
    );
    assert_eq!(cps(&n), ["create", "rollback", "expired"]);
    assert_eq!(n.lock().unwrap().profiles, before);
}

#[test]
fn rollback_that_restores_nothing_is_indeterminate() {
    let rc = Recipe::new();
    let n = nm();
    let body = mgmt_change("");
    let (_d, c, st) = approval_for(&rc, &body, || target(&n, net()));
    n.lock().unwrap().rollback = FakeRollback::Noop;
    let (r, _) = run(
        rc.model(&body).unwrap(),
        Mode::Apply,
        target(&n, failing_probe(&n)),
        c,
    );
    let (ex, _, why) = outcome(&r, "m");
    assert_eq!(ex, Execution::Indeterminate, "{why}");
    assert!(why.contains("could not be verified"), "{why}");
    assert!(ledger_events(&st).contains(&"rollback-unverified".to_string()));
}

#[test]
fn dead_original_connection_waits_timeout_plus_15_and_verifies() {
    for (timeout, reconnect, want) in [
        (90u64, Some(true), Execution::Failed),
        (30, Some(true), Execution::Failed),
        (90, Some(false), Execution::Indeterminate),
        (90, None, Execution::Indeterminate),
    ] {
        let rc = Recipe::new();
        let n = nm();
        let before = n.lock().unwrap().profiles.clone();
        let body = mgmt_change(&format!(", checkpoint_timeout: {}", timeout));
        let (_d, c, _st) = approval_for(&rc, &body, || target(&n, net()));
        let mut f = failing_probe(&n);
        f.original_alive = Some(false);
        f.reconnect_after_wait = reconnect;
        let t = target(&n, f);
        let opts = RunOptions {
            mode: Mode::Apply,
            sudo: false,
            target: TargetSpec { ssh: None },
            verbose: false,
            fault: None,
            fake_target: Some(t),
        };
        let e = Engine::new(rc.model(&body).unwrap(), opts)
            .unwrap()
            .with_risk(c);
        let r = e.run();
        let (ex, _, why) = outcome(&r, "m");
        assert_eq!(ex, want, "{timeout} {reconnect:?}: {why}");
        assert!(why.contains("original connection does not answer"), "{why}");
        // NetworkManager rolled back by itself at the timeout, which the
        // checkpoint was created with.
        assert_eq!(cps(&n), ["create", "expired"]);
        let rec = n.lock().unwrap().received.clone();
        let create = &rec
            .iter()
            .find(|(_, a)| a.iter().any(|x| x == "CheckpointCreate"))
            .unwrap()
            .1;
        assert_eq!(create[create.len() - 2], timeout.to_string());
        assert_eq!(n.lock().unwrap().profiles, before);
    }
}

#[test]
fn checkpoint_destroy_failure_is_rolled_back_by_the_timeout() {
    let rc = Recipe::new();
    let n = nm();
    let body = mgmt_change("");
    let (_d, c, st) = approval_for(&rc, &body, || target(&n, net()));
    n.lock().unwrap().destroy_fails = true;
    let (r, _) = run(rc.model(&body).unwrap(), Mode::Apply, target(&n, net()), c);
    let (ex, _, why) = outcome(&r, "m");
    assert_eq!(ex, Execution::Failed, "{why}");
    assert!(why.contains("could not be destroyed"), "{why}");
    assert_eq!(cps(&n), ["create", "destroy", "expired"]);
    assert!(ledger_events(&st).contains(&"checkpoint-destroy-failed".to_string()));
}

#[test]
fn failed_change_inside_the_checkpoint_is_rolled_back() {
    let rc = Recipe::new();
    let n = nm();
    let before = n.lock().unwrap().profiles.clone();
    let body = mgmt_change("");
    let (_d, c, _st) = approval_for(&rc, &body, || target(&n, net()));
    n.lock().unwrap().fail_verb.insert(
        "up".into(),
        (4, "Error: Connection activation failed.".into()),
    );
    let (r, _) = run(rc.model(&body).unwrap(), Mode::Apply, target(&n, net()), c);
    let (ex, _, why) = outcome(&r, "m");
    assert_eq!(ex, Execution::Failed, "{why}");
    assert!(why.contains("the change failed"), "{why}");
    assert_eq!(cps(&n), ["create", "rollback"]);
    assert_eq!(n.lock().unwrap().profiles, before);
}

// ---------------------------------------------------------------------------
// approvals
// ---------------------------------------------------------------------------

#[test]
fn approval_bound_to_the_observed_state() {
    let rc = Recipe::new();
    let n = nm();
    let body = mgmt_change("");
    let (_d, c, _st) = approval_for(&rc, &body, || target(&n, net()));
    // The profile changes after the approval: the change digest differs.
    {
        let mut g = n.lock().unwrap();
        let i = g
            .profiles
            .iter()
            .position(|p| p["connection.id"] == "mgmt")
            .unwrap();
        g.profiles[i].insert("ipv4.dns".into(), "192.0.2.99".into());
    }
    let (r, _) = run(rc.model(&body).unwrap(), Mode::Apply, target(&n, net()), c);
    refused(&r, &n, "m", "differs from the approved change");
    assert!(cps(&n).is_empty());
}

#[test]
fn an_approval_is_used_once() {
    let rc = Recipe::new();
    let n = nm();
    let body = mgmt_change("");
    let (_d, c, st) = approval_for(&rc, &body, || target(&n, net()));
    let id = c.approval.as_ref().unwrap()["approval_id"]
        .as_str()
        .unwrap()
        .to_string();
    let hosts: std::collections::BTreeSet<String> = ["web01".to_string()].into_iter().collect();
    st.use_for_run(std::slice::from_ref(&id), &hosts).unwrap();
    let again = st.use_for_run(&[id], &hosts);
    assert!(again.is_err(), "a second use is refused");
}

#[test]
fn a_second_connection_risk_change_in_the_same_run_is_refused() {
    let rc = Recipe::new();
    let n = nm();
    let body = lan_dns() + &nmres("lan2", "name: other, ifname: eth1, autoconnect: false, ipv4: { method: disabled }, ipv6: { method: ignore }");
    let (r, l) = run(
        rc.model(&body).unwrap(),
        Mode::Plan,
        target(&n, net()),
        ctx(),
    );
    r.unwrap();
    assert_eq!(l.records[1].dynamic, "deferred");
    let (r, _) = run(
        rc.model(&body).unwrap(),
        Mode::Apply,
        target(&n, net()),
        ctx(),
    );
    let (ex, _, why) = outcome(&r, "lan2");
    assert_ne!(ex, Execution::Succeeded, "{why}");
    assert!(why.contains("earlier connection-risk change"), "{why}");
    assert_eq!(muts(&n), 1, "only the first resource changed");
}
