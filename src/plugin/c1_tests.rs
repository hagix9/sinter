//! C1 tests: partial mutate permission (DESIGN §38.4, §38.11). A trust file
//! that attests every observe operation but allows only some (or none) of
//! the mutate operations keeps the plugin loadable: audit works, and plan and
//! apply refuse, before anything is contacted, every run with a resource that
//! could need a mutate operation that is not allowed. The first-party
//! firewalld 0.2.0 files run against the scripted firewalld on a FakeTarget.

use super::protect::sha256_hex;
use super::*;
use crate::audit::{run_audit, AuditResourceStatus};
use crate::engine::{AggregateStatus, Engine, Mode, RunOptions, RunReport, TargetSpec};
use crate::error::ErrorKind;
use crate::executor::FakeTarget;
use crate::fakesys::FakeFirewalld;
use crate::model::{load_model_with_plugins, Model};
use crate::result::Change;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};

const CATALOG: &str =
    include_str!("../../plugins/first-party/catalogs/firewalld-0.2.0.catalog.toml");
const PLUGIN: &str = include_str!("../../plugins/first-party/plugins/firewalld-0.2.0.plugin.toml");

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
const ADD_SERVICE: &[&str] = &["add_service_runtime", "add_service_permanent"];

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

/// A protected plugin root with the first-party 0.2.0 files, pinned with
/// the given attested observe and allowed mutate operations.
struct Setup {
    _tmp: tempfile::TempDir,
    boundary: PathBuf,
    root: PathBuf,
}

impl Setup {
    fn new(observe: &[&str], mutate: &[&str]) -> Setup {
        let tmp = tempfile::tempdir().unwrap();
        let boundary = tmp.path().to_path_buf();
        let root = boundary.join("plugins-root");
        for d in [&root, &root.join("catalogs"), &root.join("plugins")] {
            std::fs::create_dir(d).unwrap();
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        write_mode(
            &root.join("catalogs/firewalld-0.2.0.catalog.toml"),
            CATALOG,
            0o644,
        );
        write_mode(
            &root.join("plugins/firewalld-0.2.0.plugin.toml"),
            PLUGIN,
            0o644,
        );
        let trust = format!(
            "format = 1\n\n[[catalog]]\nid = \"firewalld\"\nversion = \"0.2.0\"\nsha256 = \"{}\"\nattested_observe = {}\nallowed_mutate = {}\n\n[[plugin]]\nid = \"firewalld\"\nversion = \"0.2.0\"\nsha256 = \"{}\"\n",
            sha256_hex(CATALOG.as_bytes()),
            list(observe),
            list(mutate),
            sha256_hex(PLUGIN.as_bytes())
        );
        write_mode(&root.join("trust.toml"), &trust, 0o600);
        Setup {
            _tmp: tmp,
            boundary,
            root,
        }
    }

    fn ctx(&self) -> PluginContext {
        PluginContext::Test {
            root: self.root.clone(),
            boundary: self.boundary.clone(),
            registry: FIRST_PARTY_CATALOGS.to_vec(),
        }
    }

    fn model(&self, body: &str) -> Result<Model> {
        let p = self.boundary.join("r.yml");
        std::fs::write(&p, body).unwrap();
        load_model_with_plugins(&p, &self.ctx())
    }
}

fn recipe(resources: &str) -> String {
    format!(
        "version: 1\nplugins:\n  - id: firewalld\n    version: 0.2.0\nresources:\n{}",
        resources
    )
}

fn r(id: &str, type_: &str, with: &str) -> String {
    format!(
        "  - id: {}\n    type: {}\n    with: {{ {} }}\n",
        id, type_, with
    )
}

const SERVICE_PRESENT: &str = "zone: public, service: http, state: present";
const SERVICE_ABSENT: &str = "zone: public, service: http, state: absent";
const PORT_PRESENT: &str = "zone: public, port: 8080/tcp, state: present";

fn firewalld() -> Arc<Mutex<FakeFirewalld>> {
    Arc::new(Mutex::new(FakeFirewalld::typical()))
}

fn opts(mode: Mode, fw: &Arc<Mutex<FakeFirewalld>>) -> RunOptions {
    RunOptions {
        mode,
        sudo: false,
        target: TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(
            FakeTarget::ubuntu2404()
                .as_root()
                .with_firewalld(fw.clone()),
        ),
    }
}

fn run(model: Model, mode: Mode, fw: &Arc<Mutex<FakeFirewalld>>) -> Result<RunReport> {
    Engine::new(model, opts(mode, fw))?.run()
}

fn refused(r: Result<RunReport>) -> String {
    match r {
        Ok(rep) => panic!("expected a refusal, got {:?}", rep.status),
        Err(e) => {
            assert_eq!(e.kind, ErrorKind::Schema, "{}", e.message);
            assert_eq!(e.kind.exit_code(), 2);
            e.message
        }
    }
}

fn mutations(c: &[crate::executor::CommandRecord]) -> usize {
    c.iter()
        .filter(|r| {
            r.args
                .iter()
                .any(|a| a.starts_with("--add-") || a.starts_with("--remove-"))
        })
        .count()
}

// ---------------------------------------------------------------------------
// A. observe only
// ---------------------------------------------------------------------------

#[test]
fn observe_only_loads_audits_and_never_mutates() {
    let s = Setup::new(OBSERVE, &[]);
    let body = recipe(&format!(
        "{}{}",
        r("svc", "firewalld.service", SERVICE_PRESENT),
        r("port", "firewalld.port", PORT_PRESENT)
    ));
    let m = s.model(&body).expect("observe-only trust loads the plugin");
    let set = m.plugins.clone().unwrap();
    let c = set
        .catalog(&CatalogRef {
            id: "firewalld".into(),
            version: "0.2.0".into(),
        })
        .unwrap();
    assert!(c
        .ops()
        .filter(|o| o.class() == OpClass::Mutate)
        .all(|o| !o.is_enabled()));
    assert!(c
        .ops()
        .filter(|o| o.class() == OpClass::Observe)
        .all(|o| o.is_enabled()));

    // audit: drift reported, observations only
    let fw = firewalld();
    let a = run_audit(Engine::new(m, opts(Mode::Plan, &fw)).unwrap()).unwrap();
    assert_eq!(a.resources.len(), 2);
    assert!(a
        .resources
        .iter()
        .all(|x| x.status == AuditResourceStatus::Drift));
    assert_eq!(a.exit_code(), 7);
    assert_eq!(mutations(&a.commands), 0);
    assert!(fw.lock().unwrap().mutations.is_empty());
    assert!(!fw.lock().unwrap().received.is_empty(), "audit observed");

    // plan and apply: refused before any command
    for mode in [Mode::Plan, Mode::Apply] {
        let fw = firewalld();
        let msg = refused(run(s.model(&body).unwrap(), mode, &fw));
        assert!(msg.contains("svc"), "{}", msg);
        assert!(
            msg.contains("add_service_permanent, add_service_runtime"),
            "{}",
            msg
        );
        assert!(fw.lock().unwrap().received.is_empty(), "{:?}", mode);
    }
}

#[test]
fn a_disabled_mutate_operation_can_never_become_a_call() {
    let s = Setup::new(OBSERVE, &[]);
    let m = s
        .model(&recipe(&r("svc", "firewalld.service", SERVICE_PRESENT)))
        .unwrap();
    let set = m.plugins.clone().unwrap();
    let c = set
        .catalog(&CatalogRef {
            id: "firewalld".into(),
            version: "0.2.0".into(),
        })
        .unwrap();
    let mut v = BTreeMap::new();
    v.insert("zone".to_string(), "public".to_string());
    v.insert("service".to_string(), "http".to_string());
    let add = c.op("add_service_runtime").unwrap();
    assert!(!add.is_enabled());
    assert!(exec::MutateCall::new(add, &v, false).is_err());
    assert!(exec::ObserveCall::new(add, &v, false).is_err());
    assert!(exec::ObserveCall::new(c.op("query_service_runtime").unwrap(), &v, false).is_ok());
}

// ---------------------------------------------------------------------------
// B. partial mutate permission
// ---------------------------------------------------------------------------

#[test]
fn allowed_operations_work_and_the_others_stay_refused() {
    let s = Setup::new(OBSERVE, ADD_SERVICE);

    // A service made present needs only the allowed operations.
    let fw = firewalld();
    let add = recipe(&r("svc", "firewalld.service", SERVICE_PRESENT));
    let p = run(s.model(&add).unwrap(), Mode::Plan, &fw).unwrap();
    assert_eq!(p.status, AggregateStatus::Success);
    assert_eq!(mutations(&p.commands), 0);
    let a = run(s.model(&add).unwrap(), Mode::Apply, &fw).unwrap();
    assert_eq!(a.status, AggregateStatus::Success);
    assert_eq!(a.resources[0].change, Change::Changed);
    assert_eq!(mutations(&a.commands), 2);

    // Removing it needs remove_service_*: refused, nothing run.
    let fw = firewalld();
    let msg = refused(run(
        s.model(&recipe(&r("svc", "firewalld.service", SERVICE_ABSENT)))
            .unwrap(),
        Mode::Apply,
        &fw,
    ));
    assert!(
        msg.contains("remove_service_permanent, remove_service_runtime"),
        "{}",
        msg
    );
    assert!(!msg.contains("add_service"), "{}", msg);
    assert!(fw.lock().unwrap().received.is_empty());

    // Another type of the same plugin gains nothing from the service ops.
    let fw = firewalld();
    let msg = refused(run(
        s.model(&recipe(&r("port", "firewalld.port", PORT_PRESENT)))
            .unwrap(),
        Mode::Apply,
        &fw,
    ));
    assert!(
        msg.contains("add_port_permanent, add_port_runtime"),
        "{}",
        msg
    );
    assert!(fw.lock().unwrap().received.is_empty());
}

#[test]
fn half_of_a_facet_pair_is_not_enough() {
    // Only the runtime half of the port operations is allowed: a port needs
    // both facets, so the resource is refused (no runtime-only change).
    let s = Setup::new(OBSERVE, &["add_port_runtime"]);
    let fw = firewalld();
    let msg = refused(run(
        s.model(&recipe(&r("port", "firewalld.port", PORT_PRESENT)))
            .unwrap(),
        Mode::Apply,
        &fw,
    ));
    assert!(msg.contains("add_port_permanent"), "{}", msg);
    assert!(!msg.contains("add_port_runtime"), "{}", msg);
    assert!(fw.lock().unwrap().received.is_empty());
}

#[test]
fn a_templated_state_counts_as_every_value() {
    // The wanted state is only known when evaluated, so every value of the
    // field must be allowed: present is, absent is not.
    let s = Setup::new(OBSERVE, ADD_SERVICE);
    let body = "version: 1\nvars:\n  st: { value: present }\nplugins:\n  - { id: firewalld, version: 0.2.0 }\nresources:\n  - id: svc\n    type: firewalld.service\n    with: { zone: public, service: http, state: \"{{ vars.st }}\" }\n";
    let fw = firewalld();
    let msg = refused(run(s.model(body).unwrap(), Mode::Apply, &fw));
    assert!(msg.contains("remove_service_runtime"), "{}", msg);
    assert!(fw.lock().unwrap().received.is_empty());
    // With every operation of the type allowed it runs.
    let s = Setup::new(
        OBSERVE,
        &[
            "add_service_runtime",
            "add_service_permanent",
            "remove_service_runtime",
            "remove_service_permanent",
        ],
    );
    let fw = firewalld();
    let a = run(s.model(body).unwrap(), Mode::Apply, &fw).unwrap();
    assert_eq!(a.status, AggregateStatus::Success);
}

// ---------------------------------------------------------------------------
// C. observe attestation still required
// ---------------------------------------------------------------------------

#[test]
fn a_missing_observe_attestation_still_refuses_the_plugin() {
    let observe: Vec<&str> = OBSERVE
        .iter()
        .copied()
        .filter(|o| *o != "query_port_permanent")
        .collect();
    let all_mutate: Vec<&str> = vec![
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
    for mutate in [&all_mutate[..], &[][..]] {
        let s = Setup::new(&observe, mutate);
        let Err(e) = s.model(&recipe(&r("svc", "firewalld.service", SERVICE_PRESENT))) else {
            panic!("expected a refusal at load");
        };
        assert_eq!(e.kind, ErrorKind::Schema);
        assert!(
            e.message
                .contains("operation query_port_permanent is not attested"),
            "{}",
            e.message
        );
    }
}

// ---------------------------------------------------------------------------
// D. several resources: nothing changes before the refusal
// ---------------------------------------------------------------------------

#[test]
fn a_later_resource_without_permission_stops_the_run_before_the_first_changes() {
    let s = Setup::new(OBSERVE, ADD_SERVICE);
    // The first resource is allowed and would change; the second is not.
    for body in [
        recipe(&format!(
            "{}{}",
            r("svc", "firewalld.service", SERVICE_PRESENT),
            r("port", "firewalld.port", PORT_PRESENT)
        )),
        recipe(&format!(
            "{}{}",
            r("port", "firewalld.port", PORT_PRESENT),
            r("svc", "firewalld.service", SERVICE_PRESENT)
        )),
    ] {
        for mode in [Mode::Plan, Mode::Apply] {
            let fw = firewalld();
            let msg = refused(run(s.model(&body).unwrap(), mode, &fw));
            assert!(msg.starts_with("port:"), "{}", msg);
            let f = fw.lock().unwrap();
            assert!(f.received.is_empty(), "nothing sent in {:?}", mode);
            assert!(f.mutations.is_empty());
            assert!(!f.runtime.contains(&("public".into(), "http".into())));
        }
    }
}

#[test]
fn the_gate_reads_every_resource_whatever_it_will_observe() {
    // Already in the wanted state or not, a resource that could need an
    // operation that is not allowed is refused: the decision never depends
    // on what the target reports.
    let s = Setup::new(OBSERVE, &[]);
    let body = recipe(&r("svc", "firewalld.service", SERVICE_PRESENT));
    let fw = firewalld();
    {
        let mut f = fw.lock().unwrap();
        f.runtime.insert(("public".into(), "http".into()));
        f.permanent.insert(("public".into(), "http".into()));
    }
    let m = s.model(&body).unwrap();
    assert!(require_allowed_mutations(&m).is_err());
    refused(run(m, Mode::Plan, &fw));
    assert!(fw.lock().unwrap().received.is_empty());
    // A model without plugins, or whose resources need nothing missing,
    // passes.
    let all = Setup::new(OBSERVE, ADD_SERVICE);
    assert!(require_allowed_mutations(&all.model(&body).unwrap()).is_ok());
}
