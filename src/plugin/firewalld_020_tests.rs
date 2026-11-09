//! Tests of the first-party firewalld 0.2.0 catalog and plugin
//! (`plugins/first-party/`): service removal, single ports, present-only
//! port ranges and protocols, the `port_spec` operand class, the
//! `port_single` field kind and the `deny` rules. The files are loaded
//! through the release's own registry and run against the scripted firewalld
//! on a FakeTarget. The exit codes the scripted firewalld uses are the ones
//! measured on real hosts on 2026-11-09; nothing here is itself a
//! measurement.

use super::protect::sha256_hex;
use super::*;
use crate::audit::{run_audit, AuditReport, AuditResourceStatus};
use crate::engine::{AggregateStatus, Engine, Mode, RunOptions, RunReport, TargetSpec};
use crate::executor::{Completion, FakeTarget, Output};
use crate::fakesys::FakeFirewalld;
use crate::model::{load_model_with_plugins, Model};
use crate::result::{Change, Disposition, Execution, Verification};
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};

const CATALOG: &str =
    include_str!("../../plugins/first-party/catalogs/firewalld-0.2.0.catalog.toml");
const PLUGIN: &str = include_str!("../../plugins/first-party/plugins/firewalld-0.2.0.plugin.toml");
const CATALOG_010: &str =
    include_str!("../../plugins/first-party/catalogs/firewalld-0.1.0.catalog.toml");

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
    fn with(catalog: &str, plugin: &str) -> Setup {
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
            sha256_hex(catalog.as_bytes()),
            list(OBSERVE),
            list(MUTATE),
            sha256_hex(plugin.as_bytes())
        );
        write_mode(&root.join("trust.toml"), &trust, 0o600);
        Setup {
            _tmp: tmp,
            boundary,
            root,
        }
    }

    fn new() -> Setup {
        Setup::with(CATALOG, PLUGIN)
    }

    /// The plugin root with a given registry (tests of altered bytes, or of
    /// another id or version).
    fn ctx_with(&self, registry: Vec<FirstPartyCatalog>) -> PluginContext {
        PluginContext::Test {
            root: self.root.clone(),
            boundary: self.boundary.clone(),
            registry,
        }
    }

    /// The release's own registry (only the ancestor check is limited to
    /// the temporary directory).
    fn ctx(&self) -> PluginContext {
        self.ctx_with(FIRST_PARTY_CATALOGS.to_vec())
    }

    fn model(&self, body: &str) -> Result<Model> {
        let p = self.boundary.join("r.yml");
        std::fs::write(&p, body).unwrap();
        load_model_with_plugins(&p, &self.ctx())
    }
}

/// A recipe enabling firewalld 0.2.0 with the given resources (YAML list items).
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

fn firewalld() -> Arc<Mutex<FakeFirewalld>> {
    Arc::new(Mutex::new(FakeFirewalld::typical()))
}

fn opts(mode: Mode, fw: &Arc<Mutex<FakeFirewalld>>, root: bool) -> RunOptions {
    let t = FakeTarget::ubuntu2404().with_firewalld(fw.clone());
    RunOptions {
        mode,
        sudo: false,
        target: TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(if root { t.as_root() } else { t }),
    }
}

fn run(model: Model, mode: Mode, fw: &Arc<Mutex<FakeFirewalld>>) -> RunReport {
    Engine::new(model, opts(mode, fw, true))
        .unwrap()
        .run()
        .unwrap()
}

fn audit(model: Model, fw: &Arc<Mutex<FakeFirewalld>>) -> AuditReport {
    run_audit(Engine::new(model, opts(Mode::Plan, fw, true)).unwrap()).unwrap()
}

fn res<'a>(r: &'a RunReport, id: &str) -> &'a crate::result::ResourceResult {
    r.resources.iter().find(|x| x.id == id).unwrap()
}

fn changes(c: &[crate::executor::CommandRecord]) -> Vec<String> {
    c.iter()
        .filter(|r| {
            r.args
                .iter()
                .any(|a| a.starts_with("--add-") || a.starts_with("--remove-"))
        })
        .map(|r| r.args.join(" "))
        .collect()
}

fn exited(code: i32) -> Output {
    Output {
        completion: Completion::Exited(code),
        stdout: b"SECRET-LOOKING".to_vec(),
        stderr: b"SECRET-LOOKING".to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

fn pair(a: &str, b: &str) -> (String, String) {
    (a.to_string(), b.to_string())
}

// ---------------------------------------------------------------------------
// the port_spec operand class (Core)
// ---------------------------------------------------------------------------

#[test]
fn port_spec_accepts_only_canonical_ports_ranges_and_known_protocols() {
    for ok in [
        "80/tcp",
        "1/udp",
        "65535/sctp",
        "8000-8099/udp",
        "1-65535/dccp",
        "65534-65535/sctp",
    ] {
        assert!(port_spec_ok(ok, 16), "{} refused", ok);
    }
    for bad in [
        "",
        "80",
        "tcp",
        "/tcp",
        "80/",
        "0/tcp",
        "65536/tcp",
        "080/tcp",
        "80-80/tcp",
        "90-80/tcp",
        "80-/tcp",
        "-80/tcp",
        "80/TCP",
        "80/icmp",
        "80/tcp/udp",
        "80 /tcp",
        "80/tcp\n",
        "+80/tcp",
        "80,81/tcp",
        "--port=80/tcp",
        "../80/tcp",
        "100000/tcp",
        "８０/tcp",
    ] {
        assert!(!port_spec_ok(bad, 16), "{:?} accepted", bad);
    }
    assert!(!port_spec_ok("8000-8099/udp", 8), "longer than the slot");
    assert!(operand_ok_for(SlotClass::PortSpec, "80/tcp", 16));
    assert!(!operand_ok_for(SlotClass::Ident, "80/tcp", 16));
    assert!(!operand_ok_for(SlotClass::PortSpec, "http", 16));
}

// ---------------------------------------------------------------------------
// loading: the first-party files verify and the release registry admits them
// ---------------------------------------------------------------------------

#[test]
fn firewalld_0_2_0_verifies_under_the_core_rules() {
    let s = Setup::new();
    let m = s
        .model(&recipe(&r(
            "a",
            "firewalld.port",
            "zone: public, port: 8080/tcp, state: present",
        )))
        .expect("loads");
    let set = m.plugins.as_ref().unwrap();
    let names: Vec<&str> = set.plugins()[0]
        .resource_types()
        .map(|t| t.name())
        .collect();
    assert_eq!(
        names,
        [
            "firewalld.port",
            "firewalld.port_range",
            "firewalld.protocol",
            "firewalld.service"
        ]
    );
    let c = set.catalog(set.plugins()[0].catalog()).unwrap();
    assert_eq!(c.ops().count(), 21);
    let q = c.op("query_port_permanent").unwrap();
    assert_eq!(q.slot_class("port"), Some(SlotClass::PortSpec));
    assert_eq!(q.slot_class("zone"), Some(SlotClass::Ident));
    // The seven operations of 0.1.0 are carried over byte for byte.
    let old_ops = CATALOG_010.split_once("\n[[op]]\n").unwrap().1;
    assert!(
        CATALOG.contains(old_ops.trim_end()),
        "0.1.0 operations unchanged"
    );
}

#[test]
fn the_release_registry_admits_exactly_the_measured_0_2_0_bytes() {
    // The registry entry is the digest of the repository file measured on
    // real hosts, and the file loads through the release registry.
    const MEASURED_CATALOG_SHA256: &str =
        "d32ac3947279ec2581a7049f9fa931d29c904c91ea2484cafaa6759fe09c3641";
    const PLUGIN_SHA256: &str = "e5819cfe0e2c017648f628a27d0ed6e4a18ed402f3ff6de072e61a724f0aa99a";
    assert_eq!(sha256_hex(CATALOG.as_bytes()), MEASURED_CATALOG_SHA256);
    assert_eq!(sha256_hex(PLUGIN.as_bytes()), PLUGIN_SHA256);
    let entry: Vec<_> = FIRST_PARTY_CATALOGS
        .iter()
        .filter(|f| f.id == "firewalld" && f.version == "0.2.0")
        .collect();
    assert_eq!(entry.len(), 1);
    assert_eq!(entry[0].sha256, MEASURED_CATALOG_SHA256);
    let s = Setup::new();
    let m = s
        .model(&recipe(&r(
            "a",
            "firewalld.protocol",
            "zone: public, protocol: gre, state: present",
        )))
        .expect("loads through the release registry");
    let prov = m.plugins.as_ref().unwrap().provenance();
    assert_eq!(prov[0].catalog_version, "0.2.0");
    assert_eq!(prov[0].catalog_sha256, MEASURED_CATALOG_SHA256);
    assert_eq!(prov[0].plugin_sha256, PLUGIN_SHA256);
    assert_eq!(prov[0].catalog_registry, "first-party");

    // One added byte, pinned by the Owner: refused at the release registry.
    let edited = format!("{}# edited\n", CATALOG);
    let s = Setup::with(&edited, PLUGIN);
    let p = s.boundary.join("r.yml");
    std::fs::write(
        &p,
        recipe(&r(
            "a",
            "firewalld.protocol",
            "zone: public, protocol: gre, state: present",
        )),
    )
    .unwrap();
    let e = load_model_with_plugins(&p, &s.ctx()).expect_err("refused by the release registry");
    assert!(
        e.message.contains("not a reviewed first-party catalog"),
        "{}",
        e.message
    );
    // The measured bytes under another id or version are refused too.
    for (id, version) in [("firewalld", "0.2.1"), ("firewalld2", "0.2.0")] {
        let s = Setup::new();
        let reg = vec![FirstPartyCatalog {
            id,
            version,
            sha256: MEASURED_CATALOG_SHA256,
        }];
        let p = s.boundary.join("r.yml");
        std::fs::write(
            &p,
            recipe(&r(
                "a",
                "firewalld.protocol",
                "zone: public, protocol: gre, state: present",
            )),
        )
        .unwrap();
        assert!(load_model_with_plugins(&p, &s.ctx_with(reg)).is_err());
    }
}

#[test]
fn verification_refuses_misused_classes_kinds_and_deny_rules() {
    let edit = |base: &str, from: &str, to: &str| {
        assert!(base.contains(from), "fixture lacks {:?}", from);
        base.replacen(from, to, 1)
    };
    let load = |catalog: &str, plugin: &str| -> String {
        let s = Setup::with(catalog, plugin);
        let reg = vec![FirstPartyCatalog {
            id: "firewalld",
            version: "0.2.0",
            sha256: Box::leak(sha256_hex(catalog.as_bytes()).into_boxed_str()),
        }];
        let p = s.boundary.join("r.yml");
        std::fs::write(
            &p,
            recipe(&r(
                "a",
                "firewalld.protocol",
                "zone: public, protocol: gre, state: present",
            )),
        )
        .unwrap();
        match load_model_with_plugins(&p, &s.ctx_with(reg)) {
            Ok(_) => String::from("LOADED"),
            Err(e) => e.message,
        }
    };
    let port_slot = "port = { class = \"port_spec\", max_len = 16 }";
    let cases: Vec<(&str, String, String, &str)> = vec![
        (
            "port_spec slot too long",
            edit(
                CATALOG,
                port_slot,
                "port = { class = \"port_spec\", max_len = 17 }",
            ),
            PLUGIN.to_string(),
            "class port_spec with max_len 1..=16",
        ),
        (
            "unknown slot class",
            edit(
                CATALOG,
                port_slot,
                "port = { class = \"cidr\", max_len = 16 }",
            ),
            PLUGIN.to_string(),
            "must be class ident",
        ),
        (
            "ident field into a port_spec slot",
            CATALOG.to_string(),
            edit(
                PLUGIN,
                "port = { kind = \"port_spec\" }",
                "port = { kind = \"ident\" }",
            ),
            "its kind does not match the class of slot port",
        ),
        (
            "port_spec field into an ident slot",
            CATALOG.to_string(),
            edit(
                PLUGIN,
                "protocol = { kind = \"ident\" }",
                "protocol = { kind = \"port_spec\" }",
            ),
            "its kind does not match the class of slot protocol",
        ),
        (
            "deny names an unknown field",
            CATALOG.to_string(),
            edit(
                PLUGIN,
                "deny = [{ port = \"22/tcp\", state = \"absent\" }]",
                "deny = [{ number = \"22\" }]",
            ),
            "unknown field number",
        ),
        (
            "deny value invalid for the field",
            CATALOG.to_string(),
            edit(
                PLUGIN,
                "deny = [{ port = \"22/tcp\", state = \"absent\" }]",
                "deny = [{ port = \"ssh\" }]",
            ),
            "field port is not a valid value",
        ),
        (
            "empty deny entry",
            CATALOG.to_string(),
            edit(
                PLUGIN,
                "deny = [{ port = \"22/tcp\", state = \"absent\" }]",
                "deny = [{}]",
            ),
            "names no field",
        ),
        (
            "too many deny entries",
            CATALOG.to_string(),
            edit(
                PLUGIN,
                "deny = [{ port = \"22/tcp\", state = \"absent\" }]",
                &format!("deny = [{}]", ["{ state = \"absent\" }"; 9].join(", ")),
            ),
            "more than 8 deny entries",
        ),
    ];
    for (label, c, p, want) in cases {
        let m = load(&c, &p);
        assert!(m.contains(want), "{}: {}", label, m);
    }
}

// ---------------------------------------------------------------------------
// validate: values and deny rules, nothing runs
// ---------------------------------------------------------------------------

#[test]
fn invalid_zone_service_port_and_protocol_values_are_refused_at_load() {
    let s = Setup::new();
    let cases = [
        (
            "firewalld.port",
            "zone: public, port: \"80\", state: present",
            "field port",
        ),
        (
            "firewalld.port",
            "zone: public, port: 80, state: present",
            "with.port must be a string",
        ),
        (
            "firewalld.port",
            "zone: public, port: 0/tcp, state: present",
            "field port",
        ),
        (
            "firewalld.port",
            "zone: public, port: 90-80/tcp, state: present",
            "field port",
        ),
        (
            "firewalld.port",
            "zone: public, port: 80/icmp, state: present",
            "field port",
        ),
        (
            "firewalld.port",
            "zone: \"-trusted\", port: 80/tcp, state: present",
            "field zone",
        ),
        (
            "firewalld.port",
            "zone: public, port: 80/tcp, state: enabled",
            "field state",
        ),
        (
            "firewalld.protocol",
            "zone: public, protocol: \"g re\", state: present",
            "field protocol",
        ),
        (
            "firewalld.protocol",
            "zone: public, protocol: \"--all\", state: present",
            "field protocol",
        ),
        (
            "firewalld.service",
            "zone: public, service: \"x$(id)\", state: absent",
            "field service",
        ),
        (
            "firewalld.service",
            "zone: public, service: http, state: gone",
            "field state",
        ),
    ];
    for (t, with, want) in cases {
        let e = s.model(&recipe(&r("a", t, with))).expect_err(with);
        assert!(e.message.contains(want), "{}: {}", with, e.message);
        assert!(
            !e.message.contains("80/icmp") && !e.message.contains("g re"),
            "{}",
            e.message
        );
    }
}

#[test]
fn removing_the_ssh_service_or_port_22_is_refused_before_anything_runs() {
    let s = Setup::new();
    for (t, with) in [
        (
            "firewalld.service",
            "zone: public, service: ssh, state: absent",
        ),
        (
            "firewalld.port",
            "zone: public, port: 22/tcp, state: absent",
        ),
    ] {
        let e = s.model(&recipe(&r("a", t, with))).expect_err(with);
        assert!(e.message.contains("could cut access"), "{}", e.message);
        assert!(
            !e.message.contains("ssh,") && !e.message.contains("22/tcp"),
            "{}",
            e.message
        );
    }
    // Adding them stays allowed, and so does removing another port.
    s.model(&recipe(&r(
        "a",
        "firewalld.service",
        "zone: public, service: ssh, state: present",
    )))
    .unwrap();
    s.model(&recipe(&r(
        "a",
        "firewalld.port",
        "zone: public, port: 2222/tcp, state: absent",
    )))
    .unwrap();

    // A value from a variable is checked when evaluated, before any command.
    let fw = firewalld();
    let body = format!(
        "version: 1\nvars:\n  s: {{ value: ssh }}\nplugins:\n  - id: firewalld\n    version: 0.2.0\nresources:\n{}",
        r("a", "firewalld.service", "zone: public, service: \"{{ vars.s }}\", state: absent")
    );
    let rep = run(s.model(&body).unwrap(), Mode::Apply, &fw);
    let x = res(&rep, "a");
    assert_eq!(x.execution, Execution::Failed);
    assert!(x.reason.as_deref().unwrap().contains("could cut access"));
    assert!(fw.lock().unwrap().received.is_empty(), "no command ran");
    assert!(fw.lock().unwrap().runtime.contains(&pair("public", "ssh")));
}

// ---------------------------------------------------------------------------
// plan / apply / audit through the engine
// ---------------------------------------------------------------------------

#[test]
fn ports_are_added_removed_and_left_alone_when_already_right() {
    let s = Setup::new();
    let fw = firewalld();
    let add = recipe(&r(
        "p",
        "firewalld.port",
        "zone: public, port: 8080/tcp, state: present",
    ));

    // plan: would change, nothing mutated
    let p = run(s.model(&add).unwrap(), Mode::Plan, &fw);
    let x = res(&p, "p");
    assert_eq!(x.change, Change::Changed);
    assert!(x
        .notes
        .join(" ")
        .contains("would_run=add_port_runtime,add_port_permanent"));
    assert!(changes(&p.commands).is_empty());

    // apply: both facets, observed again
    let a = run(s.model(&add).unwrap(), Mode::Apply, &fw);
    let x = res(&a, "p");
    assert_eq!(
        (x.change, x.verification),
        (Change::Changed, Verification::Verified)
    );
    assert_eq!(
        changes(&a.commands),
        [
            "--zone=public --add-port=8080/tcp",
            "--permanent --zone=public --add-port=8080/tcp"
        ]
    );
    {
        let f = fw.lock().unwrap();
        assert!(f.ports_runtime.contains(&pair("public", "8080/tcp")));
        assert!(f.ports_permanent.contains(&pair("public", "8080/tcp")));
    }

    // again: nothing to do (idempotent), audit compliant
    let a2 = run(s.model(&add).unwrap(), Mode::Apply, &fw);
    assert_eq!(res(&a2, "p").change, Change::None);
    assert!(changes(&a2.commands).is_empty());
    let au = audit(s.model(&add).unwrap(), &fw);
    assert_eq!(au.resources[0].status, AuditResourceStatus::Compliant);
    assert_eq!(au.exit_code(), 0);

    // absent: removes exactly that entry, then nothing more
    fw.lock()
        .unwrap()
        .ports_runtime
        .insert(pair("public", "9090/udp"));
    let rm = recipe(&r(
        "p",
        "firewalld.port",
        "zone: public, port: 8080/tcp, state: absent",
    ));
    let a3 = run(s.model(&rm).unwrap(), Mode::Apply, &fw);
    assert_eq!(res(&a3, "p").change, Change::Changed);
    assert_eq!(
        changes(&a3.commands),
        [
            "--zone=public --remove-port=8080/tcp",
            "--permanent --zone=public --remove-port=8080/tcp"
        ]
    );
    {
        let f = fw.lock().unwrap();
        assert!(!f.ports_runtime.contains(&pair("public", "8080/tcp")));
        assert!(
            f.ports_runtime.contains(&pair("public", "9090/udp")),
            "an entry Sinter does not manage is untouched"
        );
        assert!(f.runtime.contains(&pair("public", "ssh")));
    }
    let a4 = run(s.model(&rm).unwrap(), Mode::Apply, &fw);
    assert_eq!(res(&a4, "p").change, Change::None, "already absent");
    assert!(changes(&a4.commands).is_empty());
}

#[test]
fn port_ranges_and_other_protocols_are_passed_as_one_checked_operand() {
    let s = Setup::new();
    let fw = firewalld();
    let body = recipe(&r(
        "p",
        "firewalld.port_range",
        "zone: public, port: 60000-61000/udp, state: present",
    ));
    let a = run(s.model(&body).unwrap(), Mode::Apply, &fw);
    assert_eq!(res(&a, "p").execution, Execution::Succeeded);
    assert!(fw
        .lock()
        .unwrap()
        .ports_permanent
        .contains(&pair("public", "60000-61000/udp")));
}

#[test]
fn protocols_and_service_removal_follow_the_same_contract() {
    let s = Setup::new();
    let fw = firewalld();
    {
        let mut f = fw.lock().unwrap();
        f.runtime.insert(pair("public", "http"));
        f.permanent.insert(pair("public", "http"));
    }
    let body = recipe(&format!(
        "{}{}",
        r(
            "gre",
            "firewalld.protocol",
            "zone: public, protocol: gre, state: present"
        ),
        r(
            "nohttp",
            "firewalld.service",
            "zone: public, service: http, state: absent"
        )
    ));
    let a = run(s.model(&body).unwrap(), Mode::Apply, &fw);
    assert_eq!(a.status, AggregateStatus::Success);
    assert_eq!(
        changes(&a.commands),
        [
            "--zone=public --add-protocol=gre",
            "--permanent --zone=public --add-protocol=gre",
            "--zone=public --remove-service=http",
            "--permanent --zone=public --remove-service=http"
        ]
    );
    {
        let f = fw.lock().unwrap();
        assert!(f.protocols_permanent.contains(&pair("public", "gre")));
        assert!(!f.runtime.contains(&pair("public", "http")));
        assert!(f.runtime.contains(&pair("public", "ssh")), "ssh untouched");
    }
    let a2 = run(s.model(&body).unwrap(), Mode::Apply, &fw);
    assert!(changes(&a2.commands).is_empty(), "idempotent");
    let au = audit(s.model(&body).unwrap(), &fw);
    assert!(au
        .resources
        .iter()
        .all(|r| r.status == AuditResourceStatus::Compliant));
}

#[test]
fn a_runtime_permanent_difference_is_drift_and_apply_fixes_only_that_facet() {
    let s = Setup::new();
    let fw = firewalld();
    fw.lock()
        .unwrap()
        .ports_permanent
        .insert(pair("public", "443/tcp"));
    let body = recipe(&r(
        "p",
        "firewalld.port",
        "zone: public, port: 443/tcp, state: present",
    ));
    let au = audit(s.model(&body).unwrap(), &fw);
    let dims: Vec<&str> = au.resources[0]
        .details
        .iter()
        .map(|d| d.dimension.as_str())
        .collect();
    assert_eq!(dims, ["runtime"]);
    assert_eq!(au.exit_code(), 7);
    assert!(changes(&au.commands).is_empty(), "audit never changes");
    let a = run(s.model(&body).unwrap(), Mode::Apply, &fw);
    assert_eq!(changes(&a.commands), ["--zone=public --add-port=443/tcp"]);

    // the other way round for absent: only the permanent entry is left
    fw.lock()
        .unwrap()
        .ports_runtime
        .remove(&pair("public", "443/tcp"));
    let rm = recipe(&r(
        "p",
        "firewalld.port",
        "zone: public, port: 443/tcp, state: absent",
    ));
    let au = audit(s.model(&rm).unwrap(), &fw);
    let dims: Vec<&str> = au.resources[0]
        .details
        .iter()
        .map(|d| d.dimension.as_str())
        .collect();
    assert_eq!(dims, ["permanent"]);
}

#[test]
fn failures_are_never_reported_as_success() {
    let s = Setup::new();
    let body = recipe(&format!(
        "{}{}",
        r(
            "p",
            "firewalld.port",
            "zone: public, port: 8080/tcp, state: present"
        ),
        r(
            "after",
            "firewalld.protocol",
            "zone: public, protocol: gre, state: present"
        )
    ));

    // firewalld stopped: a failed precondition, nothing changed
    let fw = firewalld();
    fw.lock().unwrap().running = false;
    let a = run(s.model(&body).unwrap(), Mode::Apply, &fw);
    let x = res(&a, "p");
    assert_eq!((x.execution, x.change), (Execution::Failed, Change::None));
    assert!(changes(&a.commands).is_empty());

    // an unknown zone: a failed precondition
    let fw = firewalld();
    let bad_zone = recipe(&r(
        "p",
        "firewalld.port",
        "zone: internal, port: 8080/tcp, state: present",
    ));
    let a = run(s.model(&bad_zone).unwrap(), Mode::Apply, &fw);
    assert_eq!(res(&a, "p").execution, Execution::Failed);
    assert!(changes(&a.commands).is_empty());

    // not root: firewall-cmd answers 253 (authorization failed), an error
    let fw = firewalld();
    fw.lock()
        .unwrap()
        .forced
        .push(("--state".into(), exited(253)));
    let a = run(s.model(&body).unwrap(), Mode::Apply, &fw);
    let x = res(&a, "p");
    assert_eq!((x.execution, x.change), (Execution::Failed, Change::None));
    assert!(x.reason.as_deref().unwrap().contains("exit code 253"));

    // a protocol firewalld does not know: its query answers 103
    // (INVALID_PROTOCOL), an unlisted code, so the observation fails before
    // any change; fail-fast, never success
    let fw = firewalld();
    let bogus = recipe(&format!(
        "{}{}",
        r(
            "x",
            "firewalld.protocol",
            "zone: public, protocol: nosuchproto, state: present"
        ),
        r(
            "after",
            "firewalld.protocol",
            "zone: public, protocol: gre, state: present"
        )
    ));
    let a = run(s.model(&bogus).unwrap(), Mode::Apply, &fw);
    assert_eq!(a.status, AggregateStatus::ApplyFailed);
    let x = res(&a, "x");
    assert_eq!((x.execution, x.change), (Execution::Failed, Change::None));
    assert!(
        x.reason.as_deref().unwrap().contains("exit code 103"),
        "{:?}",
        x.reason
    );
    assert_eq!(res(&a, "after").disposition, Disposition::BlockedByFailFast);
    assert!(changes(&a.commands).is_empty());

    // a change that fails with an unlisted code: may have changed something
    let fw = firewalld();
    fw.lock()
        .unwrap()
        .forced
        .push(("--zone=public --add-protocol=gre".into(), exited(103)));
    let only_gre = recipe(&r(
        "g",
        "firewalld.protocol",
        "zone: public, protocol: gre, state: present",
    ));
    let a = run(s.model(&only_gre).unwrap(), Mode::Apply, &fw);
    let x = res(&a, "g");
    assert_eq!(
        (x.execution, x.change),
        (Execution::Failed, Change::Possible)
    );
    assert_eq!(
        changes(&a.commands).len(),
        1,
        "not retried, permanent not attempted"
    );
    let json = crate::output::run_report_json(&a, "apply").to_string();
    assert!(!json.contains("SECRET-LOOKING"));

    // partial: runtime added, the permanent change fails
    let fw = firewalld();
    fw.lock().unwrap().forced.push((
        "--permanent --zone=public --add-port=8080/tcp".into(),
        exited(13),
    ));
    let a = run(s.model(&body).unwrap(), Mode::Apply, &fw);
    let x = res(&a, "p");
    assert_eq!(x.execution, Execution::Failed);
    assert_eq!(x.change, Change::Changed, "the runtime facet did change");
    assert!(fw
        .lock()
        .unwrap()
        .ports_runtime
        .contains(&pair("public", "8080/tcp")));
    assert_eq!(res(&a, "after").disposition, Disposition::BlockedByFailFast);
    // audit after the partial change shows the remaining drift
    let au = audit(s.model(&body).unwrap(), &fw);
    let p = au.resources.iter().find(|r| r.id == "p").unwrap();
    assert_eq!(p.status, AuditResourceStatus::Drift);

    // a removal that reports success but leaves the entry: verification fails
    let fw = firewalld();
    {
        let mut f = fw.lock().unwrap();
        f.ports_runtime.insert(pair("public", "8080/tcp"));
        f.ports_permanent.insert(pair("public", "8080/tcp"));
        f.add_is_noop = true;
    }
    let rm = recipe(&r(
        "p",
        "firewalld.port",
        "zone: public, port: 8080/tcp, state: absent",
    ));
    let a = run(s.model(&rm).unwrap(), Mode::Apply, &fw);
    let x = res(&a, "p");
    assert_eq!(x.execution, Execution::Failed);
    assert!(
        x.reason.as_deref().unwrap().contains("not absent"),
        "{:?}",
        x.reason
    );
}

#[test]
fn audit_and_plan_run_only_attested_observations() {
    let s = Setup::new();
    let fw = firewalld();
    let body = recipe(&format!(
        "{}{}{}",
        r(
            "p",
            "firewalld.port",
            "zone: public, port: 8080/tcp, state: absent"
        ),
        r(
            "q",
            "firewalld.protocol",
            "zone: public, protocol: icmp, state: present"
        ),
        r(
            "s",
            "firewalld.service",
            "zone: public, service: https, state: absent"
        )
    ));
    let au = audit(s.model(&body).unwrap(), &fw);
    let p = run(s.model(&body).unwrap(), Mode::Plan, &fw);
    for c in au.commands.iter().chain(p.commands.iter()) {
        assert!(
            c.args
                .iter()
                .all(|a| !a.starts_with("--add-") && !a.starts_with("--remove-")),
            "{:?}",
            c.args
        );
    }
    assert!(fw.lock().unwrap().mutations.is_empty());
}

#[test]
fn the_first_party_0_1_0_recipes_are_unchanged_by_the_core_extension() {
    // The released catalog and plugin still load through the release's
    // registry, and `state: absent` is still not a value of their type.
    let tmp = tempfile::tempdir().unwrap();
    let boundary = tmp.path().to_path_buf();
    let root = boundary.join("plugins-root");
    for d in [&root, &root.join("catalogs"), &root.join("plugins")] {
        std::fs::create_dir(d).unwrap();
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let plugin = include_str!("../../plugins/first-party/plugins/firewalld-0.1.0.plugin.toml");
    write_mode(
        &root.join("catalogs/firewalld-0.1.0.catalog.toml"),
        CATALOG_010,
        0o644,
    );
    write_mode(
        &root.join("plugins/firewalld-0.1.0.plugin.toml"),
        plugin,
        0o644,
    );
    write_mode(
        &root.join("trust.toml"),
        &format!(
            "format = 1\n\n[[catalog]]\nid = \"firewalld\"\nversion = \"0.1.0\"\nsha256 = \"{}\"\nattested_observe = [\"state\", \"zone_defined\", \"service_defined\", \"query_service_runtime\", \"query_service_permanent\"]\nallowed_mutate = [\"add_service_runtime\", \"add_service_permanent\"]\n\n[[plugin]]\nid = \"firewalld\"\nversion = \"0.1.0\"\nsha256 = \"{}\"\n",
            sha256_hex(CATALOG_010.as_bytes()),
            sha256_hex(plugin.as_bytes())
        ),
        0o600,
    );
    let ctx = PluginContext::Test {
        root,
        boundary: boundary.clone(),
        registry: FIRST_PARTY_CATALOGS.to_vec(),
    };
    let p = boundary.join("r.yml");
    std::fs::write(&p, "version: 1\nplugins:\n  - { id: firewalld, version: 0.1.0 }\nresources:\n  - id: a\n    type: firewalld.service\n    with: { zone: public, service: http, state: present }\n").unwrap();
    let m = load_model_with_plugins(&p, &ctx).expect("0.1.0 loads");
    let fw = firewalld();
    let a = run(m, Mode::Apply, &fw);
    assert_eq!(res(&a, "a").execution, Execution::Succeeded);
    std::fs::write(&p, "version: 1\nplugins:\n  - { id: firewalld, version: 0.1.0 }\nresources:\n  - id: a\n    type: firewalld.service\n    with: { zone: public, service: http, state: absent }\n").unwrap();
    let e = load_model_with_plugins(&p, &ctx).expect_err("absent is not a 0.1.0 value");
    assert!(e.message.contains("field state"), "{}", e.message);
}

#[test]
fn the_first_party_readme_lists_the_exact_0_2_0_digests() {
    let readme = include_str!("../../plugins/first-party/README.md");
    for body in [CATALOG, PLUGIN] {
        let h = sha256_hex(body.as_bytes());
        assert!(readme.contains(&h), "README lacks {}", h);
    }
}

#[test]
fn the_deny_rules_are_exact_matches_and_do_not_cover_ranges_or_other_ports() {
    // Documented limit (README, DESIGN §38.6): the deny rules refuse only
    // the exact combinations. An SSH server on another port, or the ssh
    // service in another zone are not refused, so the deny rules are not a
    // guarantee against lockout. (A range cannot be removed at all: see
    // a_range_can_be_made_present_but_never_absent.)
    let s = Setup::new();
    for with in [
        "zone: public, port: 2222/tcp, state: absent",
        "zone: public, port: 22/udp, state: absent",
    ] {
        s.model(&recipe(&r("a", "firewalld.port", with)))
            .unwrap_or_else(|e| panic!("{}: {}", with, e.message));
    }
    s.model(&recipe(&r(
        "a",
        "firewalld.service",
        "zone: internal, service: ssh-custom, state: absent",
    )))
    .unwrap();
    let set = s
        .model(&recipe(&r(
            "a",
            "firewalld.port",
            "zone: public, port: 8080/tcp, state: present",
        )))
        .unwrap()
        .plugins
        .unwrap();
    let (_, t) = set.resource_type("firewalld.port").unwrap();
    assert_eq!(t.deny_rules().len(), 1);
}

#[test]
fn port_single_accepts_one_port_and_refuses_ranges() {
    for ok in ["80/tcp", "1/udp", "65535/sctp", "22/dccp"] {
        assert!(port_single_ok(ok, 16), "{} refused", ok);
    }
    for bad in [
        "8000-8099/tcp",
        "1-2/udp",
        "80",
        "0/tcp",
        "080/tcp",
        "80/icmp",
        "",
    ] {
        assert!(!port_single_ok(bad, 16), "{:?} accepted", bad);
    }
}

#[test]
fn a_range_can_be_made_present_but_never_absent() {
    // Measured on Rocky 9.8 / 10.2 and Ubuntu 24.04 (2026-11-09): firewalld
    // answers a query for a range that is only partly allowed with "no", so
    // `absent` for a range could report compliance while ports of the range
    // stay open. firewalld.port takes one port only; firewalld.port_range is
    // present only.
    let s = Setup::new();
    let e = s
        .model(&recipe(&r(
            "a",
            "firewalld.port",
            "zone: public, port: 8000-8099/tcp, state: absent",
        )))
        .expect_err("a range is not a single port");
    assert!(e.message.contains("field port"), "{}", e.message);
    let e = s
        .model(&recipe(&r(
            "a",
            "firewalld.port",
            "zone: public, port: 8000-8099/tcp, state: present",
        )))
        .expect_err("ranges belong to firewalld.port_range");
    assert!(e.message.contains("field port"), "{}", e.message);
    let e = s
        .model(&recipe(&r(
            "a",
            "firewalld.port_range",
            "zone: public, port: 8000-8099/tcp, state: absent",
        )))
        .expect_err("port_range has no absent");
    assert!(e.message.contains("field state"), "{}", e.message);

    // present works, idempotently, and audit sees drift for it
    let fw = firewalld();
    let body = recipe(&r(
        "a",
        "firewalld.port_range",
        "zone: public, port: 8000-8099/tcp, state: present",
    ));
    let au = audit(s.model(&body).unwrap(), &fw);
    assert_eq!(au.resources[0].status, AuditResourceStatus::Drift);
    let a = run(s.model(&body).unwrap(), Mode::Apply, &fw);
    assert_eq!(
        changes(&a.commands),
        [
            "--zone=public --add-port=8000-8099/tcp",
            "--permanent --zone=public --add-port=8000-8099/tcp"
        ]
    );
    let a2 = run(s.model(&body).unwrap(), Mode::Apply, &fw);
    assert!(changes(&a2.commands).is_empty());
    let au = audit(s.model(&body).unwrap(), &fw);
    assert_eq!(au.resources[0].status, AuditResourceStatus::Compliant);
    // the type offers no remove operation at all
    let set = s.model(&body).unwrap().plugins.unwrap();
    let (_, t) = set.resource_type("firewalld.port_range").unwrap();
    for f in t.facets() {
        assert!(f.ensure_op("absent").is_none());
    }
}
