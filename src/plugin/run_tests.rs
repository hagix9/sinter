//! Step 2 tests: plugin resource types through the real model, engine, audit
//! and output paths, against a scripted firewalld on a FakeTarget. The
//! catalog and the plugin definition are the first-party files of the
//! repository (`plugins/first-party/`), loaded through the release's own
//! registry (step 5).

use super::protect::sha256_hex;
use super::*;
use crate::audit::{run_audit, AuditReport, AuditResourceStatus};
use crate::engine::{AggregateStatus, Engine, Mode, RunOptions, RunReport, TargetSpec};
use crate::executor::FakeTarget;
use crate::fakesys::FakeFirewalld;
use crate::model::{load_model, load_model_with_plugins, Model};
use crate::result::{Change, Disposition, Execution, Verification};
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};

/// The attested first-party catalog, byte for byte (its SHA-256 is the
/// registry entry).
const CATALOG: &str =
    include_str!("../../plugins/first-party/catalogs/firewalld-0.1.0.catalog.toml");

/// The first-party plugin definition that was accepted on real hosts.
const PLUGIN_FW: &str =
    include_str!("../../plugins/first-party/plugins/firewalld-0.1.0.plugin.toml");

/// A second, different resource type from a different plugin, reusing the
/// same verified catalog (no new capability, so no Core change).
const PLUGIN_RT: &str = r#"format = 1
id = "fwruntime"
version = "0.1.0"
catalog = { id = "firewalld", version = "0.1.0" }

[[type]]
name = "fwruntime.service"
fields = { zone = { kind = "ident" }, service = { kind = "ident" } }
precheck = [{ op = "state", expect = "running" }]

[[type.facet]]
name = "runtime"
observe = "query_service_runtime"
want = "present"
ensure = { present = "add_service_runtime" }
"#;

const OBSERVE: &str = r#"["state", "zone_defined", "service_defined", "query_service_runtime", "query_service_permanent"]"#;
const MUTATE: &str = r#"["add_service_runtime", "add_service_permanent"]"#;

/// A plugin root and recipe directory under one temporary directory.
struct Setup {
    _tmp: tempfile::TempDir,
    boundary: PathBuf,
    root: PathBuf,
    plugins: Vec<(&'static str, &'static str)>,
}

fn write_mode(p: &Path, body: &str, mode: u32) {
    std::fs::write(p, body).unwrap();
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

impl Setup {
    fn new() -> Setup {
        let tmp = tempfile::tempdir().unwrap();
        let boundary = tmp.path().to_path_buf();
        let root = boundary.join("plugins-root");
        for d in [&root, &root.join("catalogs"), &root.join("plugins")] {
            std::fs::create_dir(d).unwrap();
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        write_mode(
            &root.join("catalogs/firewalld-0.1.0.catalog.toml"),
            CATALOG,
            0o644,
        );
        let mut s = Setup {
            _tmp: tmp,
            boundary,
            root,
            plugins: Vec::new(),
        };
        s.add_plugin("firewalld", PLUGIN_FW);
        s
    }

    /// Install a plugin and pin it (Owner action, data only).
    fn add_plugin(&mut self, id: &'static str, body: &'static str) {
        write_mode(
            &self.root.join(format!("plugins/{}-0.1.0.plugin.toml", id)),
            body,
            0o644,
        );
        self.plugins.push((id, body));
        self.write_trust();
    }

    fn write_trust(&self) {
        let mut t = format!(
            "format = 1\n\n[[catalog]]\nid = \"firewalld\"\nversion = \"0.1.0\"\nsha256 = \"{}\"\nattested_observe = {}\nallowed_mutate = {}\n",
            sha256_hex(CATALOG.as_bytes()),
            OBSERVE,
            MUTATE
        );
        for (id, body) in &self.plugins {
            t.push_str(&format!(
                "\n[[plugin]]\nid = \"{}\"\nversion = \"0.1.0\"\nsha256 = \"{}\"\n",
                id,
                sha256_hex(body.as_bytes())
            ));
        }
        write_mode(&self.root.join("trust.toml"), &t, 0o600);
    }

    /// The release's own registry; only the ancestor check is limited to
    /// the temporary directory.
    fn ctx(&self) -> PluginContext {
        PluginContext::Test {
            root: self.root.clone(),
            boundary: self.boundary.clone(),
            registry: FIRST_PARTY_CATALOGS.to_vec(),
        }
    }

    fn recipe(&self, name: &str, body: &str) -> PathBuf {
        let p = self.boundary.join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    fn model(&self, body: &str) -> Result<Model> {
        load_model_with_plugins(&self.recipe("r.yml", body), &self.ctx())
    }
}

const ALLOW_HTTP: &str = "version: 1\nplugins:\n  - id: firewalld\n    version: 0.1.0\nresources:\n  - id: allow_http\n    type: firewalld.service\n    with:\n      zone: public\n      service: http\n      state: present\n";

fn with_after(body: &str) -> String {
    format!(
        "{}  - id: after\n    type: firewalld.service\n    with: {{ zone: public, service: https, state: present }}\n",
        body
    )
}

fn firewalld() -> Arc<Mutex<FakeFirewalld>> {
    Arc::new(Mutex::new(FakeFirewalld::typical()))
}

fn fake(fw: &Arc<Mutex<FakeFirewalld>>) -> FakeTarget {
    FakeTarget::ubuntu2404()
        .as_root()
        .with_firewalld(fw.clone())
}

fn opts(mode: Mode, fw: &Arc<Mutex<FakeFirewalld>>) -> RunOptions {
    RunOptions {
        mode,
        sudo: false,
        target: TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(fake(fw)),
    }
}

fn run(model: Model, mode: Mode, fw: &Arc<Mutex<FakeFirewalld>>) -> Result<RunReport> {
    Engine::new(model, opts(mode, fw))?.run()
}

fn audit(model: Model, fw: &Arc<Mutex<FakeFirewalld>>) -> AuditReport {
    run_audit(Engine::new(model, opts(Mode::Plan, fw)).unwrap()).unwrap()
}

fn fw_commands(c: &[crate::executor::CommandRecord]) -> Vec<String> {
    c.iter()
        .filter(|r| r.program == "/usr/bin/firewall-cmd" || r.program == "[redacted]")
        .map(|r| format!("{} {}", r.program, r.args.join(" ")))
        .collect()
}

fn mutations(c: &[crate::executor::CommandRecord]) -> usize {
    c.iter()
        .filter(|r| r.args.iter().any(|a| a.starts_with("--add-")))
        .count()
}

fn res<'a>(r: &'a RunReport, id: &str) -> &'a crate::result::ResourceResult {
    r.resources.iter().find(|x| x.id == id).unwrap()
}

// ---------------------------------------------------------------------------
// compatibility: without `plugins:` nothing changes
// ---------------------------------------------------------------------------

#[test]
fn a_recipe_without_plugins_never_opens_the_plugin_root() {
    // The context names a root that does not exist: it is never opened.
    let s = Setup::new();
    let ctx = PluginContext::Test {
        root: s.boundary.join("does-not-exist"),
        boundary: s.boundary.clone(),
        registry: Vec::new(),
    };
    let p = s.recipe(
        "plain.yml",
        "version: 1\nresources:\n  - id: svc\n    type: service\n    with: { name: cron.service, state: running }\n",
    );
    let m = load_model_with_plugins(&p, &ctx).expect("loads without touching plugins");
    assert!(m.plugins.is_none());
}

#[test]
fn plugin_types_are_unknown_without_plugins_and_without_a_context() {
    let s = Setup::new();
    let e = s
        .model("version: 1\nresources:\n  - id: a\n    type: firewalld.service\n    with: { zone: public, service: http, state: present }\n")
        .expect_err("not enabled");
    assert!(
        e.message
            .contains("unknown resource type firewalld.service"),
        "{}",
        e.message
    );
    // The default (non-CLI) loader refuses a recipe that enables plugins.
    let e = load_model(&s.recipe("r2.yml", ALLOW_HTTP)).expect_err("disabled context");
    assert!(e.message.contains("not available"), "{}", e.message);
}

#[test]
fn plugins_belong_to_the_top_level_recipe_only() {
    let s = Setup::new();
    s.recipe(
        "frag.yml",
        "version: 1\nplugins:\n  - { id: firewalld, version: 0.1.0 }\nresources: []\n",
    );
    let e = s
        .model("version: 1\ninclude:\n  - frag.yml\nresources: []\n")
        .expect_err("refused");
    assert!(
        e.message
            .contains("only be declared in the top-level recipe"),
        "{}",
        e.message
    );
}

// ---------------------------------------------------------------------------
// validate (load): checks, and nothing runs
// ---------------------------------------------------------------------------

#[test]
fn validate_accepts_a_valid_plugin_resource_and_runs_nothing() {
    let s = Setup::new();
    let fw = firewalld();
    let m = s.model(ALLOW_HTTP).expect("valid");
    assert_eq!(m.resources[0].type_, "firewalld.service");
    assert!(m
        .plugins
        .as_ref()
        .unwrap()
        .resource_type("firewalld.service")
        .is_some());
    assert!(
        fw.lock().unwrap().received.is_empty(),
        "loading runs no command"
    );
}

#[test]
fn validate_refuses_bad_plugin_resources() {
    let s = Setup::new();
    let cases: &[(&str, &str, &str, &str)] = &[
        (
            "bad operand",
            "service: http",
            "service: \"-x\"",
            "not a valid value",
        ),
        (
            "list operand",
            "service: http",
            "service: \"http,https\"",
            "not a valid value",
        ),
        (
            "enum",
            "state: present",
            "state: absent",
            "not a valid value",
        ),
        (
            "unknown field",
            "state: present",
            "state: present\n      program: /bin/sh",
            "unknown field program",
        ),
        (
            "missing field",
            "      state: present\n",
            "",
            "missing field state",
        ),
        (
            "not a string",
            "service: http",
            "service: 8080",
            "must be a string",
        ),
        (
            "other type",
            "type: firewalld.service",
            "type: firewalld.port",
            "no enabled plugin provides it",
        ),
        ("version", "version: 0.1.0", "version: 0.2.0", "not trusted"),
        (
            "bad version",
            "version: 0.1.0",
            "version: \"1.0\"",
            "MAJOR.MINOR.PATCH",
        ),
    ];
    for (label, from, to, expect) in cases {
        let body = ALLOW_HTTP.replacen(from, to, 1);
        let e = s.model(&body).expect_err(label);
        assert!(e.message.contains(expect), "{}: {}", label, e.message);
        assert_eq!(e.kind, crate::error::ErrorKind::Schema, "{}", label);
        assert!(
            !e.message.contains("-x") && !e.message.contains("http,https"),
            "{}: value leaked",
            label
        );
    }
    let dup = "version: 1\nplugins:\n  - { id: firewalld, version: 0.1.0 }\n  - { id: firewalld, version: 0.1.0 }\nresources: []\n";
    let e = s.model(dup).expect_err("duplicate");
    assert!(e.message.contains("listed more than once"), "{}", e.message);
}

#[test]
fn a_tampered_plugin_or_catalog_is_refused_at_load() {
    let s = Setup::new();
    write_mode(
        &s.root.join("catalogs/firewalld-0.1.0.catalog.toml"),
        &CATALOG.replace("--query-service", "--add-service"),
        0o644,
    );
    let e = s.model(ALLOW_HTTP).expect_err("tampered");
    assert!(
        e.message.contains("does not match the sha256 pinned"),
        "{}",
        e.message
    );
}

const ATTESTED_CATALOG_SHA256: &str =
    "27741bcc6b72dfbf69d918282fb454c324e7229b764873334a5c6c0af04707ff";
const ATTESTED_PLUGIN_SHA256: &str =
    "47f33f171d239103cbb97450d17b57c857ce22436620ddf809fdd2be94948544";

#[test]
fn the_registry_lists_exactly_the_attested_firewalld_catalogs() {
    // Exactly two entries, each the digest of a repository file measured on
    // real hosts: firewalld 0.1.0 (2026-11-01) and 0.2.0 (2026-11-09).
    const CATALOG_020: &str =
        include_str!("../../plugins/first-party/catalogs/firewalld-0.2.0.catalog.toml");
    let entries: Vec<(&str, &str, &str)> = FIRST_PARTY_CATALOGS
        .iter()
        .map(|f| (f.id, f.version, f.sha256))
        .collect();
    assert_eq!(
        entries,
        [
            ("firewalld", "0.1.0", ATTESTED_CATALOG_SHA256),
            (
                "firewalld",
                "0.2.0",
                "d32ac3947279ec2581a7049f9fa931d29c904c91ea2484cafaa6759fe09c3641"
            ),
        ]
    );
    assert_eq!(sha256_hex(CATALOG_020.as_bytes()), entries[1].2);
    // Every catalog file in the repository is listed, and nothing else.
    let mut files: Vec<String> = std::fs::read_dir(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/plugins/first-party/catalogs"
    ))
    .unwrap()
    .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
    .collect();
    files.sort();
    assert_eq!(
        files,
        [
            "firewalld-0.1.0.catalog.toml",
            "firewalld-0.2.0.catalog.toml"
        ]
    );
    assert_eq!(sha256_hex(CATALOG.as_bytes()), ATTESTED_CATALOG_SHA256);
    assert_eq!(sha256_hex(PLUGIN_FW.as_bytes()), ATTESTED_PLUGIN_SHA256);
    assert!(production_enabled());
    // The Owner-pinned repository files load through the release registry.
    let s = Setup::new();
    let m = s.model(ALLOW_HTTP).unwrap();
    let prov = m.plugins.as_ref().unwrap().provenance();
    assert_eq!(prov[0].catalog_sha256, ATTESTED_CATALOG_SHA256);
    assert_eq!(prov[0].plugin_sha256, ATTESTED_PLUGIN_SHA256);
    assert_eq!(prov[0].catalog_registry, "first-party");
}

#[test]
fn the_attested_catalog_has_only_the_seven_reviewed_operations() {
    let s = Setup::new();
    let m = s.model(ALLOW_HTTP).unwrap();
    let set = m.plugins.as_ref().unwrap();
    let c = set.catalog(set.plugins()[0].catalog()).unwrap();
    let mut ops: Vec<(String, OpClass, bool)> = c
        .ops()
        .map(|o| (o.id().to_string(), o.class(), o.is_enabled()))
        .collect();
    ops.sort_by(|a, b| a.0.cmp(&b.0));
    let want = [
        ("add_service_permanent", OpClass::Mutate),
        ("add_service_runtime", OpClass::Mutate),
        ("query_service_permanent", OpClass::Observe),
        ("query_service_runtime", OpClass::Observe),
        ("service_defined", OpClass::Observe),
        ("state", OpClass::Observe),
        ("zone_defined", OpClass::Observe),
    ];
    assert_eq!(
        ops,
        want.into_iter()
            .map(|(i, c)| (i.to_string(), c, true))
            .collect::<Vec<_>>()
    );
    // No reload, removal, zone, interface or direct-rule capability.
    for banned in [
        "--reload",
        "--complete-reload",
        "--remove-",
        "--change-",
        "--new-zone",
        "--delete-",
        "--set-",
        "--direct",
        "--policy",
        "--runtime-to-permanent",
        "--panic",
        "--lockdown",
    ] {
        assert!(!CATALOG.contains(banned), "{}", banned);
    }
    // The plugin keeps the precheck that a service exists: a permanent
    // query of an unknown service answers 1 ("absent") on real hosts.
    assert!(PLUGIN_FW.contains("{ op = \"service_defined\", expect = \"defined\" }"));
}

#[test]
fn the_production_registry_refuses_any_other_catalog_bytes() {
    // One added byte, pinned by the Owner: refused at the registry.
    let s = Setup::new();
    let edited = format!("{}# edited\n", CATALOG);
    write_mode(
        &s.root.join("catalogs/firewalld-0.1.0.catalog.toml"),
        &edited,
        0o644,
    );
    let t = std::fs::read_to_string(s.root.join("trust.toml"))
        .unwrap()
        .replace(ATTESTED_CATALOG_SHA256, &sha256_hex(edited.as_bytes()));
    write_mode(&s.root.join("trust.toml"), &t, 0o600);
    let e = s.model(ALLOW_HTTP).expect_err("refused");
    assert!(
        e.message.contains("not a reviewed first-party catalog"),
        "{}",
        e.message
    );
    // Another id or version with the attested bytes is refused too.
    for (id, version) in [("firewalld", "0.1.1"), ("firewalld2", "0.1.0")] {
        let reg = vec![FirstPartyCatalog {
            id,
            version,
            sha256: ATTESTED_CATALOG_SHA256,
        }];
        let ctx = PluginContext::Test {
            root: s.root.clone(),
            boundary: s.boundary.clone(),
            registry: reg,
        };
        assert!(load_model_with_plugins(&s.recipe("q.yml", ALLOW_HTTP), &ctx).is_err());
    }
}

// ---------------------------------------------------------------------------
// plan
// ---------------------------------------------------------------------------

#[test]
fn plan_reports_would_change_and_never_mutates() {
    let s = Setup::new();
    let fw = firewalld();
    let r = run(s.model(ALLOW_HTTP).unwrap(), Mode::Plan, &fw).unwrap();
    assert_eq!(r.status, AggregateStatus::Success);
    let x = res(&r, "allow_http");
    assert_eq!(x.change, Change::Changed);
    assert_eq!(x.verification, Verification::NotPerformed);
    let note = x.notes.join("\n");
    assert!(
        note.contains("plugin=firewalld@0.1.0 plugin_sha256="),
        "{}",
        note
    );
    assert!(
        note.contains(&format!(
            "catalog_sha256={}",
            sha256_hex(CATALOG.as_bytes())
        )),
        "{}",
        note
    );
    assert!(
        note.contains("would_run=add_service_runtime,add_service_permanent"),
        "{}",
        note
    );
    assert_eq!(mutations(&r.commands), 0);
    assert!(fw.lock().unwrap().mutations.is_empty());
}

#[test]
fn an_observation_failure_in_plan_is_a_plan_error() {
    let s = Setup::new();
    let fw = firewalld();
    fw.lock().unwrap().forced.push((
        "--query-service=http".into(),
        crate::executor::Output {
            completion: crate::executor::Completion::Indeterminate {
                started: true,
                reason: "timeout".into(),
            },
            stdout: vec![],
            stderr: b"SECRET-LOOKING".to_vec(),
            stdout_truncated: false,
            stderr_truncated: false,
        },
    ));
    let Err(e) = run(s.model(ALLOW_HTTP).unwrap(), Mode::Plan, &fw) else {
        panic!("expected a plan error");
    };
    assert_eq!(e.kind, crate::error::ErrorKind::Plan);
    assert!(!e.message.contains("SECRET-LOOKING"), "{}", e.message);
}

// ---------------------------------------------------------------------------
// apply
// ---------------------------------------------------------------------------

#[test]
fn apply_changes_only_what_differs_and_observes_again() {
    let s = Setup::new();
    let fw = firewalld();
    // permanent already present: only runtime differs.
    fw.lock()
        .unwrap()
        .permanent
        .insert(("public".into(), "http".into()));
    let r = run(s.model(ALLOW_HTTP).unwrap(), Mode::Apply, &fw).unwrap();
    assert_eq!(r.status, AggregateStatus::Success);
    let x = res(&r, "allow_http");
    assert_eq!(x.change, Change::Changed);
    assert_eq!(x.verification, Verification::Verified);
    let cmds = fw_commands(&r.commands);
    let add = cmds
        .iter()
        .position(|c| c.contains("--add-service=http"))
        .unwrap();
    assert!(
        cmds[add + 1].contains("--zone=public --query-service=http"),
        "{:?}",
        cmds
    );
    assert_eq!(mutations(&r.commands), 1, "{:?}", cmds);
    assert!(x.notes.join(" ").contains("ran=") && x.notes.join(" ").contains("verified=runtime"));
    {
        let f = fw.lock().unwrap();
        assert!(f.runtime.contains(&("public".into(), "http".into())));
        assert!(
            f.runtime.contains(&("public".into(), "ssh".into())),
            "management service untouched"
        );
    }
    // A second apply changes nothing.
    let r2 = run(s.model(ALLOW_HTTP).unwrap(), Mode::Apply, &fw).unwrap();
    assert_eq!(res(&r2, "allow_http").change, Change::None);
    assert_eq!(mutations(&r2.commands), 0);
}

fn indeterminate_output() -> crate::executor::Output {
    crate::executor::Output {
        completion: crate::executor::Completion::Indeterminate {
            started: true,
            reason: "ssh channel closed".into(),
        },
        stdout: vec![],
        stderr: b"SECRET-LOOKING".to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

#[test]
fn a_lost_connection_after_a_mutation_is_indeterminate_and_not_retried() {
    let s = Setup::new();
    let fw = firewalld();
    fw.lock().unwrap().forced.push((
        "--zone=public --add-service=http".into(),
        indeterminate_output(),
    ));
    let r = run(s.model(&with_after(ALLOW_HTTP)).unwrap(), Mode::Apply, &fw).unwrap();
    assert_eq!(r.status, AggregateStatus::Indeterminate);
    let x = res(&r, "allow_http");
    assert_eq!(x.execution, Execution::Indeterminate);
    assert_eq!(x.change, Change::Possible, "changed is unknown, never none");
    assert_eq!(
        mutations(&r.commands),
        1,
        "not retried, permanent not attempted"
    );
    assert_eq!(res(&r, "after").disposition, Disposition::BlockedByFailFast);
    assert!(!format!("{:?}", r.resources).contains("SECRET-LOOKING"));
}

#[test]
fn a_timeout_on_the_second_facet_keeps_the_first_change() {
    let s = Setup::new();
    let fw = firewalld();
    fw.lock().unwrap().forced.push((
        "--permanent --zone=public --add-service=http".into(),
        indeterminate_output(),
    ));
    let r = run(s.model(ALLOW_HTTP).unwrap(), Mode::Apply, &fw).unwrap();
    let x = res(&r, "allow_http");
    assert_eq!(x.execution, Execution::Indeterminate);
    assert_eq!(
        x.change,
        Change::Changed,
        "the runtime facet definitely changed"
    );
}

#[test]
fn an_unlisted_exit_code_is_a_failure_that_may_have_changed_something() {
    let s = Setup::new();
    let fw = firewalld();
    fw.lock().unwrap().forced.push((
        "--zone=public --add-service=http".into(),
        crate::executor::Output {
            completion: crate::executor::Completion::Exited(13),
            stdout: b"SECRET-LOOKING".to_vec(),
            stderr: b"SECRET-LOOKING".to_vec(),
            stdout_truncated: false,
            stderr_truncated: false,
        },
    ));
    let r = run(s.model(&with_after(ALLOW_HTTP)).unwrap(), Mode::Apply, &fw).unwrap();
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    let x = res(&r, "allow_http");
    assert_eq!(x.execution, Execution::Failed);
    assert_eq!(x.change, Change::Possible);
    assert!(x.reason.as_deref().unwrap().contains("exit code 13"));
    assert_eq!(res(&r, "after").disposition, Disposition::BlockedByFailFast);
    let json = crate::output::run_report_json(&r, "apply").to_string();
    assert!(!json.contains("SECRET-LOOKING"));
}

#[test]
fn a_success_that_does_not_reach_the_wanted_state_fails() {
    let s = Setup::new();
    let fw = firewalld();
    fw.lock().unwrap().add_is_noop = true;
    let r = run(s.model(ALLOW_HTTP).unwrap(), Mode::Apply, &fw).unwrap();
    let x = res(&r, "allow_http");
    assert_eq!(x.execution, Execution::Failed);
    assert!(
        x.reason.as_deref().unwrap().contains("not present"),
        "{:?}",
        x.reason
    );
}

#[test]
fn a_failed_precondition_mutates_nothing() {
    let s = Setup::new();
    let fw = firewalld();
    fw.lock().unwrap().running = false;
    let r = run(s.model(ALLOW_HTTP).unwrap(), Mode::Apply, &fw).unwrap();
    let x = res(&r, "allow_http");
    assert_eq!(x.execution, Execution::Failed);
    assert_eq!(x.change, Change::None);
    assert_eq!(mutations(&r.commands), 0);
}

#[test]
fn a_variable_value_is_checked_before_anything_runs() {
    let s = Setup::new();
    let fw = firewalld();
    let body = "version: 1\nvars:\n  z: { value: \"-trusted\" }\nplugins:\n  - { id: firewalld, version: 0.1.0 }\nresources:\n  - id: a\n    type: firewalld.service\n    with: { zone: \"{{ vars.z }}\", service: http, state: present }\n";
    let r = run(s.model(body).unwrap(), Mode::Apply, &fw).unwrap();
    let x = res(&r, "a");
    assert_eq!(x.execution, Execution::Failed);
    assert!(x.reason.as_deref().unwrap().contains("field zone"));
    assert!(!x.reason.as_deref().unwrap().contains("-trusted"));
    assert!(
        fw.lock().unwrap().received.is_empty(),
        "no command for an invalid value"
    );
}

// ---------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------

#[test]
fn audit_reports_drift_compliant_and_error_and_never_mutates() {
    let s = Setup::new();
    let fw = firewalld();
    let a = audit(s.model(ALLOW_HTTP).unwrap(), &fw);
    let r = &a.resources[0];
    assert_eq!(r.status, AuditResourceStatus::Drift);
    let dims: Vec<&str> = r.details.iter().map(|d| d.dimension.as_str()).collect();
    assert_eq!(dims, ["runtime", "permanent"]);
    assert_eq!(a.exit_code(), 7);
    assert!(r
        .reason
        .as_deref()
        .unwrap()
        .starts_with("plugin=firewalld@0.1.0 plugin_sha256="));
    assert_eq!(mutations(&a.commands), 0);
    assert!(fw.lock().unwrap().mutations.is_empty());

    // runtime only missing
    fw.lock()
        .unwrap()
        .permanent
        .insert(("public".into(), "http".into()));
    let a = audit(s.model(ALLOW_HTTP).unwrap(), &fw);
    let dims: Vec<&str> = a.resources[0]
        .details
        .iter()
        .map(|d| d.dimension.as_str())
        .collect();
    assert_eq!(dims, ["runtime"]);

    // compliant after apply
    run(s.model(ALLOW_HTTP).unwrap(), Mode::Apply, &fw).unwrap();
    let a = audit(s.model(ALLOW_HTTP).unwrap(), &fw);
    assert_eq!(a.resources[0].status, AuditResourceStatus::Compliant);
    assert_eq!(a.exit_code(), 0);
    assert_eq!(
        a.summary.not_auditable, 0,
        "plugin types are auditable (strict audit unaffected)"
    );

    // an unlisted exit code is an error, never compliant
    fw.lock().unwrap().forced.push((
        "--query-service=http".into(),
        crate::executor::Output {
            completion: crate::executor::Completion::Exited(99),
            stdout: vec![],
            stderr: b"SECRET-LOOKING".to_vec(),
            stdout_truncated: false,
            stderr_truncated: false,
        },
    ));
    let a = audit(s.model(ALLOW_HTTP).unwrap(), &fw);
    assert_eq!(a.resources[0].status, AuditResourceStatus::Error);
    assert_eq!(a.exit_code(), 6);
    assert!(!crate::output::audit_report_json(&a)
        .to_string()
        .contains("SECRET-LOOKING"));

    // a timeout is an error
    fw.lock()
        .unwrap()
        .forced
        .push(("--query-service=http".into(), indeterminate_output()));
    let a = audit(s.model(ALLOW_HTTP).unwrap(), &fw);
    assert_eq!(a.resources[0].status, AuditResourceStatus::Error);

    // firewalld stopped: precondition error
    fw.lock().unwrap().running = false;
    let a = audit(s.model(ALLOW_HTTP).unwrap(), &fw);
    assert_eq!(a.resources[0].status, AuditResourceStatus::Error);
    assert_eq!(mutations(&a.commands), 0);
}

#[test]
fn audit_dispatches_only_attested_catalog_observations() {
    let s = Setup::new();
    let fw = firewalld();
    let a = audit(s.model(ALLOW_HTTP).unwrap(), &fw);
    for c in fw_commands(&a.commands) {
        let ok = [
            "/usr/bin/firewall-cmd --state",
            "/usr/bin/firewall-cmd --permanent --info-zone=public",
            "/usr/bin/firewall-cmd --permanent --info-service=http",
            "/usr/bin/firewall-cmd --zone=public --query-service=http",
            "/usr/bin/firewall-cmd --permanent --zone=public --query-service=http",
        ]
        .contains(&c.as_str());
        assert!(ok, "unexpected audit command {}", c);
    }
}

// ---------------------------------------------------------------------------
// the channels themselves
// ---------------------------------------------------------------------------

#[test]
fn call_values_require_the_right_class_and_trust() {
    let s = Setup::new();
    let m = s.model(ALLOW_HTTP).unwrap();
    let set = m.plugins.as_ref().unwrap();
    let c = set
        .catalog(&CatalogRef {
            id: "firewalld".into(),
            version: "0.1.0".into(),
        })
        .unwrap();
    let mut v = BTreeMap::new();
    v.insert("zone".to_string(), "public".to_string());
    v.insert("service".to_string(), "http".to_string());
    let observe = c.op("query_service_runtime").unwrap();
    let mutate = c.op("add_service_runtime").unwrap();
    assert!(exec::ObserveCall::new(observe, &v, false).is_ok());
    assert!(exec::MutateCall::new(mutate, &v, false).is_ok());
    assert!(
        exec::ObserveCall::new(mutate, &v, false).is_err(),
        "a mutate op is never an observation"
    );
    assert!(exec::MutateCall::new(observe, &v, false).is_err());
    v.insert("service".to_string(), "-x".to_string());
    assert!(
        exec::ObserveCall::new(observe, &v, false).is_err(),
        "operands are checked again"
    );
}

#[test]
fn a_read_only_target_has_no_permit_for_the_mutate_channel() {
    let s = Setup::new();
    let fw = firewalld();
    let e = Engine::new(s.model(ALLOW_HTTP).unwrap(), opts(Mode::Plan, &fw)).unwrap();
    assert!(e.fs.mutation_permit().is_err());
    // Audit refuses a mutation-capable engine before observing anything.
    let e = Engine::new(s.model(ALLOW_HTTP).unwrap(), opts(Mode::Apply, &fw)).unwrap();
    assert!(run_audit(e).is_err());
    assert!(fw.lock().unwrap().received.is_empty());
}

// ---------------------------------------------------------------------------
// sensitivity
// ---------------------------------------------------------------------------

#[test]
fn a_sensitive_plugin_resource_is_redacted() {
    let s = Setup::new();
    let fw = firewalld();
    let body = ALLOW_HTTP.replace(
        "    type: firewalld.service\n",
        "    type: firewalld.service\n    sensitive: true\n",
    );
    let r = run(s.model(&body).unwrap(), Mode::Plan, &fw).unwrap();
    assert!(r
        .commands
        .iter()
        .filter(|c| c.program != "/usr/bin/test" && c.program != "/bin/cat")
        .all(|c| c.program == "[redacted]" || !c.args.join(" ").contains("http")));
    let json = crate::output::run_report_json(&r, "plan").to_string();
    assert!(!json.contains("query-service=http"));
    assert!(matches!(
        res(&r, "allow_http").diff.as_ref().unwrap().body,
        crate::result::DiffBody::Redacted
    ));
    let a = audit(s.model(&body).unwrap(), &fw);
    assert!(a.resources[0]
        .details
        .iter()
        .all(|d| d.observed == "[redacted]"));
}

// ---------------------------------------------------------------------------
// external extension: a second resource type, data only
// ---------------------------------------------------------------------------

#[test]
fn a_second_plugin_type_is_added_as_data_and_reuses_the_catalog() {
    let mut s = Setup::new();
    let fw = firewalld();
    let rt = "version: 1\nplugins:\n  - { id: fwruntime, version: 0.1.0 }\nresources:\n  - id: rt\n    type: fwruntime.service\n    with: { zone: public, service: https }\n";
    // Not installed yet: refused.
    assert!(s.model(rt).is_err());
    // The Owner installs and pins the second plugin: data only.
    s.add_plugin("fwruntime", PLUGIN_RT);
    let m = s.model(rt).unwrap();
    let prov = m.plugins.as_ref().unwrap().provenance();
    assert_eq!(
        prov[0].catalog_sha256,
        sha256_hex(CATALOG.as_bytes()),
        "same verified capability"
    );
    let r = run(m, Mode::Apply, &fw).unwrap();
    assert_eq!(res(&r, "rt").change, Change::Changed);
    assert_eq!(mutations(&r.commands), 1, "runtime only");
    let f = fw.lock().unwrap();
    assert!(f.runtime.contains(&("public".into(), "https".into())));
    assert!(!f.permanent.contains(&("public".into(), "https".into())));
}

// ---------------------------------------------------------------------------
// external extension driver (run explicitly against prepared data)
// ---------------------------------------------------------------------------

/// Used by the evidence driver: the same test binary is run once per phase
/// against `SINTER_PLUGIN_DEMO_ROOT` (a plugin root prepared outside the
/// build) and `SINTER_PLUGIN_DEMO_RECIPE`, with the catalog digest from the
/// environment as the test registry. Ignored in normal runs.
#[test]
#[ignore]
fn demo_external_plugin_from_environment() {
    let root = PathBuf::from(std::env::var("SINTER_PLUGIN_DEMO_ROOT").expect("root"));
    let recipe = PathBuf::from(std::env::var("SINTER_PLUGIN_DEMO_RECIPE").expect("recipe"));
    let sha: &'static str = Box::leak(
        std::env::var("SINTER_PLUGIN_DEMO_CATALOG_SHA256")
            .expect("sha")
            .into_boxed_str(),
    );
    let ctx = PluginContext::Test {
        boundary: root.parent().unwrap().to_path_buf(),
        root,
        registry: vec![FirstPartyCatalog {
            id: "firewalld",
            version: "0.1.0",
            sha256: sha,
        }],
    };
    let fw = firewalld();
    for mode in [Mode::Plan, Mode::Apply] {
        let r = run(load_model_with_plugins(&recipe, &ctx).unwrap(), mode, &fw).unwrap();
        println!(
            "{:?}: {}",
            mode,
            crate::output::run_report_json(&r, if mode == Mode::Plan { "plan" } else { "apply" })
        );
        assert_eq!(r.status, AggregateStatus::Success);
    }
    let a = audit(load_model_with_plugins(&recipe, &ctx).unwrap(), &fw);
    println!("audit: {}", crate::output::audit_report_json(&a));
    assert_eq!(a.exit_code(), 0);
}
