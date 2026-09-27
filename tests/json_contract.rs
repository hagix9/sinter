//! v1 machine-readable output contract: the documented `--format json`
//! shapes of `validate`, `plan`, `apply`, and `audit` (docs:
//! reference/cli, "JSON output contract").
//!
//! These tests pin what the contract promises — presence, type, and the closed
//! value sets of documented fields, and the status/exit-code mapping. They do
//! not pin key order, whitespace, undocumented fields, or human-readable text,
//! which the contract explicitly leaves unspecified. Reports come from the
//! production engine/renderer path against the scripted in-process target
//! (FakeTarget), so they run on any controller.
mod common;

use common::*;
use serde_json::Value;
use sinter::audit::run_audit;
use sinter::engine::{AggregateStatus, Engine, Mode, RunOptions, TargetSpec};
use sinter::executor::FakeTarget;
use sinter::model::load_model;
use sinter::output::{render_apply, render_audit, render_plan, OutputFormat, RenderOptions};
use sinter::result::HandlerOutcomeState;
use std::process::Command;

const RUN_STATUS: &[&str] = &["success", "plan_error", "apply_failed", "indeterminate"];
const EXECUTION: &[&str] = &["not_run", "succeeded", "failed", "indeterminate"];
const CHANGE: &[&str] = &["none", "changed", "possible"];
const VERIFICATION: &[&str] = &[
    "not_applicable",
    "not_performed",
    "verified",
    "failed",
    "unknown",
];
const DISPOSITION: &[&str] = &[
    "normal",
    "skipped_by_condition",
    "guard_satisfied",
    "blocked_by_dependency",
    "blocked_by_fail_fast",
];
const DIFF_TYPE: &[&str] = &["redacted", "summary", "text"];
const AUDIT_STATUS: &[&str] = &["no_drift", "drift", "indeterminate"];
const AUDIT_RESOURCE_STATUS: &[&str] = &[
    "compliant",
    "drift",
    "not_auditable",
    "not_applicable",
    "error",
];
const HANDLER_STATE: &[&str] = &["NotRun", "Succeeded", "Failed", "Indeterminate"];

fn json_opts() -> RenderOptions {
    RenderOptions {
        verbose: false,
        format: OutputFormat::Json,
    }
}

/// One JSON object followed by a newline, and nothing else.
fn parse_document(buf: Vec<u8>) -> Value {
    let s = String::from_utf8(buf).expect("JSON output must be UTF-8");
    assert!(s.ends_with('\n'), "document must end with a newline");
    let v: Value = serde_json::from_str(s.trim_end()).expect("exactly one JSON document");
    assert!(v.is_object(), "top level must be an object");
    v
}

fn string_in(v: &Value, key: &str, allowed: &[&str]) {
    let s = v[key]
        .as_str()
        .unwrap_or_else(|| panic!("`{key}` must be a string: {v}"));
    assert!(allowed.contains(&s), "`{key}` = {s:?} not in {allowed:?}");
}

fn is_string(v: &Value, key: &str) {
    assert!(v[key].is_string(), "`{key}` must be a string: {v}");
}

fn is_bool(v: &Value, key: &str) {
    assert!(v[key].is_boolean(), "`{key}` must be a boolean: {v}");
}

fn is_uint(v: &Value, key: &str) {
    assert!(
        v[key].is_u64(),
        "`{key}` must be a non-negative integer: {v}"
    );
}

fn string_or_null(v: &Value, key: &str) {
    let f = v
        .get(key)
        .unwrap_or_else(|| panic!("`{key}` must be present: {v}"));
    assert!(
        f.is_string() || f.is_null(),
        "`{key}` must be string or null"
    );
}

fn uint_or_null(v: &Value, key: &str) {
    let f = v
        .get(key)
        .unwrap_or_else(|| panic!("`{key}` must be present: {v}"));
    assert!(f.is_u64() || f.is_null(), "`{key}` must be integer or null");
}

fn check_run_resource(r: &Value) {
    is_string(r, "id");
    is_string(r, "type");
    is_string(r, "origin");
    uint_or_null(r, "loop_index");
    string_in(r, "execution", EXECUTION);
    string_in(r, "change", CHANGE);
    string_in(r, "verification", VERIFICATION);
    string_in(r, "disposition", DISPOSITION);
    is_bool(r, "unknown");
    is_bool(r, "sensitive");
    string_or_null(r, "reason");
    let diff = r.get("diff").expect("`diff` must be present");
    if !diff.is_null() {
        string_in(diff, "type", DIFF_TYPE);
    }
    let notes = r["notes"].as_array().expect("`notes` must be an array");
    assert!(notes.iter().all(Value::is_string), "notes must be strings");
}

fn check_run_document(v: &Value, mode: &str, status: AggregateStatus) {
    assert_eq!(v["mode"], mode);
    string_in(v, "status", RUN_STATUS);
    // Documented status labels map 1:1 onto the aggregate status (and so
    // onto the documented exit codes 0/4/5/6).
    let expected = match status {
        AggregateStatus::Success => "success",
        AggregateStatus::PlanError => "plan_error",
        AggregateStatus::ApplyFailed => "apply_failed",
        AggregateStatus::Indeterminate => "indeterminate",
    };
    assert_eq!(v["status"], expected);
    let facts = &v["facts"];
    for k in ["hostname", "os_name", "os_family", "os_version", "arch"] {
        is_string(facts, k);
    }
    let resources = v["resources"]
        .as_array()
        .expect("`resources` must be an array");
    assert!(!resources.is_empty());
    resources.iter().for_each(check_run_resource);
    let handlers = v["handlers"]
        .as_array()
        .expect("`handlers` must be an array");
    for h in handlers {
        is_string(h, "id");
        is_string(h, "service");
        is_string(h, "action");
        string_in(h, "state", HANDLER_STATE);
        string_or_null(h, "reason");
    }
    let pending = v["handlers_pending"]
        .as_array()
        .expect("`handlers_pending` must be an array");
    assert!(pending.iter().all(Value::is_string));
}

fn fake_options(mode: Mode, fake: FakeTarget) -> RunOptions {
    RunOptions {
        mode,
        sudo: false,
        target: TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(fake),
    }
}

const PACKAGE_WITH_HANDLER: &str = "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: tree\n      state: present\n    notify: [h]\nhandlers:\n  - id: h\n    service: sshd\n    action: restart\n";
const PACKAGE_ONLY: &str =
    "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: tree\n      state: present\n";

#[test]
fn plan_json_matches_v1_contract() {
    let dir = trusted_root("json-contract-plan");
    let recipe = write_recipe(&dir, "r.yaml", PACKAGE_WITH_HANDLER);
    let r = run_recipe_fake(&recipe, Mode::Plan, false, FakeTarget::rocky10());
    let mut buf = Vec::new();
    render_plan(&r, &json_opts(), &mut buf).unwrap();
    let v = parse_document(buf);
    check_run_document(&v, "plan", r.status);
    let p = &v["resources"][0];
    assert_eq!(p["id"], "p");
    assert_eq!(p["type"], "package");
    assert!(p["loop_index"].is_null());
    assert_eq!(p["change"], "changed");
    // A plan never runs handlers: every notified handler is pending.
    assert_eq!(v["handlers"].as_array().unwrap().len(), 0);
    assert_eq!(v["handlers_pending"], serde_json::json!(["h"]));
}

#[test]
fn apply_json_matches_v1_contract() {
    let dir = trusted_root("json-contract-apply");
    let recipe = write_recipe(&dir, "r.yaml", PACKAGE_ONLY);
    let r = run_recipe_fake(&recipe, Mode::Apply, false, FakeTarget::rocky10());
    let mut buf = Vec::new();
    render_apply(&r, &json_opts(), &mut buf).unwrap();
    let v = parse_document(buf);
    check_run_document(&v, "apply", r.status);
    assert_eq!(v["status"], "success");
    let p = &v["resources"][0];
    assert_eq!(p["execution"], "succeeded");
    assert_eq!(p["change"], "changed");
    assert_eq!(p["verification"], "verified");
    assert_eq!(p["disposition"], "normal");
}

#[test]
fn audit_json_matches_v1_contract() {
    let dir = trusted_root("json-contract-audit");
    let recipe = write_recipe(&dir, "r.yaml", PACKAGE_ONLY);
    let model = load_model(&recipe).unwrap();
    let engine = Engine::new(model, fake_options(Mode::Plan, FakeTarget::rocky10())).unwrap();
    let report = run_audit(engine).unwrap();
    let mut buf = Vec::new();
    render_audit(&report, &json_opts(), &mut buf).unwrap();
    let v = parse_document(buf);
    assert_eq!(v["mode"], "audit");
    string_in(&v, "status", AUDIT_STATUS);
    assert_eq!(v["status"], report.aggregate_label());
    // Documented status/exit-code mapping: no_drift 0, drift 7, indeterminate 6.
    let expected_exit = match v["status"].as_str().unwrap() {
        "no_drift" => 0,
        "drift" => 7,
        _ => 6,
    };
    assert_eq!(report.exit_code(), expected_exit);
    let s = &v["summary"];
    for k in [
        "total",
        "compliant",
        "drifted",
        "not_auditable",
        "not_applicable",
        "errors",
    ] {
        is_uint(s, k);
    }
    let resources = v["resources"].as_array().unwrap();
    assert_eq!(s["total"].as_u64().unwrap(), resources.len() as u64);
    for r in resources {
        is_string(r, "id");
        is_string(r, "type");
        is_string(r, "origin");
        uint_or_null(r, "loop_index");
        string_in(r, "status", AUDIT_RESOURCE_STATUS);
        is_bool(r, "sensitive");
        string_or_null(r, "reason");
        for d in r["details"].as_array().expect("`details` must be an array") {
            is_string(d, "dimension");
            is_string(d, "observed");
            is_string(d, "desired");
        }
    }
}

#[test]
fn validate_json_matches_v1_contract() {
    let dir = trusted_root("json-contract-validate");
    let recipe = write_recipe(&dir, "r.yaml", PACKAGE_WITH_HANDLER);
    let out = Command::new(env!("CARGO_BIN_EXE_sinter"))
        .args(["validate", recipe.to_str().unwrap(), "--format", "json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let v = parse_document(out.stdout);
    assert_eq!(v["command"], "validate");
    assert_eq!(v["status"], "ok");
    assert_eq!(v["resources"], 1);
    assert_eq!(v["handlers"], 1);
    assert_eq!(v["vars"], 0);
}

#[test]
fn failure_before_report_writes_no_json_to_stdout() {
    // Contract: when no report is produced, stdout is empty and the exit
    // code is the machine-readable error class (2 = schema).
    let dir = trusted_root("json-contract-error");
    let recipe = write_recipe(&dir, "r.yaml", "version: 2\n");
    for cmd in ["validate", "plan", "audit"] {
        let out = Command::new(env!("CARGO_BIN_EXE_sinter"))
            .args([cmd, recipe.to_str().unwrap(), "--format", "json"])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2), "{cmd}");
        assert!(out.stdout.is_empty(), "{cmd}: stdout must be empty");
        assert!(
            String::from_utf8_lossy(&out.stderr).starts_with("sinter: "),
            "{cmd}"
        );
    }
}

#[test]
fn handler_state_labels_are_pinned() {
    // Handler `state` is rendered from the enum's Debug form; the documented
    // closed value set must not drift through an enum rename.
    let labels: Vec<String> = [
        HandlerOutcomeState::NotRun,
        HandlerOutcomeState::Succeeded,
        HandlerOutcomeState::Failed,
        HandlerOutcomeState::Indeterminate,
    ]
    .iter()
    .map(|s| format!("{s:?}"))
    .collect();
    assert_eq!(labels, HANDLER_STATE);
}
