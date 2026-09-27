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

/// Nested `diff` shape per documented `type`.
fn check_diff(diff: &Value) {
    string_in(diff, "type", DIFF_TYPE);
    match diff["type"].as_str().unwrap() {
        "summary" => {
            is_string(diff, "current");
            is_string(diff, "desired");
        }
        "text" => {
            for k in ["removed", "added"] {
                let lines = diff[k]
                    .as_array()
                    .unwrap_or_else(|| panic!("diff.{k} must be an array: {diff}"));
                assert!(
                    lines.iter().all(Value::is_string),
                    "diff.{k} must hold strings"
                );
            }
        }
        "redacted" => {
            // Only the marker: no content-bearing fields may accompany it.
            for k in ["current", "desired", "removed", "added"] {
                assert!(diff.get(k).is_none(), "redacted diff must not carry `{k}`");
            }
        }
        _ => unreachable!(),
    }
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
        check_diff(diff);
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
    for cmd in ["validate", "plan", "apply", "audit"] {
        let out = Command::new(env!("CARGO_BIN_EXE_sinter"))
            .args([cmd, recipe.to_str().unwrap(), "--format", "json"])
            .output()
            .unwrap();
        assert_no_report(&out, 2, cmd);
    }
}

#[test]
fn connection_failure_before_report_writes_no_json_to_stdout() {
    // Exit 3 (connection/capability/security) before any report: the
    // selected known_hosts file does not exist, so no connection is made.
    let dir = trusted_root("json-contract-connect");
    let recipe = write_recipe(&dir, "r.yaml", PACKAGE_ONLY);
    let missing = dir.join("no-such-known-hosts");
    for cmd in ["plan", "apply", "audit"] {
        let out = Command::new(env!("CARGO_BIN_EXE_sinter"))
            .args([
                cmd,
                recipe.to_str().unwrap(),
                "--host",
                "127.0.0.1",
                "--port",
                "1",
                "--user",
                "nobody",
                "--known-hosts",
                missing.to_str().unwrap(),
                "--format",
                "json",
            ])
            .output()
            .unwrap();
        assert_no_report(&out, 3, cmd);
    }
}

fn assert_no_report(out: &std::process::Output, code: i32, cmd: &str) {
    assert_eq!(out.status.code(), Some(code), "{cmd}");
    assert!(out.stdout.is_empty(), "{cmd}: stdout must be empty");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.starts_with("sinter: "), "{cmd}: {err}");
    assert_eq!(err.lines().count(), 1, "{cmd}: one stderr line: {err}");
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

// ---------------------------------------------------------------------------
// Status / exit-code mapping through the production engine and renderer.
// The CLI maps plan/apply statuses with `ErrorKind::{Plan,Apply,Indeterminate}
// .exit_code()` and audit outcomes with `AuditReport::exit_code()`; the
// documented numbers are pinned against those same functions here.
// ---------------------------------------------------------------------------

fn run_json(recipe: &std::path::Path, mode: Mode, fake: FakeTarget) -> (Value, AggregateStatus) {
    let r = run_recipe_fake(recipe, mode, false, fake);
    let mut buf = Vec::new();
    match mode {
        Mode::Plan => render_plan(&r, &json_opts(), &mut buf).unwrap(),
        Mode::Apply => render_apply(&r, &json_opts(), &mut buf).unwrap(),
    }
    let v = parse_document(buf);
    let label = match mode {
        Mode::Plan => "plan",
        Mode::Apply => "apply",
    };
    check_run_document(&v, label, r.status);
    (v, r.status)
}

fn documented_run_exit(status: &str) -> i32 {
    match status {
        "success" => 0,
        "plan_error" => 4,
        "apply_failed" => 5,
        "indeterminate" => 6,
        other => panic!("undocumented status {other}"),
    }
}

/// Mirror of `report_status_code` in `src/main.rs` (a binary-private
/// function). `cli_exit_glue_is_pinned` keeps the two from drifting.
fn cli_run_exit(status: AggregateStatus) -> i32 {
    use sinter::error::ErrorKind;
    match status {
        AggregateStatus::Success => 0,
        AggregateStatus::PlanError => ErrorKind::Plan.exit_code(),
        AggregateStatus::ApplyFailed => ErrorKind::Apply.exit_code(),
        AggregateStatus::Indeterminate => ErrorKind::Indeterminate.exit_code(),
    }
}

#[test]
fn cli_exit_glue_is_pinned() {
    // The CLI cannot reach a scripted target, so its status → exit glue is
    // pinned at the source level against the mirror used above.
    let main_rs = include_str!("../src/main.rs");
    for line in [
        "Success => 0,",
        "PlanError => ErrorKind::Plan.exit_code() as u8,",
        "ApplyFailed => ErrorKind::Apply.exit_code() as u8,",
        "Indeterminate => ErrorKind::Indeterminate.exit_code() as u8,",
    ] {
        assert!(
            main_rs.contains(line),
            "src/main.rs exit glue changed: {line}"
        );
    }
    assert!(
        main_rs.contains("report.exit_code()"),
        "audit exit glue changed"
    );
}

#[test]
fn run_status_and_exit_mapping() {
    use sinter::executor::Completion;
    let dir = trusted_root("json-contract-status");
    let recipe = write_recipe(&dir, "r.yaml", PACKAGE_ONLY);

    // success (plan and apply)
    let (v, s) = run_json(&recipe, Mode::Plan, FakeTarget::rocky10());
    assert_eq!(v["status"], "success");
    assert_eq!(cli_run_exit(s), documented_run_exit("success"));
    let (v, s) = run_json(&recipe, Mode::Apply, FakeTarget::rocky10());
    assert_eq!(v["status"], "success");
    assert_eq!(cli_run_exit(s), documented_run_exit("success"));

    // plan_error: a resource that cannot be planned aborts the plan before
    // any report is rendered (stdout stays empty, see the failure-before-
    // report tests) with the Plan error class, i.e. exit 4. A report whose
    // aggregate is PlanError maps to that same exit code.
    let mut t = FakeTarget::rocky10();
    t.query_completion = Some(Completion::Exited(99));
    let e = try_run_recipe_fake(&recipe, Mode::Plan, false, t)
        .err()
        .expect("an unplannable resource must fail the plan");
    assert_eq!(e.kind, sinter::error::ErrorKind::Plan);
    assert_eq!(e.kind.exit_code(), documented_run_exit("plan_error"));
    assert_eq!(
        cli_run_exit(AggregateStatus::PlanError),
        documented_run_exit("plan_error")
    );

    // apply_failed: a verified mutation whose snapshot cleanup fails.
    let mut t = FakeTarget::rocky9();
    t.snapshot_rm_fails = true;
    let (v, s) = run_json(&recipe, Mode::Apply, t);
    assert_eq!(v["status"], "apply_failed");
    assert_eq!(v["resources"][0]["execution"], "failed");
    assert_eq!(cli_run_exit(s), documented_run_exit("apply_failed"));

    // indeterminate: mutation completion cannot be established.
    let mut t = FakeTarget::rocky9();
    t.manager_completion = Some(Completion::Indeterminate {
        started: true,
        reason: "lost response after dispatch".into(),
    });
    let (v, s) = run_json(&recipe, Mode::Apply, t);
    assert_eq!(v["status"], "indeterminate");
    assert_eq!(v["resources"][0]["execution"], "indeterminate");
    assert_eq!(cli_run_exit(s), documented_run_exit("indeterminate"));
}

fn audit_json(recipe: &std::path::Path, fake: FakeTarget) -> (Value, u8) {
    let model = load_model(recipe).unwrap();
    let engine = Engine::new(model, fake_options(Mode::Plan, fake)).unwrap();
    let report = run_audit(engine).unwrap();
    let mut buf = Vec::new();
    render_audit(&report, &json_opts(), &mut buf).unwrap();
    (parse_document(buf), report.exit_code())
}

#[test]
fn audit_status_and_exit_mapping() {
    use sinter::executor::Completion;
    let dir = trusted_root("json-contract-audit-status");
    let recipe = write_recipe(&dir, "r.yaml", PACKAGE_ONLY);

    let mut t = FakeTarget::rocky10();
    t.packages.insert("tree".into());
    let (v, code) = audit_json(&recipe, t);
    assert_eq!((v["status"].as_str().unwrap(), code), ("no_drift", 0));
    assert_eq!(v["resources"][0]["status"], "compliant");

    let (v, code) = audit_json(&recipe, FakeTarget::rocky10());
    assert_eq!((v["status"].as_str().unwrap(), code), ("drift", 7));
    assert_eq!(v["resources"][0]["status"], "drift");

    let mut t = FakeTarget::rocky10();
    t.query_completion = Some(Completion::Exited(99));
    let (v, code) = audit_json(&recipe, t);
    assert_eq!((v["status"].as_str().unwrap(), code), ("indeterminate", 6));
    assert_eq!(v["resources"][0]["status"], "error");
    assert_eq!(v["summary"]["errors"], 1);
}

// ---------------------------------------------------------------------------
// Nested diff shapes and redaction markers.
// ---------------------------------------------------------------------------

const STAT_REGULAR: &str = "regular file|644|0|0|4|2051|1234567|2026-09-19 09:30:00.000000000 +0000|2026-09-19 09:30:00.000000000 +0000";

fn out_ok(stdout: &str) -> sinter::executor::Output {
    sinter::executor::Output {
        completion: sinter::executor::Completion::Exited(0),
        stdout: stdout.as_bytes().to_vec(),
        stderr: Vec::new(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

fn file_target(current: &str) -> FakeTarget {
    let t = FakeTarget::ubuntu2404();
    // `cat` serves /etc/os-release first (platform detection), then the file.
    let os_release = t.os_release.clone();
    t.with_observations("stat", vec![out_ok(&format!("{STAT_REGULAR}\n"))])
        .with_observations("cat", vec![out_ok(&os_release), out_ok(current)])
}

#[test]
fn diff_shapes_summary_text_and_redacted() {
    let dir = trusted_root("json-contract-diff");

    // summary: package state change
    let pkg = write_recipe(&dir, "pkg.yaml", PACKAGE_ONLY);
    let (v, _) = run_json(&pkg, Mode::Plan, FakeTarget::rocky10());
    let d = &v["resources"][0]["diff"];
    assert_eq!(d["type"], "summary", "{v}");
    check_diff(d);

    // text: file content change
    let file = write_recipe(
        &dir,
        "file.yaml",
        "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: /opt/f\n      content: \"new\\n\"\n",
    );
    let (v, _) = run_json(&file, Mode::Plan, file_target("old\n"));
    let d = &v["resources"][0]["diff"];
    assert_eq!(d["type"], "text", "{v}");
    check_diff(d);
    assert!(d["removed"]
        .as_array()
        .unwrap()
        .iter()
        .any(|l| l.as_str().unwrap().contains("old")));
    assert!(d["added"]
        .as_array()
        .unwrap()
        .iter()
        .any(|l| l.as_str().unwrap().contains("new")));

    // redacted: the same change, but the content is sensitive
    let secret = "SINTER_JSON_CONTRACT_SECRET_7f3a";
    let sens = write_recipe(
        &dir,
        "sens.yaml",
        &format!(
            "version: 1\nvars:\n  s: {{ value: \"{secret}\", sensitive: true }}\nresources:\n  - id: f\n    type: file\n    with:\n      path: /opt/f\n      content: \"{{{{ vars.s }}}}\"\n"
        ),
    );
    let (v, _) = run_json(&sens, Mode::Plan, file_target("old\n"));
    let r = &v["resources"][0];
    assert_eq!(r["sensitive"], true, "{v}");
    assert_eq!(r["diff"], serde_json::json!({"type": "redacted"}));
    assert_eq!(r["reason"], "<redacted>");
    assert!(r["notes"]
        .as_array()
        .unwrap()
        .iter()
        .all(|n| n == "<redacted>"));
    assert!(!v.to_string().contains(secret), "secret leaked: {v}");
}

#[test]
fn audit_details_are_redacted_for_sensitive_resources() {
    let dir = trusted_root("json-contract-audit-redact");
    let secret = "SINTER_JSON_CONTRACT_SECRET_91bc";
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nvars:\n  s: {{ value: \"{secret}\", sensitive: true }}\nresources:\n  - id: f\n    type: file\n    with:\n      path: /opt/f\n      content: \"{{{{ vars.s }}}}\"\n"
        ),
    );
    let fake = FakeTarget::ubuntu2404()
        .with_observations("stat", vec![out_ok(&format!("{STAT_REGULAR}\n"))])
        .with_observations(
            "sha256sum",
            vec![out_ok(&format!("{}  /opt/f\n", "0".repeat(64)))],
        );
    let (v, code) = audit_json(&recipe, fake);
    assert_eq!(code, 7, "{v}");
    let r = &v["resources"][0];
    assert_eq!(r["sensitive"], true);
    let details = r["details"].as_array().unwrap();
    assert!(!details.is_empty(), "{v}");
    for d in details {
        assert_eq!(d["observed"], "[redacted]");
        assert_eq!(d["desired"], "[redacted]");
    }
    assert!(!v.to_string().contains(secret), "secret leaked: {v}");
}

#[test]
fn handler_object_shape_in_apply() {
    let dir = trusted_root("json-contract-handler");
    let recipe = write_recipe(&dir, "r.yaml", PACKAGE_WITH_HANDLER);
    let (v, _) = run_json(&recipe, Mode::Apply, FakeTarget::rocky10());
    let handlers = v["handlers"].as_array().unwrap();
    assert_eq!(handlers.len(), 1, "{v}");
    assert_eq!(handlers[0]["id"], "h");
    // check_run_document already pinned the field types and state set.
}
