//! Typed handler foundation (generic handler extension, H1).
//!
//! H1 gives every handler a type (`type:`; absent means `service`) and keeps
//! the service handler exactly as it was. These tests run the production
//! parser, engine, audit and renderer against the scripted in-process target
//! ([`FakeTarget`]), so they run on any controller. They prove:
//!
//! * a recipe written before handler types existed means the same thing, and
//!   `type: service` is the same handler;
//! * an unknown or malformed type is refused at validation, before anything
//!   can run;
//! * notification aggregation, declaration order, fail-fast and pending
//!   reporting are unchanged;
//! * plan and audit never run a handler;
//! * the JSON keeps its documented handler keys and only adds `type`, and a
//!   sensitive handler stays redacted.
mod common;

use common::*;
use serde_json::Value;
use sinter::engine::{AggregateStatus, Mode, RunReport};
use sinter::error::ErrorKind;
use sinter::executor::FakeTarget;
use sinter::ir::HandlerKind;
use sinter::output::{render_apply, render_plan, OutputFormat, RenderOptions};
use sinter::result::HandlerOutcomeState;
use std::path::{Path, PathBuf};

fn fake() -> FakeTarget {
    FakeTarget::ubuntu2404()
        .with_fake_fs()
        .with_loaded_unit("foo.service", "A", ("loaded", "active", "enabled"))
        .with_loaded_unit("bar.service", "B", ("loaded", "active", "enabled"))
}

fn conf(id: &str, path: &str, content: &str, notify: &[&str]) -> String {
    format!(
        "  - id: {id}\n    type: file\n    with:\n      path: {path}\n      content: \"{content}\"\n    notify: [{}]\n",
        notify.join(", ")
    )
}

fn recipe(label: &str, resources: &str, handlers: &str) -> PathBuf {
    let dir = trusted_root(label);
    let yaml = format!("version: 1\nresources:\n{resources}handlers:\n{handlers}");
    write_recipe(&dir, "r.yaml", &yaml)
}

fn run(r: &Path, mode: Mode) -> RunReport {
    run_recipe_fake(r, mode, true, fake())
}

fn restart_trace(rep: &RunReport) -> Vec<String> {
    rep.commands
        .iter()
        .filter(|c| c.program.ends_with("systemctl"))
        .filter(|c| {
            matches!(
                c.args.first().map(String::as_str),
                Some("restart") | Some("reload")
            )
        })
        .map(|c| format!("{}:{}", c.args[0], c.args.last().unwrap()))
        .collect()
}

fn load_error(label: &str, handlers: &str) -> sinter::error::SinterError {
    let r = recipe(label, &conf("c", "/etc/app.conf", "v1", &["h"]), handlers);
    try_run_recipe_fake(&r, Mode::Plan, true, fake())
        .err()
        .expect("the recipe must be refused")
}

fn json_of(rep: &RunReport, mode: Mode) -> Value {
    let opts = RenderOptions {
        verbose: false,
        format: OutputFormat::Json,
        color: false,
    };
    let mut buf = Vec::new();
    match mode {
        Mode::Plan => render_plan(rep, &opts, &mut buf).unwrap(),
        Mode::Apply => render_apply(rep, &opts, &mut buf).unwrap(),
    }
    serde_json::from_slice(&buf).expect("one JSON document")
}

fn text_of(rep: &RunReport) -> String {
    let opts = RenderOptions {
        verbose: false,
        format: OutputFormat::Text,
        color: false,
    };
    let mut buf = Vec::new();
    render_apply(rep, &opts, &mut buf).unwrap();
    String::from_utf8(buf).unwrap()
}

// ---------------------------------------------------------------------------
// the service handler is unchanged
// ---------------------------------------------------------------------------

#[test]
fn a_handler_without_type_and_type_service_are_the_same_handler() {
    let res = conf("c", "/etc/app.conf", "v1", &["h"]);
    let plain = recipe(
        "ht-plain",
        &res,
        "  - id: h\n    service: foo.service\n    action: restart\n",
    );
    let typed = recipe(
        "ht-typed",
        &res,
        "  - id: h\n    type: service\n    service: foo.service\n    action: restart\n",
    );
    let (a, b) = (run(&plain, Mode::Apply), run(&typed, Mode::Apply));
    for rep in [&a, &b] {
        assert_eq!(
            rep.status,
            AggregateStatus::Success,
            "{:?}",
            rep.handlers_run
        );
        assert_eq!(rep.handlers_run.len(), 1);
        assert_eq!(rep.handlers_run[0].id, "h");
        assert_eq!(rep.handlers_run[0].kind, HandlerKind::Service);
        assert_eq!(rep.handlers_run[0].state, HandlerOutcomeState::Succeeded);
        assert_eq!(restart_trace(rep), vec!["restart:foo.service"]);
    }
    // Same command sequence, handler for handler.
    let cmds = |r: &RunReport| -> Vec<(String, Vec<String>)> {
        r.commands
            .iter()
            .map(|c| (c.program.clone(), c.args.clone()))
            .collect()
    };
    assert_eq!(cmds(&a), cmds(&b));
}

#[test]
fn a_notification_runs_each_handler_once_in_declaration_order() {
    // `bar_h` is declared first, `foo_h` second; the resources notify in the
    // opposite order and two of them notify `foo_h`.
    let res = [
        conf("c1", "/etc/a.conf", "1", &["foo_h"]),
        conf("c2", "/etc/b.conf", "2", &["foo_h", "bar_h"]),
    ]
    .concat();
    let r = recipe(
        "ht-order",
        &res,
        "  - id: bar_h\n    service: bar.service\n    action: restart\n  - id: foo_h\n    service: foo.service\n    action: reload\n",
    );
    let rep = run(&r, Mode::Apply);
    assert_eq!(
        rep.status,
        AggregateStatus::Success,
        "{:?}",
        rep.handlers_run
    );
    let ids: Vec<&str> = rep.handlers_run.iter().map(|h| h.id.as_str()).collect();
    assert_eq!(ids, vec!["bar_h", "foo_h"]);
    assert_eq!(
        restart_trace(&rep),
        vec!["restart:bar.service", "reload:foo.service"]
    );
}

#[test]
fn a_failed_handler_stops_the_phase_and_the_rest_is_pending() {
    let res = conf("c", "/etc/a.conf", "1", &["gone_h", "bar_h"]);
    let r = recipe(
        "ht-failfast",
        &res,
        "  - id: gone_h\n    service: missing.service\n    action: restart\n  - id: bar_h\n    service: bar.service\n    action: restart\n",
    );
    let rep = run(&r, Mode::Apply);
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    assert_eq!(rep.handlers_run.len(), 1);
    assert_eq!(rep.handlers_run[0].id, "gone_h");
    assert_eq!(rep.handlers_run[0].state, HandlerOutcomeState::Failed);
    assert_eq!(rep.handlers_pending, vec!["bar_h".to_string()]);
    assert!(restart_trace(&rep).is_empty(), "{:?}", restart_trace(&rep));
}

#[test]
fn plan_and_audit_never_run_a_handler() {
    let res = conf("c", "/etc/a.conf", "1", &["foo_h"]);
    let r = recipe(
        "ht-plan",
        &res,
        "  - id: foo_h\n    service: foo.service\n    action: restart\n",
    );
    let plan = run(&r, Mode::Plan);
    assert!(plan.handlers_run.is_empty());
    assert_eq!(plan.handlers_pending, vec!["foo_h".to_string()]);
    assert!(restart_trace(&plan).is_empty());

    let model = sinter::model::load_model(&r).unwrap();
    let opts = sinter::engine::RunOptions {
        mode: Mode::Plan,
        sudo: true,
        target: sinter::engine::TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(fake()),
    };
    let engine = sinter::engine::Engine::new(model, opts).unwrap();
    let audit = sinter::audit::run_audit(engine).unwrap();
    for c in &audit.commands {
        let verb = c.args.first().map(String::as_str).unwrap_or("");
        assert!(
            !(c.program.ends_with("systemctl") && matches!(verb, "restart" | "reload")),
            "audit ran {:?}",
            c.args
        );
    }
}

// ---------------------------------------------------------------------------
// types that cannot run are refused at validation
// ---------------------------------------------------------------------------

#[test]
fn unknown_and_malformed_types_are_refused() {
    for (what, handler, needle) in [
        (
            "unknown",
            "  - id: h\n    type: nosuch\n    service: foo.service\n    action: restart\n",
            "unknown handler type nosuch",
        ),
        (
            "case matters",
            "  - id: h\n    type: Service\n    service: foo.service\n    action: restart\n",
            "unknown handler type Service",
        ),
        (
            "empty",
            "  - id: h\n    type: \"\"\n    service: foo.service\n    action: restart\n",
            "unknown handler type <invalid>",
        ),
        (
            "control character",
            "  - id: h\n    type: \"a\\nb\"\n    service: foo.service\n    action: restart\n",
            "unknown handler type <invalid>",
        ),
        (
            "not a string",
            "  - id: h\n    type: 5\n    service: foo.service\n    action: restart\n",
            "type must be a string",
        ),
        (
            "a list",
            "  - id: h\n    type: [service]\n    service: foo.service\n    action: restart\n",
            "type must be a string",
        ),
    ] {
        let e = load_error("ht-badtype", handler);
        assert_eq!(e.kind, ErrorKind::Schema, "{what}");
        assert!(e.message.contains(needle), "{what}: {}", e.message);
    }
}

#[test]
fn the_service_handler_is_still_strictly_validated() {
    for (what, handler) in [
        ("service missing", "  - id: h\n    action: restart\n"),
        ("service empty", "  - id: h\n    service: \"\"\n    action: restart\n"),
        ("action missing", "  - id: h\n    service: foo.service\n"),
        ("action invalid", "  - id: h\n    service: foo.service\n    action: stop\n"),
        ("unknown field", "  - id: h\n    service: foo.service\n    action: restart\n    when: \"true\"\n"),
        ("future field `with`", "  - id: h\n    type: service\n    service: foo.service\n    action: restart\n    with: {}\n"),
        ("future field `privilege`", "  - id: h\n    service: foo.service\n    action: restart\n    privilege: root\n"),
        ("sensitive not a boolean", "  - id: h\n    service: foo.service\n    action: restart\n    sensitive: yes-please\n"),
        ("id missing", "  - service: foo.service\n    action: restart\n"),
    ] {
        let e = load_error("ht-strict", handler);
        assert_eq!(e.kind, ErrorKind::Schema, "{what}: {}", e.message);
    }
}

#[test]
fn handler_ids_and_notify_references_are_validated() {
    let one = "  - id: h\n    service: foo.service\n    action: restart\n";
    // duplicate handler id
    let e = load_error("ht-dup", &format!("{one}{one}"));
    assert!(e.message.contains("duplicate handler id"), "{}", e.message);
    // a handler id that is also a resource id
    let r = recipe("ht-collide", &conf("h", "/etc/a.conf", "1", &["h"]), one);
    let e = try_run_recipe_fake(&r, Mode::Plan, true, fake())
        .err()
        .expect("collision");
    assert!(
        e.message.contains("collides with a resource id"),
        "{}",
        e.message
    );
    // notify of an unknown handler
    let r = recipe(
        "ht-unknown-notify",
        &conf("c", "/etc/a.conf", "1", &["nope"]),
        one,
    );
    let e = try_run_recipe_fake(&r, Mode::Plan, true, fake())
        .err()
        .expect("unknown");
    assert!(e.message.contains("unknown handler"), "{}", e.message);
}

#[test]
fn every_handler_type_has_a_label_and_nothing_else_is_a_type() {
    for k in [
        HandlerKind::Service,
        HandlerKind::CaTrust,
        HandlerKind::Command,
    ] {
        assert_eq!(HandlerKind::from_label(k.label()), Some(k));
    }
    assert_eq!(HandlerKind::from_label("shell"), None);
}

// ---------------------------------------------------------------------------
// output
// ---------------------------------------------------------------------------

#[test]
fn json_keeps_the_service_handler_keys_and_only_adds_type() {
    let res = conf("c", "/etc/a.conf", "1", &["foo_h"]);
    let r = recipe(
        "ht-json",
        &res,
        "  - id: foo_h\n    service: foo.service\n    action: restart\n",
    );
    let rep = run(&r, Mode::Apply);
    let v = json_of(&rep, Mode::Apply);
    let h = &v["handlers"][0];
    let mut keys: Vec<&str> = h.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    // The documented keys (id, service, action, state, reason) plus `type`.
    assert_eq!(
        keys,
        vec!["action", "id", "reason", "service", "state", "type"]
    );
    assert_eq!(h["id"], "foo_h");
    assert_eq!(h["service"], "foo.service");
    assert_eq!(h["action"], "restart");
    assert_eq!(h["state"], "Succeeded");
    assert!(h["reason"].is_null());
    assert_eq!(h["type"], "service");
    assert_eq!(v["handlers_pending"], serde_json::json!([]));

    // A plan keeps `handlers_pending` a plain array of IDs.
    let p = json_of(&run(&r, Mode::Plan), Mode::Plan);
    assert_eq!(p["handlers_pending"], serde_json::json!(["foo_h"]));
    assert_eq!(p["handlers"], serde_json::json!([]));
}

#[test]
fn a_sensitive_handler_stays_redacted() {
    let res = conf("c", "/etc/a.conf", "1", &["gone_h"]);
    let r = recipe(
        "ht-sensitive",
        &res,
        "  - id: gone_h\n    service: missing.service\n    action: restart\n    sensitive: true\n",
    );
    let rep = run(&r, Mode::Apply);
    assert_eq!(rep.handlers_run[0].state, HandlerOutcomeState::Failed);
    let v = json_of(&rep, Mode::Apply);
    let h = &v["handlers"][0];
    assert_eq!(h["service"], "<redacted>");
    assert_eq!(h["reason"], "<redacted>");
    assert_eq!(h["type"], "service");
    assert!(!text_of(&rep).contains("missing.service"));
    assert!(!serde_json::to_string(&v)
        .unwrap()
        .contains("missing.service"));
}

#[test]
fn a_handler_notified_by_a_sensitive_resource_is_redacted() {
    let res = "  - id: c\n    type: file\n    sensitive: true\n    with:\n      path: /etc/a.conf\n      content: \"s3cret-value\"\n    notify: [gone_h]\n";
    let r = recipe(
        "ht-sensitive-res",
        res,
        "  - id: gone_h\n    service: missing.service\n    action: restart\n",
    );
    let rep = run(&r, Mode::Apply);
    let v = json_of(&rep, Mode::Apply);
    assert_eq!(v["handlers"][0]["service"], "<redacted>");
    assert_eq!(v["handlers"][0]["reason"], "<redacted>");
    assert!(!text_of(&rep).contains("missing.service"));
}
