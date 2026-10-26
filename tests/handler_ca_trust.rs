//! The `ca_trust` handler (generic handler extension, H2).
//!
//! These tests run the production parser, engine, audit and renderer against
//! the scripted in-process target ([`FakeTarget`]), so they run on any
//! controller. They prove Sinter's own decisions: which fixed command is chosen
//! for which OS family, that nothing else is ever run, the privilege and
//! availability checks, notification semantics, and that plan and audit never
//! run the tool. What only a real Debian/Ubuntu or RHEL-family host can prove
//! (the tools' real behaviour, exit codes and output) is `PENDING REAL-LINUX
//! ACCEPTANCE` (H4) and is not claimed here.
mod common;

use common::*;
use serde_json::Value;
use sinter::engine::{AggregateStatus, Mode, RunReport};
use sinter::error::ErrorKind;
use sinter::executor::{Completion, FakeTarget, Output};
use sinter::ir::HandlerKind;
use sinter::output::{render_apply, OutputFormat, RenderOptions};
use sinter::result::HandlerOutcomeState;
use std::path::{Path, PathBuf};

const DEB_TOOL: &str = "/usr/sbin/update-ca-certificates";
const RPM_TOOL: &str = "/usr/bin/update-ca-trust";
const CANARY: &str = "CANARY-9f3a-secret";

fn ubuntu() -> FakeTarget {
    FakeTarget::ubuntu2404()
        .with_fake_fs()
        .with_executable(DEB_TOOL)
        .with_loaded_unit("foo.service", "A", ("loaded", "active", "enabled"))
}

fn rocky() -> FakeTarget {
    FakeTarget::rocky10()
        .with_fake_fs()
        .with_executable(RPM_TOOL)
}

fn file(id: &str, path: &str, content: &str, notify: &[&str], sensitive: bool) -> String {
    format!(
        "  - id: {id}\n    type: file\n{}    with:\n      path: {path}\n      content: \"{content}\"\n    notify: [{}]\n",
        if sensitive { "    sensitive: true\n" } else { "" },
        notify.join(", ")
    )
}

fn recipe(label: &str, resources: &str, handlers: &str) -> PathBuf {
    let dir = trusted_root(label);
    write_recipe(
        &dir,
        "r.yaml",
        &format!("version: 1\nresources:\n{resources}handlers:\n{handlers}"),
    )
}

const CA: &str = "  - id: refresh_ca\n    type: ca_trust\n";

fn one_ca_recipe(label: &str) -> PathBuf {
    recipe(
        label,
        &file("anchor", "/etc/anchor.crt", "PEM", &["refresh_ca"], false),
        CA,
    )
}

fn apply(r: &Path, t: FakeTarget) -> RunReport {
    run_recipe_fake(r, Mode::Apply, true, t)
}

/// Every command the target ran, as `program arg arg`.
fn lines(rep: &RunReport) -> Vec<String> {
    rep.commands
        .iter()
        .map(|c| {
            format!("{} {}", c.program, c.args.join(" "))
                .trim_end()
                .to_string()
        })
        .collect()
}

fn ran(rep: &RunReport, line: &str) -> usize {
    lines(rep).iter().filter(|l| l.as_str() == line).count()
}

fn tool_runs(rep: &RunReport) -> usize {
    rep.commands
        .iter()
        .filter(|c| c.program == DEB_TOOL || c.program == RPM_TOOL)
        .count()
}

fn exited(code: i32, stderr: &str) -> Output {
    Output {
        completion: Completion::Exited(code),
        stdout: Vec::new(),
        stderr: stderr.as_bytes().to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

fn render(rep: &RunReport, format: OutputFormat) -> Vec<u8> {
    let mut buf = Vec::new();
    render_apply(
        rep,
        &RenderOptions {
            verbose: false,
            format,
            color: false,
        },
        &mut buf,
    )
    .unwrap();
    buf
}

fn json(rep: &RunReport) -> Value {
    serde_json::from_slice(&render(rep, OutputFormat::Json)).unwrap()
}

fn text(rep: &RunReport) -> String {
    String::from_utf8(render(rep, OutputFormat::Text)).unwrap()
}

// ---------------------------------------------------------------------------
// command selection (fixed program and argv, by OS family)
// ---------------------------------------------------------------------------

#[test]
fn a_debian_family_target_runs_update_ca_certificates_without_fresh() {
    let rep = apply(&one_ca_recipe("ca-deb"), ubuntu());
    assert_eq!(
        rep.status,
        AggregateStatus::Success,
        "{:?}",
        rep.handlers_run
    );
    assert_eq!(ran(&rep, DEB_TOOL), 1, "{:?}", lines(&rep));
    assert_eq!(tool_runs(&rep), 1);
    // The store is not rebuilt: no argument at all, in particular no --fresh.
    assert!(!lines(&rep).iter().any(|l| l.contains("--fresh")));
    let h = &rep.handlers_run[0];
    assert_eq!(h.id, "refresh_ca");
    assert_eq!(h.kind, HandlerKind::CaTrust);
    assert_eq!(h.state, HandlerOutcomeState::Succeeded);
    assert_eq!(h.action, "refresh");
    assert!(h.service.is_empty(), "no service name is invented");
    assert!(h.reason.is_none());
}

#[test]
fn a_redhat_family_target_runs_update_ca_trust_extract() {
    let rep = apply(&one_ca_recipe("ca-rpm"), rocky());
    assert_eq!(
        rep.status,
        AggregateStatus::Success,
        "{:?}",
        rep.handlers_run
    );
    assert_eq!(
        ran(&rep, "/usr/bin/update-ca-trust extract"),
        1,
        "{:?}",
        lines(&rep)
    );
    assert_eq!(tool_runs(&rep), 1);
    assert_eq!(rep.handlers_run[0].state, HandlerOutcomeState::Succeeded);
}

#[test]
fn the_tool_is_run_directly_with_no_shell_and_no_other_family_command() {
    for (t, own, other) in [
        (ubuntu(), DEB_TOOL, RPM_TOOL),
        (rocky(), RPM_TOOL, DEB_TOOL),
    ] {
        let rep = apply(&one_ca_recipe("ca-noshell"), t);
        let mut direct = 0;
        for c in &rep.commands {
            // The file resource has its own fixed staging script; the point is
            // that the tool is never handed to a shell or wrapped, and the
            // other family's tool never appears anywhere.
            let line = format!("{} {}", c.program, c.args.join(" "));
            assert_ne!(c.program, other, "the other family's tool was run");
            assert!(!line.contains(other), "the other tool is named: {line}");
            if c.program == own {
                direct += 1;
            } else if c.program == "/usr/bin/test" {
                // The availability check only asks whether the tool is
                // executable (other `test` calls are the connect probes).
                if line.contains("update-ca-") {
                    assert_eq!(c.args, vec!["-x".to_string(), own.to_string()]);
                }
            } else {
                assert!(
                    !line.contains("update-ca-"),
                    "the tool reached another command: {line}"
                );
            }
        }
        assert_eq!(direct, 1);
    }
}

#[test]
fn the_family_comes_from_the_detected_os_not_from_which_tool_exists() {
    // A Debian-family target that also happens to have update-ca-trust: the
    // detected family still decides.
    let t = ubuntu().with_executable(RPM_TOOL);
    let rep = apply(&one_ca_recipe("ca-family"), t);
    assert_eq!(ran(&rep, DEB_TOOL), 1);
    assert_eq!(ran(&rep, "/usr/bin/update-ca-trust extract"), 0);
}

// ---------------------------------------------------------------------------
// fail-closed
// ---------------------------------------------------------------------------

#[test]
fn an_unsupported_os_is_refused_before_anything_runs() {
    let mut t = ubuntu();
    t.os_release = "ID=arch\nNAME=\"Arch Linux\"\nVERSION_ID=rolling\n".to_string();
    let e = try_run_recipe_fake(&one_ca_recipe("ca-unsupported"), Mode::Apply, true, t)
        .err()
        .expect("must be refused");
    assert_eq!(e.kind, ErrorKind::Connect);
    assert!(
        e.message.contains("no supported CA trust store tool"),
        "{}",
        e.message
    );
    // The same recipe is fine when nothing notifies the handler: the handler
    // is never going to run there.
    let unused = recipe(
        "ca-unsupported-unused",
        &file("anchor", "/etc/anchor.crt", "PEM", &[], false),
        CA,
    );
    let mut t = ubuntu();
    t.os_release = "ID=arch\nNAME=\"Arch Linux\"\nVERSION_ID=rolling\n".to_string();
    let rep = apply(&unused, t);
    assert_eq!(rep.status, AggregateStatus::Success);
    assert!(rep.handlers_run.is_empty());
}

#[test]
fn a_missing_tool_fails_the_handler_without_running_anything_else() {
    let t = FakeTarget::ubuntu2404().with_fake_fs(); // no update-ca-certificates
    let rep = apply(&one_ca_recipe("ca-missing"), t);
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    let h = &rep.handlers_run[0];
    assert_eq!(h.state, HandlerOutcomeState::Failed);
    assert!(
        h.reason.as_deref().unwrap().contains("not installed"),
        "{:?}",
        h.reason
    );
    assert_eq!(tool_runs(&rep), 0, "the tool must not be run when absent");
}

#[test]
fn without_root_the_handler_fails_and_nothing_is_escalated() {
    // Not root and no --sudo: the resource writes to the user's own home
    // directory, the handler then refuses (it needs root) and runs no tool.
    let home = FakeTarget::ubuntu2404().home.clone();
    let r = recipe(
        "ca-noroot",
        &file(
            "anchor",
            &format!("{home}/anchor.crt"),
            "PEM",
            &["refresh_ca"],
            false,
        ),
        CA,
    );
    let mut t = FakeTarget::ubuntu2404()
        .with_fake_fs()
        .with_executable(DEB_TOOL);
    let fs = t.fs.get_or_insert_with(Default::default);
    fs.mkdir_node("/home", 0o755, 0, 0);
    fs.mkdir_node(&home, 0o755, 1000, 1000);
    let rep = run_recipe_fake(&r, Mode::Apply, false, t);
    assert_eq!(
        rep.status,
        AggregateStatus::ApplyFailed,
        "{:?}",
        rep.handlers_run
    );
    let h = &rep.handlers_run[0];
    assert_eq!(h.state, HandlerOutcomeState::Failed);
    assert!(
        h.reason.as_deref().unwrap().contains("needs root"),
        "{:?}",
        h.reason
    );
    assert_eq!(tool_runs(&rep), 0);
    assert!(
        !rep.commands.iter().any(|c| c.sudo),
        "no command may have been sent through sudo without --sudo"
    );
}

#[test]
fn a_root_login_needs_no_sudo_flag() {
    let t = ubuntu().as_root();
    let rep = run_recipe_fake(&one_ca_recipe("ca-root"), Mode::Apply, false, t);
    assert_eq!(
        rep.status,
        AggregateStatus::Success,
        "{:?}",
        rep.handlers_run
    );
    assert_eq!(ran(&rep, DEB_TOOL), 1);
    assert!(!rep.commands.iter().any(|c| c.sudo));
}

#[test]
fn a_failing_tool_is_a_failed_handler_with_the_reason() {
    let mut t = ubuntu();
    t.program_outputs.insert(
        DEB_TOOL.to_string(),
        exited(2, "cannot write bundle\nmore\n"),
    );
    let rep = apply(&one_ca_recipe("ca-fail"), t);
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    let h = &rep.handlers_run[0];
    assert_eq!(h.state, HandlerOutcomeState::Failed);
    let why = h.reason.as_deref().unwrap();
    assert!(why.contains("exited with status 2"), "{why}");
    assert!(why.contains("cannot write bundle"), "{why}");
    assert!(!why.contains("more"), "only the first line: {why}");
}

#[test]
fn an_unconfirmed_completion_is_indeterminate_and_not_retried() {
    let mut t = ubuntu();
    t.program_outputs.insert(
        DEB_TOOL.to_string(),
        Output {
            completion: Completion::Indeterminate {
                started: true,
                reason: "timeout".to_string(),
            },
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        },
    );
    let rep = apply(&one_ca_recipe("ca-indet"), t);
    assert_eq!(rep.status, AggregateStatus::Indeterminate);
    assert_eq!(
        rep.handlers_run[0].state,
        HandlerOutcomeState::Indeterminate
    );
    assert_eq!(tool_runs(&rep), 1, "never retried");
}

// ---------------------------------------------------------------------------
// notification semantics
// ---------------------------------------------------------------------------

#[test]
fn no_notification_means_no_run_and_several_are_one_run() {
    // No resource notifies: the tool is not run.
    let none = recipe(
        "ca-none",
        &file("anchor", "/etc/anchor.crt", "PEM", &[], false),
        CA,
    );
    assert_eq!(tool_runs(&apply(&none, ubuntu())), 0);
    // Two changed resources notify the same handler: one run.
    let two = recipe(
        "ca-two",
        &[
            file("a", "/etc/a.crt", "1", &["refresh_ca"], false),
            file("b", "/etc/b.crt", "2", &["refresh_ca"], false),
        ]
        .concat(),
        CA,
    );
    let rep = apply(&two, ubuntu());
    assert_eq!(tool_runs(&rep), 1);
    assert_eq!(rep.handlers_run.len(), 1);
}

#[test]
fn an_unchanged_resource_does_not_notify() {
    // The file is already exactly as declared: no change, no notification.
    let mut t = ubuntu();
    t.fs.get_or_insert_with(Default::default)
        .put_file("/etc/anchor.crt", b"PEM", 0o644, 0, 0);
    let r = recipe(
        "ca-unchanged",
        "  - id: anchor\n    type: file\n    with:\n      path: /etc/anchor.crt\n      content: \"PEM\"\n      mode: \"0644\"\n      owner: root\n      group: root\n    notify: [refresh_ca]\n",
        CA,
    );
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
    assert_eq!(tool_runs(&rep), 0);
    assert!(rep.handlers_run.is_empty());
}

#[test]
fn handlers_run_in_declaration_order_and_a_failure_stops_the_rest() {
    let both = |label: &str, handlers: &str| {
        recipe(
            label,
            &file(
                "anchor",
                "/etc/anchor.crt",
                "PEM",
                &["refresh_ca", "restart_foo"],
                false,
            ),
            handlers,
        )
    };
    let svc = "  - id: restart_foo\n    service: foo.service\n    action: restart\n";
    // ca_trust declared first: it runs first.
    let r = both("ca-order", &format!("{CA}{svc}"));
    let rep = apply(&r, ubuntu());
    assert_eq!(
        rep.status,
        AggregateStatus::Success,
        "{:?}",
        rep.handlers_run
    );
    let ids: Vec<&str> = rep.handlers_run.iter().map(|h| h.id.as_str()).collect();
    assert_eq!(ids, vec!["refresh_ca", "restart_foo"]);
    let at = |needle: &str| lines(&rep).iter().position(|l| l.contains(needle)).unwrap();
    assert!(at(DEB_TOOL) < at("restart"), "{:?}", lines(&rep));

    // The tool fails: the service handler after it does not run and is pending.
    let mut t = ubuntu();
    t.program_outputs
        .insert(DEB_TOOL.to_string(), exited(1, "boom\n"));
    let rep = apply(&both("ca-failfast", &format!("{CA}{svc}")), t);
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    assert_eq!(rep.handlers_run.len(), 1);
    assert_eq!(rep.handlers_pending, vec!["restart_foo".to_string()]);
    assert!(!lines(&rep)
        .iter()
        .any(|l| l.contains("restart") && l.contains("foo.service")));
}

#[test]
fn a_service_handler_next_to_ca_trust_is_unchanged() {
    let svc = "  - id: restart_foo\n    service: foo.service\n    action: restart\n";
    let r = recipe(
        "ca-compat",
        &file("anchor", "/etc/anchor.crt", "PEM", &["restart_foo"], false),
        &format!("{CA}{svc}"),
    );
    let rep = apply(&r, ubuntu());
    assert_eq!(rep.status, AggregateStatus::Success);
    assert_eq!(
        rep.handlers_run.len(),
        1,
        "the unnotified ca_trust handler is not run"
    );
    assert_eq!(rep.handlers_run[0].kind, HandlerKind::Service);
    assert_eq!(rep.handlers_run[0].service, "foo.service");
    assert_eq!(tool_runs(&rep), 0);
}

// ---------------------------------------------------------------------------
// plan and audit never run the tool
// ---------------------------------------------------------------------------

#[test]
fn plan_and_audit_never_run_the_tool() {
    let r = one_ca_recipe("ca-plan");
    let plan = run_recipe_fake(&r, Mode::Plan, true, ubuntu());
    assert_eq!(tool_runs(&plan), 0);
    assert!(plan.handlers_run.is_empty());
    assert_eq!(plan.handlers_pending, vec!["refresh_ca".to_string()]);

    let model = sinter::model::load_model(&r).unwrap();
    let engine = sinter::engine::Engine::new(
        model,
        sinter::engine::RunOptions {
            mode: Mode::Plan,
            sudo: true,
            target: sinter::engine::TargetSpec { ssh: None },
            verbose: false,
            fault: None,
            fake_target: Some(ubuntu()),
        },
    )
    .unwrap();
    let audit = sinter::audit::run_audit(engine).unwrap();
    assert!(
        !audit.commands.iter().any(|c| c.program == DEB_TOOL),
        "audit ran the tool"
    );
}

// ---------------------------------------------------------------------------
// output and secrets
// ---------------------------------------------------------------------------

#[test]
fn json_names_the_type_and_invents_no_service() {
    let rep = apply(&one_ca_recipe("ca-json"), ubuntu());
    let v = json(&rep);
    let h = &v["handlers"][0];
    let mut keys: Vec<&str> = h.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    // The same keys as a service handler: nothing but `type`'s value differs.
    assert_eq!(
        keys,
        vec!["action", "id", "reason", "service", "state", "type"]
    );
    assert_eq!(h["id"], "refresh_ca");
    assert_eq!(h["type"], "ca_trust");
    assert_eq!(h["action"], "refresh");
    assert_eq!(h["service"], "", "no service name is invented");
    assert_eq!(h["state"], "Succeeded");
    assert!(h["reason"].is_null());
    assert!(
        text(&rep).contains("refresh_ca -> refresh ca_trust"),
        "{}",
        text(&rep)
    );
}

#[test]
fn a_sensitive_handler_never_shows_the_tools_output() {
    // The handler is sensitive: its failure reason is withheld everywhere, and
    // the tool's standard error (which carries a canary) is not even copied
    // into the reason.
    let r = recipe(
        "ca-secret",
        &file("anchor", "/etc/anchor.crt", "PEM", &["refresh_ca"], false),
        "  - id: refresh_ca\n    type: ca_trust\n    sensitive: true\n",
    );
    let mut t = ubuntu();
    t.program_outputs
        .insert(DEB_TOOL.to_string(), exited(1, &format!("{CANARY}\n")));
    let rep = apply(&r, t);
    assert_eq!(rep.handlers_run[0].state, HandlerOutcomeState::Failed);
    assert!(
        !rep.handlers_run[0]
            .reason
            .as_deref()
            .unwrap()
            .contains(CANARY),
        "the reason itself must not carry the output"
    );
    let v = json(&rep);
    assert_eq!(v["handlers"][0]["reason"], "<redacted>");
    assert!(!serde_json::to_string(&v).unwrap().contains(CANARY));
    assert!(!text(&rep).contains(CANARY));
    for c in &rep.commands {
        assert!(!format!("{c:?}").contains(CANARY));
    }
}

#[test]
fn a_handler_notified_by_a_sensitive_resource_is_sensitive() {
    let r = recipe(
        "ca-secret-res",
        &file("anchor", "/etc/anchor.crt", "PEM", &["refresh_ca"], true),
        CA,
    );
    let mut t = ubuntu();
    t.program_outputs
        .insert(DEB_TOOL.to_string(), exited(1, &format!("{CANARY}\n")));
    let rep = apply(&r, t);
    assert!(rep.handlers_run[0].sensitive);
    assert!(!serde_json::to_string(&json(&rep)).unwrap().contains(CANARY));
    assert!(!text(&rep).contains(CANARY));
}

// ---------------------------------------------------------------------------
// recipe validation
// ---------------------------------------------------------------------------

#[test]
fn a_ca_trust_handler_takes_only_id_type_and_sensitive() {
    let accepted = recipe(
        "ca-parse-ok",
        &file("anchor", "/etc/anchor.crt", "PEM", &["h"], false),
        "  - id: h\n    type: ca_trust\n    sensitive: false\n",
    );
    assert!(try_run_recipe_fake(&accepted, Mode::Plan, true, ubuntu()).is_ok());
    for (what, extra) in [
        ("service", "    service: foo.service\n"),
        ("action", "    action: restart\n"),
        ("with", "    with: {}\n"),
        ("privilege", "    privilege: root\n"),
        ("when", "    when: \"true\"\n"),
        ("args", "    args: [x]\n"),
    ] {
        let r = recipe(
            "ca-parse-bad",
            &file("anchor", "/etc/anchor.crt", "PEM", &["h"], false),
            &format!("  - id: h\n    type: ca_trust\n{extra}"),
        );
        let e = try_run_recipe_fake(&r, Mode::Plan, true, ubuntu())
            .err()
            .expect(what);
        assert_eq!(e.kind, ErrorKind::Schema, "{what}: {}", e.message);
    }
}
