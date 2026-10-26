//! The `command` handler (generic handler extension, H3).
//!
//! These tests run the production parser, engine, audit and renderer against
//! the scripted in-process target ([`FakeTarget`]), so they run on any
//! controller. They prove Sinter's own decisions: what is accepted at
//! validation, what is run (the program and its arguments exactly, directly,
//! never through a shell), when, how often and in which order, how failures
//! are classified, that plan and audit never run it, and that a sensitive
//! handler leaks nothing. What only a real host can prove (a real program's
//! behaviour and exit codes, `sudo` itself) is `PENDING REAL-LINUX ACCEPTANCE`
//! (H4) and is not claimed here.
mod common;

use common::*;
use serde_json::Value;
use sinter::engine::{AggregateStatus, Mode, RunReport};
use sinter::error::{ErrorKind, SinterError};
use sinter::executor::{Completion, FakeTarget, Output};
use sinter::ir::HandlerKind;
use sinter::output::{render_apply, OutputFormat, RenderOptions};
use sinter::result::HandlerOutcomeState;
use std::path::{Path, PathBuf};

const PROG: &str = "/usr/local/bin/myapp";
const OTHER: &str = "/usr/local/bin/other";
const CANARY: &str = "CANARY-5c1e-secret";

fn target() -> FakeTarget {
    FakeTarget::ubuntu2404()
        .with_fake_fs()
        .with_executable(PROG)
        .with_executable(OTHER)
        .with_loaded_unit("foo.service", "A", ("loaded", "active", "enabled"))
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

/// A command handler `h` with the given `with` lines (already indented).
fn handler(with: &str) -> String {
    format!("  - id: h\n    type: command\n    with:\n{with}")
}

fn notified(label: &str, handlers: &str) -> PathBuf {
    recipe(
        label,
        &file("conf", "/etc/app.conf", "v1", &["h"], false),
        handlers,
    )
}

fn apply(r: &Path, t: FakeTarget) -> RunReport {
    run_recipe_fake(r, Mode::Apply, true, t)
}

fn refused(label: &str, handlers: &str) -> SinterError {
    try_run_recipe_fake(&notified(label, handlers), Mode::Plan, true, target())
        .err()
        .expect("the recipe must be refused")
}

fn runs_of(rep: &RunReport, program: &str) -> Vec<Vec<String>> {
    rep.commands
        .iter()
        .filter(|c| c.program == program)
        .map(|c| c.args.clone())
        .collect()
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
// validation
// ---------------------------------------------------------------------------

#[test]
fn a_command_handler_is_parsed_with_its_defaults() {
    let r = notified(
        "hc-parse",
        &handler(&format!(
            "      program: {PROG}\n      args: [cache, rebuild]\n"
        )),
    );
    let m = sinter::model::load_model(&r).unwrap();
    let h = &m.handlers[0];
    assert_eq!(h.kind, HandlerKind::Command);
    assert!(!h.sensitive);
    let c = h.command.as_ref().unwrap();
    assert_eq!(c.program, PROG);
    assert_eq!(c.args, vec!["cache".to_string(), "rebuild".to_string()]);
    assert_eq!(c.timeout_secs, 300, "default timeout");
    // No args at all is fine, and an explicit timeout is kept.
    let r = notified(
        "hc-parse2",
        &handler(&format!(
            "      program: {PROG}\n      timeout_seconds: 3600\n"
        )),
    );
    let m = sinter::model::load_model(&r).unwrap();
    let c = m.handlers[0].command.as_ref().unwrap();
    assert!(c.args.is_empty());
    assert_eq!(c.timeout_secs, 3600, "the ceiling is accepted");
}

#[test]
fn the_program_must_be_an_absolute_path() {
    for (what, program) in [
        ("relative", "myapp"),
        ("relative with directory", "bin/myapp"),
        ("empty", "\"\""),
        ("root", "/"),
        ("trailing slash", "/usr/local/bin/"),
        ("dot component", "/usr/local/./bin/myapp"),
        ("dotdot component", "/usr/local/../bin/myapp"),
        ("repeated separator", "/usr//bin/myapp"),
        ("expression", "\"/usr/{{ vars.x }}/myapp\""),
        ("NUL", "\"/usr/bin/my\\0app\""),
    ] {
        let e = refused("hc-prog", &handler(&format!("      program: {program}\n")));
        assert_eq!(e.kind, ErrorKind::Schema, "{what}: {}", e.message);
    }
    for (what, with) in [
        ("missing", "      args: [x]\n"),
        ("not a string", "      program: 5\n"),
        ("a list", "      program: [/usr/bin/true]\n"),
    ] {
        let e = refused("hc-prog2", &handler(with));
        assert_eq!(e.kind, ErrorKind::Schema, "{what}: {}", e.message);
    }
}

#[test]
fn args_are_limited_to_64_entries_of_4096_bytes() {
    let list = |n: usize| format!("[{}]", vec!["a"; n].join(", "));
    // 64 entries are fine, 65 are refused.
    let ok = notified(
        "hc-args-ok",
        &handler(&format!(
            "      program: {PROG}\n      args: {}\n",
            list(64)
        )),
    );
    assert!(try_run_recipe_fake(&ok, Mode::Plan, true, target()).is_ok());
    let e = refused(
        "hc-args-65",
        &handler(&format!(
            "      program: {PROG}\n      args: {}\n",
            list(65)
        )),
    );
    assert!(e.message.contains("at most 64"), "{}", e.message);
    // One argument of 4096 bytes is fine, 4097 is refused.
    let arg = |n: usize| format!("\"{}\"", "x".repeat(n));
    let ok = notified(
        "hc-arg-ok",
        &handler(&format!(
            "      program: {PROG}\n      args: [{}]\n",
            arg(4096)
        )),
    );
    assert!(try_run_recipe_fake(&ok, Mode::Plan, true, target()).is_ok());
    let e = refused(
        "hc-arg-4097",
        &handler(&format!(
            "      program: {PROG}\n      args: [{}]\n",
            arg(4097)
        )),
    );
    assert!(e.message.contains("at most 4096"), "{}", e.message);
    // Bytes, not characters: 2049 two-byte characters are 4098 bytes.
    let wide = format!("\"{}\"", "é".repeat(2049));
    let e = refused(
        "hc-arg-wide",
        &handler(&format!("      program: {PROG}\n      args: [{wide}]\n")),
    );
    assert!(e.message.contains("at most 4096"), "{}", e.message);
    for (what, args) in [
        ("not a list", "args: cache"),
        ("a map", "args: { a: b }"),
        ("a number inside", "args: [cache, 5]"),
        ("null", "args: null"),
        ("NUL", "args: [\"a\\0b\"]"),
        ("expression", "args: [\"{{ vars.x }}\"]"),
    ] {
        let e = refused(
            "hc-args-bad",
            &handler(&format!("      program: {PROG}\n      {args}\n")),
        );
        assert_eq!(e.kind, ErrorKind::Schema, "{what}: {}", e.message);
    }
}

#[test]
fn the_timeout_has_a_floor_and_a_ceiling() {
    for t in ["0", "-1", "3601", "86400", "\"300\"", "1.5", "true", "null"] {
        let e = refused(
            "hc-timeout",
            &handler(&format!(
                "      program: {PROG}\n      timeout_seconds: {t}\n"
            )),
        );
        assert_eq!(e.kind, ErrorKind::Schema, "{t}: {}", e.message);
        assert!(e.message.contains("timeout_seconds"), "{t}: {}", e.message);
    }
    for t in ["1", "300", "3600"] {
        let r = notified(
            "hc-timeout-ok",
            &handler(&format!(
                "      program: {PROG}\n      timeout_seconds: {t}\n"
            )),
        );
        assert!(
            try_run_recipe_fake(&r, Mode::Plan, true, target()).is_ok(),
            "{t}"
        );
    }
}

#[test]
fn fields_that_do_not_belong_to_a_command_handler_are_refused() {
    let base = format!("      program: {PROG}\n");
    for (what, handlers) in [
        ("cwd in with", handler(&format!("{base}      cwd: /tmp\n"))),
        ("env in with", handler(&format!("{base}      env: {{ A: b }}\n"))),
        ("success_codes in with", handler(&format!("{base}      success_codes: [0]\n"))),
        ("unknown in with", handler(&format!("{base}      shell: true\n"))),
        ("flat program", format!("  - id: h\n    type: command\n    program: {PROG}\n")),
        ("flat timeout", format!("  - id: h\n    type: command\n    timeout: 5\n    with:\n      program: {PROG}\n")),
        ("service", format!("  - id: h\n    type: command\n    service: foo.service\n    with:\n      program: {PROG}\n")),
        ("action", format!("  - id: h\n    type: command\n    action: restart\n    with:\n      program: {PROG}\n")),
        ("privilege", format!("  - id: h\n    type: command\n    privilege: root\n    with:\n      program: {PROG}\n")),
        ("when", format!("  - id: h\n    type: command\n    when: \"true\"\n    with:\n      program: {PROG}\n")),
        ("no with", "  - id: h\n    type: command\n".to_string()),
        ("with not a map", "  - id: h\n    type: command\n    with: [a]\n".to_string()),
        ("sensitive not boolean", format!("  - id: h\n    type: command\n    sensitive: maybe\n    with:\n      program: {PROG}\n")),
    ] {
        let e = refused("hc-fields", &handlers);
        assert_eq!(e.kind, ErrorKind::Schema, "{what}: {}", e.message);
    }
    // The other types do not take a with block.
    for (what, h) in [
        (
            "service",
            "  - id: h\n    service: foo.service\n    action: restart\n    with: { program: /x }\n",
        ),
        (
            "ca_trust",
            "  - id: h\n    type: ca_trust\n    with: { program: /x }\n",
        ),
    ] {
        let e = refused("hc-with-elsewhere", h);
        assert_eq!(e.kind, ErrorKind::Schema, "{what}: {}", e.message);
    }
}

#[test]
fn a_sensitive_handler_does_not_echo_its_program_in_an_error() {
    let e = refused(
        "hc-secret-err",
        &format!(
            "  - id: h\n    type: command\n    sensitive: true\n    with:\n      program: relative/{CANARY}\n"
        ),
    );
    assert_eq!(e.kind, ErrorKind::Schema);
    assert!(!e.message.contains(CANARY), "{}", e.message);
}

#[test]
fn the_command_resource_keeps_its_own_larger_limits() {
    // A command RESOURCE may still have 100 arguments, a 5000-byte argument and
    // a day-long timeout: the handler's limits are the handler's alone.
    let args = format!("[{}]", vec!["a"; 100].join(", "));
    let long = "x".repeat(5000);
    let dir = trusted_root("hc-resource");
    let r = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: c\n    type: command\n    with:\n      program: {PROG}\n      args: {args}\n      timeout_seconds: 86400\n  - id: d\n    type: command\n    with:\n      program: {PROG}\n      args: [\"{long}\"]\n"
        ),
    );
    sinter::model::load_model(&r).expect("existing command resources are unchanged");
}

// ---------------------------------------------------------------------------
// what runs, when
// ---------------------------------------------------------------------------

#[test]
fn the_program_runs_directly_with_exactly_the_given_arguments() {
    // Arguments full of shell syntax are passed verbatim as single arguments.
    let r = notified(
        "hc-run",
        &handler(&format!(
            "      program: {PROG}\n      args: [cache, \"; rm -rf /\", \"$(id)\", \"a b\", \"--x=*\"]\n"
        )),
    );
    let rep = apply(&r, target());
    assert_eq!(
        rep.status,
        AggregateStatus::Success,
        "{:?}",
        rep.handlers_run
    );
    let runs = runs_of(&rep, PROG);
    assert_eq!(runs.len(), 1);
    assert_eq!(
        runs[0],
        vec!["cache", "; rm -rf /", "$(id)", "a b", "--x=*"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>()
    );
    // The command's own environment is the baseline and nothing more.
    let c = rep.commands.iter().find(|c| c.program == PROG).unwrap();
    let mut keys: Vec<&str> = c.env.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, vec!["HOME", "LANG", "LC_ALL", "PATH"], "{:?}", c.env);
    // It was never handed to a shell, and nothing but the availability check
    // mentions it.
    for c in &rep.commands {
        if c.program == PROG {
            continue;
        }
        let line = format!("{} {}", c.program, c.args.join(" "));
        if line.contains(PROG) {
            assert_eq!(c.program, "/usr/bin/test", "{line}");
            assert_eq!(c.args, vec!["-x".to_string(), PROG.to_string()]);
        }
    }
    let h = &rep.handlers_run[0];
    assert_eq!(h.kind, HandlerKind::Command);
    assert_eq!(h.state, HandlerOutcomeState::Succeeded);
    assert_eq!(h.action, "run");
    assert!(h.service.is_empty(), "no service name is invented");
    assert!(h.reason.is_none());
}

#[test]
fn no_notification_or_an_unchanged_notifier_means_no_run_and_several_mean_one() {
    let h = handler(&format!("      program: {PROG}\n"));
    // Nothing notifies the handler.
    let none = recipe(
        "hc-none",
        &file("conf", "/etc/app.conf", "v1", &[], false),
        &h,
    );
    assert!(runs_of(&apply(&none, target()), PROG).is_empty());
    // The notifying file is already exactly as declared: no change, no notice.
    let mut t = target();
    t.fs.get_or_insert_with(Default::default)
        .put_file("/etc/app.conf", b"v1", 0o644, 0, 0);
    let same = recipe(
        "hc-unchanged",
        "  - id: conf\n    type: file\n    with:\n      path: /etc/app.conf\n      content: \"v1\"\n      mode: \"0644\"\n      owner: root\n      group: root\n    notify: [h]\n",
        &h,
    );
    let rep = apply(&same, t);
    assert!(runs_of(&rep, PROG).is_empty());
    assert!(rep.handlers_run.is_empty());
    // Two changed resources notify it: one run.
    let two = recipe(
        "hc-two",
        &[
            file("a", "/etc/a.conf", "1", &["h"], false),
            file("b", "/etc/b.conf", "2", &["h"], false),
        ]
        .concat(),
        &h,
    );
    let rep = apply(&two, target());
    assert_eq!(runs_of(&rep, PROG).len(), 1);
    assert_eq!(rep.handlers_run.len(), 1);
}

#[test]
fn handlers_run_in_declaration_order_across_types() {
    let res = file(
        "conf",
        "/etc/a.conf",
        "1",
        &["svc", "ca", "cmd2", "cmd1"],
        false,
    );
    let handlers = format!(
        "  - id: cmd1\n    type: command\n    with:\n      program: {PROG}\n      args: [first]\n  - id: svc\n    service: foo.service\n    action: restart\n  - id: ca\n    type: ca_trust\n  - id: cmd2\n    type: command\n    with:\n      program: {OTHER}\n"
    );
    let t = target().with_executable("/usr/sbin/update-ca-certificates");
    let rep = apply(&recipe("hc-order", &res, &handlers), t);
    assert_eq!(
        rep.status,
        AggregateStatus::Success,
        "{:?}",
        rep.handlers_run
    );
    let ids: Vec<&str> = rep.handlers_run.iter().map(|h| h.id.as_str()).collect();
    assert_eq!(ids, vec!["cmd1", "svc", "ca", "cmd2"]);
    let kinds: Vec<HandlerKind> = rep.handlers_run.iter().map(|h| h.kind).collect();
    assert_eq!(
        kinds,
        vec![
            HandlerKind::Command,
            HandlerKind::Service,
            HandlerKind::CaTrust,
            HandlerKind::Command
        ]
    );
    let at = |needle: &str| {
        rep.commands
            .iter()
            .position(|c| c.program == needle || c.args.iter().any(|a| a == needle))
            .unwrap()
    };
    assert!(at(PROG) < at("restart") && at("restart") < at("/usr/sbin/update-ca-certificates"));
    assert!(at("/usr/sbin/update-ca-certificates") < at(OTHER));
}

// ---------------------------------------------------------------------------
// failure
// ---------------------------------------------------------------------------

#[test]
fn a_failing_program_fails_the_handler_and_stops_the_phase() {
    let res = file("conf", "/etc/a.conf", "1", &["h", "later", "svc"], false);
    let handlers = format!(
        "  - id: h\n    type: command\n    with:\n      program: {PROG}\n  - id: later\n    type: command\n    with:\n      program: {OTHER}\n  - id: svc\n    service: foo.service\n    action: restart\n"
    );
    let mut t = target();
    t.program_outputs.insert(
        PROG.to_string(),
        exited(3, "cannot reach the cache\nmore\n"),
    );
    let rep = apply(&recipe("hc-fail", &res, &handlers), t);
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    assert_eq!(rep.handlers_run.len(), 1);
    let h = &rep.handlers_run[0];
    assert_eq!(h.state, HandlerOutcomeState::Failed);
    let why = h.reason.as_deref().unwrap();
    assert!(why.contains("exited with status 3"), "{why}");
    assert!(why.contains("cannot reach the cache"), "{why}");
    assert!(!why.contains("more"), "only the first line: {why}");
    // The rest did not run and is pending; the report does not call it done.
    assert_eq!(
        rep.handlers_pending,
        vec!["later".to_string(), "svc".to_string()]
    );
    assert!(runs_of(&rep, OTHER).is_empty());
    assert!(!rep
        .commands
        .iter()
        .any(|c| c.args.first().is_some_and(|a| a == "restart")));
}

#[test]
fn a_program_that_is_not_executable_fails_without_being_run() {
    let t = FakeTarget::ubuntu2404().with_fake_fs(); // PROG is not declared
    let r = notified("hc-absent", &handler(&format!("      program: {PROG}\n")));
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    assert_eq!(rep.handlers_run[0].state, HandlerOutcomeState::Failed);
    assert!(
        rep.handlers_run[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("not an executable file"),
        "{:?}",
        rep.handlers_run[0].reason
    );
    assert!(runs_of(&rep, PROG).is_empty());
}

#[test]
fn an_unconfirmed_completion_is_indeterminate_and_never_retried() {
    let mut t = target();
    t.program_outputs.insert(
        PROG.to_string(),
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
    let r = notified("hc-indet", &handler(&format!("      program: {PROG}\n")));
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::Indeterminate);
    assert_eq!(
        rep.handlers_run[0].state,
        HandlerOutcomeState::Indeterminate
    );
    assert_eq!(runs_of(&rep, PROG).len(), 1, "never retried");
}

#[test]
fn a_signal_is_a_failure() {
    let mut t = target();
    t.program_outputs.insert(
        PROG.to_string(),
        Output {
            completion: Completion::Signaled(9),
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        },
    );
    let rep = apply(
        &notified("hc-signal", &handler(&format!("      program: {PROG}\n"))),
        t,
    );
    assert_eq!(rep.handlers_run[0].state, HandlerOutcomeState::Failed);
    assert!(rep.handlers_run[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("signal 9"));
}

// ---------------------------------------------------------------------------
// privilege
// ---------------------------------------------------------------------------

#[test]
fn the_handler_runs_with_the_privilege_of_the_run_and_never_escalates() {
    // No --sudo, not root: the program is sent without sudo (the file resource
    // writes to the user's own directory, so the handler is reached).
    let home = FakeTarget::ubuntu2404().home.clone();
    let r = recipe(
        "hc-nosudo",
        &file("conf", &format!("{home}/a.conf"), "1", &["h"], false),
        &handler(&format!("      program: {PROG}\n")),
    );
    let mut t = FakeTarget::ubuntu2404()
        .with_fake_fs()
        .with_executable(PROG);
    let fs = t.fs.get_or_insert_with(Default::default);
    fs.mkdir_node("/home", 0o755, 0, 0);
    fs.mkdir_node(&home, 0o755, 1000, 1000);
    let rep = run_recipe_fake(&r, Mode::Apply, false, t);
    assert_eq!(
        rep.status,
        AggregateStatus::Success,
        "{:?}",
        rep.handlers_run
    );
    assert!(
        !rep.commands.iter().any(|c| c.sudo),
        "no sudo without --sudo"
    );
    // With --sudo, the same mechanism as every other change applies.
    let rep = apply(
        &notified("hc-sudo", &handler(&format!("      program: {PROG}\n"))),
        target(),
    );
    assert!(rep.commands.iter().any(|c| c.program == PROG && c.sudo));
}

// ---------------------------------------------------------------------------
// plan and audit
// ---------------------------------------------------------------------------

#[test]
fn plan_and_audit_never_run_the_program() {
    let r = notified("hc-plan", &handler(&format!("      program: {PROG}\n")));
    let plan = run_recipe_fake(&r, Mode::Plan, true, target());
    assert!(runs_of(&plan, PROG).is_empty());
    assert!(plan.handlers_run.is_empty());
    assert_eq!(plan.handlers_pending, vec!["h".to_string()]);

    let model = sinter::model::load_model(&r).unwrap();
    let engine = sinter::engine::Engine::new(
        model,
        sinter::engine::RunOptions {
            mode: Mode::Plan,
            sudo: true,
            target: sinter::engine::TargetSpec { ssh: None },
            verbose: false,
            fault: None,
            fake_target: Some(target()),
        },
    )
    .unwrap();
    let audit = sinter::audit::run_audit(engine).unwrap();
    assert!(
        !audit.commands.iter().any(|c| c.program == PROG),
        "audit ran it"
    );
}

// ---------------------------------------------------------------------------
// output and secrets
// ---------------------------------------------------------------------------

#[test]
fn json_names_the_type_and_invents_no_service() {
    let rep = apply(
        &notified("hc-json", &handler(&format!("      program: {PROG}\n"))),
        target(),
    );
    let v = json(&rep);
    let h = &v["handlers"][0];
    let mut keys: Vec<&str> = h.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec!["action", "id", "reason", "service", "state", "type"]
    );
    assert_eq!(h["type"], "command");
    assert_eq!(h["action"], "run");
    assert_eq!(h["service"], "");
    assert_eq!(h["state"], "Succeeded");
    assert!(h["reason"].is_null());
    assert!(text(&rep).contains("h -> run command"), "{}", text(&rep));
}

#[test]
fn the_report_never_shows_the_arguments() {
    // Even a handler that is not marked sensitive does not print its argument
    // list in the report: only the id, the type and the outcome.
    let r = notified(
        "hc-noargs",
        &handler(&format!("      program: {PROG}\n      args: [{CANARY}]\n")),
    );
    let rep = apply(&r, target());
    assert!(!text(&rep).contains(CANARY));
    assert!(!serde_json::to_string(&json(&rep)).unwrap().contains(CANARY));
    // A failure reason carries the program and the first stderr line, not args.
    let mut t = target();
    t.program_outputs
        .insert(PROG.to_string(), exited(2, "bad\n"));
    let rep = apply(&r, t);
    assert!(!rep.handlers_run[0]
        .reason
        .as_deref()
        .unwrap()
        .contains(CANARY));
    assert!(!text(&rep).contains(CANARY));
}

#[test]
fn a_sensitive_handler_leaks_nothing() {
    let handlers = format!(
        "  - id: h\n    type: command\n    sensitive: true\n    with:\n      program: {PROG}\n      args: [\"--token={CANARY}\"]\n"
    );
    let r = notified("hc-secret", &handlers);
    let mut t = target();
    t.program_outputs
        .insert(PROG.to_string(), exited(1, &format!("{CANARY} rejected\n")));
    let rep = apply(&r, t);
    let h = &rep.handlers_run[0];
    assert_eq!(h.state, HandlerOutcomeState::Failed);
    let why = h.reason.as_deref().unwrap();
    assert!(!why.contains(CANARY), "{why}");
    assert!(!why.contains(PROG), "the program is not named: {why}");
    let v = json(&rep);
    assert_eq!(v["handlers"][0]["reason"], "<redacted>");
    assert!(!serde_json::to_string(&v).unwrap().contains(CANARY));
    assert!(!text(&rep).contains(CANARY));
    // The recorded command line is the redacted placeholder, never the real one.
    for c in &rep.commands {
        assert!(!format!("{c:?}").contains(CANARY), "{c:?}");
    }
    assert!(rep.commands.iter().any(|c| c.sensitive));
}

#[test]
fn a_handler_notified_by_a_sensitive_resource_is_sensitive() {
    let r = recipe(
        "hc-secret-res",
        &file("conf", "/etc/a.conf", "s3cret", &["h"], true),
        &handler(&format!("      program: {PROG}\n      args: [{CANARY}]\n")),
    );
    let mut t = target();
    t.program_outputs
        .insert(PROG.to_string(), exited(1, &format!("{CANARY}\n")));
    let rep = apply(&r, t);
    assert!(rep.handlers_run[0].sensitive);
    assert!(!serde_json::to_string(&json(&rep)).unwrap().contains(CANARY));
    assert!(!text(&rep).contains(CANARY));
}

// ---------------------------------------------------------------------------
// the other handler types are unchanged
// ---------------------------------------------------------------------------

#[test]
fn service_and_ca_trust_handlers_next_to_a_command_handler_are_unchanged() {
    let res = file("conf", "/etc/a.conf", "1", &["svc", "ca"], false);
    let handlers = format!(
        "  - id: svc\n    service: foo.service\n    action: reload\n  - id: ca\n    type: ca_trust\n  - id: h\n    type: command\n    with:\n      program: {PROG}\n"
    );
    let t = target().with_executable("/usr/sbin/update-ca-certificates");
    let rep = apply(&recipe("hc-compat", &res, &handlers), t);
    assert_eq!(rep.status, AggregateStatus::Success);
    // `h` is not notified: only the two notified handlers run.
    let ids: Vec<&str> = rep.handlers_run.iter().map(|x| x.id.as_str()).collect();
    assert_eq!(ids, vec!["svc", "ca"]);
    assert_eq!(rep.handlers_run[0].service, "foo.service");
    assert_eq!(rep.handlers_run[0].action, "reload");
    assert_eq!(rep.handlers_run[1].action, "refresh");
    assert!(runs_of(&rep, PROG).is_empty());
}
