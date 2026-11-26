//! `dnf_module` against the scripted in-process target.
//!
//! These run the production loader, engine, audit and output code against
//! [`FakeTarget`], whose `dnf module enable|disable|reset` writes the state
//! file `/etc/dnf/modules.d/<name>.module` the way DNF 4 is documented to.
//! They prove Sinter's own decisions, argv and order. What only a real DNF
//! can show (the exact state file after each command, exit codes, the
//! behaviour on EL 10 without module streams) is NOT verified here.
#![cfg(unix)]

mod common;

use common::*;
use sinter::audit::{AuditReport, AuditResourceStatus};
use sinter::engine::{AggregateStatus, Mode, RunReport};
use sinter::executor::{Completion, FakeTarget, FsEventAction, Output};
use sinter::fake_el::FakeChange;
use sinter::output::{OutputFormat, RenderOptions};
use sinter::result::{Change, Execution, Verification};
use std::path::{Path, PathBuf};

const STATE: &str = "/etc/dnf/modules.d/nodejs.module";
const ENABLED_20: &str = "[nodejs]\nname=nodejs\nstream=20\nprofiles=\nstate=enabled\n";

fn module(body: &str) -> String {
    format!("version: 1\nresources:\n  - id: m\n    type: dnf_module\n    with:\n      name: nodejs\n{body}")
}

fn enable20() -> String {
    module("      stream: \"20\"\n      state: enabled\n")
}

fn recipe(label: &str, yaml: &str) -> PathBuf {
    let dir = trusted_root(label);
    write_recipe(&dir, "r.yaml", yaml)
}

/// A Rocky Linux 9 target as root, with the DNF module directory.
fn fake() -> FakeTarget {
    dnf_link(FakeTarget::rocky9().with_fake_fs().as_root(), "dnf-3")
        .with_fs_dir("/etc/dnf")
        .with_fs_dir("/etc/dnf/modules.d")
}

/// `/usr/bin/dnf` as a symbolic link to `target` (DNF 4: `dnf-3`).
fn dnf_link(t: FakeTarget, target: &str) -> FakeTarget {
    let mut t = t.with_fs_dir("/usr/bin");
    t.fs.as_mut()
        .unwrap()
        .put_symlink("/usr/bin/dnf", target, 0, 0);
    t
}

fn apply(r: &Path, t: FakeTarget) -> RunReport {
    run_recipe_fake(r, Mode::Apply, false, t)
}

fn plan(r: &Path, t: FakeTarget) -> RunReport {
    run_recipe_fake(r, Mode::Plan, false, t)
}

fn audit(r: &Path, t: FakeTarget) -> AuditReport {
    let model = sinter::model::load_model(r).unwrap();
    let opts = sinter::engine::RunOptions {
        mode: Mode::Plan,
        sudo: false,
        target: sinter::engine::TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(t),
    };
    let engine = sinter::engine::Engine::new(model, opts).unwrap();
    sinter::audit::run_audit(engine).unwrap()
}

fn load_err(label: &str, yaml: &str) -> String {
    let p = recipe(label, yaml);
    match sinter::model::load_model(&p) {
        Ok(_) => panic!("{label}: recipe was accepted"),
        Err(e) => {
            assert_eq!(e.kind, sinter::error::ErrorKind::Schema, "{label}");
            e.message
        }
    }
}

/// Every `dnf module ...` argv the run sent.
fn module_commands(rep: &RunReport) -> Vec<Vec<String>> {
    rep.commands
        .iter()
        .filter(|c| c.program == "/usr/bin/dnf" && c.args.iter().any(|a| a == "module"))
        .map(|c| c.args.clone())
        .collect()
}

fn state_file(rep: &RunReport) -> Option<String> {
    rep.fake_fs
        .as_ref()
        .unwrap()
        .file_bytes(STATE)
        .map(|b| String::from_utf8(b).unwrap())
}

fn reason(rep: &RunReport) -> String {
    find(rep, "m").reason.clone().unwrap_or_default()
}

/// A run that must not succeed: why, and the report when the run produced
/// one (a plan that stops on a resource returns its error instead).
fn refused(r: &Path, mode: Mode, t: FakeTarget) -> (String, Option<RunReport>) {
    let el = t.el();
    let out = match try_run_recipe_fake(r, mode, false, t) {
        Ok(rep) => {
            assert_ne!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
            assert_eq!(
                find(&rep, "m").change,
                Change::None,
                "{:?}",
                find(&rep, "m")
            );
            assert!(module_commands(&rep).is_empty(), "{:?}", rep.commands);
            (reason(&rep), Some(rep))
        }
        Err(e) => (e.message, None),
    };
    assert!(
        el.lock().unwrap().module_calls.is_empty(),
        "dnf module ran although the resource was refused"
    );
    out
}

fn forced(code: i32, stdout: &str, stderr: &str) -> Output {
    Output {
        completion: Completion::Exited(code),
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

fn surfaces(rep: &RunReport, mode: &str) -> Vec<String> {
    let mut v = Vec::new();
    for fmt in [OutputFormat::Text, OutputFormat::Json] {
        let ro = RenderOptions {
            verbose: true,
            format: fmt,
            color: false,
        };
        let mut b = Vec::new();
        if mode == "plan" {
            sinter::output::render_plan(rep, &ro, &mut b).unwrap();
        } else {
            sinter::output::render_apply(rep, &ro, &mut b).unwrap();
        }
        v.push(String::from_utf8_lossy(&b).to_string());
    }
    v.push(sinter::output::run_report_json(rep, mode).to_string());
    v.push(format!("{:?}", rep.resources));
    v
}

/// The same plus the raw command log (argv and environment as recorded).
fn surfaces_and_commands(rep: &RunReport, mode: &str) -> Vec<String> {
    let mut v = surfaces(rep, mode);
    v.push(format!("{:?}", rep.commands));
    v
}

// ---------------------------------------------------------------------------
// load time
// ---------------------------------------------------------------------------

#[test]
fn invalid_declarations_are_rejected_at_load() {
    for (label, body, want) in [
        (
            "dm-l-nostream",
            "      state: enabled\n",
            "stream is required",
        ),
        (
            "dm-l-stream-disabled",
            "      stream: \"20\"\n      state: disabled\n",
            "not allowed",
        ),
        (
            "dm-l-stream-reset",
            "      stream: \"20\"\n      state: reset\n",
            "not allowed",
        ),
        (
            "dm-l-nostate",
            "      stream: \"20\"\n",
            "state is required",
        ),
        (
            "dm-l-badstate",
            "      state: present\n",
            "enabled, disabled or reset",
        ),
        (
            "dm-l-intstream",
            "      stream: 20\n      state: enabled\n",
            "quote it",
        ),
        (
            "dm-l-badstream",
            "      stream: \"20/common\"\n      state: enabled\n",
            "valid stream name",
        ),
        (
            "dm-l-optstream",
            "      stream: \"--installroot=/x\"\n      state: enabled\n",
            "valid stream name",
        ),
        (
            "dm-l-profile",
            "      stream: \"20\"\n      state: enabled\n      profile: common\n",
            "unknown field with.profile",
        ),
        (
            "dm-l-profiles",
            "      state: reset\n      profiles: [common]\n",
            "unknown field with.profiles",
        ),
    ] {
        let msg = load_err(label, &module(body));
        assert!(msg.contains(want), "{label}: {msg}");
    }
    for (label, name) in [
        ("dm-l-name-colon", "\"nodejs:20\""),
        ("dm-l-name-opt", "\"-y\""),
        ("dm-l-name-slash", "\"../x\""),
        ("dm-l-name-space", "\"node js\""),
    ] {
        let yaml = format!(
            "version: 1\nresources:\n  - id: m\n    type: dnf_module\n    with:\n      name: {name}\n      state: reset\n"
        );
        let msg = load_err(label, &yaml);
        assert!(msg.contains("valid module name"), "{label}: {msg}");
    }
}

#[test]
fn static_variables_resolve_at_load_and_are_checked() {
    let ok = "version: 1\nvars:\n  stream:\n    value: \"20\"\nresources:\n  - id: m\n    type: dnf_module\n    with:\n      name: nodejs\n      stream: \"{{ vars.stream }}\"\n      state: enabled\n";
    let r = recipe("dm-l-var-ok", ok);
    assert!(sinter::model::load_model(&r).is_ok());
    let rep = apply(&r, fake());
    assert_eq!(
        module_commands(&rep),
        [["-y", "module", "enable", "nodejs:20"]]
    );

    let bad = "version: 1\nvars:\n  stream:\n    value: \"20 --nogpgcheck\"\nresources:\n  - id: m\n    type: dnf_module\n    with:\n      name: nodejs\n      stream: \"{{ vars.stream }}\"\n      state: enabled\n";
    let msg = load_err("dm-l-var-bad", bad);
    assert!(msg.contains("stream is not valid"), "{msg}");

    // Facts cannot form the module name or stream.
    let fact = module("      stream: \"{{ facts.os.version }}\"\n      state: enabled\n");
    let msg = load_err("dm-l-fact", &fact);
    assert!(msg.contains("stream"), "{msg}");

    let secret = "version: 1\nvars:\n  s:\n    value: \"20\"\n    sensitive: true\nresources:\n  - id: m\n    type: dnf_module\n    with:\n      name: nodejs\n      stream: \"{{ vars.s }}\"\n      state: enabled\n";
    let msg = load_err("dm-l-secret", secret);
    assert!(!msg.contains("\"20\""), "{msg}");
}

#[test]
fn two_resources_for_one_module_conflict_at_load() {
    let yaml = "version: 1\nresources:\n  - id: a\n    type: dnf_module\n    with: { name: nodejs, stream: \"20\", state: enabled }\n  - id: b\n    type: dnf_module\n    with: { name: nodejs, state: reset }\n";
    let msg = load_err("dm-l-conflict", yaml);
    assert!(
        msg.contains("conflicting ownership of DNF module nodejs") && msg.contains("a and b"),
        "{msg}"
    );
    // Different modules do not conflict.
    let ok = "version: 1\nresources:\n  - id: a\n    type: dnf_module\n    with: { name: nodejs, stream: \"20\", state: enabled }\n  - id: b\n    type: dnf_module\n    with: { name: postgresql, state: reset }\n";
    assert!(sinter::model::load_model(&recipe("dm-l-noconflict", ok)).is_ok());
}

// ---------------------------------------------------------------------------
// plan and apply
// ---------------------------------------------------------------------------

#[test]
fn plan_reports_the_change_and_does_not_mutate() {
    let r = recipe("dm-p-enable", &enable20());
    let t = fake();
    let el = t.el();
    let before = t.fs.clone().unwrap().nodes;
    let rep = plan(&r, t);
    assert_eq!(rep.status, AggregateStatus::Success);
    let m = find(&rep, "m");
    assert_eq!(m.change, Change::Changed, "{m:?}");
    assert_eq!(
        m.diff.as_ref().map(|d| d.body.clone()),
        Some(sinter::result::DiffBody::Summary {
            current: "state=default".into(),
            desired: "state=enabled stream=20".into()
        })
    );
    assert!(
        m.notes
            .iter()
            .any(|n| n.contains("nodejs:20") && n.contains("checked by dnf at apply")),
        "{:?}",
        m.notes
    );
    assert!(module_commands(&rep).is_empty(), "{:?}", rep.commands);
    assert!(el.lock().unwrap().module_calls.is_empty());
    assert_eq!(mutation_command_count(&rep), 0);
    assert_eq!(
        format!("{:?}", rep.fake_fs.as_ref().unwrap().nodes),
        format!("{:?}", before),
        "plan changed the filesystem"
    );
}

#[test]
fn apply_enables_the_stream_and_verifies_the_state_file() {
    let r = recipe("dm-a-enable", &enable20());
    let rep = apply(&r, fake());
    assert_success(&rep);
    let m = find(&rep, "m");
    assert_eq!(
        (m.execution, m.change, m.verification),
        (
            Execution::Succeeded,
            Change::Changed,
            Verification::Verified
        ),
        "{m:?}"
    );
    assert_eq!(
        module_commands(&rep),
        [["-y", "module", "enable", "nodejs:20"]]
    );
    assert_eq!(state_file(&rep).as_deref(), Some(ENABLED_20));
    // The state file was read again after dnf returned.
    let cats: Vec<usize> = rep
        .commands
        .iter()
        .enumerate()
        .filter(|(_, c)| c.program.ends_with("cat") && c.args.iter().any(|a| a == STATE))
        .map(|(i, _)| i)
        .collect();
    let dnf = rep
        .commands
        .iter()
        .position(|c| c.args.iter().any(|a| a == "module"))
        .unwrap();
    assert!(cats.iter().any(|i| *i > dnf), "no re-observation: {cats:?}");
}

#[test]
fn a_second_apply_changes_nothing_and_runs_no_dnf() {
    let r = recipe("dm-a-idem", &enable20());
    let t = fake().with_module_state("nodejs", "20", "", "enabled");
    let el = t.el();
    let before = t.fs.clone().unwrap().nodes;
    let rep = apply(&r, t);
    assert_success(&rep);
    let m = find(&rep, "m");
    assert_eq!(m.change, Change::None, "{m:?}");
    assert_eq!(m.verification, Verification::Verified);
    assert!(module_commands(&rep).is_empty());
    assert!(el.lock().unwrap().module_calls.is_empty());
    assert_eq!(
        format!("{:?}", rep.fake_fs.as_ref().unwrap().nodes),
        format!("{:?}", before),
        "the state file was rewritten"
    );
}

#[test]
fn disable_and_reset_change_the_state() {
    let disable = recipe("dm-a-disable", &module("      state: disabled\n"));
    let rep = apply(
        &disable,
        fake().with_module_state("nodejs", "20", "", "enabled"),
    );
    assert_success(&rep);
    assert_eq!(
        module_commands(&rep),
        [["-y", "module", "disable", "nodejs"]]
    );
    assert!(state_file(&rep).unwrap().contains("state=disabled\n"));
    assert_eq!(find(&rep, "m").verification, Verification::Verified);

    let reset = recipe("dm-a-reset", &module("      state: reset\n"));
    for removes in [false, true] {
        let t = fake().with_module_state("nodejs", "20", "", "enabled");
        t.el().lock().unwrap().module_reset_removes_file = removes;
        let rep = apply(&reset, t);
        assert_success(&rep);
        assert_eq!(module_commands(&rep), [["-y", "module", "reset", "nodejs"]]);
        assert_eq!(state_file(&rep).is_none(), removes);
        let m = find(&rep, "m");
        assert_eq!(
            (m.change, m.verification),
            (Change::Changed, Verification::Verified),
            "{m:?}"
        );
    }
    // A disabled module is enabled without a reset in between.
    let enable = recipe("dm-a-enable-from-disabled", &enable20());
    let rep = apply(
        &enable,
        fake().with_module_state("nodejs", "", "", "disabled"),
    );
    assert_success(&rep);
    assert_eq!(state_file(&rep).as_deref(), Some(ENABLED_20));
}

#[test]
fn reset_is_satisfied_by_an_absent_file_or_an_empty_state() {
    let reset = recipe("dm-a-reset-noop", &module("      state: reset\n"));
    // No file, no modules.d directory at all, and a file with `state=`.
    for t in [
        fake(),
        dnf_link(FakeTarget::rocky9().with_fake_fs().as_root(), "dnf-3"),
        fake().with_module_state("nodejs", "", "", ""),
    ] {
        let rep = apply(&reset, t.clone());
        assert_success(&rep);
        assert_eq!(find(&rep, "m").change, Change::None);
        assert!(module_commands(&rep).is_empty());
        let a = audit(&reset, t);
        assert_eq!(a.resources[0].status, AuditResourceStatus::Compliant);
    }
}

#[test]
fn switching_an_enabled_stream_is_refused_before_anything_runs() {
    let r = recipe("dm-x-switch", &enable20());
    let t = || fake().with_module_state("nodejs", "18", "", "enabled");
    for mode in [Mode::Plan, Mode::Apply] {
        let (why, rep) = refused(&r, mode, t());
        assert!(
            why.contains("enabled with stream 18") && why.contains("does not switch"),
            "{why}"
        );
        assert!(why.contains("state: reset"), "{why}");
        if let Some(rep) = rep {
            assert!(state_file(&rep).unwrap().contains("stream=18"));
        }
    }
    let e = try_run_recipe_fake(&r, Mode::Plan, false, t());
    assert!(
        e.map(|rep| rep.status != AggregateStatus::Success)
            .unwrap_or(true),
        "plan must fail"
    );
}

#[test]
fn installed_profiles_refuse_disable_and_reset() {
    for (label, state) in [("dm-x-prof-dis", "disabled"), ("dm-x-prof-reset", "reset")] {
        let r = recipe(label, &module(&format!("      state: {state}\n")));
        for mode in [Mode::Plan, Mode::Apply] {
            let t = fake().with_module_state("nodejs", "20", "common, development", "enabled");
            let (why, _) = refused(&r, mode, t);
            assert!(
                why.contains("installed profiles (common, development)")
                    && why.contains("package decision"),
                "{why}"
            );
        }
    }
    // Enabling the stream that is already enabled is no change, profiles or not.
    let r = recipe("dm-x-prof-same", &enable20());
    let rep = apply(
        &r,
        fake().with_module_state("nodejs", "20", "common", "enabled"),
    );
    assert_success(&rep);
    assert_eq!(find(&rep, "m").change, Change::None);
}

// ---------------------------------------------------------------------------
// failures of the change
// ---------------------------------------------------------------------------

#[test]
fn a_failing_dnf_is_a_failure() {
    let r = recipe("dm-f-exit1", &enable20());
    let t = fake();
    t.el().lock().unwrap().module_change = FakeChange::Fail;
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    let m = find(&rep, "m");
    assert_eq!(
        (m.execution, m.change, m.verification),
        (Execution::Failed, Change::Possible, Verification::Unknown),
        "{m:?}"
    );
    let why = reason(&rep);
    assert!(why.contains("failed with exit code 1"), "{why}");
    assert!(why.contains("output withheld"), "{why}");
    assert!(!why.contains("injected failure"), "{why}");
    assert!(state_file(&rep).is_none());
}

#[test]
fn a_stream_the_repositories_do_not_offer_fails_at_apply_not_in_plan() {
    let r = recipe("dm-f-nostream", &enable20());
    let t = || {
        let t = fake();
        t.el().lock().unwrap().module_streams = Some(["nodejs:18".to_string()].into());
        t
    };
    let p = plan(&r, t());
    assert_eq!(p.status, AggregateStatus::Success);
    assert_eq!(find(&p, "m").change, Change::Changed);
    let a = apply(&r, t());
    assert_eq!(a.status, AggregateStatus::ApplyFailed);
    assert!(reason(&a).contains("exit code 1"), "{}", reason(&a));
    assert!(
        reason(&a).contains("dnf module list nodejs"),
        "{}",
        reason(&a)
    );
}

#[test]
fn exit_zero_without_the_declared_state_is_a_failure() {
    let r = recipe("dm-f-noop", &enable20());
    let t = fake();
    t.el().lock().unwrap().module_change = FakeChange::SucceedWithoutChange;
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    let m = find(&rep, "m");
    assert_eq!(m.execution, Execution::Failed, "{m:?}");
    assert_eq!(m.verification, Verification::Failed);
    assert_ne!(m.change, Change::Changed);
    let why = reason(&rep);
    assert!(
        why.contains("dnf reported success but the module state is state=default")
            && why.contains("declared: state=enabled stream=20"),
        "{why}"
    );
}

#[test]
fn exit_zero_with_an_unreadable_state_file_is_a_failure() {
    let r = recipe("dm-f-reobs", &enable20());
    // The first read sees no file (stat says absent, nothing is read); the
    // read after dnf fails.
    let t = fake().with_observations_at("cat", STATE, vec![forced(1, "", "cat: read error\n")]);
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    let m = find(&rep, "m");
    assert_eq!(m.execution, Execution::Failed, "{m:?}");
    assert_ne!(m.verification, Verification::Verified);
    assert!(
        reason(&rep).contains("could not be read again"),
        "{}",
        reason(&rep)
    );
}

#[test]
fn a_killed_dnf_is_not_reported_as_success() {
    let r = recipe("dm-f-killed", &enable20());
    let t = fake();
    t.el().lock().unwrap().module_change = FakeChange::KilledAfterChange;
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    let m = find(&rep, "m");
    assert_eq!(
        (m.execution, m.change, m.verification),
        (Execution::Failed, Change::Possible, Verification::Unknown),
        "{m:?}"
    );
    assert!(reason(&rep).contains("signal 9"), "{}", reason(&rep));
    assert!(reason(&rep).contains("may or may not"), "{}", reason(&rep));
}

#[test]
fn a_dnf_that_does_not_complete_is_indeterminate_and_nothing_else_is_sent() {
    let r = recipe(
        "dm-f-timeout",
        &format!(
            "{}  - id: after\n    type: dnf_module\n    depends_on: [m]\n    with:\n      name: postgresql\n      state: disabled\n",
            enable20()
        ),
    );
    let t = fake();
    t.el().lock().unwrap().module_change = FakeChange::IndeterminateAfterChange;
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::Indeterminate);
    let m = find(&rep, "m");
    assert_eq!(
        (m.execution, m.change, m.verification),
        (
            Execution::Indeterminate,
            Change::Possible,
            Verification::Unknown
        ),
        "{m:?}"
    );
    assert!(
        reason(&rep).contains("did not complete"),
        "{}",
        reason(&rep)
    );
    // The dnf command is the last thing sent for this resource, and the
    // dependent resource never ran.
    let last = rep.commands.last().unwrap();
    assert_eq!(last.args, ["-y", "module", "enable", "nodejs:20"]);
    assert_eq!(module_commands(&rep).len(), 1);
}

#[test]
fn a_state_change_between_observation_and_the_change_is_refused() {
    // Sinter read "default" and decided to enable stream 20. Before the
    // change, another administrator enables stream 18: the read right
    // before dnf notices, and dnf is not run.
    let r = recipe("dm-f-recheck", &enable20());
    let t = fake().with_fs_event(
        "stat",
        STATE,
        1,
        vec![FsEventAction::PutFile {
            path: STATE.into(),
            data: b"[nodejs]\nname=nodejs\nstream=18\nprofiles=\nstate=enabled\n".to_vec(),
            mode: 0o644,
            uid: 0,
            gid: 0,
        }],
    );
    let (why, rep) = refused(&r, Mode::Apply, t);
    assert!(
        why.contains("changed while this resource was being handled")
            && why.contains("state=default")
            && why.contains("state=enabled stream=18"),
        "{why}"
    );
    assert!(state_file(&rep.unwrap()).unwrap().contains("stream=18"));
}

#[test]
fn a_state_change_between_observation_and_dnf_is_not_overridden() {
    // The remaining window: stream 18 is enabled after Sinter's last read
    // and before dnf looks. dnf itself refuses the switch, and Sinter
    // reports the failure.
    let r = recipe("dm-f-race", &enable20());
    let t = fake().with_fs_event(
        "dnf",
        "module",
        0,
        vec![FsEventAction::PutFile {
            path: STATE.into(),
            data: b"[nodejs]\nname=nodejs\nstream=18\nprofiles=\nstate=enabled\n".to_vec(),
            mode: 0o644,
            uid: 0,
            gid: 0,
        }],
    );
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    let m = find(&rep, "m");
    assert_eq!(m.execution, Execution::Failed, "{m:?}");
    assert_ne!(m.verification, Verification::Verified);
    assert!(state_file(&rep).unwrap().contains("stream=18"));
}

// ---------------------------------------------------------------------------
// observation failures are errors, never a state
// ---------------------------------------------------------------------------

#[test]
fn a_state_file_sinter_does_not_understand_is_an_error_everywhere() {
    let r = recipe("dm-o-garbage", &enable20());
    for (body, want) in [
        (
            "[nodejs]\nname=nodejs\nstream=20\nprofiles=\nstate=enabled\nversion=1\n",
            "does not know",
        ),
        (
            "[nodejs]\r\nstate=enabled\r\nstream=20\r\n",
            "carriage return",
        ),
        (
            "[nodejs]\nstate=enabled\nstream=20\n[other]\nstate=enabled\nstream=1\n",
            "second section",
        ),
        ("", "no [nodejs] section"),
        ("[nodejs]\nstate=installed\n", "enabled, disabled or empty"),
    ] {
        let t = || fake().with_fs_file(STATE, body);
        for mode in [Mode::Plan, Mode::Apply] {
            let (why, _) = refused(&r, mode, t());
            assert!(why.contains(want) && why.contains("not guessed"), "{why}");
        }
        let a = audit(&r, t());
        assert_eq!(
            a.resources[0].status,
            AuditResourceStatus::Error,
            "{body:?}"
        );
        assert!(
            a.resources[0].reason.as_deref().unwrap().contains(want),
            "{:?}",
            a.resources[0].reason
        );
    }
}

#[test]
fn a_failed_read_is_an_error_and_not_an_absent_module() {
    // The file exists; reading it fails (for example permission denied).
    // A reset must not be reported as satisfied, an enable must not run.
    for (label, yaml) in [
        ("dm-o-read-reset", module("      state: reset\n")),
        ("dm-o-read-enable", enable20()),
    ] {
        let r = recipe(label, &yaml);
        let t = || {
            fake()
                .with_module_state("nodejs", "20", "", "enabled")
                .with_observations_at(
                    "cat",
                    STATE,
                    vec![forced(1, "", "cat: Permission denied\n")],
                )
        };
        for mode in [Mode::Plan, Mode::Apply] {
            let (why, _) = refused(&r, mode, t());
            assert!(why.contains("Permission denied"), "{label}: {why}");
        }
        let a = audit(&r, t());
        assert_eq!(a.resources[0].status, AuditResourceStatus::Error, "{label}");
    }
}

#[test]
fn a_truncated_read_is_an_error() {
    let r = recipe("dm-o-trunc", &module("      state: reset\n"));
    let t = fake()
        .with_module_state("nodejs", "20", "", "enabled")
        .with_observations_at("cat", STATE, vec![forced(0, "[nodejs]\n", "")]);
    let (why, _) = refused(&r, Mode::Plan, t);
    assert!(why.contains("changed while it was observed"), "{why}");
}

#[test]
fn a_symlink_state_file_is_refused_and_never_followed() {
    let r = recipe("dm-o-symlink", &module("      state: reset\n"));
    let t = || {
        let mut t = fake().with_fs_file("/etc/dnf/elsewhere", ENABLED_20);
        t.fs.as_mut()
            .unwrap()
            .put_symlink(STATE, "/etc/dnf/elsewhere", 0, 0);
        t
    };
    for mode in [Mode::Plan, Mode::Apply] {
        let (why, _) = refused(&r, mode, t());
        assert!(why.contains("symlink"), "{why}");
    }
    let a = audit(&r, t());
    assert_eq!(a.resources[0].status, AuditResourceStatus::Error);
}

#[test]
fn a_parent_another_account_controls_is_refused() {
    // modules.d owned by an ordinary account: nothing behind it is read.
    let r = recipe("dm-o-parent", &enable20());
    let t = || {
        let mut t = fake().with_module_state("nodejs", "20", "", "enabled");
        t.fs.as_mut()
            .unwrap()
            .mkdir_node("/etc/dnf/modules.d", 0o777, 1001, 1001);
        t.fs.as_mut()
            .unwrap()
            .put_file(STATE, ENABLED_20.as_bytes(), 0o644, 1001, 1001);
        t
    };
    for mode in [Mode::Plan, Mode::Apply] {
        let (why, _) = refused(&r, mode, t());
        assert!(why.contains("/etc/dnf/modules.d"), "{why}");
    }
    let a = audit(&r, t());
    assert_eq!(a.resources[0].status, AuditResourceStatus::Error);
}

// ---------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------

#[test]
fn audit_reports_compliance_and_drift_and_does_not_mutate() {
    let r = recipe("dm-au", &enable20());
    let t = fake().with_module_state("nodejs", "20", "", "enabled");
    let a = audit(&r, t);
    assert_eq!(a.resources[0].status, AuditResourceStatus::Compliant);

    let detail = |a: &AuditReport| -> Vec<(String, String, String)> {
        a.resources[0]
            .details
            .iter()
            .map(|d| (d.dimension.clone(), d.observed.clone(), d.desired.clone()))
            .collect()
    };
    let a = audit(&r, fake().with_module_state("nodejs", "18", "", "enabled"));
    assert_eq!(a.resources[0].status, AuditResourceStatus::Drift);
    assert_eq!(
        detail(&a),
        [("stream".to_string(), "18".to_string(), "20".to_string())]
    );

    let t = fake();
    let el = t.el();
    let a = audit(&r, t);
    assert_eq!(a.resources[0].status, AuditResourceStatus::Drift);
    assert_eq!(
        detail(&a),
        [
            (
                "state".to_string(),
                "default".to_string(),
                "enabled".to_string()
            ),
            ("stream".to_string(), "(none)".to_string(), "20".to_string())
        ]
    );
    assert!(el.lock().unwrap().module_calls.is_empty());
    assert!(
        !a.commands
            .iter()
            .any(|c| c.program == "/usr/bin/dnf" || is_mutation_command(&c.program, &c.args)),
        "{:?}",
        a.commands
    );

    let disabled = recipe("dm-au-dis", &module("      state: disabled\n"));
    let a = audit(
        &disabled,
        fake().with_module_state("nodejs", "20", "", "enabled"),
    );
    assert_eq!(
        detail(&a),
        [(
            "state".to_string(),
            "enabled".to_string(),
            "disabled".to_string()
        )]
    );
}

// ---------------------------------------------------------------------------
// platform and privilege
// ---------------------------------------------------------------------------

#[test]
fn an_apt_host_is_refused_clearly() {
    let r = recipe("dm-u-apt", &enable20());
    let t = || FakeTarget::ubuntu2404().with_fake_fs().as_root();
    for mode in [Mode::Plan, Mode::Apply] {
        let (why, _) = refused(&r, mode, t());
        assert!(
            why.contains(
                "dnf_module is not supported on this host (its package manager is not DNF)"
            ),
            "{why}"
        );
    }
    let a = audit(&r, t());
    assert_eq!(a.resources[0].status, AuditResourceStatus::Error);
    assert!(a.resources[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("not supported on this host"));
}

#[test]
fn dnf5_and_an_unidentified_dnf_are_refused() {
    // The check itself is shared with dnf_repository (src/dnfgen.rs, where
    // the link targets are classified); this proves dnf_module calls it in
    // plan, apply and audit before anything else.
    let r = recipe("dm-u-dnf5", &enable20());
    let modules = |t: FakeTarget| t.with_fs_dir("/etc/dnf").with_fs_dir("/etc/dnf/modules.d");
    type Make = Box<dyn Fn() -> FakeTarget>;
    let rocky = || FakeTarget::rocky9().with_fake_fs().as_root();
    let cases: Vec<(Make, &str)> = vec![
        (
            Box::new(move || modules(dnf_link(rocky(), "dnf5"))),
            "dnf_module is not supported on this host: it uses DNF 5",
        ),
        (
            Box::new(move || modules(dnf_link(rocky(), "/opt/tools/wrapper"))),
            "the DNF generation cannot be told",
        ),
        (
            Box::new(move || modules(rocky().with_fs_dir("/usr/bin"))),
            "the DNF generation cannot be told",
        ),
        (
            Box::new(move || {
                modules(rocky().with_fs_dir("/usr/bin")).with_fs_file("/usr/bin/dnf", "#!/bin/sh\n")
            }),
            "the DNF generation cannot be told",
        ),
    ];
    for (make, want) in cases {
        for mode in [Mode::Plan, Mode::Apply] {
            let (why, _) = refused(&r, mode, make());
            assert!(why.contains(want), "{why}");
        }
        let a = audit(&r, make());
        assert_eq!(a.resources[0].status, AuditResourceStatus::Error);
        assert!(
            a.resources[0].reason.as_deref().unwrap().contains(want),
            "{:?}",
            a.resources[0].reason
        );
    }
}

#[test]
fn without_root_plan_notes_it_and_apply_fails_before_dnf() {
    let r = recipe("dm-u-root", &enable20());
    let t = || {
        dnf_link(FakeTarget::rocky9().with_fake_fs(), "dnf-3")
            .with_fs_dir("/etc/dnf")
            .with_fs_dir("/etc/dnf/modules.d")
    };
    let p = plan(&r, t());
    assert_eq!(p.status, AggregateStatus::Success);
    assert!(
        find(&p, "m").notes.iter().any(|n| n.contains("needs root")),
        "{:?}",
        find(&p, "m").notes
    );
    let (why, _) = refused(&r, Mode::Apply, t());
    assert!(why.contains("needs root"), "{why}");
    // With --sudo the change runs.
    let s = run_recipe_fake(&r, Mode::Apply, true, t());
    assert_success(&s);
    assert_eq!(state_file(&s).as_deref(), Some(ENABLED_20));
}

// ---------------------------------------------------------------------------
// environment and sensitivity
// ---------------------------------------------------------------------------

#[test]
fn the_recipe_wide_env_reaches_dnf_module_and_a_secret_proxy_stays_hidden() {
    let marker = "synthetic-proxy-credential-7391";
    let yaml = format!(
        "version: 1\nvars:\n  proxy:\n    value: \"http://user:{marker}@proxy.example.invalid:3128\"\n    sensitive: true\nenv:\n  https_proxy: \"{{{{ vars.proxy }}}}\"\nresources:\n  - id: m\n    type: dnf_module\n    with:\n      name: nodejs\n      stream: \"20\"\n      state: enabled\n"
    );
    let r = recipe("dm-s-env", &yaml);
    let t = fake();
    let el = t.el();
    let p = plan(&r, t.clone());
    let a = apply(&r, t);
    assert_success(&a);
    // dnf ran (the scripted tool saw the real argv) ...
    assert_eq!(el.lock().unwrap().module_calls.len(), 1);
    // ... and neither the argv record nor any output names the credential.
    for (rep, mode) in [(&p, "plan"), (&a, "apply")] {
        for s in surfaces_and_commands(rep, mode) {
            assert!(
                !s.contains(marker),
                "{mode} leaks the proxy credential: {s}"
            );
        }
    }
    let au = audit(&r, fake());
    for s in [
        au.render_text(),
        sinter::output::audit_report_json(&au).to_string(),
        format!("{:?}", au.resources),
        format!("{:?}", au.commands),
    ] {
        assert!(!s.contains(marker), "audit leaks the proxy credential: {s}");
    }

    // A non-sensitive recipe env is passed to dnf as written, and the
    // resource's own env overrides it.
    let plain = "version: 1\nenv:\n  https_proxy: \"http://proxy.example.invalid:3128\"\n  no_proxy: \"localhost\"\nresources:\n  - id: m\n    type: dnf_module\n    with:\n      name: nodejs\n      stream: \"20\"\n      state: enabled\n      env:\n        no_proxy: \"localhost,.example.invalid\"\n";
    let rep = apply(&recipe("dm-s-env-plain", plain), fake());
    let dnf = rep
        .commands
        .iter()
        .find(|c| c.args.iter().any(|a| a == "module"))
        .unwrap();
    assert_eq!(
        dnf.env.get("https_proxy").map(String::as_str),
        Some("http://proxy.example.invalid:3128")
    );
    assert_eq!(
        dnf.env.get("no_proxy").map(String::as_str),
        Some("localhost,.example.invalid")
    );
}

#[test]
fn a_sensitive_resource_names_no_module_in_any_output() {
    let yaml = "version: 1\nresources:\n  - id: m\n    type: dnf_module\n    sensitive: true\n    with:\n      name: synthmodule\n      stream: \"synthstream9\"\n      state: enabled\n";
    let r = recipe("dm-s-sensitive", yaml);
    let leaks = |texts: Vec<String>, what: &str| {
        for s in texts {
            assert!(
                !s.contains("synthmodule") && !s.contains("synthstream9"),
                "{what}: {s}"
            );
        }
    };
    leaks(surfaces(&plan(&r, fake()), "plan"), "plan");
    let a = apply(&r, fake());
    assert_success(&a);
    leaks(surfaces(&a, "apply"), "apply");
    // The change command is recorded redacted (the state file path of an
    // observation is not: a module name is not a secret value, and the
    // resource's results and messages are what `sensitive` hides).
    assert!(
        !a.commands.iter().any(|c| c
            .args
            .iter()
            .any(|x| x.contains("synthmodule:") || x == "module")),
        "{:?}",
        a.commands
    );
    // A refusal and a failure stay silent about the module too.
    let switched = fake().with_module_state("synthmodule", "other1", "", "enabled");
    let rep = run_recipe_fake(&r, Mode::Apply, false, switched);
    assert_ne!(rep.status, AggregateStatus::Success);
    leaks(surfaces(&rep, "apply"), "refusal");
    let e = try_run_recipe_fake(
        &r,
        Mode::Plan,
        false,
        fake().with_module_state("synthmodule", "other1", "", "enabled"),
    );
    if let Err(e) = e {
        leaks(vec![e.message], "plan refusal");
    }
    let failing = fake();
    failing.el().lock().unwrap().module_change = FakeChange::Fail;
    let rep = run_recipe_fake(&r, Mode::Apply, false, failing);
    assert_ne!(rep.status, AggregateStatus::Success);
    leaks(surfaces(&rep, "apply"), "failure");
    let au = audit(&r, fake());
    leaks(
        vec![
            au.render_text(),
            sinter::output::audit_report_json(&au).to_string(),
            format!("{:?}", au.resources),
        ],
        "audit",
    );
}

// ---------------------------------------------------------------------------
// order: module stream, then the package, then its service
// ---------------------------------------------------------------------------

const CHAIN: &str = "version: 1\nresources:\n  - id: stream\n    type: dnf_module\n    with:\n      name: nodejs\n      stream: \"20\"\n      state: enabled\n  - id: pkg\n    type: package\n    depends_on: [stream]\n    with:\n      name: nodejs\n      state: present\n  - id: svc\n    type: service\n    depends_on: [pkg]\n    with:\n      name: nodejs-app\n      state: running\n";

#[test]
fn module_then_package_then_service_plans_on_a_fresh_host() {
    // Nothing exists yet: no module state, no package, no unit. Plan must
    // not fail on the service whose unit the package brings.
    let r = recipe("dm-c-plan", CHAIN);
    let rep = plan(&r, fake());
    assert_eq!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
    assert_eq!(find(&rep, "stream").change, Change::Changed);
    assert_eq!(find(&rep, "pkg").change, Change::Changed);
    assert!(find(&rep, "svc").unknown, "{:?}", find(&rep, "svc"));
    assert!(module_commands(&rep).is_empty());
    assert_eq!(mutation_command_count(&rep), 0);
}

#[test]
fn module_then_package_then_service_apply_in_that_order() {
    // The scripted target does not create units when a package is
    // installed, so the unit is present (stopped) from the start; the order
    // of the three changes is what this proves.
    let r = recipe("dm-c-apply", CHAIN);
    let t = fake().with_service("nodejs-app", ("loaded", "inactive", "disabled"));
    let rep = apply(&r, t);
    assert_success(&rep);
    for id in ["stream", "pkg", "svc"] {
        assert_eq!(find(&rep, id).change, Change::Changed, "{id}");
    }
    let pos = |pred: &dyn Fn(&sinter::executor::CommandRecord) -> bool| {
        rep.commands
            .iter()
            .position(pred)
            .unwrap_or_else(|| panic!("command missing: {:?}", rep.commands))
    };
    let enable = pos(&|c| c.program == "/usr/bin/dnf" && c.args.iter().any(|a| a == "module"));
    let install = pos(&|c| is_mutation_command(&c.program, &c.args) && c.program == "/usr/bin/dnf");
    let start = pos(&|c| c.program.ends_with("systemctl") && c.args.iter().any(|a| a == "start"));
    assert!(
        enable < install && install < start,
        "{enable} {install} {start}"
    );
    // No dnf command that reads repository metadata ran before the enable.
    assert!(
        !rep.commands[..enable]
            .iter()
            .any(|c| c.program == "/usr/bin/dnf"),
        "{:?}",
        &rep.commands[..enable]
    );
}

#[test]
fn a_failed_module_blocks_the_package_that_depends_on_it() {
    let r = recipe("dm-c-blocked", CHAIN);
    let t = fake();
    t.el().lock().unwrap().module_change = FakeChange::Fail;
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    assert_eq!(find(&rep, "pkg").change, Change::None);
    assert!(
        !rep.commands
            .iter()
            .any(|c| is_mutation_command(&c.program, &c.args)),
        "{:?}",
        rep.commands
    );
}

// ---------------------------------------------------------------------------
// documentation examples
// ---------------------------------------------------------------------------

#[test]
fn the_toml_form_and_the_shipped_example_plan_like_the_yaml_form() {
    let toml = "version = 1\n\n[[resources]]\nid = \"m\"\ntype = \"dnf_module\"\n\n[resources.with]\nname = \"nodejs\"\nstream = \"20\"\nstate = \"enabled\"\n\n[[resources]]\nid = \"nodejs\"\ntype = \"package\"\ndepends_on = [\"m\"]\n\n[resources.with]\nname = \"nodejs\"\nstate = \"present\"\n";
    let dir = trusted_root("dm-d-toml");
    let r = write_recipe(&dir, "r.toml", toml);
    let rep = plan(&r, fake());
    assert_eq!(rep.status, AggregateStatus::Success);
    assert_eq!(find(&rep, "m").change, Change::Changed);

    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/quick/dnf-module.yaml");
    let text = std::fs::read_to_string(&example).unwrap();
    assert!(text.contains("type: dnf_module"));
    assert!(
        !text.contains("type: command"),
        "the command workaround is gone"
    );
    let r = write_recipe(&trusted_root("dm-d-example"), "dnf-module.yaml", &text);
    let rep = apply(&r, fake());
    assert_success(&rep);
    assert_eq!(
        module_commands(&rep),
        [["-y", "module", "enable", "nodejs:20"]]
    );
    assert_eq!(find(&rep, "install-nodejs").change, Change::Changed);
}
