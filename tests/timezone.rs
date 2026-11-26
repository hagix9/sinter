//! `timezone` against the scripted in-process target.
//!
//! These run the production loader, engine, audit and output code against
//! [`FakeTarget`], whose `timedatectl set-timezone` replaces the link
//! `/etc/localtime` on the scripted filesystem. They prove Sinter's own
//! decisions, argv and order. What only a real host can show (the real
//! tool's output and exit codes, the link it writes on each OS, the effect
//! on running programs) is NOT verified here.
#![cfg(unix)]

mod common;

use common::*;
use sinter::audit::{AuditReport, AuditResourceStatus};
use sinter::engine::{AggregateStatus, Mode, RunReport};
use sinter::executor::{Completion, FakeTarget, Output};
use sinter::fake_el::FakeChange;
use sinter::output::{OutputFormat, RenderOptions};
use sinter::result::{Change, DiffBody, Execution, Verification};
use std::path::{Path, PathBuf};

const TOOL: &str = "/usr/bin/timedatectl";
const LOCALTIME: &str = "/etc/localtime";

fn tz(name: &str) -> String {
    format!(
        "version: 1\nresources:\n  - id: z\n    type: timezone\n    with:\n      name: \"{name}\"\n"
    )
}

fn recipe(label: &str, yaml: &str) -> PathBuf {
    write_recipe(&trusted_root(label), "r.yaml", yaml)
}

const ZONES: &[&str] = &["UTC", "Asia/Tokyo", "Europe/Berlin", "Etc/GMT+5"];

/// A Rocky Linux 9 target as root with the zones above and `current` as
/// the link target.
fn fake(current: &str) -> FakeTarget {
    FakeTarget::rocky9()
        .with_fake_fs()
        .as_root()
        .with_timezones(ZONES, Some(current))
}

fn link(t: &FakeTarget) -> Option<String> {
    let fs = t.fs.as_ref().unwrap();
    fs.nodes.get(LOCALTIME).map(|n| format!("{:?}", n.kind))
}

fn link_after(rep: &RunReport) -> Option<String> {
    rep.fake_fs
        .as_ref()
        .unwrap()
        .nodes
        .get(LOCALTIME)
        .map(|n| format!("{:?}", n.kind))
}

/// The `set-timezone` operands the scripted tool received.
fn sets(t: &FakeTarget) -> Vec<String> {
    t.el()
        .lock()
        .unwrap()
        .osbase
        .timedatectl_calls
        .iter()
        .map(|a| a.join(" "))
        .collect()
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

fn reason(rep: &RunReport) -> String {
    find(rep, "z").reason.clone().unwrap_or_default()
}

fn nodes(t: &FakeTarget) -> String {
    format!("{:?}", t.fs.as_ref().unwrap().nodes)
}

fn nodes_after(rep: &RunReport) -> String {
    format!("{:?}", rep.fake_fs.as_ref().unwrap().nodes)
}

/// A run that must not succeed and must not have run `set-timezone`: why.
fn refused(r: &Path, mode: Mode, t: FakeTarget) -> String {
    let fs_before = nodes(&t);
    let why = match try_run_recipe_fake(r, mode, false, t.clone()) {
        Ok(rep) => {
            assert_ne!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
            assert_eq!(find(&rep, "z").change, Change::None, "{:?}", rep.resources);
            assert_eq!(nodes_after(&rep), fs_before);
            reason(&rep)
        }
        Err(e) => e.message,
    };
    assert!(sets(&t).is_empty(), "set-timezone ran: {:?}", sets(&t));
    why
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
    v.push(format!("{:?}", rep.commands));
    v
}

fn has_programs_note(rep: &RunReport) -> bool {
    find(rep, "z")
        .notes
        .iter()
        .any(|n| n.contains("keep the time zone they started with") && n.contains("NTP"))
}

fn failed_read(stderr: &str) -> Output {
    Output {
        completion: Completion::Exited(1),
        stdout: Vec::new(),
        stderr: stderr.as_bytes().to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

// ---------------------------------------------------------------------------
// load
// ---------------------------------------------------------------------------

#[test]
fn invalid_names_are_rejected_at_load() {
    let long = format!("{}/{}", "A".repeat(32), "b".repeat(32));
    for (label, name, want) in [
        ("tz-l1", "/Asia/Tokyo", "not a zone name"),
        ("tz-l2", "../etc/shadow", "not a zone name"),
        ("tz-l3", "Asia/../Tokyo", "not a zone name"),
        ("tz-l4", "Asia/Tokyo ", "not a zone name"),
        ("tz-l5", "-UTC", "not a zone name"),
        ("tz-l6", "a/b/c/d", "not a zone name"),
        ("tz-l7", "", "not a zone name"),
        ("tz-l8", long.as_str(), "not a zone name"),
        ("tz-l9", "posix/Asia/Tokyo", "posix/ or right/"),
        ("tz-l10", "right/UTC", "posix/ or right/"),
        ("tz-l11", "posixrules", "is not a time zone"),
        ("tz-l12", "localtime", "is not a time zone"),
    ] {
        let e = load_err(label, &tz(name));
        assert!(e.contains(want), "{label}: {e}");
    }
    let e = load_err(
        "tz-l13",
        "version: 1\nresources:\n  - id: z\n    type: timezone\n    with: {}\n",
    );
    assert!(e.contains("name is required"), "{e}");
    let e = load_err(
        "tz-l14",
        "version: 1\nresources:\n  - id: z\n    type: timezone\n    with:\n      name: UTC\n      ntp: true\n",
    );
    assert!(e.contains("ntp"), "{e}");
    let e = load_err(
        "tz-l15",
        "version: 1\nresources:\n  - id: z\n    type: timezone\n    with:\n      name: 9\n",
    );
    assert!(e.contains("string"), "{e}");
    // A variable that resolves to a refused name is refused at load too.
    let e = load_err(
        "tz-l16",
        "version: 1\nvars:\n  z: { value: posix/UTC }\nresources:\n  - id: z\n    type: timezone\n    with:\n      name: \"{{ vars.z }}\"\n",
    );
    assert!(e.contains("posix/"), "{e}");
    // A fact is not static.
    let e = load_err(
        "tz-l17",
        "version: 1\nresources:\n  - id: z\n    type: timezone\n    with:\n      name: \"{{ facts.hostname }}\"\n",
    );
    assert!(e.contains("name"), "{e}");
    sinter::model::load_model(&recipe("tz-l18", &tz("America/Argentina/Buenos_Aires"))).unwrap();
    sinter::model::load_model(&recipe(
        "tz-l19",
        "version: 1\nvars:\n  z: { value: Asia/Tokyo }\nresources:\n  - id: z\n    type: timezone\n    with:\n      name: \"{{ vars.z }}\"\n",
    ))
    .unwrap();
}

#[test]
fn conflicting_declarations_in_one_recipe_are_rejected() {
    let two = "version: 1\nresources:\n  - id: first\n    type: timezone\n    with:\n      name: UTC\n  - id: second\n    type: timezone\n    with:\n      name: UTC\n";
    let e = load_err("tz-two", two);
    assert!(
        e.contains("conflicting ownership of the system time zone")
            && e.contains("first")
            && e.contains("second"),
        "{e}"
    );
    let z = "  - id: z\n    type: timezone\n    with:\n      name: UTC\n";
    let others = [
        "  - id: other\n    type: link\n    with:\n      path: /etc/localtime\n      target: /usr/share/zoneinfo/UTC\n",
        "  - id: other\n    type: file\n    with:\n      path: /etc/localtime\n      content: synthetic\n",
        "  - id: other\n    type: file_merge\n    with:\n      path: /etc/localtime\n      merge: line\n      line: synthetic\n",
    ];
    for (i, other) in others.iter().enumerate() {
        for (j, body) in [format!("{z}{other}"), format!("{other}{z}")]
            .iter()
            .enumerate()
        {
            let e = load_err(
                &format!("tz-own-{i}-{j}"),
                &format!("version: 1\nresources:\n{body}"),
            );
            assert!(
                e.contains("/etc/localtime") && e.contains("other") && e.contains(" z"),
                "{i}/{j}: {e}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// plan and apply
// ---------------------------------------------------------------------------

#[test]
fn plan_reports_the_change_with_the_note_and_does_not_mutate() {
    let r = recipe("tz-p", &tz("Asia/Tokyo"));
    let t = fake("UTC");
    let before = nodes(&t);
    let rep = plan(&r, t.clone());
    assert_eq!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
    let z = find(&rep, "z");
    assert_eq!(z.change, Change::Changed, "{z:?}");
    assert_eq!(
        z.diff.as_ref().map(|d| d.body.clone()),
        Some(DiffBody::Summary {
            current: "UTC".into(),
            desired: "Asia/Tokyo".into()
        })
    );
    assert!(has_programs_note(&rep), "{:?}", z.notes);
    assert!(sets(&t).is_empty());
    assert_eq!(mutation_command_count(&rep), 0);
    assert!(!rep.commands.iter().any(|c| c.program == TOOL));
    assert_eq!(nodes_after(&rep), before);
}

#[test]
fn apply_sets_the_zone_and_verifies_it_by_observing_the_link_again() {
    let r = recipe("tz-a", &tz("Asia/Tokyo"));
    let t = fake("UTC");
    let rep = apply(&r, t.clone());
    assert_success(&rep);
    let z = find(&rep, "z");
    assert_eq!(
        (z.execution, z.change, z.verification),
        (
            Execution::Succeeded,
            Change::Changed,
            Verification::Verified
        ),
        "{z:?}"
    );
    assert_eq!(sets(&t), ["set-timezone Asia/Tokyo"]);
    let argv: Vec<String> = rep
        .commands
        .iter()
        .filter(|c| c.program == TOOL)
        .map(|c| c.args.join(" "))
        .collect();
    assert_eq!(argv, ["set-timezone Asia/Tokyo"]);
    assert!(link_after(&rep)
        .unwrap()
        .contains("../usr/share/zoneinfo/Asia/Tokyo"));
    assert!(has_programs_note(&rep));
    // Sinter never writes the link itself.
    assert!(!rep
        .commands
        .iter()
        .any(|c| c.program != TOOL && is_mutation_command(&c.program, &c.args)));
}

#[test]
fn a_host_already_in_the_zone_is_unchanged_in_plan_apply_and_audit() {
    let r = recipe("tz-i", &tz("Etc/GMT+5"));
    let t = fake("Etc/GMT+5");
    for mode in [Mode::Plan, Mode::Apply] {
        let rep = run_recipe_fake(&r, mode, false, t.clone());
        assert_success(&rep);
        let z = find(&rep, "z");
        assert_eq!(z.change, Change::None, "{z:?}");
        assert!(z.notes.is_empty(), "{:?}", z.notes);
    }
    assert!(sets(&t).is_empty());
    let a = audit(&r, t.clone());
    assert_eq!(a.resources[0].status, AuditResourceStatus::Compliant);

    // A second apply after a change runs no set-timezone; the absolute
    // link form is understood as well.
    let t = fake("UTC");
    t.el().lock().unwrap().osbase.timezone_absolute_link = true;
    let first = apply(&r, t.clone());
    assert_success(&first);
    assert!(link_after(&first)
        .unwrap()
        .contains("\"/usr/share/zoneinfo/Etc/GMT+5\""));
    let mut t = t;
    t.fs = first.fake_fs.clone();
    let before = link(&t);
    let second = apply(&r, t.clone());
    assert_eq!(link_after(&second), before, "the link was rewritten");
    assert_success(&second);
    assert_eq!(find(&second, "z").change, Change::None);
    assert_eq!(sets(&t), ["set-timezone Etc/GMT+5"]);
    // The tool is not needed when nothing changes.
    let mut bare = t.clone();
    bare.executables.remove(TOOL);
    assert_success(&apply(&r, bare));
}

#[test]
fn a_copied_zone_file_a_missing_link_or_an_unknown_target_is_an_error_not_a_state() {
    let r = recipe("tz-obs", &tz("Asia/Tokyo"));
    let copied = || {
        let mut t = fake("UTC");
        t.fs.as_mut()
            .unwrap()
            .put_file(LOCALTIME, b"TZif synthetic\n", 0o644, 0, 0);
        t
    };
    let missing = || {
        let mut t = fake("UTC");
        t.fs.as_mut().unwrap().nodes.remove(LOCALTIME);
        t
    };
    let odd = |target: &str| {
        let mut t = fake("UTC");
        t.fs.as_mut().unwrap().put_symlink(LOCALTIME, target, 0, 0);
        t
    };
    for mode in [Mode::Plan, Mode::Apply] {
        let why = refused(&r, mode, copied());
        assert!(
            why.contains("regular file (a copied zone file)")
                && why.contains("does not guess a zone from a copied file"),
            "{mode:?}: {why}"
        );
        let why = refused(&r, mode, missing());
        assert!(why.contains("does not exist"), "{mode:?}: {why}");
        for target in [
            "/usr/lib/zoneinfo/UTC",
            "zoneinfo/UTC",
            "/usr/share/zoneinfo/../../../etc/shadow",
        ] {
            let why = refused(&r, mode, odd(target));
            assert!(
                why.contains("is not understood"),
                "{mode:?} {target}: {why}"
            );
        }
    }
    for t in [copied(), missing(), odd("/etc/other")] {
        let a = audit(&r, t.clone());
        assert_eq!(
            a.resources[0].status,
            AuditResourceStatus::Error,
            "{:?}",
            a.resources
        );
        assert!(sets(&t).is_empty());
    }
}

#[test]
fn a_failed_readlink_or_a_refused_parent_is_an_error_not_absence() {
    let r = recipe("tz-rl", &tz("Asia/Tokyo"));
    let t = fake("UTC").with_observations_at(
        "readlink",
        LOCALTIME,
        vec![failed_read("readlink: synthetic failure\n")],
    );
    let why = refused(&r, Mode::Plan, t.clone());
    assert!(
        why.contains("readlink") || why.contains("/etc/localtime"),
        "{why}"
    );
    let a = audit(
        &r,
        fake("UTC").with_observations_at(
            "readlink",
            LOCALTIME,
            vec![failed_read("readlink: synthetic failure\n")],
        ),
    );
    assert_eq!(a.resources[0].status, AuditResourceStatus::Error);

    // A zone directory another account controls is not looked into.
    let mut t = fake("UTC");
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/usr/share/zoneinfo/Asia", 0o777, 1000, 1000);
    t.fs.as_mut().unwrap().put_file(
        "/usr/share/zoneinfo/Asia/Tokyo",
        b"TZif synthetic\n",
        0o644,
        1000,
        1000,
    );
    let why = refused(&r, Mode::Plan, t);
    assert!(why.contains("/usr/share/zoneinfo/Asia"), "{why}");
}

#[test]
fn a_zone_that_is_not_installed_is_refused_unless_an_earlier_change_may_provide_it() {
    let r = recipe("tz-ni", &tz("America/Lima"));
    for mode in [Mode::Plan, Mode::Apply] {
        let why = refused(&r, mode, fake("UTC"));
        assert!(
            why.contains("is not installed on this host")
                && why.contains("/usr/share/zoneinfo/America/Lima"),
            "{mode:?}: {why}"
        );
    }
    // A zone directory instead of a file is refused as well.
    let r = recipe("tz-dir", &tz("Asia"));
    let why = refused(&r, Mode::Plan, fake("UTC"));
    assert!(why.contains("exists as"), "{why}");

    // An earlier planned package may bring it: plan defers the check.
    let yaml = "version: 1\nresources:\n  - id: data\n    type: package\n    with:\n      name: tzdata\n      state: present\n  - id: z\n    type: timezone\n    depends_on: [data]\n    with:\n      name: America/Lima\n";
    let r = recipe("tz-ni-deferred", yaml);
    let rep = plan(&r, fake("UTC"));
    assert_eq!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
    let z = find(&rep, "z");
    assert!(
        z.notes.iter().any(|n| n.contains("checked again at apply")),
        "{z:?}"
    );
}

#[test]
fn a_host_without_the_tool_is_refused_clearly() {
    let r = recipe("tz-tool", &tz("Asia/Tokyo"));
    let mut t = fake("UTC");
    t.executables.remove(TOOL);
    for mode in [Mode::Plan, Mode::Apply] {
        let why = refused(&r, mode, t.clone());
        assert!(
            why.contains("timezone is not supported on this host")
                && why.contains("/usr/bin/timedatectl was not found"),
            "{mode:?}: {why}"
        );
    }
    // Audit reads the link only.
    let a = audit(&r, t);
    assert_eq!(a.resources[0].status, AuditResourceStatus::Drift);

    // An unrecognized OS is judged by the tool like every other host.
    let t = FakeTarget::unsupported()
        .with_fake_fs()
        .as_root()
        .with_timezones(ZONES, Some("UTC"));
    assert_success(&apply(&r, t.clone()));
    assert_eq!(sets(&t), ["set-timezone Asia/Tokyo"]);
}

// ---------------------------------------------------------------------------
// failures of the change
// ---------------------------------------------------------------------------

#[test]
fn a_failing_change_or_exit_zero_without_the_zone_is_a_failure() {
    let r = recipe("tz-f", &tz("Asia/Tokyo"));
    let t = fake("UTC");
    t.el().lock().unwrap().osbase.timezone_set = FakeChange::Fail;
    let rep = apply(&r, t.clone());
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    let z = find(&rep, "z");
    assert_eq!(
        (z.execution, z.change, z.verification),
        (Execution::Failed, Change::Possible, Verification::Unknown),
        "{z:?}"
    );
    assert!(
        reason(&rep).contains("failed with exit code 1"),
        "{}",
        reason(&rep)
    );

    let t = fake("UTC");
    t.el().lock().unwrap().osbase.timezone_set = FakeChange::SucceedWithoutChange;
    let rep = apply(&r, t.clone());
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    let z = find(&rep, "z");
    assert_eq!(
        (z.execution, z.change, z.verification),
        (Execution::Failed, Change::Possible, Verification::Failed),
        "{z:?}"
    );
    assert!(
        reason(&rep).contains("reported success but /etc/localtime names \"UTC\""),
        "{}",
        reason(&rep)
    );
}

#[test]
fn a_signal_or_timeout_of_the_change_is_indeterminate_never_success() {
    let r = recipe("tz-ind", &tz("Asia/Tokyo"));
    for mode in [
        FakeChange::KilledAfterChange,
        FakeChange::IndeterminateAfterChange,
    ] {
        let t = fake("UTC");
        t.el().lock().unwrap().osbase.timezone_set = mode;
        let rep = apply(&r, t.clone());
        assert_ne!(rep.status, AggregateStatus::Success, "{mode:?}");
        let z = find(&rep, "z");
        assert_eq!(
            (z.execution, z.change, z.verification),
            (
                Execution::Indeterminate,
                Change::Possible,
                Verification::Unknown
            ),
            "{mode:?}: {z:?}"
        );
        assert!(reason(&rep).contains("may or may not"), "{}", reason(&rep));
        // Nothing is observed after an indeterminate change.
        let after = rep.commands.iter().position(|c| c.program == TOOL).unwrap();
        assert!(
            !rep.commands[after + 1..]
                .iter()
                .any(|c| c.args.iter().any(|a| a == LOCALTIME)),
            "{mode:?}: {:?}",
            rep.commands
        );
    }
}

#[test]
fn a_failed_observation_after_the_change_is_not_success() {
    let r = recipe("tz-reobs", &tz("Asia/Tokyo"));
    // The first readlink is the observation before the change, the second
    // the one after it.
    let t = fake("UTC").with_observations_at(
        "readlink",
        LOCALTIME,
        vec![
            Output {
                completion: Completion::Exited(0),
                stdout: b"../usr/share/zoneinfo/UTC".to_vec(),
                stderr: Vec::new(),
                stdout_truncated: false,
                stderr_truncated: false,
            },
            failed_read("readlink: synthetic failure\n"),
        ],
    );
    let rep = apply(&r, t);
    assert_ne!(rep.status, AggregateStatus::Success);
    let z = find(&rep, "z");
    assert_eq!(
        (z.execution, z.change),
        (Execution::Failed, Change::Possible),
        "{z:?}"
    );
    assert_ne!(z.verification, Verification::Verified);
    assert!(
        reason(&rep).contains("could not be observed again"),
        "{}",
        reason(&rep)
    );
}

// ---------------------------------------------------------------------------
// privilege
// ---------------------------------------------------------------------------

#[test]
fn a_change_needs_root_and_plan_says_so() {
    let r = recipe("tz-root", &tz("Asia/Tokyo"));
    let user = |cur: &str| {
        FakeTarget::rocky9()
            .with_fake_fs()
            .with_timezones(ZONES, Some(cur))
    };
    let p = plan(&r, user("UTC"));
    assert!(
        find(&p, "z").notes.iter().any(|n| n.contains("needs root")),
        "{:?}",
        find(&p, "z").notes
    );
    let why = refused(&r, Mode::Apply, user("UTC"));
    assert!(why.contains("needs root"), "{why}");

    let t = user("UTC");
    assert_success(&run_recipe_fake(&r, Mode::Apply, true, t.clone()));
    assert_eq!(sets(&t), ["set-timezone Asia/Tokyo"]);

    let rep = apply(&r, user("Asia/Tokyo"));
    assert_success(&rep);
    assert_eq!(find(&rep, "z").change, Change::None);
}

// ---------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------

#[test]
fn audit_reports_drift_in_timezone_and_does_not_mutate() {
    let r = recipe("tz-au", &tz("Asia/Tokyo"));
    let t = fake("UTC");
    let before = nodes(&t);
    let a = audit(&r, t.clone());
    assert_eq!(a.resources[0].status, AuditResourceStatus::Drift);
    let d = &a.resources[0].details;
    assert_eq!(d.len(), 1, "{d:?}");
    assert_eq!(
        (
            d[0].dimension.as_str(),
            d[0].observed.as_str(),
            d[0].desired.as_str()
        ),
        ("timezone", "UTC", "Asia/Tokyo")
    );
    assert!(sets(&t).is_empty());
    assert_eq!(nodes(&t), before);
    assert!(
        !a.commands
            .iter()
            .any(|c| c.program == TOOL || is_mutation_command(&c.program, &c.args)),
        "{:?}",
        a.commands
    );
}

// ---------------------------------------------------------------------------
// sensitive values
// ---------------------------------------------------------------------------

#[test]
fn a_sensitive_resource_names_no_zone_in_any_output() {
    let yaml = "version: 1\nresources:\n  - id: z\n    type: timezone\n    sensitive: true\n    with:\n      name: Synthzone/Target\n";
    let r = recipe("tz-sens", yaml);
    let t = || {
        FakeTarget::rocky9()
            .with_fake_fs()
            .as_root()
            .with_timezones(
                &["Synthzone/Target", "Synthzone/Current"],
                Some("Synthzone/Current"),
            )
    };
    let leaks = |texts: Vec<String>, what: &str| {
        for s in texts {
            assert!(
                !s.contains("Synthzone/Target") && !s.contains("Synthzone/Current"),
                "{what}: {s}"
            );
        }
    };
    // The record of read-only commands names the zone file, as it names the
    // path of a sensitive `file`; everything else names no zone.
    let without_log = |rep: &RunReport, mode: &str| {
        let mut v = surfaces(rep, mode);
        v.pop();
        let changes: Vec<_> = rep
            .commands
            .iter()
            .filter(|c| is_mutation_command(&c.program, &c.args) || c.program.contains("redacted"))
            .collect();
        v.push(format!("{:?}", changes));
        v
    };
    leaks(without_log(&plan(&r, t()), "plan"), "plan");
    let target = t();
    let a = apply(&r, target.clone());
    assert_success(&a);
    assert!(
        !a.commands
            .iter()
            .any(|c| c.args.iter().any(|x| x == "set-timezone")),
        "the change was recorded unredacted: {:?}",
        a.commands
    );
    leaks(without_log(&a, "apply"), "apply");
    for mode in [FakeChange::SucceedWithoutChange, FakeChange::Fail] {
        let failing = t();
        failing.el().lock().unwrap().osbase.timezone_set = mode;
        let rep = apply(&r, failing);
        assert_ne!(rep.status, AggregateStatus::Success);
        leaks(without_log(&rep, "apply"), "failure");
    }
    let au = audit(&r, t());
    let mut texts = vec![au.render_text(), format!("{:?}", au.resources)];
    for fmt in [OutputFormat::Text, OutputFormat::Json] {
        let ro = RenderOptions {
            verbose: true,
            format: fmt,
            color: false,
        };
        let mut b = Vec::new();
        sinter::output::render_audit(&au, &ro, &mut b).unwrap();
        texts.push(String::from_utf8_lossy(&b).to_string());
    }
    leaks(texts, "audit");
}
