//! `locale` against the scripted in-process target.
//!
//! These run the production loader, engine, audit and output code against
//! [`FakeTarget`], whose `localectl set-locale` rewrites the locale file on
//! the scripted filesystem and whose `locale -a` answers a list. They prove
//! Sinter's own decisions, argv and order. What only a real host can show
//! (the real tools' output and exit codes, how `localectl` rewrites the file
//! on each OS and whether it keeps keys it is not given, the effect on
//! sessions) is NOT verified here.
#![cfg(unix)]

mod common;

use common::*;
use sinter::audit::{AuditReport, AuditResourceStatus};
use sinter::engine::{AggregateStatus, Mode, RunReport};
use sinter::executor::{FakeTarget, FsEventAction};
use sinter::fake_el::FakeChange;
use sinter::fake_host::FakeRead;
use sinter::output::{OutputFormat, RenderOptions};
use sinter::result::{Change, DiffBody, Execution, Verification};
use std::path::{Path, PathBuf};

const TOOL: &str = "/usr/bin/localectl";
const LIST: &str = "/usr/bin/locale";
const RHEL: &str = "/etc/locale.conf";
const DEB: &str = "/etc/default/locale";

/// The list `locale -a` printed on Rocky Linux 10.2 (measured, shortened).
const LOCALES: &[&str] = &[
    "C",
    "C.utf8",
    "POSIX",
    "en_US",
    "en_US.iso885915",
    "en_US.utf8",
    "en_GB.utf8",
    "ja_JP.utf8",
];

fn doc(with: &str) -> String {
    format!("version: 1\nresources:\n  - id: l\n    type: locale\n    with:\n{with}")
}

fn lang(v: &str) -> String {
    doc(&format!("      lang: {v}\n"))
}

fn recipe(label: &str, yaml: &str) -> PathBuf {
    write_recipe(&trusted_root(label), "r.yaml", yaml)
}

/// A Rocky Linux 9 target as root with `/etc/locale.conf` holding `content`.
fn fake(content: Option<&str>) -> FakeTarget {
    FakeTarget::rocky9()
        .with_fake_fs()
        .as_root()
        .with_locales(LOCALES, content)
}

fn ubuntu(content: Option<&str>) -> FakeTarget {
    FakeTarget::ubuntu2404()
        .with_fake_fs()
        .as_root()
        .with_locales(LOCALES, content)
}

fn file_after(rep: &RunReport, path: &str) -> Option<String> {
    rep.fake_fs
        .as_ref()
        .unwrap()
        .file_bytes(path)
        .map(|b| String::from_utf8(b).unwrap())
}

fn sets(t: &FakeTarget) -> Vec<String> {
    t.el()
        .lock()
        .unwrap()
        .osbase
        .localectl_calls
        .iter()
        .map(|a| a.join(" "))
        .collect()
}

fn lists(t: &FakeTarget) -> usize {
    t.el().lock().unwrap().osbase.locale_calls.len()
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
    find(rep, "l").reason.clone().unwrap_or_default()
}

fn nodes(t: &FakeTarget) -> String {
    format!("{:?}", t.fs.as_ref().unwrap().nodes)
}

fn nodes_after(rep: &RunReport) -> String {
    format!("{:?}", rep.fake_fs.as_ref().unwrap().nodes)
}

/// A run that must not succeed and must not have run `localectl`: why.
fn refused(r: &Path, mode: Mode, t: FakeTarget) -> String {
    let fs_before = nodes(&t);
    let why = match try_run_recipe_fake(r, mode, false, t.clone()) {
        Ok(rep) => {
            assert_ne!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
            assert_eq!(find(&rep, "l").change, Change::None, "{:?}", rep.resources);
            assert_eq!(nodes_after(&rep), fs_before);
            reason(&rep)
        }
        Err(e) => e.message,
    };
    assert!(sets(&t).is_empty(), "localectl ran: {:?}", sets(&t));
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

fn has_sessions_note(rep: &RunReport) -> bool {
    find(rep, "l")
        .notes
        .iter()
        .any(|n| n.contains("new logins") && n.contains("restarts nothing"))
}

// ---------------------------------------------------------------------------
// load
// ---------------------------------------------------------------------------

#[test]
fn invalid_declarations_are_rejected_at_load() {
    for (label, with, want) in [
        ("lo-l1", "      lang: en-US\n", "not a locale name"),
        (
            "lo-l2",
            "      lang: \"en_US.UTF-8 x\"\n",
            "not a locale name",
        ),
        ("lo-l3", "      lang: \"-C\"\n", "not a locale name"),
        ("lo-l4", "      lang: 42\n", "must be a string"),
        (
            "lo-l5",
            "      lc:\n        LC_ALL: C\n",
            "LC_ALL is not accepted",
        ),
        (
            "lo-l6",
            "      lc:\n        LANGUAGE: en\n",
            "LANGUAGE is not accepted",
        ),
        ("lo-l7", "      lc:\n        LC_FOO: C\n", "is not one of"),
        (
            "lo-l8",
            "      lc:\n        LANG: C\n",
            "declare it as lang",
        ),
        ("lo-l9", "      lc: C\n", "must be a map"),
        ("lo-l10", "      lc: {}\n", "declares nothing"),
        (
            "lo-l11",
            "      lc:\n        LC_TIME: \"$(id)\"\n",
            "not a locale name",
        ),
        (
            "lo-l12",
            "      lc:\n        LC_TIME: \"{{ vars.t }}\"\n",
            "literal locale name",
        ),
        ("lo-l13", "      charset: utf8\n", "charset"),
    ] {
        let e = load_err(label, &doc(with));
        assert!(e.contains(want), "{label}: {e}");
    }
    let e = load_err(
        "lo-l14",
        "version: 1\nresources:\n  - id: l\n    type: locale\n    with: {}\n",
    );
    assert!(e.contains("declares nothing"), "{e}");
    // lang may come from a variable, and is checked once resolved.
    sinter::model::load_model(&recipe(
        "lo-l15",
        "version: 1\nvars:\n  l: { value: ja_JP.UTF-8 }\nresources:\n  - id: l\n    type: locale\n    with:\n      lang: \"{{ vars.l }}\"\n",
    ))
    .unwrap();
    let e = load_err(
        "lo-l16",
        "version: 1\nvars:\n  l: { value: \"en US\" }\nresources:\n  - id: l\n    type: locale\n    with:\n      lang: \"{{ vars.l }}\"\n",
    );
    assert!(e.contains("not a locale name"), "{e}");
    let e = load_err(
        "lo-l17",
        "version: 1\nresources:\n  - id: l\n    type: locale\n    with:\n      lang: \"{{ facts.os.family }}\"\n",
    );
    assert!(e.contains("lang"), "{e}");
    sinter::model::load_model(&recipe(
        "lo-l18",
        &doc("      lang: C.UTF-8\n      lc:\n        LC_TIME: en_GB.UTF-8\n        LC_PAPER: POSIX\n"),
    ))
    .unwrap();
}

#[test]
fn conflicting_declarations_in_one_recipe_are_rejected() {
    let two = "version: 1\nresources:\n  - id: first\n    type: locale\n    with:\n      lang: C\n  - id: second\n    type: locale\n    with:\n      lang: C\n";
    let e = load_err("lo-two", two);
    assert!(
        e.contains("conflicting ownership of the system default locale")
            && e.contains("first")
            && e.contains("second"),
        "{e}"
    );
    let l = "  - id: l\n    type: locale\n    with:\n      lang: C\n";
    for (i, path) in [RHEL, DEB].iter().enumerate() {
        let others = [
            format!("  - id: other\n    type: file\n    with:\n      path: {path}\n      content: \"LANG=C\\n\"\n"),
            format!("  - id: other\n    type: file_merge\n    with:\n      path: {path}\n      merge: key_value\n      key: LANG\n      value: C\n"),
        ];
        for (k, other) in others.iter().enumerate() {
            for (j, body) in [format!("{l}{other}"), format!("{other}{l}")]
                .iter()
                .enumerate()
            {
                let e = load_err(
                    &format!("lo-own-{i}-{k}-{j}"),
                    &format!("version: 1\nresources:\n{body}"),
                );
                assert!(
                    e.contains(path) && e.contains("other") && e.contains(" l"),
                    "{path} {k}/{j}: {e}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// plan and apply
// ---------------------------------------------------------------------------

#[test]
fn plan_reports_the_declared_keys_and_does_not_mutate() {
    let r = recipe(
        "lo-p",
        &doc("      lang: ja_JP.UTF-8\n      lc:\n        LC_TIME: en_GB.UTF-8\n"),
    );
    let t = fake(Some("LANG=en_US.UTF-8\n"));
    let before = nodes(&t);
    let rep = plan(&r, t.clone());
    assert_eq!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
    let l = find(&rep, "l");
    assert_eq!(l.change, Change::Changed, "{l:?}");
    assert_eq!(
        l.diff.as_ref().map(|d| d.body.clone()),
        Some(DiffBody::Summary {
            current: "LANG=en_US.UTF-8 LC_TIME=(not set)".into(),
            desired: "LANG=ja_JP.UTF-8 LC_TIME=en_GB.UTF-8".into()
        })
    );
    assert!(has_sessions_note(&rep), "{:?}", l.notes);
    assert!(sets(&t).is_empty());
    assert_eq!(lists(&t), 1);
    assert_eq!(mutation_command_count(&rep), 0);
    assert_eq!(nodes_after(&rep), before);
}

#[test]
fn apply_sets_every_declared_key_keeps_others_and_verifies_by_reading_again() {
    let r = recipe(
        "lo-a",
        &doc("      lang: en_US.UTF-8\n      lc:\n        LC_TIME: en_GB.UTF-8\n"),
    );
    let t = fake(Some(
        "# synthetic comment\nLANG=en_US.UTF-8\nLC_PAPER=en_US.UTF-8\n",
    ));
    let rep = apply(&r, t.clone());
    assert_success(&rep);
    let l = find(&rep, "l");
    assert_eq!(
        (l.execution, l.change, l.verification),
        (
            Execution::Succeeded,
            Change::Changed,
            Verification::Verified
        ),
        "{l:?}"
    );
    // Every declared key, the one already set included.
    assert_eq!(
        sets(&t),
        ["set-locale LANG=en_US.UTF-8 LC_TIME=en_GB.UTF-8"]
    );
    let after = file_after(&rep, RHEL).unwrap();
    assert!(after.contains("LC_TIME=en_GB.UTF-8"), "{after}");
    assert!(after.contains("LC_PAPER=en_US.UTF-8"), "{after}");
    assert!(has_sessions_note(&rep));
    assert!(
        !l.notes.iter().any(|n| n.contains("does not manage")),
        "{:?}",
        l.notes
    );
    // Sinter never writes the file itself.
    assert!(!rep
        .commands
        .iter()
        .any(|c| c.program != TOOL && is_mutation_command(&c.program, &c.args)));
}

#[test]
fn a_host_already_set_is_unchanged_and_nothing_is_listed_or_run() {
    let r = recipe("lo-i", &lang("en_US.UTF-8"));
    let t = fake(Some("LANG=en_US.UTF-8\nLC_TIME=C\n"));
    for mode in [Mode::Plan, Mode::Apply] {
        let rep = run_recipe_fake(&r, mode, false, t.clone());
        assert_success(&rep);
        let l = find(&rep, "l");
        assert_eq!(l.change, Change::None, "{l:?}");
        assert!(l.notes.is_empty(), "{:?}", l.notes);
    }
    assert!(sets(&t).is_empty());
    assert_eq!(lists(&t), 0);
    let a = audit(&r, t.clone());
    assert_eq!(a.resources[0].status, AuditResourceStatus::Compliant);

    // A second apply after a change runs nothing.
    let t = fake(Some("LANG=C.UTF-8\n"));
    let first = apply(&r, t.clone());
    assert_success(&first);
    let mut t2 = t.clone();
    t2.fs = first.fake_fs.clone();
    let second = apply(&r, t2);
    assert_success(&second);
    assert_eq!(find(&second, "l").change, Change::None);
    assert_eq!(sets(&t).len(), 1);
}

#[test]
fn a_missing_file_sets_no_key_and_is_created_by_the_tool() {
    let r = recipe("lo-miss", &lang("C.UTF-8"));
    let t = fake(None);
    let p = plan(&r, t.clone());
    assert_eq!(
        find(&p, "l").diff.as_ref().map(|d| d.body.clone()),
        Some(DiffBody::Summary {
            current: "LANG=(not set)".into(),
            desired: "LANG=C.UTF-8".into()
        })
    );
    // C and POSIX need no list.
    assert_eq!(lists(&t), 0);
    let rep = apply(&r, t.clone());
    assert_success(&rep);
    assert_eq!(file_after(&rep, RHEL).unwrap(), "LANG=C.UTF-8\n");
    let a = audit(&r, fake(None));
    assert_eq!(a.resources[0].status, AuditResourceStatus::Drift);
    assert_eq!(a.resources[0].details[0].observed, "(not set)");
}

#[test]
fn debian_family_hosts_use_etc_default_locale() {
    let r = recipe(
        "lo-deb",
        &doc("      lang: ja_JP.UTF-8\n      lc:\n        LC_MESSAGES: C.UTF-8\n"),
    );
    let t = ubuntu(Some(
        "#  File generated by update-locale\nLANG=\"en_US.UTF-8\"\n",
    ));
    let rep = apply(&r, t.clone());
    assert_success(&rep);
    let after = file_after(&rep, DEB).unwrap();
    assert!(
        after.contains("LANG=ja_JP.UTF-8") && after.contains("LC_MESSAGES=C.UTF-8"),
        "{after}"
    );
    assert!(file_after(&rep, RHEL).is_none());
    // The quoted form is read as the same value.
    let r = recipe("lo-deb-i", &lang("en_US.UTF-8"));
    let rep = apply(&r, ubuntu(Some("LANG=\"en_US.UTF-8\"\n")));
    assert_success(&rep);
    assert_eq!(find(&rep, "l").change, Change::None);
}

#[test]
fn an_unknown_os_family_is_refused_clearly() {
    let r = recipe("lo-os", &lang("C.UTF-8"));
    let t = FakeTarget::unsupported()
        .with_fake_fs()
        .as_root()
        .with_locales(LOCALES, Some("LANG=en_US.UTF-8\n"));
    for mode in [Mode::Plan, Mode::Apply] {
        let why = refused(&r, mode, t.clone());
        assert!(
            why.contains("locale is not supported on this host")
                && why.contains("Red Hat family")
                && why.contains("Debian family"),
            "{mode:?}: {why}"
        );
    }
    let a = audit(&r, t);
    assert_eq!(a.resources[0].status, AuditResourceStatus::Error);
}

#[test]
fn a_locale_that_is_not_installed_is_refused_unless_an_earlier_change_may_provide_it() {
    let r = recipe("lo-ni", &lang("de_DE.UTF-8"));
    for mode in [Mode::Plan, Mode::Apply] {
        let why = refused(&r, mode, fake(Some("LANG=C\n")));
        assert!(
            why.contains("locale \"de_DE.UTF-8\" is not installed on this host")
                && why.contains("Sinter does not do that"),
            "{mode:?}: {why}"
        );
    }
    // Codesets are compared loosely: ISO-8859-15 is en_US.iso885915.
    let r2 = recipe("lo-iso", &lang("en_US.ISO-8859-15"));
    assert_success(&apply(&r2, fake(Some("LANG=C\n"))));

    let yaml = "version: 1\nresources:\n  - id: pack\n    type: package\n    with:\n      name: glibc-langpack-de\n      state: present\n  - id: l\n    type: locale\n    depends_on: [pack]\n    with:\n      lang: de_DE.UTF-8\n";
    let r = recipe("lo-ni-deferred", yaml);
    let rep = plan(&r, fake(Some("LANG=C\n")));
    assert_eq!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
    assert!(
        find(&rep, "l")
            .notes
            .iter()
            .any(|n| n.contains("checked again at apply")),
        "{:?}",
        find(&rep, "l")
    );
}

#[test]
fn a_failed_or_damaged_locale_list_is_an_error_not_absence() {
    let r = recipe("lo-list", &lang("ja_JP.UTF-8"));
    for mode in [
        FakeRead::Fail,
        FakeRead::Empty,
        FakeRead::Truncated,
        FakeRead::Killed,
        FakeRead::Indeterminate,
    ] {
        let t = fake(Some("LANG=C\n"));
        t.el()
            .lock()
            .unwrap()
            .osbase
            .locale_list_reads
            .push_back(mode);
        let why = refused(&r, Mode::Apply, t);
        assert!(
            why.contains("installed locales could not be listed"),
            "{mode:?}: {why}"
        );
    }
    let mut t = fake(Some("LANG=C\n"));
    t.executables.remove(LIST);
    let why = refused(&r, Mode::Plan, t);
    assert!(why.contains("/usr/bin/locale was not found"), "{why}");
}

#[test]
fn a_host_without_localectl_is_refused_clearly() {
    let r = recipe("lo-tool", &lang("ja_JP.UTF-8"));
    let mut t = fake(Some("LANG=C\n"));
    t.executables.remove(TOOL);
    for mode in [Mode::Plan, Mode::Apply] {
        let why = refused(&r, mode, t.clone());
        assert!(
            why.contains("locale is not supported on this host")
                && why.contains("/usr/bin/localectl was not found"),
            "{mode:?}: {why}"
        );
    }
    // Audit reads the file only.
    let a = audit(&r, t);
    assert_eq!(a.resources[0].status, AuditResourceStatus::Drift);
}

#[test]
fn a_file_outside_the_closed_grammar_or_a_symlink_is_an_error_not_a_state() {
    let r = recipe("lo-bad", &lang("C.UTF-8"));
    for content in [
        "LANG=en_US.UTF-8\nLANG=C\n",
        "LANG='en_US.UTF-8'\n",
        "export LANG=en_US.UTF-8\n",
        "LANG=$(synthetic)\n",
        "LANG=C\r\n",
    ] {
        for mode in [Mode::Plan, Mode::Apply] {
            let why = refused(&r, mode, fake(Some(content)));
            assert!(
                why.contains("is not understood"),
                "{content:?} {mode:?}: {why}"
            );
        }
        let a = audit(&r, fake(Some(content)));
        assert_eq!(
            a.resources[0].status,
            AuditResourceStatus::Error,
            "{content:?}"
        );
    }
    let mut t = fake(None);
    t.fs.as_mut()
        .unwrap()
        .put_file("/etc/locale.real", b"LANG=C.UTF-8\n", 0o644, 0, 0);
    t.fs.as_mut()
        .unwrap()
        .put_symlink(RHEL, "/etc/locale.real", 0, 0);
    let why = refused(&r, Mode::Apply, t.clone());
    assert!(why.contains("symlink"), "{why}");
    let a = audit(&r, t);
    assert_eq!(a.resources[0].status, AuditResourceStatus::Error);

    // A directory another account controls is not looked into.
    let mut t = ubuntu(None);
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/etc/default", 0o777, 1000, 1000);
    let why = refused(&r, Mode::Plan, t);
    assert!(why.contains("/etc/default"), "{why}");
}

// ---------------------------------------------------------------------------
// failures of the change
// ---------------------------------------------------------------------------

#[test]
fn a_failing_change_or_exit_zero_without_the_values_is_a_failure() {
    let r = recipe("lo-f", &lang("ja_JP.UTF-8"));
    let t = fake(Some("LANG=en_US.UTF-8\n"));
    t.el().lock().unwrap().osbase.locale_set = FakeChange::Fail;
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    let l = find(&rep, "l");
    assert_eq!(
        (l.execution, l.change, l.verification),
        (Execution::Failed, Change::Possible, Verification::Unknown),
        "{l:?}"
    );
    assert!(
        reason(&rep).contains("failed with exit code 1"),
        "{}",
        reason(&rep)
    );

    let t = fake(Some("LANG=en_US.UTF-8\n"));
    t.el().lock().unwrap().osbase.locale_set = FakeChange::SucceedWithoutChange;
    let rep = apply(&r, t);
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    let l = find(&rep, "l");
    assert_eq!(
        (l.execution, l.change, l.verification),
        (Execution::Failed, Change::Possible, Verification::Failed),
        "{l:?}"
    );
    assert!(
        reason(&rep).contains("has LANG=en_US.UTF-8 (declared: LANG=ja_JP.UTF-8)"),
        "{}",
        reason(&rep)
    );
}

#[test]
fn a_signal_or_timeout_of_the_change_is_indeterminate_never_success() {
    let r = recipe("lo-ind", &lang("ja_JP.UTF-8"));
    for mode in [
        FakeChange::KilledAfterChange,
        FakeChange::IndeterminateAfterChange,
    ] {
        let t = fake(Some("LANG=en_US.UTF-8\n"));
        t.el().lock().unwrap().osbase.locale_set = mode;
        let rep = apply(&r, t);
        assert_ne!(rep.status, AggregateStatus::Success, "{mode:?}");
        let l = find(&rep, "l");
        assert_eq!(
            (l.execution, l.change, l.verification),
            (
                Execution::Indeterminate,
                Change::Possible,
                Verification::Unknown
            ),
            "{mode:?}: {l:?}"
        );
        assert!(reason(&rep).contains("may or may not"), "{}", reason(&rep));
        let at = rep.commands.iter().position(|c| c.program == TOOL).unwrap();
        assert!(
            !rep.commands[at + 1..]
                .iter()
                .any(|c| c.args.iter().any(|a| a == RHEL)),
            "{mode:?}: {:?}",
            rep.commands
        );
    }
}

#[test]
fn a_tool_that_replaces_the_whole_set_keeps_declared_keys_and_says_what_it_dropped() {
    let r = recipe(
        "lo-repl",
        &doc("      lang: en_US.UTF-8\n      lc:\n        LC_TIME: en_GB.UTF-8\n"),
    );
    let t = fake(Some("LANG=en_US.UTF-8\nLC_PAPER=en_US.UTF-8\n"));
    t.el().lock().unwrap().osbase.locale_replaces_all = true;
    let rep = apply(&r, t);
    assert_success(&rep);
    let after = file_after(&rep, RHEL).unwrap();
    assert_eq!(after, "LANG=en_US.UTF-8\nLC_TIME=en_GB.UTF-8\n");
    assert!(
        find(&rep, "l")
            .notes
            .iter()
            .any(|n| n.contains("Sinter does not manage: LC_PAPER")),
        "{:?}",
        find(&rep, "l").notes
    );
}

// ---------------------------------------------------------------------------
// privilege
// ---------------------------------------------------------------------------

#[test]
fn a_change_needs_root_and_plan_says_so() {
    let r = recipe("lo-root", &lang("ja_JP.UTF-8"));
    let user = || {
        FakeTarget::rocky9()
            .with_fake_fs()
            .with_locales(LOCALES, Some("LANG=en_US.UTF-8\n"))
    };
    let p = plan(&r, user());
    assert!(
        find(&p, "l").notes.iter().any(|n| n.contains("needs root")),
        "{:?}",
        find(&p, "l").notes
    );
    let why = refused(&r, Mode::Apply, user());
    assert!(why.contains("needs root"), "{why}");
    let t = user();
    assert_success(&run_recipe_fake(&r, Mode::Apply, true, t.clone()));
    assert_eq!(sets(&t), ["set-locale LANG=ja_JP.UTF-8"]);
}

// ---------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------

#[test]
fn audit_reports_one_dimension_per_declared_key_and_does_not_mutate() {
    let r = recipe(
        "lo-au",
        &doc("      lang: en_US.UTF-8\n      lc:\n        LC_TIME: en_GB.UTF-8\n        LC_PAPER: C\n"),
    );
    let t = fake(Some("LANG=en_US.UTF-8\nLC_TIME=C.UTF-8\nLC_NAME=C\n"));
    let before = nodes(&t);
    let a = audit(&r, t.clone());
    assert_eq!(a.resources[0].status, AuditResourceStatus::Drift);
    let d: Vec<(String, String, String)> = a.resources[0]
        .details
        .iter()
        .map(|d| (d.dimension.clone(), d.observed.clone(), d.desired.clone()))
        .collect();
    assert_eq!(
        d,
        [
            ("LC_PAPER".into(), "(not set)".into(), "C".into()),
            ("LC_TIME".into(), "C.UTF-8".into(), "en_GB.UTF-8".into()),
        ]
    );
    assert!(sets(&t).is_empty());
    assert_eq!(lists(&t), 0);
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
fn a_sensitive_resource_names_no_value_in_any_output() {
    let yaml = "version: 1\nresources:\n  - id: l\n    type: locale\n    sensitive: true\n    with:\n      lang: ja_JP.UTF-8\n";
    let r = recipe("lo-sens", yaml);
    let t = || fake(Some("LANG=en_GB.UTF-8\n"));
    let leaks = |texts: Vec<String>, what: &str| {
        for s in texts {
            assert!(!s.contains("ja_JP") && !s.contains("en_GB"), "{what}: {s}");
        }
    };
    leaks(surfaces(&plan(&r, t()), "plan"), "plan");
    let a = apply(&r, t());
    assert_success(&a);
    leaks(surfaces(&a, "apply"), "apply");
    for mode in [FakeChange::SucceedWithoutChange, FakeChange::Fail] {
        let failing = t();
        failing.el().lock().unwrap().osbase.locale_set = mode;
        let rep = apply(&r, failing);
        assert_ne!(rep.status, AggregateStatus::Success);
        leaks(surfaces(&rep, "apply"), "failure");
    }
    let missing = recipe(
        "lo-sens-missing",
        "version: 1\nresources:\n  - id: l\n    type: locale\n    sensitive: true\n    with:\n      lang: de_DE.UTF-8\n",
    );
    match try_run_recipe_fake(&missing, Mode::Plan, false, t()) {
        Ok(rep) => {
            for s in surfaces(&rep, "plan") {
                assert!(!s.contains("de_DE"), "missing: {s}");
            }
        }
        Err(e) => assert!(!e.message.contains("de_DE"), "{}", e.message),
    }
    let au = audit(&r, t());
    let mut texts = vec![
        au.render_text(),
        format!("{:?}", au.resources),
        format!("{:?}", au.commands),
    ];
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

// ---------------------------------------------------------------------------
// the Debian family's link to /etc/locale.conf (DESIGN §61, v1.16.0 RC 3:
// Ubuntu 24.04 ships /etc/default/locale -> ../locale.conf)
// ---------------------------------------------------------------------------

fn ubuntu_linked(content: Option<&str>, link: &str, writes: &str) -> FakeTarget {
    FakeTarget::ubuntu2404()
        .with_fake_fs()
        .as_root()
        .with_locales_linked(LOCALES, content, link, writes)
}

fn link_after(rep: &RunReport) -> Option<String> {
    match rep
        .fake_fs
        .as_ref()
        .unwrap()
        .nodes
        .get(DEB)
        .map(|n| &n.kind)
    {
        Some(sinter::fakesys::FakeKind::Symlink(t)) => Some(t.clone()),
        _ => None,
    }
}

#[test]
fn the_os_link_to_etc_locale_conf_is_followed_and_kept() {
    let r = recipe("lo-link", &lang("ja_JP.UTF-8"));
    for link in ["../locale.conf", "/etc/locale.conf"] {
        let t = ubuntu_linked(Some("LANG=C.UTF-8\n"), link, RHEL);
        let p = plan(&r, t.clone());
        assert_success(&p);
        assert_eq!(find(&p, "l").change, Change::Changed, "{link}");
        assert!(sets(&t).is_empty(), "plan ran localectl");
        let rep = apply(&r, t.clone());
        assert_success(&rep);
        let l = find(&rep, "l");
        assert_eq!(l.verification, Verification::Verified, "{link} {:?}", l);
        assert_eq!(link_after(&rep).as_deref(), Some(link), "the link is kept");
        assert!(file_after(&rep, RHEL).unwrap().contains("LANG=ja_JP.UTF-8"));
        // Already set through the link: unchanged, compliant.
        let t2 = ubuntu_linked(Some("LANG=ja_JP.UTF-8\n"), link, RHEL);
        let rep = apply(&r, t2.clone());
        assert_eq!(find(&rep, "l").change, Change::None, "{link}");
        let a = audit(&r, t2);
        assert_eq!(
            a.resources[0].status,
            AuditResourceStatus::Compliant,
            "{link}"
        );
        let a = audit(&r, ubuntu_linked(Some("LANG=C.UTF-8\n"), link, RHEL));
        assert_eq!(a.resources[0].status, AuditResourceStatus::Drift, "{link}");
    }
}

#[test]
fn a_dangling_os_link_sets_no_key_and_the_tool_creates_the_file() {
    let r = recipe("lo-link-dangling", &lang("ja_JP.UTF-8"));
    let t = ubuntu_linked(None, "../locale.conf", RHEL);
    let rep = apply(&r, t);
    assert_success(&rep);
    assert_eq!(link_after(&rep).as_deref(), Some("../locale.conf"));
    assert!(file_after(&rep, RHEL).unwrap().contains("LANG=ja_JP.UTF-8"));
}

#[test]
fn any_other_link_is_refused_in_plan_apply_and_audit() {
    let r = recipe("lo-link-other", &lang("ja_JP.UTF-8"));
    // another target, also one that names the same file another way
    for link in [
        "/etc/locale.real",
        "locale.conf",
        "../../etc/locale.conf",
        "/etc/./locale.conf",
        "../default/locale",
    ] {
        let mut t = ubuntu_linked(Some("LANG=C.UTF-8\n"), link, RHEL);
        t.fs.as_mut()
            .unwrap()
            .put_file("/etc/locale.real", b"LANG=C.UTF-8\n", 0o644, 0, 0);
        for mode in [Mode::Plan, Mode::Apply] {
            let why = refused(&r, mode, t.clone());
            assert!(why.contains("to another target"), "{link} {mode:?}: {why}");
        }
        let a = audit(&r, t);
        assert_eq!(a.resources[0].status, AuditResourceStatus::Error, "{link}");
    }
    // the known text, owned by another account
    let mut t = ubuntu_linked(Some("LANG=C.UTF-8\n"), "../locale.conf", RHEL);
    t.fs.as_mut()
        .unwrap()
        .put_symlink(DEB, "../locale.conf", 1000, 1000);
    let why = refused(&r, Mode::Apply, t.clone());
    assert!(why.contains("not owned by root"), "{why}");
    assert_eq!(audit(&r, t).resources[0].status, AuditResourceStatus::Error);
    // a chain: /etc/locale.conf is itself a link
    let mut t = ubuntu_linked(None, "../locale.conf", RHEL);
    t.fs.as_mut()
        .unwrap()
        .put_file("/etc/locale.real", b"LANG=C.UTF-8\n", 0o644, 0, 0);
    t.fs.as_mut()
        .unwrap()
        .put_symlink(RHEL, "/etc/locale.real", 0, 0);
    let why = refused(&r, Mode::Apply, t.clone());
    assert!(why.contains("symlink"), "{why}");
    assert_eq!(audit(&r, t).resources[0].status, AuditResourceStatus::Error);
    // /etc/locale.conf is another object type
    let mut t = ubuntu_linked(None, "../locale.conf", RHEL);
    t.fs.as_mut().unwrap().mkdir_node(RHEL, 0o755, 0, 0);
    let why = refused(&r, Mode::Plan, t);
    assert!(why.contains(RHEL), "{why}");
    // a parent another account controls is not looked into
    let mut t = ubuntu_linked(Some("LANG=C.UTF-8\n"), "../locale.conf", RHEL);
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/etc/default", 0o777, 1000, 1000);
    let why = refused(&r, Mode::Plan, t);
    assert!(why.contains("/etc/default"), "{why}");
}

#[test]
fn a_link_retargeted_while_it_is_read_is_refused() {
    let r = recipe("lo-link-race", &lang("ja_JP.UTF-8"));
    let t = ubuntu_linked(Some("LANG=C.UTF-8\n"), "../locale.conf", RHEL).with_fs_event(
        "readlink",
        DEB,
        1,
        vec![FsEventAction::PutSymlink {
            path: DEB.into(),
            target: "/etc/locale.real".into(),
            uid: 0,
            gid: 0,
        }],
    );
    // (the event itself changes the filesystem, so `refused` is not used)
    let rep = try_run_recipe_fake(&r, Mode::Apply, false, t.clone()).unwrap();
    assert_ne!(rep.status, AggregateStatus::Success);
    assert_eq!(find(&rep, "l").change, Change::None);
    assert!(sets(&t).is_empty(), "localectl ran");
    let why = reason(&rep);
    assert!(why.contains("changed while it was read"), "{why}");
}

#[test]
fn a_tool_that_replaces_the_os_link_is_a_failure_not_success() {
    let r = recipe("lo-link-replaced", &lang("ja_JP.UTF-8"));
    let t = ubuntu_linked(Some("LANG=C.UTF-8\n"), "../locale.conf", DEB);
    let rep = apply(&r, t);
    let l = find(&rep, "l");
    assert_eq!(l.execution, Execution::Failed, "{l:?}");
    assert_eq!(l.change, Change::Changed);
    assert_eq!(l.verification, Verification::Failed);
    let why = l.reason.clone().unwrap_or_default();
    assert!(
        why.contains("localectl changed how /etc/default/locale is kept"),
        "{why}"
    );
    assert!(link_after(&rep).is_none());
}

#[test]
fn a_sensitive_resource_names_no_link_and_no_value() {
    let r = recipe(
        "lo-link-sens",
        "version: 1\nresources:\n  - id: l\n    type: locale\n    sensitive: true\n    with:\n      lang: ja_JP.UTF-8\n",
    );
    let mut t = ubuntu_linked(Some("LANG=C.UTF-8\n"), "/etc/locale.real", RHEL);
    t.fs.as_mut()
        .unwrap()
        .put_file("/etc/locale.real", b"LANG=C.UTF-8\n", 0o644, 0, 0);
    let why = refused(&r, Mode::Apply, t);
    assert!(why.contains("details withheld"), "{why}");
    assert!(
        !why.contains("locale.real") && !why.contains("ja_JP"),
        "{why}"
    );
}

#[test]
fn a_replaced_link_of_a_sensitive_resource_names_no_link() {
    let r = recipe(
        "lo-link-sens-replaced",
        "version: 1\nresources:\n  - id: l\n    type: locale\n    sensitive: true\n    with:\n      lang: ja_JP.UTF-8\n",
    );
    let rep = apply(
        &r,
        ubuntu_linked(Some("LANG=C.UTF-8\n"), "../locale.conf", DEB),
    );
    let l = find(&rep, "l");
    assert_eq!(l.verification, Verification::Failed);
    let why = l.reason.clone().unwrap_or_default();
    assert!(why.contains("details withheld"), "{why}");
    assert!(
        !why.contains("../locale.conf") && !why.contains("ja_JP"),
        "{why}"
    );
}

#[test]
fn a_linked_locale_conf_with_a_second_hard_link_is_refused() {
    let r = recipe("lo-link-hard", &lang("ja_JP.UTF-8"));
    let mk = || {
        let mut t = ubuntu_linked(Some("LANG=C.UTF-8\n"), "../locale.conf", RHEL);
        t.fs.as_mut()
            .unwrap()
            .put_hardlink(RHEL, "/etc/locale.other");
        t
    };
    for mode in [Mode::Plan, Mode::Apply] {
        let why = refused(&r, mode, mk());
        assert!(why.contains("2 hard links"), "{mode:?}: {why}");
    }
    assert_eq!(
        audit(&r, mk()).resources[0].status,
        AuditResourceStatus::Error
    );
}
