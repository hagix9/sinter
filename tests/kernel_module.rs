//! `kernel_module` against the scripted in-process target.
//!
//! These run the production loader, engine, audit and output code against
//! [`FakeTarget`], whose `modprobe` answers a dry run from a set of
//! available modules and loads a module by creating `/sys/module/<name>` on
//! the scripted filesystem. They prove Sinter's own decisions, argv, files
//! and order. What only a real host can show (the real tool's output and
//! exit codes, that `modprobe -n` changes nothing, how built-in modules
//! appear in `/sys/module`, what systemd-modules-load and modprobe make of
//! the files at boot) is NOT verified here.
#![cfg(unix)]

mod common;

use common::*;
use sinter::audit::{AuditReport, AuditResourceStatus};
use sinter::engine::{AggregateStatus, Mode, RunReport};
use sinter::executor::{FakeTarget, FsEventAction};
use sinter::fake_el::FakeChange;
use sinter::fake_host::FakeRead;
use sinter::output::{OutputFormat, RenderOptions};
use sinter::result::{Change, Execution, Verification};
use std::path::{Path, PathBuf};

const TOOL: &str = "/usr/sbin/modprobe";
const LOAD: &str = "/etc/modules-load.d/sinter-br_netfilter.conf";
const BLACK: &str = "/etc/modprobe.d/sinter-blacklist-br_netfilter.conf";
const SYS: &str = "/sys/module/br_netfilter";
const LOAD_TEXT: &str =
    "# Managed by Sinter (kernel_module). Local changes are replaced.\nbr_netfilter\n";
const BLACK_TEXT: &str =
    "# Managed by Sinter (kernel_module). Local changes are replaced.\nblacklist br_netfilter\n";

fn doc(resources: &str) -> String {
    format!("version: 1\nresources:\n{resources}")
}

fn module(extra: &str) -> String {
    doc(&format!(
        "  - id: m\n    type: kernel_module\n    with:\n      name: br-netfilter\n{extra}"
    ))
}

fn recipe(label: &str, yaml: &str) -> PathBuf {
    write_recipe(&trusted_root(label), "r.yaml", yaml)
}

/// A Rocky Linux 9 target as root that can load `br_netfilter` and
/// `dummy`, with `loop` built in (loaded).
fn fake() -> FakeTarget {
    FakeTarget::rocky9()
        .with_fake_fs()
        .as_root()
        .with_modules(&["br_netfilter", "dummy", "loop"], &["loop"])
}

/// [`fake`] after `br_netfilter` was loaded and its file written.
fn converged() -> FakeTarget {
    fake().with_fs_dir(SYS).with_fs_file(LOAD, LOAD_TEXT)
}

fn calls(t: &FakeTarget) -> Vec<String> {
    t.el()
        .lock()
        .unwrap()
        .osbase
        .modprobe_calls
        .iter()
        .map(|a| a.join(" "))
        .collect()
}

fn loads(t: &FakeTarget) -> Vec<String> {
    calls(t)
        .into_iter()
        .filter(|c| !c.starts_with("-n"))
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

fn file_text(rep: &RunReport, path: &str) -> Option<String> {
    rep.fake_fs
        .as_ref()
        .unwrap()
        .file_bytes(path)
        .map(|b| String::from_utf8(b).unwrap())
}

fn exists_after(rep: &RunReport, path: &str) -> bool {
    rep.fake_fs.as_ref().unwrap().nodes.contains_key(path)
}

fn nodes(t: &FakeTarget) -> String {
    format!("{:?}", t.fs.as_ref().unwrap().nodes)
}

fn nodes_after(rep: &RunReport) -> String {
    format!("{:?}", rep.fake_fs.as_ref().unwrap().nodes)
}

fn reason(rep: &RunReport) -> String {
    find(rep, "m").reason.clone().unwrap_or_default()
}

/// A run that must not succeed, change nothing and load nothing: why.
fn refused(r: &Path, mode: Mode, t: FakeTarget) -> String {
    let before = nodes(&t);
    let why = match try_run_recipe_fake(r, mode, false, t.clone()) {
        Ok(rep) => {
            assert_ne!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
            assert_eq!(find(&rep, "m").change, Change::None, "{:?}", rep.resources);
            assert_eq!(nodes_after(&rep), before);
            reason(&rep)
        }
        Err(e) => e.message,
    };
    assert!(loads(&t).is_empty(), "modprobe loaded: {:?}", loads(&t));
    why
}

fn notes(rep: &RunReport) -> String {
    find(rep, "m").notes.join(" | ")
}

// ---------------------------------------------------------------------------
// load
// ---------------------------------------------------------------------------

#[test]
fn invalid_declarations_are_rejected_at_load() {
    let res = |with: &str| {
        doc(&format!(
            "  - id: m\n    type: kernel_module\n    with:\n{with}"
        ))
    };
    for (label, with, want) in [
        ("km-l1", "      name: \"a b\"\n", "not a module name"),
        ("km-l2", "      name: a/b\n", "not a module name"),
        ("km-l3", "      name: dummy.ko\n", "not a module name"),
        ("km-l4", "      name: 7\n", "must be a string"),
        ("km-l5", "      state: present\n", "name is required"),
        (
            "km-l6",
            "      name: dummy\n      state: loaded\n",
            "literal present, absent or blacklisted",
        ),
        (
            "km-l7",
            "      name: dummy\n      state: absent\n      runtime: true\n",
            "only with state: present",
        ),
        (
            "km-l8",
            "      name: dummy\n      state: blacklisted\n      persist: false\n",
            "only with state: present",
        ),
        (
            "km-l9",
            "      name: dummy\n      runtime: false\n      persist: false\n",
            "both false",
        ),
        (
            "km-l10",
            "      name: dummy\n      runtime: \"yes\"\n",
            "literal boolean",
        ),
        ("km-l11", "      name: dummy\n      params: x\n", "params"),
        ("km-l12", "      name: \"{{ facts.hostname }}\"\n", "name"),
    ] {
        let e = load_err(label, &res(with));
        assert!(e.contains(want), "{label}: {e}");
    }
    let long = "a".repeat(65);
    let e = load_err("km-l13", &res(&format!("      name: {long}\n")));
    assert!(e.contains("not a module name"), "{e}");
    sinter::model::load_model(&recipe(
        "km-l14",
        "version: 1\nvars:\n  m: { value: dummy }\nresources:\n  - id: m\n    type: kernel_module\n    with:\n      name: \"{{ vars.m }}\"\n",
    ))
    .unwrap();
}

#[test]
fn conflicting_declarations_in_one_recipe_are_rejected() {
    // `-` and `_` name the same module.
    let two = doc("  - id: a\n    type: kernel_module\n    with:\n      name: br-netfilter\n  - id: b\n    type: kernel_module\n    with:\n      name: br_netfilter\n      state: blacklisted\n");
    let e = load_err("km-two", &two);
    assert!(
        e.contains("conflicting ownership of kernel module br_netfilter")
            && e.contains(" a ")
            && e.contains(" b"),
        "{e}"
    );
    let m = "  - id: m\n    type: kernel_module\n    with:\n      name: br-netfilter\n      state: absent\n";
    for (i, path) in [LOAD, BLACK].iter().enumerate() {
        for (k, other) in [
            format!("  - id: other\n    type: file\n    with:\n      path: {path}\n      content: synthetic\n"),
            format!("  - id: other\n    type: file_merge\n    with:\n      path: {path}\n      merge: line\n      line: synthetic\n"),
        ]
        .iter()
        .enumerate()
        {
            for (j, body) in [format!("{m}{other}"), format!("{other}{m}")].iter().enumerate() {
                let e = load_err(&format!("km-own-{i}-{k}-{j}"), &doc(body));
                assert!(
                    e.contains(path) && e.contains("other") && e.contains(" m"),
                    "{path} {k}/{j}: {e}"
                );
            }
        }
    }
    // Another module's files are someone else's.
    sinter::model::load_model(&recipe(
        "km-own-other",
        &doc(&format!(
            "{m}  - id: other\n    type: file\n    with:\n      path: /etc/modules-load.d/local.conf\n      content: synthetic\n"
        )),
    ))
    .unwrap();
}

// ---------------------------------------------------------------------------
// present
// ---------------------------------------------------------------------------

#[test]
fn plan_reports_the_file_and_the_load_and_does_not_mutate() {
    let r = recipe("km-p", &module(""));
    let t = fake();
    let before = nodes(&t);
    let rep = plan(&r, t.clone());
    assert_eq!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
    let m = find(&rep, "m");
    assert_eq!(m.change, Change::Changed, "{m:?}");
    assert!(
        notes(&rep).contains("module br_netfilter: not loaded -> loaded"),
        "{}",
        notes(&rep)
    );
    assert!(notes(&rep).contains("not evaluated"), "{}", notes(&rep));
    // Only the dry run.
    assert_eq!(calls(&t), ["-n -v -- br_netfilter"]);
    assert_eq!(mutation_command_count(&rep), 0);
    assert_eq!(nodes_after(&rep), before);
}

#[test]
fn apply_writes_the_file_first_then_loads_and_verifies() {
    let r = recipe("km-a", &module(""));
    let t = fake();
    let rep = apply(&r, t.clone());
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
    assert_eq!(file_text(&rep, LOAD).as_deref(), Some(LOAD_TEXT));
    let node = rep
        .fake_fs
        .as_ref()
        .unwrap()
        .nodes
        .get(LOAD)
        .unwrap()
        .clone();
    assert_eq!((node.mode, node.uid, node.gid), (0o644, 0, 0));
    assert!(exists_after(&rep, SYS));
    assert!(!exists_after(&rep, BLACK));
    assert_eq!(calls(&t), ["-n -v -- br_netfilter", "-- br_netfilter"]);
    // The file is published before modprobe runs.
    let publish = rep
        .commands
        .iter()
        .position(|c| c.args.iter().any(|a| a == "publish"))
        .expect("the file was published");
    let load = rep
        .commands
        .iter()
        .position(|c| c.program == TOOL && c.args == ["--", "br_netfilter"])
        .unwrap();
    assert!(publish < load, "{:?}", rep.commands);
    // Nothing unloads.
    assert!(!rep
        .commands
        .iter()
        .any(|c| c.program == TOOL && c.args.iter().any(|a| a == "-r")));
}

#[test]
fn a_converged_target_is_unchanged_and_the_file_is_not_rewritten() {
    let r = recipe("km-i", &module(""));
    let t = converged();
    let before = nodes(&t);
    for mode in [Mode::Plan, Mode::Apply] {
        let rep = run_recipe_fake(&r, mode, false, t.clone());
        assert_success(&rep);
        assert_eq!(
            find(&rep, "m").change,
            Change::None,
            "{:?}",
            find(&rep, "m")
        );
        assert_eq!(nodes_after(&rep), before);
    }
    // A loaded module needs no dry run and no load.
    assert!(calls(&t).is_empty(), "{:?}", calls(&t));
    let a = audit(&r, t);
    assert_eq!(
        a.resources[0].status,
        AuditResourceStatus::Compliant,
        "{:?}",
        a.resources
    );

    // A built-in module that appears in /sys/module counts as loaded.
    let r = recipe(
        "km-builtin",
        &doc("  - id: m\n    type: kernel_module\n    with:\n      name: loop\n      persist: false\n"),
    );
    let t = fake();
    let rep = apply(&r, t.clone());
    assert_success(&rep);
    assert_eq!(find(&rep, "m").change, Change::None);
    assert!(calls(&t).is_empty());
}

#[test]
fn runtime_false_writes_only_the_file_and_persist_false_only_loads() {
    let r = recipe("km-rt", &module("      runtime: false\n"));
    let t = fake();
    let rep = apply(&r, t.clone());
    assert_success(&rep);
    assert_eq!(file_text(&rep, LOAD).as_deref(), Some(LOAD_TEXT));
    assert!(!exists_after(&rep, SYS));
    assert!(calls(&t).is_empty(), "{:?}", calls(&t));
    assert!(notes(&rep).contains("runtime: false"), "{}", notes(&rep));

    let r = recipe("km-ps", &module("      persist: false\n"));
    let t = fake();
    let rep = apply(&r, t.clone());
    assert_success(&rep);
    assert!(file_text(&rep, LOAD).is_none());
    assert!(exists_after(&rep, SYS));
    assert_eq!(loads(&t), ["-- br_netfilter"]);
}

#[test]
fn present_removes_sinters_blacklist_file_only() {
    let r = recipe("km-unbl", &module(""));
    let t = converged()
        .with_fs_file(BLACK, BLACK_TEXT)
        .with_fs_file("/etc/modprobe.d/local.conf", "blacklist br_netfilter\n");
    let rep = apply(&r, t);
    assert_success(&rep);
    assert_eq!(find(&rep, "m").change, Change::Changed);
    assert!(!exists_after(&rep, BLACK));
    // Not Sinter's: kept and not evaluated.
    assert!(file_text(&rep, "/etc/modprobe.d/local.conf").is_some());
}

#[test]
fn an_unknown_module_is_an_error_and_nothing_is_written() {
    let r = recipe(
        "km-unk",
        &doc("  - id: m\n    type: kernel_module\n    with:\n      name: nosuchmod\n"),
    );
    for mode in [Mode::Plan, Mode::Apply] {
        let why = refused(&r, mode, fake());
        assert!(
            why.contains("module nosuchmod is not available for the running kernel")
                && why.contains("FATAL"),
            "{mode:?}: {why}"
        );
    }
    // An earlier planned package may bring it: plan defers the check.
    let yaml = doc("  - id: kmod\n    type: package\n    with:\n      name: kmod-synthetic\n      state: present\n  - id: m\n    type: kernel_module\n    depends_on: [kmod]\n    with:\n      name: nosuchmod\n");
    let rep = plan(&recipe("km-unk-deferred", &yaml), fake());
    assert_eq!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
    assert!(
        notes(&rep).contains("checked again at apply"),
        "{}",
        notes(&rep)
    );
}

#[test]
fn a_failed_or_damaged_observation_is_an_error_not_absence() {
    let r = recipe("km-obs", &module(""));
    // The dry run: anything but exit 0 or 1 is an observation error.
    for mode in [
        FakeRead::Killed,
        FakeRead::Indeterminate,
        FakeRead::Truncated,
    ] {
        let t = fake();
        t.el()
            .lock()
            .unwrap()
            .osbase
            .module_dry_reads
            .push_back(mode);
        let why = refused(&r, Mode::Apply, t);
        assert!(why.contains("could not be observed"), "{mode:?}: {why}");
    }
    // /sys/module missing (no sysfs) is not "not loaded".
    let mut t = fake();
    t.fs.as_mut().unwrap().nodes.remove("/sys/module");
    t.fs.as_mut().unwrap().nodes.remove("/sys/module/loop");
    let why = refused(&r, Mode::Plan, t.clone());
    assert!(why.contains("sysfs is not available"), "{why}");
    let a = audit(&r, t);
    assert_eq!(a.resources[0].status, AuditResourceStatus::Error);
    // /sys/module/<name> as something else.
    let t = fake().with_fs_file(SYS, "synthetic");
    let why = refused(&r, Mode::Plan, t);
    assert!(why.contains("exists as"), "{why}");
}

#[test]
fn a_host_without_modprobe_is_refused_only_when_a_load_is_needed() {
    let r = recipe("km-tool", &module(""));
    let mut t = fake();
    t.executables.remove(TOOL);
    for mode in [Mode::Plan, Mode::Apply] {
        let why = refused(&r, mode, t.clone());
        assert!(
            why.contains("kernel_module is not supported on this host")
                && why.contains("/usr/sbin/modprobe was not found"),
            "{mode:?}: {why}"
        );
    }
    // Files only: no tool needed.
    let r = recipe("km-tool-bl", &module("      state: blacklisted\n"));
    assert_success(&apply(&r, t));
}

// ---------------------------------------------------------------------------
// absent and blacklisted
// ---------------------------------------------------------------------------

#[test]
fn absent_removes_only_the_file_and_never_unloads() {
    let r = recipe("km-abs", &module("      state: absent\n"));
    let t = converged().with_fs_file(BLACK, BLACK_TEXT);
    let rep = apply(&r, t.clone());
    assert_success(&rep);
    assert!(!exists_after(&rep, LOAD));
    assert!(exists_after(&rep, SYS), "the module was unloaded");
    // The blacklist file is not managed by absent.
    assert_eq!(file_text(&rep, BLACK).as_deref(), Some(BLACK_TEXT));
    assert!(calls(&t).is_empty(), "{:?}", calls(&t));
    assert!(notes(&rep).contains("not unloaded"), "{}", notes(&rep));
    // Already absent: no change, no note.
    let rep = apply(&r, fake());
    assert_success(&rep);
    assert_eq!(find(&rep, "m").change, Change::None);
    assert!(find(&rep, "m").notes.is_empty());
}

#[test]
fn blacklisted_writes_the_blacklist_removes_the_load_file_and_never_unloads() {
    let r = recipe("km-bl", &module("      state: blacklisted\n"));
    let t = converged();
    let rep = apply(&r, t.clone());
    assert_success(&rep);
    assert_eq!(file_text(&rep, BLACK).as_deref(), Some(BLACK_TEXT));
    assert!(!exists_after(&rep, LOAD));
    assert!(exists_after(&rep, SYS), "the module was unloaded");
    assert!(calls(&t).is_empty(), "{:?}", calls(&t));
    assert!(
        notes(&rep).contains("alias-based autoloading") && notes(&rep).contains("not unloaded"),
        "{}",
        notes(&rep)
    );
    let mut t2 = t.clone();
    t2.fs = rep.fake_fs.clone();
    let before = nodes(&t2);
    let second = apply(&r, t2.clone());
    assert_success(&second);
    assert_eq!(find(&second, "m").change, Change::None);
    assert_eq!(nodes_after(&second), before);
    let a = audit(&r, t2);
    assert_eq!(
        a.resources[0].status,
        AuditResourceStatus::Compliant,
        "{:?}",
        a.resources
    );
}

// ---------------------------------------------------------------------------
// failures of the change
// ---------------------------------------------------------------------------

#[test]
fn a_failed_load_after_the_file_was_written_is_a_failure_that_reports_the_change() {
    let r = recipe("km-fail", &module(""));
    for mode in [FakeChange::Fail, FakeChange::SucceedWithoutChange] {
        let t = fake();
        t.el().lock().unwrap().osbase.module_load = mode;
        let rep = apply(&r, t);
        assert_eq!(rep.status, AggregateStatus::ApplyFailed, "{mode:?}");
        let m = find(&rep, "m");
        assert_eq!(m.execution, Execution::Failed, "{mode:?}: {m:?}");
        assert_eq!(
            m.change,
            Change::Changed,
            "{mode:?}: the file change was lost"
        );
        assert_ne!(m.verification, Verification::Verified);
        assert_eq!(file_text(&rep, LOAD).as_deref(), Some(LOAD_TEXT));
        assert!(!exists_after(&rep, SYS));
    }
    let t = fake();
    t.el().lock().unwrap().osbase.module_load = FakeChange::SucceedWithoutChange;
    let rep = apply(&r, t);
    assert!(
        reason(&rep).contains("reported success but /sys/module/br_netfilter does not exist"),
        "{}",
        reason(&rep)
    );
}

#[test]
fn a_signal_or_timeout_of_the_load_is_indeterminate_never_success() {
    let r = recipe("km-ind", &module(""));
    for mode in [
        FakeChange::KilledAfterChange,
        FakeChange::IndeterminateAfterChange,
    ] {
        let t = fake();
        t.el().lock().unwrap().osbase.module_load = mode;
        let rep = apply(&r, t);
        assert_ne!(rep.status, AggregateStatus::Success, "{mode:?}");
        let m = find(&rep, "m");
        assert_eq!(m.execution, Execution::Indeterminate, "{mode:?}: {m:?}");
        assert_ne!(m.verification, Verification::Verified);
        assert!(reason(&rep).contains("may or may not"), "{}", reason(&rep));
        let at = rep
            .commands
            .iter()
            .position(|c| c.program == TOOL && c.args[0] == "--")
            .unwrap();
        assert!(
            !rep.commands[at + 1..]
                .iter()
                .any(|c| c.args.iter().any(|a| a == SYS)),
            "{mode:?}: {:?}",
            rep.commands
        );
    }
}

#[test]
fn a_failed_file_write_stops_before_the_load() {
    let r = recipe("km-fw", &module(""));
    // The directory is a symlink: nothing behind it is touched.
    let mut t = fake().with_fs_dir("/etc/elsewhere");
    {
        let fs = t.fs.as_mut().unwrap();
        fs.nodes.remove("/etc/modules-load.d");
        fs.put_symlink("/etc/modules-load.d", "/etc/elsewhere", 0, 0);
    }
    match try_run_recipe_fake(&r, Mode::Apply, false, t.clone()) {
        Ok(rep) => {
            assert_ne!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
            assert!(!exists_after(&rep, SYS));
        }
        Err(e) => assert!(e.message.contains("/etc/modules-load.d"), "{}", e.message),
    }
    assert!(loads(&t).is_empty(), "modprobe ran: {:?}", loads(&t));

    // Sinter's file is a symlink.
    let mut t = fake().with_fs_file("/etc/other.conf", "synthetic\n");
    t.fs.as_mut()
        .unwrap()
        .put_symlink(LOAD, "/etc/other.conf", 0, 0);
    for mode in [Mode::Plan, Mode::Apply] {
        let why = refused(&r, mode, t.clone());
        assert!(why.contains("is a symlink"), "{mode:?}: {why}");
    }
}

#[test]
fn a_file_replaced_between_observation_and_publication_is_not_overwritten() {
    let r = recipe("km-race", &module(""));
    let theirs = "# written by someone else\nbr_netfilter\n";
    let mut refused = 0;
    for (program, arg) in [("sh", "stage"), ("sh", "publish"), ("sha256sum", LOAD)] {
        let t = fake().with_fs_file(LOAD, "# old\n").with_fs_event(
            program,
            arg,
            0,
            vec![
                FsEventAction::Remove { path: LOAD.into() },
                FsEventAction::PutFile {
                    path: LOAD.into(),
                    data: theirs.as_bytes().to_vec(),
                    mode: 0o644,
                    uid: 0,
                    gid: 0,
                },
            ],
        );
        match try_run_recipe_fake(&r, Mode::Apply, false, t.clone()) {
            Err(_) => {
                refused += 1;
                assert!(loads(&t).is_empty(), "{program} {arg}: modprobe ran");
            }
            Ok(rep) => {
                let now = file_text(&rep, LOAD).unwrap();
                if rep.status != AggregateStatus::Success {
                    assert_eq!(now, theirs, "{program} {arg}");
                    assert!(loads(&t).is_empty(), "{program} {arg}: modprobe ran");
                    refused += 1;
                } else {
                    assert!(now == theirs || now == LOAD_TEXT, "{program} {arg}: {now}");
                }
            }
        }
    }
    assert!(refused >= 1, "no injected replacement was detected");
}

#[test]
fn a_load_needs_root_and_plan_says_so() {
    let r = recipe("km-root", &module("      persist: false\n"));
    let user = || {
        FakeTarget::rocky9()
            .with_fake_fs()
            .with_modules(&["br_netfilter"], &[])
    };
    let p = plan(&r, user());
    assert!(notes(&p).contains("needs root"), "{}", notes(&p));
    let why = refused(&r, Mode::Apply, user());
    assert!(why.contains("needs root"), "{why}");
    let t = user();
    assert_success(&run_recipe_fake(&r, Mode::Apply, true, t.clone()));
    assert_eq!(loads(&t), ["-- br_netfilter"]);
}

// ---------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------

#[test]
fn audit_reports_persistent_loaded_and_blacklist_drift_and_does_not_mutate() {
    let r = recipe("km-au", &module(""));
    let t = fake().with_fs_file(BLACK, BLACK_TEXT);
    let before = nodes(&t);
    let a = audit(&r, t.clone());
    assert_eq!(a.resources[0].status, AuditResourceStatus::Drift);
    let dims: Vec<&str> = a.resources[0]
        .details
        .iter()
        .map(|d| d.dimension.as_str())
        .collect();
    assert_eq!(
        dims,
        ["persistent", "blacklist", "loaded"],
        "{:?}",
        a.resources[0].details
    );
    let loaded = &a.resources[0].details[2];
    assert_eq!(
        (loaded.observed.as_str(), loaded.desired.as_str()),
        ("not loaded", "loaded")
    );
    assert_eq!(nodes(&t), before);
    assert!(calls(&t).is_empty(), "audit ran modprobe: {:?}", calls(&t));
    assert!(
        !a.commands
            .iter()
            .any(|c| is_mutation_command(&c.program, &c.args)),
        "{:?}",
        a.commands
    );
    // runtime: false does not compare the loaded state.
    let r = recipe("km-au-rt", &module("      runtime: false\n"));
    let a = audit(&r, fake().with_fs_file(LOAD, LOAD_TEXT));
    assert_eq!(
        a.resources[0].status,
        AuditResourceStatus::Compliant,
        "{:?}",
        a.resources
    );
}

// ---------------------------------------------------------------------------
// sensitive and OS
// ---------------------------------------------------------------------------

#[test]
fn a_sensitive_resource_records_the_load_redacted() {
    let yaml = doc("  - id: m\n    type: kernel_module\n    sensitive: true\n    with:\n      name: br-netfilter\n      persist: false\n");
    let r = recipe("km-sens", &yaml);
    let t = fake();
    let rep = apply(&r, t);
    assert_success(&rep);
    assert!(
        !rep.commands
            .iter()
            .any(|c| c.program == TOOL && c.args.iter().any(|a| a == "--") && c.args.len() == 2),
        "the load was recorded unredacted: {:?}",
        rep.commands
    );
    let mut b = Vec::new();
    sinter::output::render_apply(
        &rep,
        &RenderOptions {
            verbose: true,
            format: OutputFormat::Json,
            color: false,
        },
        &mut b,
    )
    .unwrap();
    assert!(!b.is_empty());
}

#[test]
fn every_os_is_judged_by_the_tool_and_the_files() {
    let r = recipe("km-os", &module(""));
    for t in [
        FakeTarget::ubuntu2404(),
        FakeTarget::ubuntu2604(),
        FakeTarget::rocky10(),
        FakeTarget::unsupported(),
    ] {
        let t = t
            .with_fake_fs()
            .as_root()
            .with_modules(&["br_netfilter"], &[]);
        let rep = apply(&r, t.clone());
        assert_success(&rep);
        assert_eq!(file_text(&rep, LOAD).as_deref(), Some(LOAD_TEXT));
        assert!(exists_after(&rep, SYS));
    }
}
