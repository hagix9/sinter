//! `sysctl` against the scripted in-process target.
//!
//! These run the production loader, engine, audit and output code against
//! [`FakeTarget`], whose `sysctl -n` / `sysctl -w` keep a map of kernel
//! parameters and whose filesystem is modeled. They prove Sinter's own
//! decisions, argv and order. What only a real host can show (the real
//! tool's output and exit codes, how the kernel stores a written value, what
//! `systemd-sysctl` reads at boot) is NOT verified here.
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

const TOOL: &str = "/usr/sbin/sysctl";
const CONF: &str = "/etc/sysctl.d/90-sinter-vm.swappiness.conf";
const RENDERED: &str =
    "# Managed by Sinter (sysctl). Local changes are replaced.\nvm.swappiness = 10\n";

fn doc(resources: &str) -> String {
    format!("version: 1\nresources:\n{resources}")
}

fn res(id: &str, fields: &str) -> String {
    format!("  - id: {id}\n    type: sysctl\n    with:\n{fields}")
}

/// `vm.swappiness = 10` with extra fields.
fn swappiness(extra: &str) -> String {
    doc(&res(
        "s",
        &format!("      name: vm.swappiness\n      value: 10\n{extra}"),
    ))
}

fn recipe(label: &str, yaml: &str) -> PathBuf {
    write_recipe(&trusted_root(label), "r.yaml", yaml)
}

/// An Ubuntu 24.04 target as root with a few kernel parameters.
fn fake() -> FakeTarget {
    FakeTarget::ubuntu2404()
        .with_fake_fs()
        .as_root()
        .with_sysctl(&[
            ("vm.swappiness", "60"),
            ("net.ipv4.tcp_rmem", "4096\t131072\t6291456"),
            ("kernel.synthetic_ro", "1"),
            ("kernel.synthetic_text", "SYNTHCUR3"),
        ])
}

/// The converged target: file and running value as declared.
fn converged() -> FakeTarget {
    let t = fake().with_fs_file(CONF, RENDERED);
    set_running(&t, "vm.swappiness", "10");
    t
}

fn set_running(t: &FakeTarget, name: &str, value: &str) {
    t.el()
        .lock()
        .unwrap()
        .host
        .sysctl
        .insert(name.to_string(), value.to_string());
}

fn running(t: &FakeTarget, name: &str) -> String {
    t.el().lock().unwrap().host.sysctl[name].clone()
}

/// The `-w` assignments the scripted tool received.
fn writes(t: &FakeTarget) -> Vec<String> {
    t.el()
        .lock()
        .unwrap()
        .host
        .sysctl_calls
        .iter()
        .filter(|a| a.first().map(String::as_str) == Some("-w"))
        .map(|a| a[1..].join(" "))
        .collect()
}

fn calls(t: &FakeTarget) -> usize {
    t.el().lock().unwrap().host.sysctl_calls.len()
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

fn nodes(t: &FakeTarget) -> String {
    format!("{:?}", t.fs.as_ref().unwrap().nodes)
}

fn nodes_after(rep: &RunReport) -> String {
    format!("{:?}", rep.fake_fs.as_ref().unwrap().nodes)
}

fn reason(rep: &RunReport) -> String {
    find(rep, "s").reason.clone().unwrap_or_default()
}

/// A run that must not succeed, must not have run `sysctl -w` and must have
/// left the filesystem as it was: why it stopped.
fn refused(r: &Path, mode: Mode, t: FakeTarget) -> String {
    let before = nodes(&t);
    let why = match try_run_recipe_fake(r, mode, false, t.clone()) {
        Ok(rep) => {
            assert_ne!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
            assert_eq!(find(&rep, "s").change, Change::None, "{:?}", rep.resources);
            assert_eq!(nodes_after(&rep), before, "the filesystem changed");
            reason(&rep)
        }
        Err(e) => e.message,
    };
    assert!(writes(&t).is_empty(), "-w ran: {:?}", writes(&t));
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

// ---------------------------------------------------------------------------
// load
// ---------------------------------------------------------------------------

#[test]
fn invalid_declarations_are_rejected_at_load() {
    let one = |fields: &str| doc(&res("s", fields));
    for (label, yaml, want) in [
        (
            "sy-l1",
            one("      name: vm.swappiness\n"),
            "value is required",
        ),
        ("sy-l2", one("      value: 10\n"), "name"),
        (
            "sy-l3",
            one("      name: vm/swappiness\n      value: 10\n"),
            "dotted form",
        ),
        (
            "sy-l4",
            one("      name: \"net.ipv4.conf.*.rp_filter\"\n      value: 1\n"),
            "dotted form",
        ),
        ("sy-l5", one("      name: vm\n      value: 10\n"), "dotted form"),
        (
            "sy-l6",
            one("      name: Vm.swappiness\n      value: 10\n"),
            "dotted form",
        ),
        (
            "sy-l7",
            one("      name: vm.swappiness\n      value: \"1\\n2\"\n"),
            "one line",
        ),
        (
            "sy-l8",
            one("      name: vm.swappiness\n      value: \"\"\n"),
            "must not be empty",
        ),
        (
            "sy-l9",
            one("      name: vm.swappiness\n      value: true\n"),
            "string or an integer",
        ),
        (
            "sy-l10",
            one("      name: vm.swappiness\n      value: 10\n      state: gone\n"),
            "literal present or absent",
        ),
        (
            "sy-l11",
            one("      name: vm.swappiness\n      value: 10\n      state: absent\n"),
            "value is not accepted with state: absent",
        ),
        (
            "sy-l12",
            one("      name: vm.swappiness\n      state: absent\n      runtime: false\n"),
            "runtime is not accepted with state: absent",
        ),
        (
            "sy-l13",
            one("      name: vm.swappiness\n      value: 10\n      runtime: false\n      persist: false\n"),
            "both false",
        ),
        (
            "sy-l14",
            one("      name: vm.swappiness\n      value: 10\n      runtime: \"yes\"\n"),
            "literal boolean",
        ),
        (
            "sy-l15",
            one("      name: vm.swappiness\n      value: 10\n      file: /etc/sysctl.conf\n"),
            "file",
        ),
        (
            "sy-l16",
            format!(
                "version: 1\nvars:\n  st: {{ value: absent }}\nresources:\n{}",
                res(
                    "s",
                    "      name: vm.swappiness\n      value: 10\n      state: \"{{ vars.st }}\"\n"
                )
            ),
            "literal present or absent",
        ),
    ] {
        let e = load_err(label, &yaml);
        assert!(e.contains(want), "{label}: {e}");
    }
}

#[test]
fn name_is_static_and_value_may_come_from_a_variable() {
    let yaml = format!(
        "version: 1\nvars:\n  key: {{ value: vm.swappiness }}\n  swap: {{ value: 10 }}\nresources:\n{}",
        res(
            "s",
            "      name: \"{{ vars.key }}\"\n      value: \"{{ vars.swap }}\"\n"
        )
    );
    let r = recipe("sy-var", &yaml);
    let t = fake();
    let rep = apply(&r, t.clone());
    assert_success(&rep);
    assert_eq!(running(&t, "vm.swappiness"), "10");
    assert_eq!(file_text(&rep, CONF).as_deref(), Some(RENDERED));

    // A name that resolves to something else than a parameter name.
    let bad = format!(
        "version: 1\nvars:\n  key: {{ value: \"vm/swappiness\" }}\nresources:\n{}",
        res("s", "      name: \"{{ vars.key }}\"\n      value: 10\n")
    );
    assert!(load_err("sy-var2", &bad).contains("dotted form"));

    // A value that evaluates to something not accepted is refused before
    // anything is read or written.
    let bad_value = format!(
        "version: 1\nvars:\n  swap: {{ value: \"1\\n2\" }}\nresources:\n{}",
        res(
            "s",
            "      name: vm.swappiness\n      value: \"{{ vars.swap }}\"\n"
        )
    );
    let r = recipe("sy-var3", &bad_value);
    let t = fake();
    let why = refused(&r, Mode::Apply, t.clone());
    assert!(why.contains("one line"), "{why}");
    assert_eq!(calls(&t), 0);
}

#[test]
fn conflicting_declarations_in_one_recipe_are_rejected() {
    let two = doc(&format!(
        "{}{}",
        res("a", "      name: vm.swappiness\n      value: 10\n"),
        res(
            "b",
            "      name: vm.swappiness\n      value: 20\n      persist: false\n"
        )
    ));
    let e = load_err("sy-c1", &two);
    assert!(
        e.contains("conflicting ownership of kernel parameter vm.swappiness"),
        "{e}"
    );

    // The file is Sinter's: a file resource on the same path conflicts.
    for (label, other) in [
        (
            "sy-c2",
            format!(
                "  - id: f\n    type: file\n    with:\n      path: {CONF}\n      content: \"x\"\n"
            ),
        ),
        (
            "sy-c3",
            format!(
                "  - id: f\n    type: file_merge\n    with:\n      path: {CONF}\n      merge: line\n      line: \"vm.swappiness = 1\"\n"
            ),
        ),
    ] {
        let both = doc(&format!(
            "{}{}",
            res("a", "      name: vm.swappiness\n      value: 10\n"),
            other
        ));
        let e = load_err(label, &both);
        assert!(e.contains("conflicting") && e.contains(CONF), "{label}: {e}");
        // The same with the other order.
        let both = doc(&format!(
            "{}{}",
            other,
            res("a", "      name: vm.swappiness\n      value: 10\n")
        ));
        let e = load_err(&format!("{label}r"), &both);
        assert!(e.contains("conflicting") && e.contains(CONF), "{label}: {e}");
    }

    // Two different parameters are fine.
    let ok = doc(&format!(
        "{}{}",
        res("a", "      name: vm.swappiness\n      value: 10\n"),
        res(
            "b",
            "      name: net.ipv4.tcp_rmem\n      value: \"4096 131072 6291456\"\n"
        )
    ));
    sinter::model::load_model(&recipe("sy-c4", &ok)).unwrap();
}

// ---------------------------------------------------------------------------
// plan and apply
// ---------------------------------------------------------------------------

#[test]
fn plan_reports_both_changes_and_does_not_mutate() {
    let r = recipe("sy-p", &swappiness(""));
    let t = fake();
    let before = nodes(&t);
    let rep = plan(&r, t.clone());
    assert_eq!(rep.status, AggregateStatus::Success);
    let s = find(&rep, "s");
    assert_eq!(s.change, Change::Changed, "{s:?}");
    assert!(
        s.notes
            .iter()
            .any(|n| n.contains("running value of vm.swappiness: \"60\" -> \"10\"")),
        "{:?}",
        s.notes
    );
    assert!(
        s.notes.iter().any(|n| n.contains("sorts later")),
        "{:?}",
        s.notes
    );
    assert!(s.diff.is_some());
    assert!(writes(&t).is_empty());
    assert_eq!(running(&t, "vm.swappiness"), "60");
    assert_eq!(mutation_command_count(&rep), 0);
    assert!(
        !rep.commands
            .iter()
            .any(|c| c.program == TOOL && c.args != ["-n", "--", "vm.swappiness"]),
        "{:?}",
        rep.commands
    );
    assert_eq!(nodes_after(&rep), before);
}

#[test]
fn apply_writes_the_file_first_then_sets_and_verifies_the_running_value() {
    let r = recipe("sy-a", &swappiness(""));
    let t = fake();
    let rep = apply(&r, t.clone());
    assert_success(&rep);
    let s = find(&rep, "s");
    assert_eq!(
        (s.execution, s.change, s.verification),
        (
            Execution::Succeeded,
            Change::Changed,
            Verification::Verified
        ),
        "{s:?}"
    );
    assert_eq!(file_text(&rep, CONF).as_deref(), Some(RENDERED));
    let node = &rep.fake_fs.as_ref().unwrap().nodes[CONF];
    assert_eq!((node.mode & 0o7777, node.uid, node.gid), (0o644, 0, 0));
    assert_eq!(writes(&t), ["-- vm.swappiness=10"]);
    assert_eq!(running(&t, "vm.swappiness"), "10");

    // Order: observe, write the file, change, observe again.
    let tool: Vec<usize> = rep
        .commands
        .iter()
        .enumerate()
        .filter(|(_, c)| c.program == TOOL)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(tool.len(), 3, "{:?}", rep.commands);
    assert_eq!(rep.commands[tool[0]].args, ["-n", "--", "vm.swappiness"]);
    assert_eq!(rep.commands[tool[1]].args, ["-w", "--", "vm.swappiness=10"]);
    assert_eq!(rep.commands[tool[2]].args, ["-n", "--", "vm.swappiness"]);
    let first_mutation = rep
        .commands
        .iter()
        .position(|c| c.args.iter().any(|a| a == "publish"))
        .expect("the file was published");
    assert!(
        tool[0] < first_mutation && first_mutation < tool[1],
        "{:?}",
        rep.commands
    );
}

#[test]
fn a_converged_target_is_unchanged_and_the_file_is_not_rewritten() {
    let r = recipe("sy-i", &swappiness(""));
    // After a first apply, a second one changes nothing.
    let t = fake();
    let first = apply(&r, t.clone());
    assert_success(&first);
    let mut second = t.clone();
    second.fs = first.fake_fs.clone();
    let before = nodes(&second);
    let writes_before = writes(&second).len();
    for mode in [Mode::Plan, Mode::Apply] {
        let rep = run_recipe_fake(&r, mode, false, second.clone());
        assert_success(&rep);
        let s = find(&rep, "s");
        assert_eq!(s.change, Change::None, "{s:?}");
        assert_eq!(nodes_after(&rep), before, "the file was rewritten");
        assert_eq!(mutation_command_count(&rep), 0);
    }
    assert_eq!(writes(&second).len(), writes_before);
    let a = audit(&r, second.clone());
    assert_eq!(a.resources[0].status, AuditResourceStatus::Compliant);
}

#[test]
fn a_multi_value_parameter_is_compared_without_regard_to_tabs_and_spaces() {
    let yaml = doc(&res(
        "s",
        "      name: net.ipv4.tcp_rmem\n      value: \"4096  131072 6291456\"\n      persist: false\n",
    ));
    let r = recipe("sy-mv", &yaml);
    let t = fake();
    let rep = apply(&r, t.clone());
    assert_success(&rep);
    assert_eq!(find(&rep, "s").change, Change::None);
    assert!(writes(&t).is_empty());

    let yaml = doc(&res(
        "s",
        "      name: net.ipv4.tcp_rmem\n      value: \"4096 87380 6291456\"\n",
    ));
    let r = recipe("sy-mv2", &yaml);
    let t = fake();
    let rep = apply(&r, t.clone());
    assert_success(&rep);
    assert_eq!(writes(&t), ["-- net.ipv4.tcp_rmem=4096 87380 6291456"]);
    assert_eq!(running(&t, "net.ipv4.tcp_rmem"), "4096\t87380\t6291456");
    assert_eq!(
        file_text(&rep, "/etc/sysctl.d/90-sinter-net.ipv4.tcp_rmem.conf").as_deref(),
        Some("# Managed by Sinter (sysctl). Local changes are replaced.\nnet.ipv4.tcp_rmem = 4096 87380 6291456\n")
    );
}

#[test]
fn runtime_false_writes_only_the_file_and_never_runs_the_tool() {
    let r = recipe("sy-rf", &swappiness("      runtime: false\n"));
    // Even a host without the tool, and a parameter the kernel lacks.
    let mut t = FakeTarget::rocky9()
        .with_fake_fs()
        .as_root()
        .with_fs_dir("/etc/sysctl.d");
    t.executables.remove(TOOL);
    let p = plan(&r, t.clone());
    let s = find(&p, "s");
    assert_eq!(s.change, Change::Changed);
    assert!(
        s.notes.iter().any(|n| n.contains("runtime: false")),
        "{:?}",
        s.notes
    );
    let rep = apply(&r, t.clone());
    assert_success(&rep);
    assert_eq!(file_text(&rep, CONF).as_deref(), Some(RENDERED));
    assert_eq!(calls(&t), 0);
    assert!(!rep.commands.iter().any(|c| c.program == TOOL));

    // The running value is not compared in audit either.
    let mut conv = t.clone();
    conv.fs = rep.fake_fs.clone();
    let a = audit(&r, conv);
    assert_eq!(a.resources[0].status, AuditResourceStatus::Compliant);
    assert!(!a.commands.iter().any(|c| c.program == TOOL));
}

#[test]
fn persist_false_changes_only_the_running_value() {
    let r = recipe("sy-pf", &swappiness("      persist: false\n"));
    let t = fake().with_fs_file(CONF, "# left by an earlier run\nvm.swappiness = 1\n");
    let before = nodes(&t);
    let rep = apply(&r, t.clone());
    assert_success(&rep);
    let s = find(&rep, "s");
    assert_eq!(
        (s.change, s.verification),
        (Change::Changed, Verification::Verified)
    );
    assert_eq!(
        s.diff.as_ref().map(|d| d.body.clone()),
        Some(DiffBody::Summary {
            current: "60".into(),
            desired: "10".into()
        })
    );
    assert_eq!(running(&t, "vm.swappiness"), "10");
    assert_eq!(nodes_after(&rep), before, "the file was touched");
    assert_eq!(mutation_command_count(&rep), 0);

    // Audit compares the running value only.
    let a = audit(&r, t.clone());
    assert_eq!(a.resources[0].status, AuditResourceStatus::Compliant);
}

#[test]
fn absent_removes_only_the_file_and_leaves_the_running_value() {
    let yaml = doc(&res(
        "s",
        "      name: vm.swappiness\n      state: absent\n",
    ));
    let r = recipe("sy-ab", &yaml);
    let t = converged();
    let p = plan(&r, t.clone());
    let s = find(&p, "s");
    assert_eq!(s.change, Change::Changed);
    assert!(
        s.notes
            .iter()
            .any(|n| n.contains("running value is not reset")),
        "{:?}",
        s.notes
    );
    assert_eq!(nodes_after(&p), nodes(&t));

    let rep = apply(&r, t.clone());
    assert_success(&rep);
    assert_eq!(find(&rep, "s").change, Change::Changed);
    assert_eq!(file_text(&rep, CONF), None);
    assert_eq!(running(&t, "vm.swappiness"), "10");
    assert_eq!(calls(&t), 0, "absent ran the tool");

    // Already absent: no change; other files in the directory are not
    // Sinter's and stay.
    let other = "/etc/sysctl.d/99-local.conf";
    let t = fake().with_fs_file(other, "vm.swappiness = 1\n");
    let rep = apply(&r, t.clone());
    assert_success(&rep);
    assert_eq!(find(&rep, "s").change, Change::None);
    assert_eq!(
        file_text(&rep, other).as_deref(),
        Some("vm.swappiness = 1\n")
    );
    let a = audit(&r, t);
    assert_eq!(a.resources[0].status, AuditResourceStatus::Compliant);

    // Audit: Sinter's file still there is drift of `persistent`.
    let a = audit(&r, converged());
    assert_eq!(a.resources[0].status, AuditResourceStatus::Drift);
    assert!(a.resources[0]
        .details
        .iter()
        .all(|d| d.dimension == "persistent"));
}

// ---------------------------------------------------------------------------
// what cannot be observed is an error, never a state
// ---------------------------------------------------------------------------

#[test]
fn an_unknown_parameter_is_an_error_and_nothing_is_written() {
    let yaml = doc(&res(
        "s",
        "      name: vm.synthetic_missing\n      value: 1\n",
    ));
    let r = recipe("sy-unk", &yaml);
    for mode in [Mode::Plan, Mode::Apply] {
        let t = fake();
        let why = refused(&r, mode, t.clone());
        assert!(
            why.contains("unknown kernel parameter vm.synthetic_missing"),
            "{why}"
        );
    }
    let a = audit(&r, fake());
    assert_eq!(a.resources[0].status, AuditResourceStatus::Error);
    assert!(a.resources[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("unknown kernel parameter"));
}

#[test]
fn a_failed_or_damaged_observation_is_an_error_not_a_value() {
    let r = recipe("sy-obs", &swappiness(""));
    for (mode, want) in [
        (FakeRead::Fail, "unknown kernel parameter"),
        (FakeRead::ExtraLines, "more than one line"),
        (FakeRead::Empty, "it is empty"),
        (FakeRead::WithStderr, "standard error"),
        (FakeRead::Truncated, "truncated"),
        (FakeRead::Killed, "signal 9"),
        (FakeRead::Indeterminate, "did not complete"),
    ] {
        for run in [Mode::Plan, Mode::Apply] {
            // Converged otherwise: a damaged answer must not read as "as
            // declared" either.
            for base in [fake(), converged()] {
                base.el().lock().unwrap().host.sysctl_reads.push_back(mode);
                let before = nodes(&base);
                let why = match try_run_recipe_fake(&r, run, false, base.clone()) {
                    Ok(rep) => {
                        assert_ne!(rep.status, AggregateStatus::Success, "{mode:?}");
                        assert_eq!(nodes_after(&rep), before, "{mode:?}");
                        reason(&rep)
                    }
                    Err(e) => e.message,
                };
                assert!(why.contains(want), "{mode:?} {run:?}: {why}");
                assert!(writes(&base).is_empty(), "{mode:?}");
            }
        }
        let t = converged();
        t.el().lock().unwrap().host.sysctl_reads.push_back(mode);
        let a = audit(&r, t);
        assert_eq!(
            a.resources[0].status,
            AuditResourceStatus::Error,
            "{mode:?}: {:?}",
            a.resources[0]
        );
        assert!(a.resources[0].details.is_empty(), "{mode:?}");
    }
}

#[test]
fn a_host_without_the_tool_is_refused_clearly() {
    let r = recipe("sy-notool", &swappiness(""));
    let mut t = fake();
    t.executables.remove(TOOL);
    for mode in [Mode::Plan, Mode::Apply] {
        let why = refused(&r, mode, t.clone());
        assert!(
            why.contains("/usr/sbin/sysctl was not found"),
            "{mode:?}: {why}"
        );
    }
    assert_eq!(calls(&t), 0);
    let a = audit(&r, t);
    assert_eq!(a.resources[0].status, AuditResourceStatus::Error);
}

#[test]
fn an_unrecognized_os_is_judged_by_the_tool_like_every_other_host() {
    // Like `file`, `sysctl` needs no platform backend: what decides is
    // whether /usr/sbin/sysctl exists. Without it the host is refused.
    let r = recipe("sy-os", &swappiness(""));
    let bare = FakeTarget::unsupported()
        .with_fake_fs()
        .as_root()
        .with_fs_dir("/etc/sysctl.d");
    for mode in [Mode::Plan, Mode::Apply] {
        let why = refused(&r, mode, bare.clone());
        assert!(
            why.contains("/usr/sbin/sysctl was not found"),
            "{mode:?}: {why}"
        );
    }
    assert_eq!(calls(&bare), 0);

    let t = FakeTarget::unsupported()
        .with_fake_fs()
        .as_root()
        .with_sysctl(&[("vm.swappiness", "60")]);
    assert_success(&apply(&r, t.clone()));
    assert_eq!(running(&t, "vm.swappiness"), "10");
}

// ---------------------------------------------------------------------------
// failures of the change
// ---------------------------------------------------------------------------

#[test]
fn a_read_only_parameter_fails_and_the_written_file_is_reported() {
    let yaml = doc(&res(
        "s",
        "      name: kernel.synthetic_ro\n      value: 0\n",
    ));
    let r = recipe("sy-ro", &yaml);
    let t = fake();
    t.el()
        .lock()
        .unwrap()
        .host
        .sysctl_read_only
        .insert("kernel.synthetic_ro".into());
    let rep = apply(&r, t.clone());
    assert_ne!(rep.status, AggregateStatus::Success);
    let s = find(&rep, "s");
    assert_eq!(s.execution, Execution::Failed, "{s:?}");
    assert_eq!(s.change, Change::Changed, "the written file is a change");
    assert_ne!(s.verification, Verification::Verified);
    assert!(reason(&rep).contains("exit code 255"), "{}", reason(&rep));
    assert!(reason(&rep).contains("permission denied"));
    assert_eq!(running(&t, "kernel.synthetic_ro"), "1");
    assert!(file_text(&rep, "/etc/sysctl.d/90-sinter-kernel.synthetic_ro.conf").is_some());
}

#[test]
fn exit_zero_without_the_declared_value_is_a_failure() {
    let r = recipe("sy-noop", &swappiness(""));
    // The tool says yes and changes nothing.
    let t = fake();
    t.el().lock().unwrap().host.sysctl_write = FakeChange::SucceedWithoutChange;
    let rep = apply(&r, t.clone());
    assert_ne!(rep.status, AggregateStatus::Success);
    let s = find(&rep, "s");
    assert_eq!(
        (s.execution, s.verification),
        (Execution::Failed, Verification::Failed),
        "{s:?}"
    );
    assert_eq!(s.change, Change::Changed, "the file was written");
    assert!(
        reason(&rep).contains("reported success but the running value of vm.swappiness is \"60\"")
    );

    // The same with only the running value managed: nothing is claimed.
    let r2 = recipe("sy-noop2", &swappiness("      persist: false\n"));
    let t = fake();
    t.el().lock().unwrap().host.sysctl_write = FakeChange::SucceedWithoutChange;
    let rep = apply(&r2, t);
    assert_ne!(rep.status, AggregateStatus::Success);
    let s = find(&rep, "s");
    assert_eq!(
        (s.execution, s.change, s.verification),
        (Execution::Failed, Change::Possible, Verification::Failed),
        "{s:?}"
    );

    // The kernel stores another value than the one written.
    let t = fake();
    t.el()
        .lock()
        .unwrap()
        .host
        .sysctl_stores
        .insert("10".into(), "8".into());
    let rep = apply(&r2, t.clone());
    assert_ne!(rep.status, AggregateStatus::Success);
    let s = find(&rep, "s");
    assert_eq!(
        (s.execution, s.change, s.verification),
        (Execution::Failed, Change::Changed, Verification::Failed),
        "{s:?}"
    );
    assert!(reason(&rep).contains("is \"8\" (declared: \"10\")"));

    // The change command fails outright.
    let t = fake();
    t.el().lock().unwrap().host.sysctl_write = FakeChange::Fail;
    let rep = apply(&r2, t.clone());
    assert_ne!(rep.status, AggregateStatus::Success);
    let s = find(&rep, "s");
    assert_eq!(s.execution, Execution::Failed);
    assert_ne!(s.verification, Verification::Verified);
    assert_eq!(running(&t, "vm.swappiness"), "60");
}

#[test]
fn a_signal_or_timeout_of_the_change_is_indeterminate_never_success() {
    for (label, mode) in [
        ("sy-kill", FakeChange::KilledAfterChange),
        ("sy-tmo", FakeChange::IndeterminateAfterChange),
    ] {
        let r = recipe(label, &swappiness("      persist: false\n"));
        let t = fake();
        t.el().lock().unwrap().host.sysctl_write = mode;
        let rep = apply(&r, t.clone());
        assert_ne!(rep.status, AggregateStatus::Success, "{mode:?}");
        let s = find(&rep, "s");
        assert_eq!(
            (s.execution, s.change, s.verification),
            (
                Execution::Indeterminate,
                Change::Possible,
                Verification::Unknown
            ),
            "{mode:?}: {s:?}"
        );
        assert!(reason(&rep).contains("may or may not"), "{}", reason(&rep));
        // Nothing more was sent for the resource.
        assert_eq!(calls(&t), 2, "{mode:?}");
    }
    // With the file written first, that change stays reported.
    let r = recipe("sy-tmo2", &swappiness(""));
    let t = fake();
    t.el().lock().unwrap().host.sysctl_write = FakeChange::IndeterminateAfterChange;
    let rep = apply(&r, t);
    let s = find(&rep, "s");
    assert_eq!(
        (s.execution, s.change),
        (Execution::Indeterminate, Change::Changed),
        "{s:?}"
    );
}

#[test]
fn a_failed_observation_after_the_change_is_not_success() {
    let r = recipe("sy-reobs", &swappiness("      persist: false\n"));
    for (mode, execution) in [
        (FakeRead::Fail, Execution::Failed),
        (FakeRead::Truncated, Execution::Failed),
        (FakeRead::Indeterminate, Execution::Indeterminate),
    ] {
        let t = fake();
        t.el()
            .lock()
            .unwrap()
            .host
            .sysctl_reads
            .extend([FakeRead::Normal, mode]);
        let rep = apply(&r, t);
        assert_ne!(rep.status, AggregateStatus::Success, "{mode:?}");
        let s = find(&rep, "s");
        assert_eq!(
            (s.execution, s.change),
            (execution, Change::Possible),
            "{mode:?}: {s:?}"
        );
        assert_ne!(s.verification, Verification::Verified);
    }
}

#[test]
fn a_failed_file_write_is_a_failure_and_the_running_value_is_left_alone() {
    let r = recipe("sy-fault", &swappiness(""));
    for fault in [
        "before_publish",
        "rename_fail",
        "after_publish",
        "reobserve_fail",
    ] {
        let t = fake();
        let rep = run_recipe_fake_fault(&r, Mode::Apply, false, t.clone(), fault);
        assert_ne!(rep.status, AggregateStatus::Success, "{fault}");
        let s = find(&rep, "s");
        assert_ne!(s.execution, Execution::Succeeded, "{fault}");
        assert_ne!(s.verification, Verification::Verified, "{fault}");
        assert!(writes(&t).is_empty(), "{fault}: -w ran");
        assert_eq!(running(&t, "vm.swappiness"), "60", "{fault}");
    }
}

// ---------------------------------------------------------------------------
// privilege, symlinks, concurrent change
// ---------------------------------------------------------------------------

#[test]
fn a_change_needs_root_and_plan_says_so() {
    let r = recipe("sy-root", &swappiness(""));
    let user = || {
        FakeTarget::ubuntu2404()
            .with_fake_fs()
            .with_sysctl(&[("vm.swappiness", "60")])
    };
    let p = plan(&r, user());
    assert!(
        find(&p, "s").notes.iter().any(|n| n.contains("needs root")),
        "{:?}",
        find(&p, "s").notes
    );
    let t = user();
    let why = refused(&r, Mode::Apply, t.clone());
    assert!(why.contains("needs root"), "{why}");

    // With --sudo the change runs.
    let t = user();
    let rep = run_recipe_fake(&r, Mode::Apply, true, t.clone());
    assert_success(&rep);
    assert_eq!(running(&t, "vm.swappiness"), "10");

    // Nothing to change needs no root.
    let mut t = user().with_fs_file(CONF, RENDERED);
    set_running(&t, "vm.swappiness", "10");
    t.uid = 1000;
    let rep = apply(&r, t);
    assert_success(&rep);
    assert_eq!(find(&rep, "s").change, Change::None);
}

#[test]
fn a_symlink_in_place_of_the_file_or_its_directory_is_refused() {
    let r = recipe("sy-link", &swappiness(""));
    // Sinter's file is a symlink to another file.
    let mut t = fake().with_fs_file("/etc/sysctl.conf", "# synthetic\n");
    t.fs.as_mut()
        .unwrap()
        .put_symlink(CONF, "/etc/sysctl.conf", 0, 0);
    for mode in [Mode::Plan, Mode::Apply] {
        let why = refused(&r, mode, t.clone());
        assert!(why.contains("is a symlink"), "{mode:?}: {why}");
    }

    // The directory is a symlink: nothing behind it is touched.
    let mut t = FakeTarget::ubuntu2404()
        .with_fake_fs()
        .as_root()
        .with_fs_dir("/etc/elsewhere");
    t = t.with_sysctl(&[("vm.swappiness", "60")]);
    {
        let fs = t.fs.as_mut().unwrap();
        fs.nodes.remove("/etc/sysctl.d");
        fs.put_symlink("/etc/sysctl.d", "/etc/elsewhere", 0, 0);
    }
    for mode in [Mode::Plan, Mode::Apply] {
        let before = nodes(&t);
        match try_run_recipe_fake(&r, mode, false, t.clone()) {
            Ok(rep) => {
                assert_ne!(rep.status, AggregateStatus::Success, "{:?}", rep.resources);
                assert_eq!(nodes_after(&rep), before);
            }
            Err(e) => assert!(e.message.contains("/etc/sysctl.d"), "{}", e.message),
        }
        assert!(writes(&t).is_empty(), "-w ran behind a refused directory");
    }
}

#[test]
fn a_file_replaced_between_observation_and_publication_is_not_overwritten() {
    let r = recipe("sy-race", &swappiness(""));
    let theirs = "# written by someone else\nvm.swappiness = 1\n";
    let mut refused = 0;
    for (program, arg) in [("sh", "stage"), ("sh", "publish"), ("sha256sum", CONF)] {
        let t = fake()
            .with_fs_file(CONF, "# old\nvm.swappiness = 60\n")
            .with_fs_event(
                program,
                arg,
                0,
                vec![
                    FsEventAction::Remove { path: CONF.into() },
                    FsEventAction::PutFile {
                        path: CONF.into(),
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
                assert!(writes(&t).is_empty(), "{program} {arg}: -w ran");
            }
            Ok(rep) => {
                let now = file_text(&rep, CONF).unwrap();
                if rep.status != AggregateStatus::Success {
                    assert_eq!(now, theirs, "{program} {arg}");
                    assert!(writes(&t).is_empty(), "{program} {arg}: -w ran");
                    refused += 1;
                } else {
                    assert!(now == theirs || now == RENDERED, "{program} {arg}: {now}");
                }
            }
        }
    }
    assert!(refused >= 1, "no injected replacement was detected");
}

// ---------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------

#[test]
fn audit_reports_runtime_and_persistent_drift_and_does_not_mutate() {
    let r = recipe("sy-au", &swappiness(""));
    // Compliant.
    let a = audit(&r, converged());
    assert_eq!(a.resources[0].status, AuditResourceStatus::Compliant);
    assert!(a.resources[0]
        .reason
        .as_deref()
        .unwrap()
        .contains("not evaluated"));

    // The running value differs.
    let t = converged();
    set_running(&t, "vm.swappiness", "60");
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
        ("runtime", "60", "10")
    );
    assert!(writes(&t).is_empty());
    assert_eq!(running(&t, "vm.swappiness"), "60");
    assert_eq!(nodes(&t), before);
    assert!(
        !a.commands.iter().any(
            |c| (c.program == TOOL && c.args != ["-n", "--", "vm.swappiness"])
                || is_mutation_command(&c.program, &c.args)
        ),
        "{:?}",
        a.commands
    );

    // The file is missing, has other content, or another mode.
    let t = fake();
    set_running(&t, "vm.swappiness", "10");
    let a = audit(&r, t);
    assert_eq!(a.resources[0].status, AuditResourceStatus::Drift);
    assert!(a.resources[0]
        .details
        .iter()
        .all(|d| d.dimension == "persistent"));

    let t = fake().with_fs_file(CONF, "vm.swappiness = 60\n");
    let a = audit(&r, t);
    assert_eq!(a.resources[0].status, AuditResourceStatus::Drift);
    let dims: Vec<&str> = a.resources[0]
        .details
        .iter()
        .map(|d| d.dimension.as_str())
        .collect();
    assert!(
        dims.contains(&"persistent") && dims.contains(&"runtime"),
        "{dims:?}"
    );
    assert!(a.resources[0]
        .details
        .iter()
        .any(|d| d.dimension == "persistent" && d.observed.starts_with("content")));

    let mut t = converged();
    t.fs.as_mut()
        .unwrap()
        .put_file(CONF, RENDERED.as_bytes(), 0o600, 0, 0);
    let a = audit(&r, t);
    assert_eq!(a.resources[0].status, AuditResourceStatus::Drift);
    let d = &a.resources[0].details;
    assert_eq!(d.len(), 1, "{d:?}");
    assert_eq!(d[0].dimension, "persistent");
    assert!(d[0].observed.contains("mode"), "{d:?}");
}

// ---------------------------------------------------------------------------
// sensitive values
// ---------------------------------------------------------------------------

#[test]
fn a_sensitive_resource_shows_no_value_in_any_output() {
    let yaml = "version: 1\nresources:\n  - id: s\n    type: sysctl\n    sensitive: true\n    with:\n      name: kernel.synthetic_text\n      value: SYNTHVAL7\n";
    let r = recipe("sy-sens", yaml);
    let leaks = |texts: Vec<String>, what: &str| {
        for s in texts {
            assert!(
                !s.contains("SYNTHVAL7") && !s.contains("SYNTHCUR3"),
                "{what}: {s}"
            );
        }
    };
    leaks(surfaces(&plan(&r, fake()), "plan"), "plan");
    let t = fake();
    let a = apply(&r, t.clone());
    assert_success(&a);
    assert_eq!(running(&t, "kernel.synthetic_text"), "SYNTHVAL7");
    leaks(surfaces(&a, "apply"), "apply");

    for mode in [FakeChange::SucceedWithoutChange, FakeChange::Fail] {
        let failing = fake();
        failing.el().lock().unwrap().host.sysctl_write = mode;
        let rep = apply(&r, failing);
        assert_ne!(rep.status, AggregateStatus::Success);
        leaks(surfaces(&rep, "apply"), "failure");
    }
    let damaged = fake();
    damaged
        .el()
        .lock()
        .unwrap()
        .host
        .sysctl_reads
        .push_back(FakeRead::ExtraLines);
    match try_run_recipe_fake(&r, Mode::Plan, false, damaged) {
        Ok(rep) => leaks(surfaces(&rep, "plan"), "observation"),
        Err(e) => leaks(vec![e.message], "observation"),
    }

    let au = audit(&r, fake());
    assert_eq!(au.resources[0].status, AuditResourceStatus::Drift);
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
