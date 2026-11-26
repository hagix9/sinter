//! `file_merge` against the scripted in-process target.
//!
//! These run the production loader, engine, resources, audit and output code
//! against [`FakeTarget`], whose filesystem answers the commands the `file`
//! resource issues. They prove Sinter's own decisions: which bytes are
//! written, that nothing else changes, and what is refused. What only a real
//! Linux host can show (the staging script and `setpriv` on a real
//! `authorized_keys`, real ACL and xattr answers) is not claimed here.
#![cfg(unix)]

use sinter::audit::{AuditReport, AuditResourceStatus};
use sinter::engine::{AggregateStatus, Engine, Mode, RunOptions, RunReport, TargetSpec};
use sinter::error::{ErrorKind, SinterError};
use sinter::executor::{Completion, FakeTarget, FsEventAction, Output};
use sinter::model::load_model;
use sinter::output::{OutputFormat, RenderOptions};
use sinter::result::{Change, Execution, ResourceResult, Verification};

const AK: &str = "/root/.ssh/authorized_keys";
const HOSTS: &str = "/etc/hosts";
const CONF: &str = "/etc/app/app.conf";

// Synthetic key material: not a key of anything.
const K1: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsyntheticSYNTHETICsyntheticSYNTHETICsynthetic01 one@example.invalid";
const K2: &str = "from=\"192.0.2.10\",no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsyntheticSYNTHETICsyntheticSYNTHETICsynthetic02 two@example.invalid";
const K3: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsyntheticSYNTHETICsyntheticSYNTHETICsynthetic00 synthetic@example.invalid";

const SECRET: &str = "SINTER-TEST-CANARY-synthetic-0000";

/// A root target with `/root/.ssh` and the standard directories.
fn fake() -> FakeTarget {
    let mut t = FakeTarget::rocky9().with_fake_fs().as_root();
    let fs = t.fs.as_mut().unwrap();
    fs.mkdir_node("/root", 0o700, 0, 0);
    fs.mkdir_node("/root/.ssh", 0o700, 0, 0);
    t
}

fn with_file(mut t: FakeTarget, path: &str, content: &str, mode: u32) -> FakeTarget {
    t.fs.as_mut()
        .unwrap()
        .put_file(path, content.as_bytes(), mode, 0, 0);
    t
}

fn doc(resources: &str) -> String {
    format!("version: 1\nresources:\n{resources}")
}

/// One `file_merge` resource `m` with the given `with` lines (6 spaces deep).
fn merge(with: &str) -> String {
    doc(&format!(
        "  - id: m\n    type: file_merge\n    with:\n{with}"
    ))
}

fn line_recipe(path: &str, line: &str, extra: &str) -> String {
    merge(&format!(
        "      path: {path}\n      merge: line\n      line: '{line}'\n{extra}"
    ))
}

fn opts(mode: Mode, t: FakeTarget) -> RunOptions {
    RunOptions {
        mode,
        sudo: false,
        target: TargetSpec { ssh: None },
        verbose: true,
        fault: None,
        fake_target: Some(t),
    }
}

fn try_run(mode: Mode, yaml: &str, t: FakeTarget) -> Result<RunReport, SinterError> {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("r.yaml");
    std::fs::write(&p, yaml).unwrap();
    Engine::new(load_model(&p)?, opts(mode, t))?.run()
}

fn run(mode: Mode, yaml: &str, t: FakeTarget) -> RunReport {
    try_run(mode, yaml, t).unwrap_or_else(|e| panic!("run failed: {}", e.message))
}

fn apply(yaml: &str, t: FakeTarget) -> RunReport {
    run(Mode::Apply, yaml, t)
}

fn plan(yaml: &str, t: FakeTarget) -> RunReport {
    run(Mode::Plan, yaml, t)
}

fn plan_err(yaml: &str, t: FakeTarget) -> SinterError {
    match try_run(Mode::Plan, yaml, t) {
        Ok(r) => panic!("plan succeeded: {:?}", r.resources),
        Err(e) => e,
    }
}

fn audit(yaml: &str, t: FakeTarget) -> AuditReport {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("r.yaml");
    std::fs::write(&p, yaml).unwrap();
    let engine = Engine::new(load_model(&p).unwrap(), opts(Mode::Plan, t)).unwrap();
    sinter::audit::run_audit(engine).unwrap()
}

fn load_err(yaml: &str) -> String {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("r.yaml");
    std::fs::write(&p, yaml).unwrap();
    match load_model(&p) {
        Ok(_) => panic!("recipe was accepted:\n{yaml}"),
        Err(e) => {
            assert_eq!(e.kind, ErrorKind::Schema, "{}", e.message);
            e.message
        }
    }
}

fn res<'a>(r: &'a RunReport, id: &str) -> &'a ResourceResult {
    r.resources.iter().find(|x| x.id == id).unwrap()
}

fn content(r: &RunReport, path: &str) -> String {
    let b = r
        .fake_fs
        .as_ref()
        .unwrap()
        .file_bytes(path)
        .unwrap_or_else(|| panic!("{path} is not a file"));
    String::from_utf8(b).unwrap()
}

fn node(r: &RunReport, path: &str) -> (u32, u32, u32, u64) {
    let n = &r.fake_fs.as_ref().unwrap().nodes[path];
    (n.mode, n.uid, n.gid, n.ino)
}

fn base_name(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// Commands that can change the target (`sh` is the fixed staging script).
fn mutations(cmds: &[sinter::executor::CommandRecord]) -> Vec<String> {
    const MUTATION: [&str; 12] = [
        "mkdir", "chown", "chmod", "dd", "mv", "mktemp", "rm", "rmdir", "ln", "sh", "tee",
        "setfattr",
    ];
    cmds.iter()
        .filter(|c| MUTATION.contains(&base_name(&c.program)))
        .map(|c| format!("{} {:?}", c.program, c.args))
        .collect()
}

fn assert_changed(r: &RunReport, id: &str) {
    assert_eq!(r.status, AggregateStatus::Success);
    let x = res(r, id);
    assert_eq!(x.execution, Execution::Succeeded, "{:?}", x.reason);
    assert_eq!(x.change, Change::Changed, "{:?}", x.reason);
    assert_eq!(x.verification, Verification::Verified, "{:?}", x.reason);
}

fn assert_unchanged(r: &RunReport, id: &str) {
    assert_eq!(r.status, AggregateStatus::Success);
    let x = res(r, id);
    assert_eq!(x.execution, Execution::Succeeded, "{:?}", x.reason);
    assert_eq!(x.change, Change::None, "{:?}", x.reason);
    assert!(
        mutations(&r.commands).is_empty(),
        "{:?}",
        mutations(&r.commands)
    );
}

/// Everything a run shows: the error, or the text and JSON renderings.
fn shown(mode: Mode, yaml: &str, t: FakeTarget) -> String {
    match try_run(mode, yaml, t) {
        Err(e) => e.message,
        Ok(r) => {
            let mut all = Vec::new();
            for format in [OutputFormat::Text, OutputFormat::Json] {
                let o = RenderOptions {
                    verbose: true,
                    format,
                    color: false,
                };
                if mode == Mode::Plan {
                    sinter::output::render_plan(&r, &o, &mut all).unwrap();
                } else {
                    sinter::output::render_apply(&r, &o, &mut all).unwrap();
                }
            }
            String::from_utf8(all).unwrap()
        }
    }
}

fn audit_shown(report: &AuditReport) -> String {
    let mut all = serde_json::to_string(&sinter::output::audit_report_json(report))
        .unwrap()
        .into_bytes();
    sinter::output::render_audit(
        report,
        &RenderOptions {
            verbose: true,
            format: OutputFormat::Text,
            color: false,
        },
        &mut all,
    )
    .unwrap();
    String::from_utf8(all).unwrap()
}

fn audit_one(yaml: &str, t: FakeTarget) -> sinter::audit::AuditResourceResult {
    let rep = audit(yaml, t);
    assert!(
        mutations(&rep.commands).is_empty(),
        "audit mutated: {:?}",
        mutations(&rep.commands)
    );
    rep.resources.into_iter().find(|r| r.id == "m").unwrap()
}

fn dims(r: &sinter::audit::AuditResourceResult) -> Vec<(String, String, String)> {
    r.details
        .iter()
        .map(|d| (d.dimension.clone(), d.observed.clone(), d.desired.clone()))
        .collect()
}

fn failed(code: i32, stderr: &str) -> Output {
    Output {
        completion: Completion::Exited(code),
        stdout: Vec::new(),
        stderr: stderr.as_bytes().to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

// ---------------------------------------------------------------------------
// authorized_keys: one line
// ---------------------------------------------------------------------------

fn ak_recipe(state: &str) -> String {
    line_recipe(
        AK,
        K3,
        &format!(
            "      state: {state}\n      owner: root\n      group: root\n      mode: \"0600\"\n"
        ),
    )
}

#[test]
fn authorized_keys_gets_one_new_key_and_the_existing_keys_stay_byte_identical() {
    let before = format!("{K1}\n{K2}\n");
    let r = apply(&ak_recipe("present"), with_file(fake(), AK, &before, 0o600));
    assert_changed(&r, "m");
    assert_eq!(content(&r, AK), format!("{K1}\n{K2}\n{K3}\n"));
    let (mode, uid, gid, _) = node(&r, AK);
    assert_eq!((mode & 0o7777, uid, gid), (0o600, 0, 0));
}

#[test]
fn authorized_keys_second_apply_changes_nothing_and_does_not_rewrite_the_file() {
    let first = apply(
        &ak_recipe("present"),
        with_file(fake(), AK, &format!("{K1}\n{K2}\n"), 0o600),
    );
    let mut t = fake();
    t.fs = first.fake_fs.clone();
    let ino = node(&first, AK).3;
    let second = apply(&ak_recipe("present"), t);
    assert_unchanged(&second, "m");
    assert_eq!(content(&second, AK), format!("{K1}\n{K2}\n{K3}\n"));
    assert_eq!(node(&second, AK).3, ino, "the file was replaced");
}

#[test]
fn authorized_keys_loses_exactly_the_one_declared_key() {
    let before = format!("{K1}\n{K3}\n{K2}\n");
    let r = apply(&ak_recipe("absent"), with_file(fake(), AK, &before, 0o600));
    assert_changed(&r, "m");
    assert_eq!(content(&r, AK), format!("{K1}\n{K2}\n"));
    // Again: nothing to do.
    let mut t = fake();
    t.fs = r.fake_fs.clone();
    assert_unchanged(&apply(&ak_recipe("absent"), t), "m");
}

#[test]
fn a_key_with_another_comment_or_other_options_is_another_line() {
    let other_comment = K3.replace("synthetic@example.invalid", "renamed@example.invalid");
    let with_options = format!("no-pty {K3}");
    let before = format!("{other_comment}\n{with_options}\n");
    // Removing K3 touches neither.
    let r = apply(&ak_recipe("absent"), with_file(fake(), AK, &before, 0o600));
    assert_unchanged(&r, "m");
    assert_eq!(content(&r, AK), before);
    // Adding K3 appends it; the two lines keep their options and comments.
    let r = apply(&ak_recipe("present"), with_file(fake(), AK, &before, 0o600));
    assert_changed(&r, "m");
    assert_eq!(content(&r, AK), format!("{before}{K3}\n"));
}

#[test]
fn several_keys_from_a_loop_share_one_file() {
    let yaml = format!(
        "version: 1\nresources:\n  - id: k\n    type: file_merge\n    loop:\n      - '{K1}'\n      - '{K3}'\n    with:\n      path: {AK}\n      merge: line\n      line: \"{{{{ item }}}}\"\n      create: true\n      mode: \"0600\"\n"
    );
    let r = apply(&yaml, with_file(fake(), AK, &format!("{K2}\n"), 0o600));
    assert_eq!(r.status, AggregateStatus::Success);
    assert_eq!(content(&r, AK), format!("{K2}\n{K1}\n{K3}\n"));
}

#[test]
fn root_edits_a_users_authorized_keys_as_that_user() {
    // FS-3: the file lives in an unprivileged account's tree, so every
    // operation on it runs as that account (`setpriv`), never as root.
    const UAK: &str = "/home/deploy/.ssh/authorized_keys";
    let mut t = FakeTarget::ubuntu2404()
        .with_fake_fs()
        .with_group("deploy", 1001)
        .with_user("deploy", 1001, 1001, "/home/deploy", "/bin/bash")
        .as_root();
    let fs = t.fs.as_mut().unwrap();
    fs.mkdir_node("/home", 0o755, 0, 0);
    fs.mkdir_node("/home/deploy", 0o755, 1001, 1001);
    fs.mkdir_node("/home/deploy/.ssh", 0o700, 1001, 1001);
    fs.put_file(UAK, format!("{K1}\n{K2}\n").as_bytes(), 0o600, 1001, 1001);
    let yaml = line_recipe(
        UAK,
        K3,
        "      owner: deploy\n      group: deploy\n      mode: \"0600\"\n",
    );
    let r = apply(&yaml, t);
    assert_changed(&r, "m");
    assert_eq!(content(&r, UAK), format!("{K1}\n{K2}\n{K3}\n"));
    let (mode, uid, gid, _) = node(&r, UAK);
    assert_eq!((mode & 0o7777, uid, gid), (0o600, 1001, 1001));
    // No mutation went out as root.
    let bare = mutations(&r.commands);
    assert!(bare.is_empty(), "mutations outside setpriv: {bare:?}");
    assert!(
        r.commands
            .iter()
            .any(|c| c.program == "/usr/bin/setpriv" && c.args.iter().any(|a| a == "1001")),
        "nothing ran as the account"
    );
}

// ---------------------------------------------------------------------------
// /etc/hosts: one block
// ---------------------------------------------------------------------------

const HOSTS_BEFORE: &str = "127.0.0.1 localhost\n::1 localhost\n";
const BEGIN: &str = "# BEGIN SINTER MANAGED BLOCK app-hosts";
const END: &str = "# END SINTER MANAGED BLOCK app-hosts";

fn hosts_recipe(body: &str) -> String {
    merge(&format!(
        "      path: {HOSTS}\n      merge: block\n      marker: app-hosts\n{body}"
    ))
}

const HOSTS_CONTENT: &str =
    "      content: |\n        192.0.2.10 app1.example.invalid\n        192.0.2.11 app2.example.invalid\n";

#[test]
fn hosts_block_is_appended_replaced_and_removed_without_touching_other_lines() {
    let r = apply(
        &hosts_recipe(HOSTS_CONTENT),
        with_file(fake(), HOSTS, HOSTS_BEFORE, 0o644),
    );
    assert_changed(&r, "m");
    let made = format!(
        "{HOSTS_BEFORE}{BEGIN}\n192.0.2.10 app1.example.invalid\n192.0.2.11 app2.example.invalid\n{END}\n"
    );
    assert_eq!(content(&r, HOSTS), made);

    // The same declaration again: no change.
    let mut t = fake();
    t.fs = r.fake_fs.clone();
    assert_unchanged(&apply(&hosts_recipe(HOSTS_CONTENT), t), "m");

    // Another content, with unmanaged lines after the block.
    let before = format!("{made}192.0.2.99 later.example.invalid\n");
    let r = apply(
        &hosts_recipe("      content: \"192.0.2.20 only.example.invalid\"\n"),
        with_file(fake(), HOSTS, &before, 0o644),
    );
    assert_changed(&r, "m");
    assert_eq!(
        content(&r, HOSTS),
        format!("{HOSTS_BEFORE}{BEGIN}\n192.0.2.20 only.example.invalid\n{END}\n192.0.2.99 later.example.invalid\n")
    );

    // Absent: the block and both marker lines go, nothing else.
    let r = apply(
        &hosts_recipe("      state: absent\n"),
        with_file(fake(), HOSTS, &before, 0o644),
    );
    assert_changed(&r, "m");
    assert_eq!(
        content(&r, HOSTS),
        format!("{HOSTS_BEFORE}192.0.2.99 later.example.invalid\n")
    );
    // The mode and owner of the existing file were not declared: kept.
    assert_eq!(node(&r, HOSTS).0 & 0o7777, 0o644);
}

#[test]
fn damaged_block_markers_fail_plan_and_apply_and_change_nothing() {
    for (before, want) in [
        (format!("{BEGIN}\na\n{BEGIN}\nb\n{END}\n"), "second BEGIN"),
        (format!("{BEGIN}\na\n"), "without an END"),
        (format!("{END}\n{BEGIN}\n"), "without a BEGIN"),
        (
            format!("{BEGIN}\n{BEGIN}\na\n{END}\n{END}\n"),
            "second BEGIN",
        ),
    ] {
        for body in [HOSTS_CONTENT, "      state: absent\n"] {
            let yaml = hosts_recipe(body);
            let e = plan_err(&yaml, with_file(fake(), HOSTS, &before, 0o644));
            assert_eq!(e.kind, ErrorKind::Plan);
            assert!(e.message.contains(want), "{}", e.message);
            assert!(e.message.contains(HOSTS), "{}", e.message);

            let r = apply(&yaml, with_file(fake(), HOSTS, &before, 0o644));
            assert_eq!(r.status, AggregateStatus::ApplyFailed);
            let x = res(&r, "m");
            assert_eq!(x.execution, Execution::Failed);
            assert_eq!(x.change, Change::None);
            assert!(
                x.reason.as_deref().unwrap().contains(want),
                "{:?}",
                x.reason
            );
            assert_eq!(content(&r, HOSTS), before);
            assert!(mutations(&r.commands).is_empty());
        }
    }
}

// ---------------------------------------------------------------------------
// one key = value
// ---------------------------------------------------------------------------

fn kv_recipe(body: &str) -> String {
    merge(&format!(
        "      path: {CONF}\n      merge: key_value\n      key: max_connections\n{body}"
    ))
}

#[test]
fn key_value_sets_changes_keeps_and_removes_one_setting() {
    let before = "# app settings\nlisten = 192.0.2.1\nmax_connections = 10\ntimeout=5\n";
    // Changed value: only that line is replaced.
    let yaml = kv_recipe("      value: \"100\"\n      separator: \" = \"\n");
    let r = apply(&yaml, with_file(fake(), CONF, before, 0o640));
    assert_changed(&r, "m");
    assert_eq!(
        content(&r, CONF),
        "# app settings\nlisten = 192.0.2.1\nmax_connections = 100\ntimeout=5\n"
    );
    assert_eq!(node(&r, CONF).0 & 0o7777, 0o640, "the mode is kept");

    // Same value, other spacing: not rewritten.
    let spaced = "max_connections   =100\n";
    let r = apply(&yaml, with_file(fake(), CONF, spaced, 0o644));
    assert_unchanged(&r, "m");
    assert_eq!(content(&r, CONF), spaced);

    // Missing key: appended.
    let r = apply(&yaml, with_file(fake(), CONF, "timeout=5", 0o644));
    assert_changed(&r, "m");
    assert_eq!(content(&r, CONF), "timeout=5\nmax_connections = 100\n");

    // Absent.
    let r = apply(
        &kv_recipe("      state: absent\n"),
        with_file(fake(), CONF, before, 0o644),
    );
    assert_changed(&r, "m");
    assert_eq!(
        content(&r, CONF),
        "# app settings\nlisten = 192.0.2.1\ntimeout=5\n"
    );
}

#[test]
fn key_value_duplicate_keys_and_sections_are_refused_not_guessed() {
    let yaml = kv_recipe("      value: \"100\"\n");
    for (before, want) in [
        (
            "max_connections=1\nmax_connections=2\n",
            "appears 2 times; Sinter does not guess which one is in effect",
        ),
        ("[server]\nmax_connections=1\n", "section header"),
        ("max_connections 1\n", "another separator"),
    ] {
        let e = plan_err(&yaml, with_file(fake(), CONF, before, 0o644));
        assert!(e.message.contains(want), "{}", e.message);
        let r = apply(&yaml, with_file(fake(), CONF, before, 0o644));
        assert_eq!(r.status, AggregateStatus::ApplyFailed);
        assert_eq!(res(&r, "m").change, Change::None);
        assert_eq!(content(&r, CONF), before);
    }
}

// ---------------------------------------------------------------------------
// text rules
// ---------------------------------------------------------------------------

#[test]
fn crlf_non_utf8_and_oversize_files_are_refused_and_left_alone() {
    let yaml = line_recipe(CONF, "x", "");
    let big = "a\n".repeat(140 * 1024);
    for (bytes, want) in [
        (&b"a\r\nb\r\n"[..], "carriage return"),
        (&b"caf\xe9\n"[..], "UTF-8"),
        (&b"a\0b\n"[..], "NUL"),
        (big.as_bytes(), "larger than"),
    ] {
        let mut t = fake();
        t.fs.as_mut().unwrap().put_file(CONF, bytes, 0o644, 0, 0);
        let e = plan_err(&yaml, t.clone());
        assert!(e.message.contains(want), "{}", e.message);
        let r = apply(&yaml, t.clone());
        assert_eq!(r.status, AggregateStatus::ApplyFailed);
        assert_eq!(r.fake_fs.as_ref().unwrap().file_bytes(CONF).unwrap(), bytes);
        assert!(mutations(&r.commands).is_empty());
        let a = audit_one(&yaml, t);
        assert_eq!(a.status, AuditResourceStatus::Error, "{:?}", a.reason);
        assert!(
            a.reason.as_deref().unwrap().contains(want),
            "{:?}",
            a.reason
        );
    }
}

// ---------------------------------------------------------------------------
// absent file
// ---------------------------------------------------------------------------

#[test]
fn an_absent_file_is_not_created_without_create_true() {
    let yaml = line_recipe(AK, K3, "");
    let e = plan_err(&yaml, fake());
    assert_eq!(e.kind, ErrorKind::Plan);
    assert!(
        e.message.contains("does not exist and create is false"),
        "{}",
        e.message
    );
    assert!(e.message.contains("create: true"), "{}", e.message);

    let r = apply(&yaml, fake());
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    let x = res(&r, "m");
    assert_eq!((x.execution, x.change), (Execution::Failed, Change::None));
    assert!(!r.fake_fs.as_ref().unwrap().nodes.contains_key(AK));
    assert!(mutations(&r.commands).is_empty());
}

#[test]
fn an_absent_file_is_created_with_create_true_and_the_declared_metadata() {
    let yaml = line_recipe(AK, K3, "      create: true\n      mode: \"0600\"\n");
    let p = plan(&yaml, fake());
    assert_eq!(res(&p, "m").change, Change::Changed);
    assert!(!p.fake_fs.as_ref().unwrap().nodes.contains_key(AK));

    let r = apply(&yaml, fake());
    assert_changed(&r, "m");
    assert_eq!(content(&r, AK), format!("{K3}\n"));
    let (mode, uid, gid, _) = node(&r, AK);
    assert_eq!((mode & 0o7777, uid, gid), (0o600, 0, 0));

    // Without a declared mode a new file gets the `file` default.
    let r = apply(&line_recipe(CONF, "x", "      create: true\n"), fake());
    assert_changed(&r, "m");
    assert_eq!(node(&r, CONF).0 & 0o7777, 0o644);
}

#[test]
fn state_absent_on_an_absent_file_is_nothing_to_do() {
    for yaml in [
        line_recipe(AK, K3, "      state: absent\n"),
        line_recipe(
            AK,
            K3,
            "      state: absent\n      create: true\n      mode: \"0600\"\n",
        ),
        hosts_recipe("      state: absent\n").replace(HOSTS, AK),
    ] {
        for mode in [Mode::Plan, Mode::Apply] {
            let r = run(mode, &yaml, fake());
            assert_unchanged(&r, "m");
            assert!(!r.fake_fs.as_ref().unwrap().nodes.contains_key(AK));
        }
        let a = audit_one(&yaml, fake());
        assert_eq!(a.status, AuditResourceStatus::Compliant, "{:?}", a.reason);
    }
}

#[test]
fn an_absent_parent_directory_behaves_as_for_file() {
    let path = "/srv/none/app.conf";
    let merge_yaml = line_recipe(path, "x", "      create: true\n");
    let file_yaml = doc(&format!(
        "  - id: m\n    type: file\n    with:\n      path: {path}\n      content: \"x\\n\"\n"
    ));
    let a = try_run(Mode::Plan, &merge_yaml, fake());
    let b = try_run(Mode::Plan, &file_yaml, fake());
    match (a, b) {
        (Err(a), Err(b)) => {
            assert_eq!(a.kind, b.kind);
            assert_eq!(a.message, b.message);
        }
        (Ok(a), Ok(b)) => {
            assert_eq!(res(&a, "m").change, res(&b, "m").change);
            assert_eq!(res(&a, "m").unknown, res(&b, "m").unknown);
        }
        (a, b) => panic!(
            "file_merge and file disagree: {:?} / {:?}",
            a.is_ok(),
            b.is_ok()
        ),
    }
    let a = apply(&merge_yaml, fake());
    let b = apply(&file_yaml, fake());
    assert_eq!(a.status, b.status);
    assert_eq!(res(&a, "m").execution, res(&b, "m").execution);
    assert_eq!(res(&a, "m").change, res(&b, "m").change);
}

#[test]
fn a_file_created_earlier_in_the_run_defers_the_create_false_refusal_to_apply() {
    // `first` creates the file; `second` must not create it itself.
    let yaml = doc(&format!(
        "  - id: first\n    type: file_merge\n    with:\n      path: {AK}\n      merge: line\n      line: '{K1}'\n      create: true\n      mode: \"0600\"\n  - id: second\n    type: file_merge\n    depends_on: [first]\n    with:\n      path: {AK}\n      merge: line\n      line: '{K3}'\n"
    ));
    let p = plan(&yaml, fake());
    assert_eq!(res(&p, "first").change, Change::Changed);
    let s = res(&p, "second");
    assert!(s.unknown, "{:?}", s);
    assert!(
        s.reason.as_deref().unwrap().contains("deferred to apply"),
        "{:?}",
        s.reason
    );

    let r = apply(&yaml, fake());
    assert_eq!(r.status, AggregateStatus::Success);
    assert_eq!(content(&r, AK), format!("{K1}\n{K3}\n"));
}

// ---------------------------------------------------------------------------
// plan
// ---------------------------------------------------------------------------

#[test]
fn plan_shows_the_change_as_a_file_diff_and_mutates_nothing() {
    let before = format!("{K1}\n{K2}\n");
    let t = with_file(fake(), AK, &before, 0o600);
    let ino_before = t.fs.as_ref().unwrap().nodes[AK].ino;
    let r = plan(&ak_recipe("present"), t.clone());
    assert_eq!(r.status, AggregateStatus::Success);
    assert_eq!(res(&r, "m").change, Change::Changed);
    assert!(
        mutations(&r.commands).is_empty(),
        "{:?}",
        mutations(&r.commands)
    );
    assert_eq!(content(&r, AK), before);
    assert_eq!(node(&r, AK).3, ino_before);
    assert_eq!(
        r.fake_fs.as_ref().unwrap().nodes.len(),
        t.fs.as_ref().unwrap().nodes.len()
    );
    let text = shown(Mode::Plan, &ak_recipe("present"), t);
    assert!(text.contains(&format!("+ {K3}")), "{text}");
    assert!(
        !text.contains(K1),
        "an unchanged line is in the diff:\n{text}"
    );

    // Nothing to change: no change planned.
    let same = with_file(fake(), AK, &format!("{K1}\n{K3}\n"), 0o600);
    let r = plan(&ak_recipe("present"), same);
    assert_unchanged(&r, "m");
}

#[test]
fn declared_metadata_is_enforced_without_rewriting_an_unchanged_file() {
    let before = format!("{K3}\n");
    let t = with_file(fake(), AK, &before, 0o644);
    let ino = t.fs.as_ref().unwrap().nodes[AK].ino;
    let p = plan(&ak_recipe("present"), t.clone());
    assert_eq!(res(&p, "m").change, Change::Changed);
    let r = apply(&ak_recipe("present"), t);
    assert_changed(&r, "m");
    let (mode, _, _, ino_after) = node(&r, AK);
    assert_eq!(mode & 0o7777, 0o600);
    assert_eq!(
        ino_after, ino,
        "a metadata change must not replace the file"
    );
    assert_eq!(content(&r, AK), before);
}

// ---------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------

#[test]
fn audit_is_compliant_when_the_managed_part_matches_whatever_else_the_file_holds() {
    let a = audit_one(
        &ak_recipe("present"),
        with_file(
            fake(),
            AK,
            &format!("{K1}\nunmanaged text\n{K3}\n{K2}\n"),
            0o600,
        ),
    );
    assert_eq!(a.status, AuditResourceStatus::Compliant, "{:?}", a.reason);
    let a = audit_one(
        &ak_recipe("absent"),
        with_file(fake(), AK, &format!("{K1}\n{K2}\n"), 0o600),
    );
    assert_eq!(a.status, AuditResourceStatus::Compliant, "{:?}", a.reason);
    let made = format!(
        "x\n{BEGIN}\n192.0.2.10 app1.example.invalid\n192.0.2.11 app2.example.invalid\n{END}\ny\n"
    );
    let a = audit_one(
        &hosts_recipe(HOSTS_CONTENT),
        with_file(fake(), HOSTS, &made, 0o644),
    );
    assert_eq!(a.status, AuditResourceStatus::Compliant, "{:?}", a.reason);
    let a = audit_one(
        &kv_recipe("      value: \"100\"\n"),
        with_file(fake(), CONF, "a=1\nmax_connections = 100\n", 0o644),
    );
    assert_eq!(a.status, AuditResourceStatus::Compliant, "{:?}", a.reason);
}

#[test]
fn audit_reports_drift_per_dimension() {
    let d = |yaml: &str, t: FakeTarget| {
        let a = audit_one(yaml, t);
        assert_eq!(a.status, AuditResourceStatus::Drift, "{:?}", a.reason);
        dims(&a)
    };
    let s = |a: &str, b: &str, c: &str| (a.to_string(), b.to_string(), c.to_string());
    // line
    assert_eq!(
        d(
            &ak_recipe("present"),
            with_file(fake(), AK, &format!("{K1}\n"), 0o600)
        ),
        vec![s("line", "absent", "present")]
    );
    assert_eq!(
        d(
            &ak_recipe("absent"),
            with_file(fake(), AK, &format!("{K3}\n{K3}\n"), 0o600)
        ),
        vec![s("line", "present (2 time(s))", "absent")]
    );
    // block
    assert_eq!(
        d(
            &hosts_recipe(HOSTS_CONTENT),
            with_file(fake(), HOSTS, HOSTS_BEFORE, 0o644)
        ),
        vec![s("block", "absent", "present")]
    );
    assert_eq!(
        d(
            &hosts_recipe(HOSTS_CONTENT),
            with_file(fake(), HOSTS, &format!("{BEGIN}\nother\n{END}\n"), 0o644)
        ),
        vec![s("block", "content differs", "declared content")]
    );
    assert_eq!(
        d(
            &hosts_recipe("      state: absent\n"),
            with_file(fake(), HOSTS, &format!("{BEGIN}\nother\n{END}\n"), 0o644)
        ),
        vec![s("block", "present", "absent")]
    );
    // value
    assert_eq!(
        d(
            &kv_recipe("      value: \"100\"\n"),
            with_file(fake(), CONF, "max_connections=10\n", 0o644)
        ),
        vec![s("value", "10", "100")]
    );
    assert_eq!(
        d(
            &kv_recipe("      value: \"100\"\n"),
            with_file(fake(), CONF, "a=1\n", 0o644)
        ),
        vec![s("value", "key absent", "100")]
    );
    // file absent: drift whatever `create` says
    for extra in ["", "      create: true\n"] {
        assert_eq!(
            d(&line_recipe(AK, K3, extra), fake()),
            vec![s("state", "absent", "present")]
        );
    }
    // metadata, together with the part
    let mut t = with_file(fake(), AK, &format!("{K1}\n"), 0o644);
    {
        let n = t.fs.as_mut().unwrap().nodes.get_mut(AK).unwrap();
        n.uid = 1000;
        n.gid = 1000;
    }
    assert_eq!(
        d(&ak_recipe("present"), t),
        vec![
            s("line", "absent", "present"),
            s("owner", "1000", "0"),
            s("group", "1000", "0"),
            s("mode", "0644", "0600"),
        ]
    );
    // undeclared metadata is never compared
    let a = audit_one(
        &line_recipe(AK, K3, ""),
        with_file(fake(), AK, &format!("{K3}\n"), 0o666),
    );
    assert_eq!(a.status, AuditResourceStatus::Compliant);
}

#[test]
fn audit_reports_unjudgeable_files_as_errors_never_as_drift() {
    let kv = kv_recipe("      value: \"100\"\n");
    let block = hosts_recipe(HOSTS_CONTENT);
    for (yaml, path, before, want) in [
        (
            &kv,
            CONF,
            "max_connections=1\nmax_connections=100\n",
            "appears 2 times",
        ),
        (&kv, CONF, "[s]\nmax_connections=100\n", "section header"),
        (
            &block,
            HOSTS,
            "# BEGIN SINTER MANAGED BLOCK app-hosts\n",
            "without an END",
        ),
        (&block, HOSTS, "x\r\n", "carriage return"),
    ] {
        let a = audit_one(yaml, with_file(fake(), path, before, 0o644));
        assert_eq!(a.status, AuditResourceStatus::Error, "{:?}", a);
        assert!(a.details.is_empty());
        assert!(
            a.reason.as_deref().unwrap().contains(want),
            "{:?}",
            a.reason
        );
    }
}

// ---------------------------------------------------------------------------
// symlinks, other objects, unobservable input
// ---------------------------------------------------------------------------

#[test]
fn a_symlink_at_the_path_is_refused_and_never_followed() {
    let target = "/etc/app/real.conf";
    let mk = || {
        let mut t = with_file(fake(), target, "a=1\n", 0o644);
        t.fs.as_mut().unwrap().put_symlink(CONF, target, 0, 0);
        t
    };
    for yaml in [
        line_recipe(CONF, "x", "      create: true\n"),
        line_recipe(CONF, "a=1", "      state: absent\n"),
    ] {
        let e = plan_err(&yaml, mk());
        assert!(e.message.contains("symlink"), "{}", e.message);
        let r = apply(&yaml, mk());
        assert_eq!(r.status, AggregateStatus::ApplyFailed);
        assert_eq!(res(&r, "m").change, Change::None);
        assert_eq!(content(&r, target), "a=1\n", "the link target was edited");
        assert!(mutations(&r.commands).is_empty());
        let a = audit_one(&yaml, mk());
        assert_eq!(a.status, AuditResourceStatus::Error, "{:?}", a);
    }
}

#[test]
fn a_directory_at_the_path_is_refused() {
    let yaml = line_recipe("/etc/app", "x", "      create: true\n");
    let e = plan_err(&yaml, fake());
    assert!(e.message.contains("refusing to edit"), "{}", e.message);
    let r = apply(&yaml, fake());
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    let a = audit_one(&yaml, fake());
    assert_eq!(a.status, AuditResourceStatus::Error, "{:?}", a);
}

#[test]
fn a_failed_read_is_an_error_and_not_an_absent_file() {
    // `create: true`: were the failure taken as absence, the file would be
    // replaced by a one-line file.
    let yaml = line_recipe(AK, K3, "      create: true\n");
    let before = format!("{K1}\n{K2}\n");
    let mk = || {
        with_file(fake(), AK, &before, 0o600).with_observations_at(
            "cat",
            AK,
            vec![failed(1, "cat: read error: Input/output error")],
        )
    };
    let e = plan_err(&yaml, mk());
    assert_eq!(e.kind, ErrorKind::Plan, "{}", e.message);
    let r = apply(&yaml, mk());
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    assert_eq!(res(&r, "m").change, Change::None);
    assert_eq!(content(&r, AK), before);
    assert!(mutations(&r.commands).is_empty());
    let a = audit_one(&yaml, mk());
    assert_eq!(a.status, AuditResourceStatus::Error, "{:?}", a);
    assert!(a.details.is_empty());
}

#[test]
fn a_truncated_read_is_an_error_and_never_edited() {
    let yaml = line_recipe(AK, K3, "");
    let before = format!("{K1}\n{K2}\n");
    let truncated = Output {
        completion: Completion::Exited(0),
        stdout: K1.as_bytes().to_vec(),
        stderr: Vec::new(),
        stdout_truncated: true,
        stderr_truncated: false,
    };
    // A short capture without the truncation flag: the size disagrees.
    let short = Output {
        stdout_truncated: false,
        ..truncated.clone()
    };
    for bad in [truncated, short] {
        let mk = || {
            with_file(fake(), AK, &before, 0o600).with_observations_at("cat", AK, vec![bad.clone()])
        };
        let e = plan_err(&yaml, mk());
        assert_eq!(e.kind, ErrorKind::Plan, "{}", e.message);
        let r = apply(&yaml, mk());
        assert_eq!(r.status, AggregateStatus::ApplyFailed);
        assert_eq!(content(&r, AK), before);
        assert!(mutations(&r.commands).is_empty());
        let a = audit_one(&yaml, mk());
        assert_eq!(a.status, AuditResourceStatus::Error, "{:?}", a);
    }
}

#[test]
fn a_failed_stat_is_an_error_and_not_an_absent_file() {
    let yaml = line_recipe(AK, K3, "      create: true\n");
    let before = format!("{K1}\n");
    let mk = || {
        with_file(fake(), AK, &before, 0o600).with_observations_at(
            "stat",
            AK,
            vec![failed(1, "stat: cannot statx: Input/output error")],
        )
    };
    assert!(try_run(Mode::Plan, &yaml, mk()).is_err());
    let r = try_run(Mode::Apply, &yaml, mk());
    match r {
        Err(_) => {}
        Ok(r) => {
            assert_ne!(r.status, AggregateStatus::Success);
            assert_eq!(content(&r, AK), before);
        }
    }
    let a = audit_one(&yaml, mk());
    assert_eq!(a.status, AuditResourceStatus::Error, "{:?}", a);
}

// ---------------------------------------------------------------------------
// concurrent change, partial failure, permissions
// ---------------------------------------------------------------------------

#[test]
fn a_file_changed_between_the_read_and_the_publication_is_not_overwritten() {
    let before = format!("{K1}\n");
    let concurrent = format!("{K1}\n{K2}\n");
    // Another actor rewrites the file right after Sinter read it: before
    // the content comparison, and after it (while the new file is staged).
    for (program, arg, why) in [
        ("sha256sum", AK, "changed since it was read"),
        ("sh", "stage", "drift"),
    ] {
        let t = with_file(fake(), AK, &before, 0o600).with_fs_event(
            program,
            arg,
            0,
            vec![FsEventAction::PutFile {
                path: AK.to_string(),
                data: concurrent.clone().into_bytes(),
                mode: 0o600,
                uid: 0,
                gid: 0,
            }],
        );
        let r = apply(&ak_recipe("present"), t);
        assert_eq!(r.status, AggregateStatus::ApplyFailed, "{program}");
        let x = res(&r, "m");
        assert_eq!(x.execution, Execution::Failed, "{program}");
        assert_eq!(x.change, Change::None, "{program}");
        assert!(
            x.reason.as_deref().unwrap().contains(why),
            "{program}: {:?}",
            x.reason
        );
        assert_eq!(
            content(&r, AK),
            concurrent,
            "{program}: the concurrent writer's file was lost"
        );
    }
}

fn run_fault(yaml: &str, t: FakeTarget, fault: &str) -> RunReport {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("r.yaml");
    std::fs::write(&p, yaml).unwrap();
    let mut o = opts(Mode::Apply, t);
    o.fault = Some(fault.to_string());
    Engine::new(load_model(&p).unwrap(), o)
        .unwrap()
        .run()
        .unwrap()
}

#[test]
fn a_failure_before_or_after_publication_is_never_reported_as_success() {
    let before = format!("{K1}\n");
    let r = run_fault(
        &ak_recipe("present"),
        with_file(fake(), AK, &before, 0o600),
        "before_publish",
    );
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    let x = res(&r, "m");
    assert_eq!((x.execution, x.change), (Execution::Failed, Change::None));
    assert_eq!(content(&r, AK), before);

    let r = run_fault(
        &ak_recipe("present"),
        with_file(fake(), AK, &before, 0o600),
        "reobserve_fail",
    );
    assert_ne!(r.status, AggregateStatus::Success);
    let x = res(&r, "m");
    assert_ne!(x.execution, Execution::Succeeded);
    assert_eq!(x.change, Change::Changed, "the publication happened");

    let r = run_fault(
        &ak_recipe("present"),
        with_file(fake(), AK, &before, 0o600),
        "indeterminate_publish",
    );
    assert_eq!(r.status, AggregateStatus::Indeterminate);
    assert_eq!(res(&r, "m").execution, Execution::Indeterminate);
}

#[test]
fn plan_tells_an_unprivileged_user_that_the_change_needs_root() {
    // The scripted user is not root and `--sudo` is not given. (The scripted
    // filesystem does not model EACCES on writes; the note is what plan
    // itself decides.)
    let mut t = FakeTarget::rocky9().with_fake_fs();
    t.fs.as_mut()
        .unwrap()
        .put_file(HOSTS, HOSTS_BEFORE.as_bytes(), 0o644, 0, 0);
    let p = plan(&hosts_recipe(HOSTS_CONTENT), t);
    let x = res(&p, "m");
    assert_eq!(x.change, Change::Changed);
    assert!(
        x.notes
            .iter()
            .any(|n| n.starts_with("needs root: /etc belongs to root")),
        "plan gave no privilege note: {:?}",
        x.notes
    );
}

#[test]
fn a_file_the_user_may_not_read_is_an_error_and_is_not_taken_as_absent() {
    let yaml = line_recipe(AK, K3, "      create: true\n");
    let before = format!("{K1}\n");
    let mk = || {
        let mut t = FakeTarget::rocky9().with_fake_fs();
        let fs = t.fs.as_mut().unwrap();
        fs.mkdir_node("/root", 0o755, 0, 0);
        fs.mkdir_node("/root/.ssh", 0o755, 0, 0);
        fs.put_file(AK, before.as_bytes(), 0o600, 0, 0);
        t.with_observations_at(
            "cat",
            AK,
            vec![failed(
                1,
                "/bin/cat: /root/.ssh/authorized_keys: Permission denied",
            )],
        )
    };
    let e = plan_err(&yaml, mk());
    assert_eq!(e.kind, ErrorKind::Plan, "{}", e.message);
    let r = apply(&yaml, mk());
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    let x = res(&r, "m");
    assert_eq!((x.execution, x.change), (Execution::Failed, Change::None));
    assert_eq!(content(&r, AK), before);
    assert!(mutations(&r.commands).is_empty());
    let a = audit_one(&yaml, mk());
    assert_eq!(a.status, AuditResourceStatus::Error, "{:?}", a);
}

// ---------------------------------------------------------------------------
// sensitive values
// ---------------------------------------------------------------------------

fn sensitive_recipes() -> Vec<(&'static str, String)> {
    vec![
        (
            "sensitive: true",
            doc(&format!(
                "  - id: m\n    type: file_merge\n    sensitive: true\n    with:\n      path: {CONF}\n      merge: key_value\n      key: api_token\n      value: {SECRET}\n"
            )),
        ),
        (
            "sensitive variable",
            format!(
                "version: 1\nvars:\n  token:\n    value: {SECRET}\n    sensitive: true\nresources:\n  - id: m\n    type: file_merge\n    with:\n      path: {CONF}\n      merge: key_value\n      key: api_token\n      value: \"{{{{ vars.token }}}}\"\n"
            ),
        ),
        (
            "sensitive line",
            format!(
                "version: 1\nvars:\n  token:\n    value: {SECRET}\n    sensitive: true\nresources:\n  - id: m\n    type: file_merge\n    with:\n      path: {CONF}\n      merge: line\n      line: \"token {{{{ vars.token }}}}\"\n"
            ),
        ),
        (
            "sensitive block",
            format!(
                "version: 1\nvars:\n  token:\n    value: {SECRET}\n    sensitive: true\nresources:\n  - id: m\n    type: file_merge\n    with:\n      path: {CONF}\n      merge: block\n      marker: tok\n      content: \"token {{{{ vars.token }}}}\\n\"\n"
            ),
        ),
    ]
}

#[test]
fn sensitive_values_appear_in_no_plan_apply_or_audit_output() {
    const OLD: &str = "SINTER-TEST-CANARY-old-value-1111";
    let before = format!("user=app\napi_token={OLD}\n");
    for (what, yaml) in sensitive_recipes() {
        for mode in [Mode::Plan, Mode::Apply] {
            let text = shown(mode, &yaml, with_file(fake(), CONF, &before, 0o600));
            assert!(
                !text.contains(SECRET),
                "{what} {mode:?} leaked the value:\n{text}"
            );
            assert!(
                !text.contains(OLD),
                "{what} {mode:?} leaked the old value:\n{text}"
            );
            assert!(text.contains("redacted"), "{what} {mode:?}:\n{text}");
        }
        // The change itself is made.
        let r = apply(&yaml, with_file(fake(), CONF, &before, 0o600));
        assert_changed(&r, "m");
        assert!(res(&r, "m").sensitive);
        assert!(content(&r, CONF).contains(SECRET));
        for c in &r.commands {
            assert!(
                !c.args.iter().any(|a| a.contains(SECRET)),
                "{what}: the value is in the command log: {} {:?}",
                c.program,
                c.args
            );
        }

        let rep = audit(&yaml, with_file(fake(), CONF, &before, 0o600));
        let a = rep.resources.iter().find(|r| r.id == "m").unwrap();
        assert_eq!(a.status, AuditResourceStatus::Drift, "{what}: {:?}", a);
        assert!(a.sensitive);
        let text = audit_shown(&rep);
        assert!(!text.contains(SECRET), "{what} audit leaked:\n{text}");
        assert!(
            !text.contains(OLD),
            "{what} audit leaked the old value:\n{text}"
        );
    }
}

#[test]
fn a_sensitive_resource_names_no_value_when_it_is_refused() {
    let dup = format!("api_token={SECRET}\napi_token={SECRET}\n");
    for (what, yaml) in sensitive_recipes().into_iter().take(2) {
        for mode in [Mode::Plan, Mode::Apply] {
            let text = shown(mode, &yaml, with_file(fake(), CONF, &dup, 0o600));
            assert!(!text.contains(SECRET), "{what} {mode:?}:\n{text}");
        }
        let rep = audit(&yaml, with_file(fake(), CONF, &dup, 0o600));
        let a = rep.resources.iter().find(|r| r.id == "m").unwrap();
        assert_eq!(a.status, AuditResourceStatus::Error);
        assert!(!audit_shown(&rep).contains(SECRET), "{what}");
    }
}

#[test]
fn a_new_file_of_a_sensitive_resource_is_private_by_default() {
    let yaml = doc(&format!(
        "  - id: m\n    type: file_merge\n    sensitive: true\n    with:\n      path: {CONF}\n      merge: line\n      line: token {SECRET}\n      create: true\n"
    ));
    let r = apply(&yaml, fake());
    assert_changed(&r, "m");
    assert_eq!(node(&r, CONF).0 & 0o7777, 0o600);
}

// ---------------------------------------------------------------------------
// load-time checks
// ---------------------------------------------------------------------------

#[test]
fn invalid_declarations_are_rejected_when_the_recipe_is_loaded() {
    let cases: Vec<(String, &str)> = vec![
        (merge("      merge: line\n      line: x\n"), "missing required field path"),
        (merge("      path: etc/x\n      merge: line\n      line: x\n"), "absolute"),
        (merge("      path: /etc/x\n      line: x\n"), "missing required field merge"),
        (merge("      path: /etc/x\n      merge: regex\n      line: x\n"), "merge must be one of"),
        (merge("      path: /etc/x\n      merge: line\n"), "requires line"),
        (merge("      path: /etc/x\n      merge: line\n      line: |\n        x\n"), "exactly one line"),
        (merge("      path: /etc/x\n      merge: line\n      line: \"  \"\n"), "only whitespace"),
        (merge("      path: /etc/x\n      merge: line\n      line: x\n      regex: y\n"), "unknown field with.regex"),
        (merge("      path: /etc/x\n      merge: line\n      line: x\n      marker: y\n"), "does not apply to merge: line"),
        (merge("      path: /etc/x\n      merge: line\n      line: x\n      state: gone\n"), "present or absent"),
        (merge("      path: /etc/x\n      merge: line\n      line: x\n      create: maybe\n"), "create must be a boolean"),
        (merge("      path: /etc/x\n      merge: line\n      line: x\n      mode: \"600\"\n"), "mode"),
        (merge("      path: /etc/x\n      merge: line\n      line: x\n      owner: \"\"\n"), "invalid owner"),
        (merge("      path: /etc/x\n      merge: block\n      marker: m\n"), "requires content"),
        (merge("      path: /etc/x\n      merge: block\n      content: x\n"), "requires marker"),
        (merge("      path: /etc/x\n      merge: block\n      marker: \"a b\"\n      content: x\n"), "marker must be"),
        (merge("      path: /etc/x\n      merge: block\n      marker: m\n      content: x\n      comment_prefix: \"%\"\n"), "comment_prefix must be one of"),
        (
            merge("      path: /etc/x\n      merge: block\n      marker: m\n      content: \"# END SINTER MANAGED BLOCK other\"\n"),
            "may not contain marker lines",
        ),
        (merge("      path: /etc/x\n      merge: key_value\n      value: v\n"), "requires key"),
        (merge("      path: /etc/x\n      merge: key_value\n      key: k\n"), "requires value"),
        (merge("      path: /etc/x\n      merge: key_value\n      key: \"k k\"\n      value: v\n"), "key must be"),
        (merge("      path: /etc/x\n      merge: key_value\n      key: k\n      value: \"a\\nb\"\n"), "one line"),
        (merge("      path: /etc/x\n      merge: key_value\n      key: k\n      value: v\n      separator: \"->\"\n"), "separator must be one of"),
        // Static fields may not come from facts or registers.
        (
            merge("      path: /etc/x\n      merge: block\n      marker: \"{{ facts.os.family }}\"\n      content: x\n"),
            "facts",
        ),
        (
            merge("      path: /etc/x\n      merge: key_value\n      key: \"{{ facts.os.family }}\"\n      value: v\n"),
            "facts",
        ),
    ];
    for (yaml, want) in cases {
        let e = load_err(&yaml);
        assert!(e.contains(want), "wanted {want:?} in {e:?} for:\n{yaml}");
    }
}

#[test]
fn static_fields_from_variables_are_checked_with_their_values() {
    let yaml = |marker: &str| {
        format!(
            "version: 1\nvars:\n  m:\n    value: \"{marker}\"\nresources:\n  - id: m\n    type: file_merge\n    with:\n      path: {HOSTS}\n      merge: block\n      marker: \"{{{{ vars.m }}}}\"\n      content: x\n"
        )
    };
    assert!(load_err(&yaml("not valid")).contains("marker is not valid"));
    let r = apply(&yaml("from-var"), with_file(fake(), HOSTS, "", 0o644));
    assert_changed(&r, "m");
    assert_eq!(
        content(&r, HOSTS),
        "# BEGIN SINTER MANAGED BLOCK from-var\nx\n# END SINTER MANAGED BLOCK from-var\n"
    );
}

#[test]
fn a_line_from_a_register_is_unknown_in_plan_and_checked_when_evaluated() {
    let yaml = doc(&format!(
        "  - id: gen\n    type: command\n    with:\n      program: /usr/bin/true\n      register: out\n  - id: m\n    type: file_merge\n    depends_on: [gen]\n    with:\n      path: {CONF}\n      merge: line\n      line: \"{{{{ registers.out.stdout }}}}\"\n"
    ));
    let p = plan(&yaml, with_file(fake(), CONF, "a\n", 0o644));
    assert!(res(&p, "m").unknown);
}

fn prepared(yaml: &str) -> (tempfile::TempDir, sinter::model::Prepared) {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("r.yaml");
    std::fs::write(&p, yaml).unwrap();
    let prepared = sinter::model::prepare(&p).unwrap_or_else(|e| panic!("{}", e.message));
    (d, prepared)
}

#[test]
fn a_structure_only_check_leaves_what_a_variable_decides_and_judges_the_rest() {
    let head = "version: 1\nvars:\n  m: { value: \"CHANGE ME\" }\n  kind: { value: line }\n  p: { value: CHANGE_ME }\nresources:\n";
    // A placeholder marker, path or merge is not judged ...
    for body in [
        fm(
            "a",
            "/etc/x",
            "      merge: block\n      marker: \"{{ vars.m }}\"\n      content: x\n",
        ),
        fm(
            "a",
            "\"{{ vars.p }}\"",
            "      merge: line\n      line: x\n",
        ),
        fm(
            "a",
            "/etc/x",
            "      merge: \"{{ vars.kind }}\"\n      marker: m\n      content: x\n",
        ),
        // ... nor a conflict a variable takes part in.
        format!(
            "{}{}",
            fm(
                "a",
                "/etc/x",
                "      merge: block\n      marker: \"{{ vars.kind }}\"\n      content: x\n"
            ),
            fm(
                "b",
                "/etc/x",
                "      merge: block\n      marker: line\n      content: y\n"
            )
        ),
        format!(
            "{}{}",
            fm(
                "a",
                "\"/etc/{{ vars.kind }}\"",
                "      merge: line\n      line: x\n"
            ),
            "  - id: b\n    type: file\n    with: { path: /etc/line, content: y }\n"
        ),
    ] {
        let (_d, p) = prepared(&format!("{head}{body}"));
        p.check_structure()
            .unwrap_or_else(|e| panic!("{}\n{body}", e.message));
    }
    // Everything no variable decides still fails.
    for (body, want) in [
        (
            fm(
                "a",
                "\"{{ vars.p }}\"",
                "      merge: block\n      marker: \"bad name\"\n      content: x\n",
            ),
            "marker",
        ),
        (
            format!(
                "{}{}",
                fm(
                    "a",
                    "/etc/x",
                    "      merge: line\n      line: \"{{ vars.kind }}\"\n"
                ),
                "  - id: b\n    type: file\n    with: { path: /etc/x, content: y }\n"
            ),
            "conflicting management of path /etc/x",
        ),
        (
            format!(
                "{}{}",
                fm(
                    "a",
                    "/etc/x",
                    "      merge: key_value\n      key: k\n      value: \"{{ vars.kind }}\"\n"
                ),
                fm(
                    "b",
                    "/etc/x",
                    "      merge: key_value\n      key: k\n      value: other\n"
                )
            ),
            "the same key k",
        ),
    ] {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("r.yaml");
        std::fs::write(&p, format!("{head}{body}")).unwrap();
        let e = sinter::model::prepare(&p)
            .and_then(|p| p.check_structure())
            .err()
            .unwrap_or_else(|| panic!("accepted:\n{body}"));
        assert!(e.message.contains(want), "{}", e.message);
    }
}

#[test]
fn a_value_of_a_variables_file_is_withheld_from_a_failed_static_check() {
    const HELD: &str = "held-canary-value";
    let head = "version: 1\nvars:\n  m: { value: ok }\nresources:\n";
    let mut over = sinter::model::VarOverrides::default();
    over.insert("m", sinter::value::Value::Str(format!("{HELD} x")), "vars");
    // An invalid marker from the variables file.
    let (_d, p) = prepared(&format!(
        "{head}{}",
        fm(
            "a",
            "/etc/x",
            "      merge: block\n      marker: \"{{ vars.m }}\"\n      content: x\n"
        )
    ));
    let e = p.freeze_with(&over).expect_err("accepted");
    assert!(e.message.contains("field marker"), "{}", e.message);
    assert!(e.message.contains("withheld"), "{}", e.message);
    assert!(!e.message.contains(HELD), "{}", e.message);

    // A conflict the variables file causes: the path it decides is not named.
    let mut over = sinter::model::VarOverrides::default();
    over.insert("m", sinter::value::Value::Str(HELD.to_string()), "vars");
    for body in [
        format!(
            "{}{}",
            fm("a", "\"/etc/{{ vars.m }}\"", "      merge: line\n      line: same\n"),
            fm("b", &format!("/etc/{HELD}"), "      merge: line\n      line: same\n")
        ),
        format!(
            "{}{}",
            fm("a", "\"/etc/{{ vars.m }}\"", "      merge: line\n      line: one\n      mode: \"0600\"\n"),
            fm("b", &format!("/etc/{HELD}"), "      merge: line\n      line: two\n      mode: \"0644\"\n")
        ),
        format!(
            "{}  - id: b\n    type: file\n    with: {{ path: \"/etc/{{{{ vars.m }}}}\", content: y }}\n",
            fm("a", &format!("/etc/{HELD}"), "      merge: line\n      line: one\n"),
        ),
    ] {
        let (_d, p) = prepared(&format!("{head}{body}"));
        let e = p.freeze_with(&over).expect_err("accepted");
        assert!(e.message.contains("ownership of field path"), "{}", e.message);
        assert!(e.message.contains("withheld"), "{}", e.message);
        // The literal side of the recipe may be named; the message as a
        // whole is the generic one, without the conflict's own text.
        assert!(!e.message.contains("conflicting"), "{}", e.message);
    }
}

fn two(first: &str, second: &str) -> String {
    doc(&format!("{first}{second}"))
}

fn fm(id: &str, path: &str, body: &str) -> String {
    format!("  - id: {id}\n    type: file_merge\n    with:\n      path: {path}\n{body}")
}

#[test]
fn whole_path_and_partial_management_of_one_path_is_refused_in_either_order() {
    let part = fm("part", "/etc/x", "      merge: line\n      line: x\n");
    for whole in [
        "  - id: whole\n    type: file\n    with: { path: /etc/x, content: y }\n".to_string(),
        "  - id: whole\n    type: file\n    with: { path: /etc/x, state: absent }\n".to_string(),
        "  - id: whole\n    type: directory\n    with: { path: /etc/x }\n".to_string(),
        "  - id: whole\n    type: link\n    with: { path: /etc/x, target: /etc/y }\n".to_string(),
    ] {
        for yaml in [two(&whole, &part), two(&part, &whole)] {
            let e = load_err(&yaml);
            assert!(e.contains("conflicting management of path /etc/x"), "{e}");
            assert!(e.contains("whole") && e.contains("part"), "{e}");
        }
    }
    // A systemd_timer owns its unit file.
    let timer =
        "  - id: whole\n    type: systemd_timer\n    with: { name: backup, on_calendar: daily }\n";
    let part = fm(
        "part",
        "/etc/systemd/system/backup.timer",
        "      merge: line\n      line: x\n",
    );
    for yaml in [two(timer, &part), two(&part, timer)] {
        assert!(load_err(&yaml).contains("conflicting management of path"));
    }
    // A template too.
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("t.j2"), "x\n").unwrap();
    let p = d.path().join("r.yaml");
    std::fs::write(
        &p,
        two(
            "  - id: whole\n    type: template\n    with: { path: /etc/x, source: t.j2 }\n",
            &fm("part", "/etc/x", "      merge: line\n      line: x\n"),
        ),
    )
    .unwrap();
    let e = load_model(&p).expect_err("accepted").message;
    assert!(e.contains("conflicting management of path /etc/x"), "{e}");
}

#[test]
fn several_file_merge_resources_share_a_path_when_their_parts_differ() {
    let yaml = doc(&[
        fm("l1", CONF, "      merge: line\n      line: one\n"),
        fm("l2", CONF, "      merge: line\n      line: two\n      depends_on_placeholder: x\n")
            .replace("      depends_on_placeholder: x\n", ""),
        fm("b1", CONF, "      merge: block\n      marker: a\n      content: in-a\n"),
        fm("b2", CONF, "      merge: block\n      marker: b\n      content: in-b\n      comment_prefix: \";\"\n"),
        fm("k1", CONF, "      merge: key_value\n      key: alpha\n      value: \"1\"\n"),
        fm("k2", CONF, "      merge: key_value\n      key: beta\n      value: \"2\"\n"),
    ]
    .concat());
    let r = apply(&yaml, with_file(fake(), CONF, "", 0o644));
    assert_eq!(r.status, AggregateStatus::Success);
    assert_eq!(
        content(&r, CONF),
        "one\ntwo\n# BEGIN SINTER MANAGED BLOCK a\nin-a\n# END SINTER MANAGED BLOCK a\n; BEGIN SINTER MANAGED BLOCK b\nin-b\n; END SINTER MANAGED BLOCK b\nalpha=1\nbeta=2\n"
    );
    // Converged.
    let mut t = fake();
    t.fs = r.fake_fs.clone();
    let again = apply(&yaml, t);
    assert_eq!(again.status, AggregateStatus::Success);
    assert!(again.resources.iter().all(|x| x.change == Change::None));
    assert!(mutations(&again.commands).is_empty());
}

#[test]
fn two_file_merge_resources_with_the_same_identity_are_refused() {
    for (a, b, want) in [
        (
            "      merge: line\n      line: same\n",
            "      merge: line\n      line: same\n      state: absent\n",
            "the same line",
        ),
        (
            "      merge: block\n      marker: m\n      content: a\n",
            "      merge: block\n      marker: m\n      content: b\n      comment_prefix: \";\"\n",
            "the same block marker m",
        ),
        (
            "      merge: key_value\n      key: k\n      value: a\n",
            "      merge: key_value\n      key: k\n      value: b\n      separator: \":\"\n",
            "the same key k",
        ),
    ] {
        let e = load_err(&two(&fm("a", CONF, a), &fm("b", CONF, b)));
        assert!(
            e.contains("conflicting file_merge resources a and b"),
            "{e}"
        );
        assert!(e.contains(want), "{e}");
        // Another path: no conflict.
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("r.yaml");
        std::fs::write(
            &p,
            two(&fm("a", CONF, a), &fm("b", "/etc/app/other.conf", b)),
        )
        .unwrap();
        load_model(&p).unwrap();
    }
    // The line of a conflict is never echoed.
    let e = load_err(&two(
        &fm(
            "a",
            CONF,
            &format!("      merge: line\n      line: {SECRET}\n"),
        ),
        &fm(
            "b",
            CONF,
            &format!("      merge: line\n      line: {SECRET}\n"),
        ),
    ));
    assert!(!e.contains(SECRET), "{e}");
}

#[test]
fn the_same_line_through_a_variable_is_a_conflict_but_a_register_line_is_not_compared() {
    let via_var = format!(
        "version: 1\nvars:\n  l:\n    value: same\nresources:\n{}{}",
        fm("a", CONF, "      merge: line\n      line: same\n"),
        fm(
            "b",
            CONF,
            "      merge: line\n      line: \"{{ vars.l }}\"\n"
        ),
    );
    assert!(load_err(&via_var).contains("the same line"));

    let via_register = doc(&format!(
        "  - id: gen\n    type: command\n    with:\n      program: /usr/bin/true\n      register: out\n{}{}",
        fm("a", CONF, "      merge: line\n      line: same\n"),
        "  - id: b\n    type: file_merge\n    depends_on: [gen]\n    with:\n      path: /etc/app/app.conf\n      merge: line\n      line: \"{{ registers.out.stdout }}\"\n",
    ));
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("r.yaml");
    std::fs::write(&p, via_register).unwrap();
    load_model(&p).unwrap();
}

#[test]
fn different_metadata_for_one_path_is_refused() {
    for (field, a, b) in [
        ("mode", "\"0600\"", "\"0644\""),
        ("owner", "root", "app"),
        ("group", "root", "app"),
    ] {
        let e = load_err(&two(
            &fm(
                "a",
                CONF,
                &format!("      merge: line\n      line: one\n      {field}: {a}\n"),
            ),
            &fm(
                "b",
                CONF,
                &format!("      merge: line\n      line: two\n      {field}: {b}\n"),
            ),
        ));
        assert!(
            e.contains(&format!("declare different {field} for path {CONF}")),
            "{e}"
        );
    }
    // The same value, or only one side declaring it: accepted.
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("r.yaml");
    std::fs::write(
        &p,
        doc(&[
            fm(
                "a",
                CONF,
                "      merge: line\n      line: one\n      mode: \"0600\"\n      owner: root\n",
            ),
            fm(
                "b",
                CONF,
                "      merge: line\n      line: two\n      mode: \"0600\"\n",
            ),
            fm("c", CONF, "      merge: line\n      line: three\n"),
        ]
        .concat()),
    )
    .unwrap();
    load_model(&p).unwrap();
}

// ---------------------------------------------------------------------------
// handlers, platform
// ---------------------------------------------------------------------------

#[test]
fn a_change_notifies_its_handler_and_no_change_does_not() {
    let yaml = format!(
        "version: 1\nresources:\n  - id: m\n    type: file_merge\n    notify: [restart-app]\n    with:\n      path: {CONF}\n      merge: key_value\n      key: workers\n      value: \"4\"\nhandlers:\n  - id: restart-app\n    service: app.service\n    action: restart\n"
    );
    let t = || {
        fake().with_loaded_unit(
            "app.service",
            "[Service]\nExecStart=/usr/bin/true\n",
            ("loaded", "active", "enabled"),
        )
    };
    let restarts = |r: &RunReport| {
        r.commands
            .iter()
            .filter(|c| c.program.ends_with("systemctl") && c.args.iter().any(|a| a == "restart"))
            .count()
    };
    let r = apply(&yaml, with_file(t(), CONF, "workers=2\n", 0o644));
    assert_eq!(
        r.status,
        AggregateStatus::Success,
        "{:?} {:?}",
        r.resources,
        r.handlers_run
    );
    assert_eq!(res(&r, "m").change, Change::Changed);
    assert_eq!(restarts(&r), 1, "the handler did not run once");

    let r = apply(&yaml, with_file(t(), CONF, "workers=4\n", 0o644));
    assert_eq!(r.status, AggregateStatus::Success);
    assert_eq!(res(&r, "m").change, Change::None);
    assert_eq!(restarts(&r), 0, "the handler ran without a change");
}

#[test]
fn an_unrecognized_os_needs_no_platform_backend_exactly_like_file() {
    // `file_merge` uses only the commands of the `file` resource, which runs
    // on a platform Sinter does not recognize (only package, service and
    // account resources need a backend). The two must agree.
    let mk = || {
        let mut t = FakeTarget::unsupported().with_fake_fs().as_root();
        t.fs.as_mut().unwrap().put_file(CONF, b"a=1\n", 0o644, 0, 0);
        t
    };
    let merge_yaml = line_recipe(CONF, "x", "");
    let file_yaml = doc(&format!(
        "  - id: m\n    type: file\n    with:\n      path: {CONF}\n      content: \"a=1\\nx\\n\"\n"
    ));
    for mode in [Mode::Plan, Mode::Apply] {
        let a = run(mode, &merge_yaml, mk());
        let b = run(mode, &file_yaml, mk());
        assert_eq!(a.status, b.status, "{mode:?}");
        assert_eq!(a.status, AggregateStatus::Success, "{mode:?}");
        assert_eq!(res(&a, "m").change, res(&b, "m").change, "{mode:?}");
        assert_eq!(content(&a, CONF), content(&b, CONF), "{mode:?}");
    }
}

// ---------------------------------------------------------------------------
// documentation
// ---------------------------------------------------------------------------

/// The fenced blocks of language `lang` in a documentation page.
fn fenced(text: &str, lang: &str) -> Vec<String> {
    let open = format!("```{lang}\n");
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find(&open) {
        let body = &rest[i + open.len()..];
        let end = body.find("```").expect("unterminated block");
        out.push(body[..end].to_string());
        rest = &body[end + 3..];
    }
    out
}

#[test]
fn the_documented_recipes_load_and_yaml_and_toml_say_the_same() {
    for locale in ["en", "ja"] {
        let page = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "docs-site/src/content/docs/{locale}/reference/resources/file_merge.md"
        ));
        let text = std::fs::read_to_string(&page).unwrap();
        let yaml: Vec<String> = fenced(&text, "yaml")
            .into_iter()
            .filter(|b| b.starts_with("version: 1\n"))
            .collect();
        let toml = fenced(&text, "toml");
        assert_eq!(yaml.len(), 3, "{locale}: complete YAML recipes");
        assert_eq!(toml.len(), 3, "{locale}: TOML twins");
        for (y, t) in yaml.iter().zip(&toml) {
            let d = tempfile::tempdir().unwrap();
            let yp = d.path().join("r.yaml");
            let tp = d.path().join("r.toml");
            std::fs::write(&yp, y).unwrap();
            std::fs::write(&tp, t).unwrap();
            let ym = load_model(&yp).unwrap_or_else(|e| panic!("{locale}: {}\n{y}", e.message));
            let tm = load_model(&tp).unwrap_or_else(|e| panic!("{locale}: {}\n{t}", e.message));
            assert_eq!(ym.resources.len(), tm.resources.len());
            for (a, b) in ym.resources.iter().zip(&tm.resources) {
                assert_eq!(a.type_, "file_merge");
                assert_eq!((&a.id, &a.path, &a.notify), (&b.id, &b.path, &b.notify));
                assert_eq!(
                    a.with, b.with,
                    "{locale}: {} differs between YAML and TOML",
                    a.id
                );
            }
        }
    }
}

#[test]
fn the_documented_recipes_do_what_the_page_says() {
    let page = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("docs-site/src/content/docs/en/reference/resources/file_merge.md");
    let text = std::fs::read_to_string(&page).unwrap();
    let hosts = fenced(&text, "yaml")
        .into_iter()
        .find(|b| b.starts_with("version: 1\n") && b.contains("merge: block"))
        .unwrap();
    let r = apply(
        &hosts,
        with_file(fake(), HOSTS, "127.0.0.1 localhost\n", 0o644),
    );
    assert_eq!(r.status, AggregateStatus::Success);
    let shown = fenced(&text, "text")
        .into_iter()
        .find(|b| b.starts_with("127.0.0.1 localhost\n"))
        .unwrap();
    assert_eq!(content(&r, HOSTS), shown);
}

// ---------------------------------------------------------------------------
// audit findings: DNF configuration, content comparison, hard links, display
// ---------------------------------------------------------------------------

#[test]
fn dnf_configuration_is_not_edited_by_file_merge() {
    for path in [
        "/etc/yum.repos.d/x.repo",
        "/etc/yum.repos.d/sub/x.repo",
        "/etc/yum.repos.d",
        "/etc/dnf/dnf.conf",
        "/etc/dnf/modules.d/nodejs.module",
        "/etc/dnf/vars/releasever",
        "/etc/dnf",
        "/etc/yum.conf",
        "/etc/yum/vars/releasever",
        "/etc/yum/pluginconf.d/x.conf",
    ] {
        for with in [
            format!("      path: {path}\n      merge: line\n      line: 'gpgcheck=0'\n"),
            format!(
                "      path: {path}\n      merge: block\n      marker: m\n      content: \"gpgcheck=0\\n\"\n"
            ),
            format!(
                "      path: {path}\n      merge: key_value\n      key: gpgcheck\n      value: \"0\"\n"
            ),
        ] {
            let e = load_err(&merge(&with));
            assert!(
                e.contains("does not edit DNF configuration")
                    && e.contains("dnf_repository")
                    && e.contains("package signature checking"),
                "{path}: {e}"
            );
        }
    }
    // The path from a static variable is judged too.
    let e = load_err(
        "version: 1\nvars:\n  d:\n    value: /etc/yum.repos.d\nresources:\n  - id: m\n    type: file_merge\n    with:\n      path: \"{{ vars.d }}/x.repo\"\n      merge: line\n      line: 'gpgcheck=0'\n",
    );
    assert!(e.contains("does not edit DNF configuration"), "{e}");
    // Names that only start like these are ordinary paths.
    for path in [
        "/etc/yum.repos.d.bak/x",
        "/etc/dnfx/a.conf",
        "/etc/yum.conf.rpmnew",
    ] {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("r.yaml");
        std::fs::write(&p, line_recipe(path, "a=b", "")).unwrap();
        load_model(&p).unwrap_or_else(|e| panic!("{path}: {}", e.message));
    }
}

#[test]
fn file_merge_and_dnf_repository_on_one_file_conflict_in_either_order() {
    let repo = "  - id: r\n    type: dnf_repository\n    with:\n      name: crb\n      file: /etc/yum.repos.d/rocky.repo\n      enabled: true\n";
    let m = "  - id: m\n    type: file_merge\n    with:\n      path: /etc/yum.repos.d/rocky.repo\n      merge: line\n      line: 'x=1'\n";
    for body in [format!("{repo}{m}"), format!("{m}{repo}")] {
        load_err(&doc(&body));
    }
}

#[test]
fn a_same_size_in_place_change_after_the_read_is_refused_by_content() {
    // Neither size, inode nor (with a coarse clock) the timestamps change:
    // only the content tells.
    let before = "workers=2\nlisten=80\n";
    let theirs = "workers=2\nlisten=81\n";
    let yaml = merge(&format!(
        "      path: {CONF}\n      merge: key_value\n      key: workers\n      value: \"4\"\n"
    ));
    for mode in [Mode::Apply, Mode::Plan] {
        let mut t = with_file(fake(), CONF, before, 0o644).with_fs_event(
            "sha256sum",
            CONF,
            0,
            vec![FsEventAction::WriteInPlace {
                path: CONF.to_string(),
                data: theirs.as_bytes().to_vec(),
            }],
        );
        t.fs.as_mut().unwrap().freeze_mtime = true;
        let ino = t.fs.as_ref().unwrap().nodes[CONF].ino;
        match try_run(mode, &yaml, t) {
            Err(e) => assert!(
                e.message.contains("changed since it was read"),
                "{}",
                e.message
            ),
            Ok(r) => {
                assert_ne!(r.status, AggregateStatus::Success);
                let x = res(&r, "m");
                assert_eq!(x.change, Change::None);
                assert!(
                    x.reason
                        .as_deref()
                        .unwrap()
                        .contains("changed since it was read"),
                    "{:?}",
                    x.reason
                );
                assert_eq!(
                    content(&r, CONF),
                    theirs,
                    "the other writer's change was lost"
                );
                assert_eq!(node(&r, CONF).3, ino);
                assert!(
                    mutations(&r.commands).is_empty(),
                    "{:?}",
                    mutations(&r.commands)
                );
            }
        }
    }
    // Without the concurrent change the same target is edited.
    let mut t = with_file(fake(), CONF, before, 0o644);
    t.fs.as_mut().unwrap().freeze_mtime = true;
    let r = apply(&yaml, t);
    assert_changed(&r, "m");
    assert_eq!(content(&r, CONF), "workers=4\nlisten=80\n");
}

#[test]
fn a_file_with_a_second_hard_link_is_refused_in_plan_apply_and_audit() {
    let other = "/etc/app/other.conf";
    let before = "workers=2\n";
    let yaml = merge(&format!(
        "      path: {CONF}\n      merge: key_value\n      key: workers\n      value: \"4\"\n"
    ));
    let mk = || {
        let mut t = with_file(fake(), CONF, before, 0o644);
        t.fs.as_mut().unwrap().put_hardlink(CONF, other);
        t
    };
    let e = plan_err(&yaml, mk());
    assert!(e.message.contains("2 hard links"), "{}", e.message);
    let r = apply(&yaml, mk());
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    assert!(
        res(&r, "m")
            .reason
            .as_deref()
            .unwrap()
            .contains("2 hard links"),
        "{:?}",
        res(&r, "m").reason
    );
    assert_eq!(content(&r, CONF), before);
    assert_eq!(content(&r, other), before);
    assert_eq!(node(&r, CONF).3, node(&r, other).3, "the link was split");
    assert!(mutations(&r.commands).is_empty());
    // Also when the managed part is already as declared: the audit of a file
    // the next change would refuse is an error, not "compliant".
    let a = audit_one(&yaml, mk());
    assert_eq!(a.status, AuditResourceStatus::Error, "{:?}", a);
    assert!(
        a.reason.as_deref().unwrap().contains("2 hard links"),
        "{:?}",
        a.reason
    );
    // A link count that cannot be read is an error, never "one link".
    let t = with_file(fake(), CONF, before, 0o644).with_fs_event(
        "stat",
        "%h",
        0,
        vec![FsEventAction::FailCommand {
            code: 1,
            stderr: "stat: synthetic failure\n".to_string(),
        }],
    );
    let r = apply(&yaml, t);
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    let why = res(&r, "m").reason.clone().unwrap();
    assert!(
        why.contains("cannot determine the hard link count") && why.contains("partial edit"),
        "{why}"
    );
    assert_eq!(content(&r, CONF), before);
}

#[test]
fn removing_several_equal_lines_shows_only_those_lines() {
    let before = "keep one\ndrop me\nUNMANAGED-BETWEEN\ndrop me\nkeep two\n";
    let yaml = line_recipe(CONF, "drop me", "      state: absent\n");
    let r = plan(&yaml, with_file(fake(), CONF, before, 0o644));
    let x = res(&r, "m");
    assert_eq!(x.change, Change::Changed);
    match &x.diff.as_ref().expect("a diff").body {
        sinter::result::DiffBody::Text { removed, added } => {
            assert_eq!(removed, &["drop me", "drop me"]);
            assert!(added.is_empty());
        }
        other => panic!("unexpected diff {other:?}"),
    }
    for format in [OutputFormat::Text, OutputFormat::Json] {
        let mut out = Vec::new();
        sinter::output::render_plan(
            &r,
            &RenderOptions {
                verbose: true,
                format,
                color: false,
            },
            &mut out,
        )
        .unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(!out.contains("UNMANAGED-BETWEEN"), "{out}");
    }
    let r = apply(&yaml, with_file(fake(), CONF, before, 0o644));
    assert_changed(&r, "m");
    assert_eq!(content(&r, CONF), "keep one\nUNMANAGED-BETWEEN\nkeep two\n");
}

#[test]
fn an_indented_or_differently_cased_key_line_is_refused() {
    let yaml = |key: &str, sep: &str| {
        merge(&format!(
            "      path: {CONF}\n      merge: key_value\n      key: {key}\n      separator: \"{sep}\"\n      value: \"9\"\n"
        ))
    };
    for (label, key, sep, before, why) in [
        (
            "yaml mapping",
            "port",
            ": ",
            "server:\n  port: 1\n",
            "indented",
        ),
        (
            "sshd match",
            "PasswordAuthentication",
            " ",
            "Match User synthetic\n\tPasswordAuthentication yes\n",
            "indented",
        ),
        ("indented equals", "a", "=", " a=1\n", "indented"),
        (
            "other case",
            "PasswordAuthentication",
            " ",
            "passwordauthentication yes\n",
            "only in letter case",
        ),
        (
            "other case equals",
            "Workers",
            "=",
            "workers=2\n",
            "only in letter case",
        ),
    ] {
        for state in ["present", "absent"] {
            let y = format!("{}      state: {state}\n", yaml(key, sep));
            let y = if state == "absent" {
                y.replace("      value: \"9\"\n", "")
            } else {
                y
            };
            let e = plan_err(&y, with_file(fake(), CONF, before, 0o644));
            assert!(e.message.contains(why), "{label}/{state}: {}", e.message);
            let r = apply(&y, with_file(fake(), CONF, before, 0o644));
            assert_eq!(r.status, AggregateStatus::ApplyFailed, "{label}/{state}");
            assert_eq!(content(&r, CONF), before, "{label}/{state}");
            let a = audit_one(&y, with_file(fake(), CONF, before, 0o644));
            assert_eq!(
                a.status,
                AuditResourceStatus::Error,
                "{label}/{state}: {a:?}"
            );
        }
    }
    // An indented comment or a longer key is no setting of the key.
    let r = apply(
        &yaml("port", "="),
        with_file(fake(), CONF, "  # port=1\n  portal=2\nPORTAL=3\n", 0o644),
    );
    assert_changed(&r, "m");
    assert_eq!(
        content(&r, CONF),
        "  # port=1\n  portal=2\nPORTAL=3\nport=9\n"
    );
}

#[test]
fn a_replaced_key_line_is_rewritten_as_key_separator_value() {
    // Documented: an inline comment or quotes are part of the value.
    let yaml = merge(&format!(
        "      path: {CONF}\n      merge: key_value\n      key: a\n      value: \"2\"\n"
    ));
    let r = apply(
        &yaml,
        with_file(fake(), CONF, "a = \"1\" # note\nb=1\n", 0o644),
    );
    assert_changed(&r, "m");
    assert_eq!(content(&r, CONF), "a=2\nb=1\n");
}

#[test]
fn a_line_with_the_marker_words_is_rejected_at_load() {
    for line in [
        "# BEGIN SINTER MANAGED BLOCK foo",
        "# END SINTER MANAGED BLOCK foo",
        "x BEGIN SINTER MANAGED BLOCK",
    ] {
        for state in ["present", "absent"] {
            let e = load_err(&line_recipe(CONF, line, &format!("      state: {state}\n")));
            assert!(e.contains("managed-block marker"), "{line}: {e}");
        }
    }
    // From a variable: judged when it is evaluated, before anything is read
    // or written.
    let yaml = format!(
        "version: 1\nvars:\n  l:\n    value: '# BEGIN SINTER MANAGED BLOCK foo'\nresources:\n  - id: m\n    type: file_merge\n    with:\n      path: {CONF}\n      merge: line\n      line: \"{{{{ vars.l }}}}\"\n"
    );
    match try_run(Mode::Apply, &yaml, with_file(fake(), CONF, "a\n", 0o644)) {
        Err(e) => assert!(e.message.contains("managed-block marker"), "{}", e.message),
        Ok(r) => {
            assert_ne!(r.status, AggregateStatus::Success);
            assert_eq!(content(&r, CONF), "a\n");
        }
    }
}

#[test]
fn a_line_matches_an_equal_line_inside_a_managed_block() {
    // Documented limit: `line` looks at every line of the file.
    let before = "# BEGIN SINTER MANAGED BLOCK b\nshared\n# END SINTER MANAGED BLOCK b\n";
    let r = apply(
        &line_recipe(CONF, "shared", ""),
        with_file(fake(), CONF, before, 0o644),
    );
    assert_eq!(r.status, AggregateStatus::Success);
    assert_eq!(res(&r, "m").change, Change::None);
    let r = apply(
        &line_recipe(CONF, "shared", "      state: absent\n"),
        with_file(fake(), CONF, before, 0o644),
    );
    assert_changed(&r, "m");
    assert_eq!(
        content(&r, CONF),
        "# BEGIN SINTER MANAGED BLOCK b\n# END SINTER MANAGED BLOCK b\n"
    );
}
