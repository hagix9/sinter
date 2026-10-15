//! N-1: `file` / `template` pre-publication `validate`.
//!
//! A `validate` block names a command that Sinter runs against the *staged*
//! file — never the production path — after staging and before publication.
//! Only exit 0 lets the content be published: a non-zero exit, a signal, a
//! timeout or an unknown completion refuses the content, and the destination
//! is left exactly as it was. The command is argv-only (no shell).
#![cfg(unix)]

mod common;

use common::{find, trusted_root, write_recipe};
use sinter::engine::{AggregateStatus, Engine, Mode, RunOptions, RunReport, TargetSpec};
use sinter::error::ErrorKind;
use sinter::executor::{CommandRecord, Completion, FakeTarget, Output};
use sinter::fakesys::{FakeKind, FakeNode};
use sinter::model::load_model;
use sinter::result::{Change, Execution, Verification};

/// The command line of the fixed staging script, as the log records it.
const STAGE_MARKER: &str = "[fsstage.sh sha256:";

fn base() -> FakeTarget {
    let mut t = FakeTarget::ubuntu2404().with_fake_fs().as_root();
    let fs = t.fs.as_mut().unwrap();
    for (path, mode, uid) in [
        ("/etc", 0o755, 0),
        ("/etc/app", 0o755, 0),
        ("/root", 0o700, 0),
    ] {
        fs.mkdir_node(path, mode, uid, uid);
    }
    t
}

fn out(completion: Completion, stdout: &str, stderr: &str) -> Output {
    Output {
        completion,
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

fn file_recipe(dir: &std::path::Path, extra: &str) -> std::path::PathBuf {
    write_recipe(
        dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: app\n    type: file\n    with:\n      path: /etc/app/app.conf\n      content: \"new\\n\"\n      owner: root\n      group: root\n      mode: \"0644\"\n{extra}"
        ),
    )
}

const VALIDATE_SSHD: &str =
    "      validate:\n        program: /usr/sbin/sshd\n        args: [\"-t\", \"-f\"]\n";

fn run(recipe: &std::path::Path, mode: Mode, t: FakeTarget) -> RunReport {
    let model = load_model(recipe).unwrap();
    Engine::new(
        model,
        RunOptions {
            mode,
            sudo: true,
            target: TargetSpec { ssh: None },
            verbose: false,
            fault: None,
            fake_target: Some(t),
        },
    )
    .unwrap()
    .run()
    .unwrap_or_else(|e| panic!("{}", e.message))
}

fn fs_of(r: &RunReport) -> &sinter::fakesys::FakeFs {
    r.fake_fs.as_ref().expect("scripted filesystem")
}

fn node<'a>(fs: &'a sinter::fakesys::FakeFs, path: &str) -> Option<&'a FakeNode> {
    fs.nodes.get(path)
}

/// The operations of the fixed staging script that ran, in order.
fn stage_ops(r: &RunReport) -> Vec<String> {
    r.commands
        .iter()
        .filter(|c| c.program == "/bin/sh")
        .filter_map(|c: &CommandRecord| {
            let i = c.args.iter().position(|a| a == "sh")?;
            let is_stage = c.args.iter().any(|a| a.starts_with(STAGE_MARKER));
            is_stage.then(|| c.args.get(i + 1).cloned())?
        })
        .collect()
}

fn validator_runs(r: &RunReport) -> Vec<&CommandRecord> {
    r.commands
        .iter()
        .filter(|c| c.program == "/usr/sbin/sshd")
        .collect()
}

// ---------------------------------------------------------------------------
// Behaviour
// ---------------------------------------------------------------------------

/// The staged file validates (exit 0): the production file is published.
#[test]
fn validation_success_publishes_the_new_content() {
    let dir = trusted_root("n1-ok");
    let recipe = file_recipe(&dir, VALIDATE_SSHD);
    let t = base().with_observations("sshd", vec![out(Completion::Exited(0), "", "")]);
    let r = run(&recipe, Mode::Apply, t);
    assert_eq!(
        r.status,
        AggregateStatus::Success,
        "{:?}",
        find(&r, "app").reason
    );
    let p = find(&r, "app");
    assert_eq!(p.change, Change::Changed);
    assert_eq!(p.verification, Verification::Verified);

    let fs = fs_of(&r);
    match &node(fs, "/etc/app/app.conf").expect("published").kind {
        FakeKind::File(b) => assert_eq!(b, b"new\n"),
        other => panic!("unexpected kind {other:?}"),
    }
    // The validator ran exactly once against the STAGED payload, never the
    // production path.
    let runs = validator_runs(&r);
    assert_eq!(runs.len(), 1);
    let last = runs[0].args.last().unwrap();
    assert!(
        last.contains(".sinter-stage.") && last.ends_with("/payload"),
        "the validator must read the staged payload, got {last:?}"
    );
    assert_ne!(last, "/etc/app/app.conf");
    // The content really was published by the staging script.
    assert!(stage_ops(&r).iter().any(|o| o == "publish"));
}

/// The staged file is refused (exit non-zero): nothing is published, and a
/// pre-existing production file is not changed.
#[test]
fn validation_failure_publishes_nothing_and_leaves_the_destination() {
    let dir = trusted_root("n1-fail");
    let recipe = file_recipe(&dir, VALIDATE_SSHD);
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_file("/etc/app/app.conf", b"OLD\n", 0o644, 0, 0);
    let t = t.with_observations(
        "sshd",
        vec![out(
            Completion::Exited(1),
            "",
            "Bad configuration option: Foo\n",
        )],
    );
    let r = run(&recipe, Mode::Apply, t);

    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    let p = find(&r, "app");
    assert_eq!(p.execution, Execution::Failed);
    assert_eq!(p.change, Change::None, "no mutation means change none");
    assert_eq!(p.verification, Verification::NotPerformed);
    let reason = p.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("refused by its validate command"),
        "{reason}"
    );
    assert!(reason.contains("Bad configuration option"), "{reason}");

    let fs = fs_of(&r);
    match &node(fs, "/etc/app/app.conf")
        .expect("the old file stays")
        .kind
    {
        FakeKind::File(b) => assert_eq!(b, b"OLD\n", "the production file is unchanged"),
        other => panic!("unexpected kind {other:?}"),
    }
    assert!(
        !stage_ops(&r).iter().any(|o| o == "publish"),
        "nothing may be published: {:?}",
        stage_ops(&r)
    );
}

/// A missing destination stays missing when validation fails.
#[test]
fn validation_failure_does_not_create_the_file() {
    let dir = trusted_root("n1-fail-absent");
    let recipe = file_recipe(&dir, VALIDATE_SSHD);
    let t = base().with_observations("sshd", vec![out(Completion::Exited(1), "", "")]);
    let r = run(&recipe, Mode::Apply, t);
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    assert_eq!(find(&r, "app").change, Change::None);
    assert!(
        node(fs_of(&r), "/etc/app/app.conf").is_none(),
        "no file may be created"
    );
}

/// A timeout (indeterminate completion) refuses safely: nothing is published,
/// and the destination is unchanged.
#[test]
fn an_unresolved_validation_refuses_without_publishing() {
    let dir = trusted_root("n1-timeout");
    let recipe = file_recipe(&dir, VALIDATE_SSHD);
    let t = base().with_observations(
        "sshd",
        vec![out(
            Completion::Indeterminate {
                started: true,
                reason: "timeout of 300s elapsed after dispatch".into(),
            },
            "",
            "",
        )],
    );
    let r = run(&recipe, Mode::Apply, t);

    let p = find(&r, "app");
    assert_eq!(p.execution, Execution::Indeterminate, "{:?}", p.reason);
    assert_eq!(p.change, Change::None, "nothing was published");
    assert_eq!(p.verification, Verification::NotPerformed);
    assert!(node(fs_of(&r), "/etc/app/app.conf").is_none());
    assert!(!stage_ops(&r).iter().any(|o| o == "publish"));
}

/// Without `validate`, the file is published with no extra command.
#[test]
fn no_validate_publishes_as_before() {
    let dir = trusted_root("n1-none");
    let recipe = file_recipe(&dir, "");
    let r = run(&recipe, Mode::Apply, base());
    assert_eq!(r.status, AggregateStatus::Success);
    assert!(
        validator_runs(&r).is_empty(),
        "no validator must be dispatched"
    );
    match &node(fs_of(&r), "/etc/app/app.conf")
        .expect("published")
        .kind
    {
        FakeKind::File(b) => assert_eq!(b, b"new\n"),
        other => panic!("unexpected kind {other:?}"),
    }
}

/// A sensitive resource's validation failure never echoes the validator's
/// output or the production path.
#[test]
fn a_sensitive_resource_never_leaks_the_validator_output() {
    let dir = trusted_root("n1-sensitive");
    let marker = "N1_SECRET_c0ffee";
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: app\n    type: file\n    sensitive: true\n    with:\n      path: /etc/app/app.conf\n      content: \"new\\n\"\n      owner: root\n      group: root\n      mode: \"0644\"\n{VALIDATE_SSHD}"
        ),
    );
    let t = base().with_observations(
        "sshd",
        vec![out(
            Completion::Exited(1),
            "",
            &format!("error: {marker}\n"),
        )],
    );
    let r = run(&recipe, Mode::Apply, t);
    assert_eq!(r.status, AggregateStatus::ApplyFailed);
    let p = find(&r, "app");
    let reason = p.reason.as_deref().unwrap_or("");
    assert!(!reason.contains(marker), "leaked marker: {reason}");
    assert!(
        !reason.contains("/etc/app/app.conf"),
        "leaked path: {reason}"
    );

    // The rendered output must not carry the marker or the path either.
    for format in [
        sinter::output::OutputFormat::Text,
        sinter::output::OutputFormat::Json,
    ] {
        let mut buf = Vec::new();
        sinter::output::render_apply(
            &r,
            &sinter::output::RenderOptions {
                verbose: true,
                format,
                color: false,
            },
            &mut buf,
        )
        .unwrap();
        let shown = String::from_utf8(buf).unwrap();
        assert!(
            !shown.contains(marker),
            "marker leaked in {format:?}: {shown}"
        );
        assert!(
            !shown.contains("/etc/app/app.conf"),
            "path leaked in {format:?}: {shown}"
        );
    }
}

/// The publication stays exclusive/converged under `validate`: a second apply
/// changes nothing and runs no validator (the file already matches), and a
/// shared-directory new file is still published by `ln -T`.
#[test]
fn validate_is_idempotent_when_the_file_matches() {
    let dir = trusted_root("n1-idem");
    let recipe = file_recipe(&dir, VALIDATE_SSHD);
    let first = run(
        &recipe,
        Mode::Apply,
        base().with_observations("sshd", vec![out(Completion::Exited(0), "", "")]),
    );
    assert_eq!(first.status, AggregateStatus::Success);

    let mut t = base();
    t.fs = first.fake_fs.clone();
    // No validator result is queued: if the resource tried to validate, the
    // fake would answer 127 and the run would fail.
    let second = run(&recipe, Mode::Apply, t);
    assert_eq!(second.status, AggregateStatus::Success);
    assert_eq!(find(&second, "app").change, Change::None);
    assert!(
        validator_runs(&second).is_empty(),
        "converged: no validation"
    );
}

/// `template` shares the pre-publication validation path: the staged render is
/// checked, and a refusal leaves the destination unchanged.
#[test]
fn template_validate_refuses_and_leaves_the_destination() {
    let dir = trusted_root("n1-template");
    std::fs::write(dir.join("t.conf"), "rendered {{ template.p }}\n").unwrap();
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: app\n    type: template\n    with:\n      path: /etc/app/app.conf\n      source: t.conf\n      vars: { p: 1 }\n      owner: root\n      group: root\n      mode: \"0644\"\n      validate:\n        program: /usr/sbin/sshd\n        args: [\"-t\", \"-f\"]\n",
    );
    // A refusal publishes nothing.
    let bad = base().with_observations(
        "sshd",
        vec![out(Completion::Exited(1), "", "Bad configuration\n")],
    );
    let r = run(&recipe, Mode::Apply, bad);
    assert_eq!(find(&r, "app").execution, Execution::Failed);
    assert_eq!(find(&r, "app").change, Change::None);
    assert!(node(fs_of(&r), "/etc/app/app.conf").is_none());
    assert!(!stage_ops(&r).iter().any(|o| o == "publish"));

    // Acceptance publishes the rendered bytes.
    let ok = base().with_observations("sshd", vec![out(Completion::Exited(0), "", "")]);
    let r = run(&recipe, Mode::Apply, ok);
    assert_eq!(find(&r, "app").execution, Execution::Succeeded);
    match &node(fs_of(&r), "/etc/app/app.conf")
        .expect("published")
        .kind
    {
        FakeKind::File(b) => assert_eq!(b, b"rendered 1\n"),
        other => panic!("unexpected kind {other:?}"),
    }
    let runs = validator_runs(&r);
    assert_eq!(runs.len(), 1);
    assert!(
        runs[0].args.last().unwrap().ends_with("/payload"),
        "the validator reads the staged payload"
    );
}

// ---------------------------------------------------------------------------
// Model validation
// ---------------------------------------------------------------------------

#[test]
fn validate_shape_is_validated() {
    let dir = trusted_root("n1-model");
    let cases = [
        ("not-a-map", "      validate: 5\n", "validate"),
        (
            "no-program",
            "      validate:\n        args: [\"-t\"]\n",
            "program",
        ),
        (
            "relative",
            "      validate:\n        program: sshd\n",
            "absolute",
        ),
        (
            "bad-args",
            "      validate:\n        program: /usr/sbin/sshd\n        args: \"-t\"\n",
            "list",
        ),
        (
            "bad-timeout",
            "      validate:\n        program: /usr/sbin/sshd\n        timeout_seconds: 0\n",
            "timeout_seconds",
        ),
        (
            "unknown-key",
            "      validate:\n        program: /usr/sbin/sshd\n        slow: true\n",
            "no field",
        ),
    ];
    for (label, extra, needle) in cases {
        let recipe = file_recipe(&dir, extra);
        let e = load_model(&recipe).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Schema, "{label}: {e:?}");
        assert!(e.message.contains(needle), "{label}: {}", e.message);
    }
}

#[test]
fn a_valid_validate_block_loads() {
    let dir = trusted_root("n1-model-ok");
    let recipe = file_recipe(&dir, VALIDATE_SSHD);
    load_model(&recipe).expect("a well-formed validate block must load");
}
