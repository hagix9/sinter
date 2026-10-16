//! v1.5.1 COM-07: `validate.args` may place the staged file inside an
//! argument with the `{{ staged }}` placeholder (`--config-file={{ staged }}`,
//! the form `postgres -C ... --config-file=PATH` requires). Without a
//! placeholder the staged path is still appended as the last argument, as
//! before. The command stays argv-only (no shell), only the staged payload is
//! ever named, and a refusal leaves the destination untouched.
#![cfg(unix)]

mod common;

use common::{find, trusted_root, write_recipe};
use sinter::engine::{AggregateStatus, Engine, Mode, RunOptions, RunReport, TargetSpec};
use sinter::error::ErrorKind;
use sinter::executor::{CommandRecord, Completion, FakeTarget, Output};
use sinter::fakesys::FakeKind;
use sinter::model::load_model;
use sinter::result::{Change, Execution, Verification};

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

fn out(code: i32, stderr: &str) -> Output {
    Output {
        completion: Completion::Exited(code),
        stdout: Vec::new(),
        stderr: stderr.as_bytes().to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

fn recipe(dir: &std::path::Path, vars: &str, validate: &str) -> std::path::PathBuf {
    write_recipe(
        dir,
        "r.yaml",
        &format!(
            "version: 1\n{vars}resources:\n  - id: app\n    type: file\n    with:\n      path: /etc/app/app.conf\n      content: \"new\\n\"\n      owner: root\n      group: root\n      mode: \"0644\"\n      validate:\n{validate}"
        ),
    )
}

fn run(recipe: &std::path::Path, t: FakeTarget) -> RunReport {
    Engine::new(
        load_model(recipe).unwrap(),
        RunOptions {
            mode: Mode::Apply,
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

fn runs<'a>(r: &'a RunReport, prog: &str) -> Vec<&'a CommandRecord> {
    r.commands.iter().filter(|c| c.program == prog).collect()
}

fn staged_payload(arg: &str) -> bool {
    arg.contains(".sinter-stage.") && arg.ends_with("/payload") && !arg.contains('\0')
}

fn published(r: &RunReport) -> Option<Vec<u8>> {
    match &r.fake_fs.as_ref()?.nodes.get("/etc/app/app.conf")?.kind {
        FakeKind::File(b) => Some(b.clone()),
        _ => None,
    }
}

const PG: &str = "/usr/bin/postgres";

/// `--config-file={{ staged }}`: the staged path is joined into that one
/// argument, and is NOT appended again.
#[test]
fn placeholder_joins_the_staged_path_into_the_argument() {
    for ph in ["{{ staged }}", "{{staged}}", "{{  staged\t}}"] {
        let dir = trusted_root("com07-join");
        let r_ = recipe(
            &dir,
            "",
            &format!(
                "        program: {PG}\n        args: [\"-C\", \"data_directory\", \"-D\", \"/var/lib/pgsql/data\", \"--config-file={ph}\"]\n"
            ),
        );
        let r = run(&r_, base().with_observations("postgres", vec![out(0, "")]));
        assert_eq!(
            r.status,
            AggregateStatus::Success,
            "{:?}",
            find(&r, "app").reason
        );
        assert_eq!(find(&r, "app").verification, Verification::Verified);
        let v = runs(&r, PG);
        assert_eq!(v.len(), 1);
        let a = &v[0].args;
        assert_eq!(a.len(), 5, "no extra trailing staged argument: {a:?}");
        assert_eq!(
            &a[..4],
            ["-C", "data_directory", "-D", "/var/lib/pgsql/data"]
        );
        let joined = a[4]
            .strip_prefix("--config-file=")
            .expect("joined argument");
        assert!(staged_payload(joined), "{joined:?}");
        assert_ne!(joined, "/etc/app/app.conf");
        assert_eq!(published(&r).as_deref(), Some(&b"new\n"[..]));
    }
}

/// Several placeholders are all replaced by the same staged path.
#[test]
fn every_placeholder_is_replaced() {
    let dir = trusted_root("com07-many");
    let r_ = recipe(
        &dir,
        "",
        &format!("        program: {PG}\n        args: [\"{{{{ staged }}}}\", \"--check={{{{staged}}}}:{{{{staged}}}}\"]\n"),
    );
    let r = run(&r_, base().with_observations("postgres", vec![out(0, "")]));
    assert_eq!(
        r.status,
        AggregateStatus::Success,
        "{:?}",
        find(&r, "app").reason
    );
    let a = &runs(&r, PG)[0].args;
    assert_eq!(a.len(), 2, "{a:?}");
    assert!(staged_payload(&a[0]));
    let rest = a[1].strip_prefix("--check=").unwrap();
    let (x, y) = rest.split_once(':').unwrap();
    assert_eq!(x, a[0]);
    assert_eq!(y, a[0]);
}

/// Without a placeholder the original contract holds: staged path last.
#[test]
fn without_a_placeholder_the_staged_path_is_appended() {
    let dir = trusted_root("com07-compat");
    let r_ = recipe(
        &dir,
        "",
        "        program: /usr/sbin/sshd\n        args: [\"-t\", \"-f\"]\n",
    );
    let r = run(&r_, base().with_observations("sshd", vec![out(0, "")]));
    assert_eq!(r.status, AggregateStatus::Success);
    let a = &runs(&r, "/usr/sbin/sshd")[0].args;
    assert_eq!(a.len(), 3);
    assert_eq!(&a[..2], ["-t", "-f"]);
    assert!(staged_payload(&a[2]));
}

/// An escaped `\{{ staged }}` is literal text, not a placeholder: it is
/// passed as written and the staged path is appended.
#[test]
fn an_escaped_placeholder_is_literal() {
    let dir = trusted_root("com07-escaped");
    let r_ = recipe(
        &dir,
        "",
        &format!("        program: {PG}\n        args: [\"--name=\\\\{{{{ staged }}}}\"]\n"),
    );
    let r = run(&r_, base().with_observations("postgres", vec![out(0, "")]));
    assert_eq!(
        r.status,
        AggregateStatus::Success,
        "{:?}",
        find(&r, "app").reason
    );
    let a = &runs(&r, PG)[0].args;
    assert_eq!(a.len(), 2, "{a:?}");
    assert_eq!(a[0], "--name={{ staged }}");
    assert!(staged_payload(&a[1]));
}

/// The placeholder composes with ordinary interpolation in the same args.
#[test]
fn placeholder_and_variables_compose() {
    let dir = trusted_root("com07-vars");
    let r_ = recipe(
        &dir,
        "vars:\n  datadir:\n    value: /var/lib/pgsql/17/data\n",
        &format!("        program: {PG}\n        args: [\"-C\", \"port\", \"-D\", \"{{{{ vars.datadir }}}}\", \"--config-file={{{{ staged }}}}\"]\n"),
    );
    let r = run(&r_, base().with_observations("postgres", vec![out(0, "")]));
    assert_eq!(
        r.status,
        AggregateStatus::Success,
        "{:?}",
        find(&r, "app").reason
    );
    let a = &runs(&r, PG)[0].args;
    assert_eq!(a[3], "/var/lib/pgsql/17/data");
    assert!(staged_payload(a[4].strip_prefix("--config-file=").unwrap()));
}

/// A refusal through the placeholder path publishes nothing.
#[test]
fn a_refusal_with_a_placeholder_publishes_nothing() {
    let dir = trusted_root("com07-refuse");
    let r_ = recipe(
        &dir,
        "",
        &format!("        program: {PG}\n        args: [\"-C\", \"port\", \"--config-file={{{{ staged }}}}\"]\n"),
    );
    let r = run(
        &r_,
        base().with_observations("postgres", vec![out(1, "FATAL:  syntax error in file\n")]),
    );
    let p = find(&r, "app");
    assert_eq!(p.execution, Execution::Failed);
    assert_eq!(p.change, Change::None);
    assert!(p
        .reason
        .as_deref()
        .unwrap_or("")
        .contains("refused by its validate command"));
    assert!(published(&r).is_none(), "nothing may be published");
}

/// The placeholder works for `template` too.
#[test]
fn template_placeholder() {
    let dir = trusted_root("com07-template");
    std::fs::write(dir.join("t.conf"), "port = {{ template.p }}\n").unwrap();
    let r_ = write_recipe(
        &dir,
        "r.yaml",
        &format!("version: 1\nresources:\n  - id: app\n    type: template\n    with:\n      path: /etc/app/app.conf\n      source: t.conf\n      vars: {{ p: 5432 }}\n      owner: root\n      group: root\n      mode: \"0644\"\n      validate:\n        program: {PG}\n        args: [\"--config-file={{{{ staged }}}}\"]\n"),
    );
    let r = run(&r_, base().with_observations("postgres", vec![out(0, "")]));
    assert_eq!(
        r.status,
        AggregateStatus::Success,
        "{:?}",
        find(&r, "app").reason
    );
    let a = &runs(&r, PG)[0].args;
    assert_eq!(a.len(), 1);
    assert!(staged_payload(a[0].strip_prefix("--config-file=").unwrap()));
    assert_eq!(published(&r).as_deref(), Some(&b"port = 5432\n"[..]));
}

/// Invalid placements are rejected at load time.
#[test]
fn invalid_placeholders_are_rejected_at_load() {
    let dir = trusted_root("com07-invalid");
    let cases = [
        (
            "in-program",
            "        program: \"/usr/bin/{{ staged }}\"\n".to_string(),
            "may not contain the {{ staged }} placeholder",
        ),
        (
            "misspelled",
            format!("        program: {PG}\n        args: [\"--config-file={{{{ stage }}}}\"]\n"),
            "bare names are not allowed",
        ),
        (
            "qualified",
            format!(
                "        program: {PG}\n        args: [\"--config-file={{{{ staged.path }}}}\"]\n"
            ),
            "bare names are not allowed",
        ),
        (
            "nul",
            format!("        program: {PG}\n        args: [\"a\\0b\"]\n"),
            "may not contain NUL",
        ),
    ];
    for (label, validate, needle) in cases {
        let r_ = recipe(&dir, "", &validate);
        let e = load_model(&r_).unwrap_err();
        assert_eq!(e.kind, ErrorKind::Schema, "{label}: {e:?}");
        assert!(e.message.contains(needle), "{label}: {}", e.message);
    }
}

/// `{{ staged }}` outside validate.args is not a placeholder anywhere else.
#[test]
fn staged_is_not_a_placeholder_outside_validate_args() {
    let dir = trusted_root("com07-elsewhere");
    let r_ = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: app\n    type: file\n    with:\n      path: /etc/app/app.conf\n      content: \"{{ staged }}\\n\"\n",
    );
    let e = load_model(&r_).unwrap_err();
    assert!(
        e.message.contains("bare names are not allowed"),
        "{}",
        e.message
    );
}

/// An interpolated value can never forge the placeholder: a variable whose
/// value carries a NUL is refused instead of becoming a staged-path slot.
#[test]
fn an_interpolated_nul_cannot_forge_the_placeholder() {
    let dir = trusted_root("com07-forge");
    let r_ = recipe(
        &dir,
        "vars:\n  x:\n    value: \"a\\0b\"\n",
        &format!("        program: {PG}\n        args: [\"{{{{ vars.x }}}}\"]\n"),
    );
    // The variable loads; the evaluated argument carries a NUL the recipe did
    // not write as a placeholder, so it is refused before any validator runs.
    let model = load_model(&r_).expect("the recipe loads");
    let r = Engine::new(
        model,
        RunOptions {
            mode: Mode::Apply,
            sudo: true,
            target: TargetSpec { ssh: None },
            verbose: false,
            fault: None,
            fake_target: Some(base().with_observations("postgres", vec![out(0, "")])),
        },
    )
    .unwrap()
    .run()
    .unwrap();
    assert!(
        runs(&r, PG).is_empty(),
        "a NUL from a variable must not reach the validator"
    );
    let p = find(&r, "app");
    assert_eq!(p.execution, Execution::Failed);
    assert_eq!(p.change, Change::None);
    assert!(
        p.reason.as_deref().unwrap_or("").contains("without NUL"),
        "{:?}",
        p.reason
    );
    assert!(published(&r).is_none());
}
