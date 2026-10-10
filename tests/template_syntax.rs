//! Template bodies support only `{{ expression }}` interpolation (DESIGN
//! §26.4). A Jinja statement (`{% ... %}`) or comment (`{# ... #}`) tag used
//! to be published verbatim, so a template ported from Jinja/Ansible produced
//! a broken file without any error. It is now refused at validation (and
//! again at render), with the resource, the source file and the position.
#![cfg(unix)]

mod common;

use common::{mutation_command_count, trusted_root, write_recipe};
use sinter::engine::{Engine, Mode, RunOptions, RunReport, TargetSpec};
use sinter::error::ErrorKind;
use sinter::executor::FakeTarget;
use sinter::model::load_model;
use sinter::result::{DiffBody, Execution};
use std::path::{Path, PathBuf};

fn recipe_with_template(label: &str, body: &str, sensitive: bool) -> PathBuf {
    let dir = trusted_root(label);
    std::fs::write(dir.join("app.conf.tmpl"), body).unwrap();
    write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: app_conf\n    type: template\n{}    with:\n      path: /etc/app/app.conf\n      source: app.conf.tmpl\n      vars:\n        port: 8080\n",
            if sensitive { "    sensitive: true\n" } else { "" }
        ),
    )
}

fn run(model: sinter::model::Model, mode: Mode) -> RunReport {
    run_on(model, mode, FakeTarget::ubuntu2404().with_fake_fs())
}

fn run_on(model: sinter::model::Model, mode: Mode, target: FakeTarget) -> RunReport {
    Engine::new(
        model,
        RunOptions {
            mode,
            sudo: true,
            target: TargetSpec { ssh: None },
            verbose: false,
            fault: None,
            fake_target: Some(target),
        },
    )
    .unwrap()
    .run()
    .unwrap_or_else(|e| panic!("{}", e.message))
}

#[test]
fn a_jinja_statement_is_a_validation_error_with_its_position() {
    let r = recipe_with_template(
        "tmpl-stmt",
        "listen {{ template.port }}\n{% if facts.os_family == \"debian\" %}\nuser www-data\n{% endif %}\n",
        false,
    );
    let e = load_model(&r).expect_err("must be refused");
    assert_eq!(e.kind, ErrorKind::Schema);
    assert_eq!(e.kind.exit_code(), 2);
    for part in [
        "app_conf",
        "app.conf.tmpl",
        "line 2, column 1",
        "Jinja statement tag",
        "write {{ \"{%\" }} for a literal `{%`",
    ] {
        assert!(e.message.contains(part), "{part}: {}", e.message);
    }
}

#[test]
fn a_jinja_comment_is_a_validation_error() {
    let r = recipe_with_template("tmpl-cmt", "a = 1\n  {# managed by ansible #}\n", false);
    let e = load_model(&r).expect_err("must be refused");
    assert!(
        e.message
            .contains("line 2, column 3: `{# ... #}` is a Jinja comment tag"),
        "{}",
        e.message
    );
}

#[test]
fn the_cli_validate_command_refuses_it() {
    let r = recipe_with_template("tmpl-cli", "{% for x in y %}{% endfor %}\n", false);
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_sinter"))
        .arg("validate")
        .arg(&r)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{:?}", out);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("line 1, column 1"), "{stderr}");
}

#[test]
fn a_sensitive_template_names_the_position_but_not_the_file_or_text() {
    let r = recipe_with_template("tmpl-sens", "password=TOPSECRET-91c2\n{% if x %}\n", true);
    let e = load_model(&r).expect_err("must be refused");
    assert!(e.message.contains("line 2, column 1"), "{}", e.message);
    assert!(!e.message.contains("TOPSECRET"), "{}", e.message);
    assert!(!e.message.contains("app.conf.tmpl"), "{}", e.message);
}

/// What a template renders to, read from the planned content diff against an
/// existing file (a new file's plan shows only its size).
fn rendered(r: &RunReport) -> String {
    match &r.resources[0].diff.as_ref().expect("a diff").body {
        DiffBody::Text { added, .. } => added.join("\n"),
        other => panic!("expected a text diff, got {other:?}"),
    }
}

#[test]
fn supported_syntax_and_lookalike_text_render_unchanged() {
    let body = "listen {{ template.port }}\n\
                literal \\{{ not interpolated }}\n\
                count=${#items[@]} args=${#}\n\
                {{ \"{%\" }} raw {{ \"%}\" }}\n\
                elixir {%{a: 1}, :b}\n\
                map {%{a: 1}} {{ \"%}\" }}\n";
    let r = recipe_with_template("tmpl-ok", body, false);
    let model = load_model(&r).unwrap_or_else(|e| panic!("{}", e.message));
    let mut t = FakeTarget::ubuntu2404().with_fake_fs();
    t.fs.as_mut()
        .unwrap()
        .put_file("/etc/app/app.conf", b"old\n", 0o644, 0, 0);
    let out = rendered(&run_on(model, Mode::Plan, t));
    for line in [
        "listen 8080",
        "literal {{ not interpolated }}",
        "count=${#items[@]} args=${#}",
        "{% raw %}",
        "elixir {%{a: 1}, :b}",
        "map {%{a: 1}} %}",
    ] {
        assert!(out.contains(line), "{line:?} in {out:?}");
    }
}

#[test]
fn a_template_changed_after_validation_is_refused_at_render_without_mutation() {
    let r = recipe_with_template("tmpl-render", "listen {{ template.port }}\n", false);
    let model = load_model(&r).unwrap();
    let source = Path::new(&r).parent().unwrap().join("app.conf.tmpl");
    std::fs::write(&source, "listen 1\n{% include \"x\" %}\n").unwrap();
    let report = run(model, Mode::Apply);
    let x = &report.resources[0];
    assert_eq!(x.execution, Execution::Failed);
    let reason = x.reason.clone().unwrap();
    assert!(
        reason.contains("template rendering error: line 2, column 1"),
        "{reason}"
    );
    assert_eq!(mutation_command_count(&report), 0);
}
