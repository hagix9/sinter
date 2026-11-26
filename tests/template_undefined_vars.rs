//! A template body may only name what the recipe declares (FR-034): an
//! undeclared `vars.<name>` or a `template.<name>` that the resource's `vars`
//! map does not define is refused when the recipe is loaded, before any host
//! is contacted, and never shows a value of a sensitive resource.
mod common;

use common::*;
use sinter::model::load_model;

fn recipe(label: &str, body: &str, extra: &str) -> std::path::PathBuf {
    let dir = trusted_root(label);
    std::fs::write(dir.join("t.conf"), body).unwrap();
    write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nvars:\n  port:\n    value: 5432\n  token:\n    value: synthetic-token\n    sensitive: true\nresources:\n  - id: t\n    type: template\n{extra}    with:\n      path: /etc/app.conf\n      source: t.conf\n      vars: {{ name: app }}\n"
        ),
    )
}

#[test]
fn declared_names_load() {
    let p = recipe(
        "tu-ok",
        "port = {{ vars.port }}\nname = {{ template.name }}\nhost = {{ facts.hostname }}\n",
        "",
    );
    assert!(load_model(&p).is_ok());
}

#[test]
fn an_undeclared_variable_is_refused_at_load_and_named() {
    let p = recipe("tu-var", "port = {{ vars.prot }}\n", "");
    let e = load_model(&p).unwrap_err();
    assert_eq!(e.kind.exit_code(), 2);
    assert!(
        e.message
            .contains("references the undefined variable vars.prot"),
        "{}",
        e.message
    );
}

#[test]
fn an_undefined_template_key_is_refused_at_load_and_named() {
    let p = recipe("tu-tvar", "name = {{ template.nmae }}\n", "");
    let e = load_model(&p).unwrap_err();
    assert!(
        e.message.contains("undefined variable template.nmae"),
        "{}",
        e.message
    );
}

#[test]
fn an_undefined_name_inside_an_expression_is_found_too() {
    let p = recipe("tu-expr", "x = {{ vars.port == vars.other }}\n", "");
    let e = load_model(&p).unwrap_err();
    assert!(e.message.contains("vars.other"), "{}", e.message);
}

#[test]
fn a_sensitive_template_names_nothing() {
    // The same rule as for an unknown register in a template: the resource's
    // own sensitivity (explicit, or from a sensitive variable in a `with`
    // field) decides; a variable NAME in the body is not a secret.
    let e = load_model(&recipe(
        "tu-s2",
        "t = {{ vars.typo }}\n",
        "    sensitive: true\n",
    ))
    .unwrap_err();
    assert!(
        e.message.contains("undefined variable (value redacted)"),
        "{}",
        e.message
    );
    assert!(!e.message.contains("typo"), "{}", e.message);
    assert!(!e.message.contains("t.conf"), "{}", e.message);
}
