//! v1.5.1 R-3: `template.vars` values are passed to the template as written —
//! a `{{ ... }}` inside one is not evaluated and is rendered literally. That
//! behavior is unchanged (an existing template keeps rendering the same
//! bytes); `validate` now warns about it.

mod common;

use common::*;
use sinter::model::load_model;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sinter")
}

fn recipe(dir: &std::path::Path, vars: &str, extra: &str) -> std::path::PathBuf {
    std::fs::write(dir.join("t.conf"), "port = {{ template.p }}\n").unwrap();
    write_recipe(
        dir,
        "r.yaml",
        &format!(
            "version: 1\nvars:\n  port:\n    value: 5432\nresources:\n  - id: t\n    type: template\n{extra}    with:\n      path: /etc/app.conf\n      source: t.conf\n      vars: {vars}\n"
        ),
    )
}

#[test]
fn interpolation_in_template_vars_is_warned() {
    let dir = trusted_root("tv-warn");
    let m = load_model(&recipe(&dir, "{ p: \"{{ vars.port }}\" }", "")).unwrap();
    assert_eq!(m.warnings.len(), 1, "{:?}", m.warnings);
    assert!(
        m.warnings[0].contains("template vars value \"p\""),
        "{:?}",
        m.warnings
    );
    assert!(m.warnings[0].contains("not interpolated"));
}

#[test]
fn nested_values_are_checked_too() {
    let dir = trusted_root("tv-nested");
    let m = load_model(&recipe(
        &dir,
        "{ p: 1, list: [a, \"{{ facts.hostname }}\"] }",
        "",
    ))
    .unwrap();
    assert_eq!(m.warnings.len(), 1, "{:?}", m.warnings);
    assert!(m.warnings[0].contains("\"list\""));
}

#[test]
fn literal_template_vars_are_not_warned() {
    let dir = trusted_root("tv-ok");
    let m = load_model(&recipe(&dir, "{ p: 5432 }", "")).unwrap();
    assert!(m.warnings.is_empty(), "{:?}", m.warnings);
    // An escaped `\{{` is literal text, not an interpolation.
    let m = load_model(&recipe(&dir, "{ p: \"\\\\{{ x }}\" }", "")).unwrap();
    assert!(m.warnings.is_empty(), "{:?}", m.warnings);
}

#[test]
fn a_sensitive_template_does_not_name_the_variable() {
    let dir = trusted_root("tv-sensitive");
    let m = load_model(&recipe(
        &dir,
        "{ p: \"{{ vars.port }}\" }",
        "    sensitive: true\n",
    ))
    .unwrap();
    assert_eq!(m.warnings.len(), 1);
    assert!(
        m.warnings[0].contains("(name redacted)"),
        "{:?}",
        m.warnings
    );
    assert!(!m.warnings[0].contains("\"p\""));
}

#[test]
fn validate_prints_the_warning_on_stderr_and_in_json() {
    let dir = trusted_root("tv-cli");
    let r = recipe(&dir, "{ p: \"{{ vars.port }}\" }", "");
    let out = Command::new(bin())
        .arg("validate")
        .arg(&r)
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.starts_with("ok: 1 resource(s)"),
        "stdout format unchanged: {stdout}"
    );
    assert!(
        stderr.contains("warning: t: template vars value"),
        "{stderr}"
    );
    let out = Command::new(bin())
        .args(["validate", "--format", "json"])
        .arg(&r)
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["status"], "ok");
    assert_eq!(v["warnings"].as_array().unwrap().len(), 1);
    // Without a warning the JSON shape is exactly as before.
    let ok = recipe(&dir, "{ p: 5432 }", "");
    let out = Command::new(bin())
        .args(["validate", "--format", "json"])
        .arg(&ok)
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v.get("warnings").is_none(), "{v}");
}
