//! N-4: recipe-wide default environment for `package` / `command`.
//!
//! A top-level `env` map is a base for the environment Sinter gives to
//! `package` and `command` resources (the only resources that run an external
//! process with an environment). An explicit resource `env` overrides the
//! recipe default per variable name, and an unrelated resource or a connection
//! step never receives it.
#![cfg(unix)]

mod common;

use common::*;
use sinter::engine::{Mode, RunReport};
use sinter::executor::{CommandRecord, Completion, FakeTarget, Output};
use sinter::model::load_model;
use std::collections::BTreeMap;

fn exited0() -> Output {
    Output {
        completion: Completion::Exited(0),
        stdout: Vec::new(),
        stderr: Vec::new(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

fn records_of<'a>(r: &'a RunReport, program: &str) -> Vec<&'a CommandRecord> {
    r.commands.iter().filter(|c| c.program == program).collect()
}

fn env_of<'a>(r: &'a RunReport, program: &str) -> &'a BTreeMap<String, String> {
    &records_of(r, program)
        .first()
        .unwrap_or_else(|| panic!("no command {program} in this run"))
        .env
}

/// The default environment reaches a `command` resource.
#[test]
fn recipe_env_is_passed_to_a_command() {
    let dir = trusted_root("n4-command");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nenv:\n  HTTP_PROXY: \"http://proxy.example.com:3128\"\n  NO_PROXY: \"localhost,10.0.0.0/8\"\nresources:\n  - id: c\n    type: command\n    with:\n      program: /bin/true\n",
    );
    let r = run_recipe_fake(
        &recipe,
        Mode::Apply,
        false,
        FakeTarget::rocky9().with_observations("true", vec![exited0()]),
    );
    let env = env_of(&r, "/bin/true");
    assert_eq!(
        env.get("HTTP_PROXY").map(String::as_str),
        Some("http://proxy.example.com:3128")
    );
    assert_eq!(
        env.get("NO_PROXY").map(String::as_str),
        Some("localhost,10.0.0.0/8")
    );
}

/// A resource `env` overrides the recipe default per name; other recipe names
/// still apply. The recipe default never replaces an explicit value.
#[test]
fn a_resource_env_overrides_the_recipe_env_per_name() {
    let dir = trusted_root("n4-override");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nenv:\n  HTTP_PROXY: \"http://recipe:1\"\n  KEEP: \"kept\"\nresources:\n  - id: c\n    type: command\n    with:\n      program: /bin/true\n      env:\n        HTTP_PROXY: \"http://resource:2\"\n",
    );
    let r = run_recipe_fake(
        &recipe,
        Mode::Apply,
        false,
        FakeTarget::rocky9().with_observations("true", vec![exited0()]),
    );
    let env = env_of(&r, "/bin/true");
    assert_eq!(
        env.get("HTTP_PROXY").map(String::as_str),
        Some("http://resource:2")
    );
    assert_eq!(env.get("KEEP").map(String::as_str), Some("kept"));
}

/// The default environment reaches a `package` resource (its dnf transport).
#[test]
fn recipe_env_reaches_a_package_operation() {
    let dir = trusted_root("n4-package");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nenv:\n  HTTP_PROXY: \"http://proxy.example.com:3128\"\nresources:\n  - id: p\n    type: package\n    with:\n      name: nano\n      state: present\n",
    );
    let r = run_recipe_fake(&recipe, Mode::Apply, false, FakeTarget::rocky9());
    let download = r
        .commands
        .iter()
        .find(|c| c.program == "/usr/bin/dnf" && c.args.iter().any(|a| a == "--downloadonly"))
        .expect("a payload transport call");
    assert_eq!(
        download.env.get("HTTP_PROXY").map(String::as_str),
        Some("http://proxy.example.com:3128")
    );
    // A package observation (`rpm -q`) is not an operation with an
    // environment: it must not carry the recipe default.
    let rpm = records_of(&r, "/usr/bin/rpm");
    assert!(
        rpm.iter().all(|c| !c.env.contains_key("HTTP_PROXY")),
        "a package query must not receive the recipe env"
    );
}

/// A connection/capability step never receives the recipe default.
#[test]
fn unrelated_commands_do_not_receive_the_recipe_env() {
    let dir = trusted_root("n4-scope");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nenv:\n  HTTP_PROXY: \"http://proxy.example.com:3128\"\nresources:\n  - id: c\n    type: command\n    with:\n      program: /bin/true\n",
    );
    let r = run_recipe_fake(
        &recipe,
        Mode::Apply,
        false,
        FakeTarget::rocky9().with_observations("true", vec![exited0()]),
    );
    for c in &r.commands {
        if c.program == "/bin/true" {
            continue;
        }
        assert!(
            !c.env.contains_key("HTTP_PROXY"),
            "{} must not carry the recipe env: {:?}",
            c.program,
            c.env
        );
    }
}

/// Environment names are case-sensitive, as on Linux: both spellings are
/// passed exactly as written.
#[test]
fn env_names_are_not_case_folded() {
    let dir = trusted_root("n4-case");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nenv:\n  HTTP_PROXY: \"http://upper:1\"\n  http_proxy: \"http://lower:2\"\nresources:\n  - id: c\n    type: command\n    with:\n      program: /bin/true\n",
    );
    let r = run_recipe_fake(
        &recipe,
        Mode::Apply,
        false,
        FakeTarget::rocky9().with_observations("true", vec![exited0()]),
    );
    let env = env_of(&r, "/bin/true");
    assert_eq!(
        env.get("HTTP_PROXY").map(String::as_str),
        Some("http://upper:1")
    );
    assert_eq!(
        env.get("http_proxy").map(String::as_str),
        Some("http://lower:2")
    );
}

/// A recipe `env` derived from a sensitive variable makes the resource
/// statically sensitive too (early diagnostics are redacted, not only runtime).
#[test]
fn a_sensitive_recipe_env_sets_static_sensitivity() {
    let dir = trusted_root("n4-static");
    let marker = "N4_STATIC_marker";
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nvars:\n  proxy:\n    value: \"{marker}\"\n    sensitive: true\nenv:\n  HTTP_PROXY: \"{{{{ vars.proxy }}}}\"\nresources:\n  - id: c\n    type: command\n    with:\n      program: /bin/true\n"
        ),
    );
    let model = load_model(&recipe).unwrap();
    assert!(
        model.resources[0].derived_sensitive,
        "a recipe env from a sensitive variable must set derived_sensitive"
    );
}

/// A default derived from a sensitive variable is redacted on the wire.
#[test]
fn a_sensitive_recipe_env_is_redacted() {
    let dir = trusted_root("n4-sensitive");
    let marker = "N4_PROXY_SECRET_2f1";
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nvars:\n  proxy:\n    value: \"http://{marker}:3128\"\n    sensitive: true\nenv:\n  HTTP_PROXY: \"{{{{ vars.proxy }}}}\"\nresources:\n  - id: c\n    type: command\n    with:\n      program: /bin/true\n"
        ),
    );
    let r = run_recipe_fake(
        &recipe,
        Mode::Apply,
        false,
        FakeTarget::rocky9().with_observations("true", vec![exited0()]),
    );
    let rec = r
        .commands
        .iter()
        .find(|c| c.sensitive)
        .expect("a command with a sensitive env must be recorded as sensitive");
    let shown = format!("{:?}", rec.env);
    assert!(
        !shown.contains(marker),
        "the secret leaked into the record: {shown}"
    );
}

// ---------------------------------------------------------------------------
// Model validation
// ---------------------------------------------------------------------------

fn load_err(dir: &std::path::Path, name: &str, body: &str) -> sinter::error::SinterError {
    let p = write_recipe(dir, name, body);
    load_model(&p).unwrap_err()
}

#[test]
fn recipe_env_shape_is_validated() {
    let dir = trusted_root("n4-model");
    for (label, body, needle) in [
        (
            "not-a-map",
            "version: 1\nenv: 5\nresources: []\n",
            "must be a map",
        ),
        (
            "reserved",
            "version: 1\nenv:\n  PATH: /evil\nresources: []\n",
            "reserved",
        ),
        (
            "bad-name",
            "version: 1\nenv:\n  \"1BAD\": x\nresources: []\n",
            "invalid environment variable name",
        ),
        (
            "bad-value",
            "version: 1\nenv:\n  HTTP_PROXY: 5\nresources: []\n",
            "values must be strings",
        ),
    ] {
        let e = load_err(&dir, &format!("{label}.yaml"), body);
        assert_eq!(e.kind, sinter::error::ErrorKind::Schema, "{label}");
        assert!(e.message.contains(needle), "{label}: {}", e.message);
    }
}

#[test]
fn recipe_env_in_an_included_file_is_rejected() {
    let dir = trusted_root("n4-include");
    write_recipe(
        &dir,
        "child.yaml",
        "version: 1\nenv:\n  HTTP_PROXY: \"http://child:1\"\nresources: []\n",
    );
    let e = load_err(
        &dir,
        "main.yaml",
        "version: 1\ninclude:\n  - child.yaml\nresources: []\n",
    );
    assert!(
        e.message.contains("top-level recipe") && e.message.contains("env"),
        "{}",
        e.message
    );
}

#[test]
fn a_recipe_without_env_is_unchanged() {
    let dir = trusted_root("n4-none");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: c\n    type: command\n    with:\n      program: /bin/true\n",
    );
    let r = run_recipe_fake(
        &recipe,
        Mode::Apply,
        false,
        FakeTarget::rocky9().with_observations("true", vec![exited0()]),
    );
    let env = env_of(&r, "/bin/true");
    assert!(!env.contains_key("HTTP_PROXY"));
    // Only the fixed baseline is present.
    assert_eq!(env.get("LANG").map(String::as_str), Some("C.UTF-8"));
}
