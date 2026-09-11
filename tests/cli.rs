#![cfg(target_os = "linux")]
mod common;

use common::*;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_sinter")
}

#[test]
fn validate_exit_codes() {
    let dir = trusted_root("cli-validate");
    let good = write_recipe(&dir, "good.yaml", "version: 1\n");
    let out = Command::new(bin())
        .arg("validate")
        .arg(&good)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{:?}", out);

    let bad = write_recipe(&dir, "bad.yaml", "version: 2\n");
    let out = Command::new(bin())
        .arg("validate")
        .arg(&bad)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn validate_does_not_connect() {
    let dir = trusted_root("cli-no-connect");
    // A recipe that references a fact-free command would connect only under
    // plan/apply; validate must not.
    let good = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: c\n    type: command\n    with:\n      program: /bin/true\n",
    );
    let out = Command::new(bin())
        .arg("validate")
        .arg(&good)
        .output()
        .unwrap();
    // No target is supplied and validate must still succeed.
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn plan_difference_exits_zero_and_json() {
    let dir = trusted_root("cli-plan");
    let out_path = dir.join("f");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: x\n",
            out_path.display()
        ),
    );
    let out = Command::new(bin())
        .args(["plan", recipe.to_str().unwrap(), "--format", "json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");
    assert_eq!(v["mode"], "plan");
    assert_eq!(v["status"], "success");
    // Plan must not create the file.
    assert!(!out_path.exists());
}

#[test]
fn connection_error_exits_three() {
    let dir = trusted_root("cli-connect");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: c\n    type: command\n    with:\n      program: /bin/true\n",
    );
    let known = dir.join("kh");
    std::fs::write(&known, "").unwrap();
    let out = Command::new(bin())
        .args([
            "plan",
            recipe.to_str().unwrap(),
            "--host",
            "127.0.0.1",
            "--port",
            "1",
            "--user",
            "nobody",
            "--known-hosts",
            known.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3), "{:?}", out);
}

#[test]
fn apply_failure_exits_five() {
    let dir = trusted_root("cli-apply-fail");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: c\n    type: command\n    with:\n      program: /bin/false\n",
    );
    let out = Command::new(bin())
        .args(["apply", recipe.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(5));
}

#[test]
fn plan_unsafe_observation_exits_four() {
    let dir = trusted_root("cli-plan-unsafe");
    // A missing service without a present-package dependency is a plan error.
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        r#"version: 1
resources:
  - id: s
    type: service
    with:
      name: sinter-no-such-unit
      state: running
"#,
    );
    let out = Command::new(bin())
        .args(["plan", recipe.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(4), "{:?}", out);
}

#[test]
fn sensitive_values_never_appear_in_output() {
    let dir = trusted_root("cli-sensitive");
    let out_path = dir.join("secret");
    std::fs::write(&out_path, "old-secret-content").unwrap();
    let secret = "SUPER-SECRET-VALUE-12345";
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            r#"version: 1
vars:
  token:
    value: {secret}
    sensitive: true
resources:
  - id: f
    type: file
    sensitive: true
    with:
      path: {p}
      content: "token={{{{ vars.token }}}}"
  - id: c
    type: command
    with:
      program: /bin/sh
      args: ["-c", "echo token={secret}"]
    depends_on: [f]
"#,
            secret = secret,
            p = out_path.display()
        ),
    );
    for args in [
        vec!["plan", recipe.to_str().unwrap()],
        vec!["plan", recipe.to_str().unwrap(), "--verbose"],
        vec!["plan", recipe.to_str().unwrap(), "--format", "json"],
        vec!["apply", recipe.to_str().unwrap()],
        vec!["apply", recipe.to_str().unwrap(), "--verbose"],
        vec!["apply", recipe.to_str().unwrap(), "--format", "json"],
    ] {
        let out = Command::new(bin()).args(&args).output().unwrap();
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !combined.contains(secret),
            "secret leaked in {:?}: {}",
            args,
            combined
        );
        // The old content must never appear in a diff either.
        assert!(!combined.contains("old-secret-content"));
    }
}

#[test]
fn apply_indeterminate_exits_six() {
    // A command that outlives its timeout becomes indeterminate.
    let dir = trusted_root("cli-indet");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: c\n    type: command\n    with:\n      program: /bin/sleep\n      args: [\"30\"]\n      timeout_seconds: 1\n",
    );
    let out = Command::new(bin())
        .args(["apply", recipe.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(6), "{:?}", out);
}
