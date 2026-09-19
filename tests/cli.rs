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

#[test]
fn sensitive_invalid_package_name_never_leaks_to_stderr() {
    // Audit P1-01: a rejected sensitive package name must not appear raw in
    // stderr, in text or JSON output mode.
    let dir = trusted_root("cli-sens-pkgname");
    let secret = "P2_SECRET_f71e9;invalid";
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: p\n    type: package\n    sensitive: true\n    with:\n      name: {:?}\n      state: present\n",
            secret
        ),
    );
    for args in [
        vec!["validate"],
        vec!["validate", "--format", "json"],
        vec!["plan", "--format", "json"],
    ] {
        let mut full: Vec<&str> = args.clone();
        full.push(recipe.to_str().unwrap());
        let out = Command::new(bin()).args(&full).output().unwrap();
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert_ne!(out.status.code(), Some(0), "{:?}", args);
        assert!(
            !combined.contains(secret),
            "secret leaked in {:?}: {}",
            args,
            combined
        );
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("redacted"),
            "stderr missing redaction marker in {:?}: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn sensitive_interpolation_error_never_leaks_to_output() {
    // Audit P1-01 round 2: interpolation/reference parsing runs BEFORE
    // package-name validation. A sentinel embedded in an unparseable
    // interpolation on a sensitive resource must never reach stdout or
    // stderr in any output mode.
    let dir = trusted_root("cli-sens-interp");
    let sentinel = "SINTER_P1_01_SECRET_SENTINEL_219b";
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: p\n    type: package\n    sensitive: true\n    with:\n      name: \"{{{{ {} }}}}\"\n      state: present\n",
            sentinel
        ),
    );
    for args in [
        vec!["validate"],
        vec!["validate", "--format", "json"],
        vec!["plan", "--format", "json"],
    ] {
        let mut full: Vec<&str> = args.clone();
        full.push(recipe.to_str().unwrap());
        let out = Command::new(bin()).args(&full).output().unwrap();
        assert_ne!(out.status.code(), Some(0), "{:?}", args);
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            combined.matches(sentinel).count(),
            0,
            "sentinel leaked in {:?}: {}",
            args,
            combined
        );
        assert!(
            combined.contains("(value redacted)"),
            "missing redaction marker in {:?}: {}",
            args,
            combined
        );
    }
}

#[test]
fn sensitive_var_interpolation_error_never_leaks_to_output() {
    // A malformed interpolation that textually names a sensitive variable is
    // treated as sensitive-adjacent: its token contents never reach output.
    let dir = trusted_root("cli-sens-varinterp");
    let sentinel = "SINTER_P1_01_SECRET_SENTINEL_7f3a";
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nvars:\n  pkg:\n    value: {}\n    sensitive: true\nresources:\n  - id: p\n    type: package\n    with:\n      name: \"{{{{ vars.pkg {} }}}}\"\n      state: present\n",
            sentinel, sentinel
        ),
    );
    for args in [
        vec!["validate"],
        vec!["validate", "--format", "json"],
        vec!["plan", "--format", "json"],
    ] {
        let mut full: Vec<&str> = args.clone();
        full.push(recipe.to_str().unwrap());
        let out = Command::new(bin()).args(&full).output().unwrap();
        assert_ne!(out.status.code(), Some(0), "{:?}", args);
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            combined.matches(sentinel).count(),
            0,
            "sentinel leaked in {:?}: {}",
            args,
            combined
        );
        assert!(
            combined.contains("(value redacted)"),
            "missing redaction marker in {:?}: {}",
            args,
            combined
        );
    }
}

#[test]
fn nonsensitive_interpolation_error_stays_descriptive() {
    // The same parser error on a non-sensitive resource keeps its useful
    // diagnostic detail — redaction must not blanket everything.
    let dir = trusted_root("cli-nonsens-interp");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: \"{{ BARETOKEN }}\"\n      state: present\n",
    );
    let out = Command::new(bin())
        .args(["validate", recipe.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{:?}", out);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("bare names are not allowed"), "{}", err);
    assert!(err.contains("BARETOKEN"), "{}", err);
    assert!(!err.contains("redacted"), "{}", err);
}

// ---------------------------------------------------------------------------
// Phase 1C: `sinter audit` CLI
// ---------------------------------------------------------------------------

#[test]
fn audit_compliant_exits_zero() {
    let dir = trusted_root("cli-audit-ok");
    let target = dir.join("f");
    std::fs::write(&target, "x").unwrap();
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: x\n",
            target.display()
        ),
    );
    let out = Command::new(bin())
        .args(["audit", recipe.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{:?}", out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("== Sinter AUDIT =="), "{}", stdout);
    assert!(stdout.contains("PASS f [file]"), "{}", stdout);
    assert!(stdout.contains("status: no_drift"), "{}", stdout);
}

#[test]
fn audit_drift_exits_seven() {
    let dir = trusted_root("cli-audit-drift");
    let target = dir.join("f");
    std::fs::write(&target, "other").unwrap();
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: x\n",
            target.display()
        ),
    );
    let out = Command::new(bin())
        .args(["audit", recipe.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(7), "{:?}", out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("DRIFT f [file]"), "{}", stdout);
    assert!(stdout.contains("status: drift"), "{}", stdout);
}

#[test]
fn audit_observation_error_exits_six_and_dominates_drift() {
    // A drifted file plus a template that fails to render: error dominates.
    let dir = trusted_root("cli-audit-err");
    write_recipe(&dir, "t.tmpl", "value={{ vars.nope }}\n");
    let target = dir.join("f");
    std::fs::write(&target, "other").unwrap();
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: x\n  - id: t\n    type: template\n    with:\n      path: {}/out\n      source: t.tmpl\n",
            target.display(),
            dir.display()
        ),
    );
    let out = Command::new(bin())
        .args(["audit", recipe.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(6), "{:?}", out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ERROR t [template]"), "{}", stdout);
    assert!(stdout.contains("status: indeterminate"), "{}", stdout);
}

#[test]
fn audit_not_auditable_exits_zero_and_stays_visible() {
    let dir = trusted_root("cli-audit-na");
    let marker = dir.join("sentinel-mutated");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: c\n    type: command\n    with:\n      program: /bin/sh\n      args: [\"-c\", \"touch {}\"]\n",
            marker.display()
        ),
    );
    let out = Command::new(bin())
        .args(["audit", recipe.to_str().unwrap()])
        .output()
        .unwrap();
    // NOT_AUDITABLE alone is not drift, but must stay visible.
    assert_eq!(out.status.code(), Some(0), "{:?}", out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("NOT_AUDITABLE c [command]"), "{}", stdout);
    assert!(stdout.contains("1 not_auditable"), "{}", stdout);
    // The command must never have run.
    assert!(!marker.exists());
}

#[test]
fn audit_never_mutates_desired_state() {
    // Desired file is absent on the target: audit must report DRIFT and
    // leave the filesystem untouched.
    let dir = trusted_root("cli-audit-ro");
    let target = dir.join("must-not-be-created");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: x\n",
            target.display()
        ),
    );
    let out = Command::new(bin())
        .args(["audit", recipe.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(7), "{:?}", out);
    assert!(!target.exists(), "audit created the desired file");
}

#[test]
fn audit_json_output_is_machine_readable() {
    let dir = trusted_root("cli-audit-json");
    let target = dir.join("f");
    std::fs::write(&target, "other").unwrap();
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: x\n",
            target.display()
        ),
    );
    let out = Command::new(bin())
        .args(["audit", recipe.to_str().unwrap(), "--format", "json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(7), "{:?}", out);
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).expect("valid json");
    assert_eq!(v["mode"], "audit");
    assert_eq!(v["status"], "drift");
    assert_eq!(v["summary"]["drifted"], 1);
    assert_eq!(v["summary"]["errors"], 0);
    assert_eq!(v["resources"][0]["id"], "f");
    assert_eq!(v["resources"][0]["status"], "drift");
}

#[test]
fn audit_schema_and_connection_errors_keep_existing_codes() {
    let dir = trusted_root("cli-audit-errs");
    let bad = write_recipe(&dir, "bad.yaml", "version: 2\n");
    let out = Command::new(bin())
        .args(["audit", bad.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));

    let good = write_recipe(
        &dir,
        "good.yaml",
        "version: 1\nresources:\n  - id: c\n    type: command\n    with:\n      program: /bin/true\n",
    );
    let known = dir.join("kh");
    std::fs::write(&known, "").unwrap();
    let out = Command::new(bin())
        .args([
            "audit",
            good.to_str().unwrap(),
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
fn audit_sensitive_values_never_appear_in_output() {
    let dir = trusted_root("cli-audit-sens");
    let target = dir.join("secret");
    std::fs::write(&target, "old-secret-content").unwrap();
    let secret = "AUDIT-SUPER-SECRET-6789";
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
"#,
            secret = secret,
            p = target.display()
        ),
    );
    for args in [
        vec!["audit", recipe.to_str().unwrap()],
        vec!["audit", recipe.to_str().unwrap(), "--verbose"],
        vec!["audit", recipe.to_str().unwrap(), "--format", "json"],
    ] {
        let out = Command::new(bin()).args(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(7), "{:?}", args);
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
        assert!(!combined.contains("old-secret-content"));
    }
}
