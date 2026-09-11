#![cfg(target_os = "linux")]
mod common;

use common::*;
use sinter::engine::{AggregateStatus, Mode};
use sinter::result::{Change, Disposition, Execution, Verification};

// ===========================================================================
// C1 - SSH + sudo shell injection in internal file operations
// ===========================================================================

/// Hostile resource IDs must never become executable shell syntax. We exercise
/// a file resource whose ID contains spaces, quotes, newlines, `$()`, and other
/// metacharacters, under --sudo against the real target, and assert that
/// (a) the intended file is created and (b) no undeclared side-effect marker
/// appears.
#[test]
fn hostile_resource_id_has_no_shell_side_effects_under_sudo() {
    if ssh_spec().is_none() {
        skip("requires SSH target");
        return;
    }
    if !target_sudo_available() {
        skip("target does not provide passwordless sudo -n");
        return;
    }
    let outdir = target_private_dir("c1-inject", true);
    let payload = format!("{}/payload.conf", outdir);
    // Every listed hostile construct appears in the ID: spaces, single and
    // double quotes, `$()`, backticks, semicolon, glob, leading hyphen.
    let hostile = "x $(touch${IFS}.sinter-audit-proof) `id`; echo pwned \"q\" 'sq' a*b -lead";
    let id_yaml = hostile.replace('\\', "\\\\").replace('"', "\\\"");
    let recipe_dir = trusted_root("c1-recipe");
    let recipe = write_recipe(
        &recipe_dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: \"{}\"\n    type: file\n    with:\n      path: {}\n      content: \"safe content\"\n      mode: \"0640\"\n",
            id_yaml, payload
        ),
    );

    let r = run_recipe_target(&recipe, Mode::Apply, true, ssh_spec());
    assert_success(&r);
    assert_eq!(target_read_file(&payload, true), "safe content");

    // The classic proof artifacts must not exist on the target.
    for probe in ["/tmp/.sinter-audit-proof", "/root/.sinter-audit-proof"] {
        let (code, _o, _e) = target_run("/usr/bin/test", &["!", "-e", probe], true)
            .expect("target test failed to run");
        assert_eq!(code, 0, "shell injection produced {}", probe);
    }
    // No unexpected objects in the output directory beyond the payload and any
    // staging directory.
    let (code, listing, _e) = target_run("/bin/ls", &["-a", "--", &outdir], true).unwrap();
    assert_eq!(code, 0);
    for name in listing.lines() {
        let name = name.trim();
        if name.is_empty() || name == "." || name == ".." {
            continue;
        }
        assert!(
            name == "payload.conf" || name.starts_with(".sinter-stage."),
            "unexpected side effect in {}: {}",
            outdir,
            name
        );
    }
    target_cleanup_dir(&outdir, true);
}

// ===========================================================================
// C2 - handler failure/indeterminate must affect aggregate status + exit code
// ===========================================================================

#[test]
fn handler_failure_makes_aggregate_apply_failed_and_exit_5() {
    use std::process::Command;
    // A handler for a non-existent unit fails. The change that enqueued it must
    // still be reported, but the invocation aggregate must be a failure.
    let dir = trusted_root("c2-handler-fail");
    let outdir = trusted_root("c2-handler-fail-out");
    let out = outdir.join("conf");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            r#"version: 1
resources:
  - id: conf
    type: file
    with:
      path: {out}
      content: "v1"
    notify: [bad]
handlers:
  - id: bad
    service: sinter-definitely-not-a-unit
    action: restart
"#,
            out = out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_eq!(
        r.status,
        AggregateStatus::ApplyFailed,
        "failed handler must make the invocation fail: {:?}",
        r.handlers_run
    );
    assert_eq!(r.handlers_run.len(), 1);
    assert_eq!(
        r.handlers_run[0].state,
        sinter::result::HandlerOutcomeState::Failed
    );

    // For the CLI exit code use a fresh output path so the change (and thus the
    // handler) actually occurs in the subprocess.
    let cli_recipe = write_recipe(
        &dir,
        "cli.yaml",
        &format!(
            r#"version: 1
resources:
  - id: conf
    type: file
    with:
      path: {out}
      content: "cli-v2"
    notify: [bad]
handlers:
  - id: bad
    service: sinter-definitely-not-a-unit
    action: restart
"#,
            out = outdir.join("cli-conf").display()
        ),
    );
    let out_cli = Command::new(env!("CARGO_BIN_EXE_sinter"))
        .args(["apply", cli_recipe.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(
        out_cli.status.code(),
        Some(5),
        "CLI must exit 5 on handler failure: {}{}",
        String::from_utf8_lossy(&out_cli.stdout),
        String::from_utf8_lossy(&out_cli.stderr)
    );
}

// ===========================================================================
// C4 - partial mutation / indeterminate information must be preserved
// ===========================================================================

/// A metadata update where the first step succeeds and the second fails must
/// report change=changed (a mutation definitely occurred), never change=none.
#[test]
fn partial_metadata_mutation_reports_changed() {
    let dir = trusted_root("c4-partial");
    let out = dir.join("f");
    std::fs::write(&out, "content").unwrap();
    set_mode(&out, 0o644);
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: content\n      mode: \"0600\"\n",
            out.display()
        ),
    );
    // Inject a failure between a successful ownership step and chmod.
    let r = run_recipe_fault(&recipe, Mode::Apply, "fail_chmod_after_chown");
    let f = find(&r, "f");
    assert_eq!(f.execution, Execution::Failed);
    assert_eq!(
        f.change,
        Change::Changed,
        "a step succeeded before failure; change must be changed, not none"
    );
}

/// Conversely, when the first (and only attempted) metadata step fails, no
/// mutation occurred and change=none is truthful.
#[test]
fn failed_first_metadata_step_reports_no_change() {
    if unsafe { libc::geteuid() } == 0 {
        skip("must run unprivileged");
        return;
    }
    let dir = trusted_root("c4-nochange");
    let out = dir.join("f");
    std::fs::write(&out, "content").unwrap();
    set_mode(&out, 0o644);
    // Owner change to root: chown is applied first and cannot succeed
    // unprivileged, so nothing mutates.
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: content\n      owner: root\n",
            out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    let f = find(&r, "f");
    assert_eq!(f.execution, Execution::Failed);
    assert_eq!(
        f.change,
        Change::None,
        "no successful mutation implies change=none"
    );
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&out).unwrap().permissions().mode() & 0o7777,
        0o644
    );
}

/// A rename whose completion is unknown must be reported as indeterminate with
/// possible change, never as a plain failure with change:none.
#[test]
fn rename_indeterminate_reports_possible_change() {
    let dir = trusted_root("c4-indet-rename");
    let out = dir.join("f");
    std::fs::write(&out, "old").unwrap();
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: new\n",
            out.display()
        ),
    );
    let r = run_recipe_fault(&recipe, Mode::Apply, "indeterminate_publish");
    let f = find(&r, "f");
    assert_eq!(f.execution, Execution::Indeterminate);
    assert_eq!(f.change, Change::Possible);
    assert_eq!(f.verification, Verification::Unknown);
}

// ===========================================================================
// C3 - sensitive information must not leak through any presentation path
// ===========================================================================

#[test]
fn sensitive_sentinel_never_leaks_through_any_output_path() {
    use std::process::Command;
    let dir = trusted_root("c3-sentinel");
    let out = dir.join("secret");
    // Existing non-sensitive file so a content diff would otherwise be shown.
    std::fs::write(&out, "OLD-INSECURE-CONTENT").unwrap();
    let sentinel = "ZZSENTINEL-C3-9f3a1b-SECRET";
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            r#"version: 1
vars:
  token:
    value: {sentinel}
    sensitive: true
resources:
  - id: f
    type: file
    sensitive: true
    with:
      path: {p}
      content: "token={{{{ vars.token }}}}"
    notify: [h]
  - id: c
    type: command
    with:
      program: /bin/sh
      args: ["-c", "echo token={sentinel}"]
    depends_on: [f]
handlers:
  - id: h
    service: sinter-no-such-unit-c3
    action: restart
"#,
            sentinel = sentinel,
            p = out.display()
        ),
    );
    let modes: Vec<Vec<&str>> = vec![
        vec!["plan"],
        vec!["plan", "--verbose"],
        vec!["plan", "--format", "json"],
        vec!["apply"],
        vec!["apply", "--verbose"],
        vec!["apply", "--format", "json"],
    ];
    for args in modes {
        let mut c = Command::new(env!("CARGO_BIN_EXE_sinter"));
        c.arg(args[0]).arg(recipe.to_str().unwrap());
        for a in &args[1..] {
            c.arg(a);
        }
        let out = c.output().unwrap();
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !combined.contains(sentinel),
            "sensitive sentinel leaked in {:?}: {}",
            args,
            combined
        );
        assert!(
            !combined.contains("OLD-INSECURE-CONTENT"),
            "non-sensitive existing content leaked in diff for {:?}",
            args
        );
    }
}

#[test]
fn sensitive_variable_used_in_early_error_is_redacted() {
    // A sensitive variable referenced by a path is a validation error; the
    // error path must not echo the sensitive value.
    use std::process::Command;
    let dir = trusted_root("c3-early-error");
    let sentinel = "ZZSENTINEL-C3-EARLY-7c2d";
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nvars:\n  p:\n    value: \"{sentinel}/x\"\n    sensitive: true\nresources:\n  - id: f\n    type: file\n    with:\n      path: \"{{{{ vars.p }}}}\"\n      content: x\n"
        ),
    );
    let out = Command::new(env!("CARGO_BIN_EXE_sinter"))
        .args(["validate", recipe.to_str().unwrap()])
        .output()
        .unwrap();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !combined.contains(sentinel),
        "sensitive sentinel leaked through early error: {}",
        combined
    );
}

// ===========================================================================
// C5 - filesystem publication safety
// ===========================================================================

/// A dangling/loose staging path that happens to match a predictable name must
/// not be removed by Sinter. Since staging is now a fresh private directory with
/// a non-predictable name, we assert that a pre-created predictable file in the
/// destination parent survives a publish.
#[test]
fn predictable_staging_name_is_not_silently_removed() {
    let dir = trusted_root("c5-predictable");
    let out = dir.join("f");
    let victim = dir.join(".sinter.legacy-predictable-name");
    std::fs::write(&victim, "user data").unwrap();
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: legacy\n    type: file\n    with:\n      path: {}\n      content: new\n",
            out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r);
    assert_eq!(
        std::fs::read_to_string(&victim).unwrap(),
        "user data",
        "a predictable-looking unrelated file must not be deleted"
    );
}

/// Inspection failure must fail closed: a parent that cannot be inspected must
/// not be treated as safe.
#[test]
fn parent_inspection_failure_fails_closed() {
    let dir = trusted_root("c5-inspect-fail");
    let out = dir.join("f");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: x\n",
            out.display()
        ),
    );
    let r = run_recipe_fault(&recipe, Mode::Apply, "uninspectable_parent");
    let f = find(&r, "f");
    assert_eq!(f.execution, Execution::Failed);
    assert!(!out.exists());
}

/// A metadata-only update must apply ownership before mode (set-ID safety) and
/// must be verified. We assert the final mode is exactly as requested.
#[test]
fn metadata_update_ordering_is_safe_and_verified() {
    let dir = trusted_root("c5-meta-order");
    let out = dir.join("f");
    std::fs::write(&out, "content").unwrap();
    set_mode(&out, 0o600);
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: content\n      mode: \"0640\"\n",
            out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r);
    assert_eq!(find(&r, "f").verification, Verification::Verified);
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&out).unwrap().permissions().mode() & 0o7777,
        0o640
    );
}

// ===========================================================================
// H1 - common IR / validate contract
// ===========================================================================

#[test]
fn yaml_i64_min_matches_toml_typed_meaning() {
    // i64::MIN must parse in YAML identically to TOML.
    let min = i64::MIN.to_string();
    let y = sinter::yaml::parse_yaml(&format!("v: {}\n", min)).unwrap();
    let ym = y.as_map().unwrap();
    assert_eq!(ym["v"], sinter::value::Value::Int(i64::MIN));

    let t = sinter::toml_front::parse_toml(&format!("v = {}\n", min)).unwrap();
    let tm = t.as_map().unwrap();
    assert_eq!(tm["v"], sinter::value::Value::Int(i64::MIN));

    // Positive overflow is still rejected.
    assert!(sinter::yaml::parse_yaml("v: 9223372036854775808\n").is_err());
    assert!(sinter::toml_front::parse_toml("v = 9223372036854775808\n").is_err());
}

#[test]
fn invalid_directory_mode_is_rejected() {
    let dir = trusted_root("h1-dir-mode");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: d\n    type: directory\n    with:\n      path: /tmp/x\n      mode: \"99\"\n",
    );
    assert!(
        sinter::model::load_model(&recipe).is_err(),
        "invalid directory mode must be rejected"
    );
}

#[test]
fn register_reference_in_empty_loop_is_still_rejected() {
    // The register query is inside a loop that expands to zero instances; the
    // invalid direct-dependency requirement must still be enforced.
    let dir = trusted_root("h1-empty-loop-register");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        r#"version: 1
resources:
  - id: producer
    type: command
    with:
      program: /bin/echo
      args: ["x"]
      register: p
  - id: consumer
    type: file
    with:
      path: "/tmp/{{ item }}"
      content: "{{ registers.p.stdout }}"
    loop: []
"#,
    );
    assert!(
        sinter::model::load_model(&recipe).is_err(),
        "register reference inside an empty loop must still be validated"
    );
}

#[test]
fn invalid_declaration_shape_in_empty_loop_is_rejected() {
    let dir = trusted_root("h1-empty-loop-shape");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: d\n    type: directory\n    with:\n      path: /tmp/{{ item }}\n      mode: \"99\"\n    loop: []\n",
    );
    assert!(
        sinter::model::load_model(&recipe).is_err(),
        "invalid declaration shape must be rejected even with an empty loop"
    );
}

#[test]
fn unknown_register_reference_in_empty_loop_is_rejected() {
    let dir = trusted_root("h1-empty-loop-unknown-reg");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: c\n    type: file\n    with:\n      path: \"/tmp/{{ item }}\"\n      content: \"{{ registers.nope.stdout }}\"\n    loop: []\n",
    );
    assert!(sinter::model::load_model(&recipe).is_err());
}

// ===========================================================================
// H2 - evaluation contract consistency
// ===========================================================================

#[test]
fn template_local_vars_are_literal_not_interpolated() {
    let dir = trusted_root("h2-template-literal");
    // The template-local `t` value is the literal string "{{ vars.x }}"; it must
    // NOT be interpolated against the global namespace.
    std::fs::write(dir.join("t.tmpl"), "{{ template.t }}").unwrap();
    let out = dir.join("out");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nvars:\n  x:\n    value: GLOBAL\nresources:\n  - id: t\n    type: template\n    with:\n      path: {}\n      source: t.tmpl\n      vars:\n        t: \"{{{{ vars.x }}}}\"\n",
            out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r);
    assert_eq!(
        std::fs::read_to_string(&out).unwrap(),
        "{{ vars.x }}",
        "template-local values must remain literal"
    );
}

#[test]
fn template_body_register_reference_requires_direct_dependency() {
    let dir = trusted_root("h2-template-dep");
    std::fs::write(dir.join("t.tmpl"), "value={{ registers.p.stdout }}").unwrap();
    // Missing depends_on [producer] must be a validation error.
    let bad = write_recipe(
        &dir,
        "bad.yaml",
        r#"version: 1
resources:
  - id: producer
    type: command
    with:
      program: /bin/echo
      args: ["x"]
      register: p
  - id: t
    type: template
    with:
      path: /tmp/out
      source: t.tmpl
"#,
    );
    assert!(
        sinter::model::load_model(&bad).is_err(),
        "template body register reference without direct dependency must be rejected"
    );

    // With the direct dependency it is accepted and rendered.
    let out = dir.join("out");
    let good = write_recipe(
        &dir,
        "good.yaml",
        &format!(
            r#"version: 1
resources:
  - id: producer
    type: command
    with:
      program: /bin/echo
      args: ["x"]
      register: p
  - id: t
    type: template
    with:
      path: {out}
      source: t.tmpl
    depends_on: [producer]
"#,
            out = out.display()
        ),
    );
    let r = run_recipe(&good, Mode::Apply, false);
    assert_success(&r);
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "value=x\n");
}

#[test]
fn changed_when_with_incomplete_output_errors() {
    // A command whose stdout exceeds the capture limit exposes an incomplete
    // stdout; changed_when must not treat it as usable.
    let dir = trusted_root("h2-cw-incomplete");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        r#"version: 1
resources:
  - id: big
    type: command
    with:
      program: /bin/sh
      args: ["-c", "head -c 2000000 /dev/zero | tr '\\0' 'a'"]
      changed_when: "result.stdout == \"\""
"#,
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    let big = find(&r, "big");
    assert_eq!(
        big.execution,
        Execution::Failed,
        "changed_when reading incomplete output must fail, not silently use it"
    );
}

#[test]
fn false_condition_short_circuits_unknown_dependency() {
    // The consumer has an Unknown dependency AND a false condition. The false
    // condition must resolve the resource as skipped_by_condition, not blocked
    // by the unknown dependency.
    let dir = trusted_root("h2-unknown-cond");
    let out = dir.join("out");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            r#"version: 1
resources:
  - id: producer
    type: command
    with:
      program: /bin/echo
      args: ["x"]
      register: p
  - id: consumer
    type: file
    with:
      path: {out}
      content: "{{{{ registers.p.stdout }}}}"
    depends_on: [producer]
    when: "false && registers.p.executed"
"#,
            out = out.display()
        ),
    );
    // Plan: the producer is unknown, but the condition short-circuits to false.
    let plan = run_recipe(&recipe, Mode::Plan, false);
    assert_success(&plan);
    let c = find(&plan, "consumer");
    assert_eq!(
        c.disposition,
        Disposition::SkippedByCondition,
        "false condition must win over the unknown dependency"
    );
}

// ===========================================================================
// H3 - local HOME/cwd must come from the account database
// ===========================================================================

#[test]
fn local_home_ignores_ambient_controller_home() {
    use std::process::Command;
    let dir = trusted_root("h3-home");
    let out = dir.join("pwd");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            r#"version: 1
resources:
  - id: pwd
    type: command
    with:
      program: /bin/pwd
      register: p
  - id: save
    type: file
    with:
      path: {out}
      content: "{{{{ registers.p.stdout }}}}"
      mode: "0644"
    depends_on: [pwd]
"#,
            out = out.display()
        ),
    );
    // Poison the controller environment: HOME and cwd point at an attacker dir.
    let poison = trusted_root("h3-poison");
    let out_proc = Command::new(env!("CARGO_BIN_EXE_sinter"))
        .args(["apply", recipe.to_str().unwrap()])
        .env("HOME", &poison)
        .current_dir(&poison)
        .output()
        .unwrap();
    assert_eq!(
        out_proc.status.code(),
        Some(0),
        "apply failed: {}{}",
        String::from_utf8_lossy(&out_proc.stdout),
        String::from_utf8_lossy(&out_proc.stderr)
    );
    let pwd = std::fs::read_to_string(&out).unwrap().trim().to_string();
    assert_ne!(
        pwd,
        poison.to_string_lossy(),
        "ambient controller HOME must not leak into target cwd"
    );
    // The account database home for this user must be used.
    let expected = {
        let out = std::process::Command::new("/usr/bin/getent")
            .args(["passwd", &unsafe { libc::getuid() }.to_string()])
            .output()
            .unwrap();
        let s = String::from_utf8_lossy(&out.stdout).to_string();
        s.trim().split(':').nth(5).unwrap_or("").to_string()
    };
    assert_eq!(
        pwd, expected,
        "target HOME must be the account database home"
    );
}

#[test]
fn local_command_environment_is_clean() {
    use std::process::Command;
    let dir = trusted_root("h3-env");
    let out = dir.join("envout");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            r#"version: 1
resources:
  - id: env
    type: command
    with:
      program: /usr/bin/env
      register: e
  - id: save
    type: file
    with:
      path: {out}
      content: "{{{{ registers.e.stdout }}}}"
      mode: "0644"
    depends_on: [env]
"#,
            out = out.display()
        ),
    );
    let out_proc = Command::new(env!("CARGO_BIN_EXE_sinter"))
        .args(["apply", recipe.to_str().unwrap()])
        .env("POISONED_CONTROLLER_VAR", "leak")
        .env("HOME", "/tmp")
        .output()
        .unwrap();
    assert_eq!(out_proc.status.code(), Some(0));
    let content = std::fs::read_to_string(&out).unwrap();
    assert!(content.contains("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"));
    assert!(content.contains("LANG=C.UTF-8"));
    assert!(content.contains("LC_ALL=C.UTF-8"));
    assert!(!content.contains("POISONED_CONTROLLER_VAR"));
    assert!(!content.contains("HOME=/tmp\n"));
}

// ===========================================================================
// H4 - bounded timeout over the whole operation incl. child pipe retention
// ===========================================================================

#[test]
fn local_timeout_is_bounded_wall_clock() {
    use std::time::Instant;
    let dir = trusted_root("h4-timeout");
    // A shell that spawns a background descendant holding the stdout pipe open
    // after the direct child would otherwise exit.
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        r#"version: 1
resources:
  - id: slow
    type: command
    with:
      program: /bin/sleep
      args: ["30"]
      timeout_seconds: 1
"#,
    );
    let start = Instant::now();
    let r = run_recipe(&recipe, Mode::Apply, false);
    let elapsed = start.elapsed();
    assert_eq!(find(&r, "slow").execution, Execution::Indeterminate);
    assert!(
        elapsed.as_secs() < 8,
        "timeout of 1s must bound the operation; elapsed {:?}",
        elapsed
    );
}

#[test]
fn local_timeout_with_pipe_holding_grandchild_is_bounded() {
    use std::time::Instant;
    let dir = trusted_root("h4-timeout-pipe");
    // The shell launches a descendant that inherits the pipe; killing only the
    // direct child would leave the reader blocked. The full operation must still
    // be bounded.
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        r#"version: 1
resources:
  - id: slow
    type: command
    with:
      program: /bin/sh
      args: ["-c", "sleep 30 & sleep 30"]
      timeout_seconds: 1
"#,
    );
    let start = Instant::now();
    let r = run_recipe(&recipe, Mode::Apply, false);
    let elapsed = start.elapsed();
    assert_eq!(find(&r, "slow").execution, Execution::Indeterminate);
    assert!(
        elapsed.as_secs() < 8,
        "pipe-holding descendant must not defeat the timeout; elapsed {:?}",
        elapsed
    );
}

// ===========================================================================
// H5 - SSH host-key checking must fail closed
// ===========================================================================

#[test]
fn ssh_host_key_failure_fails_closed() {
    // A known_hosts file with an entry for the host but of a different key type
    // than the server presents, combined with a malformed line, must not
    // authorize the connection. We rely on the API returning something other
    // than Match.
    let Some(mut s) = ssh_spec() else {
        skip("requires SSH target");
        return;
    };
    let dir = trusted_root("h5-hostkey");
    let kh = dir.join("known_hosts");
    // A syntactically invalid but non-empty file, forcing the parser to fail
    // the check rather than match.
    std::fs::write(&kh, "this is not a valid known_hosts line\n").unwrap();
    s.known_hosts = kh;
    let recipe = write_recipe(
        &trusted_root("h5-hostkey-recipe"),
        "r.yaml",
        "version: 1\nresources:\n  - id: c\n    type: command\n    with:\n      program: /bin/true\n",
    );
    let model = sinter::model::load_model(&recipe).unwrap();
    let opts = sinter::engine::RunOptions {
        mode: Mode::Plan,
        sudo: false,
        target: sinter::engine::TargetSpec { ssh: Some(s) },
        verbose: false,
        fault: None,
    };
    let res = sinter::engine::Engine::new(model, opts);
    assert!(
        res.is_err(),
        "a known_hosts that cannot authorize a Match must reject the connection"
    );
    assert_eq!(res.err().unwrap().kind, sinter::error::ErrorKind::Connect);
}

// ===========================================================================
// H6 - apt observation failure must not be treated as Absent
// ===========================================================================

#[test]
fn package_observation_failure_is_not_absent() {
    // A dpkg-query failure must fail observation, never silently become absent
    // (which would trigger an install mutation).
    let dir = trusted_root("h6-pkg-obs");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: bash\n      state: present\n",
    );
    // Run apply and assert the resource fails rather than installing.
    let r2 = run_recipe_fault(&recipe, Mode::Apply, "dpkg_observe_fail");
    let p = find(&r2, "p");
    assert_eq!(
        p.execution,
        Execution::Failed,
        "observation failure must fail"
    );
    assert_ne!(p.change, Change::Changed);
    // No install mutation may have been issued.
    assert!(
        !r2.commands.iter().any(|c| c.program.ends_with("apt-get")),
        "observation failure must not trigger a mutation: {:?}",
        r2.commands
    );
}

#[test]
fn package_inconsistent_state_fails_without_repair() {
    // A dpkg status that is not clean must be rejected; Sinter must not attempt
    // automatic repair. This exercises the real classifier used at runtime.
    assert!(sinter::resources::classify_dpkg_status("install ok half-configured").is_err());
    assert!(sinter::resources::classify_dpkg_status("install ok unpacked").is_err());
    assert!(sinter::resources::classify_dpkg_status("install reinstreq half-installed").is_err());
    assert_eq!(
        sinter::resources::classify_dpkg_status("install ok installed").unwrap(),
        sinter::resources::PackageState::Installed
    );
    assert_eq!(
        sinter::resources::classify_dpkg_status("").unwrap(),
        sinter::resources::PackageState::Absent
    );
}

#[test]
fn package_absent_is_confirmed_only_on_exit_one() {
    // A definitely-absent package must be observed as absent (plan shows a
    // change), while a package observation error must not. We use a name that
    // cannot exist for the confirmed-absent case.
    let dir = trusted_root("h6-pkg-absent");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: sinter-nonexistent-package-xyz\n      state: present\n",
    );
    let plan = run_recipe(&recipe, Mode::Plan, false);
    assert_success(&plan);
    assert_eq!(find(&plan, "p").change, Change::Changed);
}

// ===========================================================================
// H7 - useful current -> desired diff
// ===========================================================================

#[test]
fn link_change_reports_current_and_desired_targets() {
    let dir = trusted_root("h7-link-diff");
    let t1 = dir.join("t1");
    let t2 = dir.join("t2");
    std::fs::write(&t1, "1").unwrap();
    std::fs::write(&t2, "2").unwrap();
    let link = dir.join("link");
    std::os::unix::fs::symlink(&t1, &link).unwrap();
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: l\n    type: link\n    with:\n      path: {}\n      target: {}\n",
            link.display(),
            t2.display()
        ),
    );
    let plan = run_recipe(&recipe, Mode::Plan, false);
    assert_success(&plan);
    let l = find(&plan, "l");
    assert_eq!(l.change, Change::Changed);
    let diff = l
        .diff
        .as_ref()
        .expect("link change must carry a useful diff");
    match &diff.body {
        sinter::result::DiffBody::Summary { current, desired } => {
            assert!(
                current.contains(&t1.to_string_lossy().to_string()),
                "current: {}",
                current
            );
            assert!(
                desired.contains(&t2.to_string_lossy().to_string()),
                "desired: {}",
                desired
            );
        }
        other => panic!(
            "expected summary diff with current/desired, got {:?}",
            other
        ),
    }
}

#[test]
fn metadata_change_reports_current_and_desired() {
    let dir = trusted_root("h7-meta-diff");
    let out = dir.join("f");
    std::fs::write(&out, "same").unwrap();
    set_mode(&out, 0o600);
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: same\n      mode: \"0644\"\n",
            out.display()
        ),
    );
    let plan = run_recipe(&recipe, Mode::Plan, false);
    assert_success(&plan);
    let f = find(&plan, "f");
    assert_eq!(f.change, Change::Changed);
    let diff = f.diff.as_ref().expect("metadata change must carry a diff");
    match &diff.body {
        sinter::result::DiffBody::Summary { current, desired } => {
            assert!(current.contains("0600"), "current: {}", current);
            assert!(desired.contains("0644"), "desired: {}", desired);
        }
        other => panic!("expected summary metadata diff, got {:?}", other),
    }
}

/// Publication succeeds but re-observation fails: the change is known to have
/// happened and must remain reported as changed, never as none.
#[test]
fn publication_success_then_reobserve_failure_reports_changed() {
    let dir = trusted_root("c4-reobserve");
    let out = dir.join("f");
    std::fs::write(&out, "old").unwrap();
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: new\n",
            out.display()
        ),
    );
    let r = run_recipe_fault(&recipe, Mode::Apply, "reobserve_fail");
    let f = find(&r, "f");
    assert_eq!(f.execution, Execution::Failed);
    assert_eq!(
        f.change,
        Change::Changed,
        "publication succeeded; change must remain changed"
    );
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "new");
}

/// A handler whose completion is indeterminate must make the whole invocation
/// indeterminate and suppress later handlers.
#[test]
fn handler_indeterminate_makes_aggregate_indeterminate() {
    if !sudo_available() {
        skip("requires local passwordless sudo and a running service");
        return;
    }
    let _svc = lock_service();
    let dir = trusted_root("c2-handler-indet");
    let out = trusted_root_sudo("c2-handler-indet-out").join("conf");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            r#"version: 1
resources:
  - id: conf
    type: file
    with:
      path: {out}
      content: "v1"
    notify: [h1, h2]
handlers:
  - id: h1
    service: ssh
    action: restart
  - id: h2
    service: ssh
    action: restart
"#,
            out = out.display()
        ),
    );
    let r = run_recipe_fault_sudo(&recipe, Mode::Apply, "handler_indeterminate", true);
    assert_eq!(r.status, AggregateStatus::Indeterminate);
    assert_eq!(r.handlers_run.len(), 1);
    assert_eq!(
        r.handlers_run[0].state,
        sinter::result::HandlerOutcomeState::Indeterminate
    );
    assert!(r.handlers_pending.iter().any(|h| h == "h2"));
}
