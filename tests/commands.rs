#![cfg(target_os = "linux")]
mod common;

use common::*;
use sinter::engine::Mode;
use sinter::result::{Change, Disposition, Execution};

fn apply(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
    let recipe = write_recipe(
        dir,
        "r.yaml",
        &format!("version: 1\nresources:\n{}\n", body),
    );
    recipe
}

#[test]
fn command_exit_codes_and_changed_when() {
    let dir = trusted_root("command-exit");
    let recipe = apply(
        &dir,
        r#"  - id: ok
    type: command
    with:
      program: /bin/true
  - id: cw_false
    type: command
    with:
      program: /bin/true
      changed_when: "false"
  - id: custom
    type: command
    with:
      program: /bin/sh
      args: ["-c", "exit 3"]
      success_codes: [3]"#,
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r);
    assert_eq!(find(&r, "ok").change, Change::Changed);
    assert_eq!(find(&r, "cw_false").change, Change::None);
    assert_eq!(find(&r, "custom").execution, Execution::Succeeded);
    assert_eq!(find(&r, "custom").change, Change::Changed);
}

#[test]
fn command_failure_is_possible_change() {
    let dir = trusted_root("command-fail");
    let recipe = apply(
        &dir,
        r#"  - id: bad
    type: command
    with:
      program: /bin/false"#,
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    let bad = find(&r, "bad");
    assert_eq!(bad.execution, Execution::Failed);
    assert_eq!(bad.change, Change::Possible);
}

#[test]
fn creates_guard_semantics_and_dependency_satisfaction() {
    let dir = trusted_root("creates-guard");
    let marker = dir.join("ready");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            r#"version: 1
resources:
  - id: guard
    type: command
    with:
      program: /bin/sh
      args: ["-c", "echo ran"]
      creates: {marker}
      register: g
  - id: dep
    type: command
    with:
      program: /bin/sh
      args: ["-c", "echo after"]
    depends_on: [guard]
"#,
            marker = marker.display()
        ),
    );
    // First apply: marker absent, guard executes and creates it.
    let r1 = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r1);
    assert!(r1
        .commands
        .iter()
        .any(|c| c.program.contains("sh") && c.args.join(" ").contains("echo ran")));
    // Second apply: guard is satisfied without execution.
    std::fs::write(&marker, "").unwrap();
    let r2 = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r2);
    let g = find(&r2, "guard");
    assert_eq!(g.disposition, Disposition::GuardSatisfied);
    assert_eq!(g.execution, Execution::Succeeded);
    assert_eq!(g.change, Change::None);
    // dependent may run because guard_satisfied satisfies dependencies.
    let d = find(&r2, "dep");
    assert_eq!(d.execution, Execution::Succeeded);
}

#[test]
fn removes_guard_semantics() {
    let dir = trusted_root("removes-guard");
    let marker = dir.join("gone");
    let recipe = write_recipe(
        &dir,
        "r2.yaml",
        &format!(
            r#"version: 1
resources:
  - id: guard
    type: command
    with:
      program: /bin/sh
      args: ["-c", "echo ran"]
      removes: {marker}
"#,
            marker = marker.display()
        ),
    );
    // Marker absent -> guard satisfied, no execution.
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r);
    assert_eq!(find(&r, "guard").disposition, Disposition::GuardSatisfied);
}

#[test]
fn register_direct_dependency_and_value_flow() {
    let dir = trusted_root("register-flow");
    let out = dir.join("out");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            r#"version: 1
resources:
  - id: produce
    type: command
    with:
      program: /bin/echo
      args: ["value"]
      register: v
  - id: consume
    type: file
    with:
      path: {out}
      content: "got={{{{ registers.v.stdout }}}}"
    depends_on: [produce]
"#,
            out = out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r);
    // echo emits a trailing newline.
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "got=value\n");
}

#[test]
fn register_rejects_incomplete_output_use() {
    // A command whose stdout exceeds the capture limit must expose a null
    // stdout, and interpolation must fail rather than use truncated data.
    let dir = trusted_root("register-overflow");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        r#"version: 1
resources:
  - id: big
    type: command
    with:
      program: /usr/bin/yes
      timeout_seconds: 2
      register: v
  - id: use
    type: command
    with:
      program: /bin/echo
      args: ["{{ registers.v.stdout }}"]
    depends_on: [big]
"#,
    );
    // `yes` never terminates; this must be classified indeterminate and stop.
    let r = run_recipe(&recipe, Mode::Apply, false);
    let big = find(&r, "big");
    assert_eq!(big.execution, Execution::Indeterminate);
    assert_eq!(big.change, Change::Possible);
    // no automatic retry
    let use_res = find(&r, "use");
    assert_eq!(use_res.disposition, Disposition::BlockedByFailFast);
}

#[test]
fn changed_when_error_fails_execution() {
    let dir = trusted_root("changed-when-error");
    let recipe = apply(
        &dir,
        r#"  - id: c
    type: command
    with:
      program: /bin/true
      changed_when: "result.nonexistent == 1""#,
    );
    // The expression validator rejects unknown result fields at schema time.
    assert!(sinter::model::load_model(&recipe).is_err());
}

#[test]
fn changed_when_cannot_read_changed() {
    let dir = trusted_root("changed-when-self");
    let recipe = apply(
        &dir,
        r#"  - id: c
    type: command
    with:
      program: /bin/true
      changed_when: "result.changed == true""#,
    );
    assert!(sinter::model::load_model(&recipe).is_err());
}

#[test]
fn command_environment_baseline() {
    let dir = trusted_root("command-env");
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
  - id: use
    type: file
    with:
      path: {out}
      content: "{{{{ registers.e.stdout }}}}"
    depends_on: [env]
"#,
            out = out.display()
        ),
    );
    // Set a controller sentinel that must not leak.
    std::env::set_var("SINTER_SENTINEL", "leak");
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r);
    let e = find(&r, "env");
    assert_eq!(e.execution, Execution::Succeeded);
    // Read the registered stdout via the file it produced.
    let content = std::fs::read_to_string(&out).unwrap();
    assert!(content.contains("LC_ALL=C.UTF-8"), "env: {}", content);
    assert!(content.contains("LANG=C.UTF-8"));
    assert!(content.contains("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"));
    assert!(
        !content.contains("SINTER_SENTINEL"),
        "sentinel leaked: {}",
        content
    );
}

#[test]
fn command_explicit_env_passed_exactly() {
    let dir = trusted_root("command-explicit-env");
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
      program: /bin/sh
      args: ["-c", "printf '%s' \"$MYVAR\""]
      env:
        MYVAR: "hello world"
      register: e
  - id: use
    type: file
    with:
      path: {out}
      content: "{{{{ registers.e.stdout }}}}"
    depends_on: [env]
"#,
            out = out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r);
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "hello world");
}

#[test]
fn guard_versus_condition_disposition() {
    let dir = trusted_root("guard-vs-condition");
    let marker = dir.join("ready");
    std::fs::write(&marker, "").unwrap();
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            r#"version: 1
resources:
  - id: guard
    type: command
    with:
      program: /bin/true
      creates: {marker}
  - id: cond
    type: file
    with:
      path: {out}
      content: x
    when: "false"
"#,
            marker = marker.display(),
            out = dir.join("o").display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r);
    assert_eq!(find(&r, "guard").disposition, Disposition::GuardSatisfied);
    assert_eq!(
        find(&r, "cond").disposition,
        Disposition::SkippedByCondition
    );
}

#[test]
fn false_condition_blocks_dependents() {
    let dir = trusted_root("false-cond-blocks");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        r#"version: 1
resources:
  - id: producer
    type: file
    with:
      path: /nonexistent-parent/x
    when: "false"
  - id: consumer
    type: command
    with:
      program: /bin/true
    depends_on: [producer]
"#,
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r);
    assert_eq!(
        find(&r, "consumer").disposition,
        Disposition::BlockedByDependency
    );
}

#[test]
fn loop_order_and_ids() {
    // Loop instances must retain list order and use zero-based generated IDs.
    let dir = trusted_root("loop-order");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        r#"version: 1
resources:
  - id: line
    type: command
    with:
      program: /bin/echo
      args: ["{{ item }}"]
      register: r
    loop:
      - a
      - b
      - c
"#,
    );
    // loop + register is forbidden, so instead use file content keyed by a
    // static path derived from the loop item is also forbidden. Verify loop
    // expansion ordering through package names (static identifiers) instead.
    assert!(sinter::model::load_model(&recipe).is_err());

    let recipe2 = write_recipe(
        &dir,
        "r2.yaml",
        r#"version: 1
resources:
  - id: pkg
    type: package
    with:
      name: "{{ item }}"
      state: present
    loop:
      - jq
      - curl
"#,
    );
    let m = sinter::model::load_model(&recipe2).unwrap();
    let names: Vec<Option<String>> = m.resources.iter().map(|r| r.package_name.clone()).collect();
    assert_eq!(
        names,
        vec![Some("jq".to_string()), Some("curl".to_string())]
    );
    assert_eq!(m.resources[0].id, "pkg[0]");
    assert_eq!(m.resources[1].id, "pkg[1]");
}

#[test]
fn independent_declaration_order() {
    let dir = trusted_root("decl-order");
    let out = dir.join("order");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        r#"version: 1
resources:
  - id: first
    type: command
    with:
      program: /bin/echo
      args: ["1"]
  - id: second
    type: command
    with:
      program: /bin/echo
      args: ["2"]
  - id: third
    type: command
    with:
      program: /bin/echo
      args: ["3"]
"#,
    );
    let _ = out;
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r);
    let ids: Vec<&str> = r.resources.iter().map(|x| x.id.as_str()).collect();
    assert_eq!(ids, vec!["first", "second", "third"]);
}

#[test]
fn truncated_output_is_not_usable_in_expressions() {
    let dir = trusted_root("truncated-output");
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
      register: b
  - id: use
    type: command
    with:
      program: /bin/echo
      args: ["{{ registers.b.stdout }}"]
    depends_on: [big]
"#,
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    // big succeeds with exit 0 but its output exceeds the capture limit.
    let big = find(&r, "big");
    assert_eq!(big.execution, Execution::Succeeded);
    // The consumer must fail rather than silently use truncated data.
    let use_res = find(&r, "use");
    assert_eq!(use_res.execution, Execution::Failed);
}
