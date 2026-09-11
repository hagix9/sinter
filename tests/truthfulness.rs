#![cfg(target_os = "linux")]
mod common;

use common::*;
use sinter::engine::Mode;
use sinter::result::{Change, Disposition, Execution, Verification};

#[test]
fn unchanged_verified_state() {
    let dir = trusted_root("truth-unchanged");
    let out = dir.join("f");
    std::fs::write(&out, "same").unwrap();
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: same\n",
            out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    let f = find(&r, "f");
    assert_eq!(f.execution, Execution::Succeeded);
    assert_eq!(f.change, Change::None);
    assert_eq!(f.verification, Verification::Verified);
    assert_eq!(f.disposition, Disposition::Normal);
}

#[test]
fn successful_change() {
    let dir = trusted_root("truth-change");
    let out = dir.join("f");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: new\n",
            out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    let f = find(&r, "f");
    assert_eq!(f.execution, Execution::Succeeded);
    assert_eq!(f.change, Change::Changed);
    assert_eq!(f.verification, Verification::Verified);
}

#[test]
fn failure_without_mutation() {
    let dir = trusted_root("truth-fail-nomut");
    let out = dir.join("f");
    // final component is a directory; file resource must refuse.
    std::fs::create_dir_all(&out).unwrap();
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: x\n",
            out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    let f = find(&r, "f");
    assert_eq!(f.execution, Execution::Failed);
    assert_eq!(f.change, Change::None);
    assert!(out.is_dir());
}

#[test]
fn failure_after_mutation() {
    let dir = trusted_root("truth-fail-mut");
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
    let r = run_recipe_fault(&recipe, Mode::Apply, "after_publish");
    let f = find(&r, "f");
    assert_eq!(f.execution, Execution::Failed);
    assert_eq!(f.change, Change::Changed);
    assert_eq!(f.verification, Verification::Failed);
}

#[test]
fn indeterminate_mutation() {
    let dir = trusted_root("truth-indet");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: c\n    type: command\n    with:\n      program: /bin/sleep\n      args: [\"30\"]\n      timeout_seconds: 1\n",
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    let c = find(&r, "c");
    assert_eq!(c.execution, Execution::Indeterminate);
    assert_eq!(c.change, Change::Possible);
    assert_eq!(r.status, sinter::engine::AggregateStatus::Indeterminate);
}

#[test]
fn blocked_dependency() {
    let dir = trusted_root("truth-blocked");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        r#"version: 1
resources:
  - id: producer
    type: command
    with:
      program: /bin/false
  - id: consumer
    type: command
    with:
      program: /bin/true
    depends_on: [producer]
"#,
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    // Fail-fast reason takes precedence for a not-yet-processed resource.
    let c = find(&r, "consumer");
    assert!(
        c.disposition == Disposition::BlockedByFailFast
            || c.disposition == Disposition::BlockedByDependency
    );
    assert_eq!(c.execution, Execution::NotRun);
}

#[test]
fn false_condition_then_dependency_block() {
    let dir = trusted_root("truth-cond-block");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        r#"version: 1
resources:
  - id: producer
    type: file
    with:
      path: /tmp/sinter-nope/x
    when: "false"
  - id: consumer
    type: command
    with:
      program: /bin/true
    depends_on: [producer]
"#,
    );
    // A condition skip does not stop traversal, so the consumer is explicitly
    // blocked_by_dependency (not fail-fast).
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r);
    assert_eq!(
        find(&r, "consumer").disposition,
        Disposition::BlockedByDependency
    );
}

#[test]
fn include_depth_first_declaration_order() {
    let dir = trusted_root("include-order");
    // main includes a and b; a includes a1. Expected expansion order:
    // a1, a, b, main.
    std::fs::write(
        dir.join("a1.yaml"),
        "version: 1\nresources:\n  - id: a1\n    type: command\n    with:\n      program: /bin/true\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("a.yaml"),
        "version: 1\ninclude:\n  - a1.yaml\nresources:\n  - id: a\n    type: command\n    with:\n      program: /bin/true\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("b.yaml"),
        "version: 1\nresources:\n  - id: b\n    type: command\n    with:\n      program: /bin/true\n",
    )
    .unwrap();
    let main = write_recipe(
        &dir,
        "main.yaml",
        "version: 1\ninclude:\n  - a.yaml\n  - b.yaml\nresources:\n  - id: main\n    type: command\n    with:\n      program: /bin/true\n",
    );
    let m = sinter::model::load_model(&main).unwrap();
    let ids: Vec<&str> = m.resources.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, vec!["a1", "a", "b", "main"]);
}

#[test]
fn fingerprint_both_frontends_in_dispositions() {
    // A YAML and TOML recipe with the same content must yield identical
    // dispositions/change on the same target.
    let dir = trusted_root("frontend-disposition");
    let out = dir.join("f");
    let yaml = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: x\n      mode: \"0644\"\n",
            out.display()
        ),
    );
    let toml_src = format!(
        "version = 1\n\n[[resources]]\nid = \"f\"\ntype = \"file\"\n\n[resources.with]\npath = \"{}\"\ncontent = \"x\"\nmode = \"0644\"\n",
        out.display()
    );
    let toml = write_recipe(&dir, "r.toml", &toml_src);

    let ry = run_recipe(&yaml, Mode::Apply, false);
    std::fs::remove_file(&out).unwrap();
    let rt = run_recipe(&toml, Mode::Apply, false);
    let fy = find(&ry, "f");
    let ft = find(&rt, "f");
    assert_eq!(fy.execution, ft.execution);
    assert_eq!(fy.change, ft.change);
    assert_eq!(fy.verification, ft.verification);
    assert_eq!(fy.disposition, ft.disposition);
}
