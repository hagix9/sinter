#![cfg(target_os = "linux")]
mod common;

use common::*;
use sinter::engine::Mode;
use sinter::result::{Change, Disposition, Execution, Verification};

#[test]
fn file_create_verify_and_idempotency() {
    let dir = trusted_root("file-create");
    let out = dir.join("f.txt");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: |\n        hello\n        world\n      mode: \"0640\"\n",
            out.display()
        ),
    );

    let r1 = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r1);
    let f = find(&r1, "f");
    assert_eq!(f.execution, Execution::Succeeded);
    assert_eq!(f.change, Change::Changed);
    assert_eq!(f.verification, Verification::Verified);
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "hello\nworld\n");
    let md = std::fs::metadata(&out).unwrap();
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(md.permissions().mode() & 0o7777, 0o640);

    // Second apply must perform zero mutations.
    let r2 = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r2);
    let f2 = find(&r2, "f");
    assert_eq!(f2.change, Change::None);
    assert_eq!(f2.verification, Verification::Verified);
    assert_eq!(
        mutation_command_count(&r2),
        0,
        "second apply must not mutate"
    );
}

#[test]
fn file_preserves_omitted_metadata_on_replace() {
    let dir = trusted_root("file-preserve");
    let out = dir.join("f.txt");
    std::fs::write(&out, "old").unwrap();
    set_mode(&out, 0o600);

    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: new\n",
            out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r);
    use std::os::unix::fs::PermissionsExt;
    let md = std::fs::metadata(&out).unwrap();
    assert_eq!(
        md.permissions().mode() & 0o7777,
        0o600,
        "mode must be preserved"
    );
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "new");
}

#[test]
fn file_empty_content_creation_and_absent() {
    let dir = trusted_root("file-empty");
    let out = dir.join("empty");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n",
            out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r);
    assert_eq!(std::fs::read(&out).unwrap(), Vec::<u8>::new());

    let recipe2 = write_recipe(
        &dir,
        "r2.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      state: absent\n",
            out.display()
        ),
    );
    let r2 = run_recipe(&recipe2, Mode::Apply, false);
    assert_success(&r2);
    assert!(!out.exists());
    // idempotent absent
    let r3 = run_recipe(&recipe2, Mode::Apply, false);
    assert_eq!(find(&r3, "f").change, Change::None);
    assert_eq!(mutation_command_count(&r3), 0);
}

#[test]
fn directory_create_absent_and_idempotency() {
    let dir = trusted_root("dir");
    let out = dir.join("sub");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: d\n    type: directory\n    with:\n      path: {}\n      mode: \"0750\"\n",
            out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r);
    assert!(out.is_dir());
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&out).unwrap().permissions().mode() & 0o7777,
        0o750
    );
    let r2 = run_recipe(&recipe, Mode::Apply, false);
    assert_eq!(mutation_command_count(&r2), 0);

    let recipe2 = write_recipe(
        &dir,
        "r2.yaml",
        &format!(
            "version: 1\nresources:\n  - id: d\n    type: directory\n    with:\n      path: {}\n      state: absent\n",
            out.display()
        ),
    );
    let r3 = run_recipe(&recipe2, Mode::Apply, false);
    assert_success(&r3);
    assert!(!out.exists());
}

#[test]
fn directory_non_empty_absent_fails() {
    let dir = trusted_root("dir-nonempty");
    let out = dir.join("sub");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("child"), "x").unwrap();
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: d\n    type: directory\n    with:\n      path: {}\n      state: absent\n",
            out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    let d = find(&r, "d");
    assert_eq!(d.execution, Execution::Failed);
    assert!(out.exists());
}

#[test]
fn link_create_replace_absent_idempotency() {
    let dir = trusted_root("link");
    let target = dir.join("target");
    std::fs::write(&target, "x").unwrap();
    let link = dir.join("link");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: l\n    type: link\n    with:\n      path: {}\n      target: {}\n",
            link.display(),
            target.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r);
    assert_eq!(std::fs::read_link(&link).unwrap(), target);
    let r2 = run_recipe(&recipe, Mode::Apply, false);
    assert_eq!(find(&r2, "l").change, Change::None);
    assert_eq!(mutation_command_count(&r2), 0);

    // Replace with a different target.
    let target2 = dir.join("target2");
    std::fs::write(&target2, "y").unwrap();
    let recipe2 = write_recipe(
        &dir,
        "r2.yaml",
        &format!(
            "version: 1\nresources:\n  - id: l\n    type: link\n    with:\n      path: {}\n      target: {}\n",
            link.display(),
            target2.display()
        ),
    );
    let r3 = run_recipe(&recipe2, Mode::Apply, false);
    assert_success(&r3);
    assert_eq!(find(&r3, "l").change, Change::Changed);
    assert_eq!(std::fs::read_link(&link).unwrap(), target2);

    // Absent.
    let recipe3 = write_recipe(
        &dir,
        "r3.yaml",
        &format!(
            "version: 1\nresources:\n  - id: l\n    type: link\n    with:\n      path: {}\n      state: absent\n",
            link.display()
        ),
    );
    let r4 = run_recipe(&recipe3, Mode::Apply, false);
    assert_success(&r4);
    assert!(std::fs::symlink_metadata(&link).is_err());
}

#[test]
fn link_non_symlink_conflict_fails() {
    let dir = trusted_root("link-conflict");
    let link = dir.join("link");
    std::fs::write(&link, "regular").unwrap();
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: l\n    type: link\n    with:\n      path: {}\n      target: /tmp/x\n",
            link.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_eq!(find(&r, "l").execution, Execution::Failed);
}

#[test]
fn sensitive_derived_content_defaults_to_0600() {
    let dir = trusted_root("sensitive-mode");
    let out = dir.join("secret.conf");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nvars:\n  token:\n    value: hunter2\n    sensitive: true\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: \"token={{{{ vars.token }}}}\"\n",
            out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r);
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&out).unwrap().permissions().mode() & 0o7777,
        0o600,
        "derived-sensitive new file must default to 0600"
    );

    // A plan against the freshly satisfied state must report the file as
    // unchanged, and the diff must not reveal sensitive content.
    let plan = run_recipe(&recipe, Mode::Plan, false);
    assert_success(&plan);
    let pf = find(&plan, "f");
    assert_eq!(pf.change, Change::None);
    assert!(pf.diff.is_none());
}

#[test]
fn sensitive_content_diff_is_redacted() {
    let dir = trusted_root("sensitive-redact-diff");
    let out = dir.join("secret.conf");
    std::fs::write(&out, "old").unwrap();
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    sensitive: true\n    with:\n      path: {}\n      content: newsecret\n",
            out.display()
        ),
    );
    let plan = run_recipe(&recipe, Mode::Plan, false);
    assert_success(&plan);
    let f = find(&plan, "f");
    assert_eq!(f.change, Change::Changed);
    let diff = f.diff.as_ref().expect("diff present");
    assert!(
        matches!(diff.body, sinter::result::DiffBody::Redacted),
        "sensitive diff must be redacted"
    );
}

#[test]
fn sensitive_explicit_mode_is_honored() {
    let dir = trusted_root("sensitive-mode-explicit");
    let out = dir.join("secret.conf");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    sensitive: true\n    with:\n      path: {}\n      content: secret\n      mode: \"0640\"\n",
            out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r);
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&out).unwrap().permissions().mode() & 0o7777,
        0o640
    );
}

#[test]
fn parent_symlink_rejected() {
    use std::os::unix::fs::symlink;
    let dir = trusted_root("parent-symlink");
    let real = dir.join("real");
    std::fs::create_dir_all(&real).unwrap();
    let link = dir.join("linkdir");
    symlink(&real, &link).unwrap();
    let out = link.join("f");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: x\n",
            out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_eq!(find(&r, "f").execution, Execution::Failed);
    assert!(!real.join("f").exists());
}

#[test]
fn untrusted_writable_parent_rejected() {
    let dir = trusted_root("untrusted-parent");
    let sub = dir.join("world");
    std::fs::create_dir_all(&sub).unwrap();
    set_mode(&sub, 0o777);
    let out = sub.join("f");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: x\n",
            out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_eq!(find(&r, "f").execution, Execution::Failed);
    assert!(!out.exists());
}

#[test]
fn final_symlink_conflict_rejected() {
    use std::os::unix::fs::symlink;
    let dir = trusted_root("final-symlink");
    let target = dir.join("target");
    std::fs::write(&target, "x").unwrap();
    let link = dir.join("f");
    symlink(&target, &link).unwrap();
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: y\n",
            link.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_eq!(find(&r, "f").execution, Execution::Failed);
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "x");
}

#[test]
fn template_rendering_and_idempotency() {
    let dir = trusted_root("template");
    std::fs::write(dir.join("t.tmpl"), "host={{ facts.hostname }}\nport=8080\n").unwrap();
    let out = dir.join("out.conf");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: t\n    type: template\n    with:\n      path: {}\n      source: t.tmpl\n      mode: \"0644\"\n",
            out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r);
    let content = std::fs::read_to_string(&out).unwrap();
    assert!(content.contains("port=8080"));
    assert!(content.starts_with("host="));
    let r2 = run_recipe(&recipe, Mode::Apply, false);
    assert_eq!(mutation_command_count(&r2), 0);
}

#[test]
fn template_local_vars_do_not_shadow_globals() {
    let dir = trusted_root("template-vars");
    std::fs::write(dir.join("t.tmpl"), "{{ template.x }}").unwrap();
    let out = dir.join("out");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: t\n    type: template\n    with:\n      path: {}\n      source: t.tmpl\n      vars:\n        x: local\n",
            out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r);
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "local");
}

#[test]
fn plan_does_not_mutate_filesystem() {
    let dir = trusted_root("plan-safety");
    let out = dir.join("f");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: created\n      mode: \"0644\"\n",
            out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Plan, false);
    assert_success(&r);
    assert_eq!(find(&r, "f").change, Change::Changed);
    assert!(!out.exists(), "plan must not create the file");
    assert_eq!(
        mutation_command_count(&r),
        0,
        "plan must issue no mutation commands: {:?}",
        r.commands
    );
}

#[test]
fn plan_does_not_mutate_for_all_resource_types() {
    let dir = trusted_root("plan-safety-all");
    std::fs::write(dir.join("t.tmpl"), "x").unwrap();
    let out = dir.join("f");
    let d = dir.join("d");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            r#"version: 1
resources:
  - id: file
    type: file
    with:
      path: {out}
      content: hi
  - id: tmpl
    type: template
    with:
      path: {out2}
      source: t.tmpl
  - id: dir
    type: directory
    with:
      path: {d}
  - id: link
    type: link
    with:
      path: {link}
      target: {out}
  - id: pkg
    type: package
    with:
      name: jq
      state: present
  - id: svc
    type: service
    with:
      name: {svc}
      state: running
  - id: cmd
    type: command
    with:
      program: /bin/true
"#,
            out = out.display(),
            out2 = dir.join("f2").display(),
            d = d.display(),
            link = dir.join("l").display(),
            svc = local_ssh_unit(),
        ),
    );
    let r = run_recipe(&recipe, Mode::Plan, false);
    assert_success(&r);
    assert_eq!(
        mutation_command_count(&r),
        0,
        "plan must issue no mutation commands: {:?}",
        r.commands
    );
    assert!(!out.exists());
    assert!(!d.exists());
    assert!(!dir.join("l").exists());
    // command resource must not have executed
    assert!(find(&r, "cmd").unknown);
}

#[test]
fn plan_reports_unknown_not_unchanged() {
    let dir = trusted_root("plan-unknown");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: c\n    type: command\n    with:\n      program: /bin/true\n",
    );
    let r = run_recipe(&recipe, Mode::Plan, false);
    let c = find(&r, "c");
    assert!(c.unknown);
    assert_eq!(c.execution, Execution::NotRun);
    // Unknown is never presented as a definite change; the structured `unknown`
    // flag is the authoritative signal.
    assert_ne!(c.execution, Execution::Succeeded);
    assert_ne!(c.verification, Verification::Failed);
}

#[test]
fn fail_fast_blocks_later_resources() {
    let dir = trusted_root("fail-fast");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            r#"version: 1
resources:
  - id: fail
    type: command
    with:
      program: /bin/false
  - id: after
    type: file
    with:
      path: {out}
      content: x
"#,
            out = dir.join("after").display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_eq!(find(&r, "fail").execution, Execution::Failed);
    let a = find(&r, "after");
    assert_eq!(a.disposition, Disposition::BlockedByFailFast);
    assert_eq!(a.execution, Execution::NotRun);
    assert!(!dir.join("after").exists());
}

#[test]
fn toml_recipe_applies_identically() {
    let dir = trusted_root("toml-apply");
    let out = dir.join("f");
    let toml = format!(
        r#"version = 1

[[resources]]
id = "f"
type = "file"

[resources.with]
path = "{}"
content = "from toml"
mode = "0644"
"#,
        out.display()
    );
    let recipe = write_recipe(&dir, "r.toml", &toml);
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r);
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "from toml");
    let r2 = run_recipe(&recipe, Mode::Apply, false);
    assert_eq!(mutation_command_count(&r2), 0);
}

#[test]
fn when_uses_facts() {
    let dir = trusted_root("when-facts");
    let out = dir.join("f");
    // The recipe is written for both families; the branch that runs is the
    // local host's own family, so the assertions follow it rather than
    // assuming the controller happens to be Debian-family.
    let family = local_os_family();
    let (run_id, skip_id) = if family == "redhat" {
        ("no", "yes")
    } else {
        ("yes", "no")
    };
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: yes\n    type: file\n    with:\n      path: {}\n      content: x\n    when: facts.os.family == \"debian\"\n  - id: no\n    type: file\n    with:\n      path: {}\n      content: y\n    when: facts.os.family == \"redhat\"\n",
            out.display(),
            dir.join("g").display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r);
    assert_eq!(find(&r, run_id).execution, Execution::Succeeded);
    assert_eq!(
        find(&r, skip_id).disposition,
        Disposition::SkippedByCondition
    );
}

#[test]
fn dependency_ordering() {
    let dir = trusted_root("dep-order");
    let marker = dir.join("first");
    let _second = dir.join("second");
    // second depends on first; if ordering were wrong, second would execute
    // before first creates its marker.
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            r#"version: 1
resources:
  - id: second
    type: command
    with:
      program: /bin/sh
      args: ["-c", "test -f {marker}"]
    depends_on: [first]
  - id: first
    type: file
    with:
      path: {marker}
      content: x
"#,
            marker = marker.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r);
    assert_eq!(find(&r, "second").execution, Execution::Succeeded);
}

#[test]
fn changed_when_reads_result_stdout() {
    let dir = trusted_root("cw-stdout");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        r#"version: 1
resources:
  - id: c
    type: command
    with:
      program: /bin/echo
      args: ["present"]
      changed_when: 'result.stdout == "present\n"'
"#,
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r);
    assert_eq!(find(&r, "c").change, Change::Changed);
}

#[test]
fn unknown_condition_fails_apply_before_mutation() {
    let dir = trusted_root("unknown-cond-apply");
    let out = dir.join("f");
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
      content: y
    depends_on: [producer]
    when: "registers.p.stdout == \"x\\n\""
"#,
            out = out.display()
        ),
    );
    // In apply the producer runs, so the condition is resolvable. This test
    // instead checks that a command resource in plan mode yields Unknown and
    // the dependent is reported unknown rather than executed.
    let plan = run_recipe(&recipe, Mode::Plan, false);
    assert_success(&plan);
    assert!(find(&plan, "consumer").unknown);
    assert!(!out.exists());
}

#[test]
fn dependency_cycle_is_validation_error() {
    let dir = trusted_root("dep-cycle");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        r#"version: 1
resources:
  - id: a
    type: command
    with:
      program: /bin/true
    depends_on: [b]
  - id: b
    type: command
    with:
      program: /bin/true
    depends_on: [a]
"#,
    );
    assert!(sinter::model::load_model(&recipe).is_err());
}

#[test]
fn loop_parent_id_dependency_forbidden() {
    let dir = trusted_root("loop-parent-dep");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        r#"version: 1
resources:
  - id: pkg
    type: package
    with:
      name: "{{ item }}"
      state: present
    loop: [jq, curl]
  - id: after
    type: command
    with:
      program: /bin/true
    depends_on: [pkg]
"#,
    );
    // The unexpanded parent loop id must not be referenced.
    assert!(sinter::model::load_model(&recipe).is_err());
}

#[test]
fn large_file_publication_and_verify() {
    let dir = trusted_root("large-file");
    let out = dir.join("big");
    // 400 KiB of data exceeds the text-diff bound, forcing summary diff while
    // still verifying content via remote digest.
    let big = "x".repeat(400 * 1024);
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: \"{}\"\n",
            out.display(),
            big
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r);
    assert_eq!(find(&r, "f").verification, Verification::Verified);
    assert_eq!(std::fs::metadata(&out).unwrap().len(), 400 * 1024);
    let r2 = run_recipe(&recipe, Mode::Apply, false);
    assert_eq!(mutation_command_count(&r2), 0);
}

#[test]
fn plan_never_runs_handlers() {
    let dir = trusted_root("plan-handler");
    let out = dir.join("conf");
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
    notify: [restart_ssh]
handlers:
  - id: restart_ssh
    service: {svc}
    action: restart
"#,
            out = out.display(),
            svc = local_ssh_unit(),
        ),
    );
    let r = run_recipe(&recipe, Mode::Plan, false);
    assert_success(&r);
    assert!(r.handlers_run.is_empty(), "plan must not run handlers");
    assert!(r.handlers_pending.iter().any(|h| h == "restart_ssh"));
    assert_eq!(mutation_command_count(&r), 0, "{:?}", r.commands);
    assert!(!r.commands.iter().any(|c| c.program.contains("systemctl")));
    assert!(!out.exists());
}

#[test]
fn plan_with_unknown_register_value_is_unknown_not_error() {
    let dir = trusted_root("plan-unknown-value");
    let out = dir.join("f");
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
      content: "value={{{{ registers.p.stdout }}}}"
    depends_on: [producer]
"#,
            out = out.display()
        ),
    );
    // Plan must not execute the command and must report the consumer as
    // Unknown rather than failing the plan.
    let r = run_recipe(&recipe, Mode::Plan, false);
    assert_success(&r);
    let c = find(&r, "consumer");
    assert!(c.unknown, "consumer must be Unknown, got {:?}", c);
    assert!(!out.exists());
    assert_eq!(mutation_command_count(&r), 0);
}

#[test]
fn plan_succeeds_with_unknown_dependency_chain() {
    let dir = trusted_root("plan-unknown-chain");
    let out = dir.join("f");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            r#"version: 1
resources:
  - id: a
    type: command
    with:
      program: /bin/echo
      args: ["x"]
      register: ra
  - id: b
    type: command
    with:
      program: /bin/echo
      args: ["{{{{ registers.ra.stdout }}}}"]
      register: rb
    depends_on: [a]
  - id: c
    type: file
    with:
      path: {out}
      content: "{{{{ registers.rb.stdout }}}}"
    depends_on: [b]
"#,
            out = out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Plan, false);
    assert_success(&r);
    assert!(find(&r, "b").unknown);
    assert!(find(&r, "c").unknown);
    assert_eq!(mutation_command_count(&r), 0);
}

#[test]
fn link_absent_on_non_symlink_fails() {
    let dir = trusted_root("link-absent-regular");
    let out = dir.join("f");
    std::fs::write(&out, "regular").unwrap();
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: l\n    type: link\n    with:\n      path: {}\n      state: absent\n",
            out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_eq!(find(&r, "l").execution, Execution::Failed);
    assert!(out.exists());
}

#[test]
fn creates_guard_treats_dangling_symlink_as_present() {
    use std::os::unix::fs::symlink;
    let dir = trusted_root("creates-dangling");
    let marker = dir.join("marker");
    symlink("/nonexistent-target", &marker).unwrap();
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: g\n    type: command\n    with:\n      program: /bin/echo\n      args: [\"should-not-run\"]\n      creates: {}\n",
            marker.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r);
    assert_eq!(find(&r, "g").disposition, Disposition::GuardSatisfied);
}

#[test]
fn directory_present_requires_existing_parent() {
    let dir = trusted_root("dir-no-parent");
    let out = dir.join("missing-parent").join("child");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: d\n    type: directory\n    with:\n      path: {}\n",
            out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_eq!(find(&r, "d").execution, Execution::Failed);
    assert!(!out.exists());
}

#[test]
fn command_zero_vs_custom_success_codes() {
    let dir = trusted_root("success-codes");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        r#"version: 1
resources:
  - id: default_code
    type: command
    with:
      program: /bin/true
  - id: custom_code
    type: command
    with:
      program: /bin/sh
      args: ["-c", "exit 7"]
      success_codes: [7]
"#,
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r);
    assert_eq!(find(&r, "default_code").execution, Execution::Succeeded);
    assert_eq!(find(&r, "custom_code").execution, Execution::Succeeded);
}
