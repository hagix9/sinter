//! `directory` with `parents: true` (DESIGN §49.3): missing parent
//! directories are created only when the recipe says so, one `mkdir` at a
//! time below parents the path check accepts, with a fixed mode and owner;
//! what exists is never changed, and `file`/`template` never create parents.
mod common;

use common::*;
use sinter::audit::{run_audit, AuditResourceStatus};
use sinter::engine::{AggregateStatus, Engine, Mode, RunOptions, TargetSpec};
use sinter::executor::FakeTarget;
use sinter::model::load_model;
use sinter::result::{Change, Execution};
use std::path::PathBuf;

fn host() -> FakeTarget {
    FakeTarget::rocky9()
        .with_fake_fs()
        .as_root()
        .with_fs_dir("/srv")
        .with_group("app", 1500)
        .with_user("app", 1500, 1500, "/srv/app", "/sbin/nologin")
}

fn recipe(label: &str, body: &str) -> PathBuf {
    write_recipe(&trusted_root(label), "r.yaml", body)
}

const DEEP: &str = r#"
version: 1
resources:
  - id: data
    type: directory
    with:
      path: /srv/app/var/data
      owner: app
      group: app
      mode: "0750"
      parents: true
"#;

fn node(fs: &sinter::fakesys::FakeFs, path: &str) -> (u32, u32, u32) {
    let n = fs
        .nodes
        .get(path)
        .unwrap_or_else(|| panic!("{path} does not exist"));
    (n.mode & 0o7777, n.uid, n.gid)
}

#[test]
fn plan_names_the_parents_apply_will_create_and_changes_nothing() {
    let rep = run_recipe_fake(&recipe("dp-plan", DEEP), Mode::Plan, true, host());
    assert_eq!(rep.status, AggregateStatus::Success);
    let r = find(&rep, "data");
    assert_eq!(r.change, Change::Changed);
    assert!(!r.unknown);
    let notes = r.notes.join("\n");
    assert!(
        notes.contains("/srv/app, /srv/app/var") && notes.contains("mode 0755"),
        "{notes}"
    );
    let fs = rep.fake_fs.as_ref().unwrap();
    assert!(!fs.nodes.contains_key("/srv/app"));
    assert!(rep.commands.iter().all(|c| c.program != "/bin/mkdir"));
}

#[test]
fn apply_creates_each_missing_parent_as_root_0755_and_the_directory_as_declared() {
    let rep = run_recipe_fake(&recipe("dp-apply", DEEP), Mode::Apply, true, host());
    assert_eq!(rep.status, AggregateStatus::Success);
    let fs = rep.fake_fs.as_ref().unwrap();
    assert_eq!(node(fs, "/srv/app"), (0o755, 0, 0));
    assert_eq!(node(fs, "/srv/app/var"), (0o755, 0, 0));
    assert_eq!(node(fs, "/srv/app/var/data"), (0o750, 1500, 1500));
    // One plain mkdir per directory: never `mkdir -p`.
    let mkdirs: Vec<&Vec<String>> = rep
        .commands
        .iter()
        .filter(|c| c.program == "/bin/mkdir")
        .map(|c| &c.args)
        .collect();
    assert_eq!(mkdirs.len(), 3, "{mkdirs:?}");
    assert!(mkdirs.iter().all(|a| !a.iter().any(|x| x == "-p")));
}

#[test]
fn an_existing_parent_is_never_changed_and_a_second_apply_changes_nothing() {
    let mut t = host();
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/srv/app", 0o700, 1500, 1500);
    let p = recipe("dp-existing", DEEP);
    let rep = run_recipe_fake(&p, Mode::Apply, true, t);
    assert_eq!(rep.status, AggregateStatus::Success);
    let fs = rep.fake_fs.clone().unwrap();
    // The existing parent keeps its mode and owner.
    assert_eq!(node(&fs, "/srv/app"), (0o700, 1500, 1500));
    assert_eq!(node(&fs, "/srv/app/var/data"), (0o750, 1500, 1500));

    let mut again = host();
    again.fs = Some(fs.clone());
    let rep2 = run_recipe_fake(&p, Mode::Apply, true, again);
    assert_eq!(rep2.status, AggregateStatus::Success);
    assert_eq!(find(&rep2, "data").change, Change::None);
    assert!(rep2.commands.iter().all(|c| c.program != "/bin/mkdir"));
    let after = rep2.fake_fs.as_ref().unwrap();
    for path in ["/srv/app", "/srv/app/var", "/srv/app/var/data"] {
        assert_eq!(node(after, path), node(&fs, path), "{path}");
    }
    assert_eq!(after.nodes.len(), fs.nodes.len());
}

#[test]
fn without_parents_a_missing_parent_is_refused_and_the_message_names_the_option() {
    let body = DEEP.replace("      parents: true\n", "");
    let p = recipe("dp-off", &body);
    let e = match try_run_recipe_fake(&p, Mode::Plan, true, host()) {
        Err(e) => e.message,
        Ok(r) => find(&r, "data").reason.clone().unwrap_or_default(),
    };
    assert!(e.contains("missing") && e.contains("parents: true"), "{e}");
    let off = DEEP.replace("parents: true", "parents: false");
    assert!(try_run_recipe_fake(&recipe("dp-false", &off), Mode::Plan, true, host()).is_err());
}

#[test]
fn parents_must_be_a_literal_boolean() {
    for bad in ["\"yes\"", "\"{{ vars.p }}\"", "1"] {
        let body = DEEP.replace("parents: true", &format!("parents: {bad}"));
        let e = load_model(&recipe("dp-bad", &body)).unwrap_err();
        assert!(
            e.message.contains("parents must be true or false"),
            "{}",
            e.message
        );
    }
}

#[test]
fn a_file_never_creates_its_parent() {
    let body = r#"
version: 1
resources:
  - id: conf
    type: file
    with: { path: /srv/app/etc/app.conf, content: "k=v\n" }
"#;
    let p = recipe("dp-file", body);
    assert!(try_run_recipe_fake(&p, Mode::Plan, true, host()).is_err());
    let rep = try_run_recipe_fake(&p, Mode::Apply, true, host());
    match rep {
        Err(_) => {}
        Ok(r) => {
            assert_ne!(r.status, AggregateStatus::Success);
            assert!(!r.fake_fs.as_ref().unwrap().nodes.contains_key("/srv/app"));
        }
    }
}

#[test]
fn a_later_file_below_a_created_parent_is_planned_and_applied() {
    let body = format!(
        "{DEEP}  - id: conf\n    type: file\n    depends_on: [data]\n    with: {{ path: /srv/app/var/app.conf, content: \"k=v\\n\" }}\n"
    );
    let p = recipe("dp-later", &body);
    let plan = run_recipe_fake(&p, Mode::Plan, true, host());
    assert_eq!(plan.status, AggregateStatus::Success);
    assert_eq!(find(&plan, "conf").change, Change::Changed);
    let apply = run_recipe_fake(&p, Mode::Apply, true, host());
    assert_eq!(apply.status, AggregateStatus::Success);
    assert!(apply
        .fake_fs
        .as_ref()
        .unwrap()
        .file_bytes("/srv/app/var/app.conf")
        .is_some());
}

#[test]
fn a_symlink_or_a_file_in_the_parent_chain_is_refused_and_nothing_is_created_below_it() {
    for kind in ["symlink", "file"] {
        let mut t = host();
        {
            let fs = t.fs.as_mut().unwrap();
            fs.mkdir_node("/srv/elsewhere", 0o755, 0, 0);
            if kind == "symlink" {
                fs.put_symlink("/srv/app", "/srv/elsewhere", 0, 0);
            } else {
                fs.put_file("/srv/app", b"x", 0o644, 0, 0);
            }
        }
        let p = recipe("dp-chain", DEEP);
        assert!(
            try_run_recipe_fake(&p, Mode::Plan, true, t.clone()).is_err(),
            "{kind}: plan"
        );
        let nodes_after = match try_run_recipe_fake(&p, Mode::Apply, true, t) {
            Err(_) => None,
            Ok(r) => {
                assert_ne!(r.status, AggregateStatus::Success, "{kind}");
                assert_eq!(find(&r, "data").change, Change::None, "{kind}");
                r.fake_fs.map(|f| f.nodes)
            }
        };
        if let Some(n) = nodes_after {
            assert!(!n.contains_key("/srv/elsewhere/var"), "{kind}");
            assert!(!n.contains_key("/srv/app/var"), "{kind}");
        }
    }
}

#[test]
fn a_group_writable_parent_is_refused_before_anything_is_created() {
    let mut t = host();
    t.fs.as_mut().unwrap().mkdir_node("/srv/app", 0o777, 0, 0);
    let p = recipe("dp-unsafe", DEEP);
    assert!(try_run_recipe_fake(&p, Mode::Plan, true, t.clone()).is_err());
    match try_run_recipe_fake(&p, Mode::Apply, true, t) {
        Err(_) => {}
        Ok(r) => {
            assert_ne!(r.status, AggregateStatus::Success);
            assert!(!r
                .fake_fs
                .as_ref()
                .unwrap()
                .nodes
                .contains_key("/srv/app/var"));
        }
    }
}

#[test]
fn a_failure_after_a_parent_was_created_is_a_failure_that_reports_the_change() {
    // The declared owner does not exist: the parents are made, the
    // directory is not, and the result is neither success nor "no change".
    let p = recipe("dp-partial", DEEP);
    let mut t = host();
    // A regular file where the directory itself should go, below missing
    // parents, cannot exist; instead make the last mkdir fail: the leaf's
    // parent chain becomes unsafe after the first parent is created.
    t.fs.as_mut().unwrap().mkdir_node("/srv/app", 0o755, 0, 0);
    t.fs.as_mut()
        .unwrap()
        .put_file("/srv/app/var", b"x", 0o644, 0, 0);
    match try_run_recipe_fake(&p, Mode::Apply, true, t) {
        Err(e) => assert!(e.message.contains("/srv/app/var"), "{}", e.message),
        Ok(r) => {
            assert_ne!(r.status, AggregateStatus::Success);
            assert_ne!(find(&r, "data").execution, Execution::Succeeded);
        }
    }
}

#[test]
fn audit_reports_the_missing_directory_as_drift_and_creates_nothing() {
    let p = recipe("dp-audit", DEEP);
    let opts = RunOptions {
        mode: Mode::Plan,
        sudo: true,
        target: TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(host()),
    };
    let engine = Engine::new(load_model(&p).unwrap(), opts).unwrap();
    let rep = run_audit(engine).unwrap();
    assert_eq!(rep.resources[0].status, AuditResourceStatus::Drift);
    assert!(rep.commands.iter().all(|c| c.program != "/bin/mkdir"));
}

#[test]
fn below_a_sticky_shared_directory_plan_and_apply_agree() {
    // /tmp is 1777: the first missing parent is created there by root, and
    // the declared directory below it gets its declared owner. Plan judges
    // the directory apply creates first, not the declared one against /tmp.
    let body = DEEP.replace("/srv/app/var/data", "/tmp/x/y");
    let p = recipe("dp-sticky", &body);
    let t = || {
        let mut t = host();
        t.fs.as_mut().unwrap().mkdir_node("/tmp", 0o1777, 0, 0);
        t
    };
    let plan = run_recipe_fake(&p, Mode::Plan, true, t());
    assert_eq!(plan.status, AggregateStatus::Success);
    let apply = run_recipe_fake(&p, Mode::Apply, true, t());
    assert_eq!(apply.status, AggregateStatus::Success);
    let fs = apply.fake_fs.as_ref().unwrap();
    assert_eq!(node(fs, "/tmp/x"), (0o755, 0, 0));
    assert_eq!(node(fs, "/tmp/x/y"), (0o750, 1500, 1500));
}

#[test]
fn an_existing_parent_is_not_judged_differently_because_parents_is_set() {
    // The parent exists: `parents: true` changes nothing about how the path
    // is checked, with or without the option.
    for parents in ["", "      parents: true\n"] {
        let body = format!(
            "version: 1\nresources:\n  - id: y\n    type: directory\n    with:\n      path: /srv/app/y\n      owner: app\n{parents}"
        );
        let mut t = host();
        t.fs.as_mut()
            .unwrap()
            .mkdir_node("/srv/app", 0o755, 1500, 1500);
        let p = recipe("dp-same", &body);
        let with = try_run_recipe_fake(&p, Mode::Plan, true, t.clone()).map(|r| r.status);
        let apply = try_run_recipe_fake(&p, Mode::Apply, true, t).map(|r| r.status);
        assert_eq!(
            with.is_ok(),
            apply.is_ok(),
            "plan and apply agree (parents: {})",
            !parents.is_empty()
        );
    }
}

#[test]
fn a_created_parent_is_made_private_first_and_never_with_the_umask_mode() {
    let rep = run_recipe_fake(&recipe("dp-mode", DEEP), Mode::Apply, true, host());
    let parents: Vec<&Vec<String>> = rep
        .commands
        .iter()
        .filter(|c| c.program == "/bin/mkdir" && !c.args.iter().any(|a| a.ends_with("/data")))
        .map(|c| &c.args)
        .collect();
    assert_eq!(parents.len(), 2, "{parents:?}");
    assert!(
        parents
            .iter()
            .all(|a| a.windows(2).any(|w| w == ["-m", "0700"])),
        "{parents:?}"
    );
}

#[test]
fn in_another_accounts_tree_an_owner_it_cannot_have_is_refused_before_anything_is_created() {
    // /home/app belongs to uid 1500; Sinter works there as that account, so
    // an entry owned by another uid is refused. With missing parents, plan
    // and apply must both refuse, and apply must create nothing.
    let t = || {
        let mut t =
            host()
                .with_group("bob", 1600)
                .with_user("bob", 1600, 1600, "/home/bob", "/bin/sh");
        let fs = t.fs.as_mut().unwrap();
        fs.mkdir_node("/home", 0o755, 0, 0);
        fs.mkdir_node("/home/app", 0o755, 1500, 1500);
        t
    };
    let body = DEEP
        .replace("/srv/app/var/data", "/home/app/x/y")
        .replace("owner: app", "owner: bob")
        .replace("group: app", "group: bob");
    let p = recipe("dp-tree-other", &body);
    assert!(
        try_run_recipe_fake(&p, Mode::Plan, true, t()).is_err(),
        "plan refuses"
    );
    match try_run_recipe_fake(&p, Mode::Apply, true, t()) {
        Err(_) => {}
        Ok(r) => {
            assert_ne!(r.status, AggregateStatus::Success);
            assert_eq!(find(&r, "data").change, Change::None);
            assert!(!r
                .fake_fs
                .as_ref()
                .unwrap()
                .nodes
                .contains_key("/home/app/x"));
        }
    }
    // The tree's own account is accepted by both, as before.
    let own = DEEP.replace("/srv/app/var/data", "/home/app/x/y");
    let p = recipe("dp-tree-own", &own);
    assert_eq!(
        run_recipe_fake(&p, Mode::Plan, true, t()).status,
        AggregateStatus::Success
    );
    assert_eq!(
        run_recipe_fake(&p, Mode::Apply, true, t()).status,
        AggregateStatus::Success
    );
}

#[test]
fn an_existing_parent_in_a_shared_directory_is_judged_the_same_with_parents_set() {
    // /tmp (1777) holds /tmp/adir, a directory of uid 1500. A directory below
    // it owned by that account is accepted without `parents`; setting the
    // option must not change that (the parent exists, nothing is missing).
    let t = || {
        let mut t = host();
        let fs = t.fs.as_mut().unwrap();
        fs.mkdir_node("/tmp", 0o1777, 0, 0);
        fs.mkdir_node("/tmp/adir", 0o755, 1500, 1500);
        t
    };
    for parents in ["", "      parents: true\n"] {
        let body = format!(
            "version: 1\nresources:\n  - id: y\n    type: directory\n    with:\n      path: /tmp/adir/y\n      owner: app\n      group: app\n{parents}"
        );
        let p = recipe("dp-shared-acct", &body);
        assert_eq!(
            run_recipe_fake(&p, Mode::Plan, true, t()).status,
            AggregateStatus::Success,
            "plan (parents: {})",
            !parents.is_empty()
        );
        assert_eq!(
            run_recipe_fake(&p, Mode::Apply, true, t()).status,
            AggregateStatus::Success,
            "apply (parents: {})",
            !parents.is_empty()
        );
    }
}
