//! The store a recipe names for its backups (DESIGN §40.6): which store wins, what
//! is refused, and that every store is ready before the first copy.
#![cfg(unix)]

use sinter::engine::{AggregateStatus, Engine, Mode, RunOptions, RunReport, TargetSpec};
use sinter::error::{ErrorKind, SinterError};
use sinter::executor::FakeTarget;
use sinter::model::load_model;

const CANARY: &str = "BACKUP_CANARY_DO_NOT_PRINT";

fn base() -> FakeTarget {
    let mut t = FakeTarget::ubuntu2404()
        .with_fake_fs()
        .with_group("postgres", 26)
        .with_user("postgres", 26, 26, "/var/lib/pgsql", "/bin/bash")
        .as_root();
    let fs = t.fs.as_mut().unwrap();
    for (path, mode, uid) in [
        ("/var", 0o755, 0),
        ("/var/backups", 0o755, 0),
        ("/var/lib", 0o755, 0),
        ("/var/lib/pgsql", 0o700, 26),
        ("/etc", 0o755, 0),
        ("/etc/app", 0o755, 0),
        ("/tmp", 0o1777, 0),
        ("/root", 0o700, 0),
    ] {
        fs.mkdir_node(path, mode, uid, uid);
    }
    fs.put_file("/etc/app/a", b"a", 0o640, 0, 0);
    fs.put_file("/etc/app/b", b"b", 0o640, 0, 0);
    fs.put_file("/var/lib/pgsql/.pgpass", CANARY.as_bytes(), 0o600, 26, 26);
    t
}

const RESOURCE: &str =
    "resources:\n  - id: f\n    type: file\n    with: { path: /etc/app/new, content: x }\n";

fn run_store(
    mode: Mode,
    backup: &str,
    project: Option<&str>,
    t: FakeTarget,
) -> Result<RunReport, SinterError> {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("r.yaml");
    std::fs::write(&p, format!("version: 1\nbackup:\n{backup}{RESOURCE}")).unwrap();
    Engine::new(
        load_model(&p)?,
        RunOptions {
            mode,
            sudo: false,
            target: TargetSpec { ssh: None },
            verbose: false,
            fault: None,
            fake_target: Some(t),
        },
    )
    .unwrap()
    .with_backup_run_id("run".to_string())
    .with_backup_store(project.map(str::to_string))
    .run()
}

fn apply(backup: &str, project: Option<&str>) -> Result<RunReport, SinterError> {
    run_store(Mode::Apply, backup, project, base())
}

fn dest(r: &RunReport, i: usize) -> &str {
    r.backup.as_ref().unwrap().entries[i]
        .destination
        .as_deref()
        .unwrap()
}

fn refused_statically(backup: &str, says: &str) {
    for mode in [Mode::Plan, Mode::Apply] {
        let e = run_store(mode, backup, None, base())
            .err()
            .unwrap_or_else(|| panic!("{backup} must be refused"));
        assert_eq!(e.kind, ErrorKind::Schema, "{backup}: {}", e.message);
        assert!(e.message.contains(says), "wanted {says:?} in {}", e.message);
    }
}

fn refused_at_run_time(backup: &str, t: FakeTarget, says: &str) {
    for mode in [Mode::Plan, Mode::Apply] {
        let e = match run_store(mode, backup, None, t.clone()) {
            Err(e) => e,
            Ok(r) => panic!("{backup} must be refused: {:?}", r.status),
        };
        assert!(e.message.contains(says), "wanted {says:?} in {}", e.message);
    }
}

#[test]
fn the_string_form_means_what_it_always_meant() {
    let r = apply("  paths: [/etc/app/a]\n", None).unwrap();
    assert_eq!(r.status, AggregateStatus::Success);
    assert_eq!(dest(&r, 0), "/root/.sinter/backups/run/etc/app/a");
    let b = r.backup.as_ref().unwrap();
    assert_eq!(b.directory.as_deref(), Some("/root/.sinter/backups/run"));
    assert_eq!(b.directories, ["/root/.sinter/backups/run"]);
}

#[test]
fn the_nearest_store_wins_and_nothing_overrides_it() {
    let backup = "  directory: /var/backups/common\n  paths:\n    - /etc/app/a\n    - { path: /etc/app/b, directory: /var/backups/own }\n";
    // The project file's store is used only by a path that names none.
    for project in [None, Some("/var/backups/project")] {
        let r = apply(backup, project).unwrap();
        assert_eq!(dest(&r, 0), "/var/backups/common/run/etc/app/a");
        assert_eq!(dest(&r, 1), "/var/backups/own/run/etc/app/b");
    }
    let r = apply(
        "  paths:\n    - /etc/app/a\n    - { path: /etc/app/b, directory: /var/backups/own }\n",
        Some("/var/backups/project"),
    )
    .unwrap();
    assert_eq!(dest(&r, 0), "/var/backups/project/run/etc/app/a");
    assert_eq!(dest(&r, 1), "/var/backups/own/run/etc/app/b");
    let r = apply(
        "  paths:\n    - /etc/app/a\n    - { path: /etc/app/b, directory: /var/backups/own }\n",
        None,
    )
    .unwrap();
    assert_eq!(dest(&r, 0), "/root/.sinter/backups/run/etc/app/a");
    assert_eq!(dest(&r, 1), "/var/backups/own/run/etc/app/b");
}

#[test]
fn every_store_is_private_and_the_report_says_where_each_copy_is() {
    let r = apply(
        "  directory: /var/backups/common\n  paths:\n    - /etc/app/a\n    - { path: /etc/app/b, directory: /var/backups/own }\n",
        None,
    )
    .unwrap();
    assert_eq!(r.status, AggregateStatus::Success);
    let b = r.backup.as_ref().unwrap();
    // Two stores: no one directory to name.
    assert_eq!(b.directory, None);
    assert_eq!(
        b.directories,
        ["/var/backups/common/run", "/var/backups/own/run"]
    );
    assert_eq!(b.entries[1].store.as_deref(), Some("/var/backups/own"));
    let fs = r.fake_fs.as_ref().unwrap();
    for d in [
        "/var/backups/common",
        "/var/backups/common/run",
        "/var/backups/own",
        "/var/backups/own/run",
    ] {
        assert_eq!(fs.nodes[d].mode & 0o777, 0o700, "{d}");
    }
    assert!(!fs.nodes.contains_key("/root/.sinter"), "no default store");
    assert_eq!(fs.nodes["/etc/app/new"].mode & 0o777, 0o644);
}

#[test]
fn plan_says_where_and_makes_nothing() {
    let r = run_store(
        Mode::Plan,
        "  directory: /var/backups/common\n  paths:\n    - /etc/app/a\n    - { path: /etc/app/b, directory: /var/backups/own }\n",
        None,
        base(),
    )
    .unwrap();
    let b = r.backup.as_ref().unwrap();
    assert_eq!(b.entries[0].store.as_deref(), Some("/var/backups/common"));
    assert_eq!(b.entries[1].store.as_deref(), Some("/var/backups/own"));
    assert_eq!(b.entries[0].status.label(), "planned");
    let fs = r.fake_fs.as_ref().unwrap();
    assert!(!fs.nodes.contains_key("/var/backups/common"));
    assert!(!fs.nodes.contains_key("/var/backups/own"));
    // The default store is named too.
    let r = run_store(Mode::Plan, "  paths: [/etc/app/a]\n", None, base()).unwrap();
    assert_eq!(
        r.backup.as_ref().unwrap().entries[0].store.as_deref(),
        Some("/root/.sinter/backups")
    );
}

#[test]
fn audit_does_not_touch_a_store() {
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_symlink("/var/backups/ln", "/etc", 0, 0);
    // A plan would refuse this store; an audit has no business with it.
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("r.yaml");
    std::fs::write(
        &p,
        format!(
            "version: 1\nbackup:\n  directory: /var/backups/ln\n  paths: [/etc/app/a]\n{RESOURCE}"
        ),
    )
    .unwrap();
    let e = Engine::new(
        load_model(&p).unwrap(),
        RunOptions {
            mode: Mode::Plan,
            sudo: false,
            target: TargetSpec { ssh: None },
            verbose: false,
            fault: None,
            fake_target: Some(t),
        },
    )
    .unwrap();
    let r = sinter::audit::run_audit(e);
    assert!(r.is_ok(), "{:?}", r.err().map(|e| e.message));
}

#[test]
fn a_bad_declaration_is_refused_before_anything_runs() {
    for (backup, says) in [
        ("  directory: rel\n  paths: [/etc/app/a]\n", "absolute"),
        (
            "  directory: /a/../b\n  paths: [/etc/app/a]\n",
            "backup.directory",
        ),
        ("  directory: /\n  paths: [/etc/app/a]\n", "root directory"),
        (
            "  directory: \"\"\n  paths: [/etc/app/a]\n",
            "backup.directory",
        ),
        (
            "  directory: 3\n  paths: [/etc/app/a]\n",
            "must be a string",
        ),
        (
            "  directory: \"/var/{{ vars.x }}\"\n  paths: [/etc/app/a]\n",
            "interpolation",
        ),
        (
            "  paths:\n    - { path: /etc/app/a, directory: \"/var/{{ vars.x }}\" }\n",
            "interpolation",
        ),
        (
            "  paths:\n    - { path: /etc/app/a, directory: rel }\n",
            "absolute",
        ),
        (
            "  paths:\n    - { directory: /var/backups/x }\n",
            "path must be a string",
        ),
        (
            "  paths:\n    - { path: /etc/app/a, owner: root }\n",
            "owner",
        ),
        (
            "  paths:\n    - { path: \"/etc/{{ vars.x }}\" }\n",
            "interpolation",
        ),
        ("  paths:\n    - 3\n", "string or a map"),
        ("  directory: /var/backups/x\n", "paths"),
        ("  owner: root\n  paths: [/etc/app/a]\n", "owner"),
    ] {
        refused_statically(backup, says);
    }
}

#[test]
fn a_source_and_any_store_never_overlap() {
    for (backup, says) in [
        // A path's store, the common store, another path's store.
        ("  paths:\n    - { path: /etc/app/a, directory: /etc/app/a/x }\n", "overlaps"),
        ("  paths:\n    - { path: /etc/app, directory: /etc/app/x }\n", "overlaps"),
        ("  directory: /etc/app\n  paths: [/etc/app/a]\n", "overlaps"),
        (
            "  paths:\n    - { path: /etc/app/a, directory: /var/backups/x }\n    - { path: /var/backups/x/f, directory: /var/backups/y }\n",
            "overlaps",
        ),
        // Stores inside one another.
        (
            "  paths:\n    - { path: /etc/app/a, directory: /var/backups/x }\n    - { path: /etc/app/b, directory: /var/backups/x/y }\n",
            "overlap",
        ),
    ] {
        refused_statically(backup, says);
    }
    // A store the declaration cannot see is checked when it is known.
    let e = run_store(
        Mode::Apply,
        "  paths:\n    - /etc/app/a\n    - { path: /etc/app/b, directory: /var/backups/x }\n",
        Some("/var/backups/x/y"),
        base(),
    )
    .err()
    .unwrap();
    assert!(e.message.contains("overlap"), "{}", e.message);
    let e = run_store(
        Mode::Plan,
        "  paths:\n    - /etc/app/a\n    - { path: /etc/app/b, directory: /var/backups/x }\n",
        Some("/etc/app"),
        base(),
    )
    .err()
    .unwrap();
    assert!(e.message.contains("overlap"), "{}", e.message);
}

#[test]
fn a_path_is_declared_once_whichever_store_it_names() {
    refused_statically(
        "  paths:\n    - /etc/app/a\n    - { path: /etc/app/a, directory: /var/backups/x }\n",
        "duplicate",
    );
    // Overlapping paths stay refused even with stores of their own.
    refused_statically(
        "  paths:\n    - { path: /etc/app, directory: /var/backups/x }\n    - { path: /etc/app/a, directory: /var/backups/y }\n",
        "overlap",
    );
}

#[test]
fn an_unsafe_store_is_refused_like_the_default_one() {
    let store = |dir: &str| format!("  directory: {dir}\n  paths: [/etc/app/a]\n");
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_symlink("/var/backups/ln", "/etc", 0, 0);
    refused_at_run_time(&store("/var/backups/ln"), t, "symlink");
    let mut t = base();
    t.fs.as_mut().unwrap().put_symlink("/var/ln", "/etc", 0, 0);
    refused_at_run_time(&store("/var/ln/store"), t, "is a symlink");
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/var/backups/o", 0o700, 26, 26);
    refused_at_run_time(&store("/var/backups/o"), t, "outside the trusted set");
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/var/backups/w", 0o775, 0, 0);
    refused_at_run_time(&store("/var/backups/w"), t, "grants group or other write");
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_file("/var/backups/f", b"x", 0o600, 0, 0);
    refused_at_run_time(&store("/var/backups/f"), t, "not a directory");
    refused_at_run_time(&store("/tmp/store"), base(), "shared directory");
    refused_at_run_time(&store("/var/lib/pgsql/store"), base(), "owned by uid 26");
    refused_at_run_time(&store("/var/backups/a/b"), base(), "parent");
}

#[test]
fn a_store_that_cannot_be_used_stops_the_apply_before_the_first_copy() {
    // The second store is bad: nothing may have been copied into the first.
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .put_symlink("/var/backups/ln", "/etc", 0, 0);
    let e = run_store(
        Mode::Apply,
        "  paths:\n    - { path: /etc/app/a, directory: /var/backups/good }\n    - { path: /etc/app/b, directory: /var/backups/ln }\n",
        None,
        t,
    )
    .err()
    .unwrap();
    assert!(
        e.message.contains("no resource was executed"),
        "{}",
        e.message
    );
    assert!(e.message.contains("/var/backups/good/run"), "{}", e.message);
    let b = e.backup.as_ref().unwrap();
    assert_eq!(b.directories, ["/var/backups/good/run"]);
    assert!(b.entries.iter().all(|x| x.destination.is_none()));
    assert!(b.entries.iter().all(|x| x.status.label() == "not_run"));
}

#[test]
fn a_run_directory_that_exists_is_a_collision_in_any_store() {
    let mut t = base();
    let fs = t.fs.as_mut().unwrap();
    fs.mkdir_node("/var/backups/two", 0o700, 0, 0);
    fs.mkdir_node("/var/backups/two/run", 0o700, 0, 0);
    let e = run_store(
        Mode::Apply,
        "  paths:\n    - { path: /etc/app/a, directory: /var/backups/one }\n    - { path: /etc/app/b, directory: /var/backups/two }\n",
        None,
        t,
    )
    .err()
    .unwrap();
    assert!(e.message.contains("collision"), "{}", e.message);
}

#[test]
fn the_two_stores_may_be_one() {
    let r = apply(
        "  directory: /var/backups/one\n  paths:\n    - /etc/app/a\n    - { path: /etc/app/b, directory: /var/backups/one }\n",
        None,
    )
    .unwrap();
    let b = r.backup.as_ref().unwrap();
    assert_eq!(b.directory.as_deref(), Some("/var/backups/one/run"));
    assert_eq!(b.directories.len(), 1);
}

#[test]
fn a_file_of_another_account_goes_to_the_store_the_recipe_names() {
    let r = apply(
        "  paths:\n    - { path: /var/lib/pgsql/.pgpass, directory: /var/backups/pg }\n",
        None,
    )
    .unwrap();
    assert_eq!(r.status, AggregateStatus::Success);
    let d = dest(&r, 0);
    assert_eq!(d, "/var/backups/pg/run/var/lib/pgsql/.pgpass");
    let fs = r.fake_fs.as_ref().unwrap();
    let copy = &fs.nodes[d];
    assert_eq!(copy.mode & 0o7777, 0o600);
    assert_eq!(copy.uid, 26);
    assert_eq!(fs.nodes["/var/backups/pg/run"].mode & 0o777, 0o700);
    assert_eq!(fs.nodes["/var/backups/pg/run"].uid, 0);
    // What is printed holds paths only.
    let text = format!("{:?}", r.backup);
    assert!(!text.contains(CANARY), "{text}");
}

#[test]
fn a_store_inside_the_account_tree_is_not_a_way_around_it() {
    refused_at_run_time(
        "  paths:\n    - { path: /var/lib/pgsql/.pgpass, directory: /var/lib/pgsql/store }\n",
        base(),
        "outside the trusted set",
    );
    // And no directory of that account can be declared as a source.
    let e = apply(
        "  paths:\n    - { path: /var/lib/pgsql, directory: /var/backups/pg }\n",
        None,
    )
    .err()
    .unwrap();
    assert!(e.message.contains("not backed up"), "{}", e.message);
}

#[test]
fn an_include_keeps_its_own_store() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(
        d.path().join("inc.yaml"),
        "version: 1\nbackup:\n  directory: /var/backups/inc\n  paths: [/etc/app/b]\n",
    )
    .unwrap();
    let p = d.path().join("r.yaml");
    std::fs::write(
        &p,
        format!("version: 1\ninclude: [inc.yaml]\nbackup:\n  directory: /var/backups/top\n  paths: [/etc/app/a]\n{RESOURCE}"),
    )
    .unwrap();
    let m = load_model(&p).unwrap();
    assert_eq!(m.backup_stores["/etc/app/a"], "/var/backups/top");
    assert_eq!(m.backup_stores["/etc/app/b"], "/var/backups/inc");
    // An include does not inherit: a path it declares alone has no store here.
    std::fs::write(
        d.path().join("inc.yaml"),
        "version: 1\nbackup:\n  paths: [/etc/app/b]\n",
    )
    .unwrap();
    let m = load_model(&p).unwrap();
    assert!(!m.backup_stores.contains_key("/etc/app/b"));
    // And the two cannot hold each other's sources.
    std::fs::write(
        d.path().join("inc.yaml"),
        "version: 1\nbackup:\n  directory: /etc/app\n  paths: [/var/backups/x]\n",
    )
    .unwrap();
    let e = load_model(&p).err().unwrap();
    assert!(e.message.contains("overlap"), "{}", e.message);
}
