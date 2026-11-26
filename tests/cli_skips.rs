//! Partial runs on the scripted target with the production engine (DESIGN §40.8):
//! the model `SkipPlan` leaves is what runs, in plan, apply and audit.
#![cfg(unix)]

use sinter::audit::run_audit;
use sinter::engine::{AggregateStatus, Engine, Mode, RunOptions, RunReport, TargetSpec};
use sinter::executor::FakeTarget;
use sinter::model::{load_model, Model};
use sinter::skips::{SkipPlan, SkipRequest, UnitView};

const RECIPE: &str = "version: 1\nresources:\n  - id: base\n    type: file\n    with:\n      path: /etc/app/base\n      content: b\n  - id: conf\n    type: file\n    depends_on: [base]\n    notify: [restart]\n    with:\n      path: /etc/app/conf\n      content: c\n  - id: other\n    type: file\n    notify: [reload]\n    with:\n      path: /etc/app/other\n      content: o\nhandlers:\n  - id: restart\n    service: nginx\n    action: restart\n  - id: reload\n    service: nginx\n    action: reload\n";

fn model() -> (tempfile::TempDir, Model) {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("r.yaml");
    std::fs::write(&p, RECIPE).unwrap();
    let m = load_model(&p).unwrap();
    (d, m)
}

fn target() -> FakeTarget {
    let mut t = FakeTarget::ubuntu2404()
        .with_fake_fs()
        .with_service("nginx", ("loaded", "active", "enabled"))
        .as_root();
    let fs = t.fs.as_mut().unwrap();
    fs.mkdir_node("/etc", 0o755, 0, 0);
    fs.mkdir_node("/etc/app", 0o755, 0, 0);
    t
}

fn opts(mode: Mode) -> RunOptions {
    RunOptions {
        mode,
        sudo: false,
        target: TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(target()),
    }
}

fn plan_for(m: &Model, resources: &[&str]) -> SkipPlan {
    SkipPlan::build(
        &SkipRequest {
            recipes: Vec::new(),
            resources: resources.iter().map(|s| s.to_string()).collect(),
        },
        &[UnitView {
            label: "r",
            unfrozen: false,
            models: vec![m],
        }],
    )
    .unwrap()
}

fn run(mode: Mode, m: Model) -> RunReport {
    Engine::new(m, opts(mode)).unwrap().run().unwrap()
}

fn ids(r: &RunReport) -> Vec<&str> {
    r.resources.iter().map(|x| x.id.as_str()).collect()
}

#[test]
fn an_excluded_resource_is_not_changed_or_reported() {
    let (_d, m) = model();
    let filtered = plan_for(&m, &["other"]).filter(0, m);
    let r = run(Mode::Apply, filtered);
    assert_eq!(r.status, AggregateStatus::Success);
    assert_eq!(ids(&r), ["base", "conf"]);
    let fs = r.fake_fs.as_ref().unwrap();
    assert!(fs.nodes.contains_key("/etc/app/conf"));
    assert!(
        !fs.nodes.contains_key("/etc/app/other"),
        "excluded: untouched"
    );
}

#[test]
fn a_handler_runs_only_for_an_included_resource() {
    let (_d, m) = model();
    let filtered = plan_for(&m, &["other"]).filter(0, m);
    let r = run(Mode::Apply, filtered);
    let run_ids: Vec<&str> = r.handlers_run.iter().map(|h| h.id.as_str()).collect();
    assert_eq!(run_ids, ["restart"]);
    assert!(r.handlers_pending.is_empty());

    let (_d, m) = model();
    let filtered = plan_for(&m, &["conf"]).filter(0, m);
    let r = run(Mode::Apply, filtered);
    let run_ids: Vec<&str> = r.handlers_run.iter().map(|h| h.id.as_str()).collect();
    assert_eq!(
        run_ids,
        ["reload"],
        "the excluded notifier starts no handler"
    );
}

#[test]
fn plan_says_the_same_as_apply() {
    let (_d, m) = model();
    let filtered = plan_for(&m, &["conf"]).filter(0, m);
    let r = run(Mode::Plan, filtered);
    assert_eq!(ids(&r), ["base", "other"]);
    assert_eq!(r.handlers_pending, ["reload"]);
    assert!(!r
        .fake_fs
        .as_ref()
        .unwrap()
        .nodes
        .contains_key("/etc/app/base"));
}

#[test]
fn audit_does_not_observe_what_is_excluded() {
    let (_d, m) = model();
    let filtered = plan_for(&m, &["conf"]).filter(0, m);
    let report = run_audit(Engine::new(filtered, opts(Mode::Plan)).unwrap()).unwrap();
    let doc = sinter::output::audit_report_json(&report).to_string();
    assert!(doc.contains("base") && doc.contains("other"), "{doc}");
    assert!(!doc.contains("/etc/app/conf"), "{doc}");
}

#[test]
fn a_dependency_on_an_excluded_resource_never_reaches_the_engine() {
    let (_d, m) = model();
    let p = plan_for(&m, &["base"]);
    let e = p.refusal().expect("refused");
    assert!(
        e.message.contains("r/conf depends on base"),
        "{}",
        e.message
    );
    // And if it did, the engine would refuse too: a missing dependency is not skipped.
    let broken = p.filter(0, m);
    assert!(Engine::new(broken, opts(Mode::Plan))
        .unwrap()
        .run()
        .is_err());
}

#[test]
fn a_register_consumer_is_covered_by_its_dependency() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("r.yaml");
    std::fs::write(
        &p,
        "version: 1\nresources:\n  - id: probe\n    type: command\n    with:\n      program: /usr/bin/true\n      register: seen\n      creates: /etc/app/probe\n  - id: use\n    type: file\n    depends_on: [probe]\n    when: \"registers.seen.exit_code == 0\"\n    with:\n      path: /etc/app/use\n      content: x\n",
    )
    .unwrap();
    let m = load_model(&p).unwrap();
    assert!(plan_for(&m, &["probe"]).refusal().is_some());
}

// ---------------------------------------------------------------------------
// Declared backups follow what a partial run runs (DESIGN §49.6).
// ---------------------------------------------------------------------------

use sinter::backup::BackupStatus;

/// Three files, each with its own declared backup; `pkg` is not a file.
const BACKUPS: &str = "version: 1\nbackup:\n  paths:\n    - /etc/app/a\n    - /srv/gone/b\n    - /etc/app/dir\nresources:\n  - id: a\n    type: file\n    with: { path: /etc/app/a, content: a }\n  - id: b\n    type: file\n    with: { path: /srv/gone/b, content: b }\n  - id: c\n    type: file\n    with: { path: /etc/app/dir/c, content: c }\n";

fn load(body: &str) -> (tempfile::TempDir, Model) {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("r.yaml");
    std::fs::write(&p, body).unwrap();
    let m = load_model(&p).unwrap();
    (d, m)
}

fn backup_target() -> FakeTarget {
    let mut t = target();
    let fs = t.fs.as_mut().unwrap();
    fs.put_file("/etc/app/a", b"old", 0o644, 0, 0);
    fs.mkdir_node("/etc/app/dir", 0o755, 0, 0);
    fs.mkdir_node("/var", 0o755, 0, 0);
    fs.mkdir_node("/var/lib", 0o755, 0, 0);
    t
}

fn run_on(mode: Mode, m: Model, t: FakeTarget) -> Result<RunReport, sinter::error::SinterError> {
    Engine::new(
        m,
        RunOptions {
            mode,
            sudo: true,
            target: TargetSpec { ssh: None },
            verbose: false,
            fault: None,
            fake_target: Some(t),
        },
    )
    .unwrap()
    .run()
}

fn statuses(r: &RunReport) -> Vec<(String, BackupStatus)> {
    r.backup
        .as_ref()
        .map(|b| {
            b.entries
                .iter()
                .map(|e| (e.path.clone(), e.status))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn without_an_exclusion_every_declared_backup_is_taken_as_before() {
    let (_d, m) = load(BACKUPS);
    let same = plan_for(&m, &[]).filter(0, m.clone());
    assert_eq!(same.backups, m.backups);
    assert!(same.backups_skipped.is_empty());
    // /srv/gone does not exist: an absent path is recorded, not a failure.
    let r = run_on(Mode::Apply, m, backup_target()).unwrap();
    assert_eq!(
        statuses(&r),
        [
            ("/etc/app/a".to_string(), BackupStatus::BackedUp),
            ("/srv/gone/b".to_string(), BackupStatus::Absent),
            ("/etc/app/dir".to_string(), BackupStatus::BackedUp),
        ]
    );
}

#[test]
fn a_backup_only_an_excluded_resource_needs_is_not_taken_in_plan_or_apply() {
    let (_d, m) = load(BACKUPS);
    let partial = plan_for(&m, &["b"]).filter(0, m);
    assert_eq!(partial.backups, ["/etc/app/a", "/etc/app/dir"]);
    assert_eq!(partial.backups_skipped, ["/srv/gone/b"]);
    for mode in [Mode::Plan, Mode::Apply] {
        let r = run_on(mode, partial.clone(), backup_target()).unwrap();
        let st = statuses(&r);
        assert_eq!(st.len(), 3, "{mode:?} {st:?}");
        assert_eq!(
            st[2],
            ("/srv/gone/b".to_string(), BackupStatus::Skipped),
            "{mode:?}"
        );
        assert!(
            st[..2].iter().all(|(_, s)| *s != BackupStatus::Skipped),
            "{mode:?}"
        );
        // Nothing of the skipped backup was observed, prepared or copied.
        assert!(
            r.commands
                .iter()
                .all(|c| !c.args.iter().any(|a| a.contains("/srv/gone"))),
            "{mode:?}"
        );
    }
}

#[test]
fn a_backup_below_or_above_an_included_path_is_kept() {
    let (_d, m) = load(BACKUPS);
    // `c` writes below the backed-up directory /etc/app/dir.
    let partial = plan_for(&m, &["a", "b"]).filter(0, m.clone());
    assert_eq!(partial.backups, ["/etc/app/dir"]);
    // A directory resource above a backed-up file keeps that backup too.
    let (_d2, up) = load(
        "version: 1\nbackup:\n  paths: [/etc/app/dir/c]\nresources:\n  - id: d\n    type: directory\n    with: { path: /etc/app/dir }\n  - id: x\n    type: file\n    with: { path: /etc/app/x, content: x }\n",
    );
    assert_eq!(
        plan_for(&up, &["x"]).filter(0, up.clone()).backups,
        ["/etc/app/dir/c"]
    );
    assert!(plan_for(&up, &["d"]).filter(0, up).backups.is_empty());
}

#[test]
fn a_resource_whose_effect_is_not_one_path_keeps_every_backup() {
    for extra in [
        "  - id: p\n    type: package\n    with: { name: jq, state: present }\n",
        "  - id: p\n    type: command\n    with: { program: /usr/bin/true }\n",
        "  - id: p\n    type: file\n    notify: [h]\n    with: { path: /etc/app/p, content: p }\nhandlers:\n  - id: h\n    service: nginx\n    action: restart\n",
    ] {
        let (_d, m) = load(&format!("{BACKUPS}{extra}"));
        let partial = plan_for(&m, &["a", "b", "c"]).filter(0, m);
        assert_eq!(partial.backups.len(), 3, "{extra}");
        assert!(partial.backups_skipped.is_empty(), "{extra}");
    }
}

#[test]
fn a_backup_declared_for_resources_follows_exactly_those_resources() {
    let body = "version: 1\nbackup:\n  paths:\n    - path: /srv/data\n      resources: [migrate]\n    - /etc/app/a\nresources:\n  - id: migrate\n    type: command\n    with: { program: /usr/bin/true }\n  - id: pkg\n    type: package\n    with: { name: jq, state: present }\n  - id: a\n    type: file\n    with: { path: /etc/app/a, content: a }\n";
    let (_d, m) = load(body);
    // `pkg` could touch anything, but /srv/data is declared for `migrate`.
    let partial = plan_for(&m, &["migrate"]).filter(0, m.clone());
    assert_eq!(partial.backups, ["/etc/app/a"]);
    assert_eq!(partial.backups_skipped, ["/srv/data"]);
    // With `migrate` included it stays, whatever else is excluded.
    // `migrate` is a command: what it changes is not known, so the
    // undeclared-for backup of /etc/app/a stays as well.
    let partial = plan_for(&m, &["pkg", "a"]).filter(0, m);
    assert_eq!(partial.backups, ["/srv/data", "/etc/app/a"]);
    assert!(partial.backups_skipped.is_empty());
}

#[test]
fn a_backup_for_resources_is_checked_when_the_recipe_is_loaded() {
    for (entry, want) in [
        (
            "{ path: /srv/data, resources: [nope] }",
            "not a resource of this recipe",
        ),
        (
            "{ path: /srv/data, resources: [] }",
            "non-empty list of resource ids",
        ),
        (
            "{ path: /srv/data, resources: a }",
            "non-empty list of resource ids",
        ),
        (
            "{ path: /srv/data, resources: [a, a] }",
            "non-empty list of resource ids",
        ),
        (
            "{ path: /srv/data, resources: [\"{{ vars.x }}\"] }",
            "non-empty list of resource ids",
        ),
    ] {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("r.yaml");
        std::fs::write(
            &p,
            format!("version: 1\nbackup:\n  paths:\n    - {entry}\nresources:\n  - id: a\n    type: file\n    with: {{ path: /etc/app/a, content: a }}\n"),
        )
        .unwrap();
        let e = load_model(&p).unwrap_err();
        assert!(e.message.contains(want), "{entry}: {}", e.message);
    }
}

#[test]
fn a_skipped_backup_that_could_not_be_taken_does_not_stop_what_runs() {
    // The backup of /srv/locked/b cannot be taken: its parent is writable by
    // others, which the backup stage refuses. In a full apply that stops the
    // run before any resource; with `b` excluded the rest applies.
    let body = BACKUPS.replace("/srv/gone/b", "/srv/locked/b");
    let unsafe_target = || {
        let mut t = backup_target();
        let fs = t.fs.as_mut().unwrap();
        fs.mkdir_node("/srv", 0o755, 0, 0);
        fs.mkdir_node("/srv/locked", 0o777, 0, 0);
        fs.put_file("/srv/locked/b", b"old", 0o644, 0, 0);
        t
    };
    let (_d, m) = load(&body);
    let full = run_on(Mode::Apply, m.clone(), unsafe_target());
    assert!(
        match &full {
            Err(_) => true,
            Ok(r) => r.status != AggregateStatus::Success,
        },
        "a needed backup that cannot be taken still stops the run"
    );
    let partial = plan_for(&m, &["b"]).filter(0, m);
    let r = run_on(Mode::Apply, partial, unsafe_target()).unwrap();
    assert_eq!(r.status, AggregateStatus::Success);
    let fs = r.fake_fs.as_ref().unwrap();
    assert_eq!(fs.file_bytes("/etc/app/a").unwrap(), b"a");
    assert_eq!(fs.file_bytes("/srv/locked/b").unwrap(), b"old");
}

#[test]
fn when_no_backup_is_needed_no_store_is_created_or_checked() {
    let (_d, m) = load(BACKUPS);
    // Only an unrelated file runs.
    let body = format!(
        "{BACKUPS}  - id: z\n    type: file\n    with: {{ path: /etc/app/z, content: z }}\n"
    );
    let (_d2, m2) = load(&body);
    drop(m);
    let partial = plan_for(&m2, &["a", "b", "c"]).filter(0, m2);
    assert!(partial.backups.is_empty());
    assert_eq!(partial.backups_skipped.len(), 3);
    let r = run_on(Mode::Apply, partial, backup_target()).unwrap();
    assert_eq!(r.status, AggregateStatus::Success);
    assert!(statuses(&r)
        .iter()
        .all(|(_, s)| *s == BackupStatus::Skipped));
    let fs = r.fake_fs.as_ref().unwrap();
    assert!(!fs.nodes.contains_key("/var/lib/sinter"));
    assert!(r.backup.as_ref().unwrap().run_id.is_none());
}

#[test]
fn audit_takes_no_backup_and_reports_none() {
    let (_d, m) = load(BACKUPS);
    let partial = plan_for(&m, &["b"]).filter(0, m);
    let rep = run_audit(
        Engine::new(
            partial,
            RunOptions {
                mode: Mode::Plan,
                sudo: true,
                target: TargetSpec { ssh: None },
                verbose: false,
                fault: None,
                fake_target: Some(backup_target()),
            },
        )
        .unwrap(),
    )
    .unwrap();
    assert!(rep.commands.iter().all(|c| c.program != "/bin/cp"));
}
