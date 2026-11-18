//! v1.14.1 BK-PARENT-ABSENT: a `backup.paths` entry whose parent directory, or
//! a directory above it, does not exist yet is recorded as `absent`, so that the
//! resources creating those directories run; every refusal of the parent trust
//! walk (DESIGN §23) that is not a plain missing directory still stops apply
//! before any resource runs. Scripted filesystem (FakeTarget), both parent
//! walks: the batched one (no `getfacl`, the default of the fake target) and
//! the sequential one (`getfacl` present).
#![cfg(unix)]

use sinter::engine::AggregateStatus;
use sinter::engine::{Engine, Mode, RunOptions, RunReport, TargetSpec};
use sinter::error::SinterError;
use sinter::executor::FakeTarget;
use sinter::model::load_model;

const D1: &str = "/etc/example";
const D2: &str = "/etc/example/app";
const F: &str = "/etc/example/app/config.conf";
const STORE_COPY: &str = "/var/lib/sinter/backups/run/etc/example/app/config.conf";

fn target(sequential: bool) -> FakeTarget {
    let mut t = FakeTarget::ubuntu2404().with_fake_fs();
    if sequential {
        t = t.with_executable("/usr/bin/getfacl");
    }
    let fs = t.fs.as_mut().unwrap();
    fs.mkdir_node("/var", 0o755, 0, 0);
    fs.mkdir_node("/var/lib", 0o755, 0, 0);
    t
}

fn run(
    mode: Mode,
    yaml: &str,
    t: FakeTarget,
    sudo: bool,
    fault: Option<&str>,
) -> Result<RunReport, SinterError> {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("r.yaml");
    std::fs::write(&p, yaml).unwrap();
    Engine::new(
        load_model(&p)?,
        RunOptions {
            mode,
            sudo,
            target: TargetSpec { ssh: None },
            verbose: false,
            fault: fault.map(str::to_string),
            fake_target: Some(t),
        },
    )
    .unwrap()
    .with_backup_run_id("run".to_string())
    .run()
}

/// backup of F; directory resources for the missing levels (`dirs`), then the file.
fn recipe(dirs: &[&str]) -> String {
    let mut s = format!("version: 1\nbackup:\n  paths: [{F}]\nresources:\n");
    let mut prev: Option<String> = None;
    for (i, d) in dirs.iter().enumerate() {
        let id = format!("dir{i}");
        s.push_str(&format!("  - id: {id}\n    type: directory\n"));
        if let Some(p) = &prev {
            s.push_str(&format!("    depends_on: [{p}]\n"));
        }
        s.push_str(&format!("    with: {{ path: {d} }}\n"));
        prev = Some(id);
    }
    s.push_str("  - id: conf\n    type: file\n");
    if let Some(p) = &prev {
        s.push_str(&format!("    depends_on: [{p}]\n"));
    }
    s.push_str(&format!(
        "    with:\n      path: {F}\n      content: \"a=1\\n\"\n"
    ));
    s
}

fn assert_absent_then_created(r: Result<RunReport, SinterError>, case: &str) {
    let rep = r.unwrap_or_else(|e| panic!("{case}: apply failed: {}", e.message));
    assert_eq!(rep.status, AggregateStatus::Success, "{case}");
    let b = rep.backup.as_ref().expect("backup report");
    assert_eq!(b.entries.len(), 1, "{case}");
    assert_eq!(b.entries[0].status.label(), "absent", "{case}");
    assert!(b.entries[0].destination.is_none(), "{case}");
    let fs = rep.fake_fs.as_ref().unwrap();
    assert_eq!(
        fs.file_bytes(F).as_deref(),
        Some(&b"a=1\n"[..]),
        "{case}: the file resource ran"
    );
    assert!(
        fs.file_bytes(STORE_COPY).is_none(),
        "{case}: nothing copied"
    );
    assert!(
        !fs.nodes.contains_key("/var/lib/sinter/backups/run/etc"),
        "{case}: no directory created in the store for an absent path"
    );
}

fn assert_backup_refused(r: Result<RunReport, SinterError>, case: &str, want: &str) {
    let e = match r {
        Ok(rep) => panic!("{case}: apply succeeded with status {:?}", rep.status),
        Err(e) => e,
    };
    assert!(
        e.message
            .contains("backup failed; no resource was executed"),
        "{case}: {}",
        e.message
    );
    assert!(
        e.message.contains(want),
        "{case}: wanted [{want}] in: {}",
        e.message
    );
    assert_eq!(e.kind.exit_code(), 5, "{case}");
}

#[test]
fn missing_parent_is_absent_and_the_directory_resource_runs_both_walks() {
    for seq in [false, true] {
        assert_absent_then_created(
            run(Mode::Apply, &recipe(&[D1, D2]), target(seq), true, None),
            &format!("two missing levels, sequential={seq}"),
        );
        let mut t = target(seq);
        t.fs.as_mut().unwrap().mkdir_node("/etc", 0o755, 0, 0);
        t.fs.as_mut().unwrap().mkdir_node(D1, 0o755, 0, 0);
        assert_absent_then_created(
            run(Mode::Apply, &recipe(&[D2]), t, true, None),
            &format!("parent missing, sequential={seq}"),
        );
    }
}

#[test]
fn missing_parent_without_sudo_is_absent_too() {
    // A non-root invocation in its own home (the fake target's home is
    // /var/empty/fake, uid 1000): the backup store and the new directory are
    // both below it.
    let mut t = target(false);
    let fs = t.fs.as_mut().unwrap();
    fs.mkdir_node("/var/empty", 0o755, 0, 0);
    fs.mkdir_node("/var/empty/fake", 0o755, 1000, 1000);
    let yaml = "version: 1\nbackup:\n  paths: [/var/empty/fake/new/sub/app.conf]\nresources:\n  - id: d\n    type: directory\n    with: { path: /var/empty/fake/new }\n  - id: d2\n    type: directory\n    depends_on: [d]\n    with: { path: /var/empty/fake/new/sub }\n  - id: f\n    type: file\n    depends_on: [d2]\n    with: { path: /var/empty/fake/new/sub/app.conf, content: \"x\\n\" }\n";
    let rep = run(Mode::Apply, yaml, t, false, None).unwrap_or_else(|e| panic!("{}", e.message));
    assert_eq!(rep.status, AggregateStatus::Success);
    assert_eq!(
        rep.backup.as_ref().unwrap().entries[0].status.label(),
        "absent"
    );
    assert_eq!(
        rep.fake_fs
            .as_ref()
            .unwrap()
            .file_bytes("/var/empty/fake/new/sub/app.conf")
            .as_deref(),
        Some(&b"x\n"[..])
    );
}

#[test]
fn existing_parent_and_existing_file_keep_their_behaviour() {
    for seq in [false, true] {
        // parent exists, file absent: absent (unchanged)
        let mut t = target(seq);
        for d in ["/etc", D1, D2] {
            t.fs.as_mut().unwrap().mkdir_node(d, 0o755, 0, 0);
        }
        let rep = run(Mode::Apply, &recipe(&[]), t, true, None).unwrap();
        assert_eq!(
            rep.backup.as_ref().unwrap().entries[0].status.label(),
            "absent"
        );
        // file exists: backed up before it is changed (unchanged)
        let mut t = target(seq);
        for d in ["/etc", D1, D2] {
            t.fs.as_mut().unwrap().mkdir_node(d, 0o755, 0, 0);
        }
        t.fs.as_mut().unwrap().put_file(F, b"old\n", 0o644, 0, 0);
        let rep = run(Mode::Apply, &recipe(&[]), t, true, None).unwrap();
        let e = &rep.backup.as_ref().unwrap().entries[0];
        assert_eq!(e.status.label(), "backed_up", "sequential={seq}");
        let fs = rep.fake_fs.as_ref().unwrap();
        assert_eq!(fs.file_bytes(STORE_COPY).as_deref(), Some(&b"old\n"[..]));
        assert_eq!(fs.file_bytes(F).as_deref(), Some(&b"a=1\n"[..]));
    }
}

#[test]
fn a_symbolic_link_parent_is_still_refused_before_any_resource() {
    for seq in [false, true] {
        for dangling in [false, true] {
            let mut t = target(seq);
            let fs = t.fs.as_mut().unwrap();
            fs.mkdir_node("/etc", 0o755, 0, 0);
            fs.mkdir_node(D1, 0o755, 0, 0);
            if !dangling {
                fs.mkdir_node("/opt", 0o755, 0, 0);
                fs.mkdir_node("/opt/real", 0o755, 0, 0);
            }
            fs.put_symlink(D2, "/opt/real", 0, 0);
            let r = run(Mode::Apply, &recipe(&[]), t, true, None);
            assert_backup_refused(
                r,
                &format!("symlink parent dangling={dangling} sequential={seq}"),
                F,
            );
        }
    }
}

#[test]
fn a_symbolic_link_above_the_missing_directory_is_still_refused() {
    for seq in [false, true] {
        let mut t = target(seq);
        let fs = t.fs.as_mut().unwrap();
        fs.mkdir_node("/etc", 0o755, 0, 0);
        fs.mkdir_node("/opt", 0o755, 0, 0);
        fs.mkdir_node("/opt/real", 0o755, 0, 0);
        fs.put_symlink(D1, "/opt/real", 0, 0); // /etc/example -> /opt/real ; /etc/example/app missing
        assert_backup_refused(
            run(Mode::Apply, &recipe(&[D2]), t, true, None),
            &format!("symlink above missing, sequential={seq}"),
            F,
        );
    }
}

#[test]
fn an_untrusted_ancestor_above_the_missing_directory_is_still_refused() {
    for seq in [false, true] {
        for (mode, uid, label) in [
            (0o777, 0, "world-writable"),
            (0o775, 0, "group-writable"),
            (0o755, 2000, "owned by another account"),
        ] {
            let mut t = target(seq);
            let fs = t.fs.as_mut().unwrap();
            fs.mkdir_node("/etc", 0o755, 0, 0);
            fs.mkdir_node(D1, mode, uid, uid); // D2 missing below it
            let r = run(Mode::Apply, &recipe(&[D2]), t, false, None);
            assert!(r.is_err(), "{label} sequential={seq}: must not succeed");
            let e = r.err().unwrap();
            assert!(
                e.message
                    .contains("backup failed; no resource was executed"),
                "{label} sequential={seq}: {}",
                e.message
            );
        }
    }
}

#[test]
fn an_ancestor_whose_extended_attributes_cannot_be_read_is_still_refused() {
    // The sequential walk fails closed when an ancestor's ACLs cannot be read;
    // the absent decision walks the ancestors above the missing directory the
    // same way, so this stays a refusal.
    let mut t = target(true);
    t.fs.as_mut().unwrap().mkdir_node("/etc", 0o755, 0, 0);
    t.fs.as_mut().unwrap().mkdir_node(D1, 0o755, 0, 0);
    let r = run(
        Mode::Apply,
        &recipe(&[D2]),
        t,
        true,
        Some("uninspectable_parent"),
    );
    assert!(r.is_err(), "must not succeed");
    assert!(r
        .err()
        .unwrap()
        .message
        .contains("backup failed; no resource was executed"));
}

#[test]
fn a_regular_file_where_a_directory_is_expected_is_still_refused() {
    for seq in [false, true] {
        let mut t = target(seq);
        let fs = t.fs.as_mut().unwrap();
        fs.mkdir_node("/etc", 0o755, 0, 0);
        fs.put_file(D1, b"x", 0o644, 0, 0);
        assert_backup_refused(
            run(Mode::Apply, &recipe(&[]), t, true, None),
            &format!("file in the way, sequential={seq}"),
            F,
        );
    }
}

#[test]
fn plan_and_apply_agree_on_the_missing_parent() {
    for seq in [false, true] {
        let rep = run(Mode::Plan, &recipe(&[D1, D2]), target(seq), true, None).unwrap();
        assert_eq!(
            rep.status,
            AggregateStatus::Success,
            "plan, sequential={seq}"
        );
        assert_eq!(
            rep.backup.as_ref().unwrap().entries[0].status.label(),
            "planned"
        );
        let rep = run(Mode::Apply, &recipe(&[D1, D2]), target(seq), true, None).unwrap();
        assert_eq!(rep.status, AggregateStatus::Success, "sequential={seq}");
    }
}

#[test]
fn a_backup_refusal_still_runs_no_resource() {
    // Two paths: the first missing (absent), the second below a symlink: the
    // whole backup fails and the directory and file resources never run.
    let mut t = target(false);
    let fs = t.fs.as_mut().unwrap();
    fs.mkdir_node("/etc", 0o755, 0, 0);
    fs.mkdir_node("/opt", 0o755, 0, 0);
    fs.mkdir_node("/opt/real", 0o755, 0, 0);
    fs.put_symlink("/etc/linked", "/opt/real", 0, 0);
    let yaml = format!("version: 1\nbackup:\n  paths: [{F}, /etc/linked/x.conf]\nresources:\n  - id: d1\n    type: directory\n    with: {{ path: {D1} }}\n");
    let e = run(Mode::Apply, &yaml, t, true, None)
        .err()
        .expect("must fail");
    assert!(
        e.message
            .contains("backup failed; no resource was executed"),
        "{}",
        e.message
    );
    assert!(e.message.contains("/etc/linked/x.conf"), "{}", e.message);
}
