//! Pre-apply backup (`backup.paths`): schema validation on every platform;
//! target behavior against the local Linux target.

use sinter::model::load_model;

fn recipe(body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("r.yaml");
    std::fs::write(&p, body).unwrap();
    (d, p)
}

#[test]
fn valid_backup_declaration() {
    let (_d, p) =
        recipe("version: 1\nbackup:\n  paths:\n    - /etc/ssh/sshd_config\n    - /etc/nginx\n");
    let m = load_model(&p).unwrap();
    assert_eq!(m.backups, vec!["/etc/ssh/sshd_config", "/etc/nginx"]);
}

#[test]
fn toml_backup_declaration_is_equivalent() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("r.toml");
    std::fs::write(
        &p,
        "version = 1\n[backup]\npaths = [\"/etc/ssh/sshd_config\", \"/etc/nginx\"]\n",
    )
    .unwrap();
    let m = load_model(&p).unwrap();
    assert_eq!(m.backups, vec!["/etc/ssh/sshd_config", "/etc/nginx"]);
}

#[test]
fn recipes_without_backup_are_unchanged() {
    let (_d, p) = recipe("version: 1\n");
    assert!(load_model(&p).unwrap().backups.is_empty());
}

#[test]
fn invalid_backup_declarations_are_schema_errors() {
    for body in [
        "backup: /etc/x\n",
        "backup: {}\n",
        "backup:\n  paths: /etc/x\n",
        "backup:\n  paths: []\n",
        "backup:\n  paths: [1]\n",
        "backup:\n  paths: [etc/x]\n",
        "backup:\n  paths: [/etc/../x]\n",
        "backup:\n  paths: [/etc//x]\n",
        "backup:\n  paths: [/etc/x/]\n",
        "backup:\n  paths: [/]\n",
        "backup:\n  paths: [\"/etc/{{ vars.x }}\"]\n",
        "backup:\n  paths: [/etc/x]\n  destination: /tmp\n",
        "backup:\n  paths: [/etc/x, /etc/x]\n",
    ] {
        let (_d, p) = recipe(&format!("version: 1\n{}", body));
        let e = load_model(&p).expect_err(body);
        assert_eq!(
            e.kind,
            sinter::error::ErrorKind::Schema,
            "{body}: {}",
            e.message
        );
    }
}

#[test]
fn backup_paths_merge_across_includes_and_reject_duplicates() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(
        d.path().join("base.yaml"),
        "version: 1\nbackup:\n  paths: [/etc/a]\n",
    )
    .unwrap();
    let main = d.path().join("main.yaml");
    std::fs::write(
        &main,
        "version: 1\ninclude: [base.yaml]\nbackup:\n  paths: [/etc/b]\n",
    )
    .unwrap();
    assert_eq!(load_model(&main).unwrap().backups, vec!["/etc/a", "/etc/b"]);
    std::fs::write(
        &main,
        "version: 1\ninclude: [base.yaml]\nbackup:\n  paths: [/etc/a]\n",
    )
    .unwrap();
    let e = load_model(&main).unwrap_err();
    assert!(e.message.contains("duplicate backup path"), "{}", e.message);
}

#[test]
fn validate_does_not_touch_backup_paths() {
    let (_d, p) =
        recipe("version: 1\nbackup:\n  paths: [/definitely/not/present/on/this/controller]\n");
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_sinter"))
        .args(["validate", p.to_str().unwrap(), "--host", "nowhere.invalid"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(0), "{o:?}");
}

#[cfg(target_os = "linux")]
mod common;

#[cfg(target_os = "linux")]
mod target {
    use super::common::*;
    use sinter::engine::{Engine, Mode, RunOptions, TargetSpec};
    use sinter::model::load_model;
    use sinter::output::{render_apply, render_plan, OutputFormat, RenderOptions};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    const CANARY: &str = "BACKUP_SECRET_CANARY_7Q2X";

    fn engine(recipe: &Path, mode: Mode, run_id: &str) -> Engine {
        let model = load_model(recipe).unwrap();
        let opts = RunOptions {
            mode,
            sudo: false,
            target: TargetSpec { ssh: None },
            verbose: false,
            fault: None,
            fake_target: None,
        };
        Engine::new(model, opts)
            .unwrap()
            .with_backup_run_id(run_id.to_string())
    }

    fn unique_id(label: &str) -> String {
        format!(
            "20260101T000000Z-{}-{}-{}",
            label,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }

    fn store_run_dir(id: &str) -> PathBuf {
        PathBuf::from(std::env::var("HOME").unwrap())
            .join(".sinter/backups")
            .join(id)
    }

    fn render(report: &sinter::engine::RunReport, mode: Mode, format: OutputFormat) -> String {
        let mut buf = Vec::new();
        let ro = RenderOptions {
            verbose: true,
            format,
            color: false,
        };
        match mode {
            Mode::Plan => render_plan(report, &ro, &mut buf).unwrap(),
            Mode::Apply => render_apply(report, &ro, &mut buf).unwrap(),
        }
        String::from_utf8(buf).unwrap()
    }

    /// A file resource that overwrites `path`, plus the declared backups.
    fn change_recipe(dir: &Path, backups: &[String], path: &Path) -> PathBuf {
        let list = backups
            .iter()
            .map(|b| format!("    - {}\n", b))
            .collect::<String>();
        write_recipe(
            dir,
            "r.yaml",
            &format!(
                "version: 1\nbackup:\n  paths:\n{}resources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: new\n",
                list,
                path.display()
            ),
        )
    }

    #[test]
    fn plan_lists_backups_and_creates_nothing() {
        let dir = trusted_root("backup-plan");
        let f = dir.join("conf");
        std::fs::write(&f, "old").unwrap();
        let r = change_recipe(&dir, &[f.display().to_string()], &f);
        let id = unique_id("plan");
        let report = engine(&r, Mode::Plan, &id).run().unwrap();
        let b = report.backup.as_ref().unwrap();
        assert!(b.run_id.is_none() && b.directory.is_none());
        assert_eq!(b.entries[0].status.label(), "planned");
        assert!(!store_run_dir(&id).exists(), "plan must not create backups");
        let text = render(&report, Mode::Plan, OutputFormat::Text);
        assert!(
            text.contains(&format!("BACKUP  {} [planned]", f.display())),
            "{text}"
        );
        let json: serde_json::Value =
            serde_json::from_str(&render(&report, Mode::Plan, OutputFormat::Json)).unwrap();
        assert_eq!(json["backup"]["entries"][0]["status"], "planned");
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "old");
    }

    #[test]
    fn apply_backs_up_before_changing_and_preserves_metadata() {
        let dir = trusted_root("backup-apply");
        let f = dir.join("conf");
        std::fs::write(&f, format!("old {}", CANARY)).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o640)).unwrap();
        let tree = dir.join("tree");
        std::fs::create_dir_all(tree.join("sub")).unwrap();
        std::fs::write(tree.join("sub/a"), "a").unwrap();
        std::os::unix::fs::symlink("sub/a", tree.join("link")).unwrap();
        let link = dir.join("toplink");
        std::os::unix::fs::symlink("/etc/hostname", &link).unwrap();
        let absent = dir.join("absent");
        let backups = vec![
            f.display().to_string(),
            tree.display().to_string(),
            link.display().to_string(),
            absent.display().to_string(),
        ];
        let r = change_recipe(&dir, &backups, &f);
        let before = std::fs::metadata(&f).unwrap();
        let id = unique_id("apply");
        let report = engine(&r, Mode::Apply, &id).run().unwrap();
        assert_success(&report);
        // The change happened ...
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "new");
        // ... after the old state was copied with its metadata.
        let run = store_run_dir(&id);
        let copy = PathBuf::from(format!("{}{}", run.display(), f.display()));
        assert_eq!(
            std::fs::read_to_string(&copy).unwrap(),
            format!("old {}", CANARY)
        );
        let m = std::fs::metadata(&copy).unwrap();
        assert_eq!(m.mode() & 0o7777, 0o640);
        assert_eq!(m.uid(), before.uid());
        assert_eq!(m.gid(), before.gid());
        assert_eq!(m.mtime(), before.mtime());
        let tcopy = PathBuf::from(format!("{}{}", run.display(), tree.display()));
        assert_eq!(std::fs::read_to_string(tcopy.join("sub/a")).unwrap(), "a");
        assert_eq!(
            std::fs::read_link(tcopy.join("link")).unwrap(),
            PathBuf::from("sub/a")
        );
        let lcopy = PathBuf::from(format!("{}{}", run.display(), link.display()));
        assert_eq!(
            std::fs::read_link(&lcopy).unwrap(),
            PathBuf::from("/etc/hostname"),
            "symlinks are copied as links, never followed"
        );
        assert_eq!(
            std::fs::metadata(&run).unwrap().mode() & 0o777,
            0o700,
            "run directory is private"
        );
        let b = report.backup.as_ref().unwrap();
        let kinds: Vec<_> = b
            .entries
            .iter()
            .map(|e| (e.status.label(), e.kind))
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("backed_up", Some("file")),
                ("backed_up", Some("directory")),
                ("backed_up", Some("symlink")),
                ("absent", None)
            ]
        );
        assert!(!PathBuf::from(format!("{}{}", run.display(), absent.display())).exists());
        // Content never reaches output.
        for fmt in [OutputFormat::Text, OutputFormat::Json] {
            let out = render(&report, Mode::Apply, fmt);
            assert!(!out.contains(CANARY), "backup content leaked: {out}");
            assert!(out.contains(&id), "run id must be reported: {out}");
        }
        assert!(report
            .commands
            .iter()
            .all(|c| !format!("{:?}", c).contains(CANARY)));
    }

    #[test]
    fn backup_failure_prevents_every_change() {
        let dir = trusted_root("backup-fail");
        let f = dir.join("conf");
        std::fs::write(&f, "old").unwrap();
        // An untrusted (world-writable) parent fails the backup trust check.
        let loose = dir.join("loose");
        std::fs::create_dir(&loose).unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o777)).unwrap();
        std::fs::write(loose.join("x"), "x").unwrap();
        let r = change_recipe(
            &dir,
            &[
                f.display().to_string(),
                loose.join("x").display().to_string(),
            ],
            &f,
        );
        let id = unique_id("fail");
        let e = match engine(&r, Mode::Apply, &id).run() {
            Ok(_) => panic!("backup failure must abort apply"),
            Err(e) => e,
        };
        assert_eq!(e.kind, sinter::error::ErrorKind::Apply);
        assert!(
            e.message.contains("no resource was executed"),
            "{}",
            e.message
        );
        assert!(
            e.message.contains("partial backup left at"),
            "{}",
            e.message
        );
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "old", "no change");
        // The first path was copied before the failure and is kept.
        let copy = PathBuf::from(format!("{}{}", store_run_dir(&id).display(), f.display()));
        assert_eq!(std::fs::read_to_string(copy).unwrap(), "old");
    }

    #[test]
    fn unsupported_object_type_fails_backup() {
        let dir = trusted_root("backup-fifo");
        let fifo = dir.join("fifo");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let f = dir.join("conf");
        std::fs::write(&f, "old").unwrap();
        let r = change_recipe(&dir, &[fifo.display().to_string()], &f);
        let e = engine(&r, Mode::Apply, &unique_id("fifo"))
            .run()
            .err()
            .unwrap();
        assert!(
            e.message.contains("unsupported object type"),
            "{}",
            e.message
        );
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "old");
    }

    #[test]
    fn run_directory_collision_fails_without_changes() {
        let dir = trusted_root("backup-collide");
        let f = dir.join("conf");
        std::fs::write(&f, "old").unwrap();
        let r = change_recipe(&dir, &[f.display().to_string()], &f);
        let id = unique_id("collide");
        engine(&r, Mode::Apply, &id).run().unwrap();
        std::fs::write(&f, "old2").unwrap();
        let e = engine(&r, Mode::Apply, &id).run().err().unwrap();
        assert!(e.message.contains("collision"), "{}", e.message);
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "old2", "no change");
    }

    #[test]
    fn backup_of_the_store_itself_is_rejected() {
        let dir = trusted_root("backup-overlap");
        let f = dir.join("conf");
        std::fs::write(&f, "old").unwrap();
        let home = std::env::var("HOME").unwrap();
        let r = change_recipe(&dir, &[format!("{}/.sinter", home)], &f);
        let e = engine(&r, Mode::Apply, &unique_id("overlap"))
            .run()
            .err()
            .unwrap();
        assert!(
            e.message.contains("overlaps the backup store"),
            "{}",
            e.message
        );
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "old");
    }

    #[test]
    fn audit_ignores_backup_declarations() {
        let dir = trusted_root("backup-audit");
        let f = dir.join("conf");
        std::fs::write(&f, "new").unwrap();
        let r = change_recipe(&dir, &[f.display().to_string()], &f);
        let id = unique_id("audit");
        let report = sinter::audit::run_audit(engine(&r, Mode::Plan, &id)).unwrap();
        assert_eq!(report.exit_code(), 0);
        assert!(
            !store_run_dir(&id).exists(),
            "audit must not create backups"
        );
    }

    #[test]
    fn json_without_backup_section_has_no_backup_key() {
        let dir = trusted_root("backup-nokey");
        let r = write_recipe(&dir, "r.yaml", "version: 1\n");
        let report = engine(&r, Mode::Plan, &unique_id("nokey")).run().unwrap();
        let json: serde_json::Value =
            serde_json::from_str(&render(&report, Mode::Plan, OutputFormat::Json)).unwrap();
        assert!(json.get("backup").is_none());
    }
}
