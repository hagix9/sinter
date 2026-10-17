//! LED-024 / LED-025: the privilege messages a user sees.
//!
//! LED-024: a plan note saying a change `needs root` is shown in the default
//! text output (it used to need `--verbose`). The note itself, when it is
//! produced (plan only, a run that is neither root nor `--sudo`), and the
//! JSON document are unchanged.
//!
//! LED-025: a `stat` refused with exactly the coreutils "Permission denied"
//! record is still an observation error (fail closed), but the message says
//! "permission denied" and, only when the run is not root, how to get root.
#![cfg(unix)]

use sinter::engine::{Engine, Mode, RunOptions, RunReport, TargetSpec};
use sinter::executor::{Completion, FakeTarget, Output};
use sinter::model::load_model;
use sinter::output::{render_apply, render_plan, run_report_json, OutputFormat, RenderOptions};
use std::path::PathBuf;

fn base() -> FakeTarget {
    let mut t = FakeTarget::ubuntu2404().with_fake_fs();
    let fs = t.fs.as_mut().unwrap();
    for (path, mode, uid) in [
        ("/etc", 0o755, 0),
        ("/etc/fs0", 0o755, 0),
        ("/root", 0o700, 0),
        ("/home", 0o755, 0),
        ("/home/fake", 0o755, 1000),
    ] {
        fs.mkdir_node(path, mode, uid, uid);
    }
    t
}

fn recipe(dir: &tempfile::TempDir, body: &str) -> PathBuf {
    let p = dir.path().join("r.yaml");
    std::fs::write(&p, format!("version: 1\n{}", body)).unwrap();
    p
}

fn run(p: &std::path::Path, mode: Mode, sudo: bool, t: FakeTarget) -> RunReport {
    Engine::new(
        load_model(p).unwrap(),
        RunOptions {
            mode,
            sudo,
            target: TargetSpec { ssh: None },
            verbose: false,
            fault: None,
            fake_target: Some(t),
        },
    )
    .unwrap_or_else(|e| panic!("connect: {}", e.message))
    .run()
    .unwrap_or_else(|e| panic!("run: {}", e.message))
}

fn text(r: &RunReport, mode: Mode, verbose: bool, color: bool) -> String {
    let opts = RenderOptions {
        verbose,
        format: OutputFormat::Text,
        color,
    };
    let mut out = Vec::new();
    match mode {
        Mode::Plan => render_plan(r, &opts, &mut out).unwrap(),
        _ => render_apply(r, &opts, &mut out).unwrap(),
    }
    String::from_utf8(out).unwrap()
}

const RECIPE: &str = "resources:\n  - id: f\n    type: file\n    with:\n      path: /etc/fs0/a.conf\n      content: \"a\\n\"\n  - id: pkg\n    type: package\n    with:\n      name: nginx\n      state: present\n  - id: mine\n    type: file\n    with:\n      path: /home/fake/a.conf\n      content: \"a\\n\"\n";

#[test]
fn needs_root_is_shown_without_verbose_for_a_user_without_sudo() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, RECIPE);
    let r = run(&p, Mode::Plan, false, base());
    for color in [false, true] {
        let out = text(&r, Mode::Plan, false, color);
        assert!(
            out.contains("note: needs root: /etc/fs0 belongs to root"),
            "color={color}:\n{out}"
        );
        assert!(
            out.contains("note: needs root: changing a package requires root privilege"),
            "color={color}:\n{out}"
        );
        // The user's own directory needs nothing.
        let mine = out.split("mine").nth(1).unwrap_or("");
        assert!(
            !mine.lines().take(3).any(|l| l.contains("needs root")),
            "{out}"
        );
    }
}

#[test]
fn no_privilege_note_for_a_root_login_or_with_sudo() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, RECIPE);
    let user = |t: FakeTarget| t.with_user("fake", 1000, 1000, "/home/fake", "/bin/bash");
    for (t, sudo) in [
        (user(base().as_root()), false),
        (user(base().as_root()), true),
        (user(base()), true),
    ] {
        let r = run(&p, Mode::Plan, sudo, t);
        for verbose in [false, true] {
            let out = text(&r, Mode::Plan, verbose, false);
            assert!(
                !out.contains("needs root"),
                "sudo={sudo} verbose={verbose}:\n{out}"
            );
            assert!(
                !out.contains("--sudo"),
                "no sudo advice for root/sudo runs:\n{out}"
            );
        }
    }
}

#[test]
fn other_notes_stay_verbose_only() {
    // A note that is not a privilege note (here: a directory the user owns
    // without the owner write bit) is still shown only with --verbose.
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(
        &dir,
        "resources:\n  - id: f\n    type: file\n    with:\n      path: /home/fake/ro/a.conf\n      content: \"a\\n\"\n",
    );
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/home/fake/ro", 0o555, 1000, 1000);
    let r = run(&p, Mode::Plan, false, t);
    let notes = &r.resources[0].notes;
    assert!(
        notes
            .iter()
            .any(|n| n.contains("no owner write permission")),
        "{notes:?}"
    );
    assert!(!text(&r, Mode::Plan, false, false).contains("no owner write permission"));
    assert!(text(&r, Mode::Plan, true, false).contains("no owner write permission"));
}

#[test]
fn a_sensitive_resource_shows_that_root_is_needed_and_nothing_else() {
    let dir = tempfile::tempdir().unwrap();
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/etc/very-secret-dir", 0o755, 0, 0);
    let p = recipe(
        &dir,
        "resources:\n  - id: s\n    type: file\n    sensitive: true\n    with:\n      path: /etc/very-secret-dir/a.conf\n      content: \"a\\n\"\n",
    );
    let r = run(&p, Mode::Plan, false, t);
    for verbose in [false, true] {
        let out = text(&r, Mode::Plan, verbose, false);
        assert!(out.contains("note: needs root (details redacted)"), "{out}");
        assert!(!out.contains("very-secret-dir"), "{out}");
    }
}

#[test]
fn json_and_apply_output_are_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, RECIPE);
    let r = run(&p, Mode::Plan, false, base());
    // JSON: the notes array carries the same texts the report holds.
    let j = run_report_json(&r, "plan");
    for (i, res) in r.resources.iter().enumerate() {
        let notes: Vec<String> = j["resources"][i]["notes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n.as_str().unwrap().to_string())
            .collect();
        assert_eq!(notes, res.notes, "{}", res.id);
    }
    // Apply carries no plan note, so its text has no privilege note either.
    let a = run(&p, Mode::Apply, false, base());
    assert!(!text(&a, Mode::Apply, false, false).contains("needs root"));
}

// ---------------------------------------------------------------------------
// LED-025
// ---------------------------------------------------------------------------

fn exited(code: i32, stderr: &str) -> Output {
    Output {
        completion: Completion::Exited(code),
        stdout: Vec::new(),
        stderr: stderr.as_bytes().to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

const ONE_FILE: &str = "resources:\n  - id: f\n    type: file\n    with:\n      path: /etc/fs0/a.conf\n      content: \"a\\n\"\n";

fn plan_message(t: FakeTarget, sudo: bool) -> String {
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, ONE_FILE);
    let engine = Engine::new(
        load_model(&p).unwrap(),
        RunOptions {
            mode: Mode::Plan,
            sudo,
            target: TargetSpec { ssh: None },
            verbose: false,
            fault: None,
            fake_target: Some(t),
        },
    )
    .unwrap();
    // Fail closed: an observation that proves nothing stops the plan.
    match engine.run() {
        Ok(r) => panic!("an unreadable observation must not plan: {:?}", r.status),
        Err(e) => {
            // The same kind as the old wording (the "anything but" cases below go
            // through the unchanged path and must agree).
            assert_eq!(e.kind, sinter::error::ErrorKind::Plan);
            e.message
        }
    }
}

fn denied(t: FakeTarget, stderr: &str) -> FakeTarget {
    t.with_observations_at("stat", "/etc/fs0/a.conf", vec![exited(1, stderr); 4])
}

#[test]
fn permission_denied_is_named_and_still_fails_closed() {
    let rec = "stat: cannot statx '/etc/fs0/a.conf': Permission denied\n";
    let m = plan_message(denied(base(), rec), false);
    assert!(
        m.contains("cannot inspect /etc/fs0/a.conf: permission denied"),
        "{m}"
    );
    assert!(m.contains("uid 1000"), "{m}");
    assert!(m.contains("connect as root or use --sudo"), "{m}");
    assert!(!m.contains("unrecognized diagnostic"), "{m}");
    // uutils renders the errno too.
    let m = plan_message(
        denied(
            base(),
            "stat: cannot statx '/etc/fs0/a.conf': Permission denied (os error 13)\n",
        ),
        false,
    );
    assert!(m.contains("permission denied: the target user"), "{m}");
}

#[test]
fn as_root_permission_denied_gives_no_sudo_advice() {
    let rec = "stat: cannot statx '/etc/fs0/a.conf': Permission denied\n";
    for (t, sudo) in [(base().as_root(), false), (base(), true)] {
        let m = plan_message(denied(t, rec), sudo);
        assert!(
            m.contains("permission denied even with root privilege"),
            "{m}"
        );
        assert!(!m.contains("--sudo"), "{m}");
    }
}

#[test]
fn anything_but_the_exact_record_keeps_the_old_wording() {
    for stderr in [
        "stat: cannot statx '/etc/fs0/a.conf': Permission denied: no such file or directory\n",
        "stat: cannot statx '/etc/other': Permission denied\n",
        "ls: cannot statx '/etc/fs0/a.conf': Permission denied\n",
        "stat: cannot statx '/etc/fs0/a.conf': Permission denied",
        "stat: cannot statx '/etc/fs0/a.conf': Permission denied\nmore\n",
    ] {
        let m = plan_message(denied(base(), stderr), false);
        assert!(m.contains("unrecognized diagnostic"), "{stderr:?}: {m}");
        assert!(!m.contains("permission denied:"), "{stderr:?}: {m}");
    }
}

#[test]
fn the_older_cannot_stat_form_is_recognized_too() {
    let m = plan_message(
        denied(
            base(),
            "stat: cannot stat '/etc/fs0/a.conf': Permission denied\n",
        ),
        false,
    );
    assert!(m.contains("permission denied: the target user"), "{m}");
}

#[test]
fn an_incomplete_signalled_or_truncated_capture_keeps_its_own_message() {
    let rec = "stat: cannot statx '/etc/fs0/a.conf': Permission denied\n";
    let with = |completion: Completion, truncated: bool| Output {
        completion,
        stdout: Vec::new(),
        stderr: rec.as_bytes().to_vec(),
        stdout_truncated: false,
        stderr_truncated: truncated,
    };
    for (o, expect) in [
        (
            with(
                Completion::Indeterminate {
                    started: true,
                    reason: "lost".into(),
                },
                false,
            ),
            "did not complete",
        ),
        (
            with(Completion::Signaled(9), false),
            "terminated by signal 9",
        ),
        (with(Completion::Exited(0), false), "unexpected diagnostic"),
        (with(Completion::Exited(1), true), "unrecognized diagnostic"),
    ] {
        let t = base().with_observations_at("stat", "/etc/fs0/a.conf", vec![o; 4]);
        let dir = tempfile::tempdir().unwrap();
        let p = recipe(&dir, ONE_FILE);
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
        .unwrap()
        .run();
        let Err(e) = e else {
            panic!("{expect}: must stay an error")
        };
        assert!(e.message.contains(expect), "{expect}: {}", e.message);
        assert!(!e.message.contains("permission denied"), "{}", e.message);
    }
}
