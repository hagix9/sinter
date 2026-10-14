//! A failed sensitive resource must not hand its own (unredacted) failure reason to the
//! non-sensitive resources that fail-fast blocks behind it (FS-2 final audit, MEDIUM-3).
#![cfg(unix)]
use sinter::engine::{Engine, Mode, RunOptions, RunReport, TargetSpec};
use sinter::executor::{FakeTarget, FsEventAction};
use sinter::model::load_model;
use sinter::output::{render_apply, OutputFormat, RenderOptions};

fn base() -> FakeTarget {
    let mut t = FakeTarget::ubuntu2404().with_fake_fs().as_root();
    let fs = t.fs.as_mut().unwrap();
    for (p, m) in [("/tmp", 0o1777), ("/etc/app", 0o755)] {
        fs.mkdir_node(p, m, 0, 0);
    }
    t
}

fn apply(body: &str, t: FakeTarget) -> RunReport {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("r.yaml");
    std::fs::write(&p, format!("version: 1\nresources:\n{}", body)).unwrap();
    Engine::new(
        load_model(&p).unwrap(),
        RunOptions {
            mode: Mode::Apply,
            sudo: false,
            target: TargetSpec { ssh: None },
            verbose: true,
            fault: None,
            fake_target: Some(t),
        },
    )
    .unwrap()
    .run()
    .unwrap()
}

/// Like `apply`, but a recipe or plan error (no report) is returned as None.
fn apply_lenient(body: &str, t: FakeTarget) -> Option<RunReport> {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("r.yaml");
    std::fs::write(&p, format!("version: 1\nresources:\n{}", body)).unwrap();
    let model = load_model(&p).ok()?;
    Engine::new(
        model,
        RunOptions {
            mode: Mode::Apply,
            sudo: false,
            target: TargetSpec { ssh: None },
            verbose: true,
            fault: None,
            fake_target: Some(t),
        },
    )
    .ok()?
    .run()
    .ok()
}

/// Everything a user can be shown: the text and JSON renderings, and the raw reasons
/// (which front ends may print as they are).
fn shown(r: &RunReport) -> String {
    let mut out = String::new();
    for format in [OutputFormat::Text, OutputFormat::Json] {
        let mut buf = Vec::new();
        render_apply(
            r,
            &RenderOptions {
                verbose: true,
                format,
                color: false,
            },
            &mut buf,
        )
        .unwrap();
        out.push_str(&String::from_utf8(buf).unwrap());
    }
    // the raw reasons and notes of the resources that are not sensitive are shown as they are
    // (by every front end, MCP included); a sensitive resource's own are redacted by the text and JSON renderers
    for x in r.resources.iter().filter(|x| !x.sensitive) {
        out.push_str(&format!("\n{}|{:?}|{:?}", x.id, x.reason, x.notes));
    }
    out
}

const SECRET: &str = "  - id: f\n    type: file\n    sensitive: true\n    with:\n      path: /tmp/topsecret-name.conf\n      content: \"x\\n\"\n";
const NEXT: &str =
    "  - id: next\n    type: file\n    with:\n      path: /etc/app/other.conf\n      content: \"y\\n\"\n";

fn assert_no_leak(r: &RunReport, what: &str) {
    let next = r.resources.iter().find(|x| x.id == "next").expect("next");
    assert_eq!(
        format!("{:?}", next.disposition),
        "BlockedByFailFast",
        "{what}: the second resource must be blocked, not run"
    );
    let text = shown(r);
    for needle in ["topsecret-name", ".sinter-stage"] {
        assert!(!text.contains(needle), "{what}: {needle} leaked:\n{text}");
    }
    assert!(
        next.reason.is_some(),
        "{what}: a blocked resource still says why"
    );
}

#[test]
fn a_staging_cleanup_failure_of_a_sensitive_file_does_not_name_its_paths_in_the_next_resource() {
    let mut t = base();
    t.fs.as_mut().unwrap().payload_undeletable = true;
    let r = apply(&format!("{SECRET}{NEXT}"), t);
    assert_no_leak(&r, "link-remains");
}

#[test]
fn a_target_drift_of_a_sensitive_file_does_not_name_its_path_in_the_next_resource() {
    let t = base().with_fs_event(
        "sh",
        "stage",
        0,
        vec![FsEventAction::PutFile {
            path: "/tmp/topsecret-name.conf".into(),
            data: b"theirs\n".to_vec(),
            mode: 0o644,
            uid: 0,
            gid: 0,
        }],
    );
    let r = apply(&format!("{SECRET}{NEXT}"), t);
    assert_no_leak(&r, "drift");
}

#[test]
fn a_non_sensitive_failure_still_explains_itself_to_the_resource_it_blocks() {
    // The fix withholds only a sensitive resource's reason.
    let mut t = base();
    t.fs.as_mut().unwrap().payload_undeletable = true;
    let body = "  - id: f\n    type: file\n    with:\n      path: /tmp/plain-name.conf\n      content: \"x\\n\"\n";
    let r = apply(&format!("{body}{NEXT}"), t);
    let next = r.resources.iter().find(|x| x.id == "next").unwrap();
    let reason = next.reason.clone().unwrap_or_default();
    assert!(
        reason.contains("plain-name") || reason.contains("f:"),
        "{reason}"
    );
}

#[test]
fn a_sensitive_resource_that_stops_the_run_in_its_condition_does_not_hand_its_reason_on() {
    // A `when` that cannot be evaluated stops the run; the next resource says why without
    // repeating what the sensitive resource said.
    let body = "  - id: f\n    type: file\n    sensitive: true\n    when: facts.nothing.here == \"x\"\n    with:\n      path: /tmp/topsecret-name.conf\n      content: \"x\\n\"\n";
    let r = apply_lenient(&format!("{body}{NEXT}"), base());
    let r = r.expect("the recipe loads and runs to a report");
    let next = r.resources.iter().find(|x| x.id == "next").expect("next");
    assert_eq!(
        format!("{:?}", next.disposition),
        "BlockedByFailFast",
        "the failed condition stops the run: {:?}",
        r.resources
            .iter()
            .map(|x| (&x.id, &x.reason))
            .collect::<Vec<_>>()
    );
    let reason = next.reason.clone().unwrap_or_default();
    assert!(!reason.contains("topsecret-name"), "{reason}");
    assert!(
        reason.contains("details withheld"),
        "the fixed text is used, not the sensitive resource's own: {reason}"
    );
}
