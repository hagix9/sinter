//! Audit of an object whose declared owner or group does not exist on the
//! host (DESIGN §49.4): a difference from the desired state (drift), not a
//! reason the object cannot be audited; the other dimensions are still
//! compared, and nothing is changed.
mod common;

use common::*;
use sinter::audit::{run_audit, AuditReport, AuditResourceStatus};
use sinter::engine::{Engine, Mode, RunOptions, TargetSpec};
use sinter::executor::FakeTarget;
use sinter::model::load_model;

fn audit(body: &str, label: &str, fake: FakeTarget) -> AuditReport {
    let p = write_recipe(&trusted_root(label), "r.yaml", body);
    let opts = RunOptions {
        mode: Mode::Plan,
        sudo: true,
        target: TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(fake),
    };
    run_audit(Engine::new(load_model(&p).unwrap(), opts).unwrap()).unwrap()
}

fn host() -> FakeTarget {
    let mut t = FakeTarget::rocky9()
        .with_fake_fs()
        .as_root()
        .with_fs_dir("/etc")
        .with_fs_dir("/etc/app");
    t.fs.as_mut()
        .unwrap()
        .put_file("/etc/app/app.conf", b"k=v\n", 0o644, 0, 0);
    t
}

const RECIPE: &str = r#"
version: 1
resources:
  - id: conf
    type: file
    with: { path: /etc/app/app.conf, content: "k=v\n", owner: appsvc, group: appsvc, mode: "0640" }
  - id: dir
    type: directory
    with: { path: /etc/app, owner: appsvc, mode: "0755" }
  - id: other
    type: file
    with: { path: /etc/app/absent.conf, content: "x\n" }
"#;

#[test]
fn a_missing_owner_account_is_drift_and_the_other_dimensions_are_still_compared() {
    let rep = audit(RECIPE, "aaa-drift", host());
    let conf = &rep.resources[0];
    assert_eq!(conf.status, AuditResourceStatus::Drift, "{:?}", conf.reason);
    let dims: Vec<&str> = conf.details.iter().map(|d| d.dimension.as_str()).collect();
    assert_eq!(dims, ["owner", "group", "mode"], "{:?}", conf.details);
    assert!(conf.details[0]
        .desired
        .contains("appsvc (no such user on the host)"));
    assert!(conf.details[1]
        .desired
        .contains("appsvc (no such group on the host)"));
    let dir = &rep.resources[1];
    assert_eq!(dir.status, AuditResourceStatus::Drift);
    assert_eq!(dir.details.len(), 1);
    // An unrelated resource is audited on its own: absent is drift.
    assert_eq!(rep.resources[2].status, AuditResourceStatus::Drift);
    assert_eq!(rep.summary.errors, 0);
    // Read-only: nothing but observations was dispatched.
    assert!(rep.commands.iter().all(|c| !matches!(
        c.program.as_str(),
        "/bin/chown" | "/bin/chmod" | "/bin/mkdir"
    )));
}

#[test]
fn an_existing_account_is_compared_by_id_as_before() {
    let t = host().with_group("appsvc", 1500).with_user(
        "appsvc",
        1500,
        1500,
        "/var/lib/appsvc",
        "/sbin/nologin",
    );
    let rep = audit(RECIPE, "aaa-existing", t);
    let conf = &rep.resources[0];
    assert_eq!(conf.status, AuditResourceStatus::Drift);
    assert_eq!(conf.details[0].desired, "1500");
}

#[test]
fn an_account_lookup_that_cannot_be_trusted_is_an_error_never_drift() {
    use sinter::executor::{Completion, Output};
    let single = r#"
version: 1
resources:
  - id: conf
    type: file
    with: { path: /etc/app/app.conf, content: "k=v\n", owner: appsvc }
"#;
    let mut t = host();
    for _ in 0..8 {
        t.observation_overrides
            .entry("getent".into())
            .or_default()
            .push_back(Output {
                completion: Completion::Exited(0),
                stdout: b"appsvc:x:990:990::/h:/s\nappsvc:x:991:991::/h:/s\n".to_vec(),
                stderr: Vec::new(),
                stdout_truncated: false,
                stderr_truncated: false,
            });
    }
    let rep = audit(single, "aaa-untrusted", t);
    assert_eq!(rep.resources[0].status, AuditResourceStatus::Error);
    assert!(rep.resources[0].details.is_empty());
}
