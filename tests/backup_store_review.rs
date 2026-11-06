//! Security review of the store a recipe names (DESIGN §40.6): what the invocation
//! can come to write, what a failure leaves, and what plan does. Everything runs on
//! the scripted filesystem; no live service reads these directories here, so what
//! a real daemon makes of a run directory is judged in the review report, not here.
#![cfg(unix)]

use sinter::engine::{AggregateStatus, Engine, Mode, RunOptions, RunReport, TargetSpec};
use sinter::error::SinterError;
use sinter::executor::FakeTarget;
use sinter::fakesys::{FakeKind, FakeNode};
use sinter::model::load_model;
use std::collections::BTreeMap;

const SECRET: &str = "REVIEW_SECRET_DO_NOT_PRINT";
const RESOURCE: &str =
    "resources:\n  - id: f\n    type: file\n    with: { path: /srv/new, content: x }\n";

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
        ("/srv", 0o755, 0),
        ("/srv/app", 0o755, 0),
        ("/tmp", 0o1777, 0),
        ("/root", 0o700, 0),
    ] {
        fs.mkdir_node(path, mode, uid, uid);
    }
    fs.put_file("/srv/app/a", b"a", 0o640, 0, 0);
    fs.put_file("/srv/app/b", b"b", 0o640, 0, 0);
    fs.put_file("/var/lib/pgsql/.pgpass", SECRET.as_bytes(), 0o600, 26, 26);
    t
}

fn run_id(mode: Mode, backup: &str, id: &str, t: FakeTarget) -> Result<RunReport, SinterError> {
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
    .with_backup_run_id(id.to_string())
    .run()
}

fn apply(backup: &str, t: FakeTarget) -> Result<RunReport, SinterError> {
    run_id(Mode::Apply, backup, "run", t)
}

/// A second store, what makes it fail, and the words expected.
type StoreCase = (&'static str, fn(&mut FakeTarget), &'static str);

type Snapshot = BTreeMap<String, (u32, u32, Option<Vec<u8>>)>;

fn snapshot(nodes: &BTreeMap<String, FakeNode>) -> Snapshot {
    nodes
        .iter()
        .map(|(p, n)| {
            let body = match &n.kind {
                FakeKind::File(b) => Some(b.clone()),
                FakeKind::Symlink(l) => Some(l.clone().into_bytes()),
                FakeKind::Dir => None,
            };
            (p.clone(), (n.mode, n.uid, body))
        })
        .collect()
}

fn program(c: &sinter::executor::CommandRecord) -> &str {
    c.program.rsplit('/').next().unwrap()
}

/// What a write looks like, whichever identity runs it.
const WRITERS: [&str; 10] = [
    "mkdir", "chmod", "chown", "cp", "rm", "ln", "mv", "touch", "setfacl", "dd",
];

#[test]
fn plan_never_writes_whatever_the_stores() {
    let mut t = base();
    t.fs.as_mut()
        .unwrap()
        .mkdir_node("/var/backups/there", 0o700, 0, 0);
    let before = snapshot(&t.fs.as_ref().unwrap().nodes);
    let r = run_id(
        Mode::Plan,
        "  directory: /var/backups/absent\n  paths:\n    - /srv/app/a\n    - { path: /srv/app/b, directory: /var/backups/there }\n    - { path: /var/lib/pgsql/.pgpass, directory: /var/backups/pg }\n",
        "run",
        t,
    )
    .unwrap();
    assert_eq!(r.status, AggregateStatus::Success);
    for c in &r.commands {
        assert!(
            !WRITERS.contains(&program(c)) && program(c) != "sh",
            "plan ran {} {:?}",
            c.program,
            c.args
        );
    }
    // Nothing in the source's account tree was read for this either.
    assert!(!format!("{:?}", r.backup).contains(SECRET));
    assert_eq!(snapshot(&r.fake_fs.as_ref().unwrap().nodes), before);
}

#[test]
fn a_service_directory_as_a_store_gets_one_directory_and_keeps_its_files() {
    for store in [
        "/etc",
        "/etc/systemd/system",
        "/etc/cron.d",
        "/etc/sudoers.d",
        "/etc/ssh",
        "/etc/profile.d",
    ] {
        let mut t = base();
        let fs = t.fs.as_mut().unwrap();
        let mut parent = String::new();
        for part in store.trim_start_matches('/').split('/') {
            parent.push('/');
            parent.push_str(part);
            if !fs.nodes.contains_key(&parent) {
                fs.mkdir_node(&parent, 0o755, 0, 0);
            }
        }
        let live = format!("{store}/live.conf");
        fs.put_file(&live, b"live", 0o440, 0, 0);
        let before = snapshot(&fs.nodes);
        let r = apply(&format!("  directory: {store}\n  paths: [/srv/app/a]\n"), t).unwrap();
        assert_eq!(r.status, AggregateStatus::Success, "{store}");
        let after = snapshot(&r.fake_fs.as_ref().unwrap().nodes);
        let run = format!("{store}/run");
        // Every entry that existed is what it was: nothing replaced, nothing chmodded.
        for (p, v) in &before {
            assert_eq!(after.get(p), Some(v), "{store}: {p} changed");
        }
        // What is new is the run directory and what lies inside it, and the resource.
        for p in after.keys().filter(|p| !before.contains_key(*p)) {
            assert!(
                p == &run || p.starts_with(&format!("{run}/")) || p == "/srv/new",
                "{store}: {p} is new"
            );
        }
        // Directly in the store the only new name is the run id, and it is a directory
        // of mode 0700: no file a service could load appears at that level.
        let n = &r.fake_fs.as_ref().unwrap().nodes[&run];
        assert!(matches!(n.kind, FakeKind::Dir), "{store}");
        assert_eq!(n.mode & 0o777, 0o700, "{store}");
        assert_eq!(
            r.backup.as_ref().unwrap().entries[0].destination.as_deref(),
            Some(format!("{run}/srv/app/a").as_str())
        );
    }
}

#[test]
fn a_new_store_is_private_whatever_its_name() {
    // A directory, never a file, at any name, and only that one level.
    let r = apply(
        "  directory: /etc/sudoers.d\n  paths: [/srv/app/a]\n",
        base(),
    )
    .unwrap();
    let fs = r.fake_fs.as_ref().unwrap();
    assert_eq!(fs.nodes["/etc/sudoers.d"].mode & 0o777, 0o700);
    assert_eq!(fs.nodes["/etc/sudoers.d"].uid, 0);
    // A missing parent is not made.
    let e = apply(
        "  directory: /etc/nosuch/sudoers.d\n  paths: [/srv/app/a]\n",
        base(),
    )
    .err()
    .unwrap();
    assert!(e.message.contains("parent"), "{}", e.message);
}

#[test]
fn nothing_is_written_through_a_link_planted_at_the_run_directory() {
    let mut t = base();
    let fs = t.fs.as_mut().unwrap();
    fs.mkdir_node("/var/backups/s", 0o700, 0, 0);
    fs.put_symlink("/var/backups/s/run", "/etc", 0, 0);
    let e = apply("  directory: /var/backups/s\n  paths: [/srv/app/a]\n", t)
        .err()
        .unwrap();
    assert!(e.message.contains("collision"), "{}", e.message);
    assert!(
        e.message.contains("no resource was executed"),
        "{}",
        e.message
    );
    assert!(e.backup.as_ref().unwrap().directories.is_empty());
}

#[test]
fn a_second_store_that_fails_leaves_the_first_empty_named_and_harmless() {
    let cases: Vec<StoreCase> = vec![
        ("/var/nosuch/s", |_| {}, "parent"),
        (
            "/var/backups/other",
            |t| {
                t.fs.as_mut()
                    .unwrap()
                    .mkdir_node("/var/backups/other", 0o700, 26, 26)
            },
            "outside the trusted set",
        ),
        (
            "/var/backups/ln",
            |t| {
                t.fs.as_mut()
                    .unwrap()
                    .put_symlink("/var/backups/ln", "/etc", 0, 0)
            },
            "symlink",
        ),
        (
            "/var/backups/taken",
            |t| {
                let fs = t.fs.as_mut().unwrap();
                fs.mkdir_node("/var/backups/taken", 0o700, 0, 0);
                fs.mkdir_node("/var/backups/taken/run", 0o700, 0, 0);
            },
            "collision",
        ),
    ];
    for (second, prepare, says) in cases {
        let mut t = base();
        prepare(&mut t);
        let e = apply(
            &format!(
                "  paths:\n    - {{ path: /srv/app/a, directory: /var/backups/good }}\n    - {{ path: /srv/app/b, directory: {second} }}\n"
            ),
            t,
        )
        .err()
        .unwrap();
        assert!(e.message.contains(says), "{second}: {}", e.message);
        assert!(
            e.message.contains("no resource was executed"),
            "{}",
            e.message
        );
        assert!(e.message.contains("/var/backups/good/run"), "{}", e.message);
        let b = e.backup.as_ref().unwrap();
        assert_eq!(b.directories, ["/var/backups/good/run"], "{second}");
        assert_eq!(b.directory.as_deref(), Some("/var/backups/good/run"));
        // Nothing was copied before the stores were all ready.
        for entry in &b.entries {
            assert_eq!(entry.status.label(), "not_run", "{second}");
            assert!(entry.destination.is_none(), "{second}");
        }
    }
}

#[test]
fn a_copy_that_fails_midway_is_reported_and_a_new_run_is_safe() {
    let mut t = base();
    let fs = t.fs.as_mut().unwrap();
    fs.put_file("/var/lib/pgsql/linked", b"x", 0o600, 26, 26);
    fs.put_hardlink("/var/lib/pgsql/linked", "/var/lib/pgsql/second");
    let e = apply(
        "  paths:\n    - { path: /srv/app/a, directory: /var/backups/one }\n    - { path: /var/lib/pgsql/linked, directory: /var/backups/two }\n    - { path: /srv/app/b, directory: /var/backups/three }\n",
        t.clone(),
    )
    .err()
    .unwrap();
    assert!(
        e.message.contains("no resource was executed"),
        "{}",
        e.message
    );
    assert!(e.message.contains("hard links"), "{}", e.message);
    let b = e.backup.as_ref().unwrap();
    // All three stores were ready; the report says which copy is where.
    assert_eq!(b.directories.len(), 3);
    assert_eq!(b.entries[0].status.label(), "backed_up");
    assert_eq!(
        b.entries[0].destination.as_deref(),
        Some("/var/backups/one/run/srv/app/a")
    );
    assert_eq!(b.entries[1].status.label(), "failed");
    assert_eq!(b.entries[2].status.label(), "not_run");
    // A repeat with the same run id cannot reuse what was left; a new one is apart.
    let r = run_id(
        Mode::Apply,
        "  paths:\n    - { path: /srv/app/a, directory: /var/backups/one }\n",
        "again",
        t,
    )
    .unwrap();
    assert_eq!(r.status, AggregateStatus::Success);
}

#[test]
fn the_same_run_id_again_is_a_collision_and_the_first_backup_stands() {
    let backup = "  directory: /var/backups/s\n  paths: [/srv/app/a]\n";
    let first = apply(backup, base()).unwrap();
    let nodes = first.fake_fs.as_ref().unwrap().nodes.clone();
    let mut t = base();
    t.fs.as_mut().unwrap().nodes = nodes.clone();
    let e = apply(backup, t).err().unwrap();
    assert!(e.message.contains("collision"), "{}", e.message);
    assert!(e.backup.as_ref().unwrap().directories.is_empty());
    assert!(nodes.contains_key("/var/backups/s/run/srv/app/a"));
}

#[test]
fn hosts_keep_their_own_copies_under_one_store_name() {
    let backup = "  directory: /var/backups/s\n  paths: [/srv/app/a]\n";
    for t in [base(), base()] {
        let r = apply(backup, t).unwrap();
        assert_eq!(r.status, AggregateStatus::Success);
        assert!(r
            .fake_fs
            .as_ref()
            .unwrap()
            .nodes
            .contains_key("/var/backups/s/run/srv/app/a"));
    }
}

#[test]
fn the_account_reads_and_root_writes_in_every_store_and_order() {
    for (first, second) in [
        ("/var/lib/pgsql/.pgpass", "/srv/app/a"),
        ("/srv/app/a", "/var/lib/pgsql/.pgpass"),
    ] {
        let r = apply(
            &format!(
                "  paths:\n    - {{ path: {first}, directory: /var/backups/one }}\n    - {{ path: {second}, directory: /var/backups/two }}\n"
            ),
            base(),
        )
        .unwrap();
        assert_eq!(r.status, AggregateStatus::Success);
        let fs = r.fake_fs.as_ref().unwrap();
        // Every store and run directory is root's and private.
        for d in [
            "/var/backups/one",
            "/var/backups/one/run",
            "/var/backups/two",
            "/var/backups/two/run",
        ] {
            assert_eq!(
                (fs.nodes[d].uid, fs.nodes[d].mode & 0o777),
                (0, 0o700),
                "{d}"
            );
        }
        for c in &r.commands {
            let text = c.args.join(" ");
            // The account's identity never touches a store.
            if program(c) == "setpriv" {
                assert!(!text.contains("/var/backups"), "{text}");
            }
            // Root never names the account's file, except through the fixed script.
            if text.contains("/var/lib/pgsql/.pgpass") {
                assert!(
                    program(c) == "setpriv" || text.contains("[fsbackup.sh"),
                    "{} {text}",
                    c.program
                );
            }
        }
        let log = format!("{:?}{:?}", r.commands, r.backup);
        assert!(!log.contains(SECRET));
    }
}

#[test]
fn a_store_inside_the_tree_and_a_source_that_holds_a_store_stay_refused() {
    // With several stores, one bad one is enough.
    let e = apply(
        "  paths:\n    - { path: /srv/app/a, directory: /var/backups/one }\n    - { path: /srv/app/b, directory: /var/lib/pgsql/mine }\n",
        base(),
    )
    .err()
    .unwrap();
    assert!(
        e.message.contains("outside the trusted set"),
        "{}",
        e.message
    );
    let e = apply(
        "  paths:\n    - { path: /srv, directory: /var/backups/one }\n    - { path: /etc/x, directory: /srv/store }\n",
        base(),
    )
    .err()
    .unwrap();
    assert!(e.message.contains("overlap"), "{}", e.message);
}

/// An ACL on the store itself: `apply` refuses it through the walk of the run
/// directory, and `plan` must say what `apply` would.
#[test]
fn plan_and_apply_agree_about_an_acl_on_the_store() {
    use sinter::executor::{Completion, Output};
    let acl = || {
        let mut t = base();
        t.fs.as_mut()
            .unwrap()
            .mkdir_node("/var/backups/acl", 0o700, 0, 0);
        t.with_observations_at(
            "getfattr",
            "/var/backups/acl",
            vec![Output {
                completion: Completion::Exited(0),
                stdout: b"# file: /var/backups/acl\nsystem.posix_acl_access=0sAgAAAAEABgD/////\n\n"
                    .to_vec(),
                stderr: Vec::new(),
                stdout_truncated: false,
                stderr_truncated: false,
            }],
        )
    };
    let backup = "  directory: /var/backups/acl\n  paths: [/srv/app/a]\n";
    let apply_says = apply(backup, acl()).err().map(|e| e.message);
    let plan_says = run_id(Mode::Plan, backup, "run", acl())
        .err()
        .map(|e| e.message);
    assert!(apply_says.is_some(), "apply must refuse it");
    assert!(
        plan_says.is_some(),
        "plan said nothing; apply says {apply_says:?}"
    );
}

/// A refusal of a store names the owner of a directory. A plain resource on that
/// directory has always shown its owner in the metadata diff, which the host tools
/// of MCP keep: a store adds no new way to learn it.
#[test]
fn a_store_learns_nothing_a_resource_does_not() {
    let t = || {
        let mut t = base();
        t.fs.as_mut()
            .unwrap()
            .mkdir_node("/srv/owned", 0o755, 26, 26);
        t
    };
    let store = run_id(
        Mode::Plan,
        "  directory: /srv/owned/s\n  paths: [/srv/app/a]\n",
        "run",
        t(),
    )
    .err()
    .unwrap();
    assert!(store.message.contains("uid 26"), "{}", store.message);
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("r.yaml");
    std::fs::write(
        &p,
        "version: 1\nresources:\n  - id: d\n    type: directory\n    with: { path: /srv/owned, owner: root, state: present }\n",
    )
    .unwrap();
    let r = Engine::new(
        load_model(&p).unwrap(),
        RunOptions {
            mode: Mode::Plan,
            sudo: false,
            target: TargetSpec { ssh: None },
            verbose: false,
            fault: None,
            fake_target: Some(t()),
        },
    )
    .unwrap()
    .run()
    .unwrap();
    let seen = format!("{:?}", r.resources[0].diff);
    assert!(seen.contains("26") || seen.contains("postgres"), "{seen}");
}

mod mcp {
    use serde_json::{json, Value};
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};

    /// One tool call through the real stdio server.
    fn call(name: &str, arguments: Value) -> Value {
        let mut child = Command::new(env!("CARGO_BIN_EXE_sinter"))
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let req = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":arguments}});
        writeln!(stdin, "{req}").unwrap();
        stdin.flush().unwrap();
        let mut line = String::new();
        stdout.read_line(&mut line).unwrap();
        drop(stdin);
        let _ = child.wait();
        serde_json::from_str(&line).unwrap()
    }

    fn manifest(store: &str) -> String {
        format!(
            "version: 1\nvars:\n  token: {{ value: REVIEW_MCP_SECRET, sensitive: true }}\nbackup:\n  directory: {store}\n  paths: [/etc/x]\nresources:\n  - id: a\n    type: file\n    with: {{ path: /srv/a, content: x }}\n"
        )
    }

    #[test]
    fn plan_over_mcp_adds_no_store_detail_and_no_secret() {
        for store in ["/var/backups/s", "/tmp/s", "/var/lib/pgsql/s"] {
            let r = call(
                "sinter_plan",
                json!({"manifest": manifest(store), "target": "ubuntu2404", "sudo": true}),
            );
            let text = r.to_string();
            assert!(!text.contains("REVIEW_MCP_SECRET"), "{text}");
            // The result has no backup section, so a store is not reported as data;
            // a refusal may name the path the caller itself sent.
            let payload = r["result"]["content"][0]["text"].as_str().unwrap_or("");
            assert!(!payload.contains("\"store\""), "{payload}");
            assert!(!payload.contains("\"backup\""), "{payload}");
        }
    }

    #[test]
    fn a_bad_store_is_refused_over_mcp_as_on_the_command_line() {
        for tool in ["sinter_validate_manifest", "sinter_inspect_manifest"] {
            let r = call(tool, json!({"manifest": manifest("/etc/x/y")}));
            let text = r.to_string();
            assert!(text.contains("overlap"), "{tool}: {text}");
            assert!(!text.contains("REVIEW_MCP_SECRET"), "{text}");
        }
    }
}
