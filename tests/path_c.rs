//! Path C: the batched trusted-parent walk (performance WP-P2).
//!
//! # What this protects
//!
//! On a target that has no `getfacl`, every trusted-parent walk observes the
//! ancestors with **one** multi-operand `stat` and, only if every record of it
//! is acceptable, **one** multi-operand `getfattr`. A target that has `getfacl`
//! keeps the sequential walk. These tests pin, through the scripted target:
//!
//! * the exact command order and counts (WP-P0 accounting);
//! * that a walk is fresh each time and that staging and publication stay
//!   behind their own complete walk (Walk 1 / Walk 2 / Walk 3);
//! * that nothing past a failed `stat` gate is queried and that a dispatched
//!   batch is never retried through the sequential walk;
//! * that the branch follows the target's actual `getfacl` capability only,
//!   and that an oversized request is replaced by the sequential walk before
//!   anything is sent;
//! * that sensitive resources and the command statistics reveal nothing new.
//!
//! The batch grammar, the strict parsers, the size guard and the per-ancestor
//! decision matrix are covered by unit tests next to the code
//! (`targetfs::tests::path_c_*`). Real tools, real filesystems and real SSH are
//! covered by the separate Linux acceptance run, not here.
#![cfg(unix)]

use sinter::engine::{AggregateStatus, Engine, Mode, RunOptions, TargetSpec};
use sinter::executor::{Completion, ExecStats, FakeTarget, Output};
use sinter::fakesys::FakeKind;
use sinter::model::load_model;
use std::path::{Path, PathBuf};

/// Commands every run spends before its first resource.
const SETUP_COMMANDS: usize = 6;

/// A named scripted-platform preset.
type Platform = (&'static str, fn() -> FakeTarget);
const TS: &str = "2026-10-02 00:00:01.000000000 +0000";

fn recipe(dir: &tempfile::TempDir, body: &str) -> PathBuf {
    let p = dir.path().join("r.yaml");
    std::fs::write(&p, format!("version: 1\nresources:\n{}", body)).unwrap();
    p
}

fn engine(path: &Path, mode: Mode, sudo: bool, target: FakeTarget) -> Engine {
    let model = load_model(path).unwrap();
    Engine::new(
        model,
        RunOptions {
            mode,
            sudo,
            target: TargetSpec { ssh: None },
            verbose: false,
            fault: None,
            fake_target: Some(target),
        },
    )
    .unwrap()
}

struct Run {
    /// Resource commands (everything after the setup commands).
    commands: usize,
    /// `program basename + args`, for every command after setup, in order.
    trace: Vec<Cmd>,
    stats: ExecStats,
    status: AggregateStatus,
    failed: bool,
    debug: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Cmd {
    program: String,
    args: Vec<String>,
}

impl Cmd {
    fn is_stat_batch(&self) -> bool {
        self.program == "stat"
            && self
                .args
                .first()
                .is_some_and(|a| a.starts_with("--printf="))
    }
    /// A `getfattr` over more than one operand slot is always a batch here; the
    /// single-operand sequential form has exactly one operand, and the file's
    /// own `getfattr` names a file, not a directory chain, so tests tell them
    /// apart by operand count and by the trusted-parent chain they expect.
    fn getfattr_operands(&self) -> Option<&[String]> {
        (self.program == "getfattr").then(|| &self.args[7..])
    }
}

fn run(path: &Path, mode: Mode, sudo: bool, target: FakeTarget) -> Run {
    let e = engine(path, mode, sudo, target);
    let handle = e.exec_stats();
    let setup = handle.snapshot().total();
    assert_eq!(setup, SETUP_COMMANDS, "setup commands");
    let report = e.run().unwrap();
    let trace: Vec<Cmd> = report
        .commands
        .iter()
        .skip(SETUP_COMMANDS)
        .map(|c| Cmd {
            program: c.program.rsplit('/').next().unwrap().to_string(),
            args: c.args.clone(),
        })
        .collect();
    let stats = handle.snapshot();
    Run {
        commands: stats.total() - setup,
        trace,
        failed: report.resources.iter().any(|r| r.is_failure()),
        status: report.status,
        debug: format!("{:?}{:?}", report.commands, stats),
        stats,
    }
}

fn target(with_getfacl: bool, dirs: &[&str]) -> FakeTarget {
    let mut t = FakeTarget::ubuntu2404().with_fake_fs();
    for d in dirs {
        t = t.with_fs_dir(d);
    }
    if with_getfacl {
        t = t.with_executable("/usr/bin/getfacl");
    }
    t
}

fn file_res(id: &str, path: &str, content: &str) -> String {
    format!(
        "  - id: {id}\n    type: file\n    with:\n      path: {path}\n      content: \"{content}\\n\"\n      owner: root\n      group: root\n      mode: \"0644\"\n"
    )
}

fn dir_res(path: &str) -> String {
    format!(
        "  - id: d\n    type: directory\n    with:\n      path: {path}\n      owner: root\n      group: root\n      mode: \"0755\"\n"
    )
}

fn exited(code: i32, stdout: &str, stderr: &str) -> Output {
    Output {
        completion: Completion::Exited(code),
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

fn stat_batch_ok(dirs: &[&str]) -> Output {
    let body: String = dirs
        .iter()
        .map(|d| format!("directory|755|0|0|4096|2049|100|{TS}|{TS}|{d}\0"))
        .collect();
    exited(0, &body, "")
}

fn absent(path: &str) -> Output {
    exited(
        1,
        "",
        &format!("stat: cannot statx '{path}': No such file or directory\n"),
    )
}

const NEW_FILE: &str = "/etc/perf/new.conf";
const NEW_FILE_ANCESTORS: [&str; 3] = ["/", "/etc", "/etc/perf"];

fn new_file_recipe(dir: &tempfile::TempDir) -> PathBuf {
    recipe(dir, &file_res("f", NEW_FILE, "x"))
}

fn position(trace: &[Cmd], pred: impl Fn(&Cmd) -> bool) -> Vec<usize> {
    trace
        .iter()
        .enumerate()
        .filter(|(_, c)| pred(c))
        .map(|(i, _)| i)
        .collect()
}

fn is_walk_getfattr(c: &Cmd) -> bool {
    c.getfattr_operands() == Some(&NEW_FILE_ANCESTORS.map(String::from)[..])
}

// ---------------------------------------------------------------------------
// command counts (WP-P0): MEASURED on the scripted target
// ---------------------------------------------------------------------------

struct Case {
    name: &'static str,
    body: String,
    dirs: Vec<&'static str>,
    seed_file: Option<(&'static str, &'static str)>,
    /// (getfacl absent, getfacl present) resource commands.
    expected: (usize, usize),
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "new file, 3 ancestors",
            body: file_res("f", NEW_FILE, "x"),
            dirs: vec!["/etc/perf"],
            seed_file: None,
            expected: (25, 46),
        },
        Case {
            name: "existing replacement",
            body: file_res("f", "/etc/perf/old.conf", "new"),
            dirs: vec!["/etc/perf"],
            seed_file: Some(("/etc/perf/old.conf", "old\n")),
            expected: (26, 48),
        },
        Case {
            name: "100 new files",
            body: (0..100)
                .map(|i| file_res(&format!("f{i}"), &format!("/etc/perf/n{i}.conf"), "x"))
                .collect(),
            dirs: vec!["/etc/perf"],
            seed_file: None,
            expected: (2500, 4600),
        },
        Case {
            name: "new file, 6 ancestors",
            body: file_res("f", "/etc/a/b/c/d/new.conf", "x"),
            dirs: vec!["/etc/a", "/etc/a/b", "/etc/a/b/c", "/etc/a/b/c/d"],
            seed_file: None,
            expected: (25, 73),
        },
        Case {
            name: "new directory",
            body: dir_res("/etc/perf/newdir"),
            dirs: vec!["/etc/perf"],
            seed_file: None,
            expected: (9, 16),
        },
    ]
}

fn case_target(c: &Case, getfacl: bool) -> FakeTarget {
    let mut t = target(getfacl, &c.dirs);
    if let Some((p, content)) = c.seed_file {
        t = t.with_fs_file(p, content);
    }
    t
}

#[test]
fn command_counts_without_getfacl_drop_to_the_path_c_targets() {
    // Before Path C: 37, 38, 3700, 55, 13 (WP-P0 / WP-P2 baselines).
    for c in cases() {
        let dir = tempfile::tempdir().unwrap();
        let p = recipe(&dir, &c.body);
        let r = run(&p, Mode::Apply, false, case_target(&c, false));
        assert_eq!(r.status, AggregateStatus::Success, "{}", c.name);
        assert_eq!(r.commands, c.expected.0, "{}: getfacl absent", c.name);
        assert_eq!(r.stats.total() - SETUP_COMMANDS, r.commands);
    }
}

#[test]
fn command_counts_with_getfacl_are_exactly_unchanged() {
    // The sequential walk is untouched: 46, 48, 4600, 73, 16.
    for c in cases() {
        let dir = tempfile::tempdir().unwrap();
        let p = recipe(&dir, &c.body);
        let r = run(&p, Mode::Apply, false, case_target(&c, true));
        assert_eq!(r.status, AggregateStatus::Success, "{}", c.name);
        assert_eq!(r.commands, c.expected.1, "{}: getfacl present", c.name);
        assert!(
            r.trace.iter().all(|c| !c.is_stat_batch()),
            "{}: no batched stat",
            c.name
        );
    }
}

#[test]
fn statistics_agree_with_the_log_for_batched_walks() {
    let dir = tempfile::tempdir().unwrap();
    let p = new_file_recipe(&dir);
    let r = run(&p, Mode::Apply, true, target(false, &["/etc/perf"]));
    assert_eq!(
        r.stats.sudo_commands(),
        r.stats.total(),
        "every command under sudo"
    );
    let batches = r.trace.iter().filter(|c| c.is_stat_batch()).count();
    assert_eq!(batches, 3, "one stat batch per walk");
    let stat_total = r.stats.count_program("stat");
    let single = r
        .trace
        .iter()
        .filter(|c| c.program == "stat" && !c.is_stat_batch())
        .count();
    assert_eq!(stat_total, batches + single);
}

// ---------------------------------------------------------------------------
// Walk 1 / Walk 2 / Walk 3
// ---------------------------------------------------------------------------

#[test]
fn each_walk_is_a_fresh_stat_batch_then_getfattr_batch_in_that_order() {
    let dir = tempfile::tempdir().unwrap();
    let p = new_file_recipe(&dir);
    let r = run(&p, Mode::Apply, false, target(false, &["/etc/perf"]));
    assert_eq!(r.status, AggregateStatus::Success);

    let stat_at = position(&r.trace, Cmd::is_stat_batch);
    let getfattr_at = position(&r.trace, is_walk_getfattr);
    assert_eq!(stat_at.len(), 3, "three walks");
    assert_eq!(getfattr_at.len(), 3, "three getfattr batches");
    for (s, g) in stat_at.iter().zip(&getfattr_at) {
        assert_eq!(*g, *s + 1, "getfattr directly follows its own stat batch");
        assert_eq!(
            r.trace[*s].args[2..],
            NEW_FILE_ANCESTORS.map(String::from),
            "the ancestor set is unchanged: root first, parent last"
        );
    }
    // No walk observation survives to the next walk: every walk dispatches its
    // own pair (the pairs above are all distinct requests in the log).
    let stage = position(&r.trace, |c| c.program == "mktemp");
    let publish = position(&r.trace, |c| c.program == "mv");
    assert_eq!(stage.len(), 1);
    assert_eq!(publish.len(), 1);
    // Walk 2 is complete (its getfattr batch is the second) before staging.
    assert!(getfattr_at[1] < stage[0], "Walk 2 completes before staging");
    assert!(
        getfattr_at[0] < getfattr_at[1] && stage[0] < stat_at[2],
        "Walk 3 is a new walk after staging"
    );
    // Walk 3 is complete before publication.
    assert!(
        getfattr_at[2] < publish[0],
        "Walk 3 completes before publication"
    );
    // Nothing is written before Walk 2 and nothing is published before Walk 3.
    for mutation in ["mktemp", "dd", "chown", "chmod", "mv"] {
        for at in position(&r.trace, |c| c.program == mutation) {
            assert!(at > getfattr_at[1], "{mutation} runs after Walk 2");
        }
    }
}

#[test]
fn a_failing_walk_1_stops_everything_before_any_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let p = new_file_recipe(&dir);
    // First stat is the file's own inspection; the second is Walk 1's batch.
    let t = target(false, &["/etc/perf"])
        .with_observations("stat", vec![absent(NEW_FILE), exited(1, "", "boom\n")]);
    let r = run(&p, Mode::Apply, false, t);
    assert!(r.failed);
    assert!(r
        .trace
        .iter()
        .all(|c| !matches!(c.program.as_str(), "mktemp" | "dd" | "mv" | "chown")));
    assert_eq!(
        position(&r.trace, is_walk_getfattr).len(),
        0,
        "no getfattr after a failed stat batch"
    );
}

#[test]
fn a_failing_walk_2_stat_batch_blocks_staging() {
    let dir = tempfile::tempdir().unwrap();
    let p = new_file_recipe(&dir);
    // stat #1 file, #2 Walk 1 batch, #3 file, #4 Walk 2 batch (fails).
    let t = target(false, &["/etc/perf"]).with_observations(
        "stat",
        vec![
            absent(NEW_FILE),
            stat_batch_ok(&NEW_FILE_ANCESTORS),
            absent(NEW_FILE),
            exited(1, "", "stat: cannot statx '/etc/perf': Permission denied\n"),
        ],
    );
    let r = run(&p, Mode::Apply, false, t);
    assert!(r.failed);
    assert_eq!(
        position(&r.trace, Cmd::is_stat_batch).len(),
        2,
        "Walk 1 and the failed Walk 2"
    );
    assert_eq!(
        position(&r.trace, is_walk_getfattr).len(),
        1,
        "no getfattr after the failed Walk 2 stat"
    );
    for mutation in ["mktemp", "dd", "mv", "chown"] {
        assert!(
            position(&r.trace, |c| c.program == mutation).is_empty(),
            "{mutation}"
        );
    }
}

#[test]
fn walk_2_getfattr_failure_or_unsafe_attribute_blocks_staging() {
    let unsafe_block = "# file: /etc\ntrusted.overlay.opaque=0sAAAA\n\n";
    for (what, second) in [
        (
            "non-zero exit",
            exited(1, "", "getfattr: /etc: Permission denied\n"),
        ),
        ("unsafe attribute", exited(0, unsafe_block, "")),
        (
            "system ACL attribute",
            exited(
                0,
                "# file: /etc/perf\nsystem.posix_acl_access=0sAgAAAAEABgD/////\n\n",
                "",
            ),
        ),
        (
            "partial output",
            exited(0, "# file: /etc\ntrusted.x=0sAA==\n", ""),
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let p = new_file_recipe(&dir);
        let t = target(false, &["/etc/perf"])
            .with_observations("getfattr", vec![exited(0, "", ""), second]);
        let r = run(&p, Mode::Apply, false, t);
        assert!(r.failed, "{what}");
        assert!(
            position(&r.trace, |c| c.program == "mktemp").is_empty(),
            "{what}: staging must not begin"
        );
        assert!(
            position(&r.trace, |c| c.program == "mv").is_empty(),
            "{what}"
        );
        assert_eq!(
            position(&r.trace, is_walk_getfattr).len(),
            2,
            "{what}: no third walk, no retry"
        );
    }
}

#[test]
fn walk_3_is_live_and_blocks_publication() {
    // Walk 3 sees a state Walks 1 and 2 did not (an ancestor gained an
    // access-affecting attribute): the final walk refuses and nothing is
    // published, proving it observes afresh and gates the rename.
    for third in [
        exited(
            0,
            "# file: /etc/perf\ntrusted.overlay.opaque=0sAAAA\n\n",
            "",
        ),
        exited(1, "", "getfattr: /etc/perf: Input/output error\n"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let p = new_file_recipe(&dir);
        let t = target(false, &["/etc/perf"]).with_observations(
            "getfattr",
            vec![exited(0, "", ""), exited(0, "", ""), third],
        );
        let r = run(&p, Mode::Apply, false, t);
        assert!(r.failed);
        assert_eq!(position(&r.trace, is_walk_getfattr).len(), 3);
        assert_eq!(
            position(&r.trace, |c| c.program == "mktemp").len(),
            1,
            "staging happened after Walk 2"
        );
        assert!(
            position(&r.trace, |c| c.program == "mv").is_empty(),
            "nothing published"
        );
    }
}

#[test]
fn walk_3_stat_gate_failure_also_blocks_publication() {
    // Unsafe ancestor appears for the last walk only: build the stat queue up
    // to Walk 3's batch from the recorded order of a healthy run.
    let dir = tempfile::tempdir().unwrap();
    let p = new_file_recipe(&dir);
    let healthy = run(&p, Mode::Apply, false, target(false, &["/etc/perf"]));
    let third_batch = position(&healthy.trace, Cmd::is_stat_batch)[2];
    // Replace every earlier stat with the default behaviour by re-serving the
    // scripted filesystem's own answers is not possible through the queue, so
    // script the whole prefix of single-operand stats explicitly.
    let mut queue: Vec<Output> = Vec::new();
    for c in &healthy.trace[..third_batch] {
        if c.program != "stat" {
            continue;
        }
        if c.is_stat_batch() {
            queue.push(stat_batch_ok(&NEW_FILE_ANCESTORS));
            continue;
        }
        let path = c.args.last().unwrap().as_str();
        if path == "/etc/perf" {
            queue.push(exited(
                0,
                &format!("directory|755|0|0|4096|2049|100|{TS}|{TS}\n"),
                "",
            ));
        } else if path == NEW_FILE {
            queue.push(absent(NEW_FILE));
        } else {
            // the staged payload / directory are created only after Walk 2; none
            // is observed before Walk 3's batch in this recipe.
            panic!("unexpected single stat before Walk 3: {path}");
        }
    }
    let bad = "directory|755|0|0|4096|2049|100|TS|TS|/\0symbolic link|777|0|0|4096|2049|100|TS|TS|/etc\0directory|755|0|0|4096|2049|100|TS|TS|/etc/perf\0".replace("TS", TS);
    queue.push(exited(0, &bad, ""));
    let t = target(false, &["/etc/perf"]).with_observations("stat", queue);
    let r = run(&p, Mode::Apply, false, t);
    assert!(r.failed);
    assert_eq!(
        position(&r.trace, |c| c.program == "mktemp").len(),
        1,
        "staged after Walk 2"
    );
    assert!(
        position(&r.trace, |c| c.program == "mv").is_empty(),
        "never published"
    );
    assert_eq!(
        position(&r.trace, is_walk_getfattr).len(),
        2,
        "no getfattr after the failed Walk 3 stat"
    );
}

// ---------------------------------------------------------------------------
// branch selection, fallback, failure contract
// ---------------------------------------------------------------------------

#[test]
fn the_getfacl_capability_alone_selects_the_branch() {
    let dir = tempfile::tempdir().unwrap();
    let p = new_file_recipe(&dir);
    let platforms: [Platform; 4] = [
        ("ubuntu2404", FakeTarget::ubuntu2404),
        ("ubuntu2604", FakeTarget::ubuntu2604),
        ("rocky9", FakeTarget::rocky9),
        ("rocky10", FakeTarget::rocky10),
    ];
    for (name, make) in platforms {
        let build = |getfacl: bool| {
            let t = make().with_fake_fs().with_fs_dir("/etc/perf");
            t.executables_mut_for_test(getfacl)
        };
        let without = run(&p, Mode::Apply, false, build(false));
        let with = run(&p, Mode::Apply, false, build(true));
        assert_eq!(without.commands, 25, "{name}: batched");
        assert_eq!(with.commands, 46, "{name}: sequential");
    }
}

trait GetfaclSwitch {
    fn executables_mut_for_test(self, present: bool) -> Self;
}

impl GetfaclSwitch for FakeTarget {
    /// Make the scripted target's `getfacl` capability exactly `present`
    /// regardless of what the platform preset ships.
    fn executables_mut_for_test(mut self, present: bool) -> Self {
        self.executables.remove("/usr/bin/getfacl");
        if present {
            self.executables.insert("/usr/bin/getfacl".to_string());
        }
        self
    }
}

#[test]
fn an_oversized_walk_falls_back_before_anything_is_dispatched() {
    // A single ancestor name long enough that the completed batch command
    // would exceed the internal guard.
    let long = "d".repeat(20_000);
    let parent = format!("/etc/{long}");
    let file = format!("{parent}/new.conf");
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, &file_res("f", &file, "x"));
    let r = run(&p, Mode::Apply, false, target(false, &[&parent]));
    assert_eq!(r.status, AggregateStatus::Success);
    assert!(
        r.trace.iter().all(|c| !c.is_stat_batch()),
        "the sequential walk was chosen before the first walk command"
    );
    assert!(r
        .trace
        .iter()
        .any(|c| c.program == "stat" && c.args.last() == Some(&parent)));
    // And the same recipe with an ordinary-length name batches.
    let p2 = recipe(&dir, &file_res("f", "/etc/short/new.conf", "x"));
    let r2 = run(&p2, Mode::Apply, false, target(false, &["/etc/short"]));
    assert!(r2.trace.iter().any(Cmd::is_stat_batch));
}

#[test]
fn an_unsafe_ancestor_refuses_in_every_position_and_kind_like_the_sequential_walk() {
    // End to end: the same scripted unsafe ancestor, with getfacl absent
    // (batched) and present (sequential), yields the same failed resource and
    // no mutation. Ancestors: / /etc /etc/a /etc/a/b /etc/a/b/c /etc/a/b/c/d.
    let ancestors = [
        "/",
        "/etc",
        "/etc/a",
        "/etc/a/b",
        "/etc/a/b/c",
        "/etc/a/b/c/d",
    ];
    let file = "/etc/a/b/c/d/new.conf";
    for (ai, a) in ancestors.iter().enumerate() {
        for kind in ["symlink", "owner", "mode", "file"] {
            let mut outcomes = Vec::new();
            for getfacl in [false, true] {
                let mut t = target(
                    getfacl,
                    &["/etc/a", "/etc/a/b", "/etc/a/b/c", "/etc/a/b/c/d"],
                );
                {
                    let fs = t.fs.as_mut().unwrap();
                    let n = fs.nodes.get_mut(*a).unwrap();
                    match kind {
                        "symlink" => {
                            n.kind = FakeKind::Symlink("/elsewhere".to_string());
                            n.mode = 0o777;
                        }
                        "owner" => n.uid = 4242,
                        "mode" => n.mode = 0o775,
                        _ => n.kind = FakeKind::File(b"x".to_vec()),
                    }
                }
                let dir = tempfile::tempdir().unwrap();
                let p = recipe(&dir, &file_res("f", file, "x"));
                let r = run(&p, Mode::Apply, false, t);
                assert!(r.failed, "getfacl={getfacl} {kind} at {ai}");
                for mutation in ["mktemp", "dd", "mv", "chown"] {
                    assert!(
                        position(&r.trace, |c| c.program == mutation).is_empty(),
                        "{mutation} must not run: getfacl={getfacl} {kind} at {ai}"
                    );
                }
                if !getfacl {
                    assert_eq!(
                        position(&r.trace, |c| c.getfattr_operands().is_some()).len(),
                        0,
                        "batched: getfattr never runs when the stat gate fails ({kind} at {ai})"
                    );
                }
                outcomes.push(r.status);
            }
            assert_eq!(
                outcomes[0], outcomes[1],
                "{kind} at {ai}: same verdict in both walks"
            );
        }
    }
}

#[test]
fn plan_mode_is_unaffected_and_audit_style_reads_issue_no_walk() {
    let dir = tempfile::tempdir().unwrap();
    let p = new_file_recipe(&dir);
    for getfacl in [false, true] {
        let r = run(&p, Mode::Plan, false, target(getfacl, &["/etc/perf"]));
        assert_eq!(r.status, AggregateStatus::Success);
        assert!(r
            .trace
            .iter()
            .all(|c| !c.is_stat_batch() && c.getfattr_operands().is_none()));
        assert_eq!(r.commands, 3, "stat, getent passwd, getent group");
    }
}

// ---------------------------------------------------------------------------
// sensitive resources and output
// ---------------------------------------------------------------------------

#[test]
fn sensitive_resources_run_the_batched_walk_without_leaking_anything_new() {
    const CANARY: &str = "SECRET-CANARY-5e1c9b";
    let body = format!(
        "  - id: s\n    type: file\n    sensitive: true\n    with:\n      path: {NEW_FILE}\n      content: \"{CANARY}\\n\"\n      owner: root\n      group: root\n      mode: \"0600\"\n"
    );
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, &body);
    let r = run(&p, Mode::Apply, false, target(false, &["/etc/perf"]));
    assert_eq!(r.status, AggregateStatus::Success);
    assert!(
        r.trace.iter().any(Cmd::is_stat_batch),
        "the walk is batched for a sensitive resource too"
    );
    assert!(
        !r.debug.contains(CANARY),
        "secret content leaked into the log or statistics"
    );
    // The walk request is not marked sensitive and carries no resource value:
    // only the fixed argv and the ancestor list.
    for c in r.trace.iter().filter(|c| c.is_stat_batch()) {
        assert!(c.args.iter().all(|a| !a.contains(CANARY)));
    }
}

#[test]
fn a_refused_walk_reports_no_raw_batch_output() {
    const CANARY: &str = "LEAK-CANARY-77aa";
    let dir = tempfile::tempdir().unwrap();
    let p = new_file_recipe(&dir);
    let t = target(false, &["/etc/perf"]).with_observations(
        "stat",
        vec![
            absent(NEW_FILE),
            exited(
                1,
                &format!("directory|755|0|0|4096|2049|100|{TS}|{TS}|{CANARY}\0"),
                &format!("{CANARY}\n"),
            ),
        ],
    );
    let model = load_model(&p).unwrap();
    let e = Engine::new(
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
    .unwrap();
    let report = e.run().unwrap();
    let shown = format!("{:?}", report.resources);
    assert!(
        !shown.contains(CANARY),
        "raw batch output reached the report: {shown}"
    );
}

#[test]
fn the_batched_walk_does_not_change_ownership_or_mutation_behaviour_of_the_resource() {
    // Same recipe, both branches: identical resulting file system.
    let dir = tempfile::tempdir().unwrap();
    let p = recipe(&dir, &file_res("f", "/etc/perf/old.conf", "new"));
    let mut seen = Vec::new();
    for getfacl in [false, true] {
        let t = target(getfacl, &["/etc/perf"]).with_fs_file("/etc/perf/old.conf", "old\n");
        let e = engine(&p, Mode::Apply, false, t);
        let report = e.run().unwrap();
        assert_eq!(report.status, AggregateStatus::Success);
        let mutations: Vec<String> = report
            .commands
            .iter()
            .filter(|c| {
                ["mktemp", "dd", "chown", "chmod", "mv", "rmdir"]
                    .contains(&c.program.rsplit('/').next().unwrap())
            })
            .map(|c| format!("{} {}", c.program, c.args.join(" ")))
            .collect();
        seen.push(mutations);
    }
    assert_eq!(
        seen[0], seen[1],
        "mutation commands are identical in both branches"
    );
}
