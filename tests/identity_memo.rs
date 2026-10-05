//! Account-lookup memo behavior at the engine level (performance WP-P1).
//!
//! A recipe whose resources share an owner or a group used to repeat
//! `getent passwd <owner>` / `getent group <group>` once per resource. The
//! memo in `TargetFs` answers a repeat of a lookup that already succeeded,
//! as long as nothing that could change the account databases ran in between.
//!
//! These tests run the production engine against the scripted target and
//! assert the commands that really reach the executor (the command log and the
//! WP-P0 statistics), the results, and the cases where the memo must not be
//! used: other hosts and engines, failed or missing lookups, and any mutation.
//! The memo's own contract (namespaces, failures, sensitivity, every mutating
//! helper) is unit-tested in `targetfs::tests`.
#![cfg(unix)]

use sinter::audit::run_audit;
use sinter::engine::{Engine, Mode, RunOptions, RunReport, TargetSpec};
use sinter::executor::{CommandRecord, FakeTarget};
use sinter::model::load_model;
use std::path::{Path, PathBuf};

fn recipe(dir: &tempfile::TempDir, body: &str) -> PathBuf {
    let p = dir.path().join("r.yaml");
    std::fs::write(&p, format!("version: 1\nresources:\n{}", body)).unwrap();
    p
}

fn engine(path: &Path, mode: Mode, target: FakeTarget) -> Engine {
    Engine::new(
        load_model(path).unwrap(),
        RunOptions {
            mode,
            sudo: false,
            target: TargetSpec { ssh: None },
            verbose: false,
            fault: None,
            fake_target: Some(target),
        },
    )
    .unwrap()
}

fn base() -> FakeTarget {
    FakeTarget::ubuntu2404()
        .with_fake_fs()
        .with_fs_dir("/etc/perf")
}

fn app_target() -> FakeTarget {
    base()
        .with_group("app", 990)
        .with_user("app", 990, 990, "/h", "/bin/sh")
}

/// `n` files that do not exist yet, each naming `owner` and/or `group`.
fn new_files(n: usize, owner: Option<&str>, group: Option<&str>) -> String {
    new_files_named("f", n, owner, group)
}

fn new_files_named(prefix: &str, n: usize, owner: Option<&str>, group: Option<&str>) -> String {
    let mut body = String::new();
    for i in 0..n {
        body.push_str(&format!(
            "  - id: {prefix}{i}\n    type: file\n    with:\n      path: /etc/perf/{prefix}{i}.conf\n      content: \"x\\n\"\n"
        ));
        if let Some(o) = owner {
            body.push_str(&format!("      owner: {o}\n"));
        }
        if let Some(g) = group {
            body.push_str(&format!("      group: {g}\n"));
        }
    }
    body
}

/// Every `getent` the run sent, as `"<database> <key>"`, in order. Ordinary
/// file-owner lookups only (`-s files` account observations are separate).
fn lookups(commands: &[CommandRecord]) -> Vec<String> {
    commands
        .iter()
        .filter(|c| {
            c.program.ends_with("getent") && c.args.first().map(|a| a.as_str()) != Some("-s")
        })
        .map(|c| c.args.join(" "))
        .collect()
}

fn count(commands: &[CommandRecord], what: &str) -> usize {
    lookups(commands)
        .iter()
        .filter(|l| l.as_str() == what)
        .count()
}

fn plan(path: &Path, target: FakeTarget) -> RunReport {
    engine(path, Mode::Plan, target)
        .run()
        .unwrap_or_else(|e| panic!("plan: {}", e.message))
}

fn apply(path: &Path, target: FakeTarget) -> RunReport {
    engine(path, Mode::Apply, target)
        .run()
        .unwrap_or_else(|e| panic!("apply: {}", e.message))
}

/// The `chown` operands of an apply: what the engine resolved the identity to.
fn chowns(r: &RunReport) -> Vec<String> {
    r.commands
        .iter()
        .filter(|c| c.program.ends_with("chown"))
        .map(|c| c.args.join(" "))
        .collect()
}

// ---------------------------------------------------------------------------
// A-D: the lookups that disappear, and the ones that must not
// ---------------------------------------------------------------------------

#[test]
fn a_shared_owner_is_looked_up_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(&dir, &new_files(6, Some("app"), None));
    let r = plan(&path, app_target());
    assert_eq!(count(&r.commands, "passwd app"), 1);
    // Without a `group`, a new file takes the owner's primary group: the
    // `passwd 990` lookup is shared as well.
    assert_eq!(count(&r.commands, "passwd 990"), 1);
    assert_eq!(lookups(&r.commands).len(), 2, "{:?}", lookups(&r.commands));
}

#[test]
fn a_shared_group_is_looked_up_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(&dir, &new_files(6, None, Some("app")));
    let r = plan(&path, app_target());
    assert_eq!(lookups(&r.commands), ["group app"]);
}

#[test]
fn a_user_and_a_group_with_the_same_name_stay_distinct() {
    // user `shared` = uid 1001 (primary gid 1001); group `shared` = gid 2002.
    let t = base()
        .with_group("pg", 1001)
        .with_group("shared", 2002)
        .with_user("shared", 1001, 1001, "/h", "/bin/sh");
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(&dir, &new_files(4, Some("shared"), Some("shared")));
    let p = plan(&path, t.clone());
    assert_eq!(lookups(&p.commands), ["passwd shared", "group shared"]);
    // And the resolved numbers are the right ones in every file.
    let a = apply(&path, t);
    assert_eq!(chowns(&a).len(), 4);
    for c in chowns(&a) {
        assert!(c.contains("1001:2002"), "{}", c);
    }
}

#[test]
fn distinct_users_and_groups_still_get_one_lookup_each() {
    let t = app_target()
        .with_group("web", 991)
        .with_user("web", 991, 991, "/h", "/bin/sh");
    let dir = tempfile::tempdir().unwrap();
    let body = new_files_named("a", 3, Some("app"), Some("app"))
        + &new_files_named("w", 3, Some("web"), Some("web"));
    let path = recipe(&dir, &body);
    let r = plan(&path, t);
    let mut l = lookups(&r.commands);
    l.sort();
    assert_eq!(l, ["group app", "group web", "passwd app", "passwd web"]);
}

#[test]
fn audit_shares_the_memo_too() {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(&dir, &new_files(5, Some("app"), Some("app")));
    // Audit resolves owners of files that exist (to compare them).
    let mut t = app_target();
    for i in 0..5 {
        t = t.with_fs_file(&format!("/etc/perf/f{i}.conf"), "x\n");
    }
    let e = engine(&path, Mode::Plan, t);
    let rep = run_audit(e).unwrap();
    assert_eq!(lookups(&rep.commands), ["passwd app", "group app"]);
}

// ---------------------------------------------------------------------------
// E-F: isolation
// ---------------------------------------------------------------------------

#[test]
fn two_engines_and_two_hosts_never_share_an_answer() {
    let host_a = base()
        .with_group("app", 1000)
        .with_user("app", 1000, 1000, "/h", "/bin/sh");
    let host_b = base()
        .with_group("app", 2000)
        .with_user("app", 2000, 2000, "/h", "/bin/sh");
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(&dir, &new_files(2, Some("app"), Some("app")));

    // Sequential engines in one process, alternating hosts and repeating one.
    for (target, want) in [
        (host_a.clone(), "1000:1000"),
        (host_b.clone(), "2000:2000"),
        (host_a.clone(), "1000:1000"),
        (host_b, "2000:2000"),
    ] {
        let r = apply(&path, target);
        let c = chowns(&r);
        assert_eq!(c.len(), 2);
        assert!(c.iter().all(|x| x.contains(want)), "{:?} vs {}", c, want);
        // Every engine pays for its own lookups.
        assert!(count(&r.commands, "passwd app") >= 1);
        assert!(count(&r.commands, "group app") >= 1);
    }

    // Two live engines at once, driven alternately by one thread each.
    let (ea, eb) = (
        engine(&path, Mode::Plan, host_a),
        engine(&path, Mode::Plan, app_target()),
    );
    let (ha, hb) = (ea.exec_stats(), eb.exec_stats());
    let (ra, rb) = (ea.run().unwrap(), eb.run().unwrap());
    assert_eq!(lookups(&ra.commands), ["passwd app", "group app"]);
    assert_eq!(lookups(&rb.commands), ["passwd app", "group app"]);
    assert_eq!(ha.snapshot().count_program("getent"), 2);
    assert_eq!(hb.snapshot().count_program("getent"), 2);
}

// ---------------------------------------------------------------------------
// G-H: failures and missing identities are never reused
// ---------------------------------------------------------------------------

#[test]
fn a_missing_account_is_asked_again_and_found_once_it_exists() {
    // `u` creates `late`; both files depend on it. In plan the account is
    // missing, so both files are deferred and each one asks the target again.
    // In apply the account exists by the time the files run: a cached "not
    // found" would break them.
    let body = "  - id: u\n    type: user\n    with:\n      name: late\n      uid: 4242\n"
        .to_string()
        + "  - id: f0\n    type: file\n    depends_on: [u]\n    with:\n      path: /etc/perf/f0.conf\n      content: \"x\\n\"\n      owner: late\n"
        + "  - id: f1\n    type: file\n    depends_on: [u]\n    with:\n      path: /etc/perf/f1.conf\n      content: \"x\\n\"\n      owner: late\n";
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(&dir, &body);
    let t = base();
    let p = plan(&path, t.clone());
    // The plan asks again on every attempt (the deferral path looks more than
    // once per file); a cached miss would have left a single lookup.
    assert!(
        count(&p.commands, "passwd late") >= 2,
        "a miss is not cached"
    );

    let a = apply(&path, t);
    assert_eq!(a.status, sinter::engine::AggregateStatus::Success);
    let c = chowns(&a);
    assert_eq!(c.len(), 2, "{:?}", c);
    assert!(c.iter().all(|x| x.contains("4242")), "{:?}", c);
}

// ---------------------------------------------------------------------------
// I: mutation invalidation
// ---------------------------------------------------------------------------

/// `f0` is already compliant (owned by `app`), so resolving it reads `app`'s
/// uid and mutates nothing: the memo holds that answer when the account
/// changes. `app` is then deleted and recreated with another uid, and `g1`, a
/// new file owned by `app`, must get the new uid.
fn recreate_app_target() -> FakeTarget {
    let mut t = app_target().with_group("other", 995);
    t.fs.as_mut()
        .unwrap()
        .put_file("/etc/perf/f0.conf", b"x\n", 0o644, 990, 990);
    t.with_executable("/usr/sbin/userdel")
        .with_executable("/usr/sbin/useradd")
}

const F0: &str = "  - id: f0\n    type: file\n    with:\n      path: /etc/perf/f0.conf\n      content: \"x\\n\"\n      owner: app\n";
const G1: &str = "  - id: g1\n    type: file\n    depends_on: [LAST]\n    with:\n      path: /etc/perf/g1.conf\n      content: \"x\\n\"\n      owner: app\n      group: app\n";

fn cmd(id: &str, program: &str, args: &str, dep: Option<&str>) -> String {
    let dep = dep.map_or(String::new(), |d| format!("    depends_on: [{d}]\n"));
    format!(
        "  - id: {id}\n    type: command\n{dep}    with:\n      program: {program}\n      args: [{args}]\n"
    )
}

fn check_uid_follows_recreation(body: String) {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(&dir, &body);
    let a = apply(&path, recreate_app_target());
    assert_eq!(a.status, sinter::engine::AggregateStatus::Success);
    // f0 changes nothing; g1 is the only file written, as the NEW uid.
    let c = chowns(&a);
    assert_eq!(c.len(), 1, "{:?}", c);
    assert!(c[0].contains("995:995"), "stale uid used: {:?}", c);
    // f0 was answered once; the mutation emptied the memo, so g1 (and any
    // later look at the account) asked the target again.
    assert!(
        count(&a.commands, "passwd app") >= 2,
        "{:?}",
        lookups(&a.commands)
    );
}

#[test]
fn a_command_that_deletes_and_recreates_an_account_invalidates_the_memo() {
    check_uid_follows_recreation(format!(
        "{F0}{}{}{}",
        cmd("c1", "/usr/sbin/userdel", "\"app\"", None),
        cmd(
            "c2",
            "/usr/sbin/useradd",
            "\"-u\", \"995\", \"-g\", \"other\", \"-M\", \"app\"",
            Some("c1")
        ),
        G1.replace("LAST", "c2")
            .replace("group: app", "group: other"),
    ));
}

#[test]
fn a_user_resource_that_recreates_an_account_invalidates_the_memo() {
    // The account is removed by a command and re-created by a `user` resource.
    check_uid_follows_recreation(format!(
        "{F0}{}  - id: u\n    type: user\n    depends_on: [c1]\n    with:\n      name: app\n      uid: 995\n      group: other\n{}",
        cmd("c1", "/usr/sbin/userdel", "\"app\"", None),
        G1.replace("LAST", "u").replace("group: app", "group: other"),
    ));
}

#[test]
fn plan_and_audit_hold_no_permit_so_the_memo_lives_for_the_whole_run() {
    let dir = tempfile::tempdir().unwrap();
    let path = recipe(&dir, &new_files(8, Some("app"), Some("app")));
    let p = plan(&path, app_target());
    assert_eq!(lookups(&p.commands), ["passwd app", "group app"]);
}

// ---------------------------------------------------------------------------
// WP-P1 remediation: a sensitive resource never reads or writes the memo,
// including the owner's primary-gid lookup made when `group:` is omitted.
// ---------------------------------------------------------------------------

use sinter::executor::{Completion, ExecStats, Output};

/// One new file or directory owned by `owner`, optionally with `group`.
fn object(kind: &str, id: &str, sensitive: bool, owner: &str, group: Option<&str>) -> String {
    let path = format!("/etc/perf/{id}");
    let mut s = format!("  - id: {id}\n    type: {kind}\n");
    if sensitive {
        s.push_str("    sensitive: true\n");
    }
    s.push_str(&format!("    with:\n      path: {path}\n"));
    if kind == "file" {
        s.push_str("      content: \"x\\n\"\n");
    }
    s.push_str(&format!("      owner: {owner}\n"));
    if let Some(g) = group {
        s.push_str(&format!("      group: {g}\n"));
    }
    s
}

struct Counted {
    report: RunReport,
    stats: ExecStats,
}

fn plan_counted(path: &Path, target: FakeTarget) -> Counted {
    let e = engine(path, Mode::Plan, target);
    let h = e.exec_stats();
    let report = e.run().unwrap_or_else(|e| panic!("plan: {}", e.message));
    Counted {
        report,
        stats: h.snapshot(),
    }
}

/// Lookups a sensitive resource made are redacted placeholders in the log and
/// in the statistics (`[redacted]`), never `getent`.
fn plain_getents(c: &Counted) -> usize {
    c.stats.count_program("getent")
}

fn redacted(c: &Counted) -> usize {
    c.stats.count_program("[redacted]")
}

fn no_sensitive_lookup_is_visible(c: &Counted) {
    // Nothing a sensitive resource asked is logged as a plain lookup of the
    // owner's uid (the primary-gid request used to be).
    for rec in &c.report.commands {
        if rec.sensitive {
            assert_eq!(rec.program, "[redacted]", "{:?}", rec);
            assert!(rec.args.iter().all(|a| !a.contains("990")), "{:?}", rec);
        }
    }
}

/// The four cases the independent audit reproduced, plus a numeric owner.
/// Two sensitive objects sharing an owner: every lookup is made twice.
#[test]
fn sensitive_objects_never_use_the_memo_in_any_lookup() {
    // (kind, group) -> redacted lookups per object: owner + group, or
    // owner + primary gid. Always 2, never memoized.
    for (kind, group) in [
        ("file", Some("app")),      // A: sensitive file, explicit group
        ("file", None),             // B: sensitive file, group omitted
        ("directory", Some("app")), // C: sensitive directory, explicit group
        ("directory", None),        // D: sensitive directory, group omitted
    ] {
        let dir = tempfile::tempdir().unwrap();
        let body = object(kind, "s0", true, "app", group) + &object(kind, "s1", true, "app", group);
        let c = plan_counted(&recipe(&dir, &body), app_target());
        assert_eq!(
            redacted(&c),
            4,
            "{kind} group={group:?}: every lookup is live"
        );
        assert_eq!(plain_getents(&c), 0, "{kind} group={group:?}");
        no_sensitive_lookup_is_visible(&c);
    }
}

#[test]
fn a_numeric_owner_still_looks_up_its_primary_gid_live_when_sensitive() {
    // `owner: 990` needs no owner lookup, but the primary-gid lookup is made
    // for a sensitive resource and must stay out of the memo.
    for kind in ["file", "directory"] {
        let dir = tempfile::tempdir().unwrap();
        let body =
            object(kind, "s0", true, "\"990\"", None) + &object(kind, "s1", true, "\"990\"", None);
        let c = plan_counted(&recipe(&dir, &body), app_target());
        assert_eq!(redacted(&c), 2, "{kind}");
        assert_eq!(plain_getents(&c), 0, "{kind}");
        no_sensitive_lookup_is_visible(&c);
    }
}

#[test]
fn a_sensitive_owner_value_marks_the_primary_gid_lookup_sensitive() {
    // The resource itself is not marked sensitive; its `owner` comes from a
    // sensitive variable. The implicit primary-gid lookup inherits that.
    for kind in ["file", "directory"] {
        let dir = tempfile::tempdir().unwrap();
        let mut body = String::new();
        for id in ["s0", "s1"] {
            body.push_str(&object(kind, id, false, "\"{{ vars.who }}\"", None));
        }
        let p = dir.path().join("r.yaml");
        std::fs::write(
            &p,
            format!("version: 1\nvars:\n  who:\n    value: app\n    sensitive: true\nresources:\n{body}"),
        )
        .unwrap();
        let c = plan_counted(&p, app_target());
        assert_eq!(redacted(&c), 4, "{kind}");
        assert_eq!(plain_getents(&c), 0, "{kind}");
    }
}

/// Ordinary resources still share one lookup each (no regression).
#[test]
fn ordinary_objects_keep_sharing_their_lookups() {
    for kind in ["file", "directory"] {
        let dir = tempfile::tempdir().unwrap();
        let body = object(kind, "o0", false, "app", None)
            + &object(kind, "o1", false, "app", None)
            + &object(kind, "o2", false, "app", None);
        let c = plan_counted(&recipe(&dir, &body), app_target());
        assert_eq!(plain_getents(&c), 2, "{kind}: passwd app + passwd 990");
        assert_eq!(redacted(&c), 0, "{kind}");
    }
}

fn exited(code: i32, out: &str) -> Output {
    Output {
        completion: Completion::Exited(code),
        stdout: out.as_bytes().to_vec(),
        stderr: Vec::new(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

const APP: &str = "app:x:990:990::/h:/bin/sh\n";

/// READ proof. An ordinary resource memoizes `passwd 990`. The target then
/// answers that lookup with garbage: a sensitive resource that really asks
/// again fails the run; one that read the memo would not notice.
#[test]
fn a_sensitive_primary_gid_lookup_does_not_consume_an_ordinary_entry() {
    for kind in ["file", "directory"] {
        let dir = tempfile::tempdir().unwrap();
        let body = object(kind, "o0", false, "app", None) + &object(kind, "s1", true, "app", None);
        let path = recipe(&dir, &body);
        // o0: passwd app, passwd 990.  s1: passwd app (live), passwd 990 (live, garbage).
        let t = app_target().with_observations(
            "getent",
            vec![
                exited(0, APP),
                exited(0, APP),
                exited(0, APP),
                exited(0, "garbage\n"),
            ],
        );
        let e = engine(&path, Mode::Plan, t)
            .run()
            .err()
            .unwrap_or_else(|| panic!("{kind}: the sensitive lookup read the memo"));
        // The failure is redacted for a sensitive resource.
        assert!(!e.message.contains("990"), "{}", e.message);
    }
}

/// WRITE proof. A sensitive resource looks `passwd 990` up first; the target
/// then answers the next such lookup with garbage. An ordinary resource that
/// reused a stored value would not notice; one that asks itself fails.
#[test]
fn a_sensitive_primary_gid_lookup_does_not_feed_an_ordinary_resource() {
    for kind in ["file", "directory"] {
        let dir = tempfile::tempdir().unwrap();
        let body = object(kind, "s0", true, "app", None) + &object(kind, "o1", false, "app", None);
        let path = recipe(&dir, &body);
        // s0: passwd app, passwd 990.  o1: passwd app (live), passwd 990 (live, garbage).
        let t = app_target().with_observations(
            "getent",
            vec![
                exited(0, APP),
                exited(0, APP),
                exited(0, APP),
                exited(0, "garbage\n"),
            ],
        );
        let r = engine(&path, Mode::Plan, t).run();
        assert!(
            r.is_err(),
            "{kind}: an ordinary resource reused a sensitive lookup"
        );
    }
}

/// Counts for the same two orders: nothing is shared across the boundary.
#[test]
fn mixed_sensitivity_objects_each_pay_for_their_own_primary_gid_lookup() {
    for kind in ["file", "directory"] {
        for order in [[false, true], [true, false]] {
            let dir = tempfile::tempdir().unwrap();
            let body = object(kind, "r0", order[0], "app", None)
                + &object(kind, "r1", order[1], "app", None);
            let c = plan_counted(&recipe(&dir, &body), app_target());
            // owner + primary for each of the two objects, none shared.
            assert_eq!(plain_getents(&c) + redacted(&c), 4, "{kind} {order:?}");
            assert_eq!(redacted(&c), 2, "{kind} {order:?}");
            assert_eq!(plain_getents(&c), 2, "{kind} {order:?}");
        }
    }
}
