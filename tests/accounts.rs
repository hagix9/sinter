//! `user` and `group` resource tests.
//!
//! These run the production engine, resource, audit and output code against a
//! scripted in-process target ([`FakeTarget`]) whose local account databases
//! and shadow-utils commands follow the real tools' documented refusals. They
//! prove Sinter's own decisions, argv, ordering, refusals and truthfulness.
//! What only a real Linux host can prove (the exact behavior of
//! `getent -s files`, `useradd`/`usermod`/`userdel`/`groupadd`/`groupdel` on
//! each distribution, real NSS shadowing) is `PENDING REAL-OS ACCEPTANCE` and
//! is not claimed here.
mod common;

use common::*;
use sinter::audit::{AuditReport, AuditResourceStatus};
use sinter::engine::{AggregateStatus, Mode, RunReport};
use sinter::executor::{Completion, FakeTarget, Output};
use sinter::result::{Change, Execution, Verification};
use std::path::{Path, PathBuf};

fn fake() -> FakeTarget {
    FakeTarget::ubuntu2404().with_fake_fs()
}

fn recipe(label: &str, body: &str) -> PathBuf {
    let dir = trusted_root(label);
    write_recipe(&dir, "r.yaml", &format!("version: 1\nresources:\n{}", body))
}

fn plan(r: &Path, t: FakeTarget) -> RunReport {
    run_recipe_fake(r, Mode::Plan, false, t)
}

fn apply(r: &Path, t: FakeTarget) -> RunReport {
    run_recipe_fake(r, Mode::Apply, false, t)
}

fn try_apply(r: &Path, t: FakeTarget) -> Result<RunReport, sinter::error::SinterError> {
    try_run_recipe_fake(r, Mode::Apply, false, t)
}

/// The refusal text of an apply that must not succeed and must not have run
/// an account command: either an engine error or a failed resource's reason.
fn refused_apply(r: &Path, t: FakeTarget) -> String {
    match try_apply(r, t) {
        Err(e) => e.message,
        Ok(rep) => {
            assert_ne!(rep.status, AggregateStatus::Success);
            assert!(account_cmds(&rep).is_empty(), "{:?}", account_cmds(&rep));
            rep.resources
                .iter()
                .filter(|x| x.execution == Execution::Failed)
                .filter_map(|x| x.reason.clone())
                .collect::<Vec<_>>()
                .join("; ")
        }
    }
}

fn try_plan(r: &Path, t: FakeTarget) -> Result<RunReport, sinter::error::SinterError> {
    try_run_recipe_fake(r, Mode::Plan, false, t)
}

fn audit(r: &Path, t: FakeTarget) -> AuditReport {
    let model = sinter::model::load_model(r).unwrap();
    let opts = sinter::engine::RunOptions {
        mode: Mode::Plan,
        sudo: false,
        target: sinter::engine::TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(t),
    };
    let engine = sinter::engine::Engine::new(model, opts).unwrap();
    sinter::audit::run_audit(engine).unwrap()
}

fn afind<'a>(r: &'a AuditReport, id: &str) -> &'a sinter::audit::AuditResourceResult {
    r.resources.iter().find(|x| x.id == id).unwrap()
}

/// Every account-management command the run dispatched: `program arg arg`.
fn account_cmds(r: &RunReport) -> Vec<String> {
    r.commands
        .iter()
        .filter(|c| {
            matches!(
                c.program.rsplit('/').next().unwrap_or(""),
                "useradd" | "usermod" | "userdel" | "groupadd" | "groupdel" | "groupmod"
            )
        })
        .map(|c| format!("{} {}", c.program, c.args.join(" ")))
        .collect()
}

fn group(id: &str, name: &str, extra: &str) -> String {
    format!(
        "  - id: {id}\n    type: group\n    with:\n      name: {name}\n{extra}",
        id = id,
        name = name,
        extra = extra
    )
}

fn user(id: &str, name: &str, with: &str, top: &str) -> String {
    format!(
        "  - id: {id}\n    type: user\n{top}    with:\n      name: {name}\n{with}",
        id = id,
        name = name,
        with = with,
        top = top
    )
}

fn forced(code: i32, stderr: &str) -> Output {
    Output {
        completion: Completion::Exited(code),
        stdout: Vec::new(),
        stderr: stderr.as_bytes().to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

// ---------------------------------------------------------------------------
// group
// ---------------------------------------------------------------------------

#[test]
fn group_plan_reports_a_create_and_mutates_nothing() {
    let r = recipe("g-plan", &group("g", "app", "      gid: 990\n"));
    let rep = plan(&r, fake());
    let g = find(&rep, "g");
    assert_eq!(g.change, Change::Changed);
    assert!(!g.unknown);
    assert_eq!(mutation_command_count(&rep), 0);
    assert!(account_cmds(&rep).is_empty());
}

#[test]
fn group_apply_creates_with_exact_argv_and_verifies() {
    let r = recipe(
        "g-create",
        &group("g", "app", "      gid: 990\n      system: true\n"),
    );
    let rep = apply(&r, fake());
    let g = find(&rep, "g");
    assert_eq!(g.change, Change::Changed);
    assert_eq!(g.verification, Verification::Verified);
    assert_eq!(
        account_cmds(&rep),
        ["/usr/sbin/groupadd --system -g 990 app"]
    );
    assert_success(&rep);
}

#[test]
fn group_default_state_is_present_and_gid_is_optional() {
    let r = recipe("g-min", &group("g", "app", ""));
    let rep = apply(&r, fake());
    assert_eq!(account_cmds(&rep), ["/usr/sbin/groupadd app"]);
    assert_eq!(find(&rep, "g").verification, Verification::Verified);
}

#[test]
fn group_matching_is_idempotent() {
    let r = recipe("g-idem", &group("g", "app", "      gid: 990\n"));
    let rep = apply(&r, fake().with_group("app", 990));
    assert_eq!(find(&rep, "g").change, Change::None);
    assert_eq!(mutation_command_count(&rep), 0);
    assert_success(&rep);
}

#[test]
fn group_gid_mismatch_is_refused_not_renumbered() {
    let r = recipe("g-gid", &group("g", "app", "      gid: 991\n"));
    let t = fake().with_group("app", 990);
    let e = try_plan(&r, t.clone()).err().expect("plan must refuse");
    assert!(e.message.contains("never renumbered"), "{}", e.message);
    let rep = try_apply(&r, t);
    match rep {
        Err(e) => assert!(e.message.contains("never renumbered"), "{}", e.message),
        Ok(rep) => {
            assert_ne!(rep.status, AggregateStatus::Success);
            assert!(account_cmds(&rep).is_empty());
        }
    }
}

#[test]
fn group_create_refuses_a_gid_already_in_use() {
    let r = recipe("g-collide", &group("g", "app", "      gid: 990\n"));
    let t = fake().with_group("other", 990);
    let e = try_plan(&r, t).err().expect("must refuse");
    assert!(e.message.contains("already in use"), "{}", e.message);
}

#[test]
fn group_absent_deletes_without_touching_anything_else() {
    let r = recipe("g-del", &group("g", "app", "      state: absent\n"));
    let rep = apply(&r, fake().with_group("app", 990));
    assert_eq!(account_cmds(&rep), ["/usr/sbin/groupdel app"]);
    let g = find(&rep, "g");
    assert_eq!(g.change, Change::Changed);
    assert_eq!(g.verification, Verification::Verified);
}

#[test]
fn group_absent_when_already_absent_is_unchanged() {
    let r = recipe("g-del2", &group("g", "app", "      state: absent\n"));
    let rep = apply(&r, fake());
    assert_eq!(find(&rep, "g").change, Change::None);
    assert_eq!(mutation_command_count(&rep), 0);
}

#[test]
fn group_absent_refuses_a_users_primary_group() {
    let r = recipe("g-del3", &group("g", "app", "      state: absent\n"));
    let t = fake()
        .with_group("app", 990)
        .with_user("svc", 990, 990, "/h", "/bin/sh");
    let e = try_plan(&r, t).err().expect("must refuse");
    assert!(e.message.contains("primary group"), "{}", e.message);
    assert!(e.message.contains("svc"), "{}", e.message);
}

#[test]
fn group_absent_refuses_the_root_group() {
    let r = recipe("g-del4", &group("g", "root", "      state: absent\n"));
    let e = try_plan(&r, fake()).err().expect("must refuse");
    assert!(e.message.contains("root group"), "{}", e.message);
}

#[test]
fn group_provided_only_by_nss_is_an_error_never_a_create() {
    let r = recipe("g-nss", &group("g", "corp", ""));
    let mut t = fake();
    t.accounts.nss_groups.push(sinter::fakesys::FakeGroup {
        name: "corp".into(),
        gid: 5000,
        members: vec![],
    });
    let m = refused_apply(&r, t.clone());
    assert!(m.contains("non-local"), "{}", m);
    let rep = audit(&r, t);
    assert_eq!(afind(&rep, "g").status, AuditResourceStatus::Error);
}

#[test]
fn group_local_lookup_that_getent_cannot_do_fails_closed() {
    let r = recipe("g-nolookup", &group("g", "app", ""));
    let mut t = fake();
    t.accounts.files_lookup_fails = Some(Completion::Exited(1));
    let m = refused_apply(&r, t);
    assert!(m.contains("failed unexpectedly"), "{}", m);
}

#[test]
fn group_failed_command_is_reported_as_possible_change_and_fails_dependents() {
    let r = recipe(
        "g-fail",
        &format!(
            "{}{}",
            group("g", "app", ""),
            "  - id: after\n    type: command\n    with:\n      program: /bin/true\n    depends_on: [g]\n"
        ),
    );
    let mut t = fake();
    t.accounts.forced.insert(
        "groupadd".into(),
        forced(10, "groupadd: cannot lock /etc/group"),
    );
    let rep = apply(&r, t);
    let g = find(&rep, "g");
    assert_eq!(g.execution, Execution::Failed);
    assert_eq!(g.change, Change::Possible);
    assert_eq!(g.verification, Verification::Unknown);
    assert!(g.reason.as_deref().unwrap().contains("cannot lock"));
    assert_ne!(find(&rep, "after").execution, Execution::Succeeded);
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
}

#[test]
fn group_success_without_effect_fails_verification() {
    let r = recipe("g-verify", &group("g", "app", ""));
    let mut t = fake();
    t.accounts.forced.insert("groupadd".into(), forced(0, ""));
    let rep = apply(&r, t);
    let g = find(&rep, "g");
    assert_eq!(g.change, Change::Changed);
    assert_eq!(g.execution, Execution::Failed);
    assert_eq!(g.verification, Verification::Failed);
}

#[test]
fn group_audit_dimensions() {
    let body = format!(
        "{}{}{}",
        group("ok", "okg", "      gid: 700\n"),
        group("missing", "nog", ""),
        group("wrong", "wrongg", "      gid: 801\n"),
    );
    let r = recipe("g-audit", &body);
    let t = fake().with_group("okg", 700).with_group("wrongg", 800);
    let rep = audit(&r, t);
    assert_eq!(afind(&rep, "ok").status, AuditResourceStatus::Compliant);
    let m = afind(&rep, "missing");
    assert_eq!(m.status, AuditResourceStatus::Drift);
    assert_eq!(m.details[0].dimension, "state");
    let w = afind(&rep, "wrong");
    assert_eq!(w.status, AuditResourceStatus::Drift);
    assert_eq!(w.details[0].dimension, "gid");
    assert_eq!(
        (
            w.details[0].observed.as_str(),
            w.details[0].desired.as_str()
        ),
        ("800", "801")
    );
}

#[test]
fn group_absent_audit_reports_a_present_group_as_drift() {
    let r = recipe("g-audit2", &group("g", "app", "      state: absent\n"));
    let rep = audit(&r, fake().with_group("app", 990));
    assert_eq!(afind(&rep, "g").status, AuditResourceStatus::Drift);
}

// ---------------------------------------------------------------------------
// group / user validation
// ---------------------------------------------------------------------------

fn load_err(label: &str, body: &str) -> String {
    let r = recipe(label, body);
    sinter::model::load_model(&r)
        .err()
        .unwrap_or_else(|| panic!("expected a validation error for {}", label))
        .message
}

#[test]
fn account_names_are_validated() {
    for (i, bad) in [
        "App", "9x", "-x", "a:b", "a,b", "a b", "root;id", "$(id)", "a/b", "1000", "",
    ]
    .iter()
    .enumerate()
    {
        let m = load_err(
            &format!("bad-name-{}", i),
            &group("g", &format!("{:?}", bad), ""),
        );
        assert!(
            m.contains("name") || m.contains("empty"),
            "{:?}: {}",
            bad,
            m
        );
    }
}

#[test]
fn account_ids_are_range_checked_and_root_ids_are_never_declarable() {
    for v in ["0", "-1", "4294967295", "\"x\"", "1.5"] {
        let m = load_err(
            &format!("bad-gid-{}", v.len()),
            &group("g", "app", &format!("      gid: {}\n", v)),
        );
        assert!(m.contains("gid"), "{}: {}", v, m);
    }
    let m = load_err("bad-uid", &user("u", "app", "      uid: 0\n", ""));
    assert!(m.contains("uid"), "{}", m);
}

#[test]
fn unsupported_fields_are_rejected() {
    for f in [
        "password",
        // `password_hash` is supported since Phase D, as a secret reference
        // only (tests/password_hash.rs): a bare value is a schema error there.
        "locked",
        "expires",
        "ssh_keys",
        "move_home",
        "remove_home",
        "force",
        "non_unique",
        "comment",
        "append",
    ] {
        let m = load_err(
            &format!("field-{}", f),
            &user("u", "app", &format!("      {}: x\n", f), ""),
        );
        assert!(m.contains("unknown field"), "{}: {}", f, m);
    }
    let m = load_err("gfield", &group("g", "app", "      members: [a]\n"));
    assert!(m.contains("unknown field"), "{}", m);
}

#[test]
fn user_paths_and_groups_are_validated() {
    for (i, w) in [
        "      shell: nologin\n",
        "      shell: /a:b\n",
        "      home: relative\n",
        "      home: /\n",
        "      home: \"/a/../b\"\n",
        "      group: \"Bad Group\"\n",
        "      groups: [\"a,b\"]\n",
        "      groups: [a, a]\n",
        "      group: a\n      groups: [a]\n",
        "      state: maybe\n",
        "      create_home: \"yes\"\n",
    ]
    .iter()
    .enumerate()
    {
        let m = load_err(&format!("user-val-{}", i), &user("u", "app", w, ""));
        assert!(!m.is_empty(), "{}", w);
    }
}

#[test]
fn two_resources_may_not_manage_the_same_account() {
    let m = load_err(
        "dup",
        &format!("{}{}", group("a", "app", ""), group("b", "app", "")),
    );
    assert!(m.contains("conflicting ownership"), "{}", m);
    // A user and a group of the same name are different objects.
    let r = recipe(
        "dup-ok",
        &format!("{}{}", group("a", "app", ""), user("b", "app", "", "")),
    );
    assert!(sinter::model::load_model(&r).is_ok());
}

// ---------------------------------------------------------------------------
// user
// ---------------------------------------------------------------------------

#[test]
fn user_minimal_create_is_explicit_about_the_home_directory() {
    let r = recipe("u-min", &user("u", "svc", "", ""));
    let rep = apply(&r, fake());
    assert_eq!(account_cmds(&rep), ["/usr/sbin/useradd -M svc"]);
    let u = find(&rep, "u");
    assert_eq!(u.change, Change::Changed);
    assert_eq!(u.verification, Verification::Verified);
}

#[test]
fn user_full_create_uses_exact_argv() {
    let w = "      uid: 990\n      group: app\n      groups: [wheel, adm]\n      shell: /usr/sbin/nologin\n      home: /var/lib/app\n      create_home: true\n      system: true\n";
    let r = recipe("u-full", &user("u", "app", w, ""));
    let t = fake()
        .with_group("app", 990)
        .with_group("wheel", 10)
        .with_group("adm", 4);
    let rep = apply(&r, t);
    assert_eq!(
        account_cmds(&rep),
        ["/usr/sbin/useradd --system -u 990 -g app -G wheel,adm -s /usr/sbin/nologin -d /var/lib/app -m app"]
    );
    assert_eq!(find(&rep, "u").verification, Verification::Verified);
}

#[test]
fn user_matching_is_idempotent_and_unmanaged_dimensions_are_ignored() {
    let w = "      uid: 990\n      shell: /usr/sbin/nologin\n";
    let r = recipe("u-idem", &user("u", "app", w, ""));
    // The home, the primary group and memberships are not declared: whatever
    // they are, they are not touched.
    let t = fake()
        .with_group("grp", 50)
        .with_user("app", 990, 50, "/anywhere", "/usr/sbin/nologin")
        .with_membership("grp", "app");
    let rep = apply(&r, t);
    assert_eq!(find(&rep, "u").change, Change::None);
    assert_eq!(mutation_command_count(&rep), 0);
}

#[test]
fn user_update_is_one_usermod_and_membership_is_additive() {
    let w = "      group: app\n      groups: [wheel]\n      shell: /usr/sbin/nologin\n      home: /srv/app\n";
    let r = recipe("u-upd", &user("u", "app", w, ""));
    let t = fake()
        .with_group("app", 990)
        .with_group("wheel", 10)
        .with_group("keep", 20)
        .with_user("app", 990, 20, "/var/lib/app", "/bin/sh")
        .with_membership("keep", "app");
    let rep = apply(&r, t);
    assert_eq!(
        account_cmds(&rep),
        ["/usr/sbin/usermod -g app -s /usr/sbin/nologin -d /srv/app -a -G wheel app"]
    );
    let cmd = &account_cmds(&rep)[0];
    for forbidden in [" -m", " -r", " -f", " -u ", " -l ", " -o"] {
        assert!(!cmd.contains(forbidden), "{} in {}", forbidden, cmd);
    }
    assert_eq!(find(&rep, "u").verification, Verification::Verified);
}

#[test]
fn user_already_a_member_needs_no_usermod() {
    let r = recipe("u-member", &user("u", "app", "      groups: [wheel]\n", ""));
    let t = fake()
        .with_group("wheel", 10)
        .with_user("app", 990, 990, "/h", "/bin/sh")
        .with_membership("wheel", "app");
    let rep = apply(&r, t);
    assert_eq!(find(&rep, "u").change, Change::None);
    assert!(account_cmds(&rep).is_empty());
}

#[test]
fn user_uid_mismatch_is_refused_and_nothing_is_run() {
    let r = recipe("u-uid", &user("u", "app", "      uid: 991\n", ""));
    let t = fake().with_user("app", 990, 990, "/h", "/bin/sh");
    let e = try_plan(&r, t.clone()).err().expect("plan must refuse");
    assert!(e.message.contains("never renumbered"), "{}", e.message);
    match try_apply(&r, t) {
        Err(e) => assert!(e.message.contains("never renumbered")),
        Ok(rep) => {
            assert!(account_cmds(&rep).is_empty());
            assert_ne!(rep.status, AggregateStatus::Success);
        }
    }
}

#[test]
fn user_create_refuses_a_uid_already_in_use() {
    let r = recipe("u-uidcol", &user("u", "app", "      uid: 990\n", ""));
    let t = fake().with_user("other", 990, 990, "/h", "/bin/sh");
    let e = try_plan(&r, t).err().expect("must refuse");
    assert!(e.message.contains("already in use"), "{}", e.message);
}

#[test]
fn user_with_a_missing_group_and_no_dependency_is_an_error() {
    let r = recipe("u-nogrp", &user("u", "app", "      group: ghost\n", ""));
    let e = try_plan(&r, fake()).err().expect("must fail");
    assert!(e.message.contains("does not exist"), "{}", e.message);
    assert!(e.message.contains("depends_on"), "{}", e.message);
    let m = refused_apply(&r, fake());
    assert!(m.contains("does not exist"), "{}", m);
}

#[test]
fn group_then_user_with_depends_on_plans_deferred_and_applies_in_order() {
    let body = format!(
        "{}{}",
        group("g", "app", "      gid: 990\n"),
        user(
            "u",
            "app",
            "      uid: 990\n      group: app\n",
            "    depends_on: [g]\n"
        )
    );
    let r = recipe("g-u", &body);
    let p = plan(&r, fake());
    assert_eq!(find(&p, "g").change, Change::Changed);
    let pu = find(&p, "u");
    assert!(pu.unknown, "user must be deferred in plan");
    assert!(pu.reason.as_deref().unwrap().contains("deferred"));
    assert_eq!(mutation_command_count(&p), 0);

    let a = apply(&r, fake());
    assert_success(&a);
    assert_eq!(
        account_cmds(&a),
        [
            "/usr/sbin/groupadd -g 990 app",
            "/usr/sbin/useradd -u 990 -g app -M app"
        ]
    );
    assert_eq!(find(&a, "u").verification, Verification::Verified);
}

#[test]
fn a_group_that_runs_earlier_is_known_to_plan_without_depends_on() {
    // F-3. The group is declared before the user and the user does not list
    // it: apply finds the group (it ran first), so plan defers instead of
    // reporting an error apply would never give. No dependency is added.
    let body = format!(
        "{}{}",
        group("g", "app", ""),
        user("u", "app", "      group: app\n", "")
    );
    let r = recipe("u-earlier", &body);
    let p = plan(&r, fake());
    assert_eq!(find(&p, "g").change, Change::Changed);
    let pu = find(&p, "u");
    assert!(pu.unknown, "the user is deferred, not an error");
    assert!(
        pu.reason.as_deref().unwrap().contains("runs earlier"),
        "{:?}",
        pu.reason
    );
    assert_eq!(mutation_command_count(&p), 0);
    // Apply does exactly what the plan expected: the group, then the user.
    let a = apply(&r, fake());
    assert_success(&a);
    assert_eq!(
        account_cmds(&a),
        ["/usr/sbin/groupadd app", "/usr/sbin/useradd -g app -M app"]
    );
}

#[test]
fn a_group_that_runs_later_is_still_a_plan_error_as_it_is_an_apply_error() {
    // The user is declared before the group and does not list it: Sinter
    // neither reorders nor infers. Plan and apply both refuse.
    let body = format!(
        "{}{}",
        user("u", "app", "      group: app\n", ""),
        group("g", "app", "")
    );
    let r = recipe("u-later", &body);
    let e = try_plan(&r, fake()).err().expect("plan must refuse");
    assert!(e.message.contains("does not exist"), "{}", e.message);
    assert!(e.message.contains("depends_on"), "{}", e.message);
    let m = refused_apply(&r, fake());
    assert!(m.contains("does not exist"), "{}", m);
    // Listing the group moves it first: plan defers and apply succeeds.
    let body = format!(
        "{}{}",
        user("u", "app", "      group: app\n", "    depends_on: [g]\n"),
        group("g", "app", "")
    );
    let r = recipe("u-later-listed", &body);
    assert!(find(&plan(&r, fake()), "u").unknown);
    assert_success(&apply(&r, fake()));
}

#[test]
fn file_owner_naming_a_created_user_is_deferred_only_with_explicit_depends_on() {
    let dir = trusted_root("owner-defer");
    // A directory that exists on the scripted target: plan runs apply's
    // parent path check for the planned file.
    let target = std::path::Path::new("/etc/app/conf");
    let owned = |deps: &str| {
        format!(
            "{}  - id: f\n    type: file\n{}    with:\n      path: {}\n      content: x\n      owner: svcacct\n",
            user("u", "svcacct", "", ""),
            deps,
            target.display()
        )
    };
    // Without depends_on, the user declared first: it runs first, so plan
    // defers the file as apply will find the account (F-3).
    let r = write_recipe(
        &dir,
        "no.yaml",
        &format!("version: 1\nresources:\n{}", owned("")),
    );
    let p = try_plan(&r, fake()).expect("an earlier producer is known to plan");
    let f = find(&p, "f");
    assert!(f.unknown);
    assert!(f.reason.as_deref().unwrap().contains("runs earlier"));
    // Without depends_on, the file declared first: nothing is inferred or
    // reordered, the plan error stays (and apply fails the same way).
    let later = format!(
        "  - id: f\n    type: file\n    with:\n      path: {}\n      content: x\n      owner: svcacct\n{}",
        target.display(),
        user("u", "svcacct", "", "")
    );
    let r = write_recipe(
        &dir,
        "later.yaml",
        &format!("version: 1\nresources:\n{}", later),
    );
    let e = try_plan(&r, fake()).err().expect("must fail");
    assert!(e.message.contains("unknown user"), "{}", e.message);
    let m = refused_apply(&r, fake());
    assert!(m.contains("unknown user"), "{}", m);

    // With depends_on: the user is planned, the file is deferred.
    let r = write_recipe(
        &dir,
        "yes.yaml",
        &format!("version: 1\nresources:\n{}", owned("    depends_on: [u]\n")),
    );
    let p = try_plan(&r, fake()).expect("deferred plan must succeed");
    assert_eq!(find(&p, "u").change, Change::Changed);
    let f = find(&p, "f");
    assert!(f.unknown);
    assert!(f
        .reason
        .as_deref()
        .unwrap()
        .contains("created by a dependency"));
    assert_eq!(mutation_command_count(&p), 0);

    // The account exists already: the file plans normally.
    let p = try_plan(&r, fake().with_user("svcacct", 990, 990, "/h", "/bin/sh")).expect("plan");
    assert!(!find(&p, "f").unknown);
}

#[test]
fn file_group_naming_a_created_group_is_deferred_with_explicit_depends_on() {
    let dir = trusted_root("group-defer");
    let target = dir.join("conf");
    let body = format!(
        "{}  - id: f\n    type: file\n    depends_on: [g]\n    with:\n      path: {}\n      content: x\n      group: svcgrp\n",
        group("g", "svcgrp", ""),
        target.display()
    );
    let r = write_recipe(&dir, "r.yaml", &format!("version: 1\nresources:\n{}", body));
    let p = try_plan(&r, fake()).expect("plan");
    assert!(find(&p, "f").unknown);
}

#[test]
fn consumer_of_a_deferred_user_is_unknown_not_unchanged() {
    // A dependent of an unknown resource is unknown (existing propagation).
    let body = format!(
        "{}{}  - id: tail\n    type: command\n    with:\n      program: /bin/true\n    depends_on: [u]\n",
        group("g", "app", ""),
        user("u", "app", "      group: app\n", "    depends_on: [g]\n")
    );
    let r = recipe("chain", &body);
    let p = plan(&r, fake());
    assert!(find(&p, "u").unknown);
    assert!(find(&p, "tail").unknown);
}

#[test]
fn user_absent_deletes_without_removing_the_home_or_files() {
    let r = recipe("u-del", &user("u", "svc", "      state: absent\n", ""));
    let t = fake().with_user("svc", 990, 50, "/home/svc", "/bin/sh");
    let p = plan(&r, t.clone());
    assert_eq!(find(&p, "u").change, Change::Changed);
    assert!(find(&p, "u")
        .notes
        .iter()
        .any(|n| n.contains("home directory and mail spool are kept")));
    assert_eq!(mutation_command_count(&p), 0);

    let rep = apply(&r, t);
    assert_eq!(account_cmds(&rep), ["/usr/sbin/userdel svc"]);
    let u = find(&rep, "u");
    assert_eq!(u.verification, Verification::Verified);
    assert!(u.notes.iter().any(|n| n.contains("were kept")));
    assert!(u.notes.iter().any(|n| n.contains("uid 990 remain")));
}

#[test]
fn user_absent_when_already_absent_is_unchanged() {
    let r = recipe("u-del2", &user("u", "svc", "      state: absent\n", ""));
    let rep = apply(&r, fake());
    assert_eq!(find(&rep, "u").change, Change::None);
    assert_eq!(mutation_command_count(&rep), 0);
}

#[test]
fn user_absent_reports_the_private_group_userdel_removed() {
    let r = recipe("u-del3", &user("u", "svc", "      state: absent\n", ""));
    let t = fake()
        .with_group("svc", 990)
        .with_user("svc", 990, 990, "/home/svc", "/bin/sh");
    let rep = apply(&r, t);
    let u = find(&rep, "u");
    assert_eq!(u.verification, Verification::Verified);
    assert!(
        u.notes.iter().any(|n| n.contains("private group svc")),
        "{:?}",
        u.notes
    );
}

#[test]
fn user_absent_refuses_root_and_the_executing_and_session_accounts() {
    // root
    let r = recipe(
        "u-del-root",
        &user("u", "root", "      state: absent\n", ""),
    );
    let e = try_plan(&r, fake()).err().expect("root");
    assert!(e.message.contains("root"), "{}", e.message);
    // the account this run executes as (uid 1000 of the fake)
    let r = recipe(
        "u-del-me",
        &user("u", "fakeuser", "      state: absent\n", ""),
    );
    let e = try_plan(&r, fake()).err().expect("self");
    assert!(
        e.message.contains("refusing to delete user"),
        "{}",
        e.message
    );
    // under --sudo the effective user is root, but the session user is still
    // protected
    let model = sinter::model::load_model(&r).unwrap();
    let opts = sinter::engine::RunOptions {
        mode: Mode::Plan,
        sudo: true,
        target: sinter::engine::TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(fake()),
    };
    let e = sinter::engine::Engine::new(model, opts)
        .unwrap()
        .run()
        .err()
        .expect("session user");
    assert!(e.message.contains("session"), "{}", e.message);
}

#[test]
fn user_with_running_processes_fails_truthfully() {
    let r = recipe("u-busy", &user("u", "svc", "      state: absent\n", ""));
    let mut t = fake().with_user("svc", 990, 50, "/home/svc", "/bin/sh");
    t.accounts.running_users.insert("svc".into());
    let rep = apply(&r, t);
    let u = find(&rep, "u");
    assert_eq!(u.execution, Execution::Failed);
    assert_eq!(u.change, Change::Possible);
    assert_eq!(u.verification, Verification::Unknown);
    assert!(u
        .reason
        .as_deref()
        .unwrap()
        .contains("currently used by process"));
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
}

#[test]
fn user_failure_after_effect_still_reports_possible_change() {
    let r = recipe("u-partial", &user("u", "svc", "", ""));
    let mut t = fake();
    t.accounts.fail_after_effect.insert("useradd".into());
    let rep = apply(&r, t);
    let u = find(&rep, "u");
    assert_eq!(u.execution, Execution::Failed);
    assert_eq!(u.change, Change::Possible);
}

#[test]
fn user_success_without_effect_fails_verification() {
    let r = recipe("u-noeffect", &user("u", "svc", "", ""));
    let mut t = fake();
    t.accounts.forced.insert("useradd".into(), forced(0, ""));
    let rep = apply(&r, t);
    let u = find(&rep, "u");
    assert_eq!(u.change, Change::Changed);
    assert_eq!(u.verification, Verification::Failed);
}

#[test]
fn failed_user_stops_its_dependents() {
    let body = format!(
        "{}  - id: f\n    type: command\n    with:\n      program: /bin/true\n    depends_on: [u]\n",
        user("u", "svc", "", "")
    );
    let r = recipe("u-dep-fail", &body);
    let mut t = fake();
    t.accounts
        .forced
        .insert("useradd".into(), forced(1, "boom"));
    let rep = apply(&r, t);
    assert_ne!(find(&rep, "f").execution, Execution::Succeeded);
}

#[test]
fn user_provided_only_by_nss_is_never_created() {
    let r = recipe("u-nss", &user("u", "corpuser", "", ""));
    let mut t = fake();
    t.accounts.nss_users.push(sinter::fakesys::FakeUser {
        name: "corpuser".into(),
        uid: 5000,
        gid: 5000,
        home: "/home/corpuser".into(),
        shell: "/bin/bash".into(),
    });
    let m = refused_apply(&r, t.clone());
    assert!(m.contains("non-local"), "{}", m);
    assert_eq!(afind(&audit(&r, t), "u").status, AuditResourceStatus::Error);
}

#[test]
fn user_audit_reports_each_declared_dimension_independently() {
    let w = "      uid: 990\n      group: app\n      groups: [wheel]\n      shell: /usr/sbin/nologin\n      home: /var/lib/app\n";
    let r = recipe("u-audit", &user("u", "app", w, ""));
    let t = fake()
        .with_group("app", 990)
        .with_group("other", 50)
        .with_group("wheel", 10)
        .with_user("app", 991, 50, "/home/app", "/bin/bash");
    let rep = audit(&r, t);
    let u = afind(&rep, "u");
    assert_eq!(u.status, AuditResourceStatus::Drift);
    let dims: Vec<&str> = u.details.iter().map(|d| d.dimension.as_str()).collect();
    assert_eq!(dims, ["uid", "group", "shell", "home", "groups"]);
}

#[test]
fn user_audit_compliant_absent_and_missing() {
    let body = format!(
        "{}{}{}",
        user("ok", "okuser", "      shell: /bin/sh\n", ""),
        user("gone", "gone", "      state: absent\n", ""),
        user("missing", "nouser", "", ""),
    );
    let r = recipe("u-audit2", &body);
    let t = fake().with_user("okuser", 700, 700, "/h", "/bin/sh");
    let rep = audit(&r, t);
    assert_eq!(afind(&rep, "ok").status, AuditResourceStatus::Compliant);
    assert_eq!(afind(&rep, "gone").status, AuditResourceStatus::Compliant);
    assert_eq!(afind(&rep, "missing").status, AuditResourceStatus::Drift);
}

#[test]
fn user_audit_with_a_missing_group_is_drift_not_an_error() {
    let r = recipe("u-audit3", &user("u", "app", "      groups: [ghost]\n", ""));
    let t = fake().with_user("app", 700, 700, "/h", "/bin/sh");
    let rep = audit(&r, t);
    assert_eq!(afind(&rep, "u").status, AuditResourceStatus::Drift);
}

#[test]
fn audit_and_plan_never_run_an_account_mutation() {
    let body = format!(
        "{}{}",
        group("g", "app", ""),
        user("u", "app", "      group: app\n", "    depends_on: [g]\n")
    );
    let r = recipe("readonly", &body);
    let rep = audit(&r, fake());
    for c in &rep.commands {
        assert!(
            !is_mutation_command(&c.program, &c.args),
            "audit mutated: {} {:?}",
            c.program,
            c.args
        );
    }
    let p = plan(&r, fake());
    assert!(account_cmds(&p).is_empty());
}

#[test]
fn interpolated_and_looped_names_resolve_before_use() {
    let r = recipe(
        "loop",
        "  - id: g\n    type: group\n    with:\n      name: \"svc-{{ item }}\"\n    loop: [a, b]\n",
    );
    let rep = apply(&r, fake());
    assert_eq!(
        account_cmds(&rep),
        ["/usr/sbin/groupadd svc-a", "/usr/sbin/groupadd svc-b"]
    );
}

#[test]
fn sensitive_account_resources_redact_names_in_commands_and_errors() {
    let body = "  - id: u\n    type: user\n    sensitive: true\n    with:\n      name: topsecretname\n      uid: 990\n";
    let r = recipe("sens", body);
    let rep = apply(&r, fake());
    let u = find(&rep, "u");
    let shown = format!("{:?} {:?}", u.reason, u.notes);
    assert!(!shown.contains("topsecretname"));
    for c in &rep.commands {
        let line = format!("{} {:?}", c.program, c.args);
        assert!(
            !line.contains("topsecretname") || c.program == "[redacted]",
            "{}",
            line
        );
    }
    let e = try_plan(
        &recipe(
            "sens2",
            "  - id: u\n    type: user\n    sensitive: true\n    with:\n      name: topsecretname\n      uid: 990\n",
        ),
        fake().with_user("other", 990, 990, "/h", "/bin/sh"),
    )
    .err()
    .expect("collision");
    assert!(!e.message.contains("topsecretname"), "{}", e.message);
}

#[test]
fn account_commands_are_fixed_executables_with_argv_only() {
    let w = "      group: app\n      groups: [wheel]\n      shell: /usr/sbin/nologin\n      home: /var/lib/app\n      create_home: true\n";
    let r = recipe("argv", &user("u", "app", w, ""));
    let t = fake().with_group("app", 990).with_group("wheel", 10);
    let rep = apply(&r, t);
    for c in rep.commands.iter().filter(|c| {
        matches!(
            c.program.rsplit('/').next().unwrap(),
            "useradd" | "usermod" | "userdel" | "groupadd" | "groupdel"
        )
    }) {
        assert!(c.program.starts_with("/usr/sbin/"), "{}", c.program);
        assert!(
            !c.args
                .iter()
                .any(|a| a.contains(' ') || a.contains(';') || a.contains('$')),
            "shell-looking argument: {:?}",
            c.args
        );
    }
    assert!(!rep
        .commands
        .iter()
        .any(|c| c.program.ends_with("/sh") || c.program.ends_with("/bash")));
}

#[test]
fn local_lookup_is_always_files_only_before_any_decision() {
    let r = recipe("files-only", &user("u", "app", "", ""));
    let rep = apply(&r, fake());
    let first = rep
        .commands
        .iter()
        .find(|c| c.program == "/usr/bin/getent" && c.args.iter().any(|a| a == "app"))
        .expect("a lookup of the account");
    assert_eq!(first.args, ["-s", "files", "passwd", "app"]);
}

#[test]
fn service_account_unit_group_user_directory_file_applies_end_to_end() {
    // The Gateway-style unit: group -> user -> state directory -> config file
    // owned by the new account, each link an explicit depends_on.
    let body = format!(
        "{}{}{}{}",
        group("grp", "sinter-gw", "      system: true\n"),
        user(
            "usr",
            "sinter-gw",
            "      group: sinter-gw\n      shell: /usr/sbin/nologin\n      home: /var/lib/sinter-gw\n      system: true\n",
            "    depends_on: [grp]\n"
        ),
        "  - id: dir\n    type: directory\n    depends_on: [usr, grp]\n    with:\n      path: /var/lib/sinter-gw\n      owner: sinter-gw\n      group: sinter-gw\n      mode: \"0750\"\n",
        "  - id: conf\n    type: file\n    depends_on: [dir, usr]\n    with:\n      path: /etc/sinter-gw.env\n      content: \"A=1\\n\"\n      owner: root\n      group: sinter-gw\n      mode: \"0640\"\n",
    );
    let r = recipe("e2e", &body);
    let t = fake()
        .with_fs_dir("/var")
        .with_fs_dir("/var/lib")
        .with_fs_dir("/etc");

    let p = plan(&r, t.clone());
    assert_eq!(find(&p, "grp").change, Change::Changed);
    assert!(find(&p, "usr").unknown);
    assert!(find(&p, "dir").unknown);
    assert!(find(&p, "conf").unknown);
    assert_eq!(mutation_command_count(&p), 0);

    let a = run_recipe_fake(&r, Mode::Apply, true, t);
    assert_success(&a);
    for id in ["grp", "usr", "dir", "conf"] {
        assert_eq!(find(&a, id).verification, Verification::Verified, "{}", id);
    }
    assert_eq!(
        account_cmds(&a),
        [
            "/usr/sbin/groupadd --system sinter-gw",
            "/usr/sbin/useradd --system -g sinter-gw -s /usr/sbin/nologin -d /var/lib/sinter-gw -M sinter-gw"
        ]
    );
}

// ---------------------------------------------------------------------------
// independent-review regressions
// ---------------------------------------------------------------------------

#[test]
fn user_without_group_is_refused_when_a_same_named_group_exists() {
    // useradd would fail ("group app exists - use -g"): say so in plan and
    // apply, before anything runs.
    let r = recipe("u-samegrp", &user("u", "app", "", ""));
    let t = fake().with_group("app", 990);
    let e = try_plan(&r, t.clone()).err().expect("plan must refuse");
    assert!(e.message.contains("declare group:"), "{}", e.message);
    let m = refused_apply(&r, t);
    assert!(m.contains("declare group:"), "{}", m);
}

#[test]
fn user_without_group_is_refused_when_a_dependency_creates_the_same_name() {
    let body = format!(
        "{}{}",
        group("g", "app", ""),
        user("u", "app", "", "    depends_on: [g]\n")
    );
    let r = recipe("u-samegrp-dep", &body);
    let e = try_plan(&r, fake()).err().expect("plan must refuse");
    assert!(e.message.contains("declare group:"), "{}", e.message);
}

#[test]
fn user_created_without_group_reports_the_private_group() {
    let r = recipe("u-private", &user("u", "app", "", ""));
    let rep = apply(&r, fake());
    let u = find(&rep, "u");
    assert_eq!(u.verification, Verification::Verified);
    assert!(
        u.notes.iter().any(|n| n.contains("private group app")),
        "{:?}",
        u.notes
    );
}

#[test]
fn sensitive_plan_diffs_are_redacted_at_the_result_level() {
    let body = "  - id: u\n    type: user\n    sensitive: true\n    with:\n      name: topsecretname\n      group: secretgrp\n      home: /srv/secret\n";
    let r = recipe("sens-diff", body);
    let t =
        fake()
            .with_group("secretgrp", 50)
            .with_user("topsecretname", 700, 700, "/old", "/bin/sh");
    let rep = plan(&r, t);
    let u = find(&rep, "u");
    assert_eq!(u.change, Change::Changed);
    assert!(matches!(
        u.diff.as_ref().map(|d| &d.body),
        Some(sinter::result::DiffBody::Redacted)
    ));
}

#[test]
fn sensitive_errors_do_not_carry_ids() {
    let body = "  - id: u\n    type: user\n    sensitive: true\n    with:\n      name: topsecretname\n      uid: 4242\n";
    let r = recipe("sens-ids", body);
    let e = try_plan(&r, fake().with_user("other", 4242, 4242, "/h", "/bin/sh"))
        .err()
        .expect("collision");
    assert!(!e.message.contains("4242"), "{}", e.message);
    let e = try_plan(
        &r,
        fake().with_user("topsecretname", 4343, 4343, "/h", "/bin/sh"),
    )
    .err()
    .expect("renumbering");
    assert!(
        !e.message.contains("4242") && !e.message.contains("4343"),
        "{}",
        e.message
    );
}

#[test]
fn owner_deferral_requires_a_confirmed_absence() {
    let dir = trusted_root("defer-confirmed");
    let body = format!(
        "version: 1\nresources:\n{}  - id: f\n    type: file\n    depends_on: [u]\n    with:\n      path: {}\n      content: x\n      owner: svcacct\n",
        user("u", "svcacct", "", ""),
        dir.join("conf").display()
    );
    let r = write_recipe(&dir, "r.yaml", &body);
    // The local lookup itself is broken: that is not "absent", so the plan
    // error stays instead of a deferral.
    let mut t = fake();
    t.accounts.files_lookup_fails = Some(Completion::Exited(1));
    assert!(try_plan(&r, t).is_err());
}

#[test]
fn user_with_one_covered_and_one_uncovered_missing_group_is_an_error() {
    let body = format!(
        "{}{}",
        group("g", "covered", ""),
        user(
            "u",
            "app",
            "      group: covered\n      groups: [uncovered]\n",
            "    depends_on: [g]\n"
        )
    );
    let r = recipe("mixed", &body);
    let e = try_plan(&r, fake()).err().expect("must fail");
    assert!(e.message.contains("does not exist"), "{}", e.message);
}

#[test]
fn nss_only_primary_or_supplementary_group_is_an_error() {
    let mut t = fake();
    t.accounts.nss_groups.push(sinter::fakesys::FakeGroup {
        name: "corp".into(),
        gid: 5000,
        members: vec![],
    });
    let r = recipe("nss-pg", &user("u", "app", "      group: corp\n", ""));
    let m = refused_apply(&r, t.clone());
    assert!(m.contains("non-local"), "{}", m);
    let r = recipe("nss-sg", &user("u", "app", "      groups: [corp]\n", ""));
    let m = refused_apply(&r, t);
    assert!(m.contains("non-local"), "{}", m);
}

#[test]
fn an_indeterminate_account_command_is_possible_change_and_indeterminate() {
    let r = recipe("u-indet", &user("u", "svc", "", ""));
    let mut t = fake();
    t.accounts.forced.insert(
        "useradd".into(),
        Output {
            completion: Completion::Indeterminate {
                started: true,
                reason: "connection lost".into(),
            },
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        },
    );
    let rep = apply(&r, t);
    let u = find(&rep, "u");
    assert_eq!(u.execution, Execution::Indeterminate);
    assert_eq!(u.change, Change::Possible);
    assert_eq!(u.verification, Verification::Unknown);
    assert_eq!(rep.status, AggregateStatus::Indeterminate);
}

#[test]
fn truncated_or_multi_record_getent_output_fails_closed() {
    for (i, bad) in [
        "svc:x:990:990::/h:/s\nsvc:x:991:991::/h:/s\n",
        "svc:x:990:990::/h:/s",
        "svc:x:+990:990::/h:/s\n",
    ]
    .iter()
    .enumerate()
    {
        let r = recipe(&format!("bad-getent-{}", i), &user("u", "svc", "", ""));
        let mut t = fake();
        t.observation_overrides
            .entry("getent".into())
            .or_default()
            .push_back(Output {
                completion: Completion::Exited(0),
                stdout: bad.as_bytes().to_vec(),
                stderr: Vec::new(),
                stdout_truncated: false,
                stderr_truncated: false,
            });
        let m = refused_apply(&r, t);
        assert!(m.contains("account lookup"), "{:?}: {}", bad, m);
    }
}

// ---------------------------------------------------------------------------
// F-3: plan knows what runs earlier, apply is unchanged
// ---------------------------------------------------------------------------

fn file_owned_by(id: &str, path: &Path, owner: &str, group: &str, top: &str) -> String {
    format!(
        "  - id: {id}\n    type: file\n{top}    with:\n      path: {path}\n      content: x\n      owner: {owner}\n      group: {group}\n",
        path = path.display()
    )
}

#[test]
fn group_user_file_in_declaration_order_without_depends_on_plans_and_applies_alike() {
    // The D2b / D3b recipes of the real-Linux report: plan used to be rc 4,
    // apply succeeded. Now plan defers each consumer and apply is as before.
    let dir = trusted_root("f3-chain");
    // A directory that exists on the scripted target.
    let conf = Path::new("/etc/app/conf").to_path_buf();
    let body = format!(
        "{}{}{}",
        group("g", "svcgrp", ""),
        user("u", "svcacct", "      group: svcgrp\n", ""),
        file_owned_by("f", &conf, "svcacct", "svcgrp", "")
    );
    let r = write_recipe(&dir, "r.yaml", &format!("version: 1\nresources:\n{}", body));
    let p = try_plan(&r, fake()).expect("the plan no longer contradicts apply");
    assert_eq!(find(&p, "g").change, Change::Changed);
    assert!(find(&p, "u").unknown, "user deferred to the group");
    assert!(find(&p, "f").unknown, "file deferred to the user and group");
    assert_eq!(mutation_command_count(&p), 0);
    // The same recipe with explicit depends_on gives the same plan outcome.
    let body2 = format!(
        "{}{}{}",
        group("g", "svcgrp", ""),
        user(
            "u",
            "svcacct",
            "      group: svcgrp\n",
            "    depends_on: [g]\n"
        ),
        file_owned_by("f", &conf, "svcacct", "svcgrp", "    depends_on: [u, g]\n")
    );
    let r2 = write_recipe(
        &dir,
        "r2.yaml",
        &format!("version: 1\nresources:\n{}", body2),
    );
    let p2 = try_plan(&r2, fake()).expect("plan");
    for id in ["g", "u", "f"] {
        let (a, b) = (find(&p, id), find(&p2, id));
        assert_eq!((a.change, a.unknown), (b.change, b.unknown), "{id}");
    }
    // Apply: the order and the commands are exactly those of the explicit form.
    let a = apply(&r, fake());
    assert_eq!(a.status, AggregateStatus::Success, "{:?}", a.resources);
    assert_eq!(
        account_cmds(&a),
        [
            "/usr/sbin/groupadd svcgrp",
            "/usr/sbin/useradd -g svcgrp -M svcacct"
        ]
    );
    // ... and the file got the new account's owner and group.
    assert_eq!(find(&a, "f").change, Change::Changed);
}

#[test]
fn several_earlier_producers_cover_user_groups_and_file_owner_and_group() {
    let dir = trusted_root("f3-several");
    let body = format!(
        "{}{}{}{}",
        group("g1", "alpha", ""),
        group("g2", "beta", ""),
        user(
            "u",
            "svcacct",
            "      group: alpha\n      groups: [beta]\n",
            ""
        ),
        file_owned_by("f", &dir.join("conf"), "svcacct", "beta", "")
    );
    let r = write_recipe(&dir, "r.yaml", &format!("version: 1\nresources:\n{}", body));
    let p = try_plan(&r, fake()).expect("plan");
    assert!(find(&p, "u").unknown && find(&p, "f").unknown);
    // One group missing from the producers: still the error, with the advice.
    let body = format!(
        "{}{}",
        group("g1", "alpha", ""),
        user(
            "u",
            "svcacct",
            "      group: alpha\n      groups: [ghost]\n",
            ""
        )
    );
    let r = write_recipe(
        &dir,
        "r2.yaml",
        &format!("version: 1\nresources:\n{}", body),
    );
    let e = try_plan(&r, fake())
        .err()
        .expect("an uncovered group is an error");
    assert!(e.message.contains("ghost"), "{}", e.message);
    assert!(e.message.contains("depends_on"), "{}", e.message);
}

#[test]
fn an_earlier_producer_that_is_skipped_or_absent_does_not_cover_the_consumer() {
    // when: false -> the group is never created; apply fails, so plan fails.
    let body = format!(
        "{}{}",
        group("g", "app", "").replace(
            "    type: group\n",
            "    type: group\n    when: \"false\"\n"
        ),
        user("u", "app", "      group: app\n", "")
    );
    let r = recipe("f3-skipped", &body);
    let e = try_plan(&r, fake()).err().expect("plan must refuse");
    assert!(e.message.contains("does not exist"), "{}", e.message);
    let rep = apply(&r, fake());
    assert_eq!(rep.status, AggregateStatus::ApplyFailed);
    assert_eq!(find(&rep, "u").execution, Execution::Failed);
    assert!(account_cmds(&rep).is_empty(), "{:?}", account_cmds(&rep));
    // state: absent -> nothing is created, nothing covers.
    let body = format!(
        "{}{}",
        group("g", "app", "      state: absent\n"),
        user("u", "app", "      group: app\n", "")
    );
    let r = recipe("f3-absent", &body);
    let e = try_plan(&r, fake()).err().expect("plan must refuse");
    assert!(e.message.contains("does not exist"), "{}", e.message);
}

#[test]
fn an_earlier_producer_whose_condition_plan_cannot_decide_defers_instead_of_failing() {
    let body = format!(
        "  - id: probe\n    type: command\n    with:\n      program: /bin/echo\n      args: [\"x\"]\n      register: p\n{}{}",
        group("g", "app", "").replace(
            "    type: group\n",
            "    type: group\n    depends_on: [probe]\n    when: \"registers.p.stdout == \\\"x\\\\n\\\"\"\n"
        ),
        user("u", "app", "      group: app\n", "")
    );
    let r = recipe("f3-unknown-when", &body);
    let p = try_plan(&r, fake()).expect("an undecidable producer defers");
    assert!(find(&p, "u").unknown);
}

#[test]
fn a_same_named_group_that_certainly_runs_earlier_is_refused_in_plan_as_in_apply() {
    // useradd without `group` fails when the private group already exists:
    // apply refuses once the earlier group is there, so plan says so now.
    let body = format!("{}{}", group("g", "app", ""), user("u", "app", "", ""));
    let r = recipe("f3-private", &body);
    let e = try_plan(&r, fake()).err().expect("plan must refuse");
    assert!(e.message.contains("same name"), "{}", e.message);
    let a = try_apply(&r, fake());
    match a {
        Err(e) => assert!(e.message.contains("same name"), "{}", e.message),
        Ok(rep) => assert_ne!(rep.status, AggregateStatus::Success),
    }
    // A producer plan cannot decide never makes plan fail on this rule.
    let body = format!(
        "  - id: probe\n    type: command\n    with:\n      program: /bin/echo\n      args: [\"x\"]\n      register: p\n{}{}",
        group("g", "app", "").replace(
            "    type: group\n",
            "    type: group\n    depends_on: [probe]\n    when: \"registers.p.stdout == \\\"x\\\\n\\\"\"\n"
        ),
        user("u", "app", "", "")
    );
    let r = recipe("f3-private-unknown", &body);
    assert!(try_plan(&r, fake()).is_ok());
}

#[test]
fn a_sensitive_consumer_deferred_to_an_earlier_producer_names_no_account() {
    let dir = trusted_root("f3-sensitive");
    let body = format!(
        "{}  - id: f\n    type: file\n    sensitive: true\n    with:\n      path: {}\n      content: x\n      owner: topsecretacct\n",
        user("u", "topsecretacct", "", ""),
        dir.join("conf").display()
    );
    let r = write_recipe(&dir, "r.yaml", &format!("version: 1\nresources:\n{}", body));
    let p = try_plan(&r, fake()).expect("plan");
    let f = find(&p, "f");
    assert!(f.unknown);
    assert!(
        !f.reason
            .clone()
            .unwrap_or_default()
            .contains("topsecretacct"),
        "{:?}",
        f.reason
    );
}

#[test]
fn audit_of_accounts_declared_in_order_without_depends_on_is_not_deferred_or_compliant() {
    // Deferral exists only in plan. Audit reports what the host has: accounts
    // that do not exist are drift, never a pass.
    let dir = trusted_root("f3-audit");
    let body = format!(
        "{}{}",
        group("g", "svcgrp", ""),
        user("u", "svcacct", "      group: svcgrp\n", "")
    );
    let r = write_recipe(&dir, "r.yaml", &format!("version: 1\nresources:\n{}", body));
    let rep = audit(&r, fake());
    assert_ne!(afind(&rep, "g").status, AuditResourceStatus::Compliant);
    assert_ne!(afind(&rep, "u").status, AuditResourceStatus::Compliant);
}

fn skipped_command(id: &str) -> String {
    format!(
        "  - id: {id}\n    type: command\n    when: \"false\"\n    with:\n      program: /bin/true\n"
    )
}

#[test]
fn an_earlier_producer_blocked_by_its_own_dependency_does_not_cover_the_consumer() {
    // A resource whose dependency is skipped is blocked and creates nothing;
    // the run goes on, so the consumer fails in apply: plan must say so too.
    for (label, middle, dep) in [
        ("f3-blocked-direct", "", "skip"),
        (
            "f3-blocked-chain",
            "  - id: mid\n    type: command\n    depends_on: [skip]\n    with:\n      program: /bin/true\n",
            "mid",
        ),
    ] {
        let body = format!(
            "{}{}{}{}",
            skipped_command("skip"),
            middle,
            group("g", "app", "").replace(
                "    type: group\n",
                &format!("    type: group\n    depends_on: [{dep}]\n")
            ),
            user("u", "app", "      group: app\n", "")
        );
        let r = recipe(label, &body);
        let e = try_plan(&r, fake()).err().expect("plan must refuse");
        assert!(e.message.contains("does not exist"), "{label}: {}", e.message);
        let rep = apply(&r, fake());
        assert_eq!(find(&rep, "g").disposition.label(), "blocked_by_dependency");
        assert_eq!(find(&rep, "u").execution, Execution::Failed, "{label}");
        assert!(account_cmds(&rep).is_empty(), "{label}: {:?}", account_cmds(&rep));
    }
}

#[test]
fn a_blocked_same_named_group_neither_refuses_the_user_in_plan_nor_in_apply() {
    // The group never exists (blocked), so useradd's private group is fine.
    let body = format!(
        "{}{}{}",
        skipped_command("skip"),
        group("g", "app", "").replace(
            "    type: group\n",
            "    type: group\n    depends_on: [skip]\n"
        ),
        user("u", "app", "", "")
    );
    let r = recipe("f3-blocked-private", &body);
    assert!(try_plan(&r, fake()).is_ok());
    let rep = apply(&r, fake());
    assert_eq!(find(&rep, "u").execution, Execution::Succeeded);
    assert_eq!(account_cmds(&rep), ["/usr/sbin/useradd -M app"]);
}
