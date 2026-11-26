//! v1.5.1 COM-04: an account that a package's scriptlet creates does not
//! exist when plan runs. The supported way is to declare the account (with
//! the package's own attributes) before the package; plan then defers what
//! depends on it instead of aborting. Without the declaration plan still
//! refuses — it never assumes the account exists — and now says how to fix
//! the recipe.

mod common;

use common::*;
use sinter::engine::{Engine, Mode, RunOptions, TargetSpec};
use sinter::executor::FakeTarget;
use sinter::model::load_model;

fn target() -> FakeTarget {
    let mut t = FakeTarget::rocky9().with_fake_fs().as_root();
    let fs = t.fs.as_mut().unwrap();
    for p in ["/var", "/var/www"] {
        fs.mkdir_node(p, 0o755, 0, 0);
    }
    t
}

fn run(
    recipe: &std::path::Path,
    mode: Mode,
) -> Result<sinter::engine::RunReport, sinter::error::SinterError> {
    Engine::new(
        load_model(recipe).unwrap(),
        RunOptions {
            mode,
            sudo: true,
            target: TargetSpec { ssh: None },
            verbose: false,
            fault: None,
            fake_target: Some(target()),
        },
    )
    .unwrap()
    .run()
}

const PLAIN: &str = "version: 1\nresources:\n  - id: httpd\n    type: package\n    with: { name: httpd, state: present }\n  - id: docroot\n    type: directory\n    depends_on: [httpd]\n    with: { path: /var/www/site, owner: root, group: apache, mode: \"0750\" }\n";

#[test]
fn plan_without_the_declaration_refuses_and_says_how_to_fix_it() {
    let dir = trusted_root("com04-plain");
    let r = write_recipe(&dir, "r.yaml", PLAIN);
    let Err(e) = run(&r, Mode::Plan) else {
        panic!("plan must refuse an account that does not exist");
    };
    assert!(e.message.contains("unknown group: apache"), "{}", e.message);
    assert!(
        e.message
            .contains("declare the group with a group resource before that resource"),
        "{}",
        e.message
    );
}

#[test]
fn plan_with_the_declared_account_defers_instead_of_aborting() {
    let dir = trusted_root("com04-declared");
    let r = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: g\n    type: group\n    with: { name: apache, gid: 48, system: true }\n  - id: httpd\n    type: package\n    depends_on: [g]\n    with: { name: httpd, state: present }\n  - id: docroot\n    type: directory\n    depends_on: [httpd, g]\n    with: { path: /var/www/site, owner: root, group: apache, mode: \"0750\" }\n",
    );
    let rep = run(&r, Mode::Plan).expect("plan completes");
    let d = find(&rep, "docroot");
    assert!(
        d.unknown,
        "the dependent is deferred, not assumed: {:?}",
        d.reason
    );
}

// ---------------------------------------------------------------------------
// v1.16.0 (DESIGN §49.2): `creates_accounts` on a package names the accounts its
// installation creates. It is a declaration, never an inference, and it only
// defers a plan-time lookup; apply looks the account up for real.
// ---------------------------------------------------------------------------

const CREATES: &str = "version: 1\nresources:\n  - id: httpd\n    type: package\n    with:\n      name: httpd\n      state: present\n      creates_accounts: { users: [apache], groups: [apache] }\n  - id: docroot\n    type: directory\n    with: { path: /var/www/site, owner: apache, group: apache, mode: \"0750\" }\n  - id: index\n    type: file\n    with: { path: /var/www/site/index.html, content: \"ok\\n\", owner: apache }\n  - id: deploy\n    type: user\n    with: { name: deploy, groups: [apache], state: present }\n";

#[test]
fn creates_accounts_defers_what_is_owned_by_the_account_the_package_creates() {
    let dir = trusted_root("ca-plan");
    let r = write_recipe(&dir, "r.yaml", CREATES);
    let rep = run(&r, Mode::Plan).expect("plan completes");
    assert!(!find(&rep, "httpd").unknown);
    for id in ["docroot", "index", "deploy"] {
        let d = find(&rep, id);
        assert!(d.unknown, "{id}: {:?}", d.reason);
    }
    let reason = find(&rep, "docroot").reason.clone().unwrap_or_default();
    assert!(reason.contains("created when httpd applies"), "{reason}");
    // Plan dispatched no mutation.
    assert!(rep
        .commands
        .iter()
        .all(|c| !matches!(c.program.as_str(), "/bin/mkdir" | "/usr/sbin/useradd")));
}

#[test]
fn creates_accounts_of_an_installed_package_defers_nothing() {
    // The package is installed and the account still does not exist: apply
    // would not create it, so plan must not pretend it will.
    let dir = trusted_root("ca-installed");
    let r = write_recipe(&dir, "r.yaml", CREATES);
    let res = Engine::new(
        load_model(&r).unwrap(),
        RunOptions {
            mode: Mode::Plan,
            sudo: true,
            target: TargetSpec { ssh: None },
            verbose: false,
            fault: None,
            fake_target: Some(target().with_package("httpd")),
        },
    )
    .unwrap()
    .run();
    let Err(e) = res else {
        panic!("plan must refuse");
    };
    assert!(e.message.contains("unknown user: apache"), "{}", e.message);
}

#[test]
fn creates_accounts_names_only_what_it_lists_and_only_after_the_package() {
    let dir = trusted_root("ca-scope");
    // Another account is not covered.
    let other = CREATES.replace(
        "owner: apache, group: apache",
        "owner: nginx, group: apache",
    );
    assert!(run(&write_recipe(&dir, "other.yaml", &other), Mode::Plan).is_err());
    // A resource that runs BEFORE the package is not covered.
    let before = "version: 1\nresources:\n  - id: docroot\n    type: directory\n    with: { path: /var/www/site, group: apache }\n  - id: httpd\n    type: package\n    with:\n      name: httpd\n      state: present\n      creates_accounts: { groups: [apache] }\n";
    assert!(run(&write_recipe(&dir, "before.yaml", before), Mode::Plan).is_err());
    // A package that is removed provides nothing.
    let absent = CREATES.replace(
        "state: present\n      creates_accounts",
        "state: absent\n      creates_accounts",
    );
    assert!(run(&write_recipe(&dir, "absent.yaml", &absent), Mode::Plan).is_err());
}

#[test]
fn apply_does_not_trust_creates_accounts() {
    // The scripted host's package installation creates no account: apply
    // looks the owner up for real and fails; it never assumes.
    let dir = trusted_root("ca-apply");
    let r = write_recipe(&dir, "r.yaml", CREATES);
    match run(&r, Mode::Apply) {
        Err(e) => assert!(e.message.contains("apache"), "{}", e.message),
        Ok(rep) => {
            assert_ne!(rep.status, sinter::engine::AggregateStatus::Success);
            let d = find(&rep, "docroot");
            assert_ne!(d.execution, sinter::result::Execution::Succeeded);
        }
    }
}

#[test]
fn creates_accounts_is_checked_when_the_recipe_is_loaded() {
    let dir = trusted_root("ca-shape");
    for (bad, want) in [
        (
            "creates_accounts: [apache]",
            "creates_accounts must be a map",
        ),
        (
            "creates_accounts: { services: [httpd] }",
            "creates_accounts has no key",
        ),
        ("creates_accounts: { users: apache }", "must be a list"),
        (
            "creates_accounts: { users: [\"{{ vars.u }}\"] }",
            "literal account names",
        ),
        (
            "creates_accounts: { users: [\"Bad Name\"] }",
            "literal account names",
        ),
        ("creates_accounts: { groups: [0] }", "literal account names"),
    ] {
        let body = format!(
            "version: 1\nvars:\n  u: {{ value: apache }}\nresources:\n  - id: httpd\n    type: package\n    with:\n      name: httpd\n      state: present\n      {bad}\n"
        );
        let e = load_model(&write_recipe(&dir, "bad.yaml", &body)).unwrap_err();
        assert!(e.message.contains(want), "{bad}: {}", e.message);
    }
}
