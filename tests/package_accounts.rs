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
