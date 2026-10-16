//! The example recipes under `examples/` load (the same checks as
//! `sinter validate`). Recipes that reference secrets get synthetic,
//! freshly encrypted placeholders in a temporary copy, so the examples stay
//! valid without shipping any secret.

mod common;

use common::*;
use sinter::model::load_model;
use std::path::Path;

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let p = e.path();
        let dst = to.join(e.file_name());
        if p.is_dir() {
            copy_dir(&p, &dst);
        } else {
            std::fs::copy(&p, &dst).unwrap();
        }
    }
}

#[test]
fn every_example_recipe_loads() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    let dir = trusted_root("example-recipes");
    copy_dir(&root, &dir);
    // Synthetic secrets for the recipes that reference them.
    let id = sinter::secrets::generate_identity();
    let enc = |plain: &[u8]| {
        sinter::secrets::encrypt_to_recipients(plain, std::slice::from_ref(&id.recipient)).unwrap()
    };
    let secrets = dir.join("recipes").join("secrets");
    std::fs::create_dir_all(&secrets).unwrap();
    std::fs::write(
        secrets.join("app-verifier.age"),
        enc(b"SCRAM-SHA-256$4096:c3ludGhldGljLXNhbHQ=$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\n"),
    )
    .unwrap();
    std::fs::write(
        secrets.join("htpasswd.age"),
        enc(b"example:$2y$05$synthetic.placeholder.not.a.real.hash.0000000000000\n"),
    )
    .unwrap();
    let mut loaded = 0;
    for sub in ["quick", "start", "multihost", "recipes"] {
        for e in std::fs::read_dir(dir.join(sub)).unwrap() {
            let p = e.unwrap().path();
            if p.extension().and_then(|x| x.to_str()) != Some("yaml") {
                continue;
            }
            // multihost/hosts.yaml is an inventory and web-stack.yaml a
            // bundle, not recipes (`sinter validate` checks the bundle).
            if matches!(
                p.file_name().and_then(|x| x.to_str()),
                Some("hosts.yaml" | "web-stack.yaml")
            ) {
                continue;
            }
            load_model(&p).unwrap_or_else(|e| panic!("{}: {}", p.display(), e.message));
            loaded += 1;
        }
    }
    assert!(loaded >= 12, "loaded {loaded} recipes");
}

/// The new v1.5.1 recipes use the features they document.
#[test]
fn the_v151_recipes_use_the_features_they_document() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/recipes");
    let read = |f: &str| std::fs::read_to_string(root.join(f)).unwrap();
    let os = read("postgresql-os.yaml");
    assert!(os.contains("--config-file={{ staged }}"));
    assert!(os.contains("type: postgresql_role"));
    assert!(os.contains("postgresql:16"));
    assert!(os.contains("facts.os.version_major"));
    let pgdg = read("postgresql-pgdg17.yaml");
    assert!(pgdg.contains("source: pgdg/PGDG-RPM-GPG-KEY-RHEL"));
    assert!(
        !pgdg.contains("reporpms"),
        "no unverified repo RPM from a URL"
    );
    let repo = read("pgdg/pgdg-17.repo");
    assert_eq!(repo.matches("gpgcheck=1").count(), 2);
    assert_eq!(repo.matches("repo_gpgcheck = 1").count(), 2);
    let py = read("python-el8.yaml");
    assert!(py.contains("name: python36"));
    assert!(!py.contains("name: python3,") && !py.contains("name: python311"));
    let apache = read("apache-htpasswd.yaml");
    assert!(apache.find("id: apache_user").unwrap() < apache.find("id: httpd\n").unwrap());
}
