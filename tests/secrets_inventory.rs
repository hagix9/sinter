//! `sinter secrets list --recipe FILE` (Phase E): the recipe-derived inventory.
//!
//! Real-binary tests: the command runs with no terminal, no identity and a
//! minimal environment, which is also the proof that the inventory never
//! decrypts, prompts or looks for an identity. They pin the contract:
//! `used-by`, `missing`, "not referenced" only from a complete analysis, the
//! `identity.age` safety treatment, matching by file identity, structural
//! failure of any recipe (exit 2, empty stdout), the strict loader staying
//! strict, and Phase B output staying byte-for-byte when no `--recipe` is
//! given.
#![cfg(unix)]
mod common;

use common::*;
use sinter::model::load_model;
use sinter::secrets::{self, Recipient};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const CANARY: &str = "CANARY-INVENTORY-PLAINTEXT-81c4d9";
const TARGET_CANARY: &str = "/srv/canary-target-path-6f20";

struct Lab {
    dir: PathBuf,
    recipient: Recipient,
}

fn lab(label: &str) -> Lab {
    let dir = trusted_root(label);
    std::fs::create_dir_all(dir.join("secrets")).unwrap();
    let id = secrets::generate_identity();
    Lab {
        dir,
        recipient: id.recipient,
    }
}

fn file_res(id: &str, secret: &str) -> String {
    format!(
        "  - id: {id}\n    type: file\n    with:\n      path: {TARGET_CANARY}/{id}\n      content: {{ secret: {secret} }}\n"
    )
}

fn user_res(id: &str, name: &str, secret: &str) -> String {
    format!(
        "  - id: {id}\n    type: user\n    with:\n      name: {name}\n      password_hash: {{ secret: {secret} }}\n"
    )
}

impl Lab {
    /// An age file (to this lab's recipient) at `rel`, holding the canary.
    fn age(&self, rel: &str) -> PathBuf {
        let p = self.dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let ct = secrets::encrypt_to_recipients(
            CANARY.as_bytes(),
            std::slice::from_ref(&self.recipient),
        )
        .unwrap();
        std::fs::write(&p, ct).unwrap();
        p
    }

    /// A passphrase-protected age file at `rel` (header only is inspected).
    fn age_passphrase(&self, rel: &str) -> PathBuf {
        let p = self.dir.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let pass =
            secrets::Passphrase::for_encryption("inventory test passphrase 42".into()).unwrap();
        let ct = secrets::encrypt_with_passphrase(CANARY.as_bytes(), &pass).unwrap();
        std::fs::write(&p, ct).unwrap();
        p
    }

    fn recipe(&self, name: &str, resources: &str) -> PathBuf {
        let p = self.dir.join(name);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, format!("version: 1\nresources:\n{}", resources)).unwrap();
        p
    }

    /// The binary, run from the lab directory with no terminal, no stdin and
    /// no identity anywhere.
    fn run(&self, args: &[&str]) -> Output {
        use std::os::unix::process::CommandExt;
        let mut c = Command::new(env!("CARGO_BIN_EXE_sinter"));
        c.args(args)
            .current_dir(&self.dir)
            .env_clear()
            .env("HOME", self.dir.join("home"))
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            c.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        c.output().unwrap()
    }

    /// `secrets list --format json` plus `extra`, parsed.
    fn json(&self, extra: &[&str]) -> serde_json::Value {
        let mut a = vec!["secrets", "list", "--format", "json"];
        a.extend_from_slice(extra);
        let o = self.run(&a);
        assert_eq!(o.status.code(), Some(0), "{}", text(&o));
        serde_json::from_slice(&o.stdout).unwrap()
    }
}

fn text(o: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

/// The one entry whose path ends with `suffix`.
fn entry<'a>(v: &'a serde_json::Value, suffix: &str) -> &'a serde_json::Value {
    let hits: Vec<_> = v["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["path"].as_str().unwrap().ends_with(suffix))
        .collect();
    assert_eq!(hits.len(), 1, "entries ending {suffix:?} in {v:#}");
    hits[0]
}

fn used_by(e: &serde_json::Value) -> Vec<String> {
    e["referenced_by"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| {
            format!(
                "{}|{}",
                u["recipe"].as_str().unwrap(),
                u["resource"].as_str().unwrap()
            )
        })
        .collect()
}

fn count(v: &serde_json::Value) -> usize {
    v["secrets"].as_array().unwrap().len()
}

// ---------------------------------------------------------------------------
// Phase B behaviour is untouched without --recipe
// ---------------------------------------------------------------------------

#[test]
fn without_recipe_the_output_is_the_phase_b_output() {
    let l = lab("inv-b");
    l.age("secrets/a.age");
    l.recipe("r.yaml", &file_res("k", "secrets/a.age"));
    let v = l.json(&[]);
    let mut top: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
    top.sort();
    assert_eq!(top, ["command", "secrets", "truncated"]);
    let mut keys: Vec<_> = v["secrets"][0]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    keys.sort();
    assert_eq!(
        keys,
        ["armored", "method", "note", "path", "recipients", "status"]
    );
    // The recipe sitting next to the secret is not read, not listed, not used.
    assert_eq!(count(&v), 1);
    let o = l.run(&["secrets", "list"]);
    let t = String::from_utf8_lossy(&o.stdout).to_string();
    assert!(
        t.starts_with("STATUS      METHOD      RECIPIENTS  PATH\n"),
        "{t}"
    );
    for word in ["referenced", "recipe", "identity file", "missing"] {
        assert!(!t.contains(word), "{word}: {t}");
    }
}

// ---------------------------------------------------------------------------
// used-by, not referenced, scope
// ---------------------------------------------------------------------------

#[test]
fn used_by_is_deduplicated_and_the_unreferenced_claim_is_scoped() {
    let l = lab("inv-used");
    l.age("secrets/shared.age");
    l.age("secrets/lonely.age");
    l.recipe(
        "a.yaml",
        &format!(
            "{}{}",
            file_res("key", "secrets/shared.age"),
            user_res("pw", "app", "secrets/shared.age")
        ),
    );
    l.recipe("b.yaml", &file_res("copy", "secrets/shared.age"));
    // The same recipe named twice does not duplicate anything.
    let v = l.json(&[
        "--recipe", "a.yaml", "--recipe", "b.yaml", "--recipe", "a.yaml",
    ]);
    assert_eq!(count(&v), 2, "{v:#}");
    let shared = entry(&v, "secrets/shared.age");
    assert_eq!(
        used_by(shared),
        ["a.yaml|file:key", "a.yaml|user:pw", "b.yaml|file:copy"]
    );
    assert_eq!(shared["not_referenced"], false);
    let lonely = entry(&v, "secrets/lonely.age");
    assert_eq!(lonely["not_referenced"], true);
    assert!(used_by(lonely).is_empty());
    assert_eq!(v["recipes"], serde_json::json!(["a.yaml", "b.yaml"]));

    let o = l.run(&[
        "secrets", "list", "--recipe", "a.yaml", "--recipe", "b.yaml",
    ]);
    let t = String::from_utf8_lossy(&o.stdout).to_string();
    assert_eq!(o.status.code(), Some(0));
    assert!(t.contains("not referenced by the 2 recipe(s) given"), "{t}");
    assert!(
        t.contains("recipe analysis covers only the 2 recipe(s) given"),
        "{t}"
    );
    assert!(
        t.contains("references from other recipes are not considered"),
        "{t}"
    );
    // The claim never reads as advice or as a global statement.
    for bad in ["orphan", "delete", "safe to", "unused"] {
        assert!(!t.to_lowercase().contains(bad), "{bad}: {t}");
    }
}

#[test]
fn only_the_recipes_named_are_considered_and_none_is_discovered() {
    let l = lab("inv-explicit");
    l.age("secrets/x.age");
    l.recipe("uses-x.yaml", &file_res("k", "secrets/x.age"));
    l.recipe(
        "other.yaml",
        &file_res("o", "secrets/other-not-there.age").replace("other-not-there", "x"),
    );
    let v = l.json(&["--recipe", "other.yaml"]);
    // uses-x.yaml lies in the listed tree, but was not named.
    assert_eq!(used_by(entry(&v, "secrets/x.age")), ["other.yaml|file:o"]);
    assert_eq!(v["recipes"], serde_json::json!(["other.yaml"]));
}

#[test]
fn resources_that_may_not_run_still_count_as_references() {
    let l = lab("inv-static");
    l.age("secrets/c.age");
    l.age("secrets/d.age");
    l.recipe(
        "r.yaml",
        "  - id: cond\n    type: file\n    when: \"false\"\n    with:\n      path: /x/c\n      content: { secret: secrets/c.age }\n  - id: gone\n    type: file\n    with:\n      path: /x/d\n      state: absent\n      content: { secret: secrets/d.age }\n",
    );
    let v = l.json(&["--recipe", "r.yaml"]);
    assert_eq!(entry(&v, "secrets/c.age")["not_referenced"], false);
    assert_eq!(entry(&v, "secrets/d.age")["not_referenced"], false);
}

#[test]
fn only_labels_are_shown_never_resource_values() {
    let l = lab("inv-labels");
    l.age("secrets/a.age");
    l.recipe(
        "r.yaml",
        &format!(
            "  - id: key\n    type: file\n    sensitive: true\n    with:\n      path: {TARGET_CANARY}/key\n      mode: \"0600\"\n      owner: svc\n      content: {{ secret: secrets/a.age }}\n"
        ),
    );
    for fmt in ["text", "json"] {
        let o = l.run(&["secrets", "list", "--format", fmt, "--recipe", "r.yaml"]);
        let t = text(&o);
        assert_eq!(o.status.code(), Some(0), "{t}");
        assert!(t.contains("file:key"), "{t}");
        for leak in [
            TARGET_CANARY,
            "0600",
            "svc",
            CANARY,
            "age1",
            "AGE-SECRET-KEY-",
        ] {
            assert!(!t.contains(leak), "{leak}: {t}");
        }
    }
}

#[test]
fn loop_expanded_and_included_references_are_followed() {
    let l = lab("inv-loop");
    l.age("secrets/one.age");
    l.age("sub/secrets/in.age");
    std::fs::write(
        l.dir.join("sub/inc.yaml"),
        format!(
            "version: 1\nresources:\n{}",
            file_res("inc", "secrets/in.age")
        ),
    )
    .unwrap();
    std::fs::write(
        l.dir.join("top.yaml"),
        format!(
            "version: 1\ninclude: [sub/inc.yaml]\nresources:\n{}",
            file_res("top", "secrets/one.age")
        ),
    )
    .unwrap();
    let v = l.json(&["--recipe", "top.yaml"]);
    // A reference resolves against the file that declares the resource.
    assert_eq!(
        used_by(entry(&v, "sub/secrets/in.age")),
        ["top.yaml|file:inc"]
    );
    assert_eq!(used_by(entry(&v, "secrets/one.age")), ["top.yaml|file:top"]);
}

#[test]
fn a_bundle_is_analysed_as_all_of_its_recipes() {
    let l = lab("inv-bundle");
    l.age("secrets/a.age");
    l.age("secrets/b.age");
    l.recipe("ra.yaml", &file_res("a", "secrets/a.age"));
    l.recipe("rb.yaml", &file_res("b", "secrets/b.age"));
    std::fs::write(
        l.dir.join("bundle.yaml"),
        "version: 1\nrecipes:\n  - ra.yaml\n  - rb.yaml\n",
    )
    .unwrap();
    let v = l.json(&["--recipe", "bundle.yaml"]);
    assert_eq!(used_by(entry(&v, "secrets/a.age")), ["bundle.yaml|file:a"]);
    assert_eq!(used_by(entry(&v, "secrets/b.age")), ["bundle.yaml|file:b"]);
}

#[test]
fn a_referenced_secret_outside_the_listed_paths_is_still_shown() {
    let l = lab("inv-outside");
    l.age("elsewhere/secrets/o.age");
    std::fs::create_dir_all(l.dir.join("empty")).unwrap();
    l.recipe("elsewhere/r.yaml", &file_res("k", "secrets/o.age"));
    let v = l.json(&["--recipe", "elsewhere/r.yaml", "empty"]);
    let e = entry(&v, "secrets/o.age");
    assert_eq!(used_by(e), ["elsewhere/r.yaml|file:k"]);
    assert_eq!(e["status"], "ok");
    // Shown the way the operator spelled the recipe, not as a host path.
    assert_eq!(e["path"], "elsewhere/secrets/o.age");
    assert!(!v.to_string().contains(l.dir.to_str().unwrap()), "{v:#}");
}

// ---------------------------------------------------------------------------
// missing, and what is not missing
// ---------------------------------------------------------------------------

#[test]
fn a_missing_secret_is_a_record_not_a_failure_and_validate_still_refuses() {
    let l = lab("inv-missing");
    l.age("secrets/here.age");
    let r = l.recipe(
        "r.yaml",
        &format!(
            "{}{}{}",
            file_res("present", "secrets/here.age"),
            file_res("absent", "secrets/gone.age"),
            user_res("pw", "svc", "secrets/gone.age")
        ),
    );
    let v = l.json(&["--recipe", "r.yaml"]);
    let m = entry(&v, "secrets/gone.age");
    assert_eq!(m["status"], "missing");
    assert_eq!(m["method"], serde_json::Value::Null);
    assert_eq!(m["recipients"], serde_json::Value::Null);
    assert_eq!(m["not_referenced"], serde_json::Value::Null);
    // One record, every resource that names it.
    assert_eq!(used_by(m), ["r.yaml|file:absent", "r.yaml|user:pw"]);
    assert_eq!(count(&v), 2);
    // The strict loader is unchanged: the same recipe does not validate.
    let o = l.run(&["validate", r.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains("secret file not found"), "{}", text(&o));
    assert!(load_model(&r).is_err());
    // An absent intermediate directory is also absent, not something else.
    l.recipe("deep.yaml", &file_res("d", "nodir/x.age"));
    let v = l.json(&["--recipe", "deep.yaml"]);
    assert_eq!(entry(&v, "nodir/x.age")["status"], "missing");
}

#[test]
fn the_path_of_a_missing_secret_is_shown_even_for_a_sensitive_resource() {
    let l = lab("inv-sens");
    let r = l.recipe(
        "r.yaml",
        "  - id: key\n    type: file\n    sensitive: true\n    with:\n      path: /x/k\n      content: { secret: secrets/NAMED-gone.age }\n",
    );
    let v = l.json(&["--recipe", "r.yaml"]);
    let m = entry(&v, "secrets/NAMED-gone.age");
    assert_eq!(m["status"], "missing");
    assert_eq!(used_by(m), ["r.yaml|file:key"]);
    // The loader's own error text stays redacted for the same resource.
    let o = l.run(&["validate", r.to_str().unwrap()]);
    assert!(text(&o).contains("value redacted"), "{}", text(&o));
    assert!(!text(&o).contains("NAMED-gone"), "{}", text(&o));
}

#[test]
fn other_reference_problems_are_never_called_missing() {
    let l = lab("inv-states");
    let outside = trusted_root("inv-states-outside");
    let ok = l.age("secrets/ok.age");
    // a directory
    std::fs::create_dir_all(l.dir.join("secrets/adir")).unwrap();
    // a regular file that is not age
    std::fs::write(l.dir.join("secrets/plain.age"), b"just text").unwrap();
    // a leaf link, and a link as a directory component
    symlink(&ok, l.dir.join("secrets/leaf.age")).unwrap();
    symlink(&outside, l.dir.join("linkdir")).unwrap();
    std::fs::write(outside.join("x.age"), std::fs::read(&ok).unwrap()).unwrap();
    // a broken link
    symlink(l.dir.join("nowhere"), l.dir.join("secrets/broken.age")).unwrap();
    // a file that cannot be read, and a directory that cannot be entered
    let denied = l.age("secrets/denied.age");
    let _g1 = ModeGuard(denied.clone(), 0o600);
    set_mode(&denied, 0o000);
    let sealed = l.age("sealed/s.age");
    let _g2 = ModeGuard(sealed.parent().unwrap().to_path_buf(), 0o700);
    set_mode(sealed.parent().unwrap(), 0o000);
    let unprivileged = unsafe { libc::geteuid() } != 0;

    let cases: &[(&str, &str, bool)] = &[
        ("secrets/adir", "unreadable", true),
        ("secrets/plain.age", "not-age", true),
        ("secrets/leaf.age", "unreadable", true),
        ("linkdir/x.age", "unreadable", true),
        ("secrets/broken.age", "unreadable", true),
        ("secrets/denied.age", "unreadable", unprivileged),
        ("sealed/s.age", "unreadable", unprivileged),
    ];
    for (reference, want, check) in cases {
        if !check {
            continue;
        }
        let name = format!("r-{}.yaml", reference.replace('/', "_"));
        l.recipe(&name, &file_res("k", reference));
        std::fs::create_dir_all(l.dir.join("empty-none")).unwrap();
        let v = l.json(&["--recipe", &name, "empty-none"]);
        assert_eq!(count(&v), 1, "{reference}: {v:#}");
        let e = &v["secrets"][0];
        assert_eq!(e["status"], *want, "{reference}: {v:#}");
        assert_ne!(e["status"], "missing", "{reference}");
        assert_eq!(e["not_referenced"], serde_json::Value::Null, "{reference}");
        assert_eq!(used_by(e), [format!("{name}|file:k")], "{reference}");
        // None of these passes the strict loader either.
        assert!(load_model(&l.dir.join(&name)).is_err(), "{reference}");
    }
    set_mode(&denied, 0o600);
    set_mode(sealed.parent().unwrap(), 0o700);
}

// ---------------------------------------------------------------------------
// structural errors: exit 2, empty stdout, every failing recipe, no conclusion
// ---------------------------------------------------------------------------

#[test]
fn any_structural_error_fails_the_whole_command_and_names_every_failing_recipe() {
    let l = lab("inv-fail");
    l.age("secrets/a.age");
    l.age("secrets/unref.age");
    l.recipe("good.yaml", &file_res("k", "secrets/a.age"));
    std::fs::write(l.dir.join("badyaml.yaml"), "version: 1\nresources: [\n").unwrap();
    l.recipe(
        "unknown.yaml",
        &format!("{}      bogus: 1\n", file_res("u", "secrets/a.age")),
    );
    l.recipe("trav.yaml", &file_res("t", "../x.age"));
    for fmt in ["text", "json"] {
        let o = l.run(&[
            "secrets",
            "list",
            "--format",
            fmt,
            "--recipe",
            "good.yaml",
            "--recipe",
            "badyaml.yaml",
            "--recipe",
            "unknown.yaml",
            "--recipe",
            "trav.yaml",
            "--recipe",
            "does-not-exist.yaml",
        ]);
        assert_eq!(o.status.code(), Some(2), "{}", text(&o));
        assert!(o.stdout.is_empty(), "stdout must stay empty: {}", text(&o));
        let err = String::from_utf8_lossy(&o.stderr).to_string();
        for failing in [
            "badyaml.yaml",
            "unknown.yaml",
            "trav.yaml",
            "does-not-exist.yaml",
        ] {
            assert!(
                err.contains(&format!("--recipe {failing}:")),
                "{failing}: {err}"
            );
        }
        assert!(!err.contains("--recipe good.yaml"), "{err}");
        assert!(!err.to_lowercase().contains("not referenced"), "{err}");
    }
}

#[test]
fn a_missing_secret_does_not_hide_a_later_structural_error() {
    let l = lab("inv-mask");
    l.age("secrets/a.age");
    // The strict loader stops at the first resource (missing secret) and never
    // reaches the ownership conflict below it; the inventory must not accept
    // the recipe either way.
    let r = l.recipe(
        "r.yaml",
        &format!(
            "{}  - id: g\n    type: file\n    with:\n      path: {TARGET_CANARY}/k\n      content: hello\n",
            file_res("k", "secrets/gone.age")
        ),
    );
    assert!(load_model(&r).is_err());
    let o = l.run(&["secrets", "list", "--recipe", "r.yaml"]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(o.stdout.is_empty());
    assert!(text(&o).contains("conflicting ownership"), "{}", text(&o));
}

/// Both loaders share one grammar: every reference rejected for its *text* is
/// rejected identically by `validate` and by the inventory; only the state of
/// the file differs.
#[test]
fn the_reference_text_rules_are_identical_in_both_modes() {
    let l = lab("inv-diff");
    l.age("secrets/ok.age");
    let text_rules: &[(&str, &str)] = &[
        ("\"\"", "non-empty"),
        ("/etc/passwd", "relative"),
        ("../ok.age", "'..'"),
        ("secrets/../secrets/ok.age", "'..'"),
        ("./secrets/ok.age", "'.'"),
        ("secrets//ok.age", "empty"),
        ("secrets/ok.age/", "empty"),
        ("\"secrets\\\\ok.age\"", "relative"),
        ("\"secrets/{{ x }}.age\"", "interpolation"),
        ("\"secrets/o\\tk.age\"", "control"),
    ];
    for (i, (reference, want)) in text_rules.iter().enumerate() {
        let name = format!("t{i}.yaml");
        let r = l.recipe(&name, &file_res("k", reference));
        let strict = l.run(&["validate", r.to_str().unwrap()]);
        let inv = l.run(&["secrets", "list", "--recipe", &name]);
        assert_eq!(strict.status.code(), Some(2), "{reference}");
        assert_eq!(inv.status.code(), Some(2), "{reference}: {}", text(&inv));
        assert!(inv.stdout.is_empty(), "{reference}");
        assert!(
            text(&strict).contains(want),
            "{reference}: {}",
            text(&strict)
        );
        assert!(text(&inv).contains(want), "{reference}: {}", text(&inv));
    }
    // A reference that passes validate passes the inventory too, and the
    // frozen outcome (what is referenced) is the same.
    let good = l.recipe("good.yaml", &file_res("k", "secrets/ok.age"));
    assert_eq!(
        l.run(&["validate", good.to_str().unwrap()]).status.code(),
        Some(0)
    );
    let v = l.json(&["--recipe", "good.yaml"]);
    assert_eq!(used_by(entry(&v, "secrets/ok.age")), ["good.yaml|file:k"]);
    // A structural problem unrelated to references fails in both.
    let dup = l.recipe(
        "dup.yaml",
        &format!(
            "{}{}",
            file_res("k", "secrets/ok.age"),
            file_res("k", "secrets/ok.age")
        ),
    );
    assert_eq!(
        l.run(&["validate", dup.to_str().unwrap()]).status.code(),
        Some(2)
    );
    assert_eq!(
        l.run(&["secrets", "list", "--recipe", "dup.yaml"])
            .status
            .code(),
        Some(2)
    );
    // Wrong shape.
    for shape in [
        "{ secret: 1 }",
        "{ other: secrets/ok.age }",
        "{ secret: a, x: y }",
        "5",
    ] {
        let r = l.recipe(
            "shape.yaml",
            &format!(
                "  - id: f\n    type: file\n    with:\n      path: /x/f\n      content: {shape}\n"
            ),
        );
        assert_eq!(
            l.run(&["validate", r.to_str().unwrap()]).status.code(),
            Some(2),
            "{shape}"
        );
        assert_eq!(
            l.run(&["secrets", "list", "--recipe", "shape.yaml"])
                .status
                .code(),
            Some(2),
            "{shape}"
        );
    }
}

#[test]
fn a_sensitive_resource_keeps_its_redacted_structural_error() {
    let l = lab("inv-redact");
    l.recipe(
        "r.yaml",
        "  - id: key\n    type: file\n    sensitive: true\n    with:\n      path: /x/k\n      content: { secret: ../LEAKY-NAME.age }\n",
    );
    let o = l.run(&["secrets", "list", "--recipe", "r.yaml"]);
    assert_eq!(o.status.code(), Some(2));
    assert!(text(&o).contains("value redacted"), "{}", text(&o));
    assert!(!text(&o).contains("LEAKY-NAME"), "{}", text(&o));
}

// ---------------------------------------------------------------------------
// false-orphan prevention: file identity, not path spelling
// ---------------------------------------------------------------------------

#[test]
fn equivalent_spellings_of_a_referenced_file_are_not_unreferenced() {
    let l = lab("inv-alias");
    let real = l.age("secrets/real.age");
    l.age("secrets/stray.age");
    l.recipe("r.yaml", &file_res("k", "secrets/real.age"));
    // a hard link under another name, and the same tree through a link
    std::fs::hard_link(&real, l.dir.join("secrets/hard.age")).unwrap();
    let alias_root = trusted_root("inv-alias-root");
    symlink(&l.dir, alias_root.join("viaroot")).unwrap();

    let v = l.json(&["--recipe", "r.yaml", "secrets"]);
    assert_eq!(entry(&v, "secrets/real.age")["not_referenced"], false);
    // The hard link is the same file: referenced, not a stray.
    assert_eq!(entry(&v, "secrets/hard.age")["not_referenced"], false);
    assert_eq!(entry(&v, "secrets/stray.age")["not_referenced"], true);

    // The same directory reached through a symbolic link in its parent path:
    // the walk spells every file differently from the recipe, and the files
    // are matched by identity, one record each.
    let via = alias_root.join("viaroot/secrets");
    let o = l.run(&[
        "secrets",
        "list",
        "--format",
        "json",
        "--recipe",
        "r.yaml",
        via.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(count(&v), 3, "{v:#}");
    let real = entry(&v, "viaroot/secrets/real.age");
    assert_eq!(real["not_referenced"], false, "{v:#}");
    assert_eq!(used_by(real), ["r.yaml|file:k"]);
    assert_eq!(
        entry(&v, "viaroot/secrets/hard.age")["not_referenced"],
        false
    );
    assert_eq!(
        entry(&v, "viaroot/secrets/stray.age")["not_referenced"],
        true
    );
}

#[test]
fn a_case_variant_spelling_is_matched_where_the_filesystem_ignores_case() {
    let l = lab("inv-case");
    l.age("secrets/Case.age");
    if !l.dir.join("SECRETS/CASE.AGE").exists() {
        return; // case-sensitive filesystem: the spelling cannot alias
    }
    // The recipe spells the file differently from the directory walk.
    l.recipe("r.yaml", &file_res("k", "SECRETS/CASE.AGE"));
    let v = l.json(&["--recipe", "r.yaml"]);
    assert_eq!(entry(&v, "Case.age")["not_referenced"], false, "{v:#}");
    assert_eq!(count(&v), 1, "{v:#}");
}

#[test]
fn only_a_parsed_age_file_can_be_called_unreferenced() {
    let l = lab("inv-eligible");
    std::fs::write(l.dir.join("secrets/notage.age"), b"hello").unwrap();
    std::fs::write(
        l.dir.join("secrets/future.age"),
        b"age-encryption.org/v2\n-> x\n--- AAAA\n",
    )
    .unwrap();
    symlink(
        l.dir.join("secrets/notage.age"),
        l.dir.join("secrets/link.age"),
    )
    .unwrap();
    l.age("secrets/real.age");
    l.recipe("r.yaml", &file_res("k", "secrets/real.age"));
    let v = l.json(&["--recipe", "r.yaml"]);
    for name in ["notage.age", "future.age", "link.age"] {
        let e = entry(&v, name);
        assert_ne!(e["status"], "ok", "{name}");
        assert_eq!(e["not_referenced"], serde_json::Value::Null, "{name}");
    }
    let t = String::from_utf8_lossy(&l.run(&["secrets", "list", "--recipe", "r.yaml"]).stdout)
        .to_string();
    assert!(!t.contains("not referenced"), "{t}");
}

// ---------------------------------------------------------------------------
// identity.age
// ---------------------------------------------------------------------------

#[test]
fn a_possible_identity_file_is_never_presented_as_unreferenced() {
    let l = lab("inv-identity");
    l.age_passphrase("identity.age");
    l.age_passphrase("secrets/identity.age");
    l.age("secrets/stray.age");
    let real = l.age("secrets/real.age");
    l.recipe("r.yaml", &file_res("k", "secrets/real.age"));
    // another name for the same file Sinter's discovery would pick
    std::fs::hard_link(l.dir.join("identity.age"), l.dir.join("copy.age")).unwrap();
    // an ordinary file whose name merely resembles the identity name
    std::fs::copy(&real, l.dir.join("secrets/identity-old.age")).unwrap();

    let v = l.json(&["--recipe", "r.yaml"]);
    for name in ["./identity.age", "secrets/identity.age", "copy.age"] {
        let e = v["secrets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["path"].as_str().unwrap().ends_with(name))
            .unwrap();
        assert_eq!(e["possible_identity_file"], true, "{name}");
        assert_eq!(e["not_referenced"], serde_json::Value::Null, "{name}");
    }
    // Only the exact name (or the same file) counts: no guessing from a
    // similar name.
    let old = entry(&v, "identity-old.age");
    assert_eq!(old["possible_identity_file"], false);
    assert_eq!(old["not_referenced"], true);
    assert_eq!(entry(&v, "secrets/stray.age")["not_referenced"], true);

    let o = l.run(&["secrets", "list", "--recipe", "r.yaml"]);
    for line in String::from_utf8_lossy(&o.stdout).lines() {
        if line.contains("identity.age") || line.contains("copy.age") {
            assert!(line.contains("possible Sinter identity file"), "{line}");
            assert!(!line.contains("not referenced"), "{line}");
        }
    }
}

// ---------------------------------------------------------------------------
// non-decrypting and identity-free
// ---------------------------------------------------------------------------

#[test]
fn the_inventory_needs_no_key_no_terminal_and_never_looks_for_one() {
    let l = lab("inv-nokey");
    l.age("secrets/a.age");
    l.age_passphrase("secrets/p.age");
    l.recipe(
        "r.yaml",
        &format!(
            "{}{}",
            file_res("a", "secrets/a.age"),
            user_res("p", "svc", "secrets/p.age")
        ),
    );
    // No identity exists, SINTER_IDENTITY points nowhere (and would fail any
    // attempt to use it), nothing could be typed.
    let mut c = Command::new(env!("CARGO_BIN_EXE_sinter"));
    c.args(["secrets", "list", "--format", "json", "--recipe", "r.yaml"])
        .current_dir(&l.dir)
        .env_clear()
        .env("HOME", l.dir.join("home"))
        .env(
            "SINTER_IDENTITY",
            "/nonexistent/identity-that-must-not-be-read",
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let o = c.output().unwrap();
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let all = text(&o);
    assert!(!all.contains(CANARY), "{all}");
    assert!(!all.contains("passphrase:"), "{all}");
    assert!(!all.contains("nonexistent"), "{all}");
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(entry(&v, "secrets/a.age")["method"], "recipients");
    assert_eq!(entry(&v, "secrets/p.age")["method"], "passphrase");
}

#[test]
fn recovery_warnings_are_the_header_facts_only() {
    let l = lab("inv-recovery");
    l.age("secrets/single.age");
    l.age_passphrase("secrets/pass.age");
    l.recipe(
        "r.yaml",
        &format!(
            "{}{}",
            file_res("a", "secrets/single.age"),
            user_res("p", "svc", "secrets/pass.age")
        ),
    );
    let v = l.json(&["--recipe", "r.yaml"]);
    assert!(entry(&v, "secrets/pass.age")["note"]
        .as_str()
        .unwrap()
        .contains("forgotten passphrase cannot be recovered"));
    // Notes never claim anything about who can decrypt.
    for e in v["secrets"].as_array().unwrap() {
        let note = e["note"].as_str().unwrap_or("").to_lowercase();
        for claim in ["can decrypt", "recoverable", "your identity", "you can"] {
            assert!(!note.contains(claim), "{claim}: {note}");
        }
    }
}

// ---------------------------------------------------------------------------
// paths are not turned into host paths
// ---------------------------------------------------------------------------

#[test]
fn recipe_labels_are_the_operators_arguments() {
    let l = lab("inv-labels2");
    l.age("sub/secrets/a.age");
    l.recipe("sub/r.yaml", &file_res("k", "secrets/a.age"));
    let v = l.json(&["--recipe", "./sub/r.yaml"]);
    assert_eq!(v["recipes"], serde_json::json!(["./sub/r.yaml"]));
    let e = entry(&v, "sub/secrets/a.age");
    assert_eq!(used_by(e), ["./sub/r.yaml|file:k"]);
    assert!(!v.to_string().contains(l.dir.to_str().unwrap()), "{v:#}");
}

/// The recipe argument may be an absolute path: it is shown as given.
#[test]
fn an_absolute_recipe_argument_is_shown_as_given() {
    let l = lab("inv-abs");
    l.age("secrets/a.age");
    let r = l.recipe("r.yaml", &file_res("k", "secrets/a.age"));
    let abs: &Path = r.as_path();
    let v = l.json(&["--recipe", abs.to_str().unwrap()]);
    assert_eq!(v["recipes"], serde_json::json!([abs.to_str().unwrap()]));
}

// ---------------------------------------------------------------------------
// the strict loader stays strict for everything else
// ---------------------------------------------------------------------------

#[test]
fn bundles_and_every_other_caller_still_require_the_secret_to_exist() {
    let l = lab("inv-strict");
    l.age("secrets/here.age");
    l.recipe("ra.yaml", &file_res("a", "secrets/here.age"));
    l.recipe("rb.yaml", &file_res("b", "secrets/gone.age"));
    std::fs::write(
        l.dir.join("bundle.yaml"),
        "version: 1\nrecipes:\n  - ra.yaml\n  - rb.yaml\n",
    )
    .unwrap();
    // library loaders
    assert!(sinter::bundle::load_source(&l.dir.join("bundle.yaml")).is_err());
    assert!(sinter::bundle::load_source(&l.dir.join("rb.yaml")).is_err());
    assert!(load_model(&l.dir.join("rb.yaml")).is_err());
    assert!(sinter::bundle::load_source(&l.dir.join("ra.yaml")).is_ok());
    // commands that load a recipe
    for sub in ["validate", "plan", "audit"] {
        let o = l.run(&[sub, "rb.yaml"]);
        assert_eq!(o.status.code(), Some(2), "{sub}: {}", text(&o));
        assert!(
            text(&o).contains("secret file not found"),
            "{sub}: {}",
            text(&o)
        );
    }
    let o = l.run(&["validate", "bundle.yaml"]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    // the inventory is the only reader that tolerates it
    let v = l.json(&["--recipe", "bundle.yaml"]);
    assert_eq!(entry(&v, "secrets/gone.age")["status"], "missing");
}

#[test]
fn recipe_mode_adds_only_additive_keys_to_each_entry() {
    let l = lab("inv-keys");
    l.age("secrets/a.age");
    l.recipe("r.yaml", &file_res("k", "secrets/a.age"));
    let plain = l.json(&[]);
    let with = l.json(&["--recipe", "r.yaml"]);
    let base: std::collections::BTreeSet<_> = plain["secrets"][0]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    let more: std::collections::BTreeSet<_> = with["secrets"][0]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    assert!(base.is_subset(&more));
    let added: Vec<_> = more.difference(&base).cloned().collect();
    assert_eq!(
        added,
        ["not_referenced", "possible_identity_file", "referenced_by"]
    );
    // every Phase B value is unchanged
    for k in &base {
        assert_eq!(plain["secrets"][0][k], with["secrets"][0][k], "{k}");
    }
}

// ---------------------------------------------------------------------------
// review follow-ups
// ---------------------------------------------------------------------------

/// Restores a mode when dropped, so a failing assertion cannot leave a
/// mode-000 directory behind in the shared test root.
struct ModeGuard(PathBuf, u32);

impl Drop for ModeGuard {
    fn drop(&mut self) {
        set_mode(&self.0, self.1);
    }
}

/// Phase B output, exactly: fixed fixtures, relative paths, golden text/JSON.
#[test]
fn without_recipe_the_listing_is_exactly_the_phase_b_listing() {
    let l = lab("inv-golden");
    let fx = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/secrets");
    std::fs::create_dir_all(l.dir.join("s")).unwrap();
    for n in ["go-recipient.age", "go-passphrase.age"] {
        std::fs::copy(format!("{fx}/{n}"), l.dir.join("s").join(n)).unwrap();
    }
    std::fs::write(
        l.dir.join("s/future.age"),
        b"age-encryption.org/v2\n-> x\n--- AAAA\n",
    )
    .unwrap();
    std::fs::write(l.dir.join("s/notage.age"), b"hi\n").unwrap();
    let t = l.run(&["secrets", "list", "s"]);
    assert_eq!(
        String::from_utf8_lossy(&t.stdout),
        "STATUS      METHOD      RECIPIENTS  PATH\n\
         unsupported -           -           s/future.age\n\
         ok          passphrase  1           s/go-passphrase.age  (a forgotten passphrase cannot be recovered)\n\
         ok          recipients  2           s/go-recipient.age\n\
         not-age     -           -           s/notage.age\n"
    );
    assert!(t.stderr.is_empty());
    let j = l.run(&["secrets", "list", "--format", "json", "s"]);
    let want = serde_json::json!({
        "command": "secrets list",
        "truncated": false,
        "secrets": [
            {"armored": false, "method": null, "note": null, "path": "s/future.age", "recipients": null, "status": "unsupported"},
            {"armored": false, "method": "passphrase", "note": "a forgotten passphrase cannot be recovered", "path": "s/go-passphrase.age", "recipients": 1, "status": "ok"},
            {"armored": false, "method": "recipients", "note": null, "path": "s/go-recipient.age", "recipients": 2, "status": "ok"},
            {"armored": false, "method": null, "note": null, "path": "s/notage.age", "recipients": null, "status": "not-age"}
        ]
    });
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&j.stdout).unwrap(),
        want
    );
}

/// A reference that cannot be inspected might still be the very file a listed
/// hard link names: no "not referenced" conclusion is allowed then.
#[test]
fn an_uninspectable_reference_withholds_every_unreferenced_conclusion() {
    if unsafe { libc::geteuid() } == 0 {
        return; // root can traverse everything: nothing is uninspectable
    }
    let l = lab("inv-hardlink-denied");
    let sealed = l.age("sealed/s.age");
    // the same file under another name, in a readable place
    std::fs::hard_link(&sealed, l.dir.join("secrets/alias.age")).unwrap();
    l.age("secrets/other.age");
    l.recipe("r.yaml", &file_res("k", "sealed/s.age"));
    let _guard = ModeGuard(l.dir.join("sealed"), 0o700);
    set_mode(&l.dir.join("sealed"), 0o000);
    let v = l.json(&["--recipe", "r.yaml", "secrets"]);
    for e in v["secrets"].as_array().unwrap() {
        assert_eq!(e["not_referenced"], serde_json::Value::Null, "{v:#}");
    }
    let t = l.run(&["secrets", "list", "--recipe", "r.yaml", "secrets"]);
    assert!(!String::from_utf8_lossy(&t.stdout).contains("not referenced by"));
}

#[test]
fn spelling_the_same_recipe_or_missing_file_two_ways_changes_nothing() {
    let l = lab("inv-spelling");
    l.recipe("sub/r.yaml", &file_res("k", "secrets/gone.age"));
    l.recipe("sub/r2.yaml", &file_res("k2", "secrets/gone.age"));
    let v = l.json(&[
        "--recipe",
        "./sub/r.yaml",
        "--recipe",
        "sub/r2.yaml",
        "--recipe",
        "sub/../sub/r.yaml",
    ]);
    assert_eq!(count(&v), 1, "{v:#}");
    let m = &v["secrets"][0];
    assert_eq!(m["status"], "missing");
    assert_eq!(used_by(m).len(), 3, "{v:#}");
    // three arguments, two distinct files: the wording does not claim three
    l.age("other/a.age");
    let o = l.run(&[
        "secrets",
        "list",
        "--recipe",
        "./sub/r.yaml",
        "--recipe",
        "sub/r.yaml",
        "--recipe",
        "sub/r2.yaml",
        "other",
    ]);
    let t = String::from_utf8_lossy(&o.stdout).to_string();
    assert!(t.contains("not referenced by the 2 recipe(s) given"), "{t}");
    assert!(t.contains("covers only the 2 recipe(s)"), "{t}");
}
