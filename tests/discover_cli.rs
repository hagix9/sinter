//! `sinter discover` command line (DESIGN §46.1): every refusal happens
//! before any host is contacted (the hosts here are unroutable or absent).

use std::os::unix::fs::PermissionsExt;
use std::process::Command;

fn sinter(dir: &std::path::Path, args: &[&str]) -> (i32, String, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_sinter"))
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

fn private_dir() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(
        d.path().join("hosts.yaml"),
        "hosts:\n  web01:\n    address: 192.0.2.10\n  web02:\n    address: 192.0.2.11\ngroups:\n  web: [web01, web02]\n  one: [web01]\n",
    )
    .unwrap();
    d
}

#[test]
fn exactly_one_host() {
    let d = private_dir();
    for args in [
        vec!["discover", "--output", "r.yaml"],
        vec!["discover", "@web", "--output", "r.yaml"],
        vec!["discover", "web01,web02", "--output", "r.yaml"],
        vec!["discover", "nosuch", "--output", "r.yaml"],
        vec![
            "discover",
            "--host",
            "192.0.2.10",
            "web01",
            "--output",
            "r.yaml",
        ],
        vec![
            "discover",
            "--host",
            "192.0.2.10",
            "--inventory",
            "hosts.yaml",
            "--output",
            "r.yaml",
        ],
    ] {
        let (code, _, err) = sinter(d.path(), &args);
        assert_eq!(code, 2, "{args:?}: {err}");
    }
    assert!(!d.path().join("r.yaml").exists());
}

#[test]
fn output_is_required_and_never_overwritten() {
    let d = private_dir();
    let (code, _, _) = sinter(d.path(), &["discover", "web01"]);
    assert_eq!(code, 2, "--output is required");
    std::fs::write(d.path().join("r.yaml"), "keep").unwrap();
    let (code, _, err) = sinter(d.path(), &["discover", "web01", "--output", "r.yaml"]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("already exists"), "{err}");
    assert_eq!(
        std::fs::read_to_string(d.path().join("r.yaml")).unwrap(),
        "keep"
    );
    std::fs::write(d.path().join("s.yaml.discover.json"), "keep").unwrap();
    let (code, _, _) = sinter(d.path(), &["discover", "web01", "--output", "s.yaml"]);
    assert_eq!(code, 2);
    std::os::unix::fs::symlink("/nonexistent", d.path().join("t.yaml")).unwrap();
    let (code, _, _) = sinter(d.path(), &["discover", "web01", "--output", "t.yaml"]);
    assert_eq!(code, 2);
}

#[test]
fn bad_options_are_refused_before_contact() {
    let d = private_dir();
    for args in [
        vec![
            "discover",
            "web01",
            "--output",
            "r.yaml",
            "--include-path",
            "etc/motd",
        ],
        vec![
            "discover",
            "web01",
            "--output",
            "r.yaml",
            "--include-path",
            "/etc/../shadow",
        ],
        vec![
            "discover",
            "web01",
            "--output",
            "r.yaml",
            "--include-path",
            "/etc/a",
            "--include-path",
            "/etc/a",
        ],
        vec![
            "discover",
            "web01",
            "--output",
            "r.yaml",
            "--profile",
            "units",
            "--include-path",
            "/etc/a",
        ],
        vec![
            "discover",
            "web01",
            "--output",
            "r.yaml",
            "--profile",
            "firewalld",
        ],
    ] {
        let (code, _, err) = sinter(d.path(), &args);
        assert_eq!(code, 2, "{args:?}: {err}");
    }
}

#[test]
fn discover_is_listed_but_plan_and_apply_options_are_not_accepted() {
    let d = private_dir();
    let (code, out, _) = sinter(d.path(), &["discover", "--help"]);
    assert_eq!(code, 0);
    assert!(out.contains("--include-path") && out.contains("--output"));
    for opt in ["--approval", "--format", "--vars-file"] {
        let (code, _, _) = sinter(
            d.path(),
            &["discover", "web01", "--output", "r.yaml", opt, "x"],
        );
        assert_eq!(code, 2, "{opt}");
    }
}
