#![cfg(target_os = "linux")]
mod common;

use common::*;
use sinter::engine::Mode;
use sinter::result::{Change, Execution, Verification};

#[test]
fn failure_before_publication_leaves_old_file() {
    let dir = trusted_root("fault-before");
    let out = dir.join("f");
    std::fs::write(&out, "old").unwrap();
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: new\n",
            out.display()
        ),
    );
    let r = run_recipe_fault(&recipe, Mode::Apply, "before_publish");
    let f = find(&r, "f");
    assert_eq!(f.execution, Execution::Failed);
    assert_eq!(f.change, Change::None);
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "old");
    // No staging artifact remains.
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with(".sinter"))
        .collect();
    assert!(leftovers.is_empty(), "staging artifacts left behind");
}

#[test]
fn failure_after_publication_reports_changed_and_failure() {
    let dir = trusted_root("fault-after");
    let out = dir.join("f");
    std::fs::write(&out, "old").unwrap();
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: new\n",
            out.display()
        ),
    );
    let r = run_recipe_fault(&recipe, Mode::Apply, "after_publish");
    let f = find(&r, "f");
    assert_eq!(
        f.change,
        Change::Changed,
        "published change must be reported"
    );
    assert_eq!(f.verification, Verification::Failed);
    assert_eq!(f.execution, Execution::Failed);
    // The new content is visible: publication happened.
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "new");
}

#[test]
fn unsupported_security_metadata_refuses_replacement() {
    // Requires getfattr and root.
    if !sudo_available() || !std::path::Path::new("/usr/bin/getfattr").exists() {
        skip_or_fail("requires sudo and getfattr");
        return;
    }
    let dir = trusted_root_sudo("secmeta");
    let out = dir.join("f");
    write_file_sudo(&out, b"old");
    // Add a security.* xattr (needs root).
    let st = std::process::Command::new("sudo")
        .args(["-n", "setfattr", "-n", "security.sinter_test", "-v", "x"])
        .arg(&out)
        .status()
        .expect("setfattr");
    assert!(st.success());
    let recipe = write_recipe(
        &trusted_root("secmeta-recipe"),
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: new\n",
            out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, true);
    let f = find(&r, "f");
    assert_eq!(f.execution, Execution::Failed);
    assert!(f.reason.as_deref().unwrap_or("").contains("security"));
    assert_eq!(read_file_sudo(&out), "old");
}

#[test]
fn user_xattrs_preserved_across_replacement() {
    if !std::path::Path::new("/usr/bin/getfattr").exists()
        || !std::path::Path::new("/usr/bin/setfattr").exists()
    {
        skip_or_fail("requires getfattr and setfattr");
        return;
    }
    let dir = trusted_root("xattr-preserve");
    let out = dir.join("f");
    std::fs::write(&out, "old").unwrap();
    let st = std::process::Command::new("setfattr")
        .args(["-n", "user.sinter", "-v", "hello"])
        .arg(&out)
        .status()
        .expect("setfattr");
    if !st.success() {
        skip_or_fail("filesystem may not support user xattrs");
        return;
    }
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: new\n",
            out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r);
    let got = std::process::Command::new("getfattr")
        .args(["-n", "user.sinter", "--only-values"])
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&got.stdout).trim(), "hello");
}

#[test]
fn metadata_only_update_succeeds() {
    let dir = trusted_root("meta-only");
    let out = dir.join("f");
    std::fs::write(&out, "same").unwrap();
    set_mode(&out, 0o600);
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: same\n      mode: \"0644\"\n",
            out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r);
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&out).unwrap().permissions().mode() & 0o7777,
        0o644
    );
    assert_eq!(find(&r, "f").change, Change::Changed);

    let r2 = run_recipe(&recipe, Mode::Apply, false);
    assert_eq!(find(&r2, "f").change, Change::None);
    assert_eq!(mutation_command_count(&r2), 0);
}

/// The program that sets the `security.*` fixture attribute. Tests may point
/// `SINTER_TEST_SETFATTR` elsewhere only to prove that a missing or failing
/// `setfattr` fails the test under `SINTER_TEST_STRICT=1` instead of leaving
/// an unprepared fixture behind.
fn setfattr_program() -> String {
    std::env::var("SINTER_TEST_SETFATTR").unwrap_or_else(|_| "/usr/bin/setfattr".to_string())
}

#[test]
fn plan_reports_unsupported_metadata_without_mutating() {
    if !sudo_available() || !std::path::Path::new("/usr/bin/getfattr").exists() {
        skip_or_fail("requires sudo and getfattr");
        return;
    }
    let setfattr = setfattr_program();
    if !std::path::Path::new(&setfattr).exists() {
        skip_or_fail("requires setfattr");
        return;
    }
    let dir = trusted_root_sudo("plan-secmeta");
    let out = dir.join("f");
    write_file_sudo(&out, b"old");
    // The fixture is a file carrying a security.* attribute Sinter cannot
    // preserve. Without it the Plan below inspects a plain file and proves
    // nothing, so a failure to set it must not fall through to the asserts.
    let st = std::process::Command::new("sudo")
        .args(["-n", &setfattr, "-n", "security.sinter_test2", "-v", "x"])
        .arg(&out)
        .status()
        .expect("sudo setfattr");
    if !st.success() {
        skip_or_fail("could not set security.sinter_test2 on the fixture file");
        return;
    }
    let got = std::process::Command::new("sudo")
        .args([
            "-n",
            "getfattr",
            "-n",
            "security.sinter_test2",
            "--only-values",
        ])
        .arg(&out)
        .output()
        .expect("sudo getfattr");
    assert!(
        got.status.success(),
        "fixture attribute must be readable back: {}",
        String::from_utf8_lossy(&got.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&got.stdout).trim(), "x");
    let recipe = write_recipe(
        &trusted_root("plan-secmeta-recipe"),
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: new\n",
            out.display()
        ),
    );
    // Plan runs apply's security metadata check and reports the refusal apply
    // would make (nothing earlier in the run can change the file), without
    // mutating anything.
    let Err(e) = try_run_recipe(&recipe, Mode::Plan, true) else {
        panic!("plan must report the refusal");
    };
    assert!(
        e.message.contains("refusing content replacement")
            && e.message.contains("security.sinter_test2")
            && e.message
                .contains("security metadata check would refuse this change at apply"),
        "{}",
        e.message
    );
    assert_eq!(read_file_sudo(&out), "old");
}

/// A `setfattr` that is not installed skips the Plan fixture test, and fails
/// it under `SINTER_TEST_STRICT=1` (the release gate) instead of passing
/// without the security attribute.
#[test]
fn missing_setfattr_fails_under_strict_mode() {
    if !sudo_available() || !std::path::Path::new("/usr/bin/getfattr").exists() {
        skip_or_fail("requires sudo and getfattr");
        return;
    }
    assert_skips_unless_strict(
        "plan_reports_unsupported_metadata_without_mutating",
        "requires setfattr",
        &[("SINTER_TEST_SETFATTR", "/nonexistent/setfattr")],
        &[],
    );
}

/// A `setfattr` that is installed but fails to set the attribute skips the
/// Plan fixture test, and fails it under `SINTER_TEST_STRICT=1`.
#[test]
fn failing_setfattr_fails_under_strict_mode() {
    if !sudo_available() || !std::path::Path::new("/usr/bin/getfattr").exists() {
        skip_or_fail("requires sudo and getfattr");
        return;
    }
    assert_skips_unless_strict(
        "plan_reports_unsupported_metadata_without_mutating",
        "could not set security.sinter_test2 on the fixture file",
        &[("SINTER_TEST_SETFATTR", "/bin/false")],
        &[],
    );
}

fn write_file_sudo(path: &std::path::Path, data: &[u8]) {
    let p = path.to_string_lossy().to_string();
    let mut child = std::process::Command::new("sudo")
        .args(["-n", "tee"])
        .arg(&p)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("sudo tee");
    use std::io::Write;
    child.stdin.as_mut().unwrap().write_all(data).unwrap();
    let st = child.wait().unwrap();
    assert!(st.success());
}

#[test]
fn atomic_publication_preserves_existing_inode_visibility() {
    // Verify rename-based publication rather than in-place truncation by
    // checking that the inode changes across replacement.
    let dir = trusted_root("atomic");
    let out = dir.join("f");
    std::fs::write(&out, "old").unwrap();
    use std::os::unix::fs::MetadataExt;
    let before = std::fs::metadata(&out).unwrap().ino();
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: new content\n",
            out.display()
        ),
    );
    let r = run_recipe(&recipe, Mode::Apply, false);
    assert_success(&r);
    let after = std::fs::metadata(&out).unwrap().ino();
    assert_ne!(before, after, "replacement must use atomic rename");
}

#[test]
fn inability_to_inspect_metadata_refuses_replacement() {
    // When security-metadata inspection cannot be performed, content replacement
    // must be refused rather than silently treating failure as absence.
    if !std::path::Path::new("/usr/bin/getfattr").exists() {
        skip_or_fail("requires getfattr");
        return;
    }
    let dir = trusted_root("uninspectable");
    let out = dir.join("f");
    std::fs::write(&out, "old").unwrap();
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: new\n",
            out.display()
        ),
    );
    let r = run_recipe_fault(&recipe, Mode::Apply, "uninspectable_metadata");
    let f = find(&r, "f");
    assert_eq!(f.execution, Execution::Failed);
    assert!(
        f.reason.as_deref().unwrap_or("").contains("inspect"),
        "reason: {:?}",
        f.reason
    );
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "old");
}
