//! Round-5 audit remediation regression tests (R4-F01 .. R4-F05).
//!
//! Every case drives the production parser/control path: a scripted in-process
//! FakeTarget so platform detection, backend selection, the private-snapshot
//! lifecycle, payload-URL validation, DNF grammar parsing, identifier
//! validation, and result classification all run production code. Malformed,
//! ambiguous or uninterpretable input must fail closed — no copy, no payload
//! download and no mutation — while valid, native DNF output still completes.
//!
//! The Astra reproductions are fed through the production decision path via
//! explicit helper-output overrides (the live-cache `find -print0` answer, the
//! `mktemp` answer, `repolist -v`, the `--assumeno` transaction table, the
//! download-only answer, and the snapshot payload listing), so the
//! boundary being hardened is the one that actually runs.

mod common;

use common::*;
use sinter::engine::Mode;
use sinter::executor::{Completion, DnfRepo, FakeTarget, Output};
use sinter::result::{Change, Execution, Verification};

/// The private snapshot root the scripted target hands out via `mktemp`.
const FAKE_SNAP: &str = "/var/tmp/sinter-dnf.fakesnap";

/// The live DNF metadata cache root the snapshot is copied from.
const LIVE_CACHE_ROOT: &str = "/var/cache/dnf";

/// The native libdnf cache hash format this target models (16 hex chars).
const CACHE_HASH: &str = "cafebabecafebabe";

// ===========================================================================
// Shared helpers
// ===========================================================================

fn pkg_recipe(dir: &std::path::Path, name: &str, state: &str) -> std::path::PathBuf {
    write_recipe(
        dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: {}\n      state: {}\n",
            name, state
        ),
    )
}

fn commands_with<'a>(
    report: &'a sinter::engine::RunReport,
    prog: &str,
) -> Vec<&'a sinter::executor::CommandRecord> {
    report
        .commands
        .iter()
        .filter(|c| c.program == prog)
        .collect()
}

fn dnf_mutations(report: &sinter::engine::RunReport) -> usize {
    report
        .commands
        .iter()
        .filter(|c| {
            c.program == "/usr/bin/dnf"
                && c.args.iter().any(|a| a == "-y")
                && !c.args.iter().any(|a| a == "--downloadonly")
        })
        .count()
}

/// Payload-transport dispatches: the native `dnf install --downloadonly`
/// invocation that fills the snapshot package cache. Explicit fetchers
/// (curl/wget) are gone — librepo owns the transfer.
fn downloads(report: &sinter::engine::RunReport) -> usize {
    commands_with(report, "/usr/bin/dnf")
        .into_iter()
        .filter(|c| c.args.iter().any(|a| a == "--downloadonly"))
        .count()
}

fn copies(report: &sinter::engine::RunReport) -> usize {
    commands_with(report, "/usr/bin/cp").len()
}

fn override_output(completion: Completion, stdout: &str, stderr: &str) -> Output {
    Output {
        completion,
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

/// Override raw stdout bytes for the live-cache `find -print0` answer.
fn override_find_stdout(bytes: &[u8]) -> Output {
    Output {
        completion: Completion::Exited(0),
        stdout: bytes.to_vec(),
        stderr: Vec::new(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

/// A well-formed `dnf repolist -v` block for one enabled repository, in the
/// native upstream shape: opened by `Repo-id`, always showing `Repo-name`,
/// with the conditional fields a mirror-resolving repository prints. Plain
/// `repolist -v` prints no `Repo-status`. The `Total packages: N` footer is
/// dnf's once-per-output line, so it is appended by the caller after the last
/// block — never per block.
fn dnf_repolist_block(repoid: &str, mirrors: bool) -> String {
    let mut fields = vec![
        format!("Repo-id            : {}", repoid),
        format!("Repo-name          : {}", repoid),
    ];
    if mirrors {
        fields.push("Repo-mirrors       : https://mirrors.example/?repo=x".into());
    }
    fields.push("Repo-expire        : Never (last: unknown)".into());
    fields.push("Repo-filename      : /etc/yum.repos.d/fake.repo".into());
    fields.join("\n")
}

/// The `CliError` line an `--assumeno` install leaves on stderr: the abort
/// is logged at ERROR level, so it lands on stderr — never stdout (R5-F04).
const DNF_ABORT_STDERR: &str = "Operation aborted.\n";

/// A well-formed `dnf install --assumeno` transaction table for one package,
/// in the real dnf 4.14 stream layout (R5-F04): the INFO-level metadata-age
/// line, `Dependencies resolved.`, the wide column header (`Architecture`/
/// `Repository` are the long forms dnf picks when the columns allow), and
/// the `Installed size:` trailer. `Operation aborted.` is *not* part of
/// stdout — callers pass it as the dry-run's stderr.
fn dnf_transaction_table(name: &str, repoid: &str) -> String {
    format!(
        "Last metadata expiration check: 0:30:00 ago on Wed Sep 16 10:28:01 2026.\n\
         Dependencies resolved.\n\
         ================================================================================\n \
         Package        Architecture     Version                 Repository        Size\n\
         ================================================================================\n\
         Installing:\n \
         {n:<15}x86_64           1.0-1.el9             {r:<16} 1 k\n\n\
         Transaction Summary\n\
         ================================================================================\n\
         Install  1 Package\n\n\
         Total download size: 1 k\n\
         Installed size: 2 k\n",
        n = name,
        r = repoid
    )
}

/// A transaction table whose single row is arbitrary raw text (used to model
/// transaction-derived identifiers that are not valid operands).
fn dnf_transaction_row_raw(row: &str) -> String {
    format!(
        "Last metadata expiration check: 0:30:00 ago on Wed Sep 16 10:28:01 2026.\n\
         Dependencies resolved.\n\
         ================================================================================\n \
         Package        Architecture     Version                 Repository        Size\n\
         ================================================================================\n\
         Installing:\n \
         {row}\n\n\
         Transaction Summary\n\
         ================================================================================\n\
         Install  1 Package\n\n\
         Total download size: 1 k\n\
         Installed size: 2 k\n",
        row = row
    )
}

/// Assert the resource was blocked by the snapshot contract: no copy, no
/// payload download and no mutation, with no change or verification claimed.
fn assert_blocked_no_mutation(r: &sinter::engine::RunReport) -> &sinter::result::ResourceResult {
    let p = find(r, "p");
    assert_eq!(p.execution, Execution::Failed, "blocked input must fail");
    assert_eq!(p.change, Change::None, "no mutation means no change claim");
    assert_eq!(
        p.verification,
        Verification::NotPerformed,
        "verification must not be claimed"
    );
    assert_eq!(
        dnf_mutations(r),
        0,
        "no mutation may be dispatched for uninterpretable input"
    );
    assert_eq!(
        downloads(r),
        0,
        "no payload download may be dispatched for uninterpretable input"
    );
    assert!(
        p.reason
            .as_deref()
            .unwrap_or("")
            .contains("repository metadata not locally complete"),
        "blocked reason must name the metadata contract: {:?}",
        p.reason
    );
    p
}

/// Assert the resource completed a full prefetch + mutation (the positive
/// control shape: valid input is never rejected).
fn assert_full_install(r: &sinter::engine::RunReport) {
    let p = find(r, "p");
    assert_eq!(
        p.execution,
        Execution::Succeeded,
        "valid input must succeed"
    );
    assert_eq!(p.change, Change::Changed);
    assert_eq!(p.verification, Verification::Verified);
    assert_eq!(downloads(r), 1, "the payload must be prefetched");
    assert_eq!(dnf_mutations(r), 1, "the mutation must run");
}

/// Assert the private snapshot was cleaned up exactly once.
fn assert_snapshot_cleaned(r: &sinter::engine::RunReport) {
    let rm = commands_with(r, "/usr/bin/rm");
    assert_eq!(
        rm.len(),
        1,
        "the private snapshot must be removed exactly once"
    );
    assert!(rm[0].args.iter().any(|a| a == FAKE_SNAP));
}

/// Assert no removal command was dispatched: an unverified snapshot path must
/// never become a cleanup target (R2-05, R4-F01).
fn assert_no_cleanup(r: &sinter::engine::RunReport) {
    assert!(
        commands_with(r, "/usr/bin/rm").is_empty(),
        "an unverified snapshot path must not be used as a cleanup target"
    );
}

// ===========================================================================
// R4-F01 — find enumeration / snapshot path boundary. External bytes must be
// captured, NUL-framed, then path-domain validated before any copy argv.
// ===========================================================================

/// The Astra reproduction: entries injected into the `find -print0` output
/// flow straight into a `cp -a --` argv. Every non-child value must be
/// rejected before any copy is dispatched.
#[test]
fn r5_f01_find_injection_rejected_before_copy() {
    let injections: &[&[u8]] = &[
        // An absolute path outside the cache root.
        b"/etc/passwd\0",
        // A relative path.
        b"../../etc\0",
        // Traversal from inside the root.
        b"/var/cache/dnf/../../etc\0",
        // The `.` form of the root.
        b"/var/cache/dnf/.\0",
        // A nested descendant, not a direct child.
        b"/var/cache/dnf/sub/nested\0",
        // The root itself.
        b"/var/cache/dnf\0",
        // A sibling root that merely shares the prefix.
        b"/var/cache/dnf-evil/x\0",
        // A `..` child.
        b"/var/cache/dnf/..\0",
    ];
    for (i, bytes) in injections.iter().enumerate() {
        let dir = trusted_root(&format!("r5-f01-inject-{}", i));
        let recipe = pkg_recipe(&dir, "nano", "present");
        let mut t = FakeTarget::rocky9();
        t.live_cache_find_output = Some(override_find_stdout(bytes));
        let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
        assert_blocked_no_mutation(&r);
        assert_eq!(
            copies(&r),
            0,
            "no copy may be dispatched for a non-child entry"
        );
        // The snapshot itself was valid, so its cleanup is safe and runs.
        assert_snapshot_cleaned(&r);
    }
}

/// A `find -print0` answer missing its trailing NUL is truncated framing.
#[test]
fn r5_f01_missing_trailing_nul_rejected() {
    let dir = trusted_root("r5-f01-no-trailing-nul");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.live_cache_find_output = Some(override_find_stdout(
        format!("{}/baseos-{}", LIVE_CACHE_ROOT, CACHE_HASH).as_bytes(),
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_eq!(copies(&r), 0);
    assert_snapshot_cleaned(&r);
}

/// An empty (doubled-NUL) entry is malformed framing.
#[test]
fn r5_f01_empty_entry_rejected() {
    let dir = trusted_root("r5-f01-empty-entry");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.live_cache_find_output = Some(override_find_stdout(
        b"/var/cache/dnf/a\0\0/var/cache/dnf/b\0",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_eq!(copies(&r), 0);
    assert_snapshot_cleaned(&r);
}

/// A duplicate entry is not a listing `find` prints.
#[test]
fn r5_f01_duplicate_entry_rejected() {
    let dir = trusted_root("r5-f01-dup-entry");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    let one = format!("{}/baseos-{}\0", LIVE_CACHE_ROOT, CACHE_HASH);
    t.live_cache_find_output = Some(override_find_stdout((one.clone() + &one).as_bytes()));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_eq!(copies(&r), 0);
    assert_snapshot_cleaned(&r);
}

/// Invalid UTF-8 must not be lossily converted into a different path.
#[test]
fn r5_f01_invalid_utf8_rejected() {
    let dir = trusted_root("r5-f01-bad-utf8");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.live_cache_find_output = Some(override_find_stdout(b"/var/cache/dnf/\xff\0"));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_eq!(copies(&r), 0);
    assert_snapshot_cleaned(&r);
}

/// Truncated stdout or unexpected stderr on the enumeration makes the answer
/// uninterpretable, so no copy may be dispatched.
#[test]
fn r5_f01_truncated_and_stderr_rejected() {
    for (label, out) in [
        (
            "truncated stdout",
            Output {
                completion: Completion::Exited(0),
                stdout: format!("{}/baseos-{}\0", LIVE_CACHE_ROOT, CACHE_HASH).into_bytes(),
                stderr: Vec::new(),
                stdout_truncated: true,
                stderr_truncated: false,
            },
        ),
        (
            "truncated stderr",
            Output {
                completion: Completion::Exited(0),
                stdout: format!("{}/baseos-{}\0", LIVE_CACHE_ROOT, CACHE_HASH).into_bytes(),
                stderr: Vec::new(),
                stdout_truncated: false,
                stderr_truncated: true,
            },
        ),
        (
            "unexpected stderr",
            Output {
                completion: Completion::Exited(0),
                stdout: format!("{}/baseos-{}\0", LIVE_CACHE_ROOT, CACHE_HASH).into_bytes(),
                stderr: b"find: error\n".to_vec(),
                stdout_truncated: false,
                stderr_truncated: false,
            },
        ),
    ] {
        let dir = trusted_root(&format!("r5-f01-{}", label.replace(' ', "-")));
        let recipe = pkg_recipe(&dir, "nano", "present");
        let mut t = FakeTarget::rocky9();
        t.live_cache_find_output = Some(out);
        let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
        assert_blocked_no_mutation(&r);
        assert_eq!(copies(&r), 0, "{}", label);
        assert_snapshot_cleaned(&r);
    }
}

/// The snapshot helper's own output is validated before any operation
/// targets it. A path outside the private namespace is never used — and is
/// never a cleanup target either, because cleanup on an unverified path is
/// exactly the unsafe operation (R2-05).
#[test]
fn r5_f01_snapshot_path_outside_namespace_rejected_without_cleanup() {
    for (i, bad) in [
        "/tmp/outside\n",
        "../outside\n",
        "/\n",
        ".\n",
        "..\n",
        "/var/tmp/sinter-dnf.\n",
        "/var/tmp/sinter-dnf.short\n",
        "/var/tmp/sinter-dnf.too-long\n",
        "/var/tmp/sinter-dnf.with/slash\n",
        "/var/tmp/other.fakesnap\n",
        "/var/tmp/sinter-dnf.fakesnap\nextra\n",
    ]
    .iter()
    .enumerate()
    {
        let dir = trusted_root(&format!("r5-f01-snap-{}", i));
        let recipe = pkg_recipe(&dir, "nano", "present");
        let mut t = FakeTarget::rocky9();
        t.mktemp_output = Some(override_output(Completion::Exited(0), bad, ""));
        let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
        assert_blocked_no_mutation(&r);
        // No chmod/stat/copy happened, and no cleanup was attempted on the
        // unverified path.
        assert!(commands_with(&r, "/usr/bin/chmod").is_empty());
        assert!(commands_with(&r, "/usr/bin/stat").is_empty());
        assert_eq!(copies(&r), 0);
        assert_no_cleanup(&r);
    }
}

/// Positive control: the copy accepts every legal direct child the cache root
/// may hold — hidden entries, spaces, newlines, leading dashes — because each
/// stays a discrete argv element after `--`. (Run on the real filesystem so
/// the copy semantics are exercised, mirroring the production loop.)
#[cfg(unix)]
#[test]
fn r5_f01_legal_children_are_copied_and_root_stays_private() {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    let work = std::env::temp_dir().join(format!("r5-f01-copy-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).unwrap();
    // A source cache root (0755, as /var/cache/dnf commonly is) with the
    // legal-but-unusual direct children the enumeration must not reject.
    let src = work.join("cache");
    std::fs::create_dir_all(&src).unwrap();
    let odd = [
        ".hidden-entry",
        "name with spaces",
        "name\nwith newline",
        "-leading-dash",
        "plain_child",
    ];
    for name in &odd {
        // A name containing a newline cannot be created as a regular file on
        // every filesystem: fall back to a directory there, and skip the
        // entry entirely where the FS rejects both forms.
        if std::fs::write(src.join(name), b"content\n").is_err() {
            if !name.contains('\n') {
                panic!("failed to create a plain child entry: {:?}", name);
            }
            std::fs::create_dir_all(src.join(name)).ok();
        }
    }
    let mut perm = std::fs::metadata(&src).unwrap().permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(&src, perm).unwrap();
    // The private destination root, 0700 as mktemp + chmod enforce.
    let dst = work.join("snap");
    std::fs::create_dir_all(&dst).unwrap();
    let mut perm = std::fs::metadata(&dst).unwrap().permissions();
    perm.set_mode(0o700);
    std::fs::set_permissions(&dst, perm).unwrap();

    // Enumerate exactly as production does, then copy each proven child.
    let list = Command::new("find")
        .args([
            src.to_str().unwrap(),
            "-mindepth",
            "1",
            "-maxdepth",
            "1",
            "-print0",
        ])
        .output()
        .expect("find failed");
    assert!(list.status.success());
    let children: Vec<String> = String::from_utf8_lossy(&list.stdout)
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    assert!(children.len() >= odd.len() - 1, "odd entries enumerated");
    for child in &children {
        let status = Command::new("cp")
            .args(["-a", "--", child, &format!("{}/", dst.display())])
            .status()
            .expect("cp failed");
        assert!(status.success(), "copy of {:?} failed", child);
        let mode = std::fs::metadata(&dst).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o700, "the snapshot root must stay 0700 during copy");
    }
    // Every copyable odd child arrived under the private root.
    assert!(dst.join(".hidden-entry").exists());
    assert!(dst.join("name with spaces").exists());
    assert!(dst.join("-leading-dash").exists());
    assert!(dst.join("plain_child").exists());
    let _ = std::fs::remove_dir_all(&work);
}

// ===========================================================================
// R4-F03 / R4-F04 — a strict but native-compatible DNF grammar. Malformed
// output fails closed; native valid output is accepted. Treated as two sides
// of one grammar contract.
// ===========================================================================

/// F04: native upstream DNF 4.14 `repolist -v` output — no `Repo-status`,
/// other native fields, and the `Total packages: N` footer — is accepted, and
/// the install completes.
#[test]
fn r5_f04_native_repolist_without_status_accepted() {
    let dir = trusted_root("r5-f04-native-repolist");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_repolist_output = Some(override_output(
        Completion::Exited(0),
        "Repo-id            : baseos\n\
         Repo-name          : Rocky Linux 9 - BaseOS\n\
         Repo-baseurl       : https://mirror.example/baseos\n\
         Repo-expire        : Never (last: unknown)\n\
         Repo-filename      : /etc/yum.repos.d/rocky.repo\n\
         Total packages: 0\n",
        "",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_full_install(&r);
    assert_snapshot_cleaned(&r);
}

/// F04: multiple repositories in the native shape — blank-separated blocks
/// with a single footer — are all accepted.
#[test]
fn r5_f04_native_multi_repo_repolist_accepted() {
    let dir = trusted_root("r5-f04-multi-repo");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_repos = vec![
        DnfRepo {
            id: "baseos".to_string(),
            mirrors: true,
            repodata_cached: true,
            mirrorlist_cached: true,
        },
        DnfRepo {
            id: "appstream".to_string(),
            mirrors: true,
            repodata_cached: true,
            mirrorlist_cached: true,
        },
    ];
    t.dnf_repolist_output = Some(override_output(
        Completion::Exited(0),
        &format!(
            "{}\n\n{}\nTotal packages: 2\n",
            dnf_repolist_block("baseos", true),
            dnf_repolist_block("appstream", true)
        ),
        "",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_full_install(&r);
    assert_snapshot_cleaned(&r);
}

/// F03: an orphan field after a completed block is not a continuation of it
/// — the block lifecycle is explicit, so a blank closes the block (the Astra
/// reproduction).
#[test]
fn r5_f03_orphan_field_after_block_rejected() {
    let dir = trusted_root("r5-f03-orphan-field");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_repolist_output = Some(override_output(
        Completion::Exited(0),
        &format!(
            "{}\n\nRepo-status        : enabled\n",
            dnf_repolist_block("baseos", true)
        ),
        "",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_snapshot_cleaned(&r);
}

/// F03: an unknown `Repo-*` field is not structure dnf prints and is not
/// tolerated as an extra.
#[test]
fn r5_f03_unknown_repo_field_rejected() {
    let dir = trusted_root("r5-f03-unknown-field");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_repolist_output = Some(override_output(
        Completion::Exited(0),
        "Repo-id            : baseos\nRepo-name          : BaseOS\nRepo-nonsense      : x\n",
        "",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_snapshot_cleaned(&r);
}

/// F03: a garbage footer is unrecognized trailing structure.
#[test]
fn r5_f03_garbage_footer_rejected() {
    for (i, footer) in [
        "Total packages: none",
        "Total packages: 01",
        "Total packages: 1,234",
        "Totally packages: 1",
        "Total packages 1",
    ]
    .iter()
    .enumerate()
    {
        let dir = trusted_root(&format!("r5-f03-footer-{}", i));
        let recipe = pkg_recipe(&dir, "nano", "present");
        let mut t = FakeTarget::rocky9();
        t.dnf_repolist_output = Some(override_output(
            Completion::Exited(0),
            &format!(
                "Repo-id            : baseos\nRepo-name          : BaseOS\n{}\n",
                footer
            ),
            "",
        ));
        let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
        assert_blocked_no_mutation(&r);
        assert_snapshot_cleaned(&r);
    }
}

/// F03: an unknown preamble before the transaction table makes the whole
/// table uninterpretable (the Astra reproduction: `ERROR rpm database
/// unavailable`).
#[test]
fn r5_f03_unknown_preamble_rejected() {
    let dir = trusted_root("r5-f03-bad-preamble");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_dry_run_output = Some(override_output(
        Completion::Exited(1),
        &format!(
            "ERROR rpm database unavailable\n{}",
            dnf_transaction_table("nano", "baseos")
        ),
        DNF_ABORT_STDERR,
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_snapshot_cleaned(&r);
}

/// F03: the column header must be the exact token sequence dnf prints — a
/// header whose first token merely starts with `Package` is not the header
/// (the Astra reproduction).
#[test]
fn r5_f03_fake_header_rejected() {
    let dir = trusted_root("r5-f03-fake-header");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_dry_run_output = Some(override_output(
        Completion::Exited(1),
        "Dependencies resolved.\n\
         ================================================================================\n \
         PackageEVIL Arch Version Repository Size\n\
         ================================================================================\n\
         Installing:\n \
         nano                   x86_64      1.0-1.el9              baseos          1 k\n\n\
         Transaction Summary\n\
         ================================================================================\n\
         Install  1 Package\n\n\
         Total download size: 1 k\n\
         Installed size: 2 k\n",
        DNF_ABORT_STDERR,
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_snapshot_cleaned(&r);
}

/// F03: a size value that is not a size dnf prints (the Astra reproduction:
/// `1..2 k`) is rejected by the same grammar the summary uses.
#[test]
fn r5_f03_malformed_size_rejected() {
    let dir = trusted_root("r5-f03-bad-size");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_dry_run_output = Some(override_output(
        Completion::Exited(1),
        &dnf_transaction_row_raw("nano x86_64 1.0-1.el9 baseos 1..2 k"),
        DNF_ABORT_STDERR,
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_snapshot_cleaned(&r);
}

/// F03: a non-canonical count (the Astra reproduction: `01`) is not a count
/// dnf prints.
#[test]
fn r5_f03_malformed_count_rejected() {
    let dir = trusted_root("r5-f03-bad-count");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_dry_run_output = Some(override_output(
        Completion::Exited(1),
        &dnf_transaction_table("nano", "baseos")
            .replace("Install  1 Package", "Install  01 Package"),
        DNF_ABORT_STDERR,
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_snapshot_cleaned(&r);
}

/// F03: a duplicated Transaction Summary verb is malformed.
#[test]
fn r5_f03_duplicate_summary_rejected() {
    let dir = trusted_root("r5-f03-dup-summary");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_dry_run_output = Some(override_output(
        Completion::Exited(1),
        &dnf_transaction_table("nano", "baseos").replace(
            "Install  1 Package",
            "Install  1 Package\nInstall  1 Package",
        ),
        DNF_ABORT_STDERR,
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_snapshot_cleaned(&r);
}

/// F03 positive control: a native-style upgrade transaction resolves and
/// completes; the downloaded payload's identity is verified against the
/// row's exact version.
#[test]
fn r5_f03_native_upgrade_transaction_accepted() {
    let dir = trusted_root("r5-f03-upgrade");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_dry_run_output = Some(override_output(
        Completion::Exited(1),
        "Dependencies resolved.\n\
         ================================================================================\n \
         Package                Arch        Version                Repository      Size\n\
         ================================================================================\n\
         Upgrading:\n \
         nano                   x86_64      2.0-1.el9              baseos          1 k\n\n\
         Transaction Summary\n\
         ================================================================================\n\
         Upgrade  1 Package\n\n\
         Total download size: 1 k\n\
         Installed size: 2 k\n",
        DNF_ABORT_STDERR,
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_full_install(&r);
    assert_snapshot_cleaned(&r);
}

/// F03 positive control: a dependency install (two rows, one summary count of
/// 2) resolves and completes.
#[test]
fn r5_f03_native_dependency_install_accepted() {
    let dir = trusted_root("r5-f03-deps");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_dry_run_output = Some(override_output(
        Completion::Exited(1),
        "Dependencies resolved.\n\
         ================================================================================\n \
         Package                Arch        Version                Repository      Size\n\
         ================================================================================\n\
         Installing:\n \
         nano                   x86_64      1.0-1.el9              baseos          1 k\n\
         Installing dependencies:\n \
         libnano                x86_64      1.0-1.el9              baseos          1 k\n\n\
         Transaction Summary\n\
         ================================================================================\n\
         Install  2 Packages\n\n\
         Total download size: 2 k\n\
         Installed size: 2 k\n",
        DNF_ABORT_STDERR,
    ));
    // Both payload rows are carried by one download-only transport call
    // as exact NEVRA operands.
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Succeeded);
    assert_eq!(p.change, Change::Changed);
    assert_eq!(p.verification, Verification::Verified);
    assert_eq!(downloads(&r), 1, "the payload transport runs once");
    let dl = commands_with(&r, "/usr/bin/dnf")
        .into_iter()
        .find(|c| c.args.iter().any(|a| a == "--downloadonly"))
        .expect("a payload transport call");
    assert!(dl.args.iter().any(|a| a == "nano-1.0-1.el9.x86_64"));
    assert!(dl.args.iter().any(|a| a == "libnano-1.0-1.el9.x86_64"));
    assert_eq!(dnf_mutations(&r), 1);
    assert_snapshot_cleaned(&r);
}

// ===========================================================================
// R4-F05 — transaction-derived identifiers are domain-validated before they
// reach a command or a path.
// ===========================================================================

/// A package name that is an option to the target CLI is rejected before it
/// can become a download-only operand (the Astra reproduction: `--refresh`).
#[test]
fn r5_f05_option_like_package_name_rejected() {
    let dir = trusted_root("r5-f05-opt-pkg");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_dry_run_output = Some(override_output(
        Completion::Exited(1),
        &dnf_transaction_row_raw("--refresh x86_64 1.0-1.el9 baseos 1 k"),
        DNF_ABORT_STDERR,
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    // No payload-transport call may be dispatched at all — the row failed
    // validation before any download-only operand could be constructed.
    assert!(
        commands_with(&r, "/usr/bin/dnf")
            .into_iter()
            .filter(|c| c.args.iter().any(|a| a == "--downloadonly"))
            .count()
            == 0,
        "no payload operand may carry an option-like value"
    );
    assert_snapshot_cleaned(&r);
}

/// A package name that is a path, or contains a separator or control byte, is
/// rejected before use.
#[test]
fn r5_f05_path_like_package_name_rejected() {
    for (i, name) in ["../x", "a/b", "a\nb"].iter().enumerate() {
        let dir = trusted_root(&format!("r5-f05-path-pkg-{}", i));
        let recipe = pkg_recipe(&dir, "nano", "present");
        let mut t = FakeTarget::rocky9();
        t.dnf_dry_run_output = Some(override_output(
            Completion::Exited(1),
            &dnf_transaction_row_raw(&format!("{} x86_64 1.0-1.el9 baseos 1 k", name)),
            "",
        ));
        let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
        assert_blocked_no_mutation(&r);
        assert_snapshot_cleaned(&r);
    }
}

/// A repository id that is not a safe path component is rejected before it
/// can recognize a cache directory (the Astra reproduction: `../escape`).
#[test]
fn r5_f05_traversal_repo_id_rejected() {
    for (i, repoid) in ["../escape", ".", "..", "/absolute", "a/b", "a\\b", "a\nb"]
        .iter()
        .enumerate()
    {
        let dir = trusted_root(&format!("r5-f05-repoid-{}", i));
        let recipe = pkg_recipe(&dir, "nano", "present");
        let mut t = FakeTarget::rocky9();
        t.dnf_dry_run_output = Some(override_output(
            Completion::Exited(1),
            &dnf_transaction_table("nano", repoid),
            "",
        ));
        let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
        assert_blocked_no_mutation(&r);
        // No directory was created from the traversal-like repository id.
        assert!(
            commands_with(&r, "/usr/bin/mkdir").is_empty(),
            "no payload directory may be built from an unvalidated repo id"
        );
        assert_snapshot_cleaned(&r);
    }
}

/// A cache directory whose hash is not the exact native libdnf format proves
/// no repository mapping.
#[test]
fn r5_f05_non_native_cache_hash_rejected() {
    for (i, name) in [
        "baseos-cafebabef00d",
        "baseos-cafebabecafebabe00",
        "baseos-xyzzyxyzzyxyzzy",
        "baseos-",
        "../escape-0123456789abcdef",
        "baseos-extra-cafebabecafebabe",
    ]
    .iter()
    .enumerate()
    {
        let dir = trusted_root(&format!("r5-f05-hash-{}", i));
        let recipe = pkg_recipe(&dir, "nano", "present");
        let mut t = FakeTarget::rocky9();
        t.snapshot_listing = Some(format!(
            "{snap}/{n}\n{snap}/{n}/mirrorlist\n",
            snap = FAKE_SNAP,
            n = name
        ));
        let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
        assert_blocked_no_mutation(&r);
        assert_snapshot_cleaned(&r);
    }
}

/// Two directories that both prove the transaction's repository are
/// ambiguous and fail closed.
#[test]
fn r5_f05_multiple_valid_cache_hashes_rejected() {
    let dir = trusted_root("r5-f05-multi-hash");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.snapshot_listing = Some(format!(
        "{snap}/baseos-cafebabecafebabe\n{snap}/baseos-cafebabecafebabe/mirrorlist\n{snap}/baseos-deadbeefdeadbeef\n{snap}/baseos-deadbeefdeadbeef/mirrorlist\n",
        snap = FAKE_SNAP
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = assert_blocked_no_mutation(&r);
    assert!(
        p.reason.as_deref().unwrap_or("").contains("not unique"),
        "ambiguous cache dirs must be reported: {:?}",
        p.reason
    );
    assert_snapshot_cleaned(&r);
}

/// Positive control: legitimate Rocky/DNF repository ids — including a `-`,
/// and the `_`/`.` libdnf permits — resolve by identity, and the exact
/// 16-hex native cache suffix is recognized.
#[test]
fn r5_f05_native_repo_ids_accepted() {
    for (i, id) in ["baseos", "appstream", "rocky-plus", "my_repo", "my.repo"]
        .iter()
        .enumerate()
    {
        let dir = trusted_root(&format!("r5-f05-good-id-{}", i));
        let recipe = pkg_recipe(&dir, "nano", "present");
        let mut t = FakeTarget::rocky9();
        t.dnf_repos = vec![DnfRepo {
            id: id.to_string(),
            mirrors: true,
            repodata_cached: true,
            mirrorlist_cached: true,
        }];
        let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
        assert_full_install(&r);
        assert_snapshot_cleaned(&r);
    }
}

// ===========================================================================
// R5-F04 closure — native Rocky 9.8 / DNF 4.14.0 stream contracts. Each dnf
// subcommand carries its own exact stderr grammar: the benign lines real dnf
// prints are accepted for that command only, and everything else — an unknown
// line, an extra line, a repeat, a malformed line, non-UTF-8 bytes or a
// truncated capture — still fails closed before any mutation.
// ===========================================================================

/// The real `dnf -C repoquery` stderr captured on Rocky 9.8 / dnf 4.14.0
/// under `LC_ALL=C.UTF-8` (repoquery redirects INFO to stderr).
const REAL_REPOQUERY_STDERR: &str =
    "Last metadata expiration check: 1:35:13 ago on Wed Sep 16 10:28:01 2026.\n";

/// A `dnf_probe_output` override in the native success shape: exit 0, the
/// queried name on stdout, and the real benign stderr line.
fn repoquery_probe_output(stderr: &str) -> Output {
    override_output(Completion::Exited(0), "nano\n", stderr)
}

/// Positive: the byte-exact benign stderr a successful `dnf -C repoquery`
/// emits on real Rocky 9.8 is accepted by the metadata-completeness check.
#[test]
fn r51_repoquery_native_expiration_stderr_accepted() {
    let dir = trusted_root("r51-repoquery-native-stderr");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_probe_output = Some(repoquery_probe_output(REAL_REPOQUERY_STDERR));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_full_install(&r);
    assert_snapshot_cleaned(&r);
}

/// Positive: an empty repoquery stderr is native too — the line is emitted
/// only while metadata is being aged/loaded, so absence is a normal
/// variation, not a defect.
#[test]
fn r51_repoquery_empty_stderr_accepted() {
    let dir = trusted_root("r51-repoquery-empty-stderr");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_probe_output = Some(repoquery_probe_output(""));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_full_install(&r);
    assert_snapshot_cleaned(&r);
}

/// Negative: any stderr line that is not the exact benign grammar fails
/// closed — including the `--assumeno` line on the wrong command.
#[test]
fn r51_repoquery_unknown_stderr_rejected() {
    for (i, stderr) in [
        "Warning: something odd\n",
        "Operation aborted.\n",
        "Last metadata expiration check: soon.\n",
        "Last metadata expiration check\n",
        "Last metadata expiration check: 1:35:13 ago on Wed Sep 16 10:28:01 2026. extra\n",
    ]
    .iter()
    .enumerate()
    {
        let dir = trusted_root(&format!("r51-repoquery-bad-stderr-{}", i));
        let recipe = pkg_recipe(&dir, "nano", "present");
        let mut t = FakeTarget::rocky9();
        t.dnf_probe_output = Some(repoquery_probe_output(stderr));
        let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
        assert_blocked_no_mutation(&r);
        assert_snapshot_cleaned(&r);
    }
}

/// Negative: the benign line plus any extra content is not the native
/// answer — and a repeat of the benign line is not either (dnf emits it at
/// most once).
#[test]
fn r51_repoquery_extra_or_duplicate_stderr_rejected() {
    for (i, stderr) in [
        "Last metadata expiration check: 1:35:13 ago on Wed Sep 16 10:28:01 2026.\nUnexpected line\n",
        "Last metadata expiration check: 1:35:13 ago on Wed Sep 16 10:28:01 2026.\nLast metadata expiration check: 1:35:13 ago on Wed Sep 16 10:28:01 2026.\n",
    ]
    .iter()
    .enumerate()
    {
        let dir = trusted_root(&format!("r51-repoquery-extra-stderr-{}", i));
        let recipe = pkg_recipe(&dir, "nano", "present");
        let mut t = FakeTarget::rocky9();
        t.dnf_probe_output = Some(repoquery_probe_output(stderr));
        let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
        assert_blocked_no_mutation(&r);
        assert_snapshot_cleaned(&r);
    }
}

/// Negative: a truncated or non-UTF-8 capture can never be matched against
/// the expected lines and fails closed.
#[test]
fn r51_repoquery_truncated_or_nonutf8_stderr_rejected() {
    let dir = trusted_root("r51-repoquery-truncated-stderr");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_probe_output = Some(Output {
        completion: Completion::Exited(0),
        stdout: b"nano\n".to_vec(),
        stderr: b"Last metadata expiration che".to_vec(),
        stdout_truncated: false,
        stderr_truncated: true,
    });
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_snapshot_cleaned(&r);

    let dir = trusted_root("r51-repoquery-nonutf8-stderr");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_probe_output = Some(Output {
        completion: Completion::Exited(0),
        stdout: b"nano\n".to_vec(),
        stderr: b"Last metadata \xff\xfe\n".to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    });
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_snapshot_cleaned(&r);
}

// -- repolist -v -----------------------------------------------------------

/// Positive: the real native preamble (`Loaded plugins:` / `DNF version:` /
/// `cachedir:`) and benign stderr from the Rocky 9.8 capture, with a block
/// using real field values — including `Repo-distro-tags` and a
/// `Repo-baseurl` carrying the `(32 more)` suffix dnf prints.
#[test]
fn r51_repolist_native_preamble_and_stderr_accepted() {
    let dir = trusted_root("r51-repolist-native");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_repolist_output = Some(override_output(
        Completion::Exited(0),
        "Loaded plugins: builddep, changelog, config-manager, copr, debug, debuginfo-install, download, generate_completion_cache, groups-manager, needs-restarting, playground, repoclosure, repodiff, repograph, repomanage, reposync, system-upgrade\n\
         DNF version: 4.14.0\n\
         cachedir: /var/cache/dnf\n\
         Repo-id            : baseos\n\
         Repo-name          : Rocky Linux 9 - BaseOS\n\
         Repo-revision      : 9.8\n\
         Repo-distro-tags      : [cpe:/o:rocky:rocky:9.8]:  ,  , ., 8, 9, L, R, c, i, k, n, o, u, x, y\n\
         Repo-updated       : Tue Sep 15 12:23:34 2026\n\
         Repo-pkgs          : 2767\n\
         Repo-available-pkgs: 2767\n\
         Repo-size          : 13 G\n\
         Repo-mirrors       : https://mirrors.rockylinux.org/mirrorlist?arch=x86_64&repo=BaseOS-9\n\
         Repo-baseurl       : https://rocky-linux-asia-northeast1.production.gcp.mirrors.ctrliq.cloud/pub/rocky//9.8/BaseOS/x86_64/os/ (32 more)\n\
         Repo-expire        : 21600 second(s) (last: Wed Sep 16 10:28:00 2026)\n\
         Repo-filename      : /etc/yum.repos.d/rocky.repo\n\
         Total packages: 14291\n",
        "Last metadata expiration check: 0:41:14 ago on Wed Sep 16 10:28:01 2026.\n",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_full_install(&r);
    assert_snapshot_cleaned(&r);
}

/// Negative: an unknown or malformed preamble line is not native structure —
/// banners, empty plugin lists, non-numeric versions and relative cachedirs
/// all fail closed.
#[test]
fn r51_repolist_malformed_preamble_rejected() {
    for (i, pre) in [
        "Banner: hello\n",
        "Loaded plugins:\n",
        "DNF version:\n",
        "DNF version: 4.x\n",
        "cachedir: var/cache/dnf\n",
        "Repo-info          : stray\n",
    ]
    .iter()
    .enumerate()
    {
        let dir = trusted_root(&format!("r51-repolist-bad-pre-{}", i));
        let recipe = pkg_recipe(&dir, "nano", "present");
        let mut t = FakeTarget::rocky9();
        t.dnf_repolist_output = Some(override_output(
            Completion::Exited(0),
            &format!(
                "{}{}",
                pre,
                "Repo-id            : baseos\nRepo-name          : BaseOS\nRepo-mirrors       : https://m/?repo=baseos\nTotal packages: 1\n"
            ),
            "",
        ));
        let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
        assert_blocked_no_mutation(&r);
        assert_snapshot_cleaned(&r);
    }
}

/// Negative: preamble grammar only lives before the first `Repo-id` — the
/// same line inside a repository block, or repeated in the preamble, is
/// unrecognized structure.
#[test]
fn r51_repolist_preamble_misplaced_or_duplicate_rejected() {
    for (i, out) in [
        // `DNF version:` inside a repo block.
        "Repo-id            : baseos\nRepo-name          : BaseOS\nDNF version: 4.14.0\nRepo-mirrors       : https://m/?repo=baseos\nTotal packages: 1\n",
        // `cachedir:` after the first block.
        "Repo-id            : baseos\nRepo-name          : BaseOS\nRepo-mirrors       : https://m/?repo=baseos\n\ncachedir: /var/cache/dnf\nRepo-id            : appstream\nRepo-name          : AppStream\nTotal packages: 1\n",
        // A duplicated preamble line.
        "DNF version: 4.14.0\nDNF version: 4.14.0\nRepo-id            : baseos\nRepo-name          : BaseOS\nRepo-mirrors       : https://m/?repo=baseos\nTotal packages: 1\n",
        // A preamble line after the footer.
        "Repo-id            : baseos\nRepo-name          : BaseOS\nRepo-mirrors       : https://m/?repo=baseos\nTotal packages: 1\nDNF version: 4.14.0\n",
    ]
    .iter()
    .enumerate()
    {
        let dir = trusted_root(&format!("r51-repolist-bad-pre2-{}", i));
        let recipe = pkg_recipe(&dir, "nano", "present");
        let mut t = FakeTarget::rocky9();
        t.dnf_repolist_output = Some(override_output(Completion::Exited(0), out, ""));
        let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
        assert_blocked_no_mutation(&r);
        assert_snapshot_cleaned(&r);
    }
}

/// Negative: arbitrary repolist stderr — including the assumeno line on the
/// wrong command — fails closed.
#[test]
fn r51_repolist_unknown_stderr_rejected() {
    for (i, stderr) in ["Plugin warning\n", "Operation aborted.\n"]
        .iter()
        .enumerate()
    {
        let dir = trusted_root(&format!("r51-repolist-bad-stderr-{}", i));
        let recipe = pkg_recipe(&dir, "nano", "present");
        let mut t = FakeTarget::rocky9();
        t.dnf_repolist_output = Some(override_output(
            Completion::Exited(0),
            &format!(
                "{}\nTotal packages: 1\n",
                dnf_repolist_block("baseos", true)
            ),
            stderr,
        ));
        let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
        assert_blocked_no_mutation(&r);
        assert_snapshot_cleaned(&r);
    }
}

// -- install --assumeno -----------------------------------------------------

/// Positive: the real `--assumeno` contract — exit 1, the transaction table
/// with `Installed size:` on stdout, `Operation aborted.` on stderr — is
/// accepted. (The FakeTarget default already models it; this override pins
/// the byte-exact Rocky capture.)
#[test]
fn r51_assumeno_native_streams_accepted() {
    let dir = trusted_root("r51-assumeno-native");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_dry_run_output = Some(override_output(
        Completion::Exited(1),
        "Last metadata expiration check: 0:41:15 ago on Wed Sep 16 10:28:01 2026.\n\
         Dependencies resolved.\n\
         ================================================================================\n \
         Package        Architecture     Version                 Repository        Size\n\
         ================================================================================\n\
         Installing:\n \
         nano           x86_64           5.6.1-7.el9             baseos           691 k\n\n\
         Transaction Summary\n\
         ================================================================================\n\
         Install  1 Package\n\n\
         Total download size: 691 k\n\
         Installed size: 2.7 M\n",
        DNF_ABORT_STDERR,
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_full_install(&r);
    assert_snapshot_cleaned(&r);
}

/// Negative: any other stderr on the dry run fails closed — even content
/// that would be benign on a different dnf subcommand.
#[test]
fn r51_assumeno_unexpected_stderr_rejected() {
    for (i, stderr) in [
        "Last metadata expiration check: 0:41:15 ago on Wed Sep 16 10:28:01 2026.\n",
        "Operation aborted.\nExtra line\n",
        "Operation aborted.\nOperation aborted.\n",
        "warning: assumeno\n",
    ]
    .iter()
    .enumerate()
    {
        let dir = trusted_root(&format!("r51-assumeno-bad-stderr-{}", i));
        let recipe = pkg_recipe(&dir, "nano", "present");
        let mut t = FakeTarget::rocky9();
        t.dnf_dry_run_output = Some(override_output(
            Completion::Exited(1),
            &dnf_transaction_table("nano", "baseos"),
            stderr,
        ));
        let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
        assert_blocked_no_mutation(&r);
        assert_snapshot_cleaned(&r);
    }
}

/// Negative: `Operation aborted.` on an exit-0 stderr contradicts the
/// completion — the line is only expected after the exit-1 abort.
#[test]
fn r51_assumeno_abort_stderr_on_exit0_rejected() {
    let dir = trusted_root("r51-assumeno-abort-exit0");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_dry_run_output = Some(override_output(
        Completion::Exited(0),
        "Nothing to do.\n",
        DNF_ABORT_STDERR,
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_snapshot_cleaned(&r);
}

/// Negative: `Operation aborted.` is a stderr line — the same text inside
/// the stdout table is unrecognized structure.
#[test]
fn r51_assumeno_abort_in_stdout_rejected() {
    let dir = trusted_root("r51-assumeno-abort-stdout");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_dry_run_output = Some(override_output(
        Completion::Exited(1),
        &format!(
            "{}Operation aborted.\n",
            dnf_transaction_table("nano", "baseos")
        ),
        DNF_ABORT_STDERR,
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_blocked_no_mutation(&r);
    assert_snapshot_cleaned(&r);
}

/// Negative: `Installed size:` must carry a real dnf size value — anything
/// else after the label is a malformed trailer.
#[test]
fn r51_malformed_installed_size_rejected() {
    for (i, trailer) in [
        "Installed size: huge\n",
        "Installed size:\n",
        "Installed size: 2 k extra\n",
        "Installed size 2 k\n",
    ]
    .iter()
    .enumerate()
    {
        let dir = trusted_root(&format!("r51-bad-instsize-{}", i));
        let recipe = pkg_recipe(&dir, "nano", "present");
        let mut t = FakeTarget::rocky9();
        t.dnf_dry_run_output = Some(override_output(
            Completion::Exited(1),
            &dnf_transaction_table("nano", "baseos").replace("Installed size: 2 k\n", trailer),
            DNF_ABORT_STDERR,
        ));
        let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
        assert_blocked_no_mutation(&r);
        assert_snapshot_cleaned(&r);
    }
}

/// Negative: content after the native trailer is not part of the table.
#[test]
fn r51_transaction_trailing_garbage_rejected() {
    for (i, tail) in ["Done.\n", "Complete!\n", "garbage garbage\n"]
        .iter()
        .enumerate()
    {
        let dir = trusted_root(&format!("r51-tail-garbage-{}", i));
        let recipe = pkg_recipe(&dir, "nano", "present");
        let mut t = FakeTarget::rocky9();
        t.dnf_dry_run_output = Some(override_output(
            Completion::Exited(1),
            &format!("{}{}", dnf_transaction_table("nano", "baseos"), tail),
            DNF_ABORT_STDERR,
        ));
        let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
        assert_blocked_no_mutation(&r);
        assert_snapshot_cleaned(&r);
    }
}

/// F04 closure: the complete byte-exact `dnf -C repolist -v` capture from
/// Rocky Linux 9.8 / dnf 4.14.0 (`LC_ALL=C.UTF-8`) — all six enabled
/// repositories with their real field sets, the full plugin list, and the
/// real footer — parses and drives a complete install, alongside the real
/// `--assumeno` table.
#[test]
fn r51_full_real_rocky_capture_replay() {
    let dir = trusted_root("r51-real-rocks-replay");
    let recipe = pkg_recipe(&dir, "nano", "present");
    let mut t = FakeTarget::rocky9();
    t.dnf_repos = vec![
        DnfRepo {
            id: "appstream".to_string(),
            mirrors: true,
            repodata_cached: true,
            mirrorlist_cached: true,
        },
        DnfRepo {
            id: "baseos".to_string(),
            mirrors: true,
            repodata_cached: true,
            mirrorlist_cached: true,
        },
        DnfRepo {
            id: "extras".to_string(),
            mirrors: true,
            repodata_cached: true,
            mirrorlist_cached: true,
        },
        DnfRepo {
            id: "google-cloud-ops-agent".to_string(),
            mirrors: false,
            repodata_cached: true,
            mirrorlist_cached: false,
        },
        DnfRepo {
            id: "google-cloud-sdk".to_string(),
            mirrors: false,
            repodata_cached: true,
            mirrorlist_cached: false,
        },
        DnfRepo {
            id: "google-compute-engine".to_string(),
            mirrors: false,
            repodata_cached: true,
            mirrorlist_cached: false,
        },
    ];
    t.dnf_probe_output = Some(repoquery_probe_output(REAL_REPOQUERY_STDERR));
    // Byte-exact stdout of `dnf -C repolist -v` on the Rocky 9.8 target.
    t.dnf_repolist_output = Some(override_output(
        Completion::Exited(0),
        r#"Loaded plugins: builddep, changelog, config-manager, copr, debug, debuginfo-install, download, generate_completion_cache, groups-manager, needs-restarting, playground, repoclosure, repodiff, repograph, repomanage, reposync, system-upgrade
DNF version: 4.14.0
cachedir: /var/cache/dnf
Repo-id            : appstream
Repo-name          : Rocky Linux 9 - AppStream
Repo-revision      : 9.8
Repo-distro-tags      : [cpe:/o:rocky:rocky:9.8]:  ,  , ., 8, 9, L, R, c, i, k, n, o, u, x, y
Repo-updated       : Tue Sep 15 12:21:30 2026
Repo-pkgs          : 9598
Repo-available-pkgs: 8547
Repo-size          : 25 G
Repo-mirrors       : https://mirrors.rockylinux.org/mirrorlist?arch=x86_64&repo=AppStream-9
Repo-baseurl       : https://rocky-linux-asia-northeast1.production.gcp.mirrors.ctrliq.cloud/pub/rocky//9.8/AppStream/x86_64/os/ (32 more)
Repo-expire        : 21600 second(s) (last: Wed Sep 16 10:28:01 2026)
Repo-filename      : /etc/yum.repos.d/rocky.repo

Repo-id            : baseos
Repo-name          : Rocky Linux 9 - BaseOS
Repo-revision      : 9.8
Repo-distro-tags      : [cpe:/o:rocky:rocky:9.8]:  ,  , ., 8, 9, L, R, c, i, k, n, o, u, x, y
Repo-updated       : Tue Sep 15 12:23:34 2026
Repo-pkgs          : 2767
Repo-available-pkgs: 2767
Repo-size          : 13 G
Repo-mirrors       : https://mirrors.rockylinux.org/mirrorlist?arch=x86_64&repo=BaseOS-9
Repo-baseurl       : https://rocky-linux-asia-northeast1.production.gcp.mirrors.ctrliq.cloud/pub/rocky//9.8/BaseOS/x86_64/os/ (32 more)
Repo-expire        : 21600 second(s) (last: Wed Sep 16 10:28:00 2026)
Repo-filename      : /etc/yum.repos.d/rocky.repo

Repo-id            : extras
Repo-name          : Rocky Linux 9 - Extras
Repo-revision      : 9.8
Repo-distro-tags      : [cpe:/o:rocky:rocky:9.8]:  ,  , ., 8, 9, L, R, c, i, k, n, o, u, x, y
Repo-updated       : Tue Sep  1 05:55:47 2026
Repo-pkgs          : 57
Repo-available-pkgs: 57
Repo-size          : 3.4 M
Repo-mirrors       : https://mirrors.rockylinux.org/mirrorlist?arch=x86_64&repo=extras-9
Repo-baseurl       : https://rocky-linux-asia-northeast1.production.gcp.mirrors.ctrliq.cloud/pub/rocky//9.8/extras/x86_64/os/ (32 more)
Repo-expire        : 21600 second(s) (last: Wed Sep 16 10:28:01 2026)
Repo-filename      : /etc/yum.repos.d/rocky-extras.repo

Repo-id            : google-cloud-ops-agent
Repo-name          : Google Cloud Ops Agent Repository
Repo-revision      : 1789404420939961
Repo-updated       : Fri Dec  2 04:21:13 1994
Repo-pkgs          : 48
Repo-available-pkgs: 48
Repo-size          : 7.4 G
Repo-baseurl       : https://packages.cloud.google.com/yum/repos/google-cloud-ops-agent-el9-x86_64-2
Repo-expire        : 172800 second(s) (last: Wed Sep 16 10:28:00 2026)
Repo-filename      : /etc/yum.repos.d/osconfig_managed_db65a01907.repo

Repo-id            : google-cloud-sdk
Repo-name          : Google Cloud SDK
Repo-revision      : 1789473720061509
Repo-updated       : Mon Apr 15 00:48:05 2013
Repo-pkgs          : 1806
Repo-available-pkgs: 1806
Repo-size          : 64 G
Repo-baseurl       : https://packages.cloud.google.com/yum/repos/cloud-sdk-el9-x86_64
Repo-expire        : 172800 second(s) (last: Wed Sep 16 10:27:59 2026)
Repo-filename      : /etc/yum.repos.d/google-cloud.repo

Repo-id            : google-compute-engine
Repo-name          : Google Compute Engine
Repo-revision      : 1785174405970831
Repo-updated       : Wed Aug 24 04:18:23 2011
Repo-pkgs          : 15
Repo-available-pkgs: 15
Repo-size          : 147 M
Repo-baseurl       : https://packages.cloud.google.com/yum/repos/google-compute-engine-el9-x86_64-stable
Repo-expire        : 172800 second(s) (last: Wed Sep 16 10:27:59 2026)
Repo-filename      : /etc/yum.repos.d/google-cloud.repo
Total packages: 14291
"#,
        // Byte-exact stderr of the same invocation.
        "Last metadata expiration check: 0:41:14 ago on Wed Sep 16 10:28:01 2026.\n",
    ));
    // Byte-exact stdout/stderr of `dnf -C install --assumeno nano`.
    t.dnf_dry_run_output = Some(override_output(
        Completion::Exited(1),
        r#"Last metadata expiration check: 0:41:15 ago on Wed Sep 16 10:28:01 2026.
Dependencies resolved.
================================================================================
 Package        Architecture     Version                 Repository        Size
================================================================================
Installing:
 nano           x86_64           5.6.1-7.el9             baseos           691 k

Transaction Summary
================================================================================
Install  1 Package

Total download size: 691 k
Installed size: 2.7 M
"#,
        DNF_ABORT_STDERR,
    ));
    // The row resolves from baseos, so the payload must land under
    // baseos's snapshot cache dir — the fake's default first-repo
    // placement would not match.
    t.snap_rpm_listing = Some(format!(
        "{}/baseos-cafebabecafebabe/packages/nano-5.6.1-7.el9.x86_64.rpm\n",
        FAKE_SNAP
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_full_install(&r);
    assert_snapshot_cleaned(&r);
}
