//! v1.5.1 DNF-01 / DNF-09: dnf refusals are named by their cause, and a
//! package name dnf only reaches through a provides match is refused before
//! any change.
//!
//! The dnf outputs below are the shapes measured on Rocky Linux 8.10
//! (dnf 4.7.0), 9.8 (dnf 4.14.0) and 10.2 (dnf 4.20.0) in the v1.5.1 Phase 1
//! real-host runs: the python36 transaction table (with its `Enabling module
//! streams:` section and a wrapped `python3-setuptools` row), the
//! `Package ... is already installed.` answer, `Error: Unable to find a
//! match`, the solver's `nothing provides` report, `Error: GPG check FAILED`
//! and `Error: Failed to download metadata for repo '<id>'`. Every case runs
//! the production control path against a scripted target, and every refusal
//! must leave the host untouched: no install mutation, `Change::None`, no
//! verification claim, and the private snapshot removed.

mod common;

use common::*;
use sinter::engine::Mode;
use sinter::executor::{Completion, FakeTarget, Output};
use sinter::result::{Change, Execution, Verification};

const META: &str = "Last metadata expiration check: 0:04:10 ago on Fri Oct 16 18:37:49 2026.\n";

/// The python36 dry-run table measured on Rocky Linux 8.10, with every row
/// in the scripted target's one repository so the positive control can also
/// prefetch.
const PY36_TABLE: &str = "Dependencies resolved.\n\
================================================================================\n \
Package          Arch   Version                                Repo       Size\n\
================================================================================\n\
Installing:\n \
python36         x86_64 3.6.8-39.module+el8.10.0+1910+234ad790 baseos     18 k\n\
Installing dependencies:\n \
python3-pip      noarch 9.0.3-24.el8.rocky.0                   baseos     20 k\n \
python3-setuptools\n                  \
noarch 39.2.0-9.el8_10                        baseos    162 k\n\
Enabling module streams:\n \
python36                3.6                                                   \n\
\n\
Transaction Summary\n\
================================================================================\n\
Install  3 Packages\n\
\n\
Total download size: 200 k\n\
Installed size: 466 k\n";

fn pkg_recipe(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
    write_recipe(
        dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: {}\n      state: present\n",
            name
        ),
    )
}

fn sensitive_pkg_recipe(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
    write_recipe(
        dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: p\n    type: package\n    sensitive: true\n    with:\n      name: {}\n      state: present\n",
            name
        ),
    )
}

fn out(completion: Completion, stdout: &str, stderr: &str) -> Output {
    Output {
        completion,
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

fn dnf_calls<'a>(
    r: &'a sinter::engine::RunReport,
    marker: &str,
) -> Vec<&'a sinter::executor::CommandRecord> {
    r.commands
        .iter()
        .filter(|c| c.program == "/usr/bin/dnf" && c.args.iter().any(|a| a == marker))
        .collect()
}

/// `dnf -C install` / `remove` mutations (the dry run and the download-only
/// transport are not mutations).
fn mutations(r: &sinter::engine::RunReport) -> usize {
    r.commands
        .iter()
        .filter(|c| {
            c.program == "/usr/bin/dnf"
                && c.args.iter().any(|a| a == "-y")
                && !c
                    .args
                    .iter()
                    .any(|a| a == "--downloadonly" || a == "makecache")
        })
        .count()
}

/// The refusal contract: failed, nothing changed or claimed, no mutation,
/// the private snapshot removed. Returns the reason.
fn assert_refused(r: &sinter::engine::RunReport) -> String {
    let p = find(r, "p");
    assert_eq!(p.execution, Execution::Failed, "{:?}", p.reason);
    assert_eq!(p.change, Change::None, "{:?}", p.reason);
    assert_eq!(p.verification, Verification::NotPerformed);
    assert_eq!(mutations(r), 0, "no install may run: {:?}", p.reason);
    let rm = r
        .commands
        .iter()
        .filter(|c| {
            c.program == "/usr/bin/rm"
                && c.args.iter().any(|a| a.starts_with("/var/tmp/sinter-dnf"))
        })
        .count();
    assert!(rm >= 1, "the private snapshot must be removed");
    let reason = p.reason.clone().unwrap_or_default();
    assert!(
        !reason.contains("not locally complete"),
        "a refusal dnf explained must not be reported as a metadata gap: {reason}"
    );
    reason
}

// ---------------------------------------------------------------------------
// DNF-01: provides
// ---------------------------------------------------------------------------

/// `name: python3` on Rocky 8: dnf resolves it to python36 (provides). The
/// install is refused before any change and names the real package.
#[test]
fn provides_name_is_refused_before_install_and_names_the_real_package() {
    let dir = trusted_root("dnf01-provides");
    let recipe = pkg_recipe(&dir, "python3");
    let mut t = FakeTarget::rocky9();
    t.dnf_dry_run_output = Some(out(
        Completion::Exited(1),
        &format!("{META}{PY36_TABLE}"),
        "Operation aborted.\n",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let reason = assert_refused(&r);
    assert!(reason.contains("python3 is not a package name"), "{reason}");
    assert!(reason.contains("package python36"), "{reason}");
    assert!(reason.contains("name: python36"), "{reason}");
    assert!(
        dnf_calls(&r, "--downloadonly").is_empty(),
        "no payload is fetched for a refused name"
    );
}

/// Positive control: the real name `python36` with the same table installs
/// and verifies (the module-streams section and the wrapped row still parse).
#[test]
fn real_package_name_with_the_same_table_installs() {
    let dir = trusted_root("dnf01-real-name");
    let recipe = pkg_recipe(&dir, "python36");
    let mut t = FakeTarget::rocky9();
    t.dnf_dry_run_output = Some(out(
        Completion::Exited(1),
        &format!("{META}{PY36_TABLE}"),
        "Operation aborted.\n",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Succeeded, "{:?}", p.reason);
    assert_eq!(p.change, Change::Changed);
    assert_eq!(p.verification, Verification::Verified);
    assert_eq!(mutations(&r), 1);
}

/// `name: python3` when python36 is already installed: dnf answers "already
/// installed / Nothing to do". Refused before any change, naming python36
/// (in v1.5.0 this was "cannot establish the install transaction set").
#[test]
fn provides_name_satisfied_by_an_installed_package_is_refused() {
    let dir = trusted_root("dnf01-installed-provider");
    let recipe = pkg_recipe(&dir, "python3");
    let mut t = FakeTarget::rocky9();
    t.dnf_dry_run_output = Some(out(
        Completion::Exited(0),
        &format!(
            "{META}Package python36-3.6.8-39.module+el8.10.0+1910+234ad790.x86_64 is already installed.\n\
             Dependencies resolved.\nNothing to do.\nComplete!\n"
        ),
        "",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let reason = assert_refused(&r);
    assert!(
        reason.contains("no package named python3 is installed"),
        "{reason}"
    );
    assert!(reason.contains("installed package python36"), "{reason}");
}

/// A bare `Nothing to do.` for a name that is not installed is the same
/// mismatch: in v1.5.0 the install ran (changing nothing) and was then
/// reported Failed. It is now refused before the install.
#[test]
fn nothing_to_do_for_an_absent_name_is_refused_before_install() {
    for stdout in [
        "Nothing to do.\n",
        "Dependencies resolved.\nNothing to do.\nComplete!\n",
    ] {
        let dir = trusted_root("dnf01-nothing-to-do");
        let recipe = pkg_recipe(&dir, "python3");
        let mut t = FakeTarget::rocky9();
        t.dnf_dry_run_output = Some(out(Completion::Exited(0), stdout, ""));
        let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
        let reason = assert_refused(&r);
        assert!(reason.contains("nothing to install"), "{reason}");
    }
}

/// A provides name that dnf would satisfy by UPGRADING an installed package
/// of another name is refused too: Sinter must never upgrade python36 because
/// `python3` was declared.
#[test]
fn provides_name_resolved_to_an_upgrade_of_another_package_is_refused() {
    let dir = trusted_root("dnf01-upgrade-other");
    let recipe = pkg_recipe(&dir, "python3");
    let mut t = FakeTarget::rocky9();
    t.dnf_dry_run_output = Some(out(
        Completion::Exited(1),
        "Dependencies resolved.\n\
         ================================================================================\n \
         Package          Arch   Version                Repo       Size\n\
         ================================================================================\n\
         Upgrading:\n \
         python36         x86_64 3.6.8-40.el8           baseos     18 k\n\n\
         Transaction Summary\n\
         ================================================================================\n\
         Upgrade  1 Package\n\n\
         Total download size: 18 k\n",
        "Operation aborted.\n",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let reason = assert_refused(&r);
    assert!(reason.contains("package python36"), "{reason}");
}

/// A sensitive package resource never echoes dnf-derived names.
#[test]
fn provides_refusal_of_a_sensitive_resource_is_redacted() {
    let dir = trusted_root("dnf01-sensitive");
    let recipe = sensitive_pkg_recipe(&dir, "python3");
    let mut t = FakeTarget::rocky9();
    t.dnf_dry_run_output = Some(out(
        Completion::Exited(1),
        &format!("{META}{PY36_TABLE}"),
        "Operation aborted.\n",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let reason = assert_refused(&r);
    assert!(!reason.contains("python3"), "{reason}");
    assert!(!reason.contains("python36"), "{reason}");
    assert!(reason.contains("[redacted]"), "{reason}");
}

// ---------------------------------------------------------------------------
// DNF-09: causes
// ---------------------------------------------------------------------------

/// `Error: Unable to find a match` (Rocky 10 shape: stderr only; Rocky 8
/// shape: `No match for argument` on stdout as well).
#[test]
fn unknown_package_is_reported_as_no_match() {
    for (stdout, stderr) in [
        ("", "Error: Unable to find a match: python311\n"),
        (
            "No match for argument: python311\n",
            "Error: Unable to find a match: python311\n",
        ),
        (
            "",
            "No match for argument: python311\nError: Unable to find a match: python311\n",
        ),
    ] {
        let dir = trusted_root("dnf09-nomatch");
        let recipe = pkg_recipe(&dir, "python311");
        let mut t = FakeTarget::rocky9();
        t.dnf_dry_run_output = Some(out(Completion::Exited(1), stdout, stderr));
        let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
        let reason = assert_refused(&r);
        assert!(
            reason.contains("dnf found no package named python311"),
            "{reason}"
        );
    }
}

/// A no-match line naming a DIFFERENT package is not this request's answer:
/// it is not classified as a no-match for this name.
#[test]
fn no_match_for_another_name_is_not_trusted() {
    let dir = trusted_root("dnf09-nomatch-other");
    let recipe = pkg_recipe(&dir, "python311");
    let mut t = FakeTarget::rocky9();
    t.dnf_dry_run_output = Some(out(
        Completion::Exited(1),
        "",
        "Error: Unable to find a match: something-else\n",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let reason = assert_refused(&r);
    assert!(
        reason.contains("unrecognized dnf error output withheld"),
        "{reason}"
    );
    assert!(!reason.contains("something-else"), "{reason}");
}

/// The solver's `nothing provides` report (EPEL package needing CRB while CRB
/// is disabled; measured on Rocky 9.8).
#[test]
fn missing_dependency_is_reported_with_the_capability() {
    let dir = trusted_root("dnf09-deps");
    let recipe = pkg_recipe(&dir, "tolua++-devel");
    let mut t = FakeTarget::rocky9();
    t.dnf_dry_run_output = Some(out(
        Completion::Exited(1),
        "",
        "Error: \n Problem: conflicting requests\n  - nothing provides lua-devel >= 5.3 needed by tolua++-devel-1.0.93-35.el9.x86_64 from epel\n(try to add '--skip-broken' to skip uninstallable packages or '--nobest' to use not only best candidate packages)\n",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let reason = assert_refused(&r);
    assert!(
        reason.contains("dnf cannot resolve the dependencies of tolua++-devel"),
        "{reason}"
    );
    assert!(
        reason.contains("nothing provides lua-devel >= 5.3"),
        "{reason}"
    );
    assert!(reason.contains("CRB or PowerTools"), "{reason}");
}

/// A dependency problem without a `nothing provides` line (a conflict) is
/// still a dependency problem; an unsafe capability is never echoed.
#[test]
fn dependency_problem_without_a_safe_capability() {
    let dir = trusted_root("dnf09-deps-conflict");
    let recipe = pkg_recipe(&dir, "foo");
    let mut t = FakeTarget::rocky9();
    t.dnf_dry_run_output = Some(out(
        Completion::Exited(1),
        "",
        "Error: \n Problem: package foo-1-1.x86_64 conflicts with bar provided by bar-1-1.x86_64\n  - conflicting requests\n  - nothing provides `rm -rf /` needed by foo-1-1.x86_64\n",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let reason = assert_refused(&r);
    assert!(reason.contains("(dependency problem)"), "{reason}");
    assert!(!reason.contains("rm -rf"), "{reason}");
}

/// A signature refusal at payload download (`Error: GPG check FAILED`,
/// measured for an unsigned and a wrong-key package).
#[test]
fn signature_refusal_is_reported_as_such() {
    for stderr in [
        "Package v151-unsigned-1.0-1.noarch.rpm is not signed\nThe downloaded packages were saved in cache until the next successful transaction.\nYou can remove cached packages by executing 'dnf clean packages'.\nError: GPG check FAILED\n",
        "Public key for v151-badsig-1.0-1.noarch.rpm is not installed. Failing package is: v151-badsig-1.0-1.noarch\n GPG Keys are configured as: file:///etc/pki/rpm-gpg/RPM-GPG-KEY-v151-test\nError: GPG check FAILED\n",
    ] {
        let dir = trusted_root("dnf09-gpg");
        let recipe = pkg_recipe(&dir, "nano");
        let mut t = FakeTarget::rocky9();
        t.dnf_downloadonly_output = Some(out(Completion::Exited(1), "", stderr));
        let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
        let reason = assert_refused(&r);
        assert!(reason.contains("GPG check FAILED"), "{reason}");
        assert!(reason.contains("nothing was installed"), "{reason}");
        // Raw dnf text (file names, key URLs) is never echoed.
        assert!(!reason.contains("file://"), "{reason}");
        assert!(!reason.contains("v151-"), "{reason}");
    }
}

/// An unreachable repository: the bounded metadata refresh fails with dnf's
/// own error, which names the repository but never its URL.
#[test]
fn unreachable_repository_is_named_without_its_url() {
    let dir = trusted_root("dnf09-repo");
    let recipe = pkg_recipe(&dir, "tree");
    let mut t = FakeTarget::rocky9();
    t.dnf_repos[0].repodata_cached = false;
    t.dnf_makecache_output = Some(out(
        Completion::Exited(1),
        "",
        "Errors during downloading metadata for repository 'v151-broken':\n  - Curl error (7): Couldn't connect to server for http://user:hunter2@192.0.2.1:1/repodata/repomd.xml [Failed to connect to 192.0.2.1 port 1: Connection refused]\nError: Failed to download metadata for repo 'v151-broken': Cannot download repomd.xml: Cannot download repodata/repomd.xml: All mirrors were tried\n",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let reason = assert_refused(&r);
    assert!(
        reason.contains("could not download the metadata of repository v151-broken"),
        "{reason}"
    );
    assert!(!reason.contains("hunter2"), "{reason}");
    assert!(!reason.contains("192.0.2.1"), "{reason}");
    assert!(!reason.contains("http"), "{reason}");
    assert_eq!(
        dnf_calls(&r, "makecache").len(),
        1,
        "the refresh is bounded"
    );
}

/// A repository id that is not a valid id is not echoed.
#[test]
fn malformed_repository_id_is_not_echoed() {
    let dir = trusted_root("dnf09-repo-bad-id");
    let recipe = pkg_recipe(&dir, "tree");
    let mut t = FakeTarget::rocky9();
    t.dnf_repos[0].repodata_cached = false;
    t.dnf_makecache_output = Some(out(
        Completion::Exited(1),
        "",
        "Error: Failed to download metadata for repo 'evil repo/../x': Cannot download repomd.xml\n",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let reason = assert_refused(&r);
    assert!(
        reason.contains("could not download repository metadata"),
        "{reason}"
    );
    assert!(!reason.contains("evil"), "{reason}");
}

/// Unknown dnf failure output fails closed and is withheld (only its size is
/// reported).
#[test]
fn unrecognized_resolution_failure_is_withheld() {
    let dir = trusted_root("dnf09-unknown");
    let recipe = pkg_recipe(&dir, "nano");
    let mut t = FakeTarget::rocky9();
    t.dnf_dry_run_output = Some(out(
        Completion::Exited(1),
        "",
        "Error: something only a future dnf prints SECRET-CANARY-XYZ\n",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let reason = assert_refused(&r);
    assert!(
        reason.contains("bytes of unrecognized dnf error output withheld"),
        "{reason}"
    );
    assert!(!reason.contains("SECRET-CANARY"), "{reason}");
}

/// Non-UTF-8 stderr is not a message dnf printed: unrecognized, withheld.
#[test]
fn non_utf8_resolution_failure_is_unrecognized() {
    let dir = trusted_root("dnf09-nonutf8");
    let recipe = pkg_recipe(&dir, "nano");
    let mut t = FakeTarget::rocky9();
    t.dnf_dry_run_output = Some(Output {
        completion: Completion::Exited(1),
        stdout: Vec::new(),
        stderr: b"Error: Unable to find a match: nano\xff\n".to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    });
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let reason = assert_refused(&r);
    assert!(
        reason.contains("unrecognized dnf error output withheld"),
        "{reason}"
    );
}

/// A truncated capture is never classified: it stays the fail-closed
/// output-contract block.
#[test]
fn truncated_failure_output_is_not_classified() {
    let dir = trusted_root("dnf09-truncated");
    let recipe = pkg_recipe(&dir, "nano");
    let mut t = FakeTarget::rocky9();
    t.dnf_dry_run_output = Some(Output {
        completion: Completion::Exited(1),
        stdout: Vec::new(),
        stderr: b"Error: Unable to find a match: nano\n".to_vec(),
        stdout_truncated: false,
        stderr_truncated: true,
    });
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed);
    assert_eq!(p.change, Change::None);
    assert_eq!(mutations(&r), 0);
    assert!(
        !p.reason
            .as_deref()
            .unwrap_or("")
            .contains("no package named"),
        "{:?}",
        p.reason
    );
}

/// Plan never runs the dry run: a provides name is predicted as an install
/// (the refusal is an apply-time answer and changes nothing).
#[test]
fn plan_does_not_resolve_and_apply_then_refuses() {
    let dir = trusted_root("dnf01-plan");
    let recipe = pkg_recipe(&dir, "python3");
    let mut t = FakeTarget::rocky9();
    t.dnf_dry_run_output = Some(out(
        Completion::Exited(1),
        &format!("{META}{PY36_TABLE}"),
        "Operation aborted.\n",
    ));
    let plan = run_recipe_fake(&recipe, Mode::Plan, false, t.clone());
    assert!(dnf_calls(&plan, "--assumeno").is_empty());
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    assert_refused(&r);
}

// ---------------------------------------------------------------------------
// R-8: output of a failed package mutation
// ---------------------------------------------------------------------------

/// A dnf mutation that fails for a reason Sinter does not recognize shows no
/// raw dnf output — it could carry a repository URL with credentials — only
/// its size, and the result stays a possible change.
#[test]
fn an_unrecognized_dnf_mutation_failure_withholds_the_output() {
    let dir = trusted_root("r8-dnf-unknown");
    let recipe = pkg_recipe(&dir, "nano");
    let mut t = FakeTarget::rocky9();
    t.manager_output = Some(out(
        Completion::Exited(1),
        "Running transaction check\n",
        "Error: Transaction test error:\n  file /usr/bin/x from install of nano conflicts with https://user:hunter2@repo.example.com/el9/\n",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed);
    assert_eq!(p.change, Change::Possible);
    let reason = p.reason.clone().unwrap_or_default();
    assert!(
        reason.contains("dnf install nano failed with exit code 1"),
        "{reason}"
    );
    assert!(reason.contains("bytes of dnf output withheld"), "{reason}");
    for leak in ["hunter2", "repo.example.com", "conflicts", "https://"] {
        assert!(!reason.contains(leak), "{leak} leaked: {reason}");
    }
}

/// A recognized cause at the mutation is named (fixed text only).
#[test]
fn a_signature_failure_at_the_mutation_is_named() {
    let dir = trusted_root("r8-dnf-gpg");
    let recipe = pkg_recipe(&dir, "nano");
    let mut t = FakeTarget::rocky9();
    t.manager_output = Some(out(
        Completion::Exited(1),
        "",
        "Public key for nano-1.0-1.el9.x86_64.rpm is not installed. Failing package is: nano-1.0-1.el9.x86_64\n GPG Keys are configured as: file:///etc/pki/rpm-gpg/KEY\nError: GPG check FAILED\n",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let reason = find(&r, "p").reason.clone().unwrap_or_default();
    assert!(reason.contains("GPG check FAILED"), "{reason}");
    assert!(!reason.contains("file://"), "{reason}");
}

/// apt keeps its (useful) message, without URL credentials.
#[test]
fn an_apt_mutation_failure_redacts_url_credentials() {
    let dir = trusted_root("r8-apt");
    let recipe = pkg_recipe(&dir, "nano");
    let mut t = FakeTarget::ubuntu2404();
    t.manager_output = Some(out(
        Completion::Exited(100),
        "",
        "E: Failed to fetch https://deploy:s3cr3t@apt.example.com/pool/n/nano.deb  401  Unauthorized\n",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);
    let reason = find(&r, "p").reason.clone().unwrap_or_default();
    assert!(
        reason.contains("E: Failed to fetch https://[redacted]@apt.example.com/pool"),
        "{reason}"
    );
    assert!(
        !reason.contains("s3cr3t") && !reason.contains("deploy:"),
        "{reason}"
    );
}
