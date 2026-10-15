//! Automatic dnf metadata acquisition.
//!
//! A host whose enabled repositories hold no cached repodata — a fresh image,
//! or a repository added since the last refresh — used to fail the install
//! with "repository metadata not locally complete", leaving the operator to
//! run `dnf makecache` by hand first. Sinter now refreshes the target's own
//! metadata cache once, exactly as `dnf makecache` does, rebuilds the private
//! snapshot from the refreshed cache, and re-runs the completeness check.
//! These cases pin that behaviour, its one-attempt bound, and its fail-closed
//! edges. Everything above the command transport runs production code.

mod common;

use common::*;
use sinter::engine::Mode;
use sinter::executor::{Completion, FakeTarget, Output};
use sinter::result::{Change, Execution, Verification};

/// Every `dnf` invocation carrying `needle` as a whole argument.
fn dnf_invocations<'a>(
    report: &'a sinter::engine::RunReport,
    needle: &str,
) -> Vec<&'a sinter::executor::CommandRecord> {
    report
        .commands
        .iter()
        .filter(|c| c.program == "/usr/bin/dnf" && c.args.iter().any(|a| a == needle))
        .collect()
}

/// Indexes in the audit log of every `dnf` invocation carrying `needle`.
fn dnf_positions(report: &sinter::engine::RunReport, needle: &str) -> Vec<usize> {
    report
        .commands
        .iter()
        .enumerate()
        .filter(|(_, c)| c.program == "/usr/bin/dnf" && c.args.iter().any(|a| a == needle))
        .map(|(i, _)| i)
        .collect()
}

/// Real install mutations: `dnf ... install <name>` — never the `--assumeno`
/// dry run or the `--downloadonly` payload transport.
fn install_mutations(report: &sinter::engine::RunReport) -> usize {
    dnf_invocations(report, "install")
        .into_iter()
        .filter(|c| {
            !c.args.iter().any(|a| a == "--downloadonly")
                && !c.args.iter().any(|a| a == "--assumeno")
        })
        .count()
}

/// A scripted RHEL-family target whose enabled repository has no cached
/// repodata — the state a fresh image or a just-added repository is in.
fn cold_cache() -> FakeTarget {
    let mut t = FakeTarget::rocky9();
    for r in t.dnf_repos.iter_mut() {
        r.repodata_cached = false;
        r.mirrorlist_cached = false;
    }
    t
}

fn pkg_recipe(dir: &std::path::Path, resources: &[(&str, &str)]) -> std::path::PathBuf {
    let mut body = String::from("version: 1\nresources:\n");
    for (id, name) in resources {
        body.push_str(&format!(
            "  - id: {id}\n    type: package\n    with:\n      name: {name}\n      state: present\n"
        ));
    }
    write_recipe(dir, "r.yaml", &body)
}

fn output(completion: Completion, stdout: &str, stderr: &str) -> Output {
    Output {
        completion,
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

/// The live dnf cache must never be a removal target of any dispatched
/// command, whatever the refresh did.
fn assert_live_cache_never_removed(report: &sinter::engine::RunReport) {
    for c in &report.commands {
        if c.program != "/usr/bin/rm" {
            continue;
        }
        assert!(
            !c.args.iter().any(|a| a.starts_with("/var/cache/dnf")),
            "the live dnf cache must never be a removal target: {:?}",
            c.args
        );
    }
}

/// A cold cache is refreshed automatically, the snapshot is re-verified, and
/// the install then runs normally — no manual `dnf makecache` is needed.
#[test]
fn a_cold_metadata_cache_is_refreshed_then_the_install_succeeds() {
    let dir = trusted_root("dnf-refresh-cold");
    let recipe = pkg_recipe(&dir, &[("p", "nano")]);
    let r = run_recipe_fake(&recipe, Mode::Apply, false, cold_cache());

    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Succeeded, "{:?}", p.reason);
    assert_eq!(p.change, Change::Changed);
    assert_eq!(p.verification, Verification::Verified);

    // Exactly one refresh, in the documented shape: the host's own cache (no
    // `cachedir=` override), only absent metadata (`metadata_expire=-1`),
    // every enabled repository a hard requirement, and the completion-cache
    // plugin disabled so no live-cache artifact is left behind.
    let refresh = dnf_invocations(&r, "makecache");
    assert_eq!(refresh.len(), 1, "the cache is refreshed exactly once");
    let a = &refresh[0].args;
    assert!(a.iter().any(|x| x == "-y"), "{a:?}");
    assert!(
        a.iter().any(|x| x == "--setopt=*.metadata_expire=-1"),
        "present metadata must not be re-downloaded: {a:?}"
    );
    assert!(
        a.iter().any(|x| x == "--setopt=*.skip_if_unavailable=0"),
        "{a:?}"
    );
    assert!(
        a.iter()
            .any(|x| x == "--disableplugin=generate_completion_cache"),
        "{a:?}"
    );
    assert!(
        !a.iter().any(|x| x.starts_with("--setopt=cachedir=")),
        "the refresh targets the host's own cache: {a:?}"
    );

    // The completeness check failed once, the refresh ran, and the re-check
    // passed: two repoquery invocations with the refresh between them.
    let probes = dnf_positions(&r, "repoquery");
    let refreshes = dnf_positions(&r, "makecache");
    assert_eq!(probes.len(), 2, "one failed check then one re-check");
    assert_eq!(refreshes.len(), 1);
    assert!(
        probes[0] < refreshes[0] && refreshes[0] < probes[1],
        "the refresh must sit between the failed check and the re-check: {probes:?} {refreshes:?}"
    );

    assert_eq!(install_mutations(&r), 1, "exactly one install mutation");
    assert_live_cache_never_removed(&r);
}

/// A complete cache fetches nothing: no refresh, one successful check.
#[test]
fn a_warm_metadata_cache_is_not_refreshed() {
    let dir = trusted_root("dnf-refresh-warm");
    let recipe = pkg_recipe(&dir, &[("p", "nano")]);
    let r = run_recipe_fake(&recipe, Mode::Apply, false, FakeTarget::rocky9());

    assert_eq!(find(&r, "p").execution, Execution::Succeeded);
    assert_eq!(
        dnf_invocations(&r, "makecache").len(),
        0,
        "nothing is fetched when the cache is already complete"
    );
    assert_eq!(dnf_invocations(&r, "repoquery").len(), 1);
    assert_eq!(install_mutations(&r), 1);
}

/// The refresh is attempted once and its failure fails the resource closed —
/// no mutation, no retry, no false change.
#[test]
fn a_failed_refresh_fails_closed_without_a_mutation() {
    let dir = trusted_root("dnf-refresh-fail");
    let recipe = pkg_recipe(&dir, &[("p", "nano")]);
    let mut t = cold_cache();
    t.dnf_makecache_output = Some(output(
        Completion::Exited(1),
        "",
        "Error: Failed to download metadata for repo 'baseos'\n",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);

    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed, "{:?}", p.reason);
    assert_eq!(p.change, Change::None);
    assert_eq!(p.verification, Verification::NotPerformed);
    assert_eq!(dnf_invocations(&r, "makecache").len(), 1);
    assert_eq!(
        install_mutations(&r),
        0,
        "no install may run when the metadata could not be obtained"
    );
    let reason = p.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("repository metadata not locally complete"),
        "{reason}"
    );
    assert!(
        reason.contains("refreshing the repository metadata cache exited 1"),
        "{reason}"
    );
    assert_live_cache_never_removed(&r);
}

/// An incomplete snapshot whose *check* did not complete is never refreshed:
/// a refresh would be guesswork about an unknown state.
#[test]
fn an_indeterminate_check_is_not_refreshed() {
    let dir = trusted_root("dnf-refresh-indet");
    let recipe = pkg_recipe(&dir, &[("p", "nano")]);
    let mut t = cold_cache();
    t.probe_completion = Some(Completion::Indeterminate {
        started: true,
        reason: "timeout".into(),
    });
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);

    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Indeterminate, "{:?}", p.reason);
    assert_eq!(p.change, Change::None);
    assert_eq!(
        dnf_invocations(&r, "makecache").len(),
        0,
        "an unknown check result must not trigger a refresh"
    );
    assert_eq!(install_mutations(&r), 0);
}

/// A refresh that leaves the cache incomplete fails closed and is never
/// looped: the retry is bounded to one attempt.
#[test]
fn a_refresh_that_leaves_the_cache_incomplete_still_fails_closed() {
    let dir = trusted_root("dnf-refresh-noop");
    let recipe = pkg_recipe(&dir, &[("p", "nano")]);
    let mut t = cold_cache();
    // Exit 0 but the modeled cache is unchanged: the re-check still fails.
    t.dnf_makecache_output = Some(output(
        Completion::Exited(0),
        "Metadata cache created.\n",
        "",
    ));
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);

    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed, "{:?}", p.reason);
    assert_eq!(p.change, Change::None);
    assert_eq!(
        dnf_invocations(&r, "makecache").len(),
        1,
        "the refresh is attempted exactly once, never looped"
    );
    assert_eq!(
        dnf_invocations(&r, "repoquery").len(),
        2,
        "a second completeness check follows the refresh"
    );
    assert_eq!(install_mutations(&r), 0);
    let reason = p.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("after refreshing repository metadata:"),
        "the reason must record the refresh and the failed re-check: {reason}"
    );
}

/// The refresh touches the network, so it must carry the package operation's
/// own environment (a proxy) — exactly as the payload transport does.
#[test]
fn the_refresh_carries_the_packages_environment() {
    let dir = trusted_root("dnf-refresh-env");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: nano\n      state: present\n      env:\n        HTTP_PROXY: \"http://proxy.example.com:3128\"\n        NO_PROXY: \"localhost\"\n",
    );
    let r = run_recipe_fake(&recipe, Mode::Apply, false, cold_cache());
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Succeeded, "{:?}", p.reason);

    let refresh = dnf_invocations(&r, "makecache");
    assert_eq!(refresh.len(), 1);
    assert_eq!(
        refresh[0].env.get("HTTP_PROXY").map(String::as_str),
        Some("http://proxy.example.com:3128"),
        "the refresh must carry the operation's proxy: {:?}",
        refresh[0].env
    );
    assert_eq!(
        refresh[0].env.get("NO_PROXY").map(String::as_str),
        Some("localhost")
    );
}

/// A failed cleanup of the first (incomplete) snapshot blocks before any
/// refresh: a leftover private snapshot must never be hidden behind a
/// successful retry.
#[test]
fn a_failed_first_snapshot_cleanup_blocks_before_refreshing() {
    let dir = trusted_root("dnf-refresh-rmfail");
    let recipe = pkg_recipe(&dir, &[("p", "nano")]);
    let mut t = cold_cache();
    t.snapshot_rm_fails = true;
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);

    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed, "{:?}", p.reason);
    assert_eq!(p.change, Change::None);
    assert_eq!(
        dnf_invocations(&r, "makecache").len(),
        0,
        "no refresh may follow a failed snapshot cleanup"
    );
    assert_eq!(install_mutations(&r), 0);
    let reason = p.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("private snapshot cleanup failed"),
        "{reason}"
    );
}

/// An indeterminate refresh is reported as indeterminate, not as a definite
/// failure: the refresh process may still be writing the cache.
#[test]
fn an_indeterminate_refresh_is_reported_indeterminate() {
    let dir = trusted_root("dnf-refresh-indet-result");
    let recipe = pkg_recipe(&dir, &[("p", "nano")]);
    let mut t = cold_cache();
    t.dnf_makecache_output = Some(Output {
        completion: Completion::Indeterminate {
            started: true,
            reason: "timeout".into(),
        },
        stdout: Vec::new(),
        stderr: Vec::new(),
        stdout_truncated: false,
        stderr_truncated: false,
    });
    let r = run_recipe_fake(&recipe, Mode::Apply, false, t);

    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Indeterminate, "{:?}", p.reason);
    assert_eq!(p.change, Change::None);
    assert_eq!(install_mutations(&r), 0);
}

/// `plan` and `state: absent` never touch the metadata cache at all.
#[test]
fn plan_and_absent_never_refresh_metadata() {
    let dir = trusted_root("dnf-refresh-never");
    let present = pkg_recipe(&dir, &[("p", "nano")]);
    let r = run_recipe_fake(&present, Mode::Plan, false, cold_cache());
    assert_eq!(
        dnf_invocations(&r, "makecache").len(),
        0,
        "plan must not refresh metadata"
    );

    let absent = write_recipe(
        &dir,
        "absent.yaml",
        "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: nano\n      state: absent\n",
    );
    let r = run_recipe_fake(&absent, Mode::Apply, false, cold_cache());
    assert_eq!(
        dnf_invocations(&r, "makecache").len(),
        0,
        "removing a package must not refresh metadata"
    );
    assert_eq!(find(&r, "p").change, Change::None);
}

/// Once a run warms the cache, later packages in the same run reuse it (no
/// refresh per package) as long as the enabled repository set is unchanged.
#[test]
fn later_packages_reuse_the_warmed_cache() {
    let dir = trusted_root("dnf-refresh-once");
    let recipe = pkg_recipe(&dir, &[("a", "nano"), ("b", "tree")]);
    let r = run_recipe_fake(&recipe, Mode::Apply, false, cold_cache());

    assert_eq!(find(&r, "a").execution, Execution::Succeeded);
    assert_eq!(find(&r, "b").execution, Execution::Succeeded);
    assert_eq!(
        dnf_invocations(&r, "makecache").len(),
        1,
        "the cache is warmed once; later packages reuse it"
    );
    assert_eq!(install_mutations(&r), 2);
}
