//! WP-PKG-CORE-REPAIR P1/P2: exact-target removal on APT and DNF4 hosts.
//!
//! `state: absent` removes exactly the named package with `dpkg --remove` /
//! `rpm -e`, never through the package manager's resolver. These tests run the
//! production engine against the scripted in-process target on Ubuntu 24.04 and
//! 26.04 (APT) and Rocky 9 and 10 (DNF4). They assert the commands that were
//! dispatched, not only the result: a refused removal must not have dispatched
//! a removing command at all.
//!
//! The scripted target models the real tools' safety behavior (a removal is
//! refused while an installed package requires the target; `rpm -e` does not
//! look at dependencies again after its dry-run). Real-host behavior is
//! established separately by the real-OS acceptance, not by these tests.

mod common;

use common::*;
use sinter::engine::{Engine, Mode, RunOptions, TargetSpec};
use sinter::executor::{Completion, FakeTarget, Output};
use sinter::fakepkg::FakeScriptlet;
use sinter::model::load_model;
use sinter::output::{render_apply, OutputFormat, RenderOptions};
use sinter::result::{Change, Execution, Verification};

fn output(code: i32, stdout: &str, stderr: &str) -> Output {
    Output {
        completion: Completion::Exited(code),
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

/// dpkg options that cancel forced dependency removal from configuration.
const REFUSE: &[&str] = &[
    "--refuse-depends",
    "--refuse-remove-essential",
    "--refuse-remove-protected",
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Flavor {
    Apt,
    Rpm,
}

fn targets() -> Vec<(&'static str, Flavor, FakeTarget)> {
    vec![
        ("ubuntu2404", Flavor::Apt, FakeTarget::ubuntu2404()),
        ("ubuntu2604", Flavor::Apt, FakeTarget::ubuntu2604()),
        ("rocky9", Flavor::Rpm, FakeTarget::rocky9()),
        ("rocky10", Flavor::Rpm, FakeTarget::rocky10()),
    ]
}

/// A recipe of `(id, name, state)` package resources, in order.
fn recipe(label: &str, items: &[(&str, &str, &str)], sensitive: bool) -> std::path::PathBuf {
    let dir = trusted_root(label);
    let mut text = String::from("version: 1\nresources:\n");
    for (id, name, state) in items {
        text.push_str(&format!("  - id: {id}\n    type: package\n"));
        if sensitive {
            text.push_str("    sensitive: true\n");
        }
        text.push_str(&format!(
            "    with:\n      name: {name}\n      state: {state}\n"
        ));
    }
    write_recipe(&dir, "r.yaml", &text)
}

fn one(label: &str, name: &str) -> std::path::PathBuf {
    recipe(label, &[("p", name, "absent")], false)
}

/// The commands that remove a package from the database.
fn removing(r: &sinter::engine::RunReport) -> Vec<&sinter::executor::CommandRecord> {
    r.commands
        .iter()
        .filter(|c| {
            let prog = c.program.rsplit('/').next().unwrap_or(&c.program);
            let has = |a: &str| c.args.iter().any(|x| x == a);
            match prog {
                "dpkg" => has("--remove") && !has("--dry-run"),
                "rpm" => has("-e") && !has("--test"),
                // rpm runs under the dnf lock via this wrapper.
                "sh" => has("sinter-erase"),
                _ => false,
            }
        })
        .collect()
}

/// Options no removal may ever use, and managers it may never call.
fn assert_exact_only(label: &str, r: &sinter::engine::RunReport) {
    const FORBIDDEN: &[&str] = &[
        "--nodeps",
        "--force-depends",
        "--force-all",
        "--force-remove-essential",
        "--force-remove-protected",
        "--allmatches",
        "--auto-remove",
        "--autoremove",
        "autoremove",
        "--purge",
        "--purge-unused",
        "-P",
        "--justdb",
    ];
    for c in &r.commands {
        let prog = c.program.rsplit('/').next().unwrap_or(&c.program);
        // `apt-get check` only reads; no manager may be asked to change anything.
        let read_only_check = prog == "apt-get" && c.args == ["-s", "check"];
        assert!(
            read_only_check || !matches!(prog, "apt-get" | "apt" | "dnf" | "yum"),
            "{label}: the resolver was run: {} {:?}",
            c.program,
            c.args
        );
        if (prog == "rpm" && c.args.iter().any(|a| a == "-e"))
            || (prog == "sh" && c.args.iter().any(|a| a == "sinter-erase"))
        {
            assert!(
                !c.args.iter().any(|a| a.contains("--noscripts")),
                "{label}: scripts were disabled in {:?}",
                c.args
            );
        }
        for a in &c.args {
            assert!(
                !FORBIDDEN.contains(&a.as_str()),
                "{label}: forbidden option {a} in {} {:?}",
                c.program,
                c.args
            );
        }
    }
}

fn reason(r: &sinter::engine::RunReport, id: &str) -> String {
    find(r, id).reason.clone().unwrap_or_default()
}

fn run(recipe: &std::path::Path, sudo: bool, fake: FakeTarget) -> sinter::engine::RunReport {
    run_recipe_fake(recipe, Mode::Apply, sudo, fake)
}

// ---------------------------------------------------------------------------
// the removal itself
// ---------------------------------------------------------------------------

#[test]
fn leaf_removal_removes_only_the_target_with_exact_commands() {
    for (label, flavor, fake) in targets() {
        let path = recipe(
            &format!("exact-leaf-{label}"),
            &[
                ("rm", "leafpkg", "absent"),
                ("keep", "otherpkg", "present"),
                ("again", "thirdpkg", "present"),
            ],
            false,
        );
        let fake = fake
            .with_package("leafpkg")
            .with_package("otherpkg")
            .with_package("thirdpkg");
        let r = run(&path, true, fake);
        assert_success(&r);
        let rm = find(&r, "rm");
        assert_eq!(rm.change, Change::Changed, "{label}");
        assert_eq!(rm.execution, Execution::Succeeded, "{label}");
        assert_eq!(rm.verification, Verification::Verified, "{label}");
        // The other packages are untouched.
        for id in ["keep", "again"] {
            assert_eq!(find(&r, id).change, Change::None, "{label}: {id}");
        }
        assert_exact_only(label, &r);
        let mutating = removing(&r);
        assert_eq!(mutating.len(), 1, "{label}");
        match flavor {
            Flavor::Apt => {
                assert_eq!(mutating[0].program, "/usr/bin/dpkg");
                assert_eq!(
                    mutating[0].args,
                    [REFUSE, &["--remove", "leafpkg"][..]].concat()
                );
                let dry: Vec<_> = r
                    .commands
                    .iter()
                    .filter(|c| c.args.iter().any(|a| a == "--dry-run"))
                    .collect();
                assert_eq!(dry.len(), 1, "{label}");
                assert_eq!(
                    dry[0].args,
                    [REFUSE, &["--dry-run", "--remove", "leafpkg"][..]].concat()
                );
            }
            Flavor::Rpm => {
                // rpm runs under dnf's lock so a dnf transaction cannot
                // overlap its dependency check.
                assert_eq!(mutating[0].program, "/usr/bin/sh");
                let a = &mutating[0].args;
                assert_eq!((a[0].as_str(), a[2].as_str()), ("-c", "sinter-erase"));
                assert_eq!(a[3], "leafpkg-1.0-1.el9.x86_64");
                assert!(a[1].contains("/usr/bin/rpm' -e -- \"$1\""));
                let dry: Vec<_> = r
                    .commands
                    .iter()
                    .filter(|c| c.args.iter().any(|a| a == "--test"))
                    .collect();
                assert_eq!(dry.len(), 1, "{label}");
                assert_eq!(
                    dry[0].args,
                    vec!["-e", "--test", "--", "leafpkg-1.0-1.el9.x86_64"]
                );
            }
        }
        // The dry-run precedes the removal.
        let at = |needle: &sinter::executor::CommandRecord| {
            r.commands
                .iter()
                .position(|c| std::ptr::eq(c, needle))
                .unwrap()
        };
        let dry_at = r
            .commands
            .iter()
            .position(|c| c.args.iter().any(|a| a == "--dry-run" || a == "--test"))
            .unwrap();
        assert!(dry_at < at(mutating[0]), "{label}");
    }
}

#[test]
fn removing_an_absent_package_is_idempotent_and_runs_nothing_mutating() {
    for (label, _, fake) in targets() {
        let path = one(&format!("exact-absent-{label}"), "leafpkg");
        let r = run(&path, true, fake.with_package("otherpkg"));
        assert_success(&r);
        assert_eq!(find(&r, "p").change, Change::None, "{label}");
        assert!(removing(&r).is_empty(), "{label}");
        assert_exact_only(label, &r);
    }
}

#[test]
fn multiple_removals_in_one_run_leave_unrelated_packages() {
    for (label, _, mut fake) in targets() {
        // `app` requires `lib`: both stay. Two leaves go.
        fake.pkgdb.add_requires("app", "lib");
        let fake = fake
            .with_package("leaf1")
            .with_package("leaf2")
            .with_package("app")
            .with_package("lib");
        let path = recipe(
            &format!("exact-multi-{label}"),
            &[
                ("a", "leaf1", "absent"),
                ("b", "leaf2", "absent"),
                ("c", "app", "present"),
                ("d", "lib", "present"),
            ],
            false,
        );
        let r = run(&path, true, fake);
        assert_success(&r);
        assert_eq!(find(&r, "a").change, Change::Changed, "{label}");
        assert_eq!(find(&r, "b").change, Change::Changed, "{label}");
        assert_eq!(find(&r, "c").change, Change::None, "{label}");
        assert_eq!(find(&r, "d").change, Change::None, "{label}");
        assert_eq!(removing(&r).len(), 2, "{label}");
        assert_exact_only(label, &r);
    }
}

// ---------------------------------------------------------------------------
// reverse dependencies
// ---------------------------------------------------------------------------

#[test]
fn a_package_that_others_depend_on_is_refused_before_any_removal() {
    for (label, _, mut fake) in targets() {
        fake.pkgdb.add_requires("app", "libpkg");
        let fake = fake.with_package("libpkg").with_package("app");
        let path = one(&format!("exact-revdep-{label}"), "libpkg");
        let r = run(&path, true, fake);
        let p = find(&r, "p");
        assert_eq!(p.execution, Execution::Failed, "{label}");
        assert_eq!(p.change, Change::None, "{label}");
        assert_eq!(p.verification, Verification::NotPerformed, "{label}");
        assert!(removing(&r).is_empty(), "{label}: a removal was dispatched");
        let why = reason(&r, "p");
        assert!(why.contains("depend"), "{label}: {why}");
        assert!(
            why.contains("app"),
            "{label}: the dependent is named: {why}"
        );
        assert!(why.contains("nothing was changed"), "{label}: {why}");
        assert_exact_only(label, &r);
    }
}

#[test]
fn dependents_are_not_named_for_a_sensitive_resource() {
    for (label, _, mut fake) in targets() {
        fake.pkgdb.add_requires("appsecret", "libsecret");
        let fake = fake.with_package("libsecret").with_package("appsecret");
        let path = recipe(
            &format!("exact-sens-{label}"),
            &[("p", "libsecret", "absent")],
            true,
        );
        let r = run(&path, true, fake);
        let p = find(&r, "p");
        assert_eq!(p.execution, Execution::Failed, "{label}");
        let why = reason(&r, "p");
        assert!(!why.contains("libsecret"), "{label}: {why}");
        assert!(!why.contains("appsecret"), "{label}: {why}");
        assert!(removing(&r).is_empty(), "{label}");
        // The recorded command lines are redacted too.
        for c in &r.commands {
            if c.sensitive {
                assert!(
                    !c.args.iter().any(|a| a.contains("libsecret")),
                    "{label}: {:?}",
                    c.args
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// identity
// ---------------------------------------------------------------------------

#[test]
fn a_name_the_backend_cannot_have_is_refused() {
    // The model accepts `_` and upper case; neither is a Debian package name.
    let path = one("exact-badname-apt", "Leaf_Pkg");
    let r = run(
        &path,
        true,
        FakeTarget::ubuntu2404().with_package("Leaf_Pkg"),
    );
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed);
    assert_eq!(p.change, Change::None);
    assert!(reason(&r, "p").contains("not valid"), "{}", reason(&r, "p"));
    assert!(removing(&r).is_empty());
    // `~` is not an RPM name character.
    let path = one("exact-badname-rpm", "leaf~pkg");
    let r = run(&path, true, FakeTarget::rocky9().with_package("leaf~pkg"));
    assert_eq!(find(&r, "p").execution, Execution::Failed);
    assert!(removing(&r).is_empty());
}

#[test]
fn more_than_one_installed_instance_is_refused() {
    for (label, _, mut fake) in targets() {
        fake.pkgdb.meta.insert(
            "leafpkg".to_string(),
            sinter::fakepkg::FakePkg {
                duplicates: vec![("i686".to_string(), "0.9".to_string())],
                ..Default::default()
            },
        );
        let path = one(&format!("exact-ambiguous-{label}"), "leafpkg");
        let r = run(&path, true, fake.with_package("leafpkg"));
        let p = find(&r, "p");
        assert_eq!(p.execution, Execution::Failed, "{label}");
        assert_eq!(p.change, Change::None, "{label}");
        assert!(
            reason(&r, "p").contains("more than one"),
            "{label}: {}",
            reason(&r, "p")
        );
        assert!(removing(&r).is_empty(), "{label}");
    }
}

#[test]
fn unreadable_or_malformed_identity_answers_fail_closed() {
    let cases: Vec<(&str, Output)> = vec![
        ("empty", output(0, "", "")),
        ("garbage", output(0, "not a record\n", "")),
        (
            "missing-newline",
            output(0, "leafpkg\t0\t1.0\t1.el9\tx86_64", ""),
        ),
        (
            "wrong-name",
            output(0, "other\t0\t1.0\t1.el9\tx86_64\n", ""),
        ),
        (
            "stderr",
            output(0, "leafpkg\t0\t1.0\t1.el9\tx86_64\n", "warning\n"),
        ),
        ("failed", output(2, "", "rpmdb: damaged\n")),
        (
            "bad-arch",
            output(0, "leafpkg\t0\t1.0\t1.el9\t(none)\n", ""),
        ),
        (
            "bad-epoch",
            output(0, "leafpkg\tx\t1.0\t1.el9\tx86_64\n", ""),
        ),
    ];
    for (name, forced) in cases {
        let mut fake = FakeTarget::rocky9().with_package("leafpkg");
        fake.pkgdb.force("rpm-identity", forced);
        let path = one(&format!("exact-rpm-malformed-{name}"), "leafpkg");
        let r = run(&path, true, fake);
        let p = find(&r, "p");
        assert_eq!(p.execution, Execution::Failed, "{name}");
        assert_eq!(p.change, Change::None, "{name}");
        assert!(removing(&r).is_empty(), "{name}");
    }
    let apt_cases: Vec<(&str, Output)> = vec![
        ("empty", output(0, "", "")),
        ("short", output(0, "install ok installed\tleafpkg\n", "")),
        (
            "wrong-name",
            output(0, "install ok installed\tother\tamd64\t1.0\t\t\n", ""),
        ),
        (
            "truncated",
            Output {
                stdout_truncated: true,
                ..output(0, "install ok installed\tleafpkg\tamd64\t1.0\t\t\n", "")
            },
        ),
        (
            "essential-garbage",
            output(
                0,
                "install ok installed\tleafpkg\tamd64\t1.0\tmaybe\t\n",
                "",
            ),
        ),
    ];
    for (name, forced) in apt_cases {
        let mut fake = FakeTarget::ubuntu2404().with_package("leafpkg");
        fake.pkgdb.force("dpkg-identity", forced);
        let path = one(&format!("exact-apt-malformed-{name}"), "leafpkg");
        let r = run(&path, true, fake);
        let p = find(&r, "p");
        assert_eq!(p.execution, Execution::Failed, "{name}");
        assert_eq!(p.change, Change::None, "{name}");
        assert!(removing(&r).is_empty(), "{name}");
    }
}

#[test]
fn a_dpkg_package_in_a_broken_state_is_refused() {
    for status in [
        "install ok half-configured",
        "install ok unpacked",
        "install reinstreq half-installed",
    ] {
        let mut fake = FakeTarget::ubuntu2404().with_package("leafpkg");
        fake.pkgdb.meta.insert(
            "leafpkg".to_string(),
            sinter::fakepkg::FakePkg {
                status: Some(status.to_string()),
                ..Default::default()
            },
        );
        let path = one("exact-apt-broken", "leafpkg");
        let r = run(&path, true, fake);
        let p = find(&r, "p");
        assert_eq!(p.execution, Execution::Failed, "{status}");
        assert_eq!(p.change, Change::None, "{status}");
        assert!(removing(&r).is_empty(), "{status}");
    }
}

#[test]
fn the_package_changing_between_planning_and_removal_is_refused() {
    // APT: the version differs on the second identity read.
    let mut fake = FakeTarget::ubuntu2404().with_package("leafpkg");
    fake.pkgdb.force(
        "dpkg-identity",
        output(0, "install ok installed\tleafpkg\tamd64\t1.0-1\t\t\n", ""),
    );
    fake.pkgdb.force(
        "dpkg-identity",
        output(0, "install ok installed\tleafpkg\tamd64\t1.0-2\t\t\n", ""),
    );
    let r = run(&one("exact-toctou-apt", "leafpkg"), true, fake);
    assert_eq!(find(&r, "p").change, Change::None);
    assert_eq!(find(&r, "p").execution, Execution::Failed);
    assert!(removing(&r).is_empty());

    // RPM: the NEVRA resolves to a different package than the one identified.
    let mut fake = FakeTarget::rocky9().with_package("leafpkg");
    fake.pkgdb.force(
        "rpm-identity",
        output(0, "leafpkg\t0\t1.0\t1.el9\tx86_64\n", ""),
    );
    fake.pkgdb.force(
        "rpm-identity",
        output(0, "leafpkg\t0\t2.0\t1.el9\tx86_64\n", ""),
    );
    let r = run(&one("exact-toctou-rpm", "leafpkg"), true, fake);
    assert_eq!(find(&r, "p").change, Change::None);
    assert_eq!(find(&r, "p").execution, Execution::Failed);
    assert!(removing(&r).is_empty());
}

#[test]
fn the_nevra_is_resolved_once_more_immediately_before_the_erase() {
    // identity by name, operand check, then the check right before `rpm -e`
    let record = |version: &str| output(0, &format!("leafpkg\t0\t{version}\t1.el9\tx86_64\n"), "");
    let mut fake = FakeTarget::rocky10().with_package("leafpkg");
    fake.pkgdb.force("rpm-identity", record("1.0"));
    fake.pkgdb.force("rpm-identity", record("1.0"));
    fake.pkgdb.force("rpm-identity", record("1.1"));
    let r = run(&one("exact-nevra-third-read", "leafpkg"), true, fake);
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed);
    assert_eq!(p.change, Change::None);
    assert!(removing(&r).is_empty());
}

// ---------------------------------------------------------------------------
// protections dnf and apt apply by themselves
// ---------------------------------------------------------------------------

#[test]
fn essential_and_protected_apt_packages_are_refused() {
    for kind in ["essential", "protected"] {
        let mut fake = FakeTarget::ubuntu2404().with_package("corepkg");
        if kind == "essential" {
            fake.pkgdb.essential.insert("corepkg".to_string());
        } else {
            fake.pkgdb.protected.insert("corepkg".to_string());
        }
        let r = run(&one(&format!("exact-apt-{kind}"), "corepkg"), true, fake);
        let p = find(&r, "p");
        assert_eq!(p.execution, Execution::Failed, "{kind}");
        assert_eq!(p.change, Change::None, "{kind}");
        assert!(reason(&r, "p").contains(kind), "{}", reason(&r, "p"));
        assert!(removing(&r).is_empty(), "{kind}");
    }
}

#[test]
fn dnf_protected_packages_are_refused_like_dnf_does() {
    let cases: Vec<(&str, Option<&str>, Option<&str>)> = vec![
        ("by-file-name", Some("# comment\nleafpkg\n"), None),
        ("by-file-glob", Some("glob:leaf*\n"), None),
        (
            "by-conf",
            None,
            Some("[main]\nprotected_packages = foo,\n    leafpkg\n"),
        ),
    ];
    for (name, protected_d, conf) in cases {
        let mut fake = FakeTarget::rocky9().with_package("leafpkg");
        fake.pkgdb.dnf_protected_d = protected_d.map(str::to_string).or(Some(String::new()));
        fake.pkgdb.dnf_conf = conf.map(str::to_string);
        let r = run(
            &one(&format!("exact-dnf-prot-{name}"), "leafpkg"),
            true,
            fake,
        );
        let p = find(&r, "p");
        assert_eq!(p.execution, Execution::Failed, "{name}");
        assert_eq!(p.change, Change::None, "{name}");
        assert!(
            reason(&r, "p").contains("protected"),
            "{name}: {}",
            reason(&r, "p")
        );
        assert!(removing(&r).is_empty(), "{name}");
    }
    // dnf protects itself whatever the files say.
    let mut fake = FakeTarget::rocky9().with_package("dnf");
    fake.pkgdb.dnf_protected_d = Some(String::new());
    let r = run(&one("exact-dnf-self", "dnf"), true, fake);
    assert_eq!(find(&r, "p").execution, Execution::Failed);
    assert!(removing(&r).is_empty());
}

#[test]
fn a_host_without_protected_lists_still_removes_an_unprotected_package() {
    // Missing directories are an empty list, as they are for dnf itself.
    let mut fake = FakeTarget::rocky10().with_package("leafpkg");
    fake.pkgdb.dnf_protected_d = None;
    let r = run(&one("exact-dnf-nodirs", "leafpkg"), true, fake);
    assert_success(&r);
    assert_eq!(find(&r, "p").change, Change::Changed);
}

#[test]
fn an_unreadable_protected_list_fails_closed() {
    let mut fake = FakeTarget::rocky10().with_package("leafpkg");
    fake.pkgdb.force(
        "protected-d",
        output(2, "", "find: 'x': Input/output error\n"),
    );
    let r = run(&one("exact-dnf-unreadable", "leafpkg"), true, fake);
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed);
    assert_eq!(p.change, Change::None);
    assert!(removing(&r).is_empty());
}

#[test]
fn the_package_that_owns_the_running_kernel_image_is_refused_and_others_are_not() {
    // kernel-core owns the image of the running kernel: refused.
    let mut fake = FakeTarget::rocky9()
        .with_package("kernel-core")
        .with_package("kernel-tools");
    fake.pkgdb.kernel_release = Some("5.14.0-1.el9.x86_64".to_string());
    fake.pkgdb.kernel_owner = Some("kernel-core".to_string());
    let r = run(
        &one("exact-kernel-running", "kernel-core"),
        true,
        fake.clone(),
    );
    assert_eq!(find(&r, "p").execution, Execution::Failed);
    assert_eq!(find(&r, "p").change, Change::None);
    assert!(
        reason(&r, "p").contains("running kernel"),
        "{}",
        reason(&r, "p")
    );
    assert!(removing(&r).is_empty());

    // A kernel package that merely carries the same version (kernel-tools) is
    // not the running kernel and can be removed, as with dnf.
    let r = run(
        &one("exact-kernel-tools", "kernel-tools"),
        true,
        fake.clone(),
    );
    assert_success(&r);
    assert_eq!(find(&r, "p").change, Change::Changed);

    // The owner is asked about for every package, not only for names that
    // start with "kernel": whoever owns the running image is protected.
    let mut odd = FakeTarget::rocky9().with_package("vmlinuz-owner");
    odd.pkgdb.kernel_release = Some("5.14.0-1.el9.x86_64".to_string());
    odd.pkgdb.kernel_owner = Some("vmlinuz-owner".to_string());
    let r = run(&one("exact-kernel-odd-name", "vmlinuz-owner"), true, odd);
    assert!(
        reason(&r, "p").contains("running kernel"),
        "{}",
        reason(&r, "p")
    );
    assert!(removing(&r).is_empty());

    // Another installed kernel is not the running one either.
    fake.pkgdb.kernel_owner = Some("kernel-other".to_string());
    let fake = fake.with_package("kernel-other");
    let r = run(&one("exact-kernel-other", "kernel-core"), true, fake);
    assert_success(&r);
}

// ---------------------------------------------------------------------------
// failures before the removing command
// ---------------------------------------------------------------------------

#[test]
fn a_failed_dry_run_dispatches_no_removal() {
    for (label, flavor, fake) in targets() {
        let mut fake = fake.with_package("leafpkg");
        let key = if flavor == Flavor::Apt {
            "dpkg-dry-run"
        } else {
            "rpm-test"
        };
        fake.pkgdb
            .force(key, output(3, "", "unexpected failure of the check\n"));
        let r = run(
            &one(&format!("exact-dryfail-{label}"), "leafpkg"),
            true,
            fake,
        );
        let p = find(&r, "p");
        assert_eq!(p.execution, Execution::Failed, "{label}");
        assert_eq!(p.change, Change::None, "{label}");
        assert_eq!(p.verification, Verification::NotPerformed, "{label}");
        assert!(removing(&r).is_empty(), "{label}");
        assert!(reason(&r, "p").contains("check failed"), "{label}");
    }
}

#[test]
fn a_dry_run_that_plans_another_package_is_refused() {
    let mut fake = FakeTarget::ubuntu2404().with_package("leafpkg");
    fake.pkgdb.force(
        "dpkg-dry-run",
        output(
            0,
            "Removing leafpkg (1.0-1) ...\nRemoving innocent (2.0) ...\n",
            "",
        ),
    );
    let r = run(&one("exact-dry-plan-other", "leafpkg"), true, fake);
    assert_eq!(find(&r, "p").execution, Execution::Failed);
    assert!(removing(&r).is_empty());
}

#[test]
fn an_unreadable_baseline_refuses_before_the_removal() {
    let mut fake = FakeTarget::ubuntu2404().with_package("leafpkg");
    fake.pkgdb.force("dpkg-inventory", output(1, "", "boom\n"));
    let r = run(&one("exact-baseline-apt", "leafpkg"), true, fake);
    assert_eq!(find(&r, "p").change, Change::None);
    assert_eq!(find(&r, "p").execution, Execution::Failed);
    assert!(removing(&r).is_empty());

    let mut fake = FakeTarget::rocky9().with_package("leafpkg");
    fake.pkgdb.force("rpm-inventory", output(1, "", "boom\n"));
    let r = run(&one("exact-baseline-rpm", "leafpkg"), true, fake);
    assert_eq!(find(&r, "p").change, Change::None);
    assert!(removing(&r).is_empty());
}

#[test]
fn a_command_that_cannot_complete_before_the_removal_changes_nothing() {
    let mut fake = FakeTarget::rocky9().with_package("leafpkg");
    fake.pkgdb.force(
        "rpm-test",
        Output {
            completion: Completion::Indeterminate {
                reason: "timed out".to_string(),
                started: true,
            },
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        },
    );
    let r = run(&one("exact-indeterminate-pre", "leafpkg"), true, fake);
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Indeterminate);
    assert_eq!(p.change, Change::None);
    assert!(removing(&r).is_empty());
}

#[test]
fn no_privilege_means_no_package_change() {
    for (label, _, mut fake) in targets() {
        fake.pkgdb.enforce_root = true;
        let fake = fake.with_package("leafpkg");
        // uid 1000 without sudo.
        let r = run(
            &one(&format!("exact-noroot-{label}"), "leafpkg"),
            false,
            fake,
        );
        let p = find(&r, "p");
        assert_eq!(p.execution, Execution::Failed, "{label}");
        assert_eq!(p.change, Change::None, "{label}: {}", reason(&r, "p"));
        assert_exact_only(label, &r);
    }
}

#[test]
fn the_same_removal_succeeds_with_sudo() {
    for (label, _, mut fake) in targets() {
        fake.pkgdb.enforce_root = true;
        let fake = fake.with_package("leafpkg");
        let r = run(&one(&format!("exact-sudo-{label}"), "leafpkg"), true, fake);
        assert_success(&r);
        assert!(removing(&r).iter().all(|c| c.sudo), "{label}");
    }
}

#[test]
fn a_package_database_lock_held_by_another_process_changes_nothing() {
    for (label, _, mut fake) in targets() {
        fake.pkgdb.lock_busy = true;
        let fake = fake.with_package("leafpkg");
        let r = run(&one(&format!("exact-lock-{label}"), "leafpkg"), true, fake);
        let p = find(&r, "p");
        assert_eq!(p.execution, Execution::Failed, "{label}");
        assert_eq!(p.change, Change::None, "{label}: {}", reason(&r, "p"));
        assert!(
            reason(&r, "p").contains("still installed"),
            "{label}: {}",
            reason(&r, "p")
        );
    }
}

// ---------------------------------------------------------------------------
// results after the removing command
// ---------------------------------------------------------------------------

#[test]
fn a_tool_that_removes_more_than_the_target_is_reported_as_failed() {
    for (label, _, mut fake) in targets() {
        fake.pkgdb.extra_removed = vec!["innocent".to_string()];
        let fake = fake.with_package("leafpkg").with_package("innocent");
        let r = run(&one(&format!("exact-extra-{label}"), "leafpkg"), true, fake);
        let p = find(&r, "p");
        assert_eq!(p.execution, Execution::Failed, "{label}");
        assert_eq!(p.change, Change::Changed, "{label}");
        assert_eq!(p.verification, Verification::Failed, "{label}");
        assert!(
            reason(&r, "p").contains("other package"),
            "{label}: {}",
            reason(&r, "p")
        );
        assert!(reason(&r, "p").contains("innocent"), "{label}");
    }
}

#[test]
fn removed_packages_are_not_named_for_a_sensitive_resource() {
    let mut fake = FakeTarget::rocky9()
        .with_package("leafsecret")
        .with_package("innocent");
    fake.pkgdb.extra_removed = vec!["innocent".to_string()];
    let path = recipe("exact-extra-sens", &[("p", "leafsecret", "absent")], true);
    let r = run(&path, true, fake);
    let why = reason(&r, "p");
    assert!(
        !why.contains("innocent") && !why.contains("leafsecret"),
        "{why}"
    );
    assert_eq!(find(&r, "p").execution, Execution::Failed);
}

#[test]
fn a_removal_command_that_succeeds_without_removing_is_not_success() {
    for (label, flavor, fake) in targets() {
        let mut fake = fake.with_package("leafpkg");
        let key = if flavor == Flavor::Apt {
            "dpkg-remove"
        } else {
            "rpm-erase"
        };
        fake.pkgdb.force(key, output(0, "", ""));
        let r = run(&one(&format!("exact-noop-{label}"), "leafpkg"), true, fake);
        let p = find(&r, "p");
        assert_eq!(p.execution, Execution::Failed, "{label}");
        assert_eq!(p.verification, Verification::Failed, "{label}");
        assert_ne!(p.change, Change::None, "{label}");
        assert!(
            reason(&r, "p").contains("did not reach desired state"),
            "{label}: {}",
            reason(&r, "p")
        );
    }
}

#[test]
fn a_failing_pre_removal_script_leaves_the_package_and_reports_failure() {
    for (label, flavor, mut fake) in targets() {
        fake.pkgdb.scriptlet = FakeScriptlet::PreRemoveFails;
        let fake = fake.with_package("leafpkg");
        let r = run(&one(&format!("exact-prerm-{label}"), "leafpkg"), true, fake);
        let p = find(&r, "p");
        assert_eq!(p.execution, Execution::Failed, "{label}");
        // Package scripts may have run: the change is possible, not none.
        assert_eq!(p.change, Change::Possible, "{label}");
        match flavor {
            // dpkg recorded the removal request before the script ran and
            // leaves `deinstall ok installed`, a state Sinter does not read:
            // the result says so instead of guessing.
            Flavor::Apt => {
                assert_eq!(p.verification, Verification::Unknown, "{label}");
                assert!(
                    reason(&r, "p").contains("deinstall ok installed"),
                    "{label}: {}",
                    reason(&r, "p")
                );
            }
            Flavor::Rpm => {
                assert_eq!(p.verification, Verification::Failed, "{label}");
                assert!(reason(&r, "p").contains("still installed"), "{label}");
            }
        }
    }
}

#[test]
fn a_failing_post_removal_script_is_reported_as_a_failure_never_as_success() {
    for (label, flavor, mut fake) in targets() {
        fake.pkgdb.scriptlet = FakeScriptlet::PostRemoveFails;
        let fake = fake.with_package("leafpkg");
        let r = run(
            &one(&format!("exact-postrm-{label}"), "leafpkg"),
            true,
            fake,
        );
        let p = find(&r, "p");
        assert_eq!(p.execution, Execution::Failed, "{label}");
        match flavor {
            // dpkg leaves the package half-installed, which Sinter does not read.
            Flavor::Apt => {
                assert_eq!(p.change, Change::Possible, "{label}");
                assert_eq!(p.verification, Verification::Unknown, "{label}");
                assert!(reason(&r, "p").contains("half-installed"), "{label}");
            }
            // rpm erases the package and only warns (exit 0).
            Flavor::Rpm => {
                assert_eq!(p.change, Change::Changed, "{label}");
                assert_eq!(p.verification, Verification::Verified, "{label}");
                assert!(reason(&r, "p").contains("script"), "{label}");
            }
        }
    }
}

#[test]
fn a_script_failure_warned_with_exit_zero_is_still_a_failure() {
    let mut fake = FakeTarget::rocky10().with_package("leafpkg");
    fake.pkgdb.scriptlet = FakeScriptlet::PostRemoveWarns;
    let r = run(&one("exact-warn", "leafpkg"), true, fake);
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed);
    assert_eq!(p.change, Change::Changed);
    assert!(reason(&r, "p").contains("script"), "{}", reason(&r, "p"));
}

// ---------------------------------------------------------------------------
// concurrency
// ---------------------------------------------------------------------------

#[test]
fn a_package_installed_between_check_and_removal_cannot_be_broken_on_apt() {
    // dpkg checks dependencies again under its own lock and refuses. It has
    // already recorded the removal request by then, so the package is left
    // marked `deinstall ok installed`: nothing was removed, the result says the
    // state could not be read and that a change is possible.
    for target in [FakeTarget::ubuntu2404(), FakeTarget::ubuntu2604()] {
        let mut fake = target.with_package("libpkg");
        fake.pkgdb.concurrent = Some(("newapp".to_string(), "libpkg".to_string()));
        let r = run(&one("exact-race-apt", "libpkg"), true, fake);
        let p = find(&r, "p");
        assert_eq!(p.execution, Execution::Failed);
        assert_eq!(p.change, Change::Possible, "{}", reason(&r, "p"));
        assert_ne!(p.verification, Verification::Verified);
        assert!(
            reason(&r, "p").contains("deinstall ok installed"),
            "{}",
            reason(&r, "p")
        );
        assert_eq!(removing(&r).len(), 1);
    }
}

#[test]
fn rpm_does_not_recheck_so_a_dependent_installed_in_the_window_is_detected_afterwards() {
    // Residual risk, documented: rpm -e checks dependencies, then takes its
    // transaction lock. A package committed in that gap is not seen by rpm.
    // The dependency verification after the removal reports it, and the
    // result is a failure, never a success.
    for target in [FakeTarget::rocky9(), FakeTarget::rocky10()] {
        let mut fake = target.with_package("libpkg");
        fake.pkgdb.concurrent = Some(("newapp".to_string(), "libpkg".to_string()));
        let r = run(&one("exact-race-rpm", "libpkg"), true, fake);
        let p = find(&r, "p");
        assert_eq!(p.execution, Execution::Failed);
        assert_eq!(p.change, Change::Changed);
        assert_eq!(p.verification, Verification::Failed);
        assert!(
            reason(&r, "p").contains("new package database problem"),
            "{}",
            reason(&r, "p")
        );
    }
}

#[test]
fn pre_existing_database_problems_do_not_block_a_clean_removal() {
    for (label, flavor, mut fake) in targets() {
        fake.pkgdb.audit_noise = vec![match flavor {
            Flavor::Apt => "The following packages are only half configured".to_string(),
            Flavor::Rpm => "Unsatisfied dependencies for old-1.0-1.el9.x86_64: missing".to_string(),
        }];
        let fake = fake.with_package("leafpkg");
        let r = run(&one(&format!("exact-noise-{label}"), "leafpkg"), true, fake);
        assert_success(&r);
        assert_eq!(find(&r, "p").change, Change::Changed, "{label}");
    }
}

// ---------------------------------------------------------------------------
// faults, output contract, audit
// ---------------------------------------------------------------------------

#[test]
fn injected_dispatch_and_reobserve_faults_keep_their_truthfulness() {
    for (label, _, fake) in targets() {
        let fake = fake.with_package("leafpkg");
        let path = one(&format!("exact-fault-{label}"), "leafpkg");
        let model = load_model(&path).unwrap();
        for (fault, change, execution) in [
            ("package_reobserve_fail", Change::Changed, Execution::Failed),
            (
                "package_reobserve_indeterminate",
                Change::Changed,
                Execution::Indeterminate,
            ),
        ] {
            let opts = RunOptions {
                mode: Mode::Apply,
                sudo: true,
                target: TargetSpec { ssh: None },
                verbose: false,
                fault: Some(fault.to_string()),
                fake_target: Some(fake.clone()),
            };
            let r = Engine::new(model.clone(), opts).unwrap().run().unwrap();
            let p = find(&r, "p");
            assert_eq!(p.change, change, "{label}: {fault}");
            assert_eq!(p.execution, execution, "{label}: {fault}");
        }
        let opts = RunOptions {
            mode: Mode::Apply,
            sudo: true,
            target: TargetSpec { ssh: None },
            verbose: false,
            fault: Some("package_mutation_dispatch_fail".to_string()),
            fake_target: Some(fake.clone()),
        };
        let r = Engine::new(model.clone(), opts).unwrap().run().unwrap();
        // A dispatch failure is an error result with no removing command.
        assert!(removing(&r).is_empty(), "{label}");
        assert_ne!(find(&r, "p").execution, Execution::Succeeded, "{label}");
    }
}

#[test]
fn plan_and_audit_never_dispatch_a_removing_command() {
    for (label, _, fake) in targets() {
        let fake = fake.with_package("leafpkg");
        let path = one(&format!("exact-plan-{label}"), "leafpkg");
        let plan = run_recipe_fake(&path, Mode::Plan, false, fake.clone());
        assert_eq!(find(&plan, "p").change, Change::Changed, "{label}");
        assert!(removing(&plan).is_empty(), "{label}");
        assert_exact_only(label, &plan);

        let model = load_model(&path).unwrap();
        let opts = RunOptions {
            mode: Mode::Plan,
            sudo: false,
            target: TargetSpec { ssh: None },
            verbose: false,
            fault: None,
            fake_target: Some(fake),
        };
        let engine = Engine::new(model, opts).unwrap();
        let audit = sinter::audit::run_audit(engine).unwrap();
        assert_eq!(audit.aggregate_label(), "drift", "{label}");
    }
}

#[test]
fn the_json_report_of_a_refused_removal_follows_the_contract_and_hides_sensitive_names() {
    let mut fake = FakeTarget::ubuntu2404()
        .with_package("libsecret")
        .with_package("appsecret");
    fake.pkgdb.add_requires("appsecret", "libsecret");
    let path = recipe("exact-json", &[("p", "libsecret", "absent")], true);
    let r = run(&path, true, fake);
    let mut buf = Vec::new();
    let opts = RenderOptions {
        verbose: true,
        format: OutputFormat::Json,
        color: false,
    };
    render_apply(&r, &opts, &mut buf).unwrap();
    let text = String::from_utf8(buf).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    let p = &v["resources"][0];
    assert_eq!(p["execution"], "failed");
    assert_eq!(p["change"], "none");
    assert_eq!(p["verification"], "not_performed");
    assert!(!text.contains("libsecret"), "{text}");
    assert!(!text.contains("appsecret"), "{text}");
}

// ---------------------------------------------------------------------------
// checks after the removal that cannot be completed
// ---------------------------------------------------------------------------

fn indeterminate() -> Output {
    Output {
        completion: Completion::Indeterminate {
            started: true,
            reason: "connection lost".to_string(),
        },
        stdout: Vec::new(),
        stderr: Vec::new(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

#[test]
fn a_post_removal_check_that_cannot_complete_is_unknown_not_clean_and_not_an_error() {
    // (target, key of the check, the baseline answer served first)
    let cases: Vec<(FakeTarget, &str, Output)> = vec![
        (
            FakeTarget::ubuntu2404(),
            "dpkg-inventory",
            output(
                0,
                "install ok installed\tleafpkg\tamd64\ninstall ok installed\tbase-files\tamd64\n",
                "",
            ),
        ),
        (FakeTarget::ubuntu2404(), "dpkg-audit", output(0, "", "")),
        (
            FakeTarget::rocky9(),
            "rpm-inventory",
            output(0, "leafpkg\tx86_64\nsetup\tnoarch\n", ""),
        ),
        (FakeTarget::rocky9(), "rpm-verify", output(0, "", "")),
    ];
    for (fake, key, baseline) in cases {
        let mut fake = fake.with_package("leafpkg");
        fake.pkgdb.force(key, baseline);
        fake.pkgdb.force(key, indeterminate());
        let r = run(&one(&format!("exact-post-{key}"), "leafpkg"), true, fake);
        let p = find(&r, "p");
        assert_eq!(p.change, Change::Changed, "{key}");
        assert_eq!(p.execution, Execution::Failed, "{key}");
        assert_eq!(p.verification, Verification::Unknown, "{key}");
        assert!(
            reason(&r, "p").contains("could not be read back"),
            "{key}: {}",
            reason(&r, "p")
        );
        assert_eq!(removing(&r).len(), 1, "{key}");
    }
}

#[test]
fn a_removal_that_does_not_show_in_the_package_list_is_not_verified() {
    let mut fake = FakeTarget::rocky9().with_package("leafpkg");
    // Before and after both list the target: the database does not show a
    // removal even though the package query says it is gone.
    let listed = "leafpkg\tx86_64\nsetup\tnoarch\n";
    fake.pkgdb.force("rpm-inventory", output(0, listed, ""));
    fake.pkgdb.force("rpm-inventory", output(0, listed, ""));
    let r = run(&one("exact-post-nodrop", "leafpkg"), true, fake);
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed);
    assert_eq!(p.verification, Verification::Failed);
    assert!(reason(&r, "p").contains("exactly the requested package"));
}

// ---------------------------------------------------------------------------
// independent-audit findings (B-1, N-2, N-3, N-4)
// ---------------------------------------------------------------------------

#[test]
fn a_live_dnf_transaction_refuses_the_removal_before_rpm_runs() {
    for target in [FakeTarget::rocky9(), FakeTarget::rocky10()] {
        let mut fake = target.with_package("leafpkg");
        fake.pkgdb.dnf_lock_holder = true;
        let r = run(&one("exact-dnf-active", "leafpkg"), true, fake);
        let p = find(&r, "p");
        assert_eq!(p.execution, Execution::Failed);
        assert_eq!(p.change, Change::None);
        assert!(
            reason(&r, "p").contains("a dnf transaction is in progress"),
            "{}",
            reason(&r, "p")
        );
    }
    // The wrapper's other exit codes are refusals too, with their own words.
    for (code, words) in [
        (75, "the dnf lock is held by another process"),
        (77, "the dnf lock file could not be read"),
    ] {
        let mut fake = FakeTarget::rocky9().with_package("leafpkg");
        fake.pkgdb.force("rpm-erase", output(code, "", ""));
        let r = run(&one("exact-dnf-wrapper-code", "leafpkg"), true, fake);
        let p = find(&r, "p");
        assert_eq!(p.change, Change::None, "{code}");
        assert!(
            reason(&r, "p").contains(words),
            "{code}: {}",
            reason(&r, "p")
        );
    }
}

#[test]
fn recipe_environment_cannot_change_how_dpkg_or_rpm_behave() {
    for (label, _, fake) in targets() {
        let dir = trusted_root(&format!("exact-env-{label}"));
        let path = write_recipe(
            &dir,
            "r.yaml",
            "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: leafpkg\n      state: absent\n      env:\n        DPKG_FORCE: depends\n        DPKG_ADMINDIR: /tmp/elsewhere\n        DPKG_FRONTEND_LOCKED: \"1\"\n        LANGUAGE: de\n        RPM_CONFIGDIR: /tmp/elsewhere\n        DEBIAN_FRONTEND: noninteractive\n",
        );
        let r = run(&path, true, fake.with_package("leafpkg"));
        assert_success(&r);
        for c in &r.commands {
            let prog = c.program.rsplit('/').next().unwrap_or(&c.program);
            if !matches!(
                prog,
                "dpkg" | "dpkg-query" | "rpm" | "sh" | "find" | "cat" | "uname"
            ) {
                continue;
            }
            for bad in [
                "DPKG_FORCE",
                "DPKG_ADMINDIR",
                "DPKG_FRONTEND_LOCKED",
                "LANGUAGE",
                "RPM_CONFIGDIR",
            ] {
                assert!(!c.env.contains_key(bad), "{label}: {bad} reached {prog}");
            }
        }
        let removal = removing(&r);
        assert_eq!(removal.len(), 1, "{label}");
        // A name on the allowlist still gets through.
        assert_eq!(
            removal[0].env.get("DEBIAN_FRONTEND").map(String::as_str),
            Some("noninteractive"),
            "{label}"
        );
    }
}

#[test]
fn forced_dependency_removal_configured_on_the_host_is_cancelled_and_never_success() {
    // The dpkg command line says --refuse-depends: a host configured with
    // force-depends still refuses.
    let mut fake = FakeTarget::ubuntu2404().with_package("libpkg");
    fake.pkgdb.force_depends_config = true;
    fake.pkgdb.concurrent = Some(("newapp".to_string(), "libpkg".to_string()));
    let r = run(&one("exact-force-config", "libpkg"), true, fake);
    assert_eq!(find(&r, "p").execution, Execution::Failed);
    assert_ne!(find(&r, "p").verification, Verification::Verified);
    // Refused under the lock: the package is still there (selection recorded).
    assert!(
        reason(&r, "p").contains("deinstall ok installed"),
        "{}",
        reason(&r, "p")
    );

    // A dpkg that ignored the options would remove it and say so. That is a
    // failed result, not a success: the dependency check afterwards sees it.
    let mut fake = FakeTarget::ubuntu2404().with_package("libpkg");
    fake.pkgdb.force_depends_config = true;
    fake.pkgdb.ignore_refuse_flags = true;
    fake.pkgdb.concurrent = Some(("newapp".to_string(), "libpkg".to_string()));
    let r = run(&one("exact-force-ignored", "libpkg"), true, fake);
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed);
    assert_eq!(p.change, Change::Changed);
    assert_eq!(p.verification, Verification::Failed);
}

#[test]
fn a_dry_run_that_reports_a_forced_removal_is_refused() {
    let mut fake = FakeTarget::ubuntu2404().with_package("libpkg");
    fake.pkgdb.force_depends_config = true;
    fake.pkgdb.ignore_refuse_flags = true;
    fake.pkgdb.add_requires("app", "libpkg");
    let fake = fake.with_package("app");
    let r = run(&one("exact-force-dryrun", "libpkg"), true, fake);
    assert_eq!(find(&r, "p").change, Change::None);
    assert!(removing(&r).is_empty());
}

#[test]
fn apt_dependency_problems_that_exist_before_are_not_blamed_on_the_removal() {
    let mut fake = FakeTarget::ubuntu2404().with_package("leafpkg");
    fake.pkgdb.check_noise = vec![" old : Depends: gone but it is not installed".to_string()];
    let r = run(&one("exact-apt-check-noise", "leafpkg"), true, fake);
    assert_success(&r);
}

#[test]
fn an_apt_dependency_check_that_cannot_run_refuses_before_the_removal() {
    let mut fake = FakeTarget::ubuntu2404().with_package("leafpkg");
    fake.pkgdb.force(
        "apt-check",
        output(
            100,
            "",
            "E: Could not get lock /var/lib/dpkg/lock-frontend\n",
        ),
    );
    let r = run(&one("exact-apt-check-lock", "leafpkg"), true, fake);
    assert_eq!(find(&r, "p").change, Change::None);
    assert_eq!(find(&r, "p").execution, Execution::Failed);
    assert!(removing(&r).is_empty());
}

#[test]
fn a_custom_protected_glob_that_cannot_be_evaluated_refuses() {
    let mut fake = FakeTarget::rocky9().with_package("leafpkg");
    fake.pkgdb.dnf_conf =
        Some("[main]\nprotected_packages=dnf glob:/etc/corp/protected/*.conf\n".to_string());
    let r = run(&one("exact-dnf-custom-glob", "leafpkg"), true, fake);
    assert_eq!(find(&r, "p").execution, Execution::Failed);
    assert_eq!(find(&r, "p").change, Change::None);
    assert!(removing(&r).is_empty());
    // The default directories alone are fine.
    let mut fake = FakeTarget::rocky9().with_package("leafpkg");
    fake.pkgdb.dnf_conf =
        Some("[main]\nprotected_packages=dnf,glob:/etc/dnf/protected.d/*.conf\n".to_string());
    let r = run(&one("exact-dnf-default-glob", "leafpkg"), true, fake);
    assert_success(&r);
}

#[test]
fn a_variant_kernel_that_is_running_is_recognised_through_its_image() {
    let mut fake = FakeTarget::rocky9().with_package("kernel-debug-core");
    fake.pkgdb.kernel_release = Some("5.14.0-1.el9.x86_64+debug".to_string());
    fake.pkgdb.kernel_owner = Some("kernel-debug-core".to_string());
    let r = run(
        &one("exact-kernel-variant", "kernel-debug-core"),
        true,
        fake,
    );
    assert!(
        reason(&r, "p").contains("running kernel"),
        "{}",
        reason(&r, "p")
    );
    assert!(removing(&r).is_empty());
}

#[test]
fn a_nonzero_exit_after_the_package_went_is_checked_like_a_success() {
    for (label, _, mut fake) in targets() {
        fake.pkgdb.scriptlet = FakeScriptlet::FailsAfterRemoval;
        fake.pkgdb.extra_removed = vec!["innocent".to_string()];
        let fake = fake.with_package("leafpkg").with_package("innocent");
        let r = run(
            &one(&format!("exact-nonzero-extra-{label}"), "leafpkg"),
            true,
            fake,
        );
        let p = find(&r, "p");
        assert_eq!(p.execution, Execution::Failed, "{label}");
        assert_eq!(p.change, Change::Changed, "{label}");
        // Not "verified": another package went with it.
        assert_eq!(p.verification, Verification::Failed, "{label}");
        assert!(
            reason(&r, "p").contains("innocent"),
            "{label}: {}",
            reason(&r, "p")
        );
    }
}

#[test]
fn a_package_that_someone_else_removed_first_is_not_credited_to_sinter() {
    // rpm fails with "not installed"; dpkg warns "ignoring request to remove X
    // which isn't installed" and exits 0. Neither is a change made by Sinter.
    for (label, _, mut fake) in targets() {
        fake.pkgdb.scriptlet = FakeScriptlet::RemovedByOther;
        let fake = fake.with_package("leafpkg");
        let r = run(
            &one(&format!("exact-by-other-{label}"), "leafpkg"),
            true,
            fake,
        );
        let p = find(&r, "p");
        assert_eq!(p.execution, Execution::Failed, "{label}");
        assert_eq!(p.change, Change::None, "{label}");
        assert!(
            reason(&r, "p").contains("already gone"),
            "{label}: {}",
            reason(&r, "p")
        );
    }
}

#[test]
fn an_already_gone_package_does_not_hide_another_package_that_vanished_with_it() {
    let mut fake = FakeTarget::ubuntu2404();
    fake.pkgdb.scriptlet = FakeScriptlet::RemovedByOther;
    fake.pkgdb.extra_removed = vec!["innocent".to_string()];
    let fake = fake.with_package("leafpkg").with_package("innocent");
    let r = run(&one("exact-gone-and-innocent", "leafpkg"), true, fake);
    let p = find(&r, "p");
    assert_eq!(p.change, Change::None);
    assert_eq!(p.execution, Execution::Failed);
    assert!(
        reason(&r, "p").contains("already gone") && reason(&r, "p").contains("innocent"),
        "{}",
        reason(&r, "p")
    );
}

#[test]
fn a_script_that_merely_says_isnt_installed_does_not_turn_a_real_removal_into_a_no_op() {
    for (label, _, mut fake) in targets() {
        fake.pkgdb.scriptlet = FakeScriptlet::NoisyScript;
        let fake = fake.with_package("leafpkg");
        let r = run(&one(&format!("exact-noisy-{label}"), "leafpkg"), true, fake);
        let p = find(&r, "p");
        assert_eq!(p.change, Change::Changed, "{label}: {}", reason(&r, "p"));
        assert_eq!(
            p.execution,
            Execution::Succeeded,
            "{label}: {}",
            reason(&r, "p")
        );
        assert!(!reason(&r, "p").contains("already gone"), "{label}");
    }
}

/// The wordings dpkg 1.22 uses for "that package is not there" (and exits 0).
const APT_GONE_WORDINGS: [FakeScriptlet; 4] = [
    FakeScriptlet::RemovedByOther,
    FakeScriptlet::RemovedByOtherConfigFiles,
    FakeScriptlet::RemovedByOtherQualified,
    FakeScriptlet::RemovedByOtherQualifiedConfigFiles,
];

#[test]
fn apt_credits_nothing_to_sinter_whichever_warning_dpkg_uses_for_a_package_that_is_gone() {
    for target in [FakeTarget::ubuntu2404(), FakeTarget::ubuntu2604()] {
        for scriptlet in APT_GONE_WORDINGS {
            let mut fake = target.clone();
            fake.pkgdb.scriptlet = scriptlet;
            let r = run(
                &one(&format!("exact-gone-{scriptlet:?}"), "leafpkg"),
                true,
                fake.with_package("leafpkg"),
            );
            let p = find(&r, "p");
            let why = format!("{scriptlet:?}: {}", reason(&r, "p"));
            assert_eq!(p.change, Change::None, "{why}");
            assert_eq!(p.execution, Execution::Failed, "{why}");
            assert_eq!(p.verification, Verification::Verified, "{why}");
            assert!(reason(&r, "p").contains("already gone"), "{why}");
            assert!(reason(&r, "p").contains("no-op"), "{why}");
        }
    }
}

#[test]
fn the_qualified_warning_names_the_architecture_of_the_package_that_was_removed() {
    for arch in ["amd64", "arm64", "i386", "all"] {
        for scriptlet in [
            FakeScriptlet::RemovedByOtherQualified,
            FakeScriptlet::RemovedByOtherQualifiedConfigFiles,
        ] {
            let mut fake = FakeTarget::ubuntu2404();
            fake.pkgdb.scriptlet = scriptlet;
            fake.pkgdb.meta.insert(
                "leafpkg".to_string(),
                sinter::fakepkg::FakePkg {
                    arch: Some(arch.to_string()),
                    ..Default::default()
                },
            );
            let r = run(
                &one(&format!("exact-gone-arch-{arch}-{scriptlet:?}"), "leafpkg"),
                true,
                fake.with_package("leafpkg"),
            );
            let p = find(&r, "p");
            let why = format!("{arch} {scriptlet:?}: {}", reason(&r, "p"));
            assert_eq!(p.change, Change::None, "{why}");
            assert_eq!(p.execution, Execution::Failed, "{why}");
            assert!(reason(&r, "p").contains("already gone"), "{why}");
        }
    }
}

#[test]
fn a_package_that_was_already_gone_never_hides_what_else_changed_in_any_wording() {
    // another package vanished with it
    for scriptlet in APT_GONE_WORDINGS {
        let mut fake = FakeTarget::ubuntu2404();
        fake.pkgdb.scriptlet = scriptlet;
        fake.pkgdb.extra_removed = vec!["innocent".to_string()];
        let fake = fake.with_package("leafpkg").with_package("innocent");
        let r = run(
            &one(&format!("exact-gone-innocent-{scriptlet:?}"), "leafpkg"),
            true,
            fake,
        );
        let p = find(&r, "p");
        let why = format!("{scriptlet:?}: {}", reason(&r, "p"));
        assert_eq!(p.change, Change::None, "{why}");
        assert_eq!(p.execution, Execution::Failed, "{why}");
        assert_ne!(p.verification, Verification::Verified, "{why}");
        assert!(
            reason(&r, "p").contains("already gone") && reason(&r, "p").contains("innocent"),
            "{why}"
        );
    }
    // a dependency problem that appeared meanwhile
    for scriptlet in APT_GONE_WORDINGS {
        let mut fake = FakeTarget::ubuntu2404().with_package("leafpkg");
        fake.pkgdb.scriptlet = scriptlet;
        let clean =
            "Reading package lists...\nBuilding dependency tree...\nReading state information...\n";
        fake.pkgdb.force("apt-check", output(0, clean, ""));
        fake.pkgdb.force(
            "apt-check",
            output(
                100,
                &format!("{clean}The following packages have unmet dependencies:\n app : Depends: gone but it is not installed\n"),
                "E: Unmet dependencies.\n",
            ),
        );
        let r = run(
            &one(&format!("exact-gone-check-{scriptlet:?}"), "leafpkg"),
            true,
            fake,
        );
        let p = find(&r, "p");
        let why = format!("{scriptlet:?}: {}", reason(&r, "p"));
        assert_eq!(p.change, Change::None, "{why}");
        assert_eq!(p.execution, Execution::Failed, "{why}");
        assert_eq!(p.verification, Verification::Failed, "{why}");
        assert!(
            reason(&r, "p").contains("already gone")
                && reason(&r, "p").contains("new package database problem"),
            "{why}"
        );
    }
    // a database that cannot be read back afterwards
    for scriptlet in APT_GONE_WORDINGS {
        let mut fake = FakeTarget::ubuntu2404().with_package("leafpkg");
        fake.pkgdb.scriptlet = scriptlet;
        let clean =
            "Reading package lists...\nBuilding dependency tree...\nReading state information...\n";
        fake.pkgdb.force("apt-check", output(0, clean, ""));
        fake.pkgdb.force(
            "apt-check",
            output(
                100,
                "",
                "E: Could not get lock /var/lib/dpkg/lock-frontend\n",
            ),
        );
        let r = run(
            &one(&format!("exact-gone-unreadable-{scriptlet:?}"), "leafpkg"),
            true,
            fake,
        );
        let p = find(&r, "p");
        let why = format!("{scriptlet:?}: {}", reason(&r, "p"));
        assert_eq!(p.change, Change::None, "{why}");
        assert_eq!(p.execution, Execution::Failed, "{why}");
        assert_ne!(p.verification, Verification::Verified, "{why}");
        assert!(reason(&r, "p").contains("already gone"), "{why}");
    }
}

#[test]
fn the_dnf4_result_for_a_package_that_is_gone_does_not_depend_on_dpkgs_wording() {
    for target in [FakeTarget::rocky9(), FakeTarget::rocky10()] {
        for scriptlet in APT_GONE_WORDINGS {
            let mut fake = target.clone();
            fake.pkgdb.scriptlet = scriptlet;
            let r = run(
                &one(&format!("exact-gone-rpm-{scriptlet:?}"), "leafpkg"),
                true,
                fake.with_package("leafpkg"),
            );
            let p = find(&r, "p");
            let why = format!("{scriptlet:?}: {}", reason(&r, "p"));
            assert_eq!(p.change, Change::None, "{why}");
            assert_eq!(p.execution, Execution::Failed, "{why}");
            assert_eq!(p.verification, Verification::Verified, "{why}");
            assert!(reason(&r, "p").contains("already gone"), "{why}");
        }
    }
}

#[test]
fn a_script_that_forges_dpkgs_warning_does_not_turn_a_real_removal_into_a_no_op() {
    for (label, _, mut fake) in targets() {
        fake.pkgdb.scriptlet = FakeScriptlet::ForgedWarning;
        let r = run(
            &one(&format!("exact-forged-{label}"), "leafpkg"),
            true,
            fake.with_package("leafpkg"),
        );
        let p = find(&r, "p");
        let why = format!("{label}: {}", reason(&r, "p"));
        assert_eq!(p.change, Change::Changed, "{why}");
        assert_eq!(p.execution, Execution::Succeeded, "{why}");
        assert_eq!(p.verification, Verification::Verified, "{why}");
        assert!(!reason(&r, "p").contains("already gone"), "{why}");
        assert_eq!(removing(&r).len(), 1, "{label}");
    }
}

#[test]
fn a_no_op_report_has_the_same_shape_for_a_sensitive_resource_and_in_json() {
    for scriptlet in APT_GONE_WORDINGS {
        let mut fake = FakeTarget::ubuntu2404();
        fake.pkgdb.scriptlet = scriptlet;
        fake.pkgdb.extra_removed = vec!["innocentsecret".to_string()];
        let fake = fake
            .with_package("leafsecret")
            .with_package("innocentsecret");
        let path = recipe(
            &format!("exact-gone-sensitive-{scriptlet:?}"),
            &[("p", "leafsecret", "absent")],
            true,
        );
        let r = run(&path, true, fake);
        let p = find(&r, "p");
        assert_eq!(p.change, Change::None, "{scriptlet:?}");
        assert_eq!(p.execution, Execution::Failed, "{scriptlet:?}");
        let why = reason(&r, "p");
        assert!(
            !why.contains("leafsecret") && !why.contains("innocentsecret"),
            "{scriptlet:?}: {why}"
        );
        let mut buf = Vec::new();
        let opts = RenderOptions {
            verbose: true,
            format: OutputFormat::Json,
            color: false,
        };
        render_apply(&r, &opts, &mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["resources"][0]["execution"], "failed", "{scriptlet:?}");
        assert_eq!(v["resources"][0]["change"], "none", "{scriptlet:?}");
        assert!(
            !text.contains("leafsecret") && !text.contains("innocentsecret"),
            "{scriptlet:?}: {text}"
        );
    }
}

#[test]
fn rpm_verification_output_that_is_not_understood_refuses_before_the_removal() {
    let mut fake = FakeTarget::rocky10().with_package("leafpkg");
    fake.pkgdb.force(
        "rpm-verify",
        output(1, "", "error: rpmdb: damaged header #5\n"),
    );
    let r = run(&one("exact-rpm-verify-garbage", "leafpkg"), true, fake);
    assert_eq!(find(&r, "p").change, Change::None);
    assert_eq!(find(&r, "p").execution, Execution::Failed);
    assert!(removing(&r).is_empty());

    // The same error after the removal is not "no new problem" either.
    let ok = output(0, "", "");
    let mut fake = FakeTarget::rocky10().with_package("leafpkg");
    fake.pkgdb.force("rpm-verify", ok);
    fake.pkgdb.force(
        "rpm-verify",
        output(1, "", "error: rpmdb: damaged header #5\n"),
    );
    let r = run(
        &one("exact-rpm-verify-garbage-after", "leafpkg"),
        true,
        fake,
    );
    assert_eq!(find(&r, "p").verification, Verification::Unknown);
    assert_eq!(find(&r, "p").execution, Execution::Failed);
}

#[test]
fn a_forced_removal_is_a_failure_even_when_the_dependency_check_afterwards_looks_clean() {
    // apt-get check is told twice that all is well (baseline and after), so
    // only dpkg's own "removing anyway" notice reveals what happened.
    let mut fake = FakeTarget::ubuntu2404().with_package("libpkg");
    fake.pkgdb.force_depends_config = true;
    fake.pkgdb.ignore_refuse_flags = true;
    fake.pkgdb.concurrent = Some(("newapp".to_string(), "libpkg".to_string()));
    let clean =
        "Reading package lists...\nBuilding dependency tree...\nReading state information...\n";
    fake.pkgdb.force("apt-check", output(0, clean, ""));
    fake.pkgdb.force("apt-check", output(0, clean, ""));
    let r = run(&one("exact-forced-clean-check", "libpkg"), true, fake);
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed);
    assert_eq!(p.change, Change::Changed);
    assert_eq!(p.verification, Verification::Failed);
    assert!(
        reason(&r, "p").contains("ignore them"),
        "{}",
        reason(&r, "p")
    );
}

#[test]
fn a_dependency_problem_that_appears_in_the_apt_check_after_the_removal_fails_it() {
    let mut fake = FakeTarget::ubuntu2404().with_package("leafpkg");
    let clean =
        "Reading package lists...\nBuilding dependency tree...\nReading state information...\n";
    fake.pkgdb.force("apt-check", output(0, clean, ""));
    fake.pkgdb.force(
        "apt-check",
        output(
            100,
            &format!("{clean}The following packages have unmet dependencies:\n app : Depends: gone but it is not installed\n"),
            "E: Unmet dependencies.\n",
        ),
    );
    let r = run(&one("exact-apt-check-after", "leafpkg"), true, fake);
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed);
    assert_eq!(p.verification, Verification::Failed);
    assert!(
        reason(&r, "p").contains("new package database problem"),
        "{}",
        reason(&r, "p")
    );
}

#[test]
fn a_baseline_that_fails_for_lack_of_privilege_says_so() {
    for (key, fake) in [
        ("dpkg-audit", FakeTarget::ubuntu2404()),
        ("rpm-verify", FakeTarget::rocky9()),
    ] {
        let mut fake = fake.with_package("leafpkg");
        fake.pkgdb.force(
            key,
            output(
                2,
                "",
                "dpkg: error: requested operation requires superuser privilege\n",
            ),
        );
        let r = run(
            &one(&format!("exact-baseline-priv-{key}"), "leafpkg"),
            true,
            fake,
        );
        assert_eq!(find(&r, "p").change, Change::None, "{key}");
        assert!(
            reason(&r, "p").contains("no privilege"),
            "{key}: {}",
            reason(&r, "p")
        );
        assert!(removing(&r).is_empty(), "{key}");
    }
}

#[test]
fn protected_files_that_cannot_be_read_because_find_cannot_run_a_program_refuse() {
    // `find` printing "No such file or directory" for the program it should
    // run must not be read as "the protected directories do not exist".
    for missing in ["/usr/bin/cat", "/usr/bin/printf"] {
        let mut fake = FakeTarget::rocky9().with_package("leafpkg");
        fake.pkgdb.dnf_protected_d = Some("leafpkg\n".to_string());
        fake.pkgdb.force(
            "protected-d",
            output(
                1,
                "",
                &format!("find: '{missing}': No such file or directory\n"),
            ),
        );
        let r = run(&one("exact-find-no-program", "leafpkg"), true, fake);
        assert_eq!(find(&r, "p").execution, Execution::Failed, "{missing}");
        assert_eq!(find(&r, "p").change, Change::None, "{missing}");
        assert!(removing(&r).is_empty(), "{missing}");
    }
}

#[test]
fn a_custom_dnf_persistdir_refuses_because_the_lock_is_elsewhere() {
    let mut fake = FakeTarget::rocky10().with_package("leafpkg");
    fake.pkgdb.dnf_conf = Some("[main]\npersistdir=/data/dnf\n".to_string());
    let r = run(&one("exact-persistdir", "leafpkg"), true, fake);
    assert_eq!(find(&r, "p").change, Change::None);
    assert!(removing(&r).is_empty());
    assert!(
        reason(&r, "p").contains("persistdir"),
        "{}",
        reason(&r, "p")
    );
    // dnf-automatic can override it in its own configuration, and a later
    // line cannot hide an earlier custom one.
    let mut fake = FakeTarget::rocky10().with_package("leafpkg");
    fake.pkgdb.automatic_conf = Some("[base]\npersistdir=/data/dnf\n".to_string());
    let r = run(&one("exact-persistdir-automatic", "leafpkg"), true, fake);
    assert_eq!(find(&r, "p").change, Change::None);
    assert!(removing(&r).is_empty());
    let mut fake = FakeTarget::rocky10().with_package("leafpkg");
    fake.pkgdb.dnf_conf =
        Some("[main]\npersistdir=/data/dnf\npersistdir=/var/lib/dnf\n".to_string());
    let r = run(&one("exact-persistdir-two", "leafpkg"), true, fake);
    assert_eq!(find(&r, "p").change, Change::None);
    assert!(removing(&r).is_empty());
    // ... and a default value first cannot hide a custom one after it.
    let mut fake = FakeTarget::rocky10().with_package("leafpkg");
    fake.pkgdb.dnf_conf =
        Some("[main]\npersistdir=/var/lib/dnf\npersistdir=/data/dnf\n".to_string());
    let r = run(&one("exact-persistdir-two-b", "leafpkg"), true, fake);
    assert_eq!(find(&r, "p").change, Change::None);
    assert!(removing(&r).is_empty());
    // The default value is fine, with or without a trailing slash.
    for dir in ["/var/lib/dnf", "/var/lib/dnf/"] {
        let mut fake = FakeTarget::rocky10().with_package("leafpkg");
        fake.pkgdb.dnf_conf = Some(format!("[main]\npersistdir={dir}\n"));
        let r = run(&one("exact-persistdir-default", "leafpkg"), true, fake);
        assert_success(&r);
    }
}

#[test]
fn dropped_recipe_environment_is_reported_without_naming_it() {
    for (label, _, fake) in targets() {
        let dir = trusted_root(&format!("exact-env-note-{label}"));
        let path = write_recipe(
            &dir,
            "r.yaml",
            "version: 1\nresources:\n  - id: p\n    type: package\n    sensitive: true\n    with:\n      name: leafpkg\n      state: absent\n      env:\n        SECRET_TOKEN_NAME: x\n        DEBIAN_FRONTEND: noninteractive\n",
        );
        let r = run(&path, true, fake.with_package("leafpkg"));
        assert_success(&r);
        let notes = find(&r, "p").notes.join(" | ");
        assert!(notes.contains("1 environment variable"), "{label}: {notes}");
        assert!(!notes.contains("SECRET_TOKEN_NAME"), "{label}: {notes}");
    }
}

#[test]
fn wrapper_exit_codes_that_mean_rpm_never_ran_are_not_a_possible_change() {
    for (code, words) in [
        (78, "changed while it was being taken"),
        (127, "could not be run"),
    ] {
        let mut fake = FakeTarget::rocky9().with_package("leafpkg");
        fake.pkgdb.force("rpm-erase", output(code, "", ""));
        let r = run(&one("exact-wrapper-codes", "leafpkg"), true, fake);
        let p = find(&r, "p");
        assert_eq!(p.change, Change::None, "{code}");
        assert!(
            reason(&r, "p").contains(words),
            "{code}: {}",
            reason(&r, "p")
        );
    }
}

// ---------------------------------------------------------------------------
// final safety hardening: DNF configuration and running-kernel edge cases
// ---------------------------------------------------------------------------

#[test]
fn dnf_configuration_that_cannot_be_read_or_understood_refuses() {
    // (key of the forced answer, answer)
    let cases: Vec<(&str, Output)> = vec![
        (
            "dnf-conf",
            output(1, "", "cat: /etc/dnf/dnf.conf: Permission denied\n"),
        ),
        ("dnf-conf", output(2, "", "")),
        (
            "dnf-conf",
            Output {
                stdout: vec![0xff, 0xfe, b'x'],
                ..output(0, "", "")
            },
        ),
        ("dnf-conf", output(0, "[main]\n", "warning\n")),
        (
            "automatic-conf",
            output(1, "", "cat: /etc/dnf/automatic.conf: Permission denied\n"),
        ),
        (
            "automatic-conf",
            Output {
                stdout_truncated: true,
                ..output(0, "[base]\n", "")
            },
        ),
        ("protected-d", output(0, "", "cat: x: Permission denied\n")),
    ];
    for (i, (key, answer)) in cases.into_iter().enumerate() {
        let mut fake = FakeTarget::rocky9().with_package("leafpkg");
        fake.pkgdb.force(key, answer);
        let r = run(
            &one(&format!("exact-dnfconf-bad-{i}"), "leafpkg"),
            true,
            fake,
        );
        assert_eq!(find(&r, "p").execution, Execution::Failed, "{key} #{i}");
        assert_eq!(find(&r, "p").change, Change::None, "{key} #{i}");
        assert!(removing(&r).is_empty(), "{key} #{i}");
    }
}

#[test]
fn an_empty_or_odd_persistdir_value_refuses() {
    for value in [
        "",
        "   ",
        "relative/dir",
        "/var/lib/dnf/../dnf2",
        "\"/var/lib/dnf\"",
        "/var/lib/dnf # note",
    ] {
        let mut fake = FakeTarget::rocky10().with_package("leafpkg");
        fake.pkgdb.dnf_conf = Some(format!("[main]\npersistdir={value}\n"));
        let r = run(&one("exact-persistdir-odd", "leafpkg"), true, fake);
        assert_eq!(find(&r, "p").change, Change::None, "{value:?}");
        assert!(removing(&r).is_empty(), "{value:?}");
    }
}

#[test]
fn running_kernel_queries_that_fail_refuse_and_either_image_path_counts() {
    let base = || {
        let mut fake = FakeTarget::rocky9().with_package("kernel-core");
        fake.pkgdb.kernel_release = Some("5.14.0-1.el9.x86_64".to_string());
        fake.pkgdb.kernel_owner = Some("kernel-core".to_string());
        fake
    };
    // uname fails or prints something that is not a kernel release.
    for (i, bad) in [
        output(1, "", "uname: error\n"),
        output(0, "", ""),
        output(0, "5.14 0\n", ""),
        output(0, "5.14.0-1\n", "warning\n"),
    ]
    .into_iter()
    .enumerate()
    {
        let mut fake = base();
        fake.pkgdb.force("uname-r", bad);
        let r = run(
            &one(&format!("exact-kernel-uname-{i}"), "kernel-core"),
            true,
            fake,
        );
        assert_eq!(find(&r, "p").change, Change::None, "uname #{i}");
        assert!(removing(&r).is_empty(), "uname #{i}");
    }
    // rpm -qf fails (damaged database) or answers with two owners.
    for (i, bad) in [
        output(1, "", "error: rpmdb: damaged header\n"),
        output(2, "", ""),
        output(0, "kernel-core\nkernel-other\n", ""),
        output(0, "", ""),
    ]
    .into_iter()
    .enumerate()
    {
        let mut fake = base();
        fake.pkgdb.force("rpm-owner", bad);
        let r = run(
            &one(&format!("exact-kernel-qf-{i}"), "kernel-core"),
            true,
            fake,
        );
        assert_eq!(find(&r, "p").change, Change::None, "qf #{i}");
        assert!(removing(&r).is_empty(), "qf #{i}");
    }
    // The first path has no owner, the second one is owned by the target.
    let mut fake = base();
    fake.pkgdb.force(
        "rpm-owner",
        output(
            1,
            "",
            "error: file /boot/vmlinuz-5.14.0-1.el9.x86_64: No such file or directory\n",
        ),
    );
    let r = run(&one("exact-kernel-second-path", "kernel-core"), true, fake);
    assert!(
        reason(&r, "p").contains("running kernel"),
        "{}",
        reason(&r, "p")
    );
    assert!(removing(&r).is_empty());
    // Nobody owns the running image (a kernel built by hand): not protected.
    let mut fake = base();
    fake.pkgdb.kernel_owner = None;
    let r = run(&one("exact-kernel-unowned", "kernel-core"), true, fake);
    assert_success(&r);
}

#[test]
fn a_removing_command_that_does_not_complete_leaves_the_target_alone_afterwards() {
    // Timeout, cancel or a lost connection after the removing command was
    // dispatched: the change is possible, the state is unknown, and nothing
    // else is sent to the host (the command may still be running).
    for (label, flavor, fake) in targets() {
        for (name, completion, execution) in [
            (
                "indeterminate",
                Completion::Indeterminate {
                    started: true,
                    reason: "connection lost".to_string(),
                },
                Execution::Indeterminate,
            ),
            ("signaled", Completion::Signaled(9), Execution::Failed),
        ] {
            let mut fake = fake.clone().with_package("leafpkg");
            let key = if flavor == Flavor::Apt {
                "dpkg-remove"
            } else {
                "rpm-erase"
            };
            fake.pkgdb.force(
                key,
                Output {
                    completion,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    stdout_truncated: false,
                    stderr_truncated: false,
                },
            );
            let r = run(
                &one(&format!("exact-incomplete-{name}-{label}"), "leafpkg"),
                true,
                fake,
            );
            let p = find(&r, "p");
            assert_eq!(p.execution, execution, "{label} {name}");
            assert_eq!(p.change, Change::Possible, "{label} {name}");
            assert_eq!(p.verification, Verification::Unknown, "{label} {name}");
            // The removing command is the last thing sent to the host.
            let last = r.commands.last().unwrap();
            assert!(
                removing(&r).iter().any(|c| std::ptr::eq(*c, last)),
                "{label} {name}: a command followed the removal: {} {:?}",
                last.program,
                last.args
            );
        }
    }
}

// ---------------------------------------------------------------------------
// SA-3: a refusal is proven by where dpkg stopped, not by words in the output
// ---------------------------------------------------------------------------

const APT_TARGETS: [fn() -> FakeTarget; 2] = [FakeTarget::ubuntu2404, FakeTarget::ubuntu2604];

fn json_of(r: &sinter::engine::RunReport) -> serde_json::Value {
    let mut buf = Vec::new();
    let opts = RenderOptions {
        verbose: true,
        format: OutputFormat::Json,
        color: false,
    };
    render_apply(r, &opts, &mut buf).unwrap();
    serde_json::from_str(&String::from_utf8(buf).unwrap()).unwrap()
}

fn text_of(r: &sinter::engine::RunReport) -> String {
    let mut buf = Vec::new();
    let opts = RenderOptions {
        verbose: true,
        format: OutputFormat::Text,
        color: false,
    };
    render_apply(r, &opts, &mut buf).unwrap();
    String::from_utf8(buf).unwrap()
}

#[test]
fn script_output_that_repeats_dpkgs_refusal_words_never_turns_a_removal_into_no_change() {
    for target in APT_TARGETS {
        let mut fake = target();
        fake.pkgdb.scriptlet = FakeScriptlet::FailsAfterRemovalRepeatingRefusals;
        let r = run(
            &one("sa3-repeating", "leafpkg"),
            true,
            fake.with_package("leafpkg"),
        );
        let p = find(&r, "p");
        let why = reason(&r, "p");
        // dpkg printed `Removing leafpkg` and the package is gone: a change.
        assert_eq!(p.change, Change::Changed, "{why}");
        assert_eq!(p.execution, Execution::Failed, "{why}");
        assert!(!why.contains("already gone"), "{why}");
        assert!(why.contains("after the package was removed"), "{why}");
        assert_eq!(removing(&r).len(), 1);
    }
}

#[test]
fn script_words_and_another_package_that_went_with_it_are_both_reported() {
    let mut fake = FakeTarget::ubuntu2404();
    fake.pkgdb.scriptlet = FakeScriptlet::FailsAfterRemovalRepeatingRefusals;
    fake.pkgdb.extra_removed = vec!["innocent".to_string()];
    let r = run(
        &one("sa3-repeating-extra", "leafpkg"),
        true,
        fake.with_package("leafpkg").with_package("innocent"),
    );
    let p = find(&r, "p");
    assert_eq!(p.change, Change::Changed);
    assert_eq!(p.execution, Execution::Failed);
    assert_eq!(p.verification, Verification::Failed);
    assert!(reason(&r, "p").contains("innocent"), "{}", reason(&r, "p"));
}

#[test]
fn a_refusal_that_dpkg_reported_before_another_process_removed_the_package_is_no_change() {
    for target in APT_TARGETS {
        let mut fake = target();
        fake.pkgdb.scriptlet = FakeScriptlet::RefusedThenRemovedByOther;
        let r = run(
            &one("sa3-refused-then-gone", "leafpkg"),
            true,
            fake.with_package("leafpkg"),
        );
        let p = find(&r, "p");
        let why = reason(&r, "p");
        assert_eq!(p.change, Change::None, "{why}");
        assert_eq!(p.execution, Execution::Failed, "{why}");
        assert_eq!(p.verification, Verification::Verified, "{why}");
        assert!(why.contains("already gone"), "{why}");
    }
}

#[test]
fn a_package_that_went_with_the_other_process_is_still_found_after_a_refusal() {
    // The post-removal inventory check also runs when dpkg refused first.
    let mut fake = FakeTarget::ubuntu2404();
    fake.pkgdb.scriptlet = FakeScriptlet::RefusedThenRemovedByOther;
    fake.pkgdb.extra_removed = vec!["innocent".to_string()];
    let r = run(
        &one("sa3-refused-gone-extra", "leafpkg"),
        true,
        fake.with_package("leafpkg").with_package("innocent"),
    );
    let p = find(&r, "p");
    let why = reason(&r, "p");
    assert_eq!(p.change, Change::None, "{why}");
    assert_eq!(p.execution, Execution::Failed, "{why}");
    assert_eq!(p.verification, Verification::Failed, "{why}");
    assert!(
        why.contains("already gone") && why.contains("innocent"),
        "{why}"
    );

    // A dependency problem that appeared meanwhile is reported too.
    let mut fake = FakeTarget::ubuntu2404().with_package("leafpkg");
    fake.pkgdb.scriptlet = FakeScriptlet::RefusedThenRemovedByOther;
    let clean =
        "Reading package lists...\nBuilding dependency tree...\nReading state information...\n";
    fake.pkgdb.force("apt-check", output(0, clean, ""));
    fake.pkgdb.force(
        "apt-check",
        output(
            100,
            &format!("{clean}The following packages have unmet dependencies:\n app : Depends: gone but it is not installed\n"),
            "E: Unmet dependencies.\n",
        ),
    );
    let r = run(&one("sa3-refused-gone-check", "leafpkg"), true, fake);
    let p = find(&r, "p");
    assert_eq!(p.change, Change::None);
    assert_ne!(
        p.verification,
        Verification::Verified,
        "{}",
        reason(&r, "p")
    );
}

#[test]
fn a_failure_that_does_not_show_how_far_dpkg_got_is_a_possible_change_never_no_change() {
    for target in APT_TARGETS {
        let mut fake = target();
        fake.pkgdb.scriptlet = FakeScriptlet::GoneThenUnexplainedFailure;
        let r = run(
            &one("sa3-unexplained", "leafpkg"),
            true,
            fake.with_package("leafpkg"),
        );
        let p = find(&r, "p");
        let why = reason(&r, "p");
        assert_eq!(p.change, Change::Possible, "{why}");
        assert_eq!(p.execution, Execution::Failed, "{why}");
        assert!(!why.contains("already gone"), "{why}");
        assert!(why.contains("nothing shows whether"), "{why}");
        // JSON and text agree.
        let v = json_of(&r);
        assert_eq!(v["resources"][0]["change"], "possible");
        assert_eq!(v["resources"][0]["execution"], "failed");
        assert!(text_of(&r).contains("possible"), "{}", text_of(&r));
    }
    // And another package that disappeared is still found.
    let mut fake = FakeTarget::ubuntu2404();
    fake.pkgdb.scriptlet = FakeScriptlet::GoneThenUnexplainedFailure;
    fake.pkgdb.extra_removed = vec!["innocent".to_string()];
    let r = run(
        &one("sa3-unexplained-extra", "leafpkg"),
        true,
        fake.with_package("leafpkg").with_package("innocent"),
    );
    let p = find(&r, "p");
    assert_eq!(p.change, Change::Possible);
    assert_eq!(p.verification, Verification::Failed);
    assert!(reason(&r, "p").contains("innocent"), "{}", reason(&r, "p"));
}

#[test]
fn a_package_that_is_still_installed_after_a_started_removal_is_a_possible_change() {
    // dpkg started (Removing ...), a script printed refusal-looking lines and
    // the package is still installed: scripts may have run.
    let listing = "(Reading database ... 1 files and directories currently installed.)\n\
                   Removing leafpkg (1.0-1) ...\n";
    let spoof = "dpkg: dependency problems prevent removal of leafpkg:\n\
                 dpkg: error: dpkg frontend lock was locked by another process with pid 7\n";
    let mut fake = FakeTarget::ubuntu2404().with_package("leafpkg");
    fake.pkgdb.force("dpkg-remove", output(1, listing, spoof));
    let r = run(&one("sa3-installed-started", "leafpkg"), true, fake);
    let p = find(&r, "p");
    let why = reason(&r, "p");
    assert_eq!(p.change, Change::Possible, "{why}");
    assert_eq!(p.execution, Execution::Failed, "{why}");
    assert_eq!(p.verification, Verification::Failed, "{why}");
    assert!(why.contains("still installed"), "{why}");

    // The same lines without the Removing line are a refusal: nothing changed.
    let mut fake = FakeTarget::ubuntu2404().with_package("leafpkg");
    fake.pkgdb.force(
        "dpkg-remove",
        output(
            1,
            "(Reading database ... 1 files and directories currently installed.)\n",
            "dpkg: error: dpkg frontend lock was locked by another process with pid 7\n",
        ),
    );
    let r = run(&one("sa3-installed-refused", "leafpkg"), true, fake);
    let p = find(&r, "p");
    assert_eq!(p.change, Change::None, "{}", reason(&r, "p"));
    assert_eq!(p.execution, Execution::Failed);
    assert_eq!(p.verification, Verification::NotPerformed);

    // Script chatter alone, without dpkg's own line, is not a refusal.
    let mut fake = FakeTarget::ubuntu2404().with_package("leafpkg");
    fake.pkgdb.force(
        "dpkg-remove",
        output(
            1,
            "",
            "postrm: dependency problems prevent removal of leafpkg: ignored\n",
        ),
    );
    let r = run(&one("sa3-installed-chatter", "leafpkg"), true, fake);
    let p = find(&r, "p");
    assert_eq!(p.change, Change::Possible, "{}", reason(&r, "p"));
    assert_eq!(p.verification, Verification::Failed);
}

#[test]
fn real_refusals_of_the_scripted_dpkg_stay_no_change() {
    // Dependency problem, lock held, no privilege: dpkg refuses before it starts.
    let mut dep = FakeTarget::ubuntu2404()
        .with_package("libpkg")
        .with_package("apppkg");
    dep.pkgdb.add_requires("apppkg", "libpkg");
    dep.pkgdb.concurrent = None;
    let mut lock = FakeTarget::ubuntu2404().with_package("leafpkg");
    lock.pkgdb.lock_busy = true;
    for (label, fake, name) in [("dep", dep, "libpkg"), ("lock", lock, "leafpkg")] {
        let r = run(&one(&format!("sa3-real-{label}"), name), true, fake);
        let p = find(&r, "p");
        assert_eq!(p.change, Change::None, "{label}: {}", reason(&r, "p"));
        assert_eq!(p.execution, Execution::Failed, "{label}");
    }
}

#[test]
fn the_dnf4_classification_is_unchanged_by_the_apt_stage_rules() {
    for fake in [FakeTarget::rocky9(), FakeTarget::rocky10()] {
        let mut fake = fake.with_package("leafpkg");
        fake.pkgdb.scriptlet = FakeScriptlet::FailsAfterRemovalRepeatingRefusals;
        let r = run(&one("sa3-dnf-unchanged", "leafpkg"), true, fake);
        let p = find(&r, "p");
        assert_eq!(p.change, Change::Changed, "{}", reason(&r, "p"));
        assert_eq!(p.execution, Execution::Failed);
        assert!(!reason(&r, "p").contains("nothing shows whether"));
    }
}

#[test]
fn a_started_and_a_proven_refusal_reasons_hide_sensitive_names_in_json_and_text() {
    for scriptlet in [
        FakeScriptlet::FailsAfterRemovalRepeatingRefusals,
        FakeScriptlet::RefusedThenRemovedByOther,
        FakeScriptlet::GoneThenUnexplainedFailure,
    ] {
        let mut fake = FakeTarget::ubuntu2404();
        fake.pkgdb.scriptlet = scriptlet;
        fake.pkgdb.extra_removed = vec!["innocentsecret".to_string()];
        let path = recipe(
            &format!("sa3-sensitive-{scriptlet:?}"),
            &[("p", "leafsecret", "absent")],
            true,
        );
        let r = run(
            &path,
            true,
            fake.with_package("leafsecret")
                .with_package("innocentsecret"),
        );
        let json = json_of(&r).to_string();
        let text = text_of(&r);
        for shown in [json, text] {
            assert!(
                !shown.contains("leafsecret") && !shown.contains("innocentsecret"),
                "{scriptlet:?}: {shown}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Multi-Arch: another architecture's leftover must not make a package unusable
// ---------------------------------------------------------------------------

fn multiarch(arch: &str, status: &str) -> sinter::fakepkg::FakePkg {
    sinter::fakepkg::FakePkg {
        other_instances: vec![(arch.to_string(), status.to_string())],
        ..Default::default()
    }
}

fn instance_queries(r: &sinter::engine::RunReport) -> usize {
    r.commands
        .iter()
        .filter(|c| {
            c.program.ends_with("dpkg-query")
                && c.args.iter().any(|a| a.contains("${Architecture}\\n"))
                && c.args.len() == 4
        })
        .count()
}

#[test]
fn removing_an_installed_package_whose_other_architecture_is_config_files_succeeds() {
    for target in APT_TARGETS {
        let mut fake = target();
        fake.pkgdb.meta.insert(
            "leafpkg".to_string(),
            multiarch("i386", "deinstall ok config-files"),
        );
        let fake = fake.with_package("leafpkg").with_package("otherpkg");
        let r = run(&one("ma-remove-config", "leafpkg"), true, fake);
        let p = find(&r, "p");
        let why = reason(&r, "p");
        assert_success(&r);
        assert_eq!(p.change, Change::Changed, "{why}");
        assert_eq!(p.execution, Execution::Succeeded, "{why}");
        assert_eq!(p.verification, Verification::Verified, "{why}");
        assert_eq!(removing(&r).len(), 1);
        assert_eq!(removing(&r)[0].args.last().unwrap(), "leafpkg");
        assert_exact_only("ma", &r);
        assert!(
            instance_queries(&r) >= 1,
            "the instances were read one by one"
        );
    }
}

#[test]
fn a_not_installed_or_purged_other_architecture_does_not_matter_either() {
    for status in [
        "purge ok not-installed",
        "unknown ok not-installed",
        "deinstall ok not-installed",
        "purge ok config-files",
    ] {
        let mut fake = FakeTarget::ubuntu2404();
        fake.pkgdb
            .meta
            .insert("leafpkg".to_string(), multiarch("i386", status));
        let r = run(
            &one(
                &format!("ma-remove-{}", status.replace(' ', "-")),
                "leafpkg",
            ),
            true,
            fake.with_package("leafpkg"),
        );
        let p = find(&r, "p");
        assert_eq!(p.change, Change::Changed, "{status}: {}", reason(&r, "p"));
        assert_eq!(p.verification, Verification::Verified, "{status}");
    }
}

#[test]
fn state_present_is_already_met_when_only_another_architecture_is_config_files() {
    let mut fake = FakeTarget::ubuntu2404();
    fake.pkgdb.meta.insert(
        "leafpkg".to_string(),
        multiarch("i386", "deinstall ok config-files"),
    );
    let path = recipe("ma-present", &[("p", "leafpkg", "present")], false);
    let r = run(&path, true, fake.with_package("leafpkg"));
    let p = find(&r, "p");
    assert_eq!(p.change, Change::None, "{}", reason(&r, "p"));
    assert_eq!(p.execution, Execution::Succeeded);
    assert!(
        !r.commands
            .iter()
            .any(|c| c.program.ends_with("apt-get") && c.args.iter().any(|a| a == "install")),
        "nothing was installed"
    );
}

#[test]
fn state_absent_is_already_met_when_only_another_architecture_is_config_files() {
    let mut fake = FakeTarget::ubuntu2404();
    fake.pkgdb.meta.insert(
        "leafpkg".to_string(),
        multiarch("i386", "deinstall ok config-files"),
    );
    // `leafpkg` itself is not installed: only the i386 leftover exists.
    let r = run(
        &one("ma-absent-met", "leafpkg"),
        true,
        fake.with_package("otherpkg"),
    );
    let p = find(&r, "p");
    assert_eq!(p.change, Change::None, "{}", reason(&r, "p"));
    assert_eq!(p.execution, Execution::Succeeded);
    assert!(removing(&r).is_empty());
}

#[test]
fn two_installed_architectures_stay_ambiguous_and_nothing_is_removed() {
    for (label, state) in [("absent", "absent"), ("present", "present")] {
        let mut fake = FakeTarget::ubuntu2404();
        fake.pkgdb.meta.insert(
            "leafpkg".to_string(),
            multiarch("i386", "install ok installed"),
        );
        let path = recipe(
            &format!("ma-ambiguous-{label}"),
            &[("p", "leafpkg", state)],
            false,
        );
        let r = run(&path, true, fake.with_package("leafpkg"));
        let p = find(&r, "p");
        let why = reason(&r, "p");
        assert_eq!(p.execution, Execution::Failed, "{label}: {why}");
        assert_eq!(p.change, Change::None, "{label}: {why}");
        assert!(
            why.contains("more than one installed instance"),
            "{label}: {why}"
        );
        assert!(removing(&r).is_empty(), "{label}");
    }
}

#[test]
fn another_architecture_in_a_broken_state_is_refused_not_ignored() {
    for status in [
        "deinstall ok installed",
        "install ok half-configured",
        "install ok unpacked",
        "install reinstreq installed",
        "deinstall ok half-installed",
    ] {
        let mut fake = FakeTarget::ubuntu2404();
        fake.pkgdb
            .meta
            .insert("leafpkg".to_string(), multiarch("i386", status));
        let r = run(
            &one(
                &format!("ma-broken-{}", status.replace(' ', "-")),
                "leafpkg",
            ),
            true,
            fake.with_package("leafpkg"),
        );
        let p = find(&r, "p");
        assert_eq!(
            p.execution,
            Execution::Failed,
            "{status}: {}",
            reason(&r, "p")
        );
        assert_eq!(p.change, Change::None, "{status}");
        assert!(removing(&r).is_empty(), "{status}");
    }
}

#[test]
fn an_instance_answer_that_cannot_be_read_or_that_changed_fails_closed() {
    let concatenated = "install ok installeddeinstall ok config-files";
    let cases: Vec<(&str, Output)> = vec![
        ("empty", output(0, "", "")),
        ("garbage", output(0, "not a record\n", "")),
        (
            "no-newline",
            output(0, "install ok installed\tleafpkg\tamd64", ""),
        ),
        (
            "other-package",
            output(0, "install ok installed\tintruder\tamd64\n", ""),
        ),
        (
            "two-installed",
            output(
                0,
                "install ok installed\tleafpkg\tamd64\ninstall ok installed\tleafpkg\ti386\n",
                "",
            ),
        ),
        (
            "run-together",
            output(0, &format!("{concatenated}\tleafpkg\tamd64\n"), ""),
        ),
        (
            "failed",
            output(2, "", "dpkg-query: error: cannot open status\n"),
        ),
        (
            "noisy",
            output(0, "install ok installed\tleafpkg\tamd64\n", "warning\n"),
        ),
        (
            "gone",
            output(1, "", "dpkg-query: no packages found matching leafpkg\n"),
        ),
    ];
    for (label, answer) in cases {
        let mut fake = FakeTarget::ubuntu2404();
        fake.pkgdb.meta.insert(
            "leafpkg".to_string(),
            multiarch("i386", "deinstall ok config-files"),
        );
        fake.pkgdb.force("dpkg-instances", answer);
        let r = run(
            &one(&format!("ma-instances-bad-{label}"), "leafpkg"),
            true,
            fake.with_package("leafpkg"),
        );
        let p = find(&r, "p");
        assert_eq!(
            p.execution,
            Execution::Failed,
            "{label}: {}",
            reason(&r, "p")
        );
        assert_eq!(p.change, Change::None, "{label}");
        assert!(removing(&r).is_empty(), "{label}");
    }
}

#[test]
fn the_run_together_answer_alone_is_still_refused_when_it_is_not_two_statuses() {
    // A single non-clean status is not the several-instance symptom: no second
    // query is made and it is refused as before.
    let mut fake = FakeTarget::ubuntu2404();
    fake.pkgdb.dpkg_status.insert(
        "leafpkg".to_string(),
        "install ok half-configured".to_string(),
    );
    let r = run(
        &one("ma-single-broken", "leafpkg"),
        true,
        fake.with_package("leafpkg"),
    );
    let p = find(&r, "p");
    assert_eq!(p.execution, Execution::Failed);
    assert_eq!(p.change, Change::None);
    assert!(reason(&r, "p").contains("non-clean"), "{}", reason(&r, "p"));
    assert_eq!(instance_queries(&r), 0);
    assert!(removing(&r).is_empty());
}

#[test]
fn an_ordinary_package_never_triggers_the_per_instance_query() {
    for (label, _, fake) in targets() {
        let r = run(
            &one(&format!("ma-ordinary-{label}"), "leafpkg"),
            true,
            fake.with_package("leafpkg"),
        );
        assert_eq!(find(&r, "p").change, Change::Changed, "{label}");
        assert_eq!(instance_queries(&r), 0, "{label}");
    }
}

#[test]
fn a_package_that_vanishes_with_the_target_is_still_found_next_to_another_architecture() {
    let mut fake = FakeTarget::ubuntu2404();
    fake.pkgdb.meta.insert(
        "leafpkg".to_string(),
        multiarch("i386", "deinstall ok config-files"),
    );
    fake.pkgdb.extra_removed = vec!["innocent".to_string()];
    let r = run(
        &one("ma-extra", "leafpkg"),
        true,
        fake.with_package("leafpkg").with_package("innocent"),
    );
    let p = find(&r, "p");
    assert_eq!(p.change, Change::Changed);
    assert_eq!(p.verification, Verification::Failed);
    assert!(reason(&r, "p").contains("innocent"), "{}", reason(&r, "p"));
}

#[test]
fn the_name_stays_hidden_when_a_sensitive_package_has_two_installed_architectures() {
    let mut fake = FakeTarget::ubuntu2404();
    fake.pkgdb.meta.insert(
        "leafsecret".to_string(),
        multiarch("i386", "install ok installed"),
    );
    let path = recipe("ma-sensitive", &[("p", "leafsecret", "absent")], true);
    let r = run(&path, true, fake.with_package("leafsecret"));
    assert_eq!(find(&r, "p").execution, Execution::Failed);
    assert!(!json_of(&r).to_string().contains("leafsecret"));
    assert!(!text_of(&r).contains("leafsecret"));
}

#[test]
fn rocky_targets_never_run_a_dpkg_query() {
    for fake in [FakeTarget::rocky9(), FakeTarget::rocky10()] {
        let r = run(
            &one("ma-rocky", "leafpkg"),
            true,
            fake.with_package("leafpkg"),
        );
        assert_eq!(find(&r, "p").change, Change::Changed);
        assert!(!r.commands.iter().any(|c| c.program.ends_with("dpkg-query")));
    }
}

#[test]
fn an_rpm_answer_that_looks_like_run_together_dpkg_statuses_is_refused_without_a_dpkg_query() {
    for fake in [FakeTarget::rocky9(), FakeTarget::rocky10()] {
        let fake = fake.with_package("leafpkg").with_query_results(vec![output(
            0,
            "install ok installeddeinstall ok config-files",
            "",
        )]);
        let r = run(&one("ma-rpm-lookalike", "leafpkg"), true, fake);
        let p = find(&r, "p");
        assert_eq!(p.execution, Execution::Failed, "{}", reason(&r, "p"));
        assert_eq!(p.change, Change::None);
        assert!(removing(&r).is_empty());
        assert!(!r.commands.iter().any(|c| c.program.ends_with("dpkg-query")));
    }
}

#[test]
fn a_refusal_naming_the_package_with_its_architecture_must_name_the_architecture_that_is_installed()
{
    let listing = "(Reading database ... 1 files and directories currently installed.)\n";
    for (installed_arch, subject, expected) in [
        ("amd64", "leafpkg:amd64", Change::None),
        ("arm64", "leafpkg:arm64", Change::None),
        ("arm64", "leafpkg:amd64", Change::Possible),
        ("amd64", "leafpkg:i386", Change::Possible),
    ] {
        let mut fake = FakeTarget::ubuntu2404().with_package("leafpkg");
        fake.pkgdb.meta.insert(
            "leafpkg".to_string(),
            sinter::fakepkg::FakePkg {
                arch: Some(installed_arch.to_string()),
                ..Default::default()
            },
        );
        fake.pkgdb.force(
            "dpkg-remove",
            output(
                1,
                listing,
                &format!("dpkg: dependency problems prevent removal of {subject}:\n"),
            ),
        );
        let r = run(
            &one(&format!("sa3-arch-{installed_arch}-{subject}"), "leafpkg"),
            true,
            fake,
        );
        assert_eq!(
            find(&r, "p").change,
            expected,
            "{installed_arch} {subject}: {}",
            reason(&r, "p")
        );
    }
}

/// SA-4 (recorded, not fixed): on DNF4 a removal that rpm refused because the
/// package was already gone does not run the post-removal inventory check,
/// unlike APT. This pins the current DNF4 behaviour so that a change is deliberate.
#[test]
fn dnf4_already_gone_branch_is_unchanged_and_still_skips_the_inventory_check() {
    for fake in [FakeTarget::rocky9(), FakeTarget::rocky10()] {
        let mut fake = fake.with_package("leafpkg").with_package("innocent");
        fake.pkgdb.scriptlet = FakeScriptlet::RemovedByOther;
        fake.pkgdb.extra_removed = vec!["innocent".to_string()];
        let r = run(&one("sa4-dnf-gone", "leafpkg"), true, fake);
        let p = find(&r, "p");
        assert_eq!(p.change, Change::None, "{}", reason(&r, "p"));
        assert_eq!(p.execution, Execution::Failed);
        assert_eq!(p.verification, Verification::Verified);
        assert!(reason(&r, "p").contains("already gone"));
    }
}
