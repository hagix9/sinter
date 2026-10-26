use super::rpm::Protection;
use super::*;

fn out(code: i32, stdout: &str, stderr: &str) -> Output {
    Output {
        completion: Completion::Exited(code),
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

fn apt_record(
    status: &str,
    name: &str,
    arch: &str,
    version: &str,
    ess: &str,
    prot: &str,
) -> String {
    format!("{status}\t{name}\t{arch}\t{version}\t{ess}\t{prot}\n")
}

fn rpm_identity(name: &str) -> ExactIdentity {
    ExactIdentity {
        name: name.to_string(),
        arch: "x86_64".to_string(),
        version: "1.0".to_string(),
        release: Some("1.el9".to_string()),
        epoch: Some("0".to_string()),
    }
}

// --------------------------------------------------------------- names

#[test]
fn apt_names_follow_debian_policy() {
    for ok in ["tree", "libc6", "g++", "python3.12", "lib-foo+bar", "a1"] {
        assert!(valid_apt_name(ok), "{ok}");
    }
    for bad in [
        "", "a", "Tree", "-rf", "+x", ".x", "foo*", "foo?", "foo[1]", "foo bar", "a/b", "a:b",
        "foo_bar", "a~b", "foo\n", "föö",
    ] {
        assert!(!valid_apt_name(bad), "{bad:?}");
    }
    assert!(!valid_apt_name(&"a".repeat(MAX_NAME + 1)));
}

#[test]
fn rpm_names_cannot_be_options_or_patterns() {
    for ok in ["tree", "python3.12", "g++", "foo_bar", "Foo-bar", "1pkg"] {
        assert!(valid_rpm_name(ok), "{ok}");
    }
    for bad in [
        "", "-e", "--nodeps", "foo*", "foo?", "foo[1]", "foo bar", "a/b", "a~b", "a^b", "a:b",
        "foo\n", "_x", ".x",
    ] {
        assert!(!valid_rpm_name(bad), "{bad:?}");
    }
}

#[test]
fn version_and_architecture_tokens_are_closed_sets() {
    assert!(
        valid_arch("x86_64") && valid_arch("amd64") && valid_arch("noarch") && valid_arch("all")
    );
    assert!(
        !valid_arch("(none)") && !valid_arch("") && !valid_arch("x86 64") && !valid_arch("a/b")
    );
    assert!(valid_apt_version("1:2.3.4+dfsg-1ubuntu1~22.04.1"));
    assert!(!valid_apt_version("1 2") && !valid_apt_version(""));
    assert!(valid_rpm_evr_part("1.el9_4") && valid_rpm_evr_part("2.0^git1"));
    assert!(!valid_rpm_evr_part("1-2") && !valid_rpm_evr_part(""));
}

// ---------------------------------------------------------- identities

#[test]
fn apt_identity_accepts_one_clean_record() {
    let rec = apt_record("install ok installed", "tree", "amd64", "2.1.1-2", "", "");
    let id = AptExact::parse_identity(&out(0, &rec, ""), "tree").unwrap();
    assert_eq!(id.name, "tree");
    assert_eq!(id.arch, "amd64");
    assert_eq!(id.version, "2.1.1-2");
    assert!(id.release.is_none() && id.epoch.is_none());
    assert!(id.rpm_operand().is_none());
    let rec = apt_record(
        "install ok installed",
        "tree",
        "amd64",
        "2.1.1-2",
        "no",
        "no",
    );
    assert!(AptExact::parse_identity(&out(0, &rec, ""), "tree").is_ok());
}

#[test]
fn apt_identity_ignores_instances_that_are_not_installed() {
    let ours = apt_record("install ok installed", "tree", "amd64", "1.0", "", "");
    let leftover = apt_record("deinstall ok config-files", "tree", "i386", "1.0", "", "");
    let never = apt_record("unknown ok not-installed", "tree", "arm64", "", "", "");
    let id =
        AptExact::parse_identity(&out(0, &format!("{leftover}{ours}{never}"), ""), "tree").unwrap();
    assert_eq!(id.arch, "amd64");
    // Only not-installed instances: nothing to remove.
    assert!(AptExact::parse_identity(&out(0, &format!("{leftover}{never}"), ""), "tree").is_err());
    // Two installed instances stay ambiguous.
    let second = apt_record("install ok installed", "tree", "i386", "1.0", "", "");
    assert_eq!(
        AptExact::parse_identity(&out(0, &format!("{ours}{second}"), ""), "tree"),
        Err(Refusal::Ambiguous)
    );
}

#[test]
fn apt_identity_refuses_everything_that_is_not_one_clean_record() {
    let ok = apt_record("install ok installed", "tree", "amd64", "1.0", "", "");
    let two = format!("{ok}{ok}");
    assert_eq!(
        AptExact::parse_identity(&out(0, &two, ""), "tree"),
        Err(Refusal::Ambiguous)
    );
    let cases: Vec<(String, Refusal)> = vec![
        (
            String::new(),
            Refusal::Unestablished("the package identity"),
        ),
        (
            "install ok installed\ttree\tamd64\t1.0\t\t".to_string(),
            Refusal::Unestablished("the package identity"),
        ),
        (
            ok.replace('\n', "\r\n"),
            Refusal::Unestablished("the package identity"),
        ),
        (
            apt_record("install ok installed", "other", "amd64", "1.0", "", ""),
            Refusal::Unestablished("the package identity"),
        ),
        (
            apt_record("install ok installed", "tree", "amd64", "1.0", "maybe", ""),
            Refusal::Unestablished("the package identity"),
        ),
        (
            apt_record("install ok installed", "tree", "am d64", "1.0", "", ""),
            Refusal::Unestablished("the package identity"),
        ),
        (
            // Not installed at all: nothing to remove.
            apt_record("deinstall ok config-files", "tree", "amd64", "1.0", "", ""),
            Refusal::Unestablished("the package identity"),
        ),
        (
            apt_record("install ok half-configured", "tree", "amd64", "1.0", "", ""),
            Refusal::NotClean,
        ),
        (
            apt_record("install ok installed", "tree", "amd64", "1.0", "yes", ""),
            Refusal::SystemProtected("essential"),
        ),
        (
            apt_record("install ok installed", "tree", "amd64", "1.0", "", "yes"),
            Refusal::SystemProtected("protected"),
        ),
    ];
    for (text, want) in cases {
        assert_eq!(
            AptExact::parse_identity(&out(0, &text, ""), "tree"),
            Err(want.clone()),
            "{text:?}"
        );
    }
    // Exit status, stderr and truncation each spoil an otherwise valid record.
    assert!(AptExact::parse_identity(&out(1, &ok, ""), "tree").is_err());
    assert!(AptExact::parse_identity(&out(0, &ok, "warning\n"), "tree").is_err());
    let mut truncated = out(0, &ok, "");
    truncated.stdout_truncated = true;
    assert!(AptExact::parse_identity(&truncated, "tree").is_err());
    let mut signaled = out(0, &ok, "");
    signaled.completion = Completion::Signaled(9);
    assert!(AptExact::parse_identity(&signaled, "tree").is_err());
}

#[test]
fn rpm_identity_builds_the_nevra_operand() {
    let id =
        RpmExact::parse_identity(&out(0, "tree\t0\t1.8.0\t10.el9\tx86_64\n", ""), "tree").unwrap();
    assert_eq!(id.rpm_operand().unwrap(), "tree-1.8.0-10.el9.x86_64");
    assert_eq!(id.epoch.as_deref(), Some("0"));
    let id = RpmExact::parse_identity(
        &out(0, "gcc-c++\t2\t11.4.1\t2.el9\tnoarch\n", ""),
        "gcc-c++",
    )
    .unwrap();
    assert_eq!(id.rpm_operand().unwrap(), "gcc-c++-11.4.1-2.el9.noarch");
}

#[test]
fn rpm_identity_refuses_everything_that_is_not_one_record() {
    let ok = "tree\t0\t1.8.0\t10.el9\tx86_64\n";
    assert_eq!(
        RpmExact::parse_identity(&out(0, &format!("{ok}{ok}"), ""), "tree"),
        Err(Refusal::Ambiguous)
    );
    assert_eq!(
        RpmExact::parse_identity(&out(1, "package tree is not installed\n", ""), "tree"),
        Err(Refusal::Changed("the installed package"))
    );
    for bad in [
        "",
        "tree\t0\t1.8.0\t10.el9\tx86_64",
        "tree\t0\t1.8.0\t10.el9\n",
        "tree\tx\t1.8.0\t10.el9\tx86_64\n",
        "tree\t\t1.8.0\t10.el9\tx86_64\n",
        "tree\t0\t1.8-0\t10.el9\tx86_64\n",
        "tree\t0\t1.8.0\t10.el9\t(none)\n",
        "other\t0\t1.8.0\t10.el9\tx86_64\n",
        "tree\t0\t1.8.0\t10.el9\tx86_64\r\n",
    ] {
        assert!(
            RpmExact::parse_identity(&out(0, bad, ""), "tree").is_err(),
            "{bad:?}"
        );
    }
    assert!(RpmExact::parse_identity(&out(0, ok, "warning: x\n"), "tree").is_err());
    assert!(RpmExact::parse_identity(&out(2, "", "rpmdb damaged\n"), "tree").is_err());
}

#[test]
fn the_identity_debug_form_hides_the_name() {
    let text = format!("{:?}", rpm_identity("secretname"));
    assert!(!text.contains("secretname"), "{text}");
}

// ------------------------------------------------------ dry-run results

#[test]
fn dpkg_dry_run_outcomes() {
    let clean = out(
        0,
        "(Reading database ... 41234 files and directories currently installed.)\n\
         Would remove or purge tree (version 2.1.1-2) ...\n",
        "",
    );
    assert_eq!(AptExact::classify_dry_run(&clean, "tree"), DryRun::Clean);
    let removing = out(0, "Removing tree (2.1.1-2) ...\n", "");
    assert_eq!(AptExact::classify_dry_run(&removing, "tree"), DryRun::Clean);
    let other_planned = out(0, "Would remove or purge other (version 1) ...\n", "");
    assert!(matches!(
        AptExact::classify_dry_run(&other_planned, "tree"),
        DryRun::Refused(Refusal::DryRunFailed(_))
    ));
    // dpkg told to ignore dependency problems prints a notice and exits 0.
    let forced = out(
        0,
        "Would remove or purge tree (version 1) ...\n",
        "dpkg: dependency problems, but removing anyway as you requested:\n x depends on tree.\n",
    );
    assert!(matches!(
        AptExact::classify_dry_run(&forced, "tree"),
        DryRun::Refused(_)
    ));
    let multiarch = out(0, "Removing tree:amd64 (2.1.1-2) ...\n", "");
    assert_eq!(
        AptExact::classify_dry_run(&multiarch, "tree"),
        DryRun::Clean
    );

    let revdeps = out(
        1,
        "",
        "dpkg: dependency problems prevent removal of libfoo:amd64:\n \
         bar depends on libfoo (>= 1).\n \
         baz:amd64 pre-depends on libfoo.\n\
         \n\
         dpkg: error processing package libfoo:amd64 (--remove):\n \
         dependency problems - not removing\n\
         Errors were encountered while processing:\n libfoo:amd64\n",
    );
    assert_eq!(
        AptExact::classify_dry_run(&revdeps, "libfoo"),
        DryRun::Refused(Refusal::ReverseDependencies(vec![
            "bar".to_string(),
            "baz".to_string()
        ]))
    );
    let essential = out(
        1,
        "",
        "dpkg: error processing package bash (--remove):\n this is an essential package - it \
         should not be removed\n",
    );
    assert_eq!(
        AptExact::classify_dry_run(&essential, "bash"),
        DryRun::Refused(Refusal::SystemProtected("essential"))
    );
    let lock = out(
        2,
        "",
        "dpkg: error: dpkg frontend lock was locked by another process with pid 99\n",
    );
    assert_eq!(
        AptExact::classify_dry_run(&lock, "tree"),
        DryRun::Refused(Refusal::LockBusy)
    );
    let root = out(
        2,
        "",
        "dpkg: error: requested operation requires superuser privilege\n",
    );
    assert_eq!(
        AptExact::classify_dry_run(&root, "tree"),
        DryRun::Refused(Refusal::Privilege)
    );
    // exit 0 with a warning is not a clean plan.
    let absent = out(
        0,
        "",
        "dpkg: warning: ignoring request to remove tree which isn't installed\n",
    );
    assert_eq!(
        AptExact::classify_dry_run(&absent, "tree"),
        DryRun::Refused(Refusal::Changed("the installed package"))
    );
    // A plan that names another package is not an exact-target plan.
    let other = out(0, "Removing tree (1) ...\nRemoving other (2) ...\n", "");
    assert!(matches!(
        AptExact::classify_dry_run(&other, "tree"),
        DryRun::Refused(Refusal::DryRunFailed(_))
    ));
    let mut cut = out(0, "Removing tree (1) ...\n", "");
    cut.stdout_truncated = true;
    assert!(matches!(
        AptExact::classify_dry_run(&cut, "tree"),
        DryRun::Refused(_)
    ));
    assert!(matches!(
        AptExact::classify_dry_run(&out(7, "", "who knows\n"), "tree"),
        DryRun::Refused(Refusal::DryRunFailed(_))
    ));
}

#[test]
fn rpm_test_outcomes() {
    assert_eq!(RpmExact::classify_dry_run(&out(0, "", "")), DryRun::Clean);
    let revdeps = out(
        1,
        "",
        "error: Failed dependencies:\n\
         \tlibfoo.so.1()(64bit) is needed by (installed) bar-1.0-1.el9.x86_64\n\
         \tlibfoo = 1.0 is needed by (installed) baz-2.0-3.el9.noarch\n",
    );
    assert_eq!(
        RpmExact::classify_dry_run(&revdeps),
        DryRun::Refused(Refusal::ReverseDependencies(vec![
            "bar-1.0-1.el9.x86_64".to_string(),
            "baz-2.0-3.el9.noarch".to_string()
        ]))
    );
    // Text that is not a plain NEVRA is never quoted back.
    assert_eq!(
        RpmExact::classify_dry_run(&out(
            1,
            "",
            "error: Failed dependencies:\n\tx is needed by (installed) bad\u{1b}[31mname-1-1.noarch\n"
        )),
        DryRun::Refused(Refusal::ReverseDependencies(vec![]))
    );
    assert_eq!(
        RpmExact::classify_dry_run(&out(1, "", "error: package tree is not installed\n")),
        DryRun::Refused(Refusal::Changed("the installed package"))
    );
    assert_eq!(
        RpmExact::classify_dry_run(&out(
            1,
            "",
            "error: can't create transaction lock on /var/lib/rpm/.rpm.lock (Resource temporarily unavailable)\n"
        )),
        DryRun::Refused(Refusal::LockBusy)
    );
    assert_eq!(
        RpmExact::classify_dry_run(&out(
            1,
            "",
            "error: can't create transaction lock on /var/lib/rpm/.rpm.lock (Permission denied)\n"
        )),
        DryRun::Refused(Refusal::Privilege)
    );
    // Any output on success is not a clean answer.
    assert!(matches!(
        RpmExact::classify_dry_run(&out(0, "", "warning: something\n")),
        DryRun::Refused(Refusal::DryRunFailed(_))
    ));
    assert!(matches!(
        RpmExact::classify_dry_run(&out(0, "x\n", "")),
        DryRun::Refused(_)
    ));
    let mut cut = out(0, "", "");
    cut.stderr_truncated = true;
    assert!(matches!(
        RpmExact::classify_dry_run(&cut),
        DryRun::Refused(_)
    ));
}

#[test]
fn failure_causes_separate_refusals_from_unknown_failures() {
    assert_eq!(
        AptExact::classify_failure(
            &out(1, "", "dpkg: dependency problems prevent removal of x:\n"),
            "x",
            "amd64"
        ),
        FailureCause::RefusedBeforeChange
    );
    assert_eq!(
        AptExact::classify_failure(
            &out(
                1,
                "",
                "installed x package pre-removal script subprocess returned error exit status 1\n"
            ),
            "x",
            "amd64"
        ),
        FailureCause::Unproven
    );
    assert_eq!(
        AptExact::classify_failure(
            &out(
                2,
                "",
                "dpkg: error: ambiguous package name 'x' with more than one installed instance\n"
            ),
            "x",
            "amd64"
        ),
        FailureCause::RefusedBeforeChange
    );
    assert_eq!(
        AptExact::classify_failure(
            &out(
                2,
                "",
                "dpkg: error: requested operation requires superuser privilege\n"
            ),
            "x",
            "amd64"
        ),
        FailureCause::RefusedBeforeChange
    );
    assert_eq!(
        RpmExact::classify_failure(&out(1, "", "error: Failed dependencies:\n")),
        FailureCause::RefusedBeforeChange
    );
    assert_eq!(
        RpmExact::classify_failure(&out(
            1,
            "",
            "error: %preun(x) scriptlet failed, exit status 1\n"
        )),
        FailureCause::Other
    );
}

// ------------------------------------------- SA-3: how far dpkg got

fn stage(stdout: &str, stderr: &str) -> FailureCause {
    AptExact::classify_failure(&out(1, stdout, stderr), "x", "amd64")
}

const READING: &str = "(Reading database ... 12345 files and directories currently installed.)\n";

#[test]
fn a_started_removal_is_never_a_refusal_whatever_the_scripts_print() {
    let refusals = [
        "dpkg: dependency problems prevent removal of x:\n",
        "dpkg: error: dpkg frontend lock was locked by another process with pid 42\n",
        "dpkg: error: requested operation requires superuser privilege\n",
        "dpkg: error: ambiguous package name 'x' with more than one installed instance\n",
        "dpkg: error processing package x (--remove):\n this is an essential package\n",
    ];
    for refusal in refusals {
        // Without the Removing line it is a refusal ...
        assert_eq!(
            stage(READING, refusal),
            FailureCause::RefusedBeforeChange,
            "{refusal}"
        );
        // ... with it, dpkg had started and scripts may have run.
        for removing in [
            "Removing x (1.0-1) ...\n",
            "Removing x:amd64 (1.0-1) ...\n",
            "  Removing x (1.0-1) ...\n",
            "REMOVING x (1.0-1) ...\n",
        ] {
            assert_eq!(
                stage(&format!("{READING}{removing}"), refusal),
                FailureCause::Started,
                "{removing:?} {refusal}"
            );
        }
        // Not even if the output is cut short after it.
        let mut cut = out(1, &format!("{READING}Removing x (1.0-1) ...\n"), refusal);
        cut.stderr_truncated = true;
        assert_eq!(
            AptExact::classify_failure(&cut, "x", "amd64"),
            FailureCause::Started
        );
    }
}

#[test]
fn words_in_the_output_prove_nothing_unless_dpkg_said_them_as_a_line() {
    // Script chatter that contains the old marker words.
    for noise in [
        "postrm: frontend lock check done\n",
        "postrm: another dependency problems prevent removal of x: note\n",
        "helper: locked by another process, retrying\n",
        "postrm: needs superuser privilege to continue\n",
        "postrm: ambiguous package name in config\n",
        "postrm: essential package list refreshed\n",
        "x: dpkg: error: dpkg frontend lock was locked by another process\n",
        " dpkg: dependency problems prevent removal of x:\n",
        "dpkg: error: requested operation requires superuser privilege and more\n",
        "dpkg: error: ambiguous package name 'x' with more than one installed instance, or not\n",
        "dpkg: dependency problems prevent removal of x: and more\n",
        "dpkg: dependency problems prevent removal of x:  \n",
    ] {
        assert_eq!(stage("", noise), FailureCause::Unproven, "{noise:?}");
    }
    // dpkg's wording, about a package this is not.
    assert_eq!(
        stage("", "dpkg: dependency problems prevent removal of xy:\n"),
        FailureCause::Unproven
    );
    assert_eq!(
        stage("", "dpkg: dependency problems prevent removal of x:i386:\n"),
        FailureCause::Unproven
    );
    assert_eq!(
        stage(
            "",
            "dpkg: error: ambiguous package name 'y' with more than one installed instance\n"
        ),
        FailureCause::Unproven
    );
    assert_eq!(
        stage(
            "",
            "dpkg: error processing package y (--remove):\n this is an essential package\n"
        ),
        FailureCause::Unproven
    );
    // The essential header without its explanation is not a refusal.
    assert_eq!(
        stage("", "dpkg: error processing package x (--remove):\n"),
        FailureCause::Unproven
    );
    assert_eq!(
        stage(
            "",
            "dpkg: error processing package x (--remove):\n installed x package \
             pre-removal script subprocess returned error exit status 1\n"
        ),
        FailureCause::Unproven
    );
    // Nothing at all says nothing.
    assert_eq!(stage("", ""), FailureCause::Unproven);
    assert_eq!(stage(READING, ""), FailureCause::Unproven);
}

#[test]
fn a_dependency_refusal_names_this_package_with_or_without_its_architecture() {
    for subject in ["x", "x:amd64"] {
        assert_eq!(
            stage(
                READING,
                &format!(
                    "dpkg: dependency problems prevent removal of {subject}:\n y depends on x.\n"
                )
            ),
            FailureCause::RefusedBeforeChange,
            "{subject}"
        );
    }
    assert_eq!(
        stage(READING, "dpkg: dependency problems prevent removal of X:\n"),
        FailureCause::RefusedBeforeChange,
        "dpkg output is compared case-insensitively like the rest of this module"
    );
    assert_eq!(
        stage(
            READING,
            "dpkg: dependency problems prevent removal of x:arm64:\n"
        ),
        FailureCause::Unproven
    );
    assert_eq!(
        stage(
            READING,
            "dpkg: error processing package x:amd64 (--remove):\n this is an essential package\n"
        ),
        FailureCause::RefusedBeforeChange
    );
}

#[test]
fn an_output_that_was_cut_short_cannot_prove_a_refusal() {
    let refusal = "dpkg: dependency problems prevent removal of x:\n";
    let mut cut = out(1, READING, refusal);
    cut.stderr_truncated = true;
    assert_eq!(
        AptExact::classify_failure(&cut, "x", "amd64"),
        FailureCause::Unproven
    );
    let mut cut = out(1, READING, refusal);
    cut.stdout_truncated = true;
    assert_eq!(
        AptExact::classify_failure(&cut, "x", "amd64"),
        FailureCause::Unproven
    );
    // Invalid UTF-8 cannot hide a Removing line or invent a refusal.
    let mut bytes = b"Removing x (1.0) ...\n".to_vec();
    bytes.extend_from_slice(&[0xff, 0xfe]);
    let o = Output {
        stdout: bytes,
        ..out(1, "", refusal)
    };
    assert_eq!(
        AptExact::classify_failure(&o, "x", "amd64"),
        FailureCause::Started
    );
}

// ------------------------------------------------------------ inventory

fn inventory(pairs: &[(&str, &str)]) -> Inventory {
    Inventory::from_pairs(pairs.iter().map(|(n, a)| (n.to_string(), a.to_string())))
}

#[test]
fn inventory_diff_allows_exactly_one_target_instance() {
    let target = rpm_identity("leaf");
    let before = inventory(&[("leaf", "x86_64"), ("other", "x86_64"), ("lib", "noarch")]);
    let after = inventory(&[("other", "x86_64"), ("lib", "noarch")]);
    assert!(before.unexpected_removals(&after, &target).is_empty());
    assert!(before.target_dropped_by_one(&after, &target));

    // Another package gone.
    let after = inventory(&[("other", "x86_64")]);
    assert_eq!(
        before.unexpected_removals(&after, &target),
        vec!["lib.noarch".to_string()]
    );

    // Packages added by someone else are not removals.
    let after = inventory(&[("other", "x86_64"), ("lib", "noarch"), ("new", "noarch")]);
    assert!(before.unexpected_removals(&after, &target).is_empty());

    // A second instance of the target going is unexpected.
    let before = inventory(&[("leaf", "x86_64"), ("leaf", "x86_64"), ("other", "x86_64")]);
    let after = inventory(&[("other", "x86_64")]);
    assert_eq!(
        before.unexpected_removals(&after, &target),
        vec!["leaf.x86_64".to_string()]
    );
    assert!(!before.target_dropped_by_one(&after, &target));
    let after = inventory(&[("leaf", "x86_64"), ("other", "x86_64")]);
    assert!(before.unexpected_removals(&after, &target).is_empty());
    assert!(before.target_dropped_by_one(&after, &target));

    // The target not leaving at all is not a removal.
    let before = inventory(&[("leaf", "x86_64")]);
    assert!(!before.target_dropped_by_one(&before, &target));
    // Same name, another architecture is another package.
    let before = inventory(&[("leaf", "x86_64"), ("leaf", "i686")]);
    let after = inventory(&[("leaf", "x86_64")]);
    assert_eq!(
        before.unexpected_removals(&after, &target),
        vec!["leaf.i686".to_string()]
    );
}

#[test]
fn inventories_are_parsed_strictly() {
    let apt = "install ok installed\ttree\tamd64\ndeinstall ok config-files\told\tamd64\n";
    let inv = AptExact::parse_inventory(&out(0, apt, "")).unwrap();
    assert_eq!(inv, inventory(&[("tree", "amd64")]));
    for bad in [
        "",
        "install ok installed\ttree\n",
        "install ok installed\ttree\tamd64",
        "deinstall ok config-files\told\tamd64\n",
    ] {
        assert!(
            AptExact::parse_inventory(&out(0, bad, "")).is_err(),
            "{bad:?}"
        );
    }
    assert!(AptExact::parse_inventory(&out(1, apt, "")).is_err());
    assert!(AptExact::parse_inventory(&out(0, apt, "warn\n")).is_err());

    let rpm = "gpg-pubkey\t(none)\ntree\tx86_64\nkernel-core\tx86_64\nkernel-core\tx86_64\n";
    let inv = RpmExact::parse_inventory(&out(0, rpm, "")).unwrap();
    assert_eq!(
        inv.unexpected_removals(&inv, &rpm_identity("tree")).len(),
        0
    );
    for bad in [
        "",
        "tree\n",
        "tree\tx86_64\textra\n",
        "tree\tx86_64",
        " \tx86_64\n",
        "tr\u{1}ee\tx86_64\n",
        "tr\u{7f}ee\tx86_64\n",
        "tree\tx86\u{1b}_64\n",
        "tree\tx86 64\n",
    ] {
        assert!(
            RpmExact::parse_inventory(&out(0, bad, "")).is_err(),
            "{bad:?}"
        );
    }
}

#[test]
fn database_issue_sets_ignore_exit_status_but_not_unreadable_output() {
    let a = AptExact::audit_issues(&out(
        0,
        "The following packages are only half configured:\n x\n",
        "",
    ))
    .unwrap();
    assert_eq!(a.len(), 2);
    assert!(AptExact::audit_issues(&out(0, "", "")).unwrap().is_empty());
    assert!(AptExact::audit_issues(&out(2, "", "boom\n")).is_err());

    let v = RpmExact::verify_issues(&out(
        1,
        "Unsatisfied dependencies for a-1-1.x86_64: b\n",
        "",
    ))
    .unwrap();
    assert!(v.contains("Unsatisfied dependencies for a-1-1.x86_64: b"));
    assert!(RpmExact::verify_issues(&out(0, "", "")).unwrap().is_empty());
    let mut cut = out(0, "", "");
    cut.stdout_truncated = true;
    assert!(RpmExact::verify_issues(&cut).is_err());
    let mut signaled = out(0, "", "");
    signaled.completion = Completion::Signaled(11);
    assert!(RpmExact::verify_issues(&signaled).is_err());
}

// ----------------------------------------------------------- protection

#[test]
fn protected_lists_follow_dnf() {
    let files = "# dnf\ndnf\nyum\n\nsystemd, sudo\n";
    let entries = RpmExact::parse_protected_files(files);
    assert_eq!(entries, vec!["dnf", "yum", "systemd", "sudo"]);
    assert_eq!(RpmExact::protection(&entries, "sudo"), Protection::Yes);
    assert_eq!(RpmExact::protection(&entries, "tree"), Protection::No);
    // Names are exact: a prefix or a pattern is not a match.
    assert_eq!(RpmExact::protection(&entries, "sud"), Protection::No);
    assert_eq!(
        RpmExact::protection(&entries, "sudo-python-plugin"),
        Protection::No
    );
    // dnf is protected even when no file says so.
    assert_eq!(RpmExact::protection(&[], "dnf"), Protection::Yes);

    let conf = "[main]\ngpgcheck=1\nprotected_packages = foo, bar\n    qux\n  baz\n\
                installonly_limit=3\n[repo]\n  not-protected\n";
    let entries = RpmExact::parse_dnf_conf_protected(conf);
    assert_eq!(entries, vec!["foo", "bar", "qux", "baz"]);
    assert!(RpmExact::parse_dnf_conf_protected("# protected_packages=x\n").is_empty());
    assert!(RpmExact::parse_dnf_conf_protected("[main]\n").is_empty());
}

#[test]
fn protected_files_are_read_like_libdnf_reads_them() {
    // Only a line whose first non-blank character is `#` is a comment (libdnf
    // `addFromFile`). A later `#` is a word: it protects more, never less.
    let files = "  # a comment\nfoo # bar\n\tbaz,qux\n#tail\n\n";
    assert_eq!(
        RpmExact::parse_protected_files(files),
        vec!["foo", "#", "bar", "baz", "qux"]
    );
    // The dnf.conf value is taken as written, continuation comments skipped.
    let conf = "[main]\nprotected_packages = # foo\n    # skipped\n    last\n";
    assert_eq!(
        RpmExact::parse_dnf_conf_protected(conf),
        vec!["#", "foo", "last"]
    );
    // Another option's continuation lines are not protected packages.
    let other = "[main]\nexclude=a\n    b\nprotected_packages=p\ngpgcheck=1\n    stray\n";
    assert_eq!(RpmExact::parse_dnf_conf_protected(other), vec!["p"]);
    assert!(RpmExact::parse_protected_files("").is_empty());
}

#[test]
fn a_glob_entry_names_files_so_only_the_default_directories_are_understood() {
    // libdnf reads `glob:<path>` as "more entries are in these files". The
    // two default directories are read directly; any other file list cannot
    // be evaluated, and a protection that cannot be evaluated refuses.
    let defaults = vec![
        "glob:/etc/yum/protected.d/*.conf".to_string(),
        "glob:/etc/dnf/protected.d/*.conf".to_string(),
        "dnf".to_string(),
    ];
    assert_eq!(RpmExact::protection(&defaults, "tree"), Protection::No);
    let custom = vec!["glob:/etc/corp/protected/*.conf".to_string()];
    assert_eq!(
        RpmExact::protection(&custom, "tree"),
        Protection::Unevaluable
    );
    // A name that is protected explicitly is still reported as protected.
    let both = vec!["tree".to_string(), "glob:/etc/corp/*.conf".to_string()];
    assert_eq!(RpmExact::protection(&both, "tree"), Protection::Yes);
    // A package-name pattern is not a thing: `glob:` is never matched to names.
    let as_name = vec!["glob:tree*".to_string()];
    assert_eq!(
        RpmExact::protection(&as_name, "tree"),
        Protection::Unevaluable
    );
}

#[test]
fn optional_text_treats_only_a_missing_file_as_empty() {
    assert_eq!(optional_text(&out(0, "a\n", "")).unwrap(), "a\n");
    assert!(optional_text(&out(0, "a\n", "warning\n")).is_err());
    assert_eq!(
        optional_text(&out(
            1,
            "x\n",
            "cat: /etc/dnf/dnf.conf: No such file or directory\n"
        ))
        .unwrap(),
        "x\n"
    );
    assert!(optional_text(&out(1, "", "")).is_err());
    assert!(optional_text(&out(1, "", "cat: x: Permission denied\n")).is_err());
    assert!(optional_text(&out(
        1,
        "",
        "No such file or directory\nPermission denied\n"
    ))
    .is_err());
    assert!(optional_text(&out(2, "", "No such file or directory\n")).is_err());
    let mut cut = out(0, "", "");
    cut.stdout_truncated = true;
    assert!(optional_text(&cut).is_err());
}

// -------------------------------------------------------------- rendering

#[test]
fn refusal_text_hides_names_for_a_sensitive_resource() {
    let r = Refusal::ReverseDependencies(vec!["app".to_string(), "web".to_string()]);
    let plain = r.render("tree", false);
    assert!(plain.contains("tree") && plain.contains("app, web") && plain.contains("2 installed"));
    let hidden = r.render("[redacted]", true);
    assert!(!hidden.contains("app") && !hidden.contains("web") && hidden.contains("2 installed"));
    let many = Refusal::ReverseDependencies((0..12).map(|i| format!("p{i}")).collect());
    let text = many.render("x", false);
    assert!(
        text.contains("p7") && !text.contains("p8") && text.contains("..."),
        "{text}"
    );
    let note = Refusal::DryRunFailed("secret detail".to_string());
    assert!(note.render("x", false).contains("secret detail"));
    assert!(!note.render("[redacted]", true).contains("secret detail"));
}

#[test]
fn excerpts_are_short_single_line_and_free_of_control_characters() {
    let text = "first line\n\nsecond\u{1b}[31m line\nthird\nfourth\n";
    let e = excerpt(text.as_bytes());
    assert_eq!(e, "first line | second [31m line | third");
    assert!(!e.chars().any(char::is_control));
    let long = "x".repeat(500);
    let e = excerpt(long.as_bytes());
    assert!(e.len() <= EXCERPT_CHARS + 3 && e.ends_with("..."));
    assert_eq!(excerpt(b""), "");
    assert_eq!(excerpt(&[0xff, 0xfe, b'a']).chars().last(), Some('a'));
}

#[test]
fn argv_never_carries_a_force_option_or_a_pattern() {
    let all: Vec<Vec<String>> = vec![
        AptExact::identity_args("tree"),
        AptExact::dry_run_args("tree"),
        AptExact::remove_args("tree"),
        AptExact::audit_args(),
        AptExact::inventory_args(),
        RpmExact::identity_args("tree-1-1.x86_64"),
        RpmExact::test_args("tree-1-1.x86_64"),
        RpmExact::erase_args("tree-1-1.x86_64"),
        RpmExact::verify_args(),
        RpmExact::inventory_args(),
        RpmExact::protected_dirs_args(),
        RpmExact::dnf_conf_args(),
        RpmExact::uname_args(),
    ];
    for args in all {
        for a in &args {
            for forbidden in [
                "--nodeps",
                "--force-depends",
                "--force-all",
                "--allmatches",
                "--auto-remove",
                "autoremove",
                "--purge",
                "--justdb",
            ] {
                assert_ne!(a, forbidden, "{args:?}");
            }
        }
    }
    assert_eq!(
        AptExact::remove_args("tree"),
        vec![
            "--refuse-depends",
            "--refuse-remove-essential",
            "--refuse-remove-protected",
            "--remove",
            "tree"
        ]
    );
    assert!(RpmExact::erase_args("tree-1-1.x86_64")
        .iter()
        .any(|a| a == "tree-1-1.x86_64"));
}

#[test]
fn rpm_verification_output_is_understood_or_it_is_an_error() {
    let ok = "Unsatisfied dependencies for a-1-1.noarch:\n\tb = 1\n\tc\n";
    let issues = RpmExact::verify_issues(&out(1, ok, "")).unwrap();
    assert!(issues.contains("Unsatisfied dependencies for a-1-1.noarch:"));
    assert!(issues.contains("a-1-1.noarch: b = 1"));
    assert_eq!(issues.len(), 3);
    // Same text before and after is no difference, as it should be.
    assert_eq!(issues, RpmExact::verify_issues(&out(1, ok, "")).unwrap());
    // Anything that is not the dependency grammar is not understood.
    for bad in [
        "error: rpmdb: damaged header\n",
        "warning: something\n",
        "\tindented without a header\n",
        "Unsatisfied dependencies for a:\nstray line\n",
    ] {
        assert!(
            RpmExact::verify_issues(&out(1, bad, "")).is_err(),
            "{bad:?}"
        );
        assert!(
            RpmExact::verify_issues(&out(1, "", bad)).is_err(),
            "{bad:?}"
        );
    }
}

#[test]
fn apt_get_check_output_is_read_strictly() {
    let clean =
        "Reading package lists...\nBuilding dependency tree...\nReading state information...\n";
    assert!(AptExact::check_issues(&out(0, clean, ""))
        .unwrap()
        .is_empty());
    let broken = format!(
        "{clean}The following packages have unmet dependencies:\n app : Depends: base but it is not installed\n"
    );
    let issues = AptExact::check_issues(&out(100, &broken, "E: Unmet dependencies.\n")).unwrap();
    assert!(issues.iter().any(|l| l.contains("app : Depends: base")));
    assert!(AptExact::check_issues(&out(100, clean, "")).unwrap().len() == 1);
    for bad in [
        out(
            100,
            clean,
            "E: Could not get lock /var/lib/dpkg/lock-frontend\n",
        ),
        out(1, clean, ""),
        out(0, clean, "E: Unable to lock the administration directory\n"),
    ] {
        assert!(AptExact::check_issues(&bad).is_err());
    }
}

#[test]
fn dpkg_commands_cancel_forced_dependency_removal_configured_elsewhere() {
    for args in [
        AptExact::dry_run_args("tree"),
        AptExact::remove_args("tree"),
    ] {
        for flag in [
            "--refuse-depends",
            "--refuse-remove-essential",
            "--refuse-remove-protected",
        ] {
            assert!(args.iter().any(|a| a == flag), "{args:?}");
        }
        assert_eq!(args.last().map(String::as_str), Some("tree"));
    }
}

#[test]
fn protected_files_are_read_with_coreutils_only_one_file_at_a_time() {
    let args = RpmExact::protected_dirs_args();
    assert_eq!(args[0], "-L");
    assert!(args.iter().any(|a| a == "/etc/dnf/protected.d"));
    assert!(args.iter().any(|a| a == "/etc/yum/protected.d"));
    // Each file is passed to `cat` alone and followed by a newline, so a file
    // without a final newline cannot run into the next one.
    assert!(args
        .windows(4)
        .any(|w| w == ["/usr/bin/cat", "{}", ";", "-exec"]));
    assert!(args.windows(2).any(|w| w == ["/usr/bin/printf", "\\n"]));
    for program in args.iter().filter(|a| a.starts_with("/usr/bin/")) {
        assert!(["/usr/bin/cat", "/usr/bin/printf"].contains(&program.as_str()));
    }
}

#[test]
fn only_missing_protected_directories_are_an_empty_list() {
    let both = "find: '/etc/yum/protected.d': No such file or directory\n\
                find: '/etc/dnf/protected.d': No such file or directory\n";
    assert_eq!(
        RpmExact::protected_files_text(&out(1, "", both)).unwrap(),
        ""
    );
    assert_eq!(
        RpmExact::protected_files_text(&out(
            1,
            "dnf\n",
            "find: ‘/etc/yum/protected.d’: No such file or directory\n"
        ))
        .unwrap(),
        "dnf\n"
    );
    assert_eq!(
        RpmExact::protected_files_text(&out(0, "dnf\n\n", "")).unwrap(),
        "dnf\n\n"
    );
    // find failing to run cat or printf looks the same as a missing file to a
    // careless reader; it is not a list.
    for bad in [
        "find: '/usr/bin/cat': No such file or directory\n",
        "find: '/usr/bin/printf': No such file or directory\n",
        "find: '/etc/dnf/protected.d': Permission denied\n",
        "find: '/etc/dnf/protected.d': No such file or directory\nfind: '/usr/bin/cat': No such file or directory\n",
        "No such file or directory\n",
        "",
    ] {
        assert!(RpmExact::protected_files_text(&out(1, "", bad)).is_err(), "{bad:?}");
    }
    assert!(RpmExact::protected_files_text(&out(2, "", both)).is_err());
    assert!(RpmExact::protected_files_text(&out(0, "", "warning\n")).is_err());
}

#[test]
fn the_running_kernel_is_the_package_that_owns_its_image() {
    let release = "5.14.0-570.el9.x86_64+debug";
    assert!(RpmExact::valid_kernel_release(release));
    assert!(RpmExact::valid_kernel_release(
        "6.12.0-211.64.1.el10_2.x86_64\n"
    ));
    for bad in ["", "5.14 0", "a/b", "$(x)", "5.14\n6.1"] {
        assert!(!RpmExact::valid_kernel_release(bad), "{bad:?}");
    }
    assert_eq!(
        RpmExact::kernel_image_paths("5.14.0-1.el9.x86_64\n"),
        vec![
            "/boot/vmlinuz-5.14.0-1.el9.x86_64",
            "/lib/modules/5.14.0-1.el9.x86_64/vmlinuz"
        ]
    );
    assert_eq!(
        RpmExact::parse_owner(&out(0, "kernel-debug-core\n", "")),
        Ok(Some("kernel-debug-core".to_string()))
    );
    // Nothing owns it: the running kernel is not an installed package.
    assert_eq!(
        RpmExact::parse_owner(&out(
            1,
            "file /boot/vmlinuz-x is not owned by any package\n",
            ""
        )),
        Ok(None)
    );
    assert_eq!(
        RpmExact::parse_owner(&out(
            1,
            "",
            "error: file /boot/vmlinuz-x: No such file or directory\n"
        )),
        Ok(None)
    );
    for bad in [
        out(0, "", ""),
        out(0, "a\nb\n", ""),
        out(0, "ok\n", "warning\n"),
        out(1, "", "error: rpmdb damaged\n"),
        out(2, "", ""),
    ] {
        assert!(RpmExact::parse_owner(&bad).is_err());
    }
}

#[test]
fn every_persistdir_a_dnf_configuration_sets_is_found() {
    assert!(RpmExact::conf_persistdirs("[main]\ngpgcheck=1\n").is_empty());
    assert_eq!(
        RpmExact::conf_persistdirs("[main]\npersistdir = /data/dnf/\n"),
        vec!["/data/dnf/"]
    );
    // A later value cannot hide an earlier one: all of them are returned.
    assert_eq!(
        RpmExact::conf_persistdirs("persistdir=/var/lib/dnf\n[base]\npersistdir=/x\n"),
        vec!["/var/lib/dnf", "/x"]
    );
    assert!(RpmExact::conf_persistdirs("# persistdir=/x\n; persistdir=/y\n").is_empty());
}

#[test]
fn the_wrapper_exit_codes_are_refusals_before_rpm_ran() {
    for code in [75, 76, 77, 78, 126, 127] {
        let o = out(code, "", "");
        assert_eq!(
            RpmExact::classify_failure(&o),
            FailureCause::RefusedBeforeChange,
            "{code}"
        );
        assert!(RpmExact::wrapper_note(&o).is_some(), "{code}");
    }
    assert!(RpmExact::wrapper_note(&out(1, "", "")).is_none());
    // A failure to open the lock file names it on stderr.
    let denied = out(
        2,
        "",
        "sh: 1: cannot create /var/lib/dnf/rpmdb_lock.pid: Permission denied\n",
    );
    assert_eq!(
        RpmExact::classify_failure(&denied),
        FailureCause::RefusedBeforeChange
    );
    assert_eq!(
        RpmExact::classify_failure(&out(
            1,
            "",
            "error: %preun(x) scriptlet failed, exit status 1\n"
        )),
        FailureCause::Other
    );
}

#[test]
fn the_erase_command_is_a_fixed_script_with_the_nevra_as_a_positional_parameter() {
    let args = RpmExact::erase_args("tree-1-1.x86_64");
    assert_eq!(args.len(), 4);
    assert_eq!(
        (args[0].as_str(), args[2].as_str(), args[3].as_str()),
        ("-c", "sinter-erase", "tree-1-1.x86_64")
    );
    let script = &args[1];
    assert!(!script.contains("tree-1-1"));
    assert!(script.contains("/usr/bin/rpm' -e -- \"$1\""));
    assert!(script.contains("'/dev/fd/9' -ef '/var/lib/dnf/rpmdb_lock.pid'"));
    for forbidden in [
        "--nodeps",
        "--allmatches",
        "--noscripts",
        "--justdb",
        "--force",
    ] {
        assert!(!script.contains(forbidden), "{forbidden}");
    }
}

/// Run the real wrapper script with `sh` against stand-ins for flock, cat, rpm
/// and /proc, so that every branch is executed, not just named.
#[cfg(unix)]
mod wrapper {
    use super::super::rpm::erase_script;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    struct Lab {
        dir: PathBuf,
    }

    impl Lab {
        fn new(name: &str) -> Lab {
            let base = std::env::var_os("SINTER_TEST_TMP")
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir);
            let dir = base.join(format!("sinter-wrapper-{}-{}", name, std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join("proc")).unwrap();
            let lab = Lab { dir };
            lab.script("rpm", "printf '%s\\n' \"$*\" > \"$0.ran\"\nexit 0\n");
            lab.script("flock", "exit 0\n");
            lab.script("cat", "exec /bin/cat \"$@\"\n");
            lab
        }
        fn path(&self, name: &str) -> PathBuf {
            self.dir.join(name)
        }
        fn script(&self, name: &str, body: &str) {
            let p = self.path(name);
            std::fs::write(&p, format!("#!/bin/sh\n{}", body)).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        fn run(&self, operand: &str) -> (i32, bool) {
            self.run_with_fd_path(operand, None)
        }
        /// `fd_path` stands in for `/dev/fd/9`; by default it is the lock file
        /// itself (what the descriptor refers to when nothing replaced it).
        fn run_with_fd_path(&self, operand: &str, fd_path: Option<PathBuf>) -> (i32, bool) {
            let lock = self.path("rpmdb_lock.pid");
            let fd_path = fd_path.unwrap_or_else(|| lock.clone());
            let script = erase_script(
                lock.to_str().unwrap(),
                fd_path.to_str().unwrap(),
                self.path("flock").to_str().unwrap(),
                self.path("cat").to_str().unwrap(),
                self.path("proc").to_str().unwrap(),
                self.path("rpm").to_str().unwrap(),
            );
            let status = Command::new("/bin/sh")
                .args(["-c", &script, "sinter-erase", operand])
                .current_dir(&self.dir)
                .output()
                .unwrap();
            let ran = Path::new(&format!("{}.ran", self.path("rpm").display())).exists();
            (status.status.code().unwrap_or(-1), ran)
        }
    }

    impl Drop for Lab {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn a_missing_empty_or_stale_lock_file_lets_rpm_run_with_the_operand() {
        let lab = Lab::new("free");
        assert_eq!(lab.run("tree-1-1.x86_64"), (0, true));
        let ran = std::fs::read_to_string(lab.path("rpm.ran")).unwrap();
        assert_eq!(ran.trim(), "-e -- tree-1-1.x86_64");
        // The lock file now exists and is empty: dnf copes with that.
        assert_eq!(
            std::fs::read_to_string(lab.path("rpmdb_lock.pid")).unwrap(),
            ""
        );

        let lab = Lab::new("stale");
        std::fs::write(lab.path("rpmdb_lock.pid"), "424242\n").unwrap();
        // No such process in the stand-in /proc: a dead dnf.
        assert_eq!(lab.run("tree-1-1.x86_64"), (0, true));
    }

    #[test]
    fn a_live_dnf_pid_is_refused_with_76_and_rpm_does_not_run() {
        let lab = Lab::new("live");
        std::fs::create_dir_all(lab.path("proc").join("4242")).unwrap();
        std::fs::write(lab.path("proc").join("4242").join("stat"), "x").unwrap();
        for content in ["4242", "4242\n"] {
            std::fs::write(lab.path("rpmdb_lock.pid"), content).unwrap();
            assert_eq!(lab.run("tree-1-1.x86_64"), (76, false), "{content:?}");
        }
    }

    #[test]
    fn a_lock_file_that_is_not_a_pid_or_cannot_be_read_is_refused_with_77() {
        for content in ["abc", "12 34", "-1", "12\n34"] {
            let lab = Lab::new("garbage");
            std::fs::write(lab.path("rpmdb_lock.pid"), content).unwrap();
            assert_eq!(lab.run("tree-1-1.x86_64"), (77, false), "{content:?}");
        }
        // cat itself fails (an unreadable file).
        let lab = Lab::new("unreadable");
        std::fs::write(lab.path("rpmdb_lock.pid"), "").unwrap();
        lab.script("cat", "exit 1\n");
        assert_eq!(lab.run("tree-1-1.x86_64"), (77, false));
    }

    #[test]
    fn a_lock_that_cannot_be_taken_is_refused_with_75() {
        let lab = Lab::new("busy");
        lab.script("flock", "exit 1\n");
        assert_eq!(lab.run("tree-1-1.x86_64"), (75, false));
    }

    #[test]
    fn a_lock_file_replaced_while_it_was_being_taken_is_refused_with_78() {
        // dnf deletes the file without taking the flock: after our flock the
        // path may name another file than the one the descriptor holds.
        let lab = Lab::new("replaced");
        std::fs::write(lab.path("held-elsewhere"), "").unwrap();
        std::fs::write(lab.path("rpmdb_lock.pid"), "").unwrap();
        assert_eq!(
            lab.run_with_fd_path("tree-1-1.x86_64", Some(lab.path("held-elsewhere"))),
            (78, false)
        );
    }

    #[test]
    fn a_lock_file_replaced_after_the_pid_was_read_is_refused_with_78() {
        // dnf may remove its file between our flock and our read of the PID:
        // the file is checked once more, after the PID, before rpm runs.
        let lab = Lab::new("replaced-late");
        let lock = lab.path("rpmdb_lock.pid");
        // The stand-in cat reads the file and then removes it, as a finishing
        // dnf would. The first check (before cat) passed; only the second can
        // notice.
        lab.script(
            "cat",
            &format!("/bin/cat \"$@\"\n/bin/rm -f '{}'\n", lock.display()),
        );
        assert_eq!(lab.run("tree-1-1.x86_64"), (78, false));
    }

    #[test]
    fn a_lock_file_that_cannot_be_opened_stops_before_rpm() {
        let lab = Lab::new("dir");
        std::fs::create_dir_all(lab.path("rpmdb_lock.pid")).unwrap();
        let (code, ran) = lab.run("tree-1-1.x86_64");
        assert_ne!(code, 0);
        assert!(!ran);
    }

    #[test]
    fn the_operand_is_never_interpreted_by_the_shell() {
        let lab = Lab::new("inject");
        let marker = lab.path("injected");
        let operand = format!("$(touch {}) ; touch {}", marker.display(), marker.display());
        assert_eq!(lab.run(&operand), (0, true));
        assert!(!marker.exists());
        let ran = std::fs::read_to_string(lab.path("rpm.ran")).unwrap();
        assert_eq!(ran.trim(), format!("-e -- {}", operand));
    }
}

/// Writes the production erase script (with the production paths) to the file
/// named by `SINTER_DUMP_ERASE_SCRIPT`, so that the very same text can be run
/// against stand-ins on a real Linux host. A no-op when the variable is unset.
#[test]
fn the_production_erase_script_can_be_dumped_for_host_experiments() {
    let args = RpmExact::erase_args("OPERAND");
    assert_eq!(args[0], "-c");
    if let Some(path) = std::env::var_os("SINTER_DUMP_ERASE_SCRIPT") {
        std::fs::write(path, &args[1]).unwrap();
    }
}

// ---------------------------------------------------------------------------
// "someone else removed it first": dpkg's own warnings (dpkg 1.22.6
// src/main/remove.c, deferred_remove) and nothing that merely looks like them
// ---------------------------------------------------------------------------

const GONE: &str = "dpkg: warning: ignoring request to remove tree which isn't installed\n";
const GONE_ARCH: &str =
    "dpkg: warning: ignoring request to remove tree:amd64 which isn't installed\n";
const CONFIG: &str = "dpkg: warning: ignoring request to remove tree, only the config\n files of which are on the system; use --purge to remove them too\n";
const CONFIG_ARCH: &str = "dpkg: warning: ignoring request to remove tree:amd64, only the config\n files of which are on the system; use --purge to remove them too\n";

fn ignored(stderr: &str, name: &str, arch: &str) -> bool {
    use crate::engine::Engine;
    Engine::dpkg_ignored_the_request(&out(0, "", stderr), name, arch)
}

#[test]
fn dpkgs_own_warnings_for_this_package_are_recognised() {
    for warning in [GONE, GONE_ARCH, CONFIG, CONFIG_ARCH] {
        assert!(ignored(warning, "tree", "amd64"), "{warning:?}");
    }
    // a name with the characters Debian allows in one
    assert!(ignored(
        "dpkg: warning: ignoring request to remove libstdc++6.1-dev which isn't installed\n",
        "libstdc++6.1-dev",
        "amd64"
    ));
    // the architecture all is just another architecture
    assert!(ignored(
        "dpkg: warning: ignoring request to remove doc-pkg:all which isn't installed\n",
        "doc-pkg",
        "all"
    ));
    // other output around it does not matter, ours is still there
    assert!(ignored(
        &format!("dpkg: warning: something else\n{CONFIG}dpkg: note: later\n"),
        "tree",
        "amd64"
    ));
    assert!(ignored(
        &format!(
            "{GONE}{}",
            "dpkg: warning: ignoring request to remove other which isn't installed\n"
        ),
        "tree",
        "amd64"
    ));
    // dpkg and the capture are case-insensitive for the comparison
    assert!(ignored(&GONE.to_ascii_uppercase(), "tree", "amd64"));
}

#[test]
fn the_subject_has_to_be_exactly_this_package_instance() {
    // longer or shorter names, in either direction
    for (stderr, name) in [
        (GONE, "tre"),
        (GONE, "tree-extra"),
        (GONE, "treex"),
        (GONE, "xtree"),
        (GONE, "ree"),
        (GONE, "other"),
    ] {
        assert!(!ignored(stderr, name, "amd64"), "{stderr:?} for {name}");
    }
    for (subject, name) in [
        ("tree-extra", "tree"),
        ("treex", "tree"),
        ("tree.", "tree"),
        ("tree+", "tree"),
        ("tree-", "tree"),
        ("xtree", "tree"),
        ("tree2", "tree"),
        ("tre", "tree"),
    ] {
        for form in [
            format!("dpkg: warning: ignoring request to remove {subject} which isn't installed\n"),
            format!("dpkg: warning: ignoring request to remove {subject}, only the config\n files of which are on the system; use --purge to remove them too\n"),
        ] {
            assert!(!ignored(&form, name, "amd64"), "{form:?} for {name}");
        }
    }
    // another architecture, an unqualified name never matches a qualifier it
    // cannot have, and malformed qualifiers are not accepted
    for subject in [
        "tree:i386",
        "tree:",
        "tree::amd64",
        "tree:amd64:amd64",
        "tree:amd6",
        "tree:amd644",
        "tree:amd64x",
        "tree:AMD 64",
        ":amd64",
        "tree amd64",
        "tree/amd64",
        "tree:*",
        "*",
        "tree*",
    ] {
        let form =
            format!("dpkg: warning: ignoring request to remove {subject} which isn't installed\n");
        assert!(!ignored(&form, "tree", "amd64"), "{form:?}");
    }
    // the qualifier has to be the architecture of the instance being removed
    assert!(ignored(GONE_ARCH, "tree", "amd64"));
    assert!(!ignored(GONE_ARCH, "tree", "i386"));
    assert!(!ignored(GONE_ARCH, "tree", "all"));
    assert!(!ignored(GONE_ARCH, "tree", ""));
    // a name in the target's architecture is not another package's
    assert!(!ignored(GONE_ARCH, "other", "amd64"));
}

#[test]
fn only_dpkgs_exact_wording_counts() {
    for text in [
        // the right words, not dpkg's line
        "ignoring request to remove tree which isn't installed\n",
        "postrm: ignoring request to remove tree which isn't installed\n",
        " dpkg: warning: ignoring request to remove tree which isn't installed\n",
        "x dpkg: warning: ignoring request to remove tree which isn't installed\n",
        "dpkg: error: ignoring request to remove tree which isn't installed\n",
        "dpkg: warning: ignore request to remove tree which isn't installed\n",
        // dpkg's line with something after (or instead of) its text
        "dpkg: warning: ignoring request to remove tree which isn't installed (but has config files)\n",
        "dpkg: warning: ignoring request to remove tree which isn't installed, skipping\n",
        "dpkg: warning: ignoring request to remove tree which is not installed\n",
        "dpkg: warning: ignoring request to remove tree which isn't installed.\n",
        "dpkg: warning: ignoring request to remove tree\n",
        "dpkg: warning: ignoring request to remove tree \n",
        "dpkg: warning: ignoring request to remove tree  which isn't installed\n",
        "dpkg: warning: ignoring request to remove  tree which isn't installed\n",
        "dpkg: warning: ignoring request to remove tree,which isn't installed\n",
        "dpkg: warning: ignoring request to remove tree, which isn't installed\n",
        // the same text but not alone on its line
        "note: dpkg: warning: ignoring request to remove tree which isn't installed\n",
        // control characters inside the subject or the text
        "dpkg: warning: ignoring request to remove tr\u{1}ee which isn't installed\n",
        "dpkg: warning: ignoring request to remove tr\0ee which isn't installed\n",
        "dpkg: warning: ignoring request to remove tr\u{7f}ee which isn't installed\n",
        "dpkg: warning: ignoring request to remove tree which isn't\u{1b} installed\n",
        "dpkg: warning: ignoring request to remove tr\u{fffd}e which isn't installed\n",
        // a script's own message
        "postrm: helper isn't installed, skipping\n",
        "",
        "\n",
    ] {
        assert!(!ignored(text, "tree", "amd64"), "{text:?}");
    }
    // the apostrophe is part of dpkg's text
    assert!(!ignored(
        "dpkg: warning: ignoring request to remove tree which isnt installed\n",
        "tree",
        "amd64"
    ));
    assert!(!ignored(
        "dpkg: warning: ignoring request to remove tree which isn\u{2019}t installed\n",
        "tree",
        "amd64"
    ));
    // bytes that are not UTF-8 do not turn into a match
    use crate::engine::Engine;
    let mut bad = out(0, "", "");
    bad.stderr =
        b"dpkg: warning: ignoring request to remove tr\xffee which isn't installed\n".to_vec();
    assert!(!Engine::dpkg_ignored_the_request(&bad, "tree", "amd64"));
    // a lossy replacement character next to a good line changes nothing
    bad.stderr = [b"\xff\xfe\n".as_slice(), GONE.as_bytes()].concat();
    assert!(Engine::dpkg_ignored_the_request(&bad, "tree", "amd64"));
}

#[test]
fn the_config_files_warning_needs_its_second_line() {
    let first = "dpkg: warning: ignoring request to remove tree, only the config\n";
    let second = " files of which are on the system; use --purge to remove them too\n";
    assert!(ignored(&format!("{first}{second}"), "tree", "amd64"));
    // missing, different, detached or already-joined second line
    for text in [
        first.to_string(),
        format!("{first}\n{second}"),
        format!("{first}{}", second.trim_start()),
        format!("{first} files of which are on the system\n"),
        format!("{first}other line\n{second}"),
        format!("{first}{}x\n", second.trim_end()),
        format!("{}{second}", first.replace(", only the config\n", ", only the config files\n")),
        "dpkg: warning: ignoring request to remove tree, only the config files of which are on the system; use --purge to remove them too\n".to_string(),
        "dpkg: warning: ignoring request to remove tree, only the config\n".to_string(),
        "dpkg: warning: ignoring request to remove tree, only\n".to_string(),
        "dpkg: warning: ignoring request to remove tree,\n".to_string(),
    ] {
        assert!(!ignored(&text, "tree", "amd64"), "{text:?}");
    }
    // carriage returns do not matter
    assert!(ignored(
        &format!("{first}{second}").replace('\n', "\r\n"),
        "tree",
        "amd64"
    ));
}

#[test]
fn a_real_removal_is_never_a_no_op() {
    use crate::engine::Engine;
    for removing in [
        "Removing tree (1.0-1) ...\n",
        "(Reading database ... 123 files and directories currently installed.)\nRemoving tree (1.0-1) ...\n",
        "  Removing tree (1.0-1) ...\n",
        "REMOVING TREE (1.0-1) ...\n",
        "Removing other (1.0-1) ...\n",
        "\n\nRemoving x\n",
    ] {
        for warning in [GONE, GONE_ARCH, CONFIG, CONFIG_ARCH] {
            assert!(
                !Engine::dpkg_ignored_the_request(&out(0, removing, warning), "tree", "amd64"),
                "{removing:?} {warning:?}"
            );
        }
    }
    // a line that merely mentions it is not a "Removing" line
    assert!(Engine::dpkg_ignored_the_request(
        &out(0, "Not Removing tree\n(Removing is later)\n", GONE),
        "tree",
        "amd64"
    ));
    // an incomplete capture of either stream proves nothing
    for (stdout_cut, stderr_cut) in [(true, false), (false, true), (true, true)] {
        for warning in [GONE, GONE_ARCH, CONFIG, CONFIG_ARCH] {
            let mut cut = out(0, "", warning);
            cut.stdout_truncated = stdout_cut;
            cut.stderr_truncated = stderr_cut;
            assert!(
                !Engine::dpkg_ignored_the_request(&cut, "tree", "amd64"),
                "{warning:?}"
            );
        }
    }
}
