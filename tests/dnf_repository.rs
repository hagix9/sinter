//! `dnf_repository` against the scripted in-process target.
//!
//! These run the production loader, engine, partial-edit helpers, audit and
//! output code against [`FakeTarget`] with its modeled filesystem. They prove
//! Sinter's own decisions: what is written to the repository file, what is
//! refused, and that plan and audit only read. What only a real host can
//! show is NOT claimed here: how DNF 4 reads the edited file, what
//! `/usr/bin/dnf` links to on each supported distribution, and that a
//! package from a repository defined this way installs (the scripted DNF
//! does not read `.repo` files).
mod common;

use common::*;
use sinter::audit::{AuditReport, AuditResourceStatus};
use sinter::engine::{AggregateStatus, Engine, Mode, RunOptions, RunReport, TargetSpec};
use sinter::executor::{Completion, FakeTarget, FsEventAction, Output};
use sinter::fakesys::{FakeFs, FakeKind};
use sinter::output::{render_apply, render_audit, render_plan, OutputFormat, RenderOptions};
use sinter::result::{Change, DiffBody, Execution, Verification};
use std::path::{Path, PathBuf};

const DIR: &str = "/etc/yum.repos.d";
const EXAMPLE: &str = "/etc/yum.repos.d/example.repo";
const ROCKY: &str = "/etc/yum.repos.d/rocky.repo";
const URL: &str = "https://repo.example.invalid/el$releasever/$basearch/";
const KEY: &str = "file:///etc/pki/rpm-gpg/RPM-GPG-KEY-example";

/// A distribution-style file: three sections, comments, both key forms.
const ROCKY_REPO: &str = "# rocky.repo\n#\n# The mirrorlist system picks a mirror close to the client.\n\n[baseos]\nname=Rocky Linux $releasever - BaseOS\nmirrorlist=https://mirrors.example.invalid/mirrorlist?arch=$basearch&repo=BaseOS-$releasever\n#baseurl=http://dl.example.invalid/$contentdir/$releasever/BaseOS/$basearch/os/\ngpgcheck=1\nenabled=1\ncountme=1\ngpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9\n\n[crb]\nname=Rocky Linux $releasever - CRB\nmirrorlist=https://mirrors.example.invalid/mirrorlist?arch=$basearch&repo=CRB-$releasever\ngpgcheck=1\nenabled=0\ncountme=1\ngpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9\n\n# Debug packages\n[crb-debug]\nname = Rocky Linux $releasever - CRB - Debug\nenabled = 0\ngpgcheck = 1\n";

/// A Rocky Linux 9 target reached as root: `/etc/yum.repos.d` exists and
/// `/usr/bin/dnf` links to the DNF 4 program.
fn target() -> FakeTarget {
    dnf_target(FakeTarget::rocky9(), Some("dnf-3")).as_root()
}

fn dnf_target(t: FakeTarget, dnf_link: Option<&str>) -> FakeTarget {
    let mut t = t.with_fake_fs().with_fs_dir(DIR).with_fs_dir("/usr/bin");
    if let Some(link) = dnf_link {
        t.fs.as_mut()
            .unwrap()
            .put_symlink("/usr/bin/dnf", link, 0, 0);
    }
    t
}

fn with_rocky(t: FakeTarget) -> FakeTarget {
    t.with_fs_file(ROCKY, ROCKY_REPO)
}

fn doc(resources: &str) -> String {
    format!("version: 1\nresources:\n{resources}")
}

fn repo(id: &str, fields: &str) -> String {
    format!("  - id: {id}\n    type: dnf_repository\n    with:\n{fields}")
}

/// Enable CRB in the distribution's file.
fn crb(enabled: bool) -> String {
    doc(&repo(
        "crb",
        &format!("      name: crb\n      file: {ROCKY}\n      enabled: {enabled}\n"),
    ))
}

/// A signed third-party repository in its own file.
fn example() -> String {
    doc(&repo(
        "example",
        &format!(
            "      name: example\n      description: Example packages\n      baseurl: \"{URL}\"\n      gpgcheck: true\n      gpgkey: {KEY}\n"
        ),
    ))
}

const EXAMPLE_REPO: &str = "[example]\nname=Example packages\nbaseurl=https://repo.example.invalid/el$releasever/$basearch/\nenabled=1\ngpgcheck=1\ngpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-example\n";

fn recipe(label: &str, yaml: &str) -> PathBuf {
    write_recipe(&trusted_root(label), "r.yaml", yaml)
}

fn apply(r: &Path, t: FakeTarget) -> RunReport {
    run_recipe_fake(r, Mode::Apply, false, t)
}

fn plan(r: &Path, t: FakeTarget) -> RunReport {
    run_recipe_fake(r, Mode::Plan, false, t)
}

fn audit(r: &Path, t: FakeTarget) -> AuditReport {
    let model = sinter::model::load_model(r).unwrap();
    let opts = RunOptions {
        mode: Mode::Plan,
        sudo: false,
        target: TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(t),
    };
    sinter::audit::run_audit(Engine::new(model, opts).unwrap()).unwrap()
}

fn fs_of(r: &RunReport) -> &FakeFs {
    r.fake_fs.as_ref().expect("scripted filesystem")
}

fn text(fs: &FakeFs, path: &str) -> String {
    String::from_utf8(
        fs.file_bytes(path)
            .unwrap_or_else(|| panic!("{path} is missing")),
    )
    .unwrap()
}

/// The target as a run left it.
fn continue_from(r: &RunReport) -> FakeTarget {
    let mut t = target();
    t.fs = r.fake_fs.clone();
    t
}

fn load_err(label: &str, yaml: &str) -> String {
    match sinter::model::load_model(&recipe(label, yaml)) {
        Ok(_) => panic!("{label}: recipe was accepted"),
        Err(e) => e.message,
    }
}

/// The failure of a run, wherever it surfaced: the error of the run itself
/// or the failed resource's reason.
fn failure(r: &Path, mode: Mode, t: FakeTarget) -> String {
    match try_run_recipe_fake(r, mode, false, t) {
        Err(e) => e.message,
        Ok(report) => {
            assert_ne!(report.status, AggregateStatus::Success, "the run succeeded");
            report
                .resources
                .iter()
                .filter_map(|x| x.reason.clone())
                .collect::<Vec<_>>()
                .join("; ")
        }
    }
}

fn rendered(report: &RunReport, mode: Mode) -> String {
    let mut all = String::new();
    for format in [OutputFormat::Text, OutputFormat::Json] {
        let opts = RenderOptions {
            verbose: true,
            format,
            color: false,
        };
        let mut out = Vec::new();
        match mode {
            Mode::Plan => render_plan(report, &opts, &mut out).unwrap(),
            Mode::Apply => render_apply(report, &opts, &mut out).unwrap(),
        }
        all.push_str(&String::from_utf8(out).unwrap());
    }
    all
}

fn rendered_audit(report: &AuditReport) -> String {
    let mut all = String::new();
    for format in [OutputFormat::Text, OutputFormat::Json] {
        let opts = RenderOptions {
            verbose: true,
            format,
            color: false,
        };
        let mut out = Vec::new();
        render_audit(report, &opts, &mut out).unwrap();
        all.push_str(&String::from_utf8(out).unwrap());
    }
    all
}

fn failing(code: i32, stderr: &str) -> Output {
    Output {
        completion: Completion::Exited(code),
        stdout: Vec::new(),
        stderr: stderr.as_bytes().to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

// ---------------------------------------------------------------------------
// create, change, idempotence
// ---------------------------------------------------------------------------

#[test]
fn a_new_repository_file_is_exactly_the_section_root_owned_and_0644() {
    let p = recipe("repo-create", &example());
    let r = apply(&p, target());
    assert_success(&r);
    let x = find(&r, "example");
    assert_eq!(x.change, Change::Changed);
    assert_eq!(x.execution, Execution::Succeeded);
    assert_eq!(x.verification, Verification::Verified);
    let fs = fs_of(&r);
    assert_eq!(text(fs, EXAMPLE), EXAMPLE_REPO);
    let n = &fs.nodes[EXAMPLE];
    assert_eq!((n.mode & 0o7777, n.uid, n.gid), (0o644, 0, 0));
    // No DNF command ran: the file is the whole change.
    assert!(
        !r.commands.iter().any(|c| c.program.ends_with("/dnf")),
        "a dnf command ran"
    );
}

#[test]
fn a_second_apply_changes_nothing_and_does_not_rewrite_the_file() {
    let p = recipe("repo-idem", &example());
    let first = apply(&p, target());
    assert_success(&first);
    let before = fs_of(&first).nodes[EXAMPLE].clone();
    let second = apply(&p, continue_from(&first));
    assert_success(&second);
    let x = find(&second, "example");
    assert_eq!(x.change, Change::None);
    assert_eq!(x.verification, Verification::Verified);
    assert_eq!(mutation_command_count(&second), 0);
    let after = &fs_of(&second).nodes[EXAMPLE];
    assert_eq!(
        (after.ino, after.mtime, after.ctime),
        (before.ino, before.mtime, before.ctime)
    );
    // Plan agrees.
    let pl = plan(&p, continue_from(&first));
    assert_eq!(find(&pl, "example").change, Change::None);
}

#[test]
fn enabling_a_distribution_repository_changes_one_line_and_keeps_the_rest() {
    let p = recipe("repo-crb", &crb(true));
    let mut t = with_rocky(target());
    // The file's own metadata is not Sinter's to change.
    t.fs.as_mut()
        .unwrap()
        .put_file(ROCKY, ROCKY_REPO.as_bytes(), 0o640, 0, 7);
    let r = apply(&p, t);
    assert_success(&r);
    assert_eq!(find(&r, "crb").change, Change::Changed);
    let fs = fs_of(&r);
    let want = {
        // Exactly the `enabled` line of [crb].
        let at = ROCKY_REPO.find("[crb]\n").unwrap();
        let rel = ROCKY_REPO[at..].find("enabled=0\n").unwrap();
        let mut s = ROCKY_REPO.to_string();
        s.replace_range(at + rel..at + rel + "enabled=0\n".len(), "enabled=1\n");
        s
    };
    assert_eq!(text(fs, ROCKY), want);
    assert_eq!(want.len(), ROCKY_REPO.len());
    let n = &fs.nodes[ROCKY];
    assert_eq!((n.mode & 0o7777, n.uid, n.gid), (0o640, 0, 7));

    let again = apply(&p, continue_from(&r));
    assert_eq!(find(&again, "crb").change, Change::None);
    assert_eq!(mutation_command_count(&again), 0);
}

#[test]
fn plan_shows_the_changed_line_and_changes_nothing() {
    let p = recipe("repo-plan", &crb(true));
    let r = plan(&p, with_rocky(target()));
    assert_success(&r);
    let x = find(&r, "crb");
    assert_eq!(x.change, Change::Changed);
    match &x.diff.as_ref().expect("a diff").body {
        DiffBody::Text { removed, added } => {
            // The declared key, old and new value: not lines of the file.
            assert_eq!(removed, &["enabled: 0"]);
            assert_eq!(added, &["enabled: 1"]);
        }
        other => panic!("unexpected diff {other:?}"),
    }
    assert_eq!(mutation_command_count(&r), 0);
    assert_eq!(text(fs_of(&r), ROCKY), ROCKY_REPO);
    // A new file: nothing is created by plan.
    let p = recipe("repo-plan-new", &example());
    let r = plan(&p, target());
    assert_eq!(find(&r, "example").change, Change::Changed);
    assert_eq!(mutation_command_count(&r), 0);
    assert!(!fs_of(&r).nodes.contains_key(EXAMPLE));
}

#[test]
fn several_repositories_in_one_file_are_edited_one_after_the_other() {
    let body = format!(
        "{}{}",
        repo(
            "crb",
            &format!("      name: crb\n      file: {ROCKY}\n      enabled: true\n")
        ),
        repo(
            "debug",
            &format!("      name: crb-debug\n      file: {ROCKY}\n      description: CRB debug\n")
        )
    );
    let p = recipe("repo-two", &doc(&body));
    let r = apply(&p, with_rocky(target()));
    assert_success(&r);
    let out = text(fs_of(&r), ROCKY);
    assert!(out.contains("[crb]\nname=Rocky Linux $releasever - CRB\nmirrorlist=https://mirrors.example.invalid/mirrorlist?arch=$basearch&repo=CRB-$releasever\ngpgcheck=1\nenabled=1\n"));
    assert!(
        out.contains("# Debug packages\n[crb-debug]\nname=CRB debug\nenabled = 0\ngpgcheck = 1\n")
    );
    assert!(out.starts_with(&ROCKY_REPO[..ROCKY_REPO.find("[crb]").unwrap()]));
}

#[test]
fn a_repository_can_be_added_to_an_existing_file() {
    let body = repo(
        "extra",
        &format!("      name: extra\n      file: {ROCKY}\n      metalink: \"{URL}\"\n      enabled: false\n"),
    );
    let p = recipe("repo-append", &doc(&body));
    let r = apply(&p, with_rocky(target()));
    assert_success(&r);
    assert_eq!(
        text(fs_of(&r), ROCKY),
        format!("{ROCKY_REPO}\n[extra]\nmetalink={URL}\nenabled=0\ngpgcheck=1\n")
    );
}

// ---------------------------------------------------------------------------
// state: absent
// ---------------------------------------------------------------------------

#[test]
fn absent_removes_the_section_and_keeps_the_file() {
    let absent = |name: &str, file: &str| {
        doc(&repo(
            "gone",
            &format!("      name: {name}\n      file: {file}\n      state: absent\n"),
        ))
    };
    let p = recipe("repo-absent", &absent("crb", ROCKY));
    let r = apply(&p, with_rocky(target()));
    assert_success(&r);
    assert_eq!(find(&r, "gone").change, Change::Changed);
    let out = text(fs_of(&r), ROCKY);
    assert!(!out.contains("[crb]"));
    assert!(out.contains("[baseos]") && out.contains("# Debug packages\n[crb-debug]\n"));
    assert_eq!(
        apply(&p, continue_from(&r)).resources[0].change,
        Change::None
    );

    // The only section of a file: the file stays.
    let p = recipe("repo-absent-last", &absent("example", EXAMPLE));
    let r = apply(&p, target().with_fs_file(EXAMPLE, EXAMPLE_REPO));
    assert_success(&r);
    assert_eq!(text(fs_of(&r), EXAMPLE), "");

    // Nothing to do: no section, or no file.
    let p = recipe("repo-absent-none", &absent("other", ROCKY));
    let r = apply(&p, with_rocky(target()));
    assert_eq!(find(&r, "gone").change, Change::None);
    assert_eq!(mutation_command_count(&r), 0);
    let r = apply(&p, target());
    assert_eq!(find(&r, "gone").change, Change::None);
    assert!(!fs_of(&r).nodes.contains_key(ROCKY));
}

// ---------------------------------------------------------------------------
// signature checking is not weakened
// ---------------------------------------------------------------------------

#[test]
fn enabling_an_unchecked_repository_is_refused_in_plan_and_apply() {
    for (label, section) in [
        (
            "off",
            "[lab]\nbaseurl=https://lab.example.invalid/\nenabled=0\ngpgcheck=0\n",
        ),
        (
            "missing",
            "[lab]\nbaseurl=https://lab.example.invalid/\nenabled=0\n",
        ),
    ] {
        let body = repo("lab", "      name: lab\n      enabled: true\n");
        let p = recipe(&format!("repo-gpg-{label}"), &doc(&body));
        let file = "/etc/yum.repos.d/lab.repo";
        for mode in [Mode::Plan, Mode::Apply] {
            let e = failure(&p, mode, target().with_fs_file(file, section));
            assert!(
                e.contains("declare gpgcheck: true")
                    && e.contains(
                        "does not enable a repository whose packages are not signature-checked"
                    ),
                "{label}: {e}"
            );
        }
        // Nothing was written by the refused apply.
        let model = sinter::model::load_model(&p).unwrap();
        let opts = RunOptions {
            mode: Mode::Apply,
            sudo: false,
            target: TargetSpec { ssh: None },
            verbose: false,
            fault: None,
            fake_target: Some(target().with_fs_file(file, section)),
        };
        if let Ok(r) = Engine::new(model, opts).unwrap().run() {
            assert_eq!(text(fs_of(&r), file), section);
            assert_eq!(mutation_command_count(&r), 0);
        }
        // Declaring gpgcheck turns it on together with the repository.
        let body = repo(
            "lab",
            "      name: lab\n      enabled: true\n      gpgcheck: true\n",
        );
        let p = recipe(&format!("repo-gpg-on-{label}"), &doc(&body));
        let r = apply(&p, target().with_fs_file(file, section));
        assert_success(&r);
        let out = text(fs_of(&r), file);
        assert!(
            out.contains("enabled=1\n") && out.contains("gpgcheck=1\n"),
            "{out}"
        );
        assert!(!out.contains("gpgcheck=0"));
    }
}

#[test]
fn an_unchecked_enabled_repository_left_alone_gets_a_note_in_plan_apply_and_audit() {
    let file = "/etc/yum.repos.d/lab.repo";
    let section = "[lab]\nname=Lab\nbaseurl=https://lab.example.invalid/\nenabled=1\ngpgcheck=0\n";
    let body = repo(
        "lab",
        "      name: lab\n      description: Lab\n      enabled: true\n",
    );
    let p = recipe("repo-note", &doc(&body));
    for mode in [Mode::Plan, Mode::Apply] {
        let r = run_recipe_fake(&p, mode, false, target().with_fs_file(file, section));
        assert_success(&r);
        let x = find(&r, "lab");
        assert_eq!(x.change, Change::None);
        assert!(
            x.notes
                .iter()
                .any(|n| n.contains("signature checking is not on")),
            "{:?}",
            x.notes
        );
        assert_eq!(text(fs_of(&r), file), section);
    }
    let a = audit(&p, target().with_fs_file(file, section));
    let x = &a.resources[0];
    assert_eq!(x.status, AuditResourceStatus::Compliant);
    assert!(x
        .reason
        .as_deref()
        .unwrap()
        .contains("signature checking is not on"));
}

// ---------------------------------------------------------------------------
// audit
// ---------------------------------------------------------------------------

#[test]
fn audit_is_compliant_when_every_declared_key_matches() {
    let p = recipe("repo-audit-ok", &example());
    // Written differently, meaning the same.
    let same = "[example]\nname = Example packages\nbaseurl =   https://repo.example.invalid/el$releasever/$basearch/\nenabled = 1\ngpgcheck = True\ngpgkey=\n    file:///etc/pki/rpm-gpg/RPM-GPG-KEY-example\nsslverify=1\n";
    for content in [EXAMPLE_REPO, same] {
        let a = audit(&p, target().with_fs_file(EXAMPLE, content));
        assert_eq!(
            a.resources[0].status,
            AuditResourceStatus::Compliant,
            "{:?}",
            a.resources[0]
        );
    }
    let p = recipe(
        "repo-audit-absent",
        &doc(&repo("x", "      name: example\n      state: absent\n")),
    );
    for t in [
        target(),
        target().with_fs_file(EXAMPLE, "[other]\nenabled=0\n"),
    ] {
        assert_eq!(
            audit(&p, t).resources[0].status,
            AuditResourceStatus::Compliant
        );
    }
}

#[test]
fn audit_reports_one_drift_detail_per_differing_key() {
    let p = recipe("repo-audit-drift", &example());
    let drifted = "[example]\nname=Example packages\nbaseurl=https://other.example.invalid/\nenabled=1\ngpgcheck=0\n";
    let a = audit(&p, target().with_fs_file(EXAMPLE, drifted));
    let x = &a.resources[0];
    assert_eq!(x.status, AuditResourceStatus::Drift);
    let dims: Vec<&str> = x.details.iter().map(|d| d.dimension.as_str()).collect();
    assert_eq!(dims, ["baseurl", "gpgcheck", "gpgkey"]);
    assert_eq!(x.details[0].observed, "https://other.example.invalid/");
    assert_eq!(x.details[0].desired, URL);
    assert_eq!(
        (
            x.details[1].observed.as_str(),
            x.details[1].desired.as_str()
        ),
        ("0", "1")
    );
    assert_eq!(x.details[2].observed, "(not set)");

    // A missing section and a missing file are drift, not errors.
    for t in [
        target(),
        target().with_fs_file(EXAMPLE, "[other]\nenabled=0\n"),
    ] {
        let a = audit(&p, t);
        let x = &a.resources[0];
        assert_eq!(x.status, AuditResourceStatus::Drift);
        assert_eq!(x.details[0].dimension, "state");
        assert_eq!(x.details[0].desired, "present");
    }
    // A section that should be gone.
    let p = recipe(
        "repo-audit-present",
        &doc(&repo("x", "      name: example\n      state: absent\n")),
    );
    let a = audit(&p, target().with_fs_file(EXAMPLE, EXAMPLE_REPO));
    assert_eq!(a.resources[0].status, AuditResourceStatus::Drift);
    assert_eq!(a.resources[0].details[0].observed, "present");
}

#[test]
fn audit_errors_on_what_it_cannot_read_with_certainty() {
    let p = recipe("repo-audit-err", &example());
    let big = format!("[example]\n{}", "#\n".repeat(200_000));
    let mut symlinked = target();
    symlinked
        .fs
        .as_mut()
        .unwrap()
        .put_symlink(EXAMPLE, "/etc/app/elsewhere.repo", 0, 0);
    let mut refused_parent = target();
    refused_parent
        .fs
        .as_mut()
        .unwrap()
        .mkdir_node(DIR, 0o777, 1001, 1001);
    let cases: Vec<(&str, FakeTarget, &str)> = vec![
        (
            "duplicate section",
            target().with_fs_file(EXAMPLE, "[example]\nenabled=1\n[example]\nenabled=0\n"),
            "more than once",
        ),
        (
            "duplicate key",
            target().with_fs_file(EXAMPLE, "[example]\nenabled=1\nenabled=0\n"),
            "more than once",
        ),
        (
            "unparsable line",
            target().with_fs_file(EXAMPLE, "[example]\nwhat is this\n"),
            "not a key=value line",
        ),
        (
            "carriage returns",
            target().with_fs_file(EXAMPLE, "[example]\r\nenabled=1\r\n"),
            "carriage return",
        ),
        ("symlink", symlinked, "it is not read"),
        (
            "oversized",
            target().with_fs_file(EXAMPLE, &big),
            "larger than",
        ),
        ("refused parent", refused_parent, "parent path check"),
        (
            "unreadable",
            target()
                .with_fs_file(EXAMPLE, EXAMPLE_REPO)
                .with_observations_at(
                    "cat",
                    EXAMPLE,
                    vec![failing(1, "cat: read error: Input/output error")],
                ),
            "",
        ),
    ];
    for (what, t, want) in cases {
        let a = audit(&p, t);
        let x = &a.resources[0];
        assert_eq!(x.status, AuditResourceStatus::Error, "{what}: {x:?}");
        assert!(x.details.is_empty(), "{what}");
        assert!(
            x.reason.as_deref().unwrap_or("").contains(want),
            "{what}: {:?}",
            x.reason
        );
        assert!(
            !a.commands
                .iter()
                .any(|c| is_mutation_command(&c.program, &c.args)),
            "{what}: audit ran a mutation command"
        );
    }
}

#[test]
fn audit_reads_only() {
    let p = recipe("repo-audit-ro", &crb(true));
    let a = audit(&p, with_rocky(target()));
    assert_eq!(a.resources[0].status, AuditResourceStatus::Drift);
    for c in &a.commands {
        assert!(
            !is_mutation_command(&c.program, &c.args),
            "audit ran {} {:?}",
            c.program,
            c.args
        );
        let prog = c.program.rsplit('/').next().unwrap();
        assert!(
            !matches!(prog, "dnf" | "rpm" | "sh" | "tee" | "cp" | "install"),
            "audit ran {} {:?}",
            c.program,
            c.args
        );
    }
}

// ---------------------------------------------------------------------------
// observation failures are errors, never absence
// ---------------------------------------------------------------------------

#[test]
fn a_failed_or_short_read_is_an_error_and_nothing_is_written() {
    let p = recipe("repo-read-fail", &example());
    let existing = "[example]\nname=Example packages\nenabled=0\ngpgcheck=1\n";
    let short = Output {
        completion: Completion::Exited(0),
        stdout: b"[example]\n".to_vec(),
        stderr: Vec::new(),
        stdout_truncated: false,
        stderr_truncated: false,
    };
    let truncated = Output {
        completion: Completion::Exited(0),
        stdout: existing.as_bytes().to_vec(),
        stderr: Vec::new(),
        stdout_truncated: true,
        stderr_truncated: false,
    };
    for (what, program, out) in [
        (
            "cat fails",
            "cat",
            failing(1, "cat: read error: Input/output error"),
        ),
        ("cat is short", "cat", short),
        ("cat is truncated", "cat", truncated),
        (
            "stat fails",
            "stat",
            failing(1, "stat: cannot statx: Input/output error"),
        ),
    ] {
        for mode in [Mode::Plan, Mode::Apply] {
            let t = target()
                .with_fs_file(EXAMPLE, existing)
                .with_observations_at(program, EXAMPLE, vec![out.clone()]);
            match try_run_recipe_fake(&p, mode, false, t) {
                Err(_) => {}
                Ok(r) => {
                    assert_ne!(r.status, AggregateStatus::Success, "{what}");
                    assert_ne!(find(&r, "example").change, Change::Changed, "{what}");
                    assert_eq!(text(fs_of(&r), EXAMPLE), existing, "{what}");
                    assert_eq!(mutation_command_count(&r), 0, "{what}");
                }
            }
        }
    }
}

#[test]
fn a_refused_parent_directory_is_an_error() {
    let p = recipe("repo-parent", &example());
    for mode in [Mode::Plan, Mode::Apply] {
        let mut t = target();
        // Another account owns the directory and everyone may write to it.
        t.fs.as_mut().unwrap().mkdir_node(DIR, 0o777, 1001, 1001);
        let e = failure(&p, mode, t);
        assert!(e.contains(DIR), "{e}");
    }
}

#[test]
fn a_symlink_at_the_repository_file_is_refused_and_not_followed() {
    let p = recipe("repo-symlink", &example());
    let elsewhere = "/etc/app/elsewhere.repo";
    for mode in [Mode::Plan, Mode::Apply] {
        let mut t = target().with_fs_file(elsewhere, "[example]\nenabled=0\ngpgcheck=1\n");
        t.fs.as_mut().unwrap().put_symlink(EXAMPLE, elsewhere, 0, 0);
        let e = failure(&p, mode, t);
        assert!(e.contains("is a symlink; refusing to follow it"), "{e}");
    }
    let mut t = target().with_fs_file(elsewhere, "[example]\nenabled=0\ngpgcheck=1\n");
    t.fs.as_mut().unwrap().put_symlink(EXAMPLE, elsewhere, 0, 0);
    if let Ok(r) = try_run_recipe_fake(&p, Mode::Apply, false, t) {
        assert_eq!(
            text(fs_of(&r), elsewhere),
            "[example]\nenabled=0\ngpgcheck=1\n"
        );
        assert!(matches!(
            fs_of(&r).nodes[EXAMPLE].kind,
            FakeKind::Symlink(_)
        ));
    }
}

#[test]
fn a_file_that_is_ambiguous_is_refused_before_any_change() {
    let p = recipe("repo-ambiguous", &crb(true));
    for (content, want) in [
        (
            format!("{ROCKY_REPO}\n[crb]\nenabled=1\n"),
            "more than once",
        ),
        (
            ROCKY_REPO.replace(
                "countme=1\ngpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9\n\n# Debug",
                "countme=1\nenabled=1\n\n# Debug",
            ),
            "appears more than once",
        ),
        (
            ROCKY_REPO.replace("[crb-debug]", "[crb-debug"),
            "not a section header",
        ),
        (ROCKY_REPO.replace("\n", "\r\n"), "carriage return"),
    ] {
        for mode in [Mode::Plan, Mode::Apply] {
            let e = failure(&p, mode, target().with_fs_file(ROCKY, &content));
            assert!(e.contains(want) && e.contains("is not read"), "{want}: {e}");
        }
    }
}

#[test]
fn a_repository_missing_from_the_file_points_at_the_file_field() {
    let body = repo("crb", "      name: crb\n      enabled: true\n");
    let p = recipe("repo-nofile", &doc(&body));
    for t in [
        target(),
        with_rocky(target()).with_fs_file("/etc/yum.repos.d/crb.repo", "[other]\nenabled=0\n"),
    ] {
        let e = failure(&p, Mode::Plan, t);
        assert!(
            e.contains("set file to the file that defines the repository"),
            "{e}"
        );
    }
}

// ---------------------------------------------------------------------------
// concurrent change, partial failure, privilege
// ---------------------------------------------------------------------------

#[test]
fn a_file_replaced_between_observation_and_publication_is_not_overwritten() {
    let p = recipe("repo-race", &crb(true));
    let theirs = "[crb]\nenabled=0\ngpgcheck=1\n# edited by someone else\n";
    let mut refused = 0;
    for (program, arg) in [("sh", "stage"), ("sh", "publish"), ("sha256sum", ROCKY)] {
        let t = with_rocky(target()).with_fs_event(
            program,
            arg,
            0,
            vec![
                FsEventAction::Remove { path: ROCKY.into() },
                FsEventAction::PutFile {
                    path: ROCKY.into(),
                    data: theirs.as_bytes().to_vec(),
                    mode: 0o644,
                    uid: 0,
                    gid: 0,
                },
            ],
        );
        match try_run_recipe_fake(&p, Mode::Apply, false, t) {
            Err(_) => refused += 1,
            Ok(r) => {
                let now = text(fs_of(&r), ROCKY);
                if r.status != AggregateStatus::Success {
                    // Refused: the other writer's file is intact.
                    assert_eq!(now, theirs, "{program} {arg}");
                    assert_ne!(find(&r, "crb").change, Change::Changed);
                    refused += 1;
                } else {
                    // The event did not fall between observation and
                    // publication for this command; the run must then have
                    // worked on what it observed.
                    assert!(
                        now == theirs || now.contains("enabled=1"),
                        "{program} {arg}: {now}"
                    );
                }
            }
        }
    }
    assert!(refused >= 1, "no injected replacement was detected");
}

#[test]
fn a_failed_publication_is_reported_as_failure() {
    let p = recipe("repo-fault", &crb(true));
    for fault in [
        "before_publish",
        "rename_fail",
        "after_publish",
        "reobserve_fail",
    ] {
        let r = run_recipe_fake_fault(&p, Mode::Apply, false, with_rocky(target()), fault);
        assert_ne!(r.status, AggregateStatus::Success, "{fault}");
        let x = find(&r, "crb");
        assert_ne!(x.execution, Execution::Succeeded, "{fault}");
        assert_ne!(x.verification, Verification::Verified, "{fault}");
    }
    let r = run_recipe_fake_fault(
        &p,
        Mode::Apply,
        false,
        with_rocky(target()),
        "indeterminate_publish",
    );
    assert_eq!(r.status, AggregateStatus::Indeterminate);
    assert_eq!(find(&r, "crb").execution, Execution::Indeterminate);
}

#[test]
fn without_root_plan_says_that_root_is_needed() {
    let p = recipe("repo-noroot", &crb(true));
    let user = || with_rocky(dnf_target(FakeTarget::rocky9(), Some("dnf-3")));
    let r = plan(&p, user());
    let x = find(&r, "crb");
    assert_eq!(x.change, Change::Changed);
    assert_eq!(
        x.notes
            .iter()
            .filter(|n| n.starts_with("needs root"))
            .count(),
        1,
        "{:?}",
        x.notes
    );
    // (The scripted filesystem does not refuse a write by uid 1000, so the
    // operating system's refusal at apply is not shown here.)
    // With --sudo, or as root, there is no such note and apply changes the file.
    let r = run_recipe_fake(&p, Mode::Plan, true, user());
    assert!(!find(&r, "crb")
        .notes
        .iter()
        .any(|n| n.contains("needs root")));
    let r = run_recipe_fake(&p, Mode::Apply, true, user());
    assert_success(&r);
    assert!(text(fs_of(&r), ROCKY).contains("gpgcheck=1\nenabled=1\ncountme=1"));
    // The directory is the connecting user's own (an unusual host): the
    // path note has nothing to say, and the type's own note is given.
    let mut t = user();
    t.fs.as_mut().unwrap().mkdir_node(DIR, 0o755, 1000, 1000);
    let r = plan(&p, t);
    let x = find(&r, "crb");
    assert_eq!(
        x.notes
            .iter()
            .filter(|n| n.starts_with("needs root"))
            .count(),
        1
    );
    assert!(x
        .notes
        .iter()
        .any(|n| n.contains("changing a dnf_repository requires root privilege")));
}

#[test]
fn a_permission_denied_observation_is_an_error_not_an_absent_file() {
    let p = recipe("repo-denied", &example());
    let denied = failing(
        1,
        "stat: cannot statx '/etc/yum.repos.d/example.repo': Permission denied\n",
    );
    for mode in [Mode::Plan, Mode::Apply] {
        let t = dnf_target(FakeTarget::rocky9(), Some("dnf-3")).with_observations_at(
            "stat",
            EXAMPLE,
            vec![denied.clone(); 4],
        );
        let e = failure(&p, mode, t);
        assert!(e.contains("permission denied"), "{e}");
    }
    let t = dnf_target(FakeTarget::rocky9(), Some("dnf-3")).with_observations_at(
        "stat",
        EXAMPLE,
        vec![denied.clone(); 4],
    );
    let a = audit(&p, t);
    assert_eq!(a.resources[0].status, AuditResourceStatus::Error);
    let t = dnf_target(FakeTarget::rocky9(), Some("dnf-3")).with_observations_at(
        "stat",
        EXAMPLE,
        vec![denied; 4],
    );
    if let Ok(r) = try_run_recipe_fake(&p, Mode::Apply, false, t) {
        assert!(!fs_of(&r).nodes.contains_key(EXAMPLE));
    }
}

// ---------------------------------------------------------------------------
// load-time rules
// ---------------------------------------------------------------------------

#[test]
fn invalid_declarations_are_rejected_when_the_recipe_is_loaded() {
    let cases: Vec<(&str, String, &str)> = vec![
        ("no-name", repo("r", "      enabled: true\n"), "name"),
        ("bad-name", repo("r", "      name: \"bad name\"\n      enabled: true\n"), "valid repository id"),
        ("main", repo("r", "      name: main\n      enabled: true\n"), "DNF's own configuration section"),
        ("unknown", repo("r", "      name: x\n      sslverify: false\n"), "unknown field"),
        ("nothing", repo("r", "      name: x\n"), "declares nothing to manage"),
        ("state", repo("r", "      name: x\n      state: disabled\n"), "present or absent"),
        ("absent-extra", repo("r", "      name: x\n      state: absent\n      enabled: false\n"), "state absent allows only name and file"),
        ("file-dir", repo("r", "      name: x\n      file: /etc/dnf/x.repo\n      enabled: true\n"), "directly inside /etc/yum.repos.d/"),
        ("file-sub", repo("r", "      name: x\n      file: /etc/yum.repos.d/sub/x.repo\n      enabled: true\n"), "directly inside /etc/yum.repos.d/"),
        ("file-dots", repo("r", "      name: x\n      file: /etc/yum.repos.d/../x.repo\n      enabled: true\n"), "directly inside /etc/yum.repos.d/"),
        ("file-ext", repo("r", "      name: x\n      file: /etc/yum.repos.d/x.conf\n      enabled: true\n"), "ends in .repo"),
        ("enabled-type", repo("r", "      name: x\n      enabled: \"yes\"\n"), "enabled must be a boolean"),
        ("gpgcheck-off", repo("r", "      name: x\n      gpgcheck: false\n"), "never writes gpgcheck=0"),
        ("repo-gpgcheck-off", repo("r", "      name: x\n      repo_gpgcheck: false\n"), "never writes gpgcheck=0"),
        ("url-scheme", repo("r", "      name: x\n      baseurl: ftp://mirror.example.invalid/\n"), "must start with https://, http:// or file:///"),
        ("url-userinfo", repo("r", "      name: x\n      baseurl: https://user:synthetic-password@repo.example.invalid/\n"), "credentials in repository URLs are not supported"),
        ("url-user", repo("r", "      name: x\n      mirrorlist: http://user@repo.example.invalid/\n"), "credentials in repository URLs are not supported"),
        ("url-space", repo("r", "      name: x\n      metalink: \"https://repo.example.invalid/a b\"\n"), "printable ASCII"),
        ("url-newline", repo("r", "      name: x\n      baseurl: \"https://repo.example.invalid/\\nenabled=0\"\n"), "printable ASCII"),
        ("url-list-type", repo("r", "      name: x\n      baseurl: [1]\n"), "string or a list of strings"),
        ("key-http", repo("r", "      name: x\n      gpgkey: http://keys.example.invalid/key\n"), "file:/// or https://"),
        ("key-path", repo("r", "      name: x\n      gpgkey: /etc/pki/rpm-gpg/key\n"), "must start with file:/// or https://"),
        ("description", repo("r", "      name: x\n      description: \"two\\nlines\"\n"), "one line"),
    ];
    for (label, body, want) in cases {
        let e = load_err(&format!("repo-bad-{label}"), &doc(&body));
        assert!(e.contains(want), "{label}: {e}");
        assert!(!e.contains("synthetic-password"), "{label}: {e}");
    }
}

#[test]
fn a_value_from_a_variable_is_checked_when_it_is_evaluated() {
    let yaml =
        format!(
        "version: 1\nvars:\n  url:\n    value: \"ftp://mirror.example.invalid/\"\nresources:\n{}",
        repo("r", "      name: example\n      baseurl: \"{{ vars.url }}\"\n")
    );
    let p = recipe("repo-var-bad", &yaml);
    let e = failure(&p, Mode::Plan, target());
    assert!(
        e.contains("must start with https://, http:// or file:///"),
        "{e}"
    );
    // `name` and `file` may use variables; they are resolved at load.
    let yaml = format!(
        "version: 1\nvars:\n  id:\n    value: example\nresources:\n{}",
        repo("r", &format!("      name: \"{{{{ vars.id }}}}\"\n      file: \"/etc/yum.repos.d/{{{{ vars.id }}}}-extra.repo\"\n      baseurl: \"{URL}\"\n"))
    );
    let p = recipe("repo-var-name", &yaml);
    let r = apply(&p, target());
    assert_success(&r);
    assert!(text(fs_of(&r), "/etc/yum.repos.d/example-extra.repo").starts_with("[example]\n"));
    // An explicit null `file` is the default file.
    let p = recipe(
        "repo-null-file",
        &doc(&repo(
            "r",
            &format!("      name: example\n      file: null\n      baseurl: \"{URL}\"\n"),
        )),
    );
    let r = apply(&p, target());
    assert_success(&r);
    assert!(fs_of(&r).nodes.contains_key(EXAMPLE));
    let yaml = format!(
        "version: 1\nvars:\n  id:\n    value: \"../x\"\nresources:\n{}",
        repo("r", "      name: x\n      file: \"/etc/yum.repos.d/{{ vars.id }}.repo\"\n      enabled: true\n")
    );
    assert!(load_err("repo-var-file", &yaml).contains("directly inside /etc/yum.repos.d/"));
}

#[test]
fn conflicting_declarations_in_one_recipe_are_rejected() {
    let crb_a = repo(
        "a",
        &format!("      name: crb\n      file: {ROCKY}\n      enabled: true\n"),
    );
    let crb_b = repo("b", "      name: crb\n      enabled: false\n");
    let e = load_err("repo-dup-name", &doc(&format!("{crb_a}{crb_b}")));
    assert!(
        e.contains("conflicting ownership of DNF repository \"crb\""),
        "{e}"
    );

    let file = |path: &str| {
        format!(
            "  - id: f\n    type: file\n    with:\n      path: {path}\n      content: \"x\\n\"\n"
        )
    };
    for (label, body) in [
        ("file-first", format!("{}{crb_a}", file(ROCKY))),
        ("file-last", format!("{crb_a}{}", file(ROCKY))),
        ("default-file", format!("{crb_b}{}", file("/etc/yum.repos.d/crb.repo"))),
        (
            "link",
            format!("{crb_a}  - id: l\n    type: link\n    with:\n      path: {ROCKY}\n      target: /etc/app/x\n"),
        ),
        (
            "directory",
            format!("  - id: d\n    type: directory\n    with:\n      path: {ROCKY}\n{crb_a}"),
        ),
    ] {
        let e = load_err(&format!("repo-conflict-{label}"), &doc(&body));
        assert!(e.contains("conflicting ownership of path"), "{label}: {e}");
    }
    // Different repositories in one file, and a file resource elsewhere.
    let ok = format!(
        "{crb_a}{}{}",
        repo(
            "c",
            &format!("      name: crb-debug\n      file: {ROCKY}\n      enabled: false\n")
        ),
        file("/etc/yum.repos.d/other.repo")
    );
    sinter::model::load_model(&recipe("repo-no-conflict", &doc(&ok))).unwrap();
}

#[test]
fn toml_recipes_declare_the_same_resource() {
    let toml = format!(
        "version = 1\n\n[[resources]]\nid = \"example\"\ntype = \"dnf_repository\"\n\n[resources.with]\nname = \"example\"\ndescription = \"Example packages\"\nbaseurl = \"{URL}\"\ngpgcheck = true\ngpgkey = \"{KEY}\"\n"
    );
    let p = write_recipe(&trusted_root("repo-toml"), "r.toml", &toml);
    let r = apply(&p, target());
    assert_success(&r);
    assert_eq!(text(fs_of(&r), EXAMPLE), EXAMPLE_REPO);
}

// ---------------------------------------------------------------------------
// sensitive values
// ---------------------------------------------------------------------------

#[test]
fn a_sensitive_value_never_appears_in_plan_apply_or_audit_output() {
    let secret = "synthetic-token-0123456789";
    let yaml = format!(
        "version: 1\nvars:\n  token:\n    value: {secret}\n    sensitive: true\nresources:\n{}",
        repo(
            "example",
            "      name: example\n      baseurl: \"https://repo.example.invalid/{{ vars.token }}/\"\n      gpgcheck: true\n"
        )
    );
    let p = recipe("repo-sensitive", &yaml);
    let existing = "[example]\nbaseurl=https://repo.example.invalid/old/\nenabled=1\ngpgcheck=1\n";
    for mode in [Mode::Plan, Mode::Apply] {
        for t in [target(), target().with_fs_file(EXAMPLE, existing)] {
            let r = run_recipe_fake(&p, mode, false, t);
            assert_success(&r);
            let x = find(&r, "example");
            assert_eq!(x.change, Change::Changed);
            assert!(x.sensitive);
            let out = rendered(&r, mode);
            assert!(!out.contains(secret), "{out}");
            if mode == Mode::Apply {
                // The value is written; an existing file keeps its mode and
                // a new one is a normal repository file.
                let fs = fs_of(&r);
                assert!(text(fs, EXAMPLE).contains(secret));
                assert_eq!(fs.nodes[EXAMPLE].mode & 0o7777, 0o644);
            }
        }
    }
    let a = audit(&p, target().with_fs_file(EXAMPLE, existing));
    let x = &a.resources[0];
    assert_eq!(x.status, AuditResourceStatus::Drift);
    assert!(x.sensitive);
    assert_eq!(x.details[0].observed, "[redacted]");
    assert!(!rendered_audit(&a).contains(secret));
    assert!(!rendered_audit(&a).contains("repo.example.invalid/old"));
}

#[test]
fn credentials_already_in_the_file_never_appear_in_any_output() {
    let password = "synthetic-file-password-98765";
    let content = format!(
        "[private]\nname=Private\nbaseurl=https://builder:{password}@private.example.invalid/\nenabled=1\ngpgcheck=1\n\n[tools]\nname=Tools\nbaseurl=https://tools.example.invalid/\npassword={password}\nenabled=0\ngpgcheck=1\n"
    );
    let file = "/etc/yum.repos.d/private.repo";
    let body = repo(
        "tools",
        &format!("      name: tools\n      file: {file}\n      enabled: true\n      description: Tools (managed)\n"),
    );
    let p = recipe("repo-file-creds", &doc(&body));
    for mode in [Mode::Plan, Mode::Apply] {
        let r = run_recipe_fake(&p, mode, false, target().with_fs_file(file, &content));
        assert_success(&r);
        let x = find(&r, "tools");
        assert_eq!(x.change, Change::Changed);
        assert!(x.sensitive, "the result is not marked sensitive");
        if mode == Mode::Plan {
            assert!(matches!(x.diff.as_ref().unwrap().body, DiffBody::Redacted));
        }
        let out = rendered(&r, mode);
        assert!(
            !out.contains(password) && !out.contains("builder:"),
            "{out}"
        );
        if mode == Mode::Apply {
            let now = text(fs_of(&r), file);
            assert!(now.contains(&format!(
                "https://builder:{password}@private.example.invalid/"
            )));
            assert!(
                now.contains("name=Tools (managed)\n") && now.contains("enabled=1\ngpgcheck=1\n")
            );
        }
    }
    let a = audit(&p, target().with_fs_file(file, &content));
    let x = &a.resources[0];
    assert_eq!(x.status, AuditResourceStatus::Drift);
    assert!(x.details.iter().all(|d| d.observed == "[redacted]"));
    assert!(!rendered_audit(&a).contains(password));
    // A refusal names a line, never its content.
    let broken = format!("[tools]\npassword={password}\npassword={password}\n");
    let e = failure(&p, Mode::Plan, target().with_fs_file(file, &broken));
    assert!(e.contains("more than once") && !e.contains(password), "{e}");
}

#[test]
fn a_resource_declared_sensitive_withholds_the_details_of_a_refusal() {
    let body = "  - id: lab\n    type: dnf_repository\n    sensitive: true\n    with:\n      name: lab\n      enabled: true\n";
    let p = recipe("repo-sensitive-refusal", &doc(body));
    let file = "/etc/yum.repos.d/lab.repo";
    let section = "[lab]\nbaseurl=https://lab.example.invalid/\nenabled=0\ngpgcheck=0\n";
    for mode in [Mode::Plan, Mode::Apply] {
        let e = failure(&p, mode, target().with_fs_file(file, section));
        assert!(e.contains("details withheld"), "{e}");
        assert!(!e.contains(file) && !e.contains("gpgcheck"), "{e}");
    }
    let a = audit(
        &p,
        target().with_fs_file(file, "[lab]\nenabled=0\nenabled=1\n"),
    );
    assert_eq!(a.resources[0].status, AuditResourceStatus::Error);
    assert!(!rendered_audit(&a).contains("more than once"));
}

// ---------------------------------------------------------------------------
// platform
// ---------------------------------------------------------------------------

#[test]
fn hosts_without_dnf_4_are_refused_clearly() {
    let p = recipe("repo-platform", &example());
    type Make = Box<dyn Fn() -> FakeTarget>;
    let cases: Vec<(&str, Make, &str)> = vec![
        (
            "apt",
            Box::new(|| dnf_target(FakeTarget::ubuntu2404(), None).as_root()),
            "dnf_repository is not supported on this host (its package manager is not DNF)",
        ),
        (
            "dnf5",
            Box::new(|| dnf_target(FakeTarget::rocky9(), Some("dnf5")).as_root()),
            "it uses DNF 5",
        ),
        (
            "no dnf",
            Box::new(|| dnf_target(FakeTarget::rocky9(), None).as_root()),
            "the DNF generation cannot be told",
        ),
        (
            "other link",
            Box::new(|| dnf_target(FakeTarget::rocky9(), Some("/opt/tools/wrapper")).as_root()),
            "the DNF generation cannot be told",
        ),
    ];
    for (what, make, want) in cases {
        for mode in [Mode::Plan, Mode::Apply] {
            let e = failure(&p, mode, make());
            assert!(e.contains(want), "{what}: {e}");
        }
        let a = audit(&p, make());
        let x = &a.resources[0];
        assert_eq!(x.status, AuditResourceStatus::Error, "{what}");
        assert!(
            x.reason.as_deref().unwrap().contains(want),
            "{what}: {:?}",
            x.reason
        );
        if let Ok(r) = try_run_recipe_fake(&p, Mode::Apply, false, make()) {
            assert!(!fs_of(&r).nodes.contains_key(EXAMPLE), "{what}");
        }
    }
    // A regular /usr/bin/dnf is not guessed about either.
    let t = dnf_target(FakeTarget::rocky9(), None)
        .with_fs_file("/usr/bin/dnf", "#!/usr/bin/python3\n")
        .as_root();
    assert!(failure(&p, Mode::Plan, t).contains("the DNF generation cannot be told"));
    // Rocky Linux 10 (DNF 4) is supported like 9.
    let r = apply(
        &p,
        dnf_target(FakeTarget::rocky10(), Some("dnf-3")).as_root(),
    );
    assert_success(&r);
    assert_eq!(text(fs_of(&r), EXAMPLE), EXAMPLE_REPO);
}

// ---------------------------------------------------------------------------
// with package
// ---------------------------------------------------------------------------

/// The order repository -> package in one recipe. The scripted DNF does not
/// read `.repo` files, so this proves the order, that the repository file
/// is in place before the first package command, and that neither resource
/// disturbs the other; it does NOT prove that a package of the new
/// repository becomes installable (real-host check).
#[test]
fn a_package_that_depends_on_a_repository_runs_after_the_file_is_written() {
    let body = format!(
        "{}  - id: pkg\n    type: package\n    depends_on: [example]\n    with:\n      name: example-app\n      state: present\n",
        repo(
            "example",
            &format!("      name: example\n      baseurl: \"{URL}\"\n      gpgcheck: true\n      gpgkey: {KEY}\n")
        )
    );
    let p = recipe("repo-package", &doc(&body));
    let pl = plan(&p, target());
    assert_success(&pl);
    assert_eq!(find(&pl, "example").change, Change::Changed);
    assert_eq!(find(&pl, "pkg").change, Change::Changed);

    let r = apply(&p, target());
    assert_success(&r);
    assert_eq!(find(&r, "example").change, Change::Changed);
    let pkg = find(&r, "pkg");
    assert_eq!(pkg.change, Change::Changed);
    assert_eq!(pkg.verification, Verification::Verified);
    assert!(text(fs_of(&r), EXAMPLE).starts_with("[example]\n"));
    let first_dnf = r
        .commands
        .iter()
        .position(|c| c.program == "/usr/bin/dnf")
        .expect("the package ran dnf");
    let publish = r
        .commands
        .iter()
        .rposition(|c| c.program == "/bin/sh" && c.args.iter().any(|a| a == "publish"))
        .expect("the repository file was published");
    assert!(
        publish < first_dnf,
        "dnf ran before the repository file was written"
    );
}

#[test]
fn plan_defers_to_apply_when_an_earlier_change_may_provide_the_repository() {
    // A release package installs the repository file; the repository is then
    // enabled. Plan cannot see the file yet and must not fail.
    let body = format!(
        "  - id: release\n    type: package\n    with:\n      name: example-release\n      state: present\n{}",
        "  - id: testing\n    type: dnf_repository\n    depends_on: [release]\n    with:\n      name: example-testing\n      file: /etc/yum.repos.d/example.repo\n      enabled: true\n"
    );
    let p = recipe("repo-defer", &doc(&body));
    let r = plan(&p, target());
    let x = find(&r, "testing");
    assert!(x.unknown, "{x:?}");
    assert!(
        x.reason.as_deref().unwrap().contains("deferred to apply"),
        "{:?}",
        x.reason
    );
    // Without the earlier change the same state is an error.
    let body = "  - id: testing\n    type: dnf_repository\n    with:\n      name: example-testing\n      file: /etc/yum.repos.d/example.repo\n      enabled: true\n";
    let p = recipe("repo-nodefer", &doc(body));
    assert!(failure(&p, Mode::Plan, target())
        .contains("set file to the file that defines the repository"));
}

// ---------------------------------------------------------------------------
// audit findings: display, description, key source, handlers, hard links
// ---------------------------------------------------------------------------

#[test]
fn no_unmanaged_line_of_the_file_is_displayed() {
    // A private repository: a token in the URL path and a client
    // certificate, neither of them declared here. They lie between the two
    // lines this resource changes.
    let token = "TOKEN-synthetic-0123456789";
    let file = "/etc/yum.repos.d/tools.repo";
    let content = format!(
        "# UNMANAGED-COMMENT\n[tools]\nname=Tools\nbaseurl=https://tools.example.invalid/{token}/el9/\nsslclientcert=/etc/pki/synthetic-client.pem\nenabled=0\ngpgcheck=1\n\n[other]\nname=UNMANAGED-OTHER\nenabled=0\n"
    );
    let body = repo(
        "tools",
        &format!("      name: tools\n      file: {file}\n      enabled: true\n      description: Tools (managed)\n"),
    );
    let p = recipe("repo-unmanaged-lines", &doc(&body));
    let unmanaged = [
        token,
        "sslclientcert",
        "synthetic-client",
        "UNMANAGED",
        "baseurl",
    ];
    for mode in [Mode::Plan, Mode::Apply] {
        let r = run_recipe_fake(&p, mode, false, target().with_fs_file(file, &content));
        assert_success(&r);
        let x = find(&r, "tools");
        assert_eq!(x.change, Change::Changed);
        if mode == Mode::Plan {
            match &x.diff.as_ref().expect("a diff").body {
                DiffBody::Text { removed, added } => {
                    assert_eq!(removed, &["description: Tools", "enabled: 0"]);
                    assert_eq!(added, &["description: Tools (managed)", "enabled: 1"]);
                }
                other => panic!("unexpected diff {other:?}"),
            }
        }
        let out = rendered(&r, mode);
        for word in unmanaged {
            assert!(!out.contains(word), "{mode:?} shows {word}: {out}");
        }
    }
    let a = audit(&p, target().with_fs_file(file, &content));
    assert_eq!(a.resources[0].status, AuditResourceStatus::Drift);
    let dims: Vec<&str> = a.resources[0]
        .details
        .iter()
        .map(|d| d.dimension.as_str())
        .collect();
    assert_eq!(dims, ["description", "enabled"]);
    let out = rendered_audit(&a);
    for word in unmanaged {
        assert!(!out.contains(word), "audit shows {word}: {out}");
    }

    // A section that is created or removed: `state`, and for a new section
    // the declared keys. Nothing of the file around it.
    let r = plan(
        &recipe("repo-unmanaged-new", &example()),
        target().with_fs_file(EXAMPLE, "[other]\nname=UNMANAGED-OTHER\nenabled=0\n"),
    );
    match &find(&r, "example").diff.as_ref().expect("a diff").body {
        DiffBody::Text { removed, added } => {
            assert_eq!(removed, &["state: absent"]);
            assert_eq!(added[0], "state: present");
            assert!(added.contains(&format!("baseurl: {URL}")), "{added:?}");
            assert!(added.contains(&"gpgcheck: 1".to_string()), "{added:?}");
        }
        other => panic!("unexpected diff {other:?}"),
    }
    assert!(!rendered(&r, Mode::Plan).contains("UNMANAGED"));
    let gone = doc(&repo(
        "tools",
        &format!("      name: tools\n      file: {file}\n      state: absent\n"),
    ));
    let r = plan(
        &recipe("repo-unmanaged-gone", &gone),
        target().with_fs_file(file, &content),
    );
    match &find(&r, "tools").diff.as_ref().expect("a diff").body {
        DiffBody::Text { removed, added } => {
            assert_eq!(removed, &["state: present"]);
            assert_eq!(added, &["state: absent"]);
        }
        other => panic!("unexpected diff {other:?}"),
    }
    let out = rendered(&r, Mode::Plan);
    for word in unmanaged {
        assert!(!out.contains(word), "removal shows {word}: {out}");
    }
}

#[test]
fn a_description_with_line_separators_or_bidi_controls_is_rejected() {
    // Written as YAML escapes, so the recipe text itself stays plain.
    for code in ["2028", "2029", "0085", "202A", "202E", "2066", "2069"] {
        let body = repo(
            "r",
            &format!("      name: example\n      description: \"a\\u{code}[evil]\"\n      baseurl: \"{URL}\"\n"),
        );
        let e = load_err(&format!("repo-desc-{code}"), &doc(&body));
        assert!(e.contains("description must be one line"), "U+{code}: {e}");
    }
    // From a variable: refused when it is evaluated, nothing is written.
    let body = format!(
        "version: 1\nvars:\n  d:\n    value: \"a\\u2028[evil]\"\nresources:\n{}",
        repo(
            "r",
            &format!("      name: example\n      description: \"{{{{ vars.d }}}}\"\n      baseurl: \"{URL}\"\n")
        )
    );
    let p = recipe("repo-desc-var", &body);
    match try_run_recipe_fake(&p, Mode::Apply, false, target()) {
        Err(e) => assert!(
            e.message.contains("description must be one line"),
            "{}",
            e.message
        ),
        Ok(r) => {
            assert_ne!(r.status, AggregateStatus::Success);
            assert!(!fs_of(&r).nodes.contains_key(EXAMPLE));
        }
    }
    // Ordinary non-ASCII text is a description.
    let body = repo(
        "r",
        &format!("      name: example\n      description: \"例のパッケージ\"\n      baseurl: \"{URL}\"\n"),
    );
    sinter::model::load_model(&recipe("repo-desc-ok", &doc(&body))).unwrap();
}

#[test]
fn a_key_fetched_over_http_is_rejected_at_load_and_at_evaluation() {
    let with_key = |key: &str| {
        repo(
            "r",
            &format!("      name: example\n      baseurl: \"{URL}\"\n      gpgkey: \"{key}\"\n"),
        )
    };
    let e = load_err(
        "repo-http-key",
        &doc(&with_key("http://keys.example.invalid/RPM-GPG-KEY-example")),
    );
    assert!(
        e.contains("gpgkey") && e.contains("file:/// or https://"),
        "{e}"
    );
    let body = format!(
        "version: 1\nvars:\n  k:\n    value: \"http://keys.example.invalid/RPM-GPG-KEY-example\"\nresources:\n{}",
        with_key("{{ vars.k }}")
    );
    let p = recipe("repo-http-key-var", &body);
    for mode in [Mode::Plan, Mode::Apply] {
        match try_run_recipe_fake(&p, mode, false, target()) {
            Err(e) => assert!(e.message.contains("file:/// or https://"), "{}", e.message),
            Ok(r) => {
                assert_ne!(r.status, AggregateStatus::Success);
                assert_eq!(mutation_command_count(&r), 0);
                assert!(!fs_of(&r).nodes.contains_key(EXAMPLE));
            }
        }
    }
}

#[test]
fn a_change_notifies_its_handler_and_no_change_does_not() {
    let yaml = format!(
        "version: 1\nresources:\n  - id: crb\n    type: dnf_repository\n    notify: [restart-app]\n    with:\n      name: crb\n      file: {ROCKY}\n      enabled: true\nhandlers:\n  - id: restart-app\n    service: myapp\n    action: restart\n"
    );
    let p = recipe("repo-handler", &yaml);
    let t = || with_rocky(target()).with_service("myapp", ("loaded", "active", "enabled"));
    let restarts = |r: &RunReport| {
        r.commands
            .iter()
            .filter(|c| c.program.ends_with("systemctl") && c.args.iter().any(|a| a == "restart"))
            .count()
    };
    let planned = plan(&p, t());
    assert_eq!(planned.handlers_pending, ["restart-app"]);
    assert_eq!(restarts(&planned), 0);
    let r = apply(&p, t());
    assert_success(&r);
    assert_eq!(find(&r, "crb").change, Change::Changed);
    assert_eq!(r.handlers_run.len(), 1);
    assert_eq!(restarts(&r), 1);
    // Already as declared: no handler.
    let mut again = t();
    again.fs = r.fake_fs.clone();
    let r = apply(&p, again);
    assert_success(&r);
    assert_eq!(find(&r, "crb").change, Change::None);
    assert!(r.handlers_run.is_empty());
    assert_eq!(restarts(&r), 0);
    // A refused change: no handler.
    let unchecked = "[crb]\nname=CRB\nenabled=0\n";
    let r = try_run_recipe_fake(
        &p,
        Mode::Apply,
        false,
        target()
            .with_fs_file(ROCKY, unchecked)
            .with_service("myapp", ("loaded", "active", "enabled")),
    );
    if let Ok(r) = r {
        assert_ne!(r.status, AggregateStatus::Success);
        assert!(r.handlers_run.is_empty());
        assert_eq!(restarts(&r), 0);
    }
}

#[test]
fn a_repository_file_with_a_second_hard_link_is_refused() {
    let p = recipe("repo-hardlink", &crb(true));
    let other = "/etc/yum.repos.d/rocky.repo.orig";
    let mk = || {
        let mut t = with_rocky(target());
        t.fs.as_mut().unwrap().put_hardlink(ROCKY, other);
        t
    };
    for mode in [Mode::Plan, Mode::Apply] {
        let e = failure(&p, mode, mk());
        assert!(e.contains("2 hard links"), "{mode:?}: {e}");
    }
    let r = try_run_recipe_fake(&p, Mode::Apply, false, mk());
    if let Ok(r) = r {
        assert_eq!(text(fs_of(&r), ROCKY), ROCKY_REPO);
        assert_eq!(text(fs_of(&r), other), ROCKY_REPO);
        assert_eq!(mutation_command_count(&r), 0);
    }
    let a = audit(&p, mk());
    assert_eq!(a.resources[0].status, AuditResourceStatus::Error);
}

#[test]
fn a_same_size_in_place_change_after_the_read_is_refused_by_content() {
    let p = recipe("repo-cas-content", &crb(true));
    let theirs = ROCKY_REPO.replace("countme=1", "countme=0");
    assert_eq!(theirs.len(), ROCKY_REPO.len());
    let mut t = with_rocky(target()).with_fs_event(
        "sha256sum",
        ROCKY,
        0,
        vec![FsEventAction::WriteInPlace {
            path: ROCKY.into(),
            data: theirs.as_bytes().to_vec(),
        }],
    );
    t.fs.as_mut().unwrap().freeze_mtime = true;
    match try_run_recipe_fake(&p, Mode::Apply, false, t) {
        Err(e) => assert!(
            e.message.contains("changed since it was read"),
            "{}",
            e.message
        ),
        Ok(r) => {
            assert_ne!(r.status, AggregateStatus::Success);
            let x = find(&r, "crb");
            assert_eq!(x.change, Change::None);
            assert!(
                x.reason
                    .as_deref()
                    .unwrap()
                    .contains("changed since it was read"),
                "{:?}",
                x.reason
            );
            assert_eq!(text(fs_of(&r), ROCKY), theirs);
            assert_eq!(mutation_command_count(&r), 0);
        }
    }
}
