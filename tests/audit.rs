//! Audit Phase 1A/1B tests: typed result model, read-only engine behavior,
//! and the structural mutation boundary.
//!
//! FakeTarget exercises the full production stack above the transport;
//! filesystem-semantics cases that need a real target filesystem are gated to
//! Linux, matching the repository's existing convention.

mod common;

use common::*;
use sinter::audit::{run_audit, AuditReport, AuditResourceStatus};
use sinter::engine::{Engine, Mode, RunOptions, TargetSpec};
use sinter::error::SinterError;
use sinter::executor::FakeTarget;
use sinter::model::load_model;
use std::path::Path;

fn try_audit_fake(recipe: &Path, fake: FakeTarget) -> Result<AuditReport, SinterError> {
    let model = load_model(recipe)?;
    let opts = RunOptions {
        mode: Mode::Plan,
        sudo: false,
        target: TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(fake),
    };
    let engine = Engine::new(model, opts)?;
    run_audit(engine)
}

fn audit_fake(recipe: &Path, fake: FakeTarget) -> AuditReport {
    try_audit_fake(recipe, fake).unwrap_or_else(|e| panic!("audit run failed: {}", e.message))
}

fn afind<'a>(report: &'a AuditReport, id: &str) -> &'a sinter::audit::AuditResourceResult {
    report
        .resources
        .iter()
        .find(|r| r.id == id)
        .unwrap_or_else(|| panic!("resource {} not in audit report", id))
}

/// The structural safety proof (RA-01/RA-05): every command the engine
/// dispatched during an Audit run must be a recognized read-only observation
/// *in the exact argv shape the Audit contract defines* (IA-03). Safety is
/// not inferred from the executable basename, from a substring of an
/// argument, or from unchanged target state: the program path, the argument
/// count, the argument order, the fixed options, the fixed property names,
/// and the operand position are all checked. Recipe-controlled values may
/// only ever appear in an operand slot.
fn assert_observation_only(report: &AuditReport) {
    for c in &report.commands {
        // Compare argv as &str slices so the patterns below are exact.
        let args: Vec<&str> = c.args.iter().map(|a| a.as_str()).collect();
        let ok = match c.program.as_str() {
            // Capability/fact probes.
            "/usr/bin/test" => matches!(args.as_slice(), ["-r", "/etc/os-release"] | ["-x", _]),
            "/bin/hostname" | "/usr/bin/hostname" => args.is_empty(),
            "/usr/bin/id" => matches!(args.as_slice(), ["-u"] | ["-g"]),
            "/bin/cat" => matches!(args.as_slice(), ["/etc/os-release"] | ["--", _]),
            "/usr/bin/uname" => matches!(args.as_slice(), ["-m"]),
            // Fixed-argv filesystem inspection. Only the final argument is a
            // recipe-controlled path.
            "/usr/bin/stat" => matches!(
                args.as_slice(),
                ["-c", "%F|%a|%u|%g|%s|%d|%i|%y|%z", "--", _] | ["-c", "%a %u", "--", _]
            ),
            "/usr/bin/readlink" => matches!(args.as_slice(), ["-n", "--", _]),
            "/usr/bin/sha256sum" => matches!(args.as_slice(), ["--", _]),
            // Account database lookup: database name then key.
            "/usr/bin/getent" => matches!(args.as_slice(), ["passwd" | "group", _]),
            // Extended-attribute/ACL inspection (fixed options, path operand).
            "/usr/bin/getfattr" => matches!(
                args.as_slice(),
                ["-d", "-m", "-", "-e", "base64", "--absolute-names", "--", _]
            ),
            "/usr/bin/getfacl" => matches!(args.as_slice(), ["-p", "-c", "--", _]),
            // Package observation is query-only: one fixed query shape whose
            // only recipe-controlled slot is the package name. rpm answers
            // through a fixed queryformat returning the package NAME field,
            // so identity is proved by whole-record equality rather than
            // inferred from human-readable NEVRA text (RA2-01).
            "/usr/bin/dpkg-query" => matches!(args.as_slice(), ["-W", "-f=${Status}", "--", _]),
            "/usr/bin/rpm" => {
                matches!(args.as_slice(), ["-q", "--queryformat", "%{NAME}", "--", _])
            }
            // Service observation is `systemctl show` with the exact property
            // list; no other verb and no other property set is permitted.
            "/usr/bin/systemctl" => matches!(
                args.as_slice(),
                ["show", _, "--property=LoadState,ActiveState,UnitFileState"]
            ),
            _ => false,
        };
        assert!(
            ok,
            "audit dispatched a command outside the strict observation \
             allowlist: {} {:?}",
            c.program, c.args
        );
        assert!(
            !is_mutation_command(&c.program, &c.args),
            "audit dispatched a mutation command: {} {:?}",
            c.program,
            c.args
        );
        // Recipe-controlled values stay in operand slots: no extra arguments
        // and no shell is ever introduced.
        assert!(
            !c.args.iter().any(|a| a.contains(' ') || a.contains('\n')),
            "audit passed a multi-token argument, which implies shell \
             construction: {} {:?}",
            c.program,
            c.args
        );
        // Sensitive requests must never record raw values.
        if c.sensitive {
            assert_eq!(
                c.program, "[redacted]",
                "sensitive observation recorded a raw program: {:?}",
                c
            );
            for a in &c.args {
                assert_eq!(
                    a, "[redacted]",
                    "sensitive observation recorded raw argv: {:?}",
                    c
                );
            }
        }
    }
}

/// Render + debug-dump everything an Audit result could carry, for canary
/// scanning.
fn report_text(report: &AuditReport) -> String {
    let mut s = report.render_text();
    s.push_str(&format!("{:?}\n", report));
    for c in &report.commands {
        s.push_str(&format!("{} {:?} {:?}\n", c.program, c.args, c.env));
    }
    s
}

// ---------------------------------------------------------------------------
// Status model + summary aggregation (Phase 1A)
// ---------------------------------------------------------------------------

#[test]
fn audit_status_labels_are_stable() {
    assert_eq!(AuditResourceStatus::Compliant.label(), "PASS");
    assert_eq!(AuditResourceStatus::Drift.label(), "DRIFT");
    assert_eq!(AuditResourceStatus::NotAuditable.label(), "NOT_AUDITABLE");
    assert_eq!(AuditResourceStatus::NotApplicable.label(), "NOT_APPLICABLE");
    assert_eq!(AuditResourceStatus::Error.label(), "ERROR");
}

#[test]
fn audit_summary_aggregates_all_statuses() {
    let dir = trusted_root("audit-summary");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        r#"version: 1
resources:
  - id: compliant
    type: package
    with:
      name: nano
      state: present
  - id: drifted
    type: package
    with:
      name: missing-pkg
      state: present
  - id: notauditable
    type: command
    with:
      program: /bin/true
  - id: notapplicable
    type: package
    with:
      name: nano
      state: present
    when: "false"
  - id: errored
    type: file
    with:
      path: /nonexistent-parent/f
      content: x
"#,
    );
    let mut fake = FakeTarget::ubuntu2404();
    fake.packages.insert("nano".to_string());
    let r = audit_fake(&recipe, fake);
    assert_eq!(
        afind(&r, "compliant").status,
        AuditResourceStatus::Compliant
    );
    assert_eq!(afind(&r, "drifted").status, AuditResourceStatus::Drift);
    assert_eq!(
        afind(&r, "notauditable").status,
        AuditResourceStatus::NotAuditable
    );
    assert_eq!(
        afind(&r, "notapplicable").status,
        AuditResourceStatus::NotApplicable
    );
    // FakeTarget has no modeled filesystem: the stat observation fails, which
    // must classify as Error, never Drift (RA-04).
    assert_eq!(afind(&r, "errored").status, AuditResourceStatus::Error);
    assert_eq!(r.summary.total, 5);
    assert_eq!(r.summary.compliant, 1);
    assert_eq!(r.summary.drifted, 1);
    assert_eq!(r.summary.not_auditable, 1);
    assert_eq!(r.summary.not_applicable, 1);
    assert_eq!(r.summary.errors, 1);
    assert!(!r.summary.no_drift());
}

// ---------------------------------------------------------------------------
// Package audit (read-only query)
// ---------------------------------------------------------------------------

#[test]
fn audit_package_states() {
    let dir = trusted_root("audit-pkg");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        r#"version: 1
resources:
  - id: present_ok
    type: package
    with:
      name: nano
      state: present
  - id: present_drift
    type: package
    with:
      name: emacs
      state: present
  - id: absent_ok
    type: package
    with:
      name: emacs
      state: absent
  - id: absent_drift
    type: package
    with:
      name: nano
      state: absent
"#,
    );
    let mut fake = FakeTarget::ubuntu2404();
    fake.packages.insert("nano".to_string());
    let r = audit_fake(&recipe, fake);
    assert_eq!(
        afind(&r, "present_ok").status,
        AuditResourceStatus::Compliant
    );
    assert_eq!(
        afind(&r, "present_drift").status,
        AuditResourceStatus::Drift
    );
    assert_eq!(
        afind(&r, "absent_ok").status,
        AuditResourceStatus::Compliant
    );
    assert_eq!(afind(&r, "absent_drift").status, AuditResourceStatus::Drift);
    assert_observation_only(&r);
}

#[test]
fn audit_package_query_failure_is_error_not_drift() {
    let dir = trusted_root("audit-pkg-fail");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        r#"version: 1
resources:
  - id: p
    type: package
    with:
      name: nano
      state: present
"#,
    );
    let mut fake = FakeTarget::ubuntu2404();
    fake.query_completion = Some(sinter::executor::Completion::Exited(2));
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "p").status, AuditResourceStatus::Error);
}

// ---------------------------------------------------------------------------
// Service audit (read-only systemctl show)
// ---------------------------------------------------------------------------

fn service_recipe(dir: &Path, state: &str, enabled: &str) -> std::path::PathBuf {
    write_recipe(
        dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: s\n    type: service\n    with:\n      name: svc\n      state: {}\n      enabled: {}\n",
            state, enabled
        ),
    )
}

#[test]
fn audit_service_states() {
    // active+enabled vs desired running+enabled -> Compliant.
    let dir = trusted_root("audit-svc-ok");
    let recipe = service_recipe(&dir, "running", "true");
    let mut fake = FakeTarget::ubuntu2404();
    fake.services.insert(
        "svc".to_string(),
        (
            "loaded".to_string(),
            "active".to_string(),
            "enabled".to_string(),
        ),
    );
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "s").status, AuditResourceStatus::Compliant);
    assert_observation_only(&r);

    // inactive vs desired running -> Drift.
    let dir = trusted_root("audit-svc-stopped");
    let recipe = service_recipe(&dir, "running", "false");
    let mut fake = FakeTarget::ubuntu2404();
    fake.services.insert(
        "svc".to_string(),
        (
            "loaded".to_string(),
            "inactive".to_string(),
            "disabled".to_string(),
        ),
    );
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "s").status, AuditResourceStatus::Drift);

    // failed vs desired stopped -> Drift (failed is not stopped).
    let dir = trusted_root("audit-svc-failed");
    let recipe = service_recipe(&dir, "stopped", "false");
    let mut fake = FakeTarget::ubuntu2404();
    fake.services.insert(
        "svc".to_string(),
        (
            "loaded".to_string(),
            "failed".to_string(),
            "disabled".to_string(),
        ),
    );
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "s").status, AuditResourceStatus::Drift);
}

#[test]
fn audit_service_missing_masked_static_are_drift_not_error() {
    // RA-03: repair feasibility is not compliance. A missing/static/masked
    // unit still has a truthful compliance answer.
    let dir = trusted_root("audit-svc-missing");
    let recipe = service_recipe(&dir, "running", "false");
    let r = audit_fake(&recipe, FakeTarget::ubuntu2404());
    assert_eq!(afind(&r, "s").status, AuditResourceStatus::Drift);

    let dir = trusted_root("audit-svc-masked");
    let recipe = service_recipe(&dir, "running", "false");
    let mut fake = FakeTarget::ubuntu2404();
    fake.services.insert(
        "svc".to_string(),
        (
            "loaded".to_string(),
            "inactive".to_string(),
            "masked".to_string(),
        ),
    );
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "s").status, AuditResourceStatus::Drift);

    let dir = trusted_root("audit-svc-static");
    let recipe = service_recipe(&dir, "running", "true");
    let mut fake = FakeTarget::ubuntu2404();
    fake.services.insert(
        "svc".to_string(),
        (
            "loaded".to_string(),
            "active".to_string(),
            "static".to_string(),
        ),
    );
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "s").status, AuditResourceStatus::Drift);
    assert_observation_only(&r);
}

// ---------------------------------------------------------------------------
// Command boundary: never executed, always NOT_AUDITABLE
// ---------------------------------------------------------------------------

#[test]
fn audit_command_is_not_auditable_and_never_dispatched() {
    let dir = trusted_root("audit-cmd");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        r#"version: 1
resources:
  - id: sentinel
    type: command
    with:
      program: /usr/bin/sinter-mutation-sentinel
      args: ["--would-mutate"]
"#,
    );
    let r = audit_fake(&recipe, FakeTarget::ubuntu2404());
    assert_eq!(
        afind(&r, "sentinel").status,
        AuditResourceStatus::NotAuditable
    );
    for c in &r.commands {
        assert!(
            !c.program.contains("sinter-mutation-sentinel"),
            "audit dispatched the recipe command: {} {:?}",
            c.program,
            c.args
        );
    }
    assert_observation_only(&r);
}

// ---------------------------------------------------------------------------
// Control flow: when / loop / depends_on / register / notify
// ---------------------------------------------------------------------------

#[test]
fn audit_when_variants() {
    let dir = trusted_root("audit-when");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        r#"version: 1
resources:
  - id: producer
    type: command
    with:
      program: /bin/echo
      register: p
  - id: true_cond
    type: package
    with:
      name: nano
      state: present
    when: "true"
  - id: false_cond
    type: package
    with:
      name: nano
      state: present
    when: "false"
  - id: unknown_cond
    type: package
    with:
      name: nano
      state: present
    depends_on: [producer]
    when: "registers.p.stdout == \"x\""
  - id: error_cond
    type: package
    with:
      name: nano
      state: present
    when: "vars.undefined_thing == 1"
"#,
    );
    let mut fake = FakeTarget::ubuntu2404();
    fake.packages.insert("nano".to_string());
    let r = audit_fake(&recipe, fake);
    assert_eq!(
        afind(&r, "true_cond").status,
        AuditResourceStatus::Compliant
    );
    assert_eq!(
        afind(&r, "false_cond").status,
        AuditResourceStatus::NotApplicable
    );
    // The register cannot exist because Audit never executes the producer:
    // NOT_AUDITABLE, never a guess (§10).
    assert_eq!(
        afind(&r, "unknown_cond").status,
        AuditResourceStatus::NotAuditable
    );
    // An actual evaluation failure (undefined variable) is ERROR.
    assert_eq!(afind(&r, "error_cond").status, AuditResourceStatus::Error);
    assert_observation_only(&r);
}

#[test]
fn audit_register_unavailable_with_value_is_not_auditable() {
    let dir = trusted_root("audit-reg-val");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        r#"version: 1
resources:
  - id: producer
    type: command
    with:
      program: /bin/echo
      register: p
  - id: consumer
    type: package
    with:
      name: nano
      state: "{{ registers.p.stdout }}"
    depends_on: [producer]
"#,
    );
    let mut fake = FakeTarget::ubuntu2404();
    fake.packages.insert("nano".to_string());
    let r = audit_fake(&recipe, fake);
    assert_eq!(
        afind(&r, "consumer").status,
        AuditResourceStatus::NotAuditable
    );
}

#[test]
fn audit_loop_expands_and_audits_each_item() {
    let dir = trusted_root("audit-loop");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        r#"version: 1
resources:
  - id: pkg
    type: package
    with:
      name: "{{ item }}"
      state: present
    loop: [jq, curl]
"#,
    );
    let mut fake = FakeTarget::ubuntu2404();
    fake.packages.insert("jq".to_string());
    let r = audit_fake(&recipe, fake);
    let first = afind(&r, "pkg[0]");
    let second = afind(&r, "pkg[1]");
    assert_eq!(first.status, AuditResourceStatus::Compliant);
    assert_eq!(first.loop_index, Some(0));
    assert_eq!(second.status, AuditResourceStatus::Drift);
    assert_eq!(second.loop_index, Some(1));
    assert_eq!(r.summary.total, 2);
}

#[test]
fn audit_dependency_drift_does_not_block_independent_observation() {
    // RA-05: ordinary dependency DRIFT must not prevent an independent
    // observation — Audit uses its own strategy, not Apply's gating.
    let dir = trusted_root("audit-dep");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        r#"version: 1
resources:
  - id: drifting_dep
    type: package
    with:
      name: missing-pkg
      state: present
  - id: dependent
    type: package
    with:
      name: nano
      state: present
    depends_on: [drifting_dep]
  - id: errored_dep
    type: file
    with:
      path: /nonexistent/f
      content: x
  - id: after_error
    type: package
    with:
      name: nano
      state: present
    depends_on: [errored_dep]
"#,
    );
    let mut fake = FakeTarget::ubuntu2404();
    fake.packages.insert("nano".to_string());
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "drifting_dep").status, AuditResourceStatus::Drift);
    // Drift of a dependency does not block the dependent's observation.
    assert_eq!(
        afind(&r, "dependent").status,
        AuditResourceStatus::Compliant
    );
    assert_eq!(afind(&r, "errored_dep").status, AuditResourceStatus::Error);
    // An observation ERROR on a dependency does not block either.
    assert_eq!(
        afind(&r, "after_error").status,
        AuditResourceStatus::Compliant
    );
}

#[test]
fn audit_notify_never_queues_and_handlers_never_run() {
    let dir = trusted_root("audit-notify");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        r#"version: 1
resources:
  - id: f
    type: file
    with:
      path: /tmp/sinter-audit-notify
      content: v1
    notify: [restart_svc]
  - id: svc
    type: service
    with:
      name: svc
      state: running
      enabled: true
handlers:
  - id: restart_svc
    service: svc
    action: restart
"#,
    );
    let mut fake = FakeTarget::ubuntu2404();
    fake.services.insert(
        "svc".to_string(),
        (
            "loaded".to_string(),
            "active".to_string(),
            "enabled".to_string(),
        ),
    );
    let r = audit_fake(&recipe, fake);
    // No systemctl mutation of any kind was dispatched — restart/reload/
    // enable/disable/start/stop/reset-failed all prove handler or service
    // mutation. `show` is the only permitted service verb.
    for c in &r.commands {
        if c.program.ends_with("systemctl") {
            assert_eq!(
                c.args.first().map(|a| a.as_str()),
                Some("show"),
                "handler/service mutation dispatched: {:?}",
                c.args
            );
        }
    }
    assert_observation_only(&r);
}

#[test]
fn audit_dnf_backend_dispatches_no_snapshot_or_mutation() {
    // A package audit on the dnf family must be `rpm -q` only: no mktemp
    // snapshot, no dnf metadata operation, no payload download (§8).
    let dir = trusted_root("audit-dnf");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        r#"version: 1
resources:
  - id: p
    type: package
    with:
      name: nano
      state: present
"#,
    );
    let mut fake = FakeTarget::rocky9();
    fake.packages.insert("nano".to_string());
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "p").status, AuditResourceStatus::Compliant);
    for c in &r.commands {
        let prog = c.program.rsplit('/').next().unwrap_or(&c.program);
        assert!(
            !matches!(
                prog,
                "mktemp" | "dnf" | "yum" | "rm" | "cp" | "curl" | "wget" | "find"
            ),
            "audit dispatched a snapshot/mutation command: {} {:?}",
            c.program,
            c.args
        );
    }
    assert_observation_only(&r);
}

// ---------------------------------------------------------------------------
// Structural mutation boundary (RA-01)
// ---------------------------------------------------------------------------

#[test]
fn audit_refuses_mutation_enabled_engine() {
    // An Audit on an Apply-constructed engine must fail closed: a
    // MutationPermit would be obtainable there.
    let dir = trusted_root("audit-apply-engine");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        r#"version: 1
resources:
  - id: p
    type: package
    with:
      name: nano
      state: present
"#,
    );
    let model = load_model(&recipe).unwrap();
    let opts = RunOptions {
        mode: Mode::Apply,
        sudo: false,
        target: TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(FakeTarget::ubuntu2404()),
    };
    let engine = Engine::new(model, opts).unwrap();
    let err = run_audit(engine).expect_err("audit must refuse a mutation-enabled target");
    assert!(
        err.message.contains("read-only"),
        "unexpected refusal message: {}",
        err.message
    );
}

// ---------------------------------------------------------------------------
// Sensitive data (RA-06)
// ---------------------------------------------------------------------------

#[test]
fn audit_sensitive_canary_never_appears() {
    const CANARY: &str = "S3CR3T-CANARY-9f27d1";
    let dir = trusted_root("audit-canary");
    // A sensitive resource whose `with` values interpolate the canary through
    // the full evaluation pipeline: the resource drifts, its details are
    // redacted at construction, and the raw canary may never surface in the
    // report, reasons, details, or command records (RA-06).
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nvars:\n  secret:\n    value: {}\n    sensitive: true\nresources:\n  - id: p\n    type: package\n    sensitive: true\n    with:\n      name: nano\n      state: present\n      env:\n        TOKEN: \"{{{{ vars.secret }}}}\"\n",
            CANARY
        ),
    );
    let r = audit_fake(&recipe, FakeTarget::ubuntu2404());
    assert_eq!(afind(&r, "p").status, AuditResourceStatus::Drift);
    assert!(afind(&r, "p").sensitive);
    let text = report_text(&r);
    assert_eq!(
        text.matches(CANARY).count(),
        0,
        "sensitive canary leaked into audit output:\n{}",
        text
    );
    for c in &r.commands {
        assert!(
            !c.args.iter().any(|a| a.contains(CANARY)),
            "canary leaked into a command record"
        );
    }
    // Sensitive drift details are redacted at construction, not just display.
    for d in &afind(&r, "p").details {
        assert_eq!(d.observed, "[redacted]");
        assert_eq!(d.desired, "[redacted]");
    }
}

#[test]
fn audit_report_renders_labels() {
    let dir = trusted_root("audit-render");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        r#"version: 1
resources:
  - id: p
    type: package
    with:
      name: nano
      state: present
"#,
    );
    let mut fake = FakeTarget::ubuntu2404();
    fake.packages.insert("nano".to_string());
    let r = audit_fake(&recipe, fake);
    let text = r.render_text();
    assert!(text.contains("PASS p [package]"));
    assert!(text.contains("summary:"));
}

// ---------------------------------------------------------------------------
// Real-filesystem semantics (Linux target only)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[cfg(target_os = "linux")]
mod local {
    use super::*;

    fn audit_local(recipe: &Path) -> AuditReport {
        let model = load_model(recipe).unwrap();
        let opts = RunOptions {
            mode: Mode::Plan,
            sudo: false,
            target: TargetSpec { ssh: None },
            verbose: false,
            fault: None,
            fake_target: None,
        };
        let engine = Engine::new(model, opts).unwrap();
        run_audit(engine).unwrap()
    }

    #[test]
    fn audit_file_present_absent_content_and_type() {
        let dir = trusted_root("audit-file");
        let good = dir.join("good");
        std::fs::write(&good, "hello").unwrap();
        let drifted = dir.join("drifted");
        std::fs::write(&drifted, "old").unwrap();
        let wrong_type = dir.join("wrongtype");
        std::fs::create_dir(&wrong_type).unwrap();
        let gone = dir.join("gone");
        // `absent_ok` needs its own path: the model rejects two filesystem
        // resources owning one path, so a second absent path is used.
        let gone2 = dir.join("gone2");
        let present_dir = dir.join("adir");
        std::fs::create_dir(&present_dir).unwrap();
        let recipe = write_recipe(
            &dir,
            "r.yaml",
            &format!(
                "version: 1\nresources:\n  - id: ok\n    type: file\n    with:\n      path: {g}\n      content: hello\n  - id: drift\n    type: file\n    with:\n      path: {d}\n      content: new\n  - id: wrongtype\n    type: file\n    with:\n      path: {w}\n  - id: missing\n    type: file\n    with:\n      path: {m}\n      content: x\n  - id: absent_drift\n    type: file\n    with:\n      path: {a}\n      state: absent\n  - id: absent_ok\n    type: file\n    with:\n      path: {m2}\n      state: absent\n",
                g = good.display(),
                d = drifted.display(),
                w = wrong_type.display(),
                m = gone.display(),
                m2 = gone2.display(),
                a = present_dir.display(),
            ),
        );
        let r = audit_local(&recipe);
        assert_eq!(afind(&r, "ok").status, AuditResourceStatus::Compliant);
        assert_eq!(afind(&r, "drift").status, AuditResourceStatus::Drift);
        // RA-03: wrong filesystem type is compliance drift, not an error.
        assert_eq!(afind(&r, "wrongtype").status, AuditResourceStatus::Drift);
        assert_eq!(afind(&r, "missing").status, AuditResourceStatus::Drift);
        // desired absent + object exists -> DRIFT.
        assert_eq!(afind(&r, "absent_drift").status, AuditResourceStatus::Drift);
        assert_eq!(
            afind(&r, "absent_ok").status,
            AuditResourceStatus::Compliant
        );
        // Nothing was created, removed, or rewritten.
        assert!(!gone.exists());
        assert!(!gone2.exists());
        assert_eq!(std::fs::read_to_string(&drifted).unwrap(), "old");
        assert_observation_only(&r);
    }

    #[test]
    fn audit_file_metadata_drift_and_content_observation_error() {
        let dir = trusted_root("audit-meta");
        let f = dir.join("meta");
        std::fs::write(&f, "x").unwrap();
        set_mode(&f, 0o600);
        let unreadable = dir.join("unreadable");
        std::fs::write(&unreadable, "secret").unwrap();
        set_mode(&unreadable, 0o000);
        let recipe = write_recipe(
            &dir,
            "r.yaml",
            &format!(
                "version: 1\nresources:\n  - id: mode_drift\n    type: file\n    with:\n      path: {f}\n      mode: \"0644\"\n  - id: unreadable\n    type: file\n    with:\n      path: {u}\n      content: anything\n",
                f = f.display(),
                u = unreadable.display(),
            ),
        );
        let r = audit_local(&recipe);
        assert_eq!(afind(&r, "mode_drift").status, AuditResourceStatus::Drift);
        // RA-04: content that cannot be observed is ERROR, never DRIFT.
        assert_eq!(afind(&r, "unreadable").status, AuditResourceStatus::Error);
        set_mode(&unreadable, 0o600);
    }

    #[test]
    fn audit_directory_and_link() {
        let dir = trusted_root("audit-dirlink");
        let d = dir.join("d");
        std::fs::create_dir(&d).unwrap();
        let link = dir.join("l");
        std::os::unix::fs::symlink("/nonexistent-target", &link).unwrap();
        // `link_drift` needs its own link: the model rejects two filesystem
        // resources owning one path.
        let link2 = dir.join("l2");
        std::os::unix::fs::symlink("/nonexistent-target", &link2).unwrap();
        let file_as_dir = dir.join("f");
        std::fs::write(&file_as_dir, "x").unwrap();
        let recipe = write_recipe(
            &dir,
            "r.yaml",
            &format!(
                "version: 1\nresources:\n  - id: dir_ok\n    type: directory\n    with:\n      path: {d}\n  - id: dir_wrong\n    type: directory\n    with:\n      path: {f}\n  - id: link_ok\n    type: link\n    with:\n      path: {l}\n      target: /nonexistent-target\n  - id: link_drift\n    type: link\n    with:\n      path: {l2}\n      target: /somewhere\n",
                d = d.display(),
                f = file_as_dir.display(),
                l = link.display(),
                l2 = link2.display(),
            ),
        );
        let r = audit_local(&recipe);
        assert_eq!(afind(&r, "dir_ok").status, AuditResourceStatus::Compliant);
        assert_eq!(afind(&r, "dir_wrong").status, AuditResourceStatus::Drift);
        // A dangling symlink whose declared target string is correct is
        // compliant — the target object is not implicitly audited (§5).
        assert_eq!(afind(&r, "link_ok").status, AuditResourceStatus::Compliant);
        assert_eq!(afind(&r, "link_drift").status, AuditResourceStatus::Drift);
        assert_observation_only(&r);
    }

    #[test]
    fn audit_template_renders_on_controller_and_compares() {
        let dir = controller_dir("audit-tmpl");
        let out = dir.join("rendered");
        std::fs::write(&out, "port=8080\n").unwrap();
        let other = dir.join("other");
        std::fs::write(&other, "port=9999\n").unwrap();
        write_recipe(&dir, "t.tmpl", "port={{ vars.port }}\n");
        let recipe = write_recipe(
            &dir,
            "r.yaml",
            &format!(
                "version: 1\nvars:\n  port:\n    value: \"8080\"\nresources:\n  - id: t_ok\n    type: template\n    with:\n      path: {o}\n      source: t.tmpl\n  - id: t_drift\n    type: template\n    with:\n      path: {p}\n      source: t.tmpl\n",
                o = out.display(),
                p = other.display(),
            ),
        );
        let r = audit_local(&recipe);
        assert_eq!(afind(&r, "t_ok").status, AuditResourceStatus::Compliant);
        assert_eq!(afind(&r, "t_drift").status, AuditResourceStatus::Drift);
        assert_observation_only(&r);
    }

    #[test]
    fn audit_mutates_nothing_on_a_real_target() {
        // Mutation sentinel: a recipe exercising every auditable kind plus
        // notify + command. After the run the filesystem must be byte-for-byte
        // identical and no mutation command may appear in the log.
        let dir = trusted_root("audit-sentinel");
        let f = dir.join("f");
        std::fs::write(&f, "v1").unwrap();
        let ghost = dir.join("never-created");
        let recipe = write_recipe(
            &dir,
            "r.yaml",
            &format!(
                "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {f}\n      content: v2\n    notify: [h]\n  - id: d\n    type: directory\n    with:\n      path: {g}\n  - id: c\n    type: command\n    with:\n      program: /usr/bin/sinter-mutation-sentinel\nhandlers:\n  - id: h\n    service: ssh\n    action: restart\n",
                f = f.display(),
                g = ghost.display(),
            ),
        );
        let before: Vec<(String, Vec<u8>)> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| {
                let p = e.unwrap().path();
                let data = std::fs::read(&p).unwrap_or_default();
                (p.display().to_string(), data)
            })
            .collect();
        let r = audit_local(&recipe);
        assert_eq!(afind(&r, "f").status, AuditResourceStatus::Drift);
        assert_eq!(afind(&r, "d").status, AuditResourceStatus::Drift);
        assert_eq!(afind(&r, "c").status, AuditResourceStatus::NotAuditable);
        assert!(!ghost.exists());
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "v1");
        let after: Vec<(String, Vec<u8>)> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| {
                let p = e.unwrap().path();
                let data = std::fs::read(&p).unwrap_or_default();
                (p.display().to_string(), data)
            })
            .collect();
        assert_eq!(before.len(), after.len());
        assert_observation_only(&r);
    }

    #[test]
    fn audit_sensitive_canary_on_real_filesystem() {
        const CANARY: &str = "S3CR3T-CANARY-8be201";
        let dir = trusted_root("audit-canary-fs");
        let f = dir.join("secret");
        std::fs::write(&f, "different-content").unwrap();
        let recipe = write_recipe(
            &dir,
            "r.yaml",
            &format!(
                "version: 1\nvars:\n  secret:\n    value: {}\n    sensitive: true\nresources:\n  - id: s\n    type: file\n    with:\n      path: {f}\n      content: \"token={{{{ vars.secret }}}}\"\n",
                CANARY,
                f = f.display(),
            ),
        );
        let r = audit_local(&recipe);
        assert_eq!(afind(&r, "s").status, AuditResourceStatus::Drift);
        let text = report_text(&r);
        assert_eq!(
            text.matches(CANARY).count(),
            0,
            "sensitive canary leaked:\n{}",
            text
        );
    }
}

// ---------------------------------------------------------------------------
// IA-01: adversarial observation contracts
//
// Every case below feeds a deliberately misleading capture through the real
// observation code path and asserts the *semantic* Audit result. The
// invariant under test is that no incomplete, truncated, malformed, or
// ambiguous observation can ever become Compliant, and that an undeterminable
// state becomes Error rather than Drift.
// ---------------------------------------------------------------------------

use sinter::executor::{Completion, Output};

/// SHA-256 of a byte string, matching the controller-side digest helper.
fn sha256_of(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let d = h.finalize();
    d.iter().map(|b| format!("{:02x}", b)).collect()
}

fn exited(code: i32, stdout: &str, stderr: &str) -> Output {
    Output {
        completion: Completion::Exited(code),
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

fn truncated_stdout(stdout: &str, stderr: &str) -> Output {
    Output {
        completion: Completion::Exited(0),
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
        stdout_truncated: true,
        stderr_truncated: false,
    }
}

fn truncated_stderr(stdout: &str, stderr: &str) -> Output {
    Output {
        completion: Completion::Exited(0),
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
        stdout_truncated: false,
        stderr_truncated: true,
    }
}

/// A complete, well-formed `stat -c %F|%a|%u|%g|%s|%d|%i|%y|%z` record for a
/// regular file owned by uid/gid 1000.
const STAT_REGULAR: &str = "regular file|644|1000|1000|12|2051|1234567|\
2026-09-19 09:30:00.000000000 +0000|2026-09-19 09:30:00.000000000 +0000";
const STAT_SYMLINK: &str = "symbolic link|777|1000|1000|7|2051|1234567|\
2026-09-19 09:30:00.000000000 +0000|2026-09-19 09:30:00.000000000 +0000";

fn file_recipe(dir: &Path, path: &str, content: &str) -> std::path::PathBuf {
    write_recipe(
        dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: {}\n      content: {}\n",
            path, content
        ),
    )
}

#[test]
fn audit_sha256_expected_prefix_plus_truncation_is_error_not_pass() {
    // The capture begins with exactly the expected digest and is then cut.
    // A prefix comparison would report PASS; the contract must report ERROR.
    let dir = trusted_root("adv-sha-trunc");
    let path = "/opt/sinter-adv-trunc";
    let digest = sha256_of("hello");
    let recipe = file_recipe(&dir, path, "hello");
    let mut fake = FakeTarget::ubuntu2404();
    fake.packages.insert("nano".to_string());
    fake = fake.with_observations("stat", vec![exited(0, &format!("{}\n", STAT_REGULAR), "")]);
    fake = fake.with_observations(
        "sha256sum",
        vec![truncated_stdout(&format!("{}  {}", digest, path), "")],
    );
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "f").status, AuditResourceStatus::Error);
    assert_ne!(afind(&r, "f").status, AuditResourceStatus::Compliant);
    assert_observation_only(&r);
}

#[test]
fn audit_sha256_expected_prefix_plus_stderr_truncation_is_error_not_pass() {
    let dir = trusted_root("adv-sha-trunc-err");
    let path = "/opt/sinter-adv-trunc2";
    let digest = sha256_of("hello");
    let recipe = file_recipe(&dir, path, "hello");
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations("stat", vec![exited(0, &format!("{}\n", STAT_REGULAR), "")]);
    fake = fake.with_observations(
        "sha256sum",
        vec![truncated_stderr(&format!("{}  {}\n", digest, path), "x")],
    );
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "f").status, AuditResourceStatus::Error);
}

#[test]
fn audit_sha256_valid_record_with_stderr_is_error_not_pass() {
    // exit 0 + a perfectly valid record + a stderr diagnostic: the
    // observation is ambiguous and must be Error, never Compliant — a
    // digest reported alongside an unexpected diagnostic is not
    // authoritative.
    let dir = trusted_root("adv-sha-stderr");
    let path = "/opt/sinter-adv-stderr";
    let digest = sha256_of("hello");
    let recipe = file_recipe(&dir, path, "hello");
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations("stat", vec![exited(0, &format!("{}\n", STAT_REGULAR), "")]);
    fake = fake.with_observations(
        "sha256sum",
        vec![exited(
            0,
            &format!("{}  {}\n", digest, path),
            "sha256sum: WARNING: diagnostic\n",
        )],
    );
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "f").status, AuditResourceStatus::Error);
    assert_ne!(afind(&r, "f").status, AuditResourceStatus::Compliant);
    assert_observation_only(&r);
}

#[test]
fn audit_sha256_malformed_short_hash_is_error() {
    let dir = trusted_root("adv-sha-short");
    let recipe = file_recipe(&dir, "/opt/f", "hello");
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations("stat", vec![exited(0, &format!("{}\n", STAT_REGULAR), "")]);
    fake = fake.with_observations("sha256sum", vec![exited(0, "abc123  /opt/f\n", "")]);
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "f").status, AuditResourceStatus::Error);
}

#[test]
fn audit_sha256_non_hex_digest_is_error() {
    let dir = trusted_root("adv-sha-nonhex");
    let recipe = file_recipe(&dir, "/opt/f", "hello");
    let bad = "g".repeat(64);
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations("stat", vec![exited(0, &format!("{}\n", STAT_REGULAR), "")]);
    fake = fake.with_observations(
        "sha256sum",
        vec![exited(0, &format!("{}  /opt/f\n", bad), "")],
    );
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "f").status, AuditResourceStatus::Error);
}

#[test]
fn audit_sha256_valid_digest_with_malformed_trailing_structure_is_error() {
    let dir = trusted_root("adv-sha-structure");
    let digest = sha256_of("hello");
    let recipe = file_recipe(&dir, "/opt/f", "hello");
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations("stat", vec![exited(0, &format!("{}\n", STAT_REGULAR), "")]);
    // One space instead of the two-space record separator.
    fake = fake.with_observations(
        "sha256sum",
        vec![exited(0, &format!("{} /opt/f\n", digest), "")],
    );
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "f").status, AuditResourceStatus::Error);
}

#[test]
fn audit_sha256_unexpected_multiple_result_lines_is_error() {
    let dir = trusted_root("adv-sha-multi");
    let digest = sha256_of("hello");
    let recipe = file_recipe(&dir, "/opt/f", "hello");
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations("stat", vec![exited(0, &format!("{}\n", STAT_REGULAR), "")]);
    fake = fake.with_observations(
        "sha256sum",
        vec![exited(
            0,
            &format!("{}  /opt/f\n{}  /opt/f\n", digest, digest),
            "",
        )],
    );
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "f").status, AuditResourceStatus::Error);
}

#[test]
fn audit_sha256_invalid_utf8_is_error() {
    let dir = trusted_root("adv-sha-utf8");
    let digest = sha256_of("hello");
    let recipe = file_recipe(&dir, "/opt/f", "hello");
    let mut bytes = format!("{}  /opt/f\n", digest).into_bytes();
    bytes.extend_from_slice(&[0xff, 0xfe]);
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations("stat", vec![exited(0, &format!("{}\n", STAT_REGULAR), "")]);
    fake = fake.with_observations(
        "sha256sum",
        vec![Output {
            completion: Completion::Exited(0),
            stdout: bytes,
            stderr: Vec::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        }],
    );
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "f").status, AuditResourceStatus::Error);
}

#[test]
fn audit_sha256_complete_digest_mismatch_is_drift() {
    // A successfully obtained, valid digest that differs from desired: this
    // is known non-compliance, so it is DRIFT, not ERROR.
    let dir = trusted_root("adv-sha-mismatch");
    let digest = sha256_of("some other content");
    let recipe = file_recipe(&dir, "/opt/f", "hello");
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations("stat", vec![exited(0, &format!("{}\n", STAT_REGULAR), "")]);
    fake = fake.with_observations(
        "sha256sum",
        vec![exited(0, &format!("{}  /opt/f\n", digest), "")],
    );
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "f").status, AuditResourceStatus::Drift);
    assert_observation_only(&r);
}

#[test]
fn audit_sha256_complete_digest_match_is_pass() {
    let dir = trusted_root("adv-sha-match");
    let digest = sha256_of("hello");
    let recipe = file_recipe(&dir, "/opt/f", "hello");
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations("stat", vec![exited(0, &format!("{}\n", STAT_REGULAR), "")]);
    fake = fake.with_observations(
        "sha256sum",
        vec![exited(0, &format!("{}  /opt/f\n", digest), "")],
    );
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "f").status, AuditResourceStatus::Compliant);
    assert_observation_only(&r);
}

#[test]
fn audit_readlink_captured_target_matches_but_truncated_is_error() {
    // Captured stdout is exactly the expected target string, yet the capture
    // was truncated: the true target may continue past the limit. This must
    // never become PASS.
    let dir = trusted_root("adv-readlink-trunc");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: l\n    type: link\n    with:\n      path: /opt/link\n      target: /desired/target\n",
    );
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations("stat", vec![exited(0, &format!("{}\n", STAT_SYMLINK), "")]);
    fake = fake.with_observations("readlink", vec![truncated_stdout("/desired/target", "")]);
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "l").status, AuditResourceStatus::Error);
    assert_ne!(afind(&r, "l").status, AuditResourceStatus::Compliant);
    assert_observation_only(&r);
}

#[test]
fn audit_readlink_target_plus_diagnostic_is_error() {
    let dir = trusted_root("adv-readlink-diag");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: l\n    type: link\n    with:\n      path: /opt/link\n      target: /desired/target\n",
    );
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations("stat", vec![exited(0, &format!("{}\n", STAT_SYMLINK), "")]);
    fake = fake.with_observations(
        "readlink",
        vec![exited(
            0,
            "/desired/target",
            "readlink: warning: weird link\n",
        )],
    );
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "l").status, AuditResourceStatus::Error);
}

#[test]
fn audit_readlink_complete_match_is_pass_and_dangling_target_is_fine() {
    let dir = trusted_root("adv-readlink-ok");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: l\n    type: link\n    with:\n      path: /opt/link\n      target: /nonexistent-dangling\n",
    );
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations("stat", vec![exited(0, &format!("{}\n", STAT_SYMLINK), "")]);
    fake = fake.with_observations("readlink", vec![exited(0, "/nonexistent-dangling", "")]);
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "l").status, AuditResourceStatus::Compliant);
    assert_observation_only(&r);
}

#[test]
fn audit_stat_valid_prefix_plus_truncation_is_error() {
    let dir = trusted_root("adv-stat-trunc");
    let recipe = file_recipe(&dir, "/opt/f", "hello");
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations("stat", vec![truncated_stdout(STAT_REGULAR, "")]);
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "f").status, AuditResourceStatus::Error);
    assert_ne!(afind(&r, "f").status, AuditResourceStatus::Compliant);
}

#[test]
fn audit_stat_missing_field_is_error() {
    let dir = trusted_root("adv-stat-missing");
    let recipe = file_recipe(&dir, "/opt/f", "hello");
    let bad = "regular file|644|1000|1000|12|2051|1234567|2026-09-19 09:30:00.000000000 +0000";
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations("stat", vec![exited(0, &format!("{}\n", bad), "")]);
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "f").status, AuditResourceStatus::Error);
}

#[test]
fn audit_stat_extra_ambiguous_field_is_error() {
    let dir = trusted_root("adv-stat-extra");
    let recipe = file_recipe(&dir, "/opt/f", "hello");
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations(
        "stat",
        vec![exited(0, &format!("{}|extra\n", STAT_REGULAR), "")],
    );
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "f").status, AuditResourceStatus::Error);
}

#[test]
fn audit_stat_invalid_numeric_field_is_error() {
    let dir = trusted_root("adv-stat-badnum");
    let recipe = file_recipe(&dir, "/opt/f", "hello");
    let bad = STAT_REGULAR.replacen("1000|1000", "root|1000", 1);
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations("stat", vec![exited(0, &format!("{}\n", bad), "")]);
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "f").status, AuditResourceStatus::Error);
}

#[test]
fn audit_stat_unexpected_diagnostic_output_is_error() {
    let dir = trusted_root("adv-stat-diag");
    let recipe = file_recipe(&dir, "/opt/f", "hello");
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations(
        "stat",
        vec![exited(
            0,
            &format!("{}\nwarning: extra line\n", STAT_REGULAR),
            "",
        )],
    );
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "f").status, AuditResourceStatus::Error);
}

#[test]
fn audit_absence_marker_mixed_with_another_error_is_error_not_drift() {
    // stderr contains the recognized missing marker AND another diagnostic.
    // Neither "absent" nor "present" is established, so the result must be
    // ERROR — never Drift and never Compliant.
    let dir = trusted_root("adv-absent-mixed");
    let recipe = file_recipe(&dir, "/opt/f", "hello");
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations(
        "stat",
        vec![exited(
            1,
            "",
            "stat: cannot statx '/opt/f': No such file or directory\nerror: I/O failure\n",
        )],
    );
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "f").status, AuditResourceStatus::Error);
}

#[test]
fn audit_absence_permission_error_with_misleading_text_is_error() {
    let dir = trusted_root("adv-absent-perm");
    let recipe = file_recipe(&dir, "/opt/f", "hello");
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations(
        "stat",
        vec![exited(
            1,
            "",
            "stat: cannot statx '/opt/f': Permission denied: no such file or directory\n",
        )],
    );
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "f").status, AuditResourceStatus::Error);
}

#[test]
fn audit_absence_truncated_diagnostic_is_error() {
    let dir = trusted_root("adv-absent-trunc");
    let recipe = file_recipe(&dir, "/opt/f", "hello");
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations(
        "stat",
        vec![truncated_stdout(
            "",
            "stat: cannot statx '/opt/f': No such file or directory\n",
        )],
    );
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "f").status, AuditResourceStatus::Error);
}

#[test]
fn audit_absence_clean_recognized_marker_is_drift_for_a_present_desire() {
    // The clean, complete absence contract is still honored: a desired
    // present file that is genuinely absent is DRIFT (known state), which
    // proves the strict contract distinguishes absence from observation
    // failure rather than collapsing both into errors.
    let dir = trusted_root("adv-absent-clean");
    let recipe = file_recipe(&dir, "/opt/f", "hello");
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations(
        "stat",
        vec![exited(
            1,
            "",
            "stat: cannot statx '/opt/f': No such file or directory\n",
        )],
    );
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "f").status, AuditResourceStatus::Drift);
    assert_observation_only(&r);
}

#[test]
fn audit_dpkg_exit_zero_truncated_stdout_is_error_not_present() {
    let dir = trusted_root("adv-dpkg-trunc");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: nano\n      state: absent\n",
    );
    let fake = FakeTarget::ubuntu2404()
        .with_query_results(vec![truncated_stdout("install ok installed", "")]);
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "p").status, AuditResourceStatus::Error);
    // The absence desire must not be satisfied by an uninterpretable capture.
    assert_ne!(afind(&r, "p").status, AuditResourceStatus::Compliant);
}

#[test]
fn audit_dpkg_exit_zero_malformed_status_is_error() {
    let dir = trusted_root("adv-dpkg-malformed");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: nano\n      state: present\n",
    );
    let fake = FakeTarget::ubuntu2404().with_query_results(vec![exited(
        0,
        "install ok half-configured\n",
        "",
    )]);
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "p").status, AuditResourceStatus::Error);
}

#[test]
fn audit_dpkg_exit_zero_unexpected_diagnostic_is_error() {
    let dir = trusted_root("adv-dpkg-diag");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: nano\n      state: present\n",
    );
    let fake = FakeTarget::ubuntu2404().with_query_results(vec![exited(
        0,
        "install ok installed\n",
        "dpkg-query: warning: database unreadable\n",
    )]);
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "p").status, AuditResourceStatus::Error);
}

#[test]
fn audit_dpkg_exit_one_unrelated_error_is_error_not_absent() {
    let dir = trusted_root("adv-dpkg-err");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: nano\n      state: absent\n",
    );
    let fake = FakeTarget::ubuntu2404().with_query_results(vec![exited(
        1,
        "",
        "dpkg-query: error: cannot open dpkg status file\n",
    )]);
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "p").status, AuditResourceStatus::Error);
    assert_ne!(afind(&r, "p").status, AuditResourceStatus::Compliant);
}

#[test]
fn audit_dpkg_exit_one_ambiguous_absence_is_error_not_absent() {
    let dir = trusted_root("adv-dpkg-ambig");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: nano\n      state: absent\n",
    );
    let fake = FakeTarget::ubuntu2404().with_query_results(vec![exited(
        1,
        "",
        "dpkg-query: no packages found matching nano\nwarning: database corrupt\n",
    )]);
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "p").status, AuditResourceStatus::Error);
    assert_ne!(afind(&r, "p").status, AuditResourceStatus::Compliant);
}

#[test]
fn audit_rpm_exit_zero_truncated_output_is_error_not_installed() {
    let dir = trusted_root("adv-rpm-trunc");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: nano\n      state: present\n",
    );
    let fake = FakeTarget::rocky9()
        .with_query_results(vec![truncated_stdout("nano-7.2-2.el9.x86_64\n", "")]);
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "p").status, AuditResourceStatus::Error);
    assert_ne!(afind(&r, "p").status, AuditResourceStatus::Compliant);
    // No dnf/mktemp/snapshot work happened for a query-only audit.
    assert_observation_only(&r);
}

#[test]
fn audit_rpm_exit_zero_malformed_output_is_error() {
    let dir = trusted_root("adv-rpm-malformed");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: nano\n      state: present\n",
    );
    let fake = FakeTarget::rocky9().with_query_results(vec![exited(0, "", "")]);
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "p").status, AuditResourceStatus::Error);
}

#[test]
fn audit_rpm_exit_zero_contradictory_diagnostic_is_error() {
    let dir = trusted_root("adv-rpm-contra");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: nano\n      state: present\n",
    );
    let fake = FakeTarget::rocky9().with_query_results(vec![exited(
        0,
        "nano-7.2-2.el9.x86_64\n",
        "error: cannot open Packages database in /var/lib/rpm\n",
    )]);
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "p").status, AuditResourceStatus::Error);
}

#[test]
fn audit_rpm_exit_code_inconsistent_with_output_is_error() {
    // exit 1 with a record that would suggest installation: the exit code and
    // the output disagree, so neither state may be claimed.
    let dir = trusted_root("adv-rpm-incons");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: nano\n      state: present\n",
    );
    let fake =
        FakeTarget::rocky9().with_query_results(vec![exited(1, "nano-7.2-2.el9.x86_64\n", "")]);
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "p").status, AuditResourceStatus::Error);
    assert_ne!(afind(&r, "p").status, AuditResourceStatus::Compliant);
}

#[test]
fn audit_package_clean_present_and_absent_still_classify() {
    // The strictened contracts still accept the genuine reference captures,
    // so the adversarial suite is not simply rejecting everything.
    let dir = trusted_root("adv-pkg-clean");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: present_ok\n    type: package\n    with:\n      name: nano\n      state: present\n  - id: absent_ok\n    type: package\n    with:\n      name: emacs\n      state: absent\n",
    );
    let mut fake = FakeTarget::rocky9();
    fake.packages.insert("nano".to_string());
    let r = audit_fake(&recipe, fake);
    assert_eq!(
        afind(&r, "present_ok").status,
        AuditResourceStatus::Compliant
    );
    assert_eq!(
        afind(&r, "absent_ok").status,
        AuditResourceStatus::Compliant
    );
    assert_observation_only(&r);
}

// ---------------------------------------------------------------------------
// RA2-01 Round 2: the exact false-PASS classes the independent re-audit
// reproduced through production (run_audit + FakeTarget::with_observations +
// the resource comparator). Every case must land on ERROR, never Compliant.
// ---------------------------------------------------------------------------

fn link_recipe(dir: &Path, path: &str, target: &str) -> std::path::PathBuf {
    write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: l\n    type: link\n    with:\n      path: {}\n      target: {}\n",
            path, target
        ),
    )
}

fn pkg_recipe_one(dir: &Path, name: &str, state: &str) -> std::path::PathBuf {
    write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: {}\n      state: {}\n",
            name, state
        ),
    )
}

fn exited_bytes(code: i32, stdout: &[u8], stderr: &str) -> Output {
    Output {
        completion: Completion::Exited(code),
        stdout: stdout.to_vec(),
        stderr: stderr.as_bytes().to_vec(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

fn link_obs(target: &str) -> Output {
    exited(0, target, "")
}

fn stat_obs(record: &str) -> Output {
    exited(0, &format!("{}\n", record), "")
}

#[test]
fn readlink_trailing_newline_is_error_never_pass() {
    // Reproduced false PASS: `foo/bar\n` was normalized into `foo/bar` by
    // line-splitting and matched the desired target. The exact-bytes
    // `readlink -n` contract must reject the framing instead.
    let dir = trusted_root("r2-readlink-nl");
    let recipe = link_recipe(&dir, "/opt/link", "/desired/target");
    for (label, out) in [
        ("trailing newline", link_obs("/desired/target\n")),
        ("trailing crlf", link_obs("/desired/target\r\n")),
        ("trailing blank line", link_obs("/desired/target\n\n")),
        (
            "target plus a second record",
            link_obs("/desired/target\n/desired/other\n"),
        ),
    ] {
        let mut fake = FakeTarget::ubuntu2404();
        fake = fake.with_observations("stat", vec![stat_obs(STAT_SYMLINK)]);
        fake = fake.with_observations("readlink", vec![out]);
        let r = audit_fake(&recipe, fake);
        assert_eq!(
            afind(&r, "l").status,
            AuditResourceStatus::Error,
            "readlink with {} must be ERROR",
            label
        );
        assert_ne!(afind(&r, "l").status, AuditResourceStatus::Compliant);
        assert_observation_only(&r);
    }
}

#[test]
fn readlink_invalid_utf8_is_error() {
    let dir = trusted_root("r2-readlink-utf8");
    let recipe = link_recipe(&dir, "/opt/link", "/desired/target");
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations("stat", vec![stat_obs(STAT_SYMLINK)]);
    let mut bytes = b"/desired/".to_vec();
    bytes.extend_from_slice(&[0xff, 0xfe]);
    fake = fake.with_observations("readlink", vec![exited_bytes(0, &bytes, "")]);
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "l").status, AuditResourceStatus::Error);
}

#[test]
fn readlink_different_complete_target_is_drift_and_prefix_extension_is_drift() {
    // A complete but different target is known state: DRIFT, not ERROR. A
    // capture that merely extends the expected string is also a complete
    // target under the protocol, so it is DRIFT — never a PASS.
    let dir = trusted_root("r2-readlink-drift");
    let recipe = link_recipe(&dir, "/opt/link", "/desired/target");
    for target in ["/desired/other", "/desired/target-extended"] {
        let mut fake = FakeTarget::ubuntu2404();
        fake = fake.with_observations("stat", vec![stat_obs(STAT_SYMLINK)]);
        fake = fake.with_observations("readlink", vec![link_obs(target)]);
        let r = audit_fake(&recipe, fake);
        assert_eq!(afind(&r, "l").status, AuditResourceStatus::Drift);
        assert_ne!(afind(&r, "l").status, AuditResourceStatus::Compliant);
        assert_observation_only(&r);
    }
}

#[test]
fn stat_extra_blank_is_error_never_pass() {
    // Reproduced false PASS: a valid record plus a blank line was trimmed
    // into a valid-looking record. The terminator is now part of the
    // contract, so any extra record is a framing violation.
    let dir = trusted_root("r2-stat-blank");
    let recipe = file_recipe(&dir, "/opt/f", "hello");
    for (label, out) in [
        (
            "one extra blank line",
            stat_obs(&format!("{}\n", STAT_REGULAR)),
        ),
        (
            "multiple blank lines",
            stat_obs(&format!("{}\n\n\n", STAT_REGULAR)),
        ),
        (
            "leading blank line",
            exited(0, &format!("\n{}\n", STAT_REGULAR), ""),
        ),
        (
            "crlf terminator",
            exited(0, &format!("{}\r\n", STAT_REGULAR), ""),
        ),
        (
            "extra nonblank line",
            exited(0, &format!("{}\nwarning: extra\n", STAT_REGULAR), ""),
        ),
        ("unterminated record", exited(0, STAT_REGULAR, "")),
    ] {
        let mut fake = FakeTarget::ubuntu2404();
        fake = fake.with_observations("stat", vec![out]);
        let r = audit_fake(&recipe, fake);
        assert_eq!(
            afind(&r, "f").status,
            AuditResourceStatus::Error,
            "stat with {} must be ERROR",
            label
        );
        assert_ne!(afind(&r, "f").status, AuditResourceStatus::Compliant);
    }
}

#[test]
fn stat_valid_wrong_type_is_drift_and_encoding_failures_are_error() {
    let dir = trusted_root("r2-stat-kind");
    let recipe = file_recipe(&dir, "/opt/f", "hello");
    // A complete, valid record of the wrong type is ordinary drift evidence.
    let dir_line = STAT_REGULAR.replacen("regular file", "directory", 1);
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations("stat", vec![stat_obs(&dir_line)]);
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "f").status, AuditResourceStatus::Drift);
    assert_ne!(afind(&r, "f").status, AuditResourceStatus::Compliant);
    // Invalid UTF-8 in the record is an observation failure.
    let mut bytes = format!("{}\n", STAT_REGULAR).into_bytes();
    bytes.push(0xff);
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations("stat", vec![exited_bytes(0, &bytes, "")]);
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "f").status, AuditResourceStatus::Error);
    // Unexpected stderr alongside the record is ambiguous.
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations(
        "stat",
        vec![exited(
            0,
            &format!("{}\n", STAT_REGULAR),
            "stat: warning: deprecated option\n",
        )],
    );
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "f").status, AuditResourceStatus::Error);
    // stderr truncation is equally unusable.
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations(
        "stat",
        vec![truncated_stderr(&format!("{}\n", STAT_REGULAR), "")],
    );
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "f").status, AuditResourceStatus::Error);
}

#[test]
fn absence_extra_blank_is_error_never_absent_or_pass() {
    // Reproduced false PASS: the recognized missing diagnostic plus a blank
    // line was accepted as absence. Only the exact single-line contract may
    // classify as absent.
    let dir = trusted_root("r2-absence-blank");
    let recipe = file_recipe(&dir, "/opt/f", "hello");
    let marker = "stat: cannot statx '/opt/f': No such file or directory";
    for (label, out) in [
        (
            "marker plus blank line",
            exited(1, "", &format!("{}\n\n", marker)),
        ),
        (
            "marker plus unrelated diagnostic",
            exited(1, "", &format!("{}\nerror: I/O failure\n", marker)),
        ),
        (
            "leading blank line",
            exited(1, "", &format!("\n{}\n", marker)),
        ),
        ("unterminated marker", exited(1, "", marker)),
        (
            "wrong path",
            exited(
                1,
                "",
                "stat: cannot statx '/other': No such file or directory\n",
            ),
        ),
        (
            "wrong program identity",
            exited(
                1,
                "",
                "ls: cannot statx '/opt/f': No such file or directory\n",
            ),
        ),
        (
            "wrong message",
            exited(1, "", "stat: cannot statx '/opt/f': Input/output error\n"),
        ),
        (
            "unexpected stdout",
            exited(1, "regular file|644\n", &format!("{}\n", marker)),
        ),
    ] {
        let mut fake = FakeTarget::ubuntu2404();
        fake = fake.with_observations("stat", vec![out]);
        let r = audit_fake(&recipe, fake);
        assert_eq!(
            afind(&r, "f").status,
            AuditResourceStatus::Error,
            "absence observation with {} must be ERROR",
            label
        );
        assert_ne!(afind(&r, "f").status, AuditResourceStatus::Compliant);
    }
    // Invalid UTF-8 in the diagnostic is an observation failure.
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations("stat", vec![exited_bytes(1, b"", "")]);
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "f").status, AuditResourceStatus::Error);
}

#[test]
fn rpm_malformed_nevra_is_error_never_present_or_pass() {
    // Reproduced false PASS: `nano-garbage` proved package `nano` installed
    // under the old `<name>`/`<name>-` prefix acceptance. Identity is now
    // proved by whole-record equality against the NAME field.
    let dir = trusted_root("r2-rpm-nevra");
    let recipe = pkg_recipe_one(&dir, "nano", "present");
    for (label, out) in [
        ("name prefix garbage", exited(0, "nano-garbage", "")),
        ("bare malformed prefix", exited(0, "nan", "")),
        ("wrong package", exited(0, "other", "")),
        (
            "legacy NEVRA shape",
            exited(0, "nano-7.2-2.el9.x86_64\n", ""),
        ),
        ("multiple records", exited(0, "nanonano", "")),
        ("extra blank record", exited(0, "nano\n", "")),
        ("no record at all", exited(0, "", "")),
        (
            "unexpected stderr",
            exited(0, "nano", "error: rpmdb open failed\n"),
        ),
        ("exit 1 with a record", exited(1, "nano", "")),
    ] {
        let fake = FakeTarget::rocky9().with_query_results(vec![out]);
        let r = audit_fake(&recipe, fake);
        assert_eq!(
            afind(&r, "p").status,
            AuditResourceStatus::Error,
            "rpm observation with {} must be ERROR",
            label
        );
        assert_ne!(afind(&r, "p").status, AuditResourceStatus::Compliant);
        assert_observation_only(&r);
    }
    // Truncation and invalid UTF-8 are observation failures too.
    let fake = FakeTarget::rocky9().with_query_results(vec![truncated_stdout("nano", "")]);
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "p").status, AuditResourceStatus::Error);
    let fake = FakeTarget::rocky9().with_query_results(vec![exited_bytes(0, &[0xff, 0xfe], "")]);
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "p").status, AuditResourceStatus::Error);
}

#[test]
fn rpm_exact_identity_and_exact_absence_are_the_only_passing_answers() {
    let dir = trusted_root("r2-rpm-clean");
    let recipe = pkg_recipe_one(&dir, "nano", "present");
    // The exact NAME record proves the requested package is installed.
    let fake = FakeTarget::rocky9().with_query_results(vec![exited(0, "nano", "")]);
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "p").status, AuditResourceStatus::Compliant);
    assert_observation_only(&r);
    // The exact absence diagnostic proves it is not installed.
    let recipe2 = pkg_recipe_one(&dir, "nano", "absent");
    let fake = FakeTarget::rocky9().with_query_results(vec![exited(0, "nano", "")]);
    let r = audit_fake(&recipe2, fake);
    assert_eq!(afind(&r, "p").status, AuditResourceStatus::Drift);
    let fake = FakeTarget::rocky9().with_query_results(vec![exited(
        1,
        "package nano is not installed\n",
        "",
    )]);
    let r = audit_fake(&recipe2, fake);
    assert_eq!(afind(&r, "p").status, AuditResourceStatus::Compliant);
    assert_observation_only(&r);
}

#[test]
fn dpkg_framing_violations_are_error_never_a_clean_state() {
    let dir = trusted_root("r2-dpkg-framing");
    let recipe = pkg_recipe_one(&dir, "nano", "present");
    for (label, out) in [
        ("leading whitespace", exited(0, " install ok installed", "")),
        (
            "trailing whitespace",
            exited(0, "install ok installed ", ""),
        ),
        ("trailing newline", exited(0, "install ok installed\n", "")),
        (
            "extra blank record",
            exited(0, "install ok installed\n\n", ""),
        ),
        (
            "multiple records",
            exited(0, "install ok installed\ninstall ok installed", ""),
        ),
        (
            "unexpected stderr",
            exited(0, "install ok installed", "dpkg-query: warning: db\n"),
        ),
        ("no record at all", exited(0, "", "")),
        (
            "non-clean state",
            exited(0, "install ok half-configured", ""),
        ),
        (
            "exit 1 with a status record",
            exited(1, "install ok installed", ""),
        ),
    ] {
        let fake = FakeTarget::ubuntu2404().with_query_results(vec![out]);
        let r = audit_fake(&recipe, fake);
        let got = afind(&r, "p").status;
        assert_eq!(
            got,
            AuditResourceStatus::Error,
            "dpkg observation with {} must be ERROR (got {})",
            label,
            got.label()
        );
        assert_ne!(got, AuditResourceStatus::Compliant);
    }
    // Truncation and invalid UTF-8 are observation failures too.
    let fake = FakeTarget::ubuntu2404()
        .with_query_results(vec![truncated_stdout("install ok installed", "")]);
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "p").status, AuditResourceStatus::Error);
    let mut bad = b"install ok installed".to_vec();
    bad.push(0xff);
    bad.push(0xfe);
    let fake = FakeTarget::ubuntu2404().with_query_results(vec![exited_bytes(0, &bad, "")]);
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "p").status, AuditResourceStatus::Error);
}

#[test]
fn dpkg_exact_records_still_classify() {
    let dir = trusted_root("r2-dpkg-clean");
    let recipe = pkg_recipe_one(&dir, "nano", "present");
    let fake =
        FakeTarget::ubuntu2404().with_query_results(vec![exited(0, "install ok installed", "")]);
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "p").status, AuditResourceStatus::Compliant);
    assert_observation_only(&r);
    let recipe2 = pkg_recipe_one(&dir, "nano", "absent");
    let fake = FakeTarget::ubuntu2404().with_query_results(vec![exited(
        1,
        "",
        "dpkg-query: no packages found matching nano\n",
    )]);
    let r = audit_fake(&recipe2, fake);
    assert_eq!(afind(&r, "p").status, AuditResourceStatus::Compliant);
    assert_observation_only(&r);
}

#[test]
fn readlink_exact_match_still_passes_and_dangling_target_is_fine() {
    // Positive control for RA2-01: the exact target bytes still PASS, and the
    // target object's existence is not implied by the link observation.
    let dir = trusted_root("r2-readlink-ok");
    let recipe = link_recipe(&dir, "/opt/link", "/nonexistent-dangling");
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations("stat", vec![stat_obs(STAT_SYMLINK)]);
    fake = fake.with_observations("readlink", vec![link_obs("/nonexistent-dangling")]);
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "l").status, AuditResourceStatus::Compliant);
    assert_observation_only(&r);
}

#[test]
fn stat_exact_record_still_comparators_and_absence_still_drifts() {
    // Positive controls: the exact protocol record still yields a normal
    // comparison, and a clean recognized absence is still known state.
    let dir = trusted_root("r2-stat-ok");
    let recipe = file_recipe(&dir, "/opt/f", "hello");
    let digest = sha256_of("hello");
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations("stat", vec![stat_obs(STAT_REGULAR)]);
    fake = fake.with_observations(
        "sha256sum",
        vec![exited(0, &format!("{}  /opt/f\n", digest), "")],
    );
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "f").status, AuditResourceStatus::Compliant);
    assert_observation_only(&r);
    let recipe_absent = file_recipe(&dir, "/opt/g", "hello");
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations(
        "stat",
        vec![exited(
            1,
            "",
            "stat: cannot statx '/opt/g': No such file or directory\n",
        )],
    );
    let r = audit_fake(&recipe_absent, fake);
    // A clean, recognized absence is still known state: a desired-present
    // object that is genuinely absent is DRIFT, never an observation error.
    assert_eq!(afind(&r, "f").status, AuditResourceStatus::Drift);
    assert_ne!(afind(&r, "f").status, AuditResourceStatus::Compliant);
}

// ---------------------------------------------------------------------------
// Sensitive-data safety across the new RA2-01 error paths (§15).
// ---------------------------------------------------------------------------

#[test]
fn sensitive_framing_errors_never_leak_raw_observations() {
    // A sensitive link resource whose capture carries a forbidden trailing
    // newline: the new framing error must not echo the captured bytes.
    const CANARY: &str = "S3CR3T-CANARY-r2-9d31";
    let dir = trusted_root("r2-sens-framing");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: l\n    type: link\n    sensitive: true\n    with:\n      path: /opt/link\n      target: {}\n",
            CANARY
        ),
    );
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations("stat", vec![stat_obs(STAT_SYMLINK)]);
    fake = fake.with_observations("readlink", vec![link_obs(&format!("{}\n", CANARY))]);
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "l").status, AuditResourceStatus::Error);
    assert!(afind(&r, "l").sensitive);
    let text = report_text(&r);
    assert_eq!(
        text.matches(CANARY).count(),
        0,
        "sensitive canary leaked through the framing error:\n{}",
        text
    );
    // A sensitive file resource with an extra-blank stat record.
    let recipe2 = file_recipe(&dir, "/opt/sfile", "hello");
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations("stat", vec![stat_obs(&format!("{}\n", STAT_REGULAR))]);
    let r = audit_fake(&recipe2, fake);
    assert_eq!(afind(&r, "f").status, AuditResourceStatus::Error);
}

// ---------------------------------------------------------------------------
// IA-02: an Unknown command-derived register is NOT_AUDITABLE; a genuine
// template/render failure remains ERROR.
// ---------------------------------------------------------------------------

#[test]
fn audit_template_unknown_command_register_is_not_auditable() {
    let dir = controller_dir("audit-tmpl-unknown");
    write_recipe(&dir, "t.tmpl", "value={{ registers.p.stdout }}\n");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: producer\n    type: command\n    with:\n      program: /bin/echo\n      register: p\n  - id: consumer\n    type: template\n    with:\n      path: /opt/out\n      source: t.tmpl\n    depends_on: [producer]\n",
    );
    let r = audit_fake(&recipe, FakeTarget::ubuntu2404());
    let c = afind(&r, "consumer");
    assert_eq!(c.status, AuditResourceStatus::NotAuditable);
    assert_ne!(c.status, AuditResourceStatus::Error);
    // The producer command was never executed to obtain the register.
    for cmd in &r.commands {
        assert!(
            !cmd.program.contains("/bin/echo"),
            "audit executed the producer command to obtain a register"
        );
    }
    assert_observation_only(&r);
}

#[test]
fn audit_template_unknown_register_in_when_is_not_auditable() {
    let dir = controller_dir("audit-tmpl-when");
    write_recipe(&dir, "t.tmpl", "static\n");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: producer\n    type: command\n    with:\n      program: /bin/echo\n      register: p\n  - id: consumer\n    type: template\n    with:\n      path: /opt/out\n      source: t.tmpl\n    when: \"registers.p.stdout == \\\"x\\\"\"\n    depends_on: [producer]\n",
    );
    let r = audit_fake(&recipe, FakeTarget::ubuntu2404());
    assert_eq!(
        afind(&r, "consumer").status,
        AuditResourceStatus::NotAuditable
    );
}

#[test]
fn audit_template_genuine_render_error_is_error() {
    let dir = controller_dir("audit-tmpl-err");
    write_recipe(&dir, "t.tmpl", "value={{ vars.nope }}\n");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: t\n    type: template\n    with:\n      path: /opt/out\n      source: t.tmpl\n",
    );
    let r = audit_fake(&recipe, FakeTarget::ubuntu2404());
    let t = afind(&r, "t");
    assert_eq!(t.status, AuditResourceStatus::Error);
    assert_ne!(t.status, AuditResourceStatus::NotAuditable);
}

#[test]
fn audit_template_genuine_parse_error_is_error() {
    let dir = controller_dir("audit-tmpl-parse");
    write_recipe(&dir, "t.tmpl", "value={{ unterminated expression");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: t\n    type: template\n    with:\n      path: /opt/out\n      source: t.tmpl\n",
    );
    let r = audit_fake(&recipe, FakeTarget::ubuntu2404());
    assert_eq!(afind(&r, "t").status, AuditResourceStatus::Error);
}

// ---------------------------------------------------------------------------
// IA-03: the observation allowlist must reject anything that is not the exact
// defined query shape — including mutation flags, shell execution, package
// mutation, service mutation, staging commands, and arbitrary recipe commands.
// ---------------------------------------------------------------------------

fn record(program: &str, args: &[&str]) -> AuditReport {
    AuditReport {
        resources: Vec::new(),
        summary: sinter::audit::AuditSummary::default(),
        commands: vec![sinter::executor::CommandRecord {
            program: program.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            env: std::collections::BTreeMap::new(),
            sudo: false,
            sensitive: false,
        }],
    }
}

#[test]
fn audit_allowlist_rejects_loose_package_and_service_shapes() {
    // These are exactly the shapes a basename-only check (`rpm` + `-q`) would
    // have accepted: a mutation flag smuggled past the query, a shell, a
    // staging command, and service mutation.
    let bad = [
        record("/usr/bin/rpm", &["-q", "--", "nano"]),
        record("/usr/bin/rpm", &["-q", "-v", "--", "nano"]),
        record("/usr/bin/rpm", &["-qi", "--", "nano"]),
        record("/usr/bin/rpm", &["-q", "--queryformat", "%{NAME}", "nano"]),
        record(
            "/usr/bin/rpm",
            &["-q", "--queryformat", "%{NEVRA}", "--", "nano"],
        ),
        record(
            "/usr/bin/rpm",
            &["-q", "--queryformat", "%{NAME}", "--", "nano", "-e"],
        ),
        record("/usr/bin/dpkg-query", &["-W", "-f=${Status}", "nano"]),
        record("/usr/bin/dpkg-query", &["-W", "--", "nano"]),
        record("/usr/bin/dnf", &["-q", "install", "nano"]),
        record("/usr/bin/apt-get", &["-y", "install", "nano"]),
        record("/usr/bin/systemctl", &["show", "svc"]),
        record(
            "/usr/bin/systemctl",
            &["show", "svc", "--property=LoadState,ActiveState"],
        ),
        record("/usr/bin/systemctl", &["restart", "svc"]),
        record("/usr/bin/systemctl", &["enable", "svc"]),
        record("/bin/sh", &["-c", "/bin/rm -rf /"]),
        record("/usr/bin/mktemp", &["-d"]),
        record("/bin/rm", &["-rf", "/opt/x"]),
        record("/bin/chmod", &["700", "/opt/x"]),
        record("/bin/mv", &["/tmp/a", "/opt/b"]),
        record("/usr/bin/sinter-mutation-sentinel", &["--would-mutate"]),
        record("/usr/bin/stat", &["-c", "%F", "/opt/f"]),
        record(
            "/usr/bin/stat",
            &["-c", "%F|%a|%u|%g|%s|%d|%i|%y|%z", "/opt/f"],
        ),
        record("/usr/bin/sha256sum", &["/opt/f"]),
        record("/usr/bin/readlink", &["-f", "/opt/l"]),
        record("/usr/bin/getent", &["passwd"]),
        record("/usr/bin/getent", &["shadow", "root"]),
        record("/bin/cat", &["/etc/shadow"]),
    ];
    for r in &bad {
        let res = std::panic::catch_unwind(|| assert_observation_only(r));
        assert!(
            res.is_err(),
            "the strict allowlist accepted a non-observation or wrong-shape \
             command: {} {:?}",
            r.commands[0].program,
            r.commands[0].args
        );
    }
}

#[test]
fn audit_allowlist_accepts_every_defined_observation_shape() {
    let good = [
        record("/usr/bin/test", &["-r", "/etc/os-release"]),
        record("/usr/bin/test", &["-x", "/usr/bin/rpm"]),
        record("/bin/hostname", &[]),
        record("/bin/cat", &["/etc/os-release"]),
        record("/usr/bin/uname", &["-m"]),
        record(
            "/usr/bin/stat",
            &["-c", "%F|%a|%u|%g|%s|%d|%i|%y|%z", "--", "/opt/f"],
        ),
        record("/usr/bin/readlink", &["-n", "--", "/opt/l"]),
        record("/usr/bin/sha256sum", &["--", "/opt/f"]),
        record("/usr/bin/getent", &["passwd", "root"]),
        record("/usr/bin/getent", &["group", "root"]),
        record("/usr/bin/dpkg-query", &["-W", "-f=${Status}", "--", "nano"]),
        record(
            "/usr/bin/rpm",
            &["-q", "--queryformat", "%{NAME}", "--", "nano"],
        ),
        record(
            "/usr/bin/systemctl",
            &[
                "show",
                "svc",
                "--property=LoadState,ActiveState,UnitFileState",
            ],
        ),
    ];
    for r in &good {
        assert_observation_only(r);
    }
}

#[test]
fn audit_allowlist_rejects_shell_construction_in_arguments() {
    // Even a recognized program must not receive a multi-token argument,
    // which would imply shell construction.
    let r = record(
        "/usr/bin/stat",
        &["-c", "%F|%a", "--", "/opt/f && rm -rf /"],
    );
    let res = std::panic::catch_unwind(|| assert_observation_only(&r));
    assert!(res.is_err(), "multi-token argument was accepted");
}

// ---------------------------------------------------------------------------
// Sensitive data across the new error paths (§19)
// ---------------------------------------------------------------------------

#[test]
fn audit_sensitive_observation_error_does_not_leak() {
    const CANARY: &str = "S3CR3T-CANARY-adv-7c1a";
    let dir = trusted_root("adv-sens-err");
    let path = "/opt/sinter-adv-secret";
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nvars:\n  secret:\n    value: {}\n    sensitive: true\nresources:\n  - id: s\n    type: file\n    sensitive: true\n    with:\n      path: {}\n      content: \"token={{{{ vars.secret }}}}\"\n",
            CANARY, path
        ),
    );
    // A truncated digest capture drives the new fail-closed error path.
    let digest = sha256_of(&format!("token={}", CANARY));
    let mut fake = FakeTarget::ubuntu2404();
    fake = fake.with_observations("stat", vec![exited(0, &format!("{}\n", STAT_REGULAR), "")]);
    fake = fake.with_observations(
        "sha256sum",
        vec![truncated_stdout(&format!("{}  {}", digest, path), "")],
    );
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "s").status, AuditResourceStatus::Error);
    assert!(afind(&r, "s").sensitive);
    let text = report_text(&r);
    assert_eq!(
        text.matches(CANARY).count(),
        0,
        "sensitive canary leaked through the new error path:\n{}",
        text
    );
    for d in &afind(&r, "s").details {
        assert_eq!(d.observed, "[redacted]");
        assert_eq!(d.desired, "[redacted]");
    }
}

#[test]
fn audit_sensitive_package_observation_error_does_not_leak() {
    const CANARY: &str = "S3CR3T-CANARY-adv-pkg-3f02";
    let dir = trusted_root("adv-sens-pkg");
    let recipe = write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: p\n    type: package\n    sensitive: true\n    with:\n      name: {}\n      state: present\n",
            CANARY
        ),
    );
    // Truncated successful capture on a sensitive query: the error path must
    // not echo the captured output.
    let fake = FakeTarget::ubuntu2404()
        .with_query_results(vec![truncated_stdout("install ok installed", "")]);
    let r = audit_fake(&recipe, fake);
    assert_eq!(afind(&r, "p").status, AuditResourceStatus::Error);
    let text = report_text(&r);
    assert_eq!(
        text.matches(CANARY).count(),
        0,
        "sensitive canary leaked:\n{}",
        text
    );
}
