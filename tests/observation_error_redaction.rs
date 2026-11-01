//! N151-03: a package query that fails never copies its captured output into
//! a message. The output of `rpm -q` / `dpkg-query` is target text that may
//! carry anything, so plan, apply and audit, in text and in JSON, show only
//! the backend, the exit status and how many bytes were withheld.
//!
//! The canary strings are synthetic and carry no real credential.

mod common;

use common::*;
use sinter::audit::{run_audit, AuditResourceStatus};
use sinter::engine::{Engine, Mode, RunOptions, TargetSpec};
use sinter::executor::{Completion, FakeTarget, Output};
use sinter::model::load_model;
use sinter::output::{OutputFormat, RenderOptions};
use std::path::Path;

const OUT_CANARY: &str = "SINTER-TEST-CANARY-STDOUT-0000";
const ERR_CANARY: &str = "SINTER-TEST-CANARY-STDERR-0000";

fn failed_query() -> Output {
    Output {
        completion: Completion::Exited(2),
        stdout: format!("{OUT_CANARY}\n").into_bytes(),
        stderr: format!(
            "error: {ERR_CANARY} token=example-not-a-secret\n\x1b[31msecond line\x1b[0m\n"
        )
        .into_bytes(),
        stdout_truncated: false,
        stderr_truncated: false,
    }
}

type MakeTarget = fn() -> FakeTarget;

fn targets() -> Vec<(&'static str, MakeTarget)> {
    vec![
        ("apt", FakeTarget::ubuntu2404 as MakeTarget),
        ("dnf", FakeTarget::rocky9 as MakeTarget),
    ]
}

fn recipe(label: &str, sensitive: bool) -> std::path::PathBuf {
    let dir = trusted_root(label);
    let s = if sensitive {
        "\n    sensitive: true"
    } else {
        ""
    };
    write_recipe(
        &dir,
        "r.yaml",
        &format!(
            "version: 1\nresources:\n  - id: p\n    type: package{s}\n    with:\n      name: nano\n      state: present\n"
        ),
    )
}

fn opts(mode: Mode, fake: FakeTarget) -> RunOptions {
    RunOptions {
        mode,
        sudo: false,
        target: TargetSpec { ssh: None },
        verbose: true,
        fault: None,
        fake_target: Some(fake),
    }
}

fn assert_clean(what: &str, text: &str) {
    for c in [
        OUT_CANARY,
        ERR_CANARY,
        "example-not-a-secret",
        "second line",
    ] {
        assert!(!text.contains(c), "{what} leaked {c:?}:\n{text}");
    }
}

/// Everything plan or apply shows: the error, or both renderings.
fn run_texts(path: &Path, mode: Mode, fake: FakeTarget) -> String {
    let model = load_model(path).unwrap();
    let engine = match Engine::new(model, opts(mode, fake)) {
        Ok(e) => e,
        Err(e) => return e.message,
    };
    match engine.run() {
        Err(e) => e.message,
        Ok(r) => {
            let mut all = Vec::new();
            for format in [OutputFormat::Text, OutputFormat::Json] {
                let o = RenderOptions {
                    verbose: true,
                    format,
                    color: false,
                };
                if mode == Mode::Plan {
                    sinter::output::render_plan(&r, &o, &mut all).unwrap();
                } else {
                    sinter::output::render_apply(&r, &o, &mut all).unwrap();
                }
            }
            String::from_utf8(all).unwrap()
        }
    }
}

#[test]
fn a_failed_package_query_is_reported_without_its_output_in_plan_and_apply() {
    for (backend, make) in targets() {
        for mode in [Mode::Plan, Mode::Apply] {
            let path = recipe(&format!("n15103-{backend}-{mode:?}"), false);
            let text = run_texts(&path, mode, make().with_query_results(vec![failed_query()]));
            assert_clean(&format!("{backend} {mode:?}"), &text);
            assert!(
                text.contains(&format!(
                    "package observation failed for nano: {backend} query exited 2"
                )),
                "{backend} {mode:?}: {text}"
            );
            assert!(text.contains("bytes of query output withheld"), "{text}");
        }
    }
}

#[test]
fn a_failed_package_query_is_an_audit_error_without_its_output() {
    for (backend, make) in targets() {
        for sensitive in [false, true] {
            let path = recipe(&format!("n15103-audit-{backend}-{sensitive}"), sensitive);
            let model = load_model(&path).unwrap();
            let fake = make().with_query_results(vec![failed_query()]);
            let engine = Engine::new(model, opts(Mode::Plan, fake)).unwrap();
            let report = run_audit(engine).unwrap();
            let p = report.resources.iter().find(|r| r.id == "p").unwrap();
            assert_eq!(p.status, AuditResourceStatus::Error, "{backend}");
            let json = serde_json::to_string(&sinter::output::audit_report_json(&report)).unwrap();
            let mut text = Vec::new();
            sinter::output::render_audit(
                &report,
                &RenderOptions {
                    verbose: true,
                    format: OutputFormat::Text,
                    color: false,
                },
                &mut text,
            )
            .unwrap();
            let text = String::from_utf8(text).unwrap();
            let reason = p.reason.clone().unwrap_or_default();
            for (what, s) in [("reason", &reason), ("json", &json), ("text", &text)] {
                assert_clean(&format!("{backend} sensitive={sensitive} {what}"), s);
            }
            if sensitive {
                assert!(!json.contains("withheld"), "{json}");
                assert!(!reason.contains("nano"), "{reason}");
            }
        }
    }
}
