use crate::diff::sanitize_line;
use crate::engine::{AggregateStatus, RunReport};
use crate::result::DiffBody;
use crate::result::*;
use std::io::Write;

pub struct RenderOptions {
    pub verbose: bool,
    pub format: OutputFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

pub fn render_plan(
    report: &RunReport,
    opts: &RenderOptions,
    out: &mut dyn Write,
) -> std::io::Result<()> {
    match opts.format {
        OutputFormat::Text => render_text(report, opts, "PLAN", out),
        OutputFormat::Json => render_json(report, "plan", out),
    }
}

pub fn render_apply(
    report: &RunReport,
    opts: &RenderOptions,
    out: &mut dyn Write,
) -> std::io::Result<()> {
    match opts.format {
        OutputFormat::Text => render_text(report, opts, "APPLY", out),
        OutputFormat::Json => render_json(report, "apply", out),
    }
}

fn render_text(
    report: &RunReport,
    opts: &RenderOptions,
    header: &str,
    out: &mut dyn Write,
) -> std::io::Result<()> {
    writeln!(out, "== Sinter {} ==", header)?;
    writeln!(
        out,
        "target facts: hostname={} os={} family={} version={} arch={}",
        sanitize_line(&report.facts.hostname),
        sanitize_line(&report.facts.os_name),
        sanitize_line(&report.facts.os_family),
        sanitize_line(&report.facts.os_version),
        sanitize_line(&report.facts.arch)
    )?;
    writeln!(out)?;

    for r in &report.resources {
        let status = human_status(r);
        let reason = if r.sensitive {
            r.reason.as_ref().map(|_| "<redacted>".to_string())
        } else {
            r.reason.clone()
        };
        writeln!(
            out,
            "{}  {} [{}] {}/{} {}",
            status,
            sanitize_line(&r.id),
            r.type_,
            if r.unknown { "unknown" } else { "known" },
            r.disposition.label(),
            reason.unwrap_or_default()
        )?;
        if let Some(d) = &r.diff {
            match &d.body {
                DiffBody::Redacted => {
                    writeln!(out, "    diff: redacted")?;
                }
                DiffBody::Summary { current, desired } => {
                    if r.sensitive {
                        writeln!(out, "    diff: redacted")?;
                    } else {
                        writeln!(out, "    current: {}", sanitize_line(current))?;
                        writeln!(out, "    desired: {}", sanitize_line(desired))?;
                    }
                }
                DiffBody::Text { removed, added } => {
                    for line in removed {
                        writeln!(out, "    - {}", sanitize_line(line))?;
                    }
                    for line in added {
                        writeln!(out, "    + {}", sanitize_line(line))?;
                    }
                }
            }
        }
        if opts.verbose {
            for n in &r.notes {
                if r.sensitive {
                    writeln!(out, "    note: <redacted>")?;
                } else {
                    writeln!(out, "    note: {}", sanitize_line(n))?;
                }
            }
        }
    }

    if !report.handlers_run.is_empty() {
        writeln!(out)?;
        writeln!(out, "handlers:")?;
        for h in &report.handlers_run {
            let reason = if h.sensitive {
                h.reason.as_ref().map(|_| "<redacted>".to_string())
            } else {
                h.reason.clone()
            };
            let service = if h.sensitive {
                "<redacted>".to_string()
            } else {
                sanitize_line(&h.service)
            };
            writeln!(
                out,
                "  {:?}  {} -> {} {} {}",
                h.state,
                h.id,
                h.action,
                service,
                reason.unwrap_or_default()
            )?;
        }
    }
    if !report.handlers_pending.is_empty() {
        writeln!(out)?;
        writeln!(
            out,
            "pending handlers (not run): {}",
            report
                .handlers_pending
                .iter()
                .map(|s| sanitize_line(s))
                .collect::<Vec<_>>()
                .join(", ")
        )?;
    }

    writeln!(out)?;
    let changed = report
        .resources
        .iter()
        .filter(|r| r.change == Change::Changed)
        .count();
    let possible = report
        .resources
        .iter()
        .filter(|r| r.change == Change::Possible)
        .count();
    let failed = report.resources.iter().filter(|r| r.is_failure()).count();
    let indeterminate = report
        .resources
        .iter()
        .filter(|r| r.is_indeterminate())
        .count();
    writeln!(
        out,
        "summary: {} changed, {} possible, {} failed, {} indeterminate, {} total",
        changed,
        possible,
        failed,
        indeterminate,
        report.resources.len()
    )?;
    writeln!(
        out,
        "status: {}",
        match report.status {
            AggregateStatus::Success => "success",
            AggregateStatus::PlanError => "plan_error",
            AggregateStatus::ApplyFailed => "apply_failed",
            AggregateStatus::Indeterminate => "indeterminate",
        }
    )?;
    Ok(())
}

fn render_json(report: &RunReport, mode: &str, out: &mut dyn Write) -> std::io::Result<()> {
    use serde_json::json;
    let resources: Vec<serde_json::Value> = report
        .resources
        .iter()
        .map(|r| {
            let diff = if r.sensitive {
                match &r.diff {
                    None => serde_json::Value::Null,
                    Some(_) => json!({"type": "redacted"}),
                }
            } else {
                match &r.diff {
                    None => serde_json::Value::Null,
                    Some(d) => match &d.body {
                        DiffBody::Redacted => json!({"type": "redacted"}),
                        DiffBody::Summary { current, desired } => json!({
                            "type": "summary",
                            "current": current,
                            "desired": desired
                        }),
                        DiffBody::Text { removed, added } => json!({
                            "type": "text",
                            "removed": removed,
                            "added": added
                        }),
                    },
                }
            };
            json!({
                "id": r.id,
                "type": r.type_,
                "origin": r.origin,
                "execution": r.execution.label(),
                "change": r.change.label(),
                "verification": r.verification.label(),
                "disposition": r.disposition.label(),
                "reason": if r.sensitive { serde_json::Value::String("<redacted>".to_string()) } else { serde_json::json!(r.reason) },
                "unknown": r.unknown,
                "sensitive": r.sensitive,
                "loop_index": r.loop_index,
                "diff": diff,
                "notes": if r.sensitive { serde_json::json!(r.notes.iter().map(|_| "<redacted>").collect::<Vec<_>>()) } else { serde_json::json!(r.notes) },
            })
        })
        .collect();
    let handlers: Vec<serde_json::Value> = report
        .handlers_run
        .iter()
        .map(|h| {
            let reason = if h.sensitive {
                h.reason.as_ref().map(|_| "<redacted>".to_string())
            } else {
                h.reason.clone()
            };
            json!({
                "id": h.id,
                "service": if h.sensitive { "<redacted>".to_string() } else { sanitize_line(&h.service) },
                "action": h.action,
                "state": format!("{:?}", h.state),
                "reason": reason,
            })
        })
        .collect();
    let doc = json!({
        "mode": mode,
        "status": match report.status {
            AggregateStatus::Success => "success",
            AggregateStatus::PlanError => "plan_error",
            AggregateStatus::ApplyFailed => "apply_failed",
            AggregateStatus::Indeterminate => "indeterminate",
        },
        "facts": {
            "hostname": report.facts.hostname,
            "os_name": report.facts.os_name,
            "os_family": report.facts.os_family,
            "os_version": report.facts.os_version,
            "arch": report.facts.arch,
        },
        "resources": resources,
        "handlers": handlers,
        "handlers_pending": report.handlers_pending,
    });
    writeln!(out, "{}", serde_json::to_string_pretty(&doc).unwrap())?;
    Ok(())
}

fn human_status(r: &ResourceResult) -> &'static str {
    if r.unknown {
        return "?";
    }
    match r.disposition {
        Disposition::SkippedByCondition => "skip",
        Disposition::GuardSatisfied => "guard",
        Disposition::BlockedByDependency => "blocked",
        Disposition::BlockedByFailFast => "blocked",
        Disposition::Normal => match r.execution {
            Execution::NotRun => "----",
            Execution::Succeeded => match r.change {
                Change::None => "ok  ",
                Change::Changed => "CHANGED",
                Change::Possible => "POSSIBLE",
            },
            Execution::Failed => "FAILED",
            Execution::Indeterminate => "INDET",
        },
    }
}
