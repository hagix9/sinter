//! Read-only Sinter Core MCP adapter (stdio transport).
//!
//! This module exposes a minimal Model Context Protocol surface so an
//! external agent can inspect Sinter's authoritative core behavior: manifest
//! parsing/validation, platform classification, and planning. Every tool is
//! a thin adapter over existing library functions — no validation, platform,
//! or planning rule is duplicated here.
//!
//! C1 is structurally read-only:
//!   - there is no apply/execute/install/remove tool, and none may be added
//!     without changing the registry allowlist test;
//!   - `sinter_plan` runs against a scripted in-process `FakeTarget`
//!     (supplied facts), never SSH, never a real host;
//!   - manifest content is written to a private temporary file solely so the
//!     existing `load_model` parser can process it, then deleted.
//!
//! Protocol: newline-delimited JSON-RPC 2.0 on stdin/stdout (MCP stdio
//! transport). stdout carries protocol frames only; diagnostics go to
//! stderr. Supported methods: initialize, ping, tools/list, tools/call.

use crate::audit::run_audit;
use crate::document::{parse_document, Document};
use crate::engine::{Engine, Mode, RunOptions, RunReport, TargetSpec};
use crate::error::{ErrorKind, SinterError};
use crate::executor::FakeTarget;
use crate::facts::Facts;
use crate::model::load_model;
use crate::platform::PackageBackend;
use crate::targets::{TargetProfile, TargetRegistry};
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

/// MCP protocol revision this adapter implements.
const PROTOCOL_VERSION: &str = "2025-03-26";

/// Upper bound on accepted manifest text (defensive; recipes are small).
const MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;

/// Deterministic error categories surfaced to MCP clients.
fn category(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::Schema => "invalid_manifest",
        ErrorKind::Connect => "unavailable_operation",
        ErrorKind::Plan => "plan_error",
        ErrorKind::Apply => "unavailable_operation",
        ErrorKind::Indeterminate => "indeterminate",
        ErrorKind::Unknown => "internal_error",
    }
}

#[derive(Debug)]
struct ToolError {
    category: &'static str,
    kind: Option<&'static str>,
    message: String,
}

impl ToolError {
    fn invalid_request(msg: impl Into<String>) -> Self {
        Self {
            category: "invalid_request",
            kind: None,
            message: msg.into(),
        }
    }
    fn from_core(e: &SinterError) -> Self {
        Self {
            category: category(e.kind),
            kind: Some(kind_label(e.kind)),
            message: e.message.clone(),
        }
    }
    fn to_json(&self) -> Value {
        json!({ "error": { "category": self.category, "kind": self.kind, "message": self.message } })
    }
}

fn kind_label(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::Schema => "schema",
        ErrorKind::Connect => "connect",
        ErrorKind::Plan => "plan",
        ErrorKind::Apply => "apply",
        ErrorKind::Indeterminate => "indeterminate",
        ErrorKind::Unknown => "unknown",
    }
}

fn err_value(e: SinterError) -> ToolError {
    ToolError::from_core(&e)
}

/// Redact the staging directory inside a core diagnostic — tool output must
/// never expose physical local paths. The staged manifest itself keeps the
/// established logical name `recipe`; any other path under the stage becomes
/// `recipe:/<relative>` (e.g. `recipe:/missing.tpl`).
fn staged_error(e: SinterError, stage_dir: &Path) -> ToolError {
    let mut t = ToolError::from_core(&e);
    let dir = stage_dir.display().to_string();
    if t.message.contains(&dir) {
        t.message = t
            .message
            .replace(&format!("{dir}/recipe.yaml"), "recipe")
            .replace(&dir, "recipe:");
    }
    t
}

// ---------------------------------------------------------------------------
// Manifest staging
// ---------------------------------------------------------------------------

/// Private temporary directory holding one staged manifest so the existing
/// file-based `load_model` parser can run unchanged. Deleted on drop.
///
/// Security properties (F-01/F-08):
///   - the directory name comes from `tempfile`, i.e. OS-backed randomness
///     with O_EXCL-style exclusive creation — a pre-existing object is never
///     reused and the name is not practically predictable;
///   - the directory is private (0700 on Unix) and `recipe.yaml` is created
///     private (0600 on Unix) with create_new, so a pre-existing entry —
///     including a symlink — can never be opened or overwritten.
struct Stage {
    _dir: tempfile::TempDir,
    /// Canonicalized stage directory; diagnostics are redacted against this.
    canonical: PathBuf,
}

impl Stage {
    fn new() -> Result<Self, ToolError> {
        let dir = tempfile::Builder::new()
            .prefix("sinter-mcp-")
            .tempdir()
            .map_err(|e| ToolError {
                category: "internal_error",
                kind: None,
                message: format!("cannot create staging directory: {e}"),
            })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).map_err(
                |e| ToolError {
                    category: "internal_error",
                    kind: None,
                    message: format!("cannot secure staging directory: {e}"),
                },
            )?;
        }
        // Canonicalize so staged paths match the canonicalized paths the
        // parser reports in diagnostics (staged_error replaces them).
        let canonical =
            std::fs::canonicalize(dir.path()).unwrap_or_else(|_| dir.path().to_path_buf());
        Ok(Self {
            _dir: dir,
            canonical,
        })
    }

    /// Write manifest content into the stage and return the entry path.
    /// Includes, if any, resolve relative to the staging directory; a
    /// manifest that references files not staged fails honestly.
    /// `create_new` refuses any pre-existing entry — a planted symlink is
    /// never followed.
    fn write_manifest(&self, manifest: &str) -> Result<PathBuf, ToolError> {
        let p = self.canonical.join("recipe.yaml");
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&p).map_err(|e| ToolError {
            category: "internal_error",
            kind: None,
            message: format!("cannot stage manifest: {e}"),
        })?;
        f.write_all(manifest.as_bytes()).map_err(|e| ToolError {
            category: "internal_error",
            kind: None,
            message: format!("cannot stage manifest: {e}"),
        })?;
        Ok(p)
    }
}

fn stage_manifest(manifest: &str) -> Result<(Stage, PathBuf), ToolError> {
    if manifest.len() > MAX_MANIFEST_BYTES {
        return Err(ToolError::invalid_request(format!(
            "manifest exceeds {} byte limit",
            MAX_MANIFEST_BYTES
        )));
    }
    if manifest.trim().is_empty() {
        return Err(ToolError::invalid_request("manifest is empty"));
    }
    let stage = Stage::new()?;
    let path = stage.write_manifest(manifest)?;
    Ok((stage, path))
}

fn require_manifest(args: &Value) -> Result<&str, ToolError> {
    let m = args.get("manifest").and_then(Value::as_str);
    match m {
        Some(s) => Ok(s),
        None => Err(ToolError::invalid_request(
            "missing or invalid required string parameter \"manifest\"",
        )),
    }
}

// ---------------------------------------------------------------------------
// Named target resolution (C2)
// ---------------------------------------------------------------------------

/// Host tools accept exactly `manifest` + `target`. Any other parameter —
/// including connection-policy fields like host/user/port/identity/sudo —
/// is rejected outright: those belong to the administrator-owned profile
/// and must never be caller-controlled.
fn require_only(args: &Value, allowed: &[&str]) -> Result<(), ToolError> {
    if let Some(obj) = args.as_object() {
        for key in obj.keys() {
            if !allowed.contains(&key.as_str()) {
                return Err(ToolError::invalid_request(format!(
                    "unexpected parameter \"{key}\" (allowed: {})",
                    allowed.join(", ")
                )));
            }
        }
    }
    Ok(())
}

/// Resolve the opaque `target` argument to an immutable registry profile.
/// Unknown or malformed names fail closed — never interpreted as a hostname.
fn resolve_target<'a>(
    args: &Value,
    reg: &'a TargetRegistry,
) -> Result<(String, &'a TargetProfile), ToolError> {
    let name = args.get("target").and_then(Value::as_str).ok_or_else(|| {
        ToolError::invalid_request("missing or invalid required string parameter \"target\"")
    })?;
    if !TargetRegistry::name_is_wellformed(name) {
        return Err(ToolError::invalid_request("invalid target name"));
    }
    match reg.get(name) {
        Some(p) => Ok((name.to_string(), p)),
        None => Err(ToolError::invalid_request(format!(
            "unknown target \"{name}\""
        ))),
    }
}

/// Stage-path redaction plus profile confidentiality: administrator-owned
/// connection details (host, user, known_hosts, identity paths) are replaced
/// by `[target]` wherever an underlying diagnostic embedded them.
/// Replacement is overlap-safe: complete values are deduplicated and applied
/// longest-first, so a shorter value that is a prefix of a longer one cannot
/// leave residue like `[target]-admin`.
fn host_error(e: SinterError, stage_dir: &Path, profile: &TargetProfile) -> ToolError {
    let mut t = staged_error(e, stage_dir);
    let mut secrets: Vec<String> = vec![
        profile.spec.host.clone(),
        profile.spec.user.clone(),
        profile.spec.known_hosts.display().to_string(),
    ];
    secrets.extend(
        profile
            .spec
            .identity_files
            .iter()
            .map(|p| p.display().to_string()),
    );
    secrets.retain(|s| !s.is_empty());
    secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
    secrets.dedup();
    for s in &secrets {
        t.message = if s.len() >= SHORT_SECRET_LEN {
            t.message.replace(s.as_str(), "[target]")
        } else {
            redact_bounded(&t.message, s)
        };
    }
    t
}

/// R1-N3: profile values shorter than this are only replaced at token
/// boundaries. A global substring rule would let a one- or two-character
/// configured value (e.g. `user = "u"`) mangle ordinary diagnostic words
/// such as "refused", while boundary matching still masks the value wherever
/// it is actually printed standalone.
const SHORT_SECRET_LEN: usize = 4;

fn redact_bounded(text: &str, needle: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find(needle) {
        let bounded_before = rest[..i]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_ascii_alphanumeric());
        let after = &rest[i + needle.len()..];
        let bounded_after = after
            .chars()
            .next()
            .is_none_or(|c| !c.is_ascii_alphanumeric());
        if bounded_before && bounded_after {
            out.push_str(&rest[..i]);
            out.push_str("[target]");
        } else {
            // Embedded in a larger token: not the configured value being
            // printed — keep it and continue scanning after it.
            out.push_str(&rest[..i + needle.len()]);
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

/// R2/R3: structural manifest-authority boundary for ALL MCP manifest
/// tools. Operates on the parsed `Document` produced by the same production
/// parser the CLI uses, so every spelling the grammar accepts — plain,
/// quoted, explicit or flow mapping keys, tagged scalars — is classified
/// identically.
///
/// Policy: an untrusted MCP manifest grants no controller filesystem
/// authority. `include:` (absolute, relative, nested — all forms) and any
/// resource `with.source` (file/template, absolute or relative) are
/// rejected. The check runs on the parsed structure before `load_model`,
/// so no caller-selected controller path is ever opened: the only file
/// read is the private staged manifest Sinter itself created.
fn check_mcp_manifest_authority(doc: &Document) -> Result<(), ToolError> {
    if !doc.includes.is_empty() {
        return Err(ToolError {
            category: "invalid_manifest",
            kind: Some("schema"),
            message: "MCP manifests may not use \"include:\" — controller-local \
                      file reads are not permitted over MCP"
                .to_string(),
        });
    }
    for r in &doc.resources {
        if r.with.contains_key("source") {
            return Err(ToolError {
                category: "invalid_manifest",
                kind: Some("schema"),
                message: "MCP manifests may not use \"source:\" — controller-local \
                          file reads are not permitted over MCP"
                    .to_string(),
            });
        }
    }
    Ok(())
}

/// The single MCP manifest boundary every manifest-consuming tool passes
/// through: structural parse of the staged file (the only permitted
/// controller read), then the authority policy. Callers invoke
/// `load_model` only after this returns Ok, so no caller-selected
/// controller path can be probed, read, or expanded.
fn check_staged_manifest(path: &Path, stage: &Stage) -> Result<(), ToolError> {
    let doc = parse_document(path).map_err(|e| staged_error(e, &stage.canonical))?;
    check_mcp_manifest_authority(&doc)
}

// ---------------------------------------------------------------------------
// Tool implementations — thin adapters over authoritative core entry points
// ---------------------------------------------------------------------------

fn tool_get_version() -> Result<Value, ToolError> {
    Ok(json!({
        "name": "sinter",
        "version": env!("CARGO_PKG_VERSION"),
        "readOnly": true,
    }))
}

fn tool_classify_platform(args: &Value) -> Result<Value, ToolError> {
    let os_release = args
        .get("os_release")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ToolError::invalid_request(
                "missing or invalid required string parameter \"os_release\"",
            )
        })?;
    if os_release.len() > 64 * 1024 {
        return Err(ToolError::invalid_request(
            "os_release exceeds 64 KiB limit",
        ));
    }
    let facts = Facts::from_observed(
        args.get("hostname")
            .and_then(Value::as_str)
            .unwrap_or("supplied-host")
            .to_string(),
        os_release,
        args.get("arch")
            .and_then(Value::as_str)
            .unwrap_or("x86_64")
            .to_string(),
    )
    .map_err(err_value)?;
    let backend = PackageBackend::for_os_family(&facts.os_family);
    Ok(json!({
        "os_name": facts.os_name,
        "os_family": facts.os_family,
        "os_version": facts.os_version,
        "arch": facts.arch,
        "package_backend": backend.map(|b| b.label()),
        // "manageable" = core can drive a package backend for this family.
        // Acceptance-test status is release evidence, not core data.
        "manageable": backend.is_some(),
    }))
}

fn tool_validate_manifest(args: &Value) -> Result<Value, ToolError> {
    let manifest = require_manifest(args)?;
    let (stage, path) = stage_manifest(manifest)?;
    // Parse errors remain `valid: false` diagnostics (the C1 contract); only
    // an authority-policy violation is a hard tool error.
    let doc = match parse_document(&path) {
        Ok(d) => d,
        Err(e) => {
            return Ok(json!({
                "valid": false,
                "diagnostics": [staged_error(e, &stage.canonical).to_json()["error"]],
            }))
        }
    };
    check_mcp_manifest_authority(&doc)?;
    match load_model(&path) {
        Ok(model) => Ok(json!({
            "valid": true,
            "resources": model.resources.len(),
            "handlers": model.handlers.len(),
            "vars": model.vars.len(),
        })),
        Err(e) => Ok(json!({
            "valid": false,
            "diagnostics": [staged_error(e, &stage.canonical).to_json()["error"]],
        })),
    }
}

fn tool_inspect_manifest(args: &Value) -> Result<Value, ToolError> {
    let manifest = require_manifest(args)?;
    let (stage, path) = stage_manifest(manifest)?;
    check_staged_manifest(&path, &stage)?;
    let model = load_model(&path).map_err(|e| staged_error(e, &stage.canonical))?;
    let resources: Vec<Value> = model
        .resources
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "type": r.type_,
                "sensitive": r.sensitive || r.derived_sensitive,
                "depends_on": r.depends_on,
                "notify": r.notify,
                "has_when": r.when.is_some(),
                "loop_item": r.loop_item.is_some() || r.loop_index.is_some(),
            })
        })
        .collect();
    let handlers: Vec<Value> = model
        .handlers
        .iter()
        .map(|h| json!({ "id": h.id, "service": h.service, "sensitive": h.sensitive }))
        .collect();
    let vars: Vec<Value> = model
        .vars
        .values()
        .map(|v| json!({ "name": v.name, "sensitive": v.sensitive }))
        .collect();
    Ok(json!({
        "resources": resources,
        "handlers": handlers,
        "vars": vars,
        "counts": {
            "resources": model.resources.len(),
            "handlers": model.handlers.len(),
            "vars": model.vars.len(),
        },
    }))
}

fn tool_plan(args: &Value) -> Result<Value, ToolError> {
    let manifest = require_manifest(args)?;
    let target_name = args.get("target").and_then(Value::as_str).ok_or_else(|| {
        ToolError::invalid_request("missing or invalid required string parameter \"target\"")
    })?;
    // Supplied-facts planning only: each name selects a canned in-process
    // target snapshot. No SSH, no real host, no mutation (Mode::Plan).
    let fake = match target_name {
        "ubuntu2404" => FakeTarget::ubuntu2404(),
        "ubuntu2604" => FakeTarget::ubuntu2604(),
        "rocky9" => FakeTarget::rocky9(),
        "rocky10" => FakeTarget::rocky10(),
        other => {
            return Err(ToolError::invalid_request(format!(
                "unknown target \"{other}\" (supported: ubuntu2404, ubuntu2604, rocky9, rocky10)"
            )))
        }
    };
    let sudo = args.get("sudo").and_then(Value::as_bool).unwrap_or(false);
    let (stage, path) = stage_manifest(manifest)?;
    check_staged_manifest(&path, &stage)?;
    let model = load_model(&path).map_err(|e| staged_error(e, &stage.canonical))?;
    let opts = RunOptions {
        mode: Mode::Plan,
        sudo,
        target: TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(fake),
    };
    let engine = Engine::new(model, opts).map_err(|e| staged_error(e, &stage.canonical))?;
    let report = engine
        .run()
        .map_err(|e| staged_error(e, &stage.canonical))?;
    let mut out = plan_report_json(&report, false);
    out["mode"] = json!("plan");
    out["target"] = json!(target_name);
    Ok(out)
}

/// Shared RunReport → MCP JSON mapping for both plan surfaces. One
/// serialization path — no MCP-specific planning logic.
///
/// `redact_content` (F-02): for real-host output, a textual diff may carry
/// the observed target file body and/or the desired body — the caller's
/// `sensitive` flag must NOT control whether remote content is disclosed.
/// Host tools therefore collapse every `DiffBody::Text` to `Redacted`,
/// independent of resource sensitivity. Metadata-only `Summary` diffs
/// (mode/owner/state changes) remain visible.
fn plan_report_json(report: &RunReport, redact_content: bool) -> Value {
    let resources: Vec<Value> = report
        .resources
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "type": r.type_,
                "execution": r.execution.label(),
                "change": r.change.label(),
                "verification": r.verification.label(),
                "disposition": r.disposition.label(),
                "reason": r.reason,
                "unknown": r.unknown,
                "sensitive": r.sensitive,
                "diff": r.diff.as_ref().map(|d| match &d.body {
                    crate::result::DiffBody::Text { .. } if redact_content => {
                        json!({ "kind": "redacted" })
                    }
                    crate::result::DiffBody::Text { removed, added } => json!({
                        "kind": "text", "removed": removed, "added": added,
                    }),
                    crate::result::DiffBody::Summary { current, desired } => json!({
                        "kind": "summary", "current": current, "desired": desired,
                    }),
                    crate::result::DiffBody::Redacted => json!({ "kind": "redacted" }),
                }),
            })
        })
        .collect();
    json!({
        "status": match report.status {
            crate::engine::AggregateStatus::Success => "success",
            crate::engine::AggregateStatus::PlanError => "plan_error",
            crate::engine::AggregateStatus::ApplyFailed => "apply_failed",
            crate::engine::AggregateStatus::Indeterminate => "indeterminate",
        },
        "facts": {
            "hostname": report.facts.hostname,
            "os_name": report.facts.os_name,
            "os_family": report.facts.os_family,
            "os_version": report.facts.os_version,
            "arch": report.facts.arch,
        },
        "resources": resources,
        "handlers_pending": report.handlers_pending,
    })
}

// ---------------------------------------------------------------------------
// C2 tools — named-target read-only observation
// ---------------------------------------------------------------------------

/// Opaque profile names only — never connection details.
fn tool_list_targets(reg: &TargetRegistry) -> Result<Value, ToolError> {
    Ok(json!({ "targets": reg.names() }))
}

/// Plan a recipe against a preconfigured named SSH target. Read-only by
/// construction: Mode::Plan on a read-only TargetFs — mutation permits are
/// unobtainable and command resources never execute.
fn tool_plan_host(args: &Value, reg: &TargetRegistry) -> Result<Value, ToolError> {
    require_only(args, &["manifest", "target"])?;
    let manifest = require_manifest(args)?;
    let (stage, path) = stage_manifest(manifest)?;
    // Structural parse of the staged manifest (the only permitted controller
    // read), then the authority policy — before target resolution and before
    // the production loader, which post-policy can only touch the staged
    // file again.
    check_staged_manifest(&path, &stage)?;
    let (name, profile) = resolve_target(args, reg)?;
    let model = load_model(&path).map_err(|e| staged_error(e, &stage.canonical))?;
    let opts = RunOptions {
        mode: Mode::Plan,
        sudo: profile.sudo,
        target: TargetSpec {
            ssh: Some(profile.spec.clone()),
        },
        verbose: false,
        fault: None,
        fake_target: None,
    };
    let engine = Engine::new(model, opts).map_err(|e| host_error(e, &stage.canonical, profile))?;
    let report = engine
        .run()
        .map_err(|e| host_error(e, &stage.canonical, profile))?;
    // F-02: host boundary — file/template content never crosses to the
    // caller, regardless of the manifest's own sensitivity flags.
    let mut out = plan_report_json(&report, true);
    out["mode"] = json!("plan");
    out["target"] = json!(name);
    Ok(out)
}

/// Audit a named SSH target against a recipe via the production audit path:
/// Plan-mode (read-only) engine construction, then `run_audit`, which also
/// refuses any engine that could produce a mutation permit.
fn tool_audit_host(args: &Value, reg: &TargetRegistry) -> Result<Value, ToolError> {
    require_only(args, &["manifest", "target"])?;
    let manifest = require_manifest(args)?;
    let (stage, path) = stage_manifest(manifest)?;
    check_staged_manifest(&path, &stage)?;
    let (name, profile) = resolve_target(args, reg)?;
    let model = load_model(&path).map_err(|e| staged_error(e, &stage.canonical))?;
    let opts = RunOptions {
        mode: Mode::Plan,
        sudo: profile.sudo,
        target: TargetSpec {
            ssh: Some(profile.spec.clone()),
        },
        verbose: false,
        fault: None,
        fake_target: None,
    };
    let engine = Engine::new(model, opts).map_err(|e| host_error(e, &stage.canonical, profile))?;
    let report = run_audit(engine).map_err(|e| host_error(e, &stage.canonical, profile))?;
    let resources: Vec<Value> = report
        .resources
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "type": r.type_,
                "status": r.status.label(),
                "sensitive": r.sensitive,
                "details": r.details.iter().map(|d| json!({
                    "dimension": d.dimension,
                    "observed": d.observed,
                    "desired": d.desired,
                })).collect::<Vec<Value>>(),
                "reason": r.reason,
                "loop_index": r.loop_index,
            })
        })
        .collect();
    let s = &report.summary;
    Ok(json!({
        "status": report.aggregate_label(),
        "target": name,
        "resources": resources,
        "summary": {
            "total": s.total,
            "compliant": s.compliant,
            "drifted": s.drifted,
            "not_auditable": s.not_auditable,
            "not_applicable": s.not_applicable,
            "errors": s.errors,
        },
    }))
}

// ---------------------------------------------------------------------------
// Registry + protocol
// ---------------------------------------------------------------------------

/// The complete C1+C2 tool surface. The allowlist test in tests/mcp.rs
/// asserts this exact set — no mutation-capable tool may ever appear here.
pub fn tool_names() -> Vec<&'static str> {
    vec![
        "sinter_get_version",
        "sinter_classify_platform",
        "sinter_validate_manifest",
        "sinter_inspect_manifest",
        "sinter_plan",
        "sinter_list_targets",
        "sinter_plan_host",
        "sinter_audit_host",
    ]
}

fn tools() -> Vec<Value> {
    vec![
        json!({
            "name": "sinter_get_version",
            "description": "Return the Sinter version and read-only capability statement.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
        }),
        json!({
            "name": "sinter_classify_platform",
            "description": "Classify a target platform from its /etc/os-release content using Sinter's authoritative platform model (family detection, package-backend selection).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "os_release": { "type": "string", "description": "Raw /etc/os-release content." },
                    "arch": { "type": "string", "description": "Machine architecture (default x86_64)." },
                    "hostname": { "type": "string", "description": "Optional hostname label." }
                },
                "required": ["os_release"],
                "additionalProperties": false
            },
        }),
        json!({
            "name": "sinter_validate_manifest",
            "description": "Validate a Sinter recipe (YAML or TOML) with the authoritative parser/validator. Returns valid plus structured diagnostics. Never applies anything.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "manifest": { "type": "string", "description": "Full recipe text (YAML or TOML)." }
                },
                "required": ["manifest"],
                "additionalProperties": false
            },
        }),
        json!({
            "name": "sinter_inspect_manifest",
            "description": "Return deterministic structural facts about a recipe: resource identities, types, dependencies, notifications, sensitivity flags, handlers, and variables. Values are never returned.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "manifest": { "type": "string", "description": "Full recipe text (YAML or TOML)." }
                },
                "required": ["manifest"],
                "additionalProperties": false
            },
        }),
        json!({
            "name": "sinter_plan",
            "description": "Plan a recipe against a supplied-facts target snapshot (canned in-process platforms: ubuntu2404, ubuntu2604, rocky9, rocky10). Pure: no SSH, no real host, no mutation — Mode::Plan only.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "manifest": { "type": "string", "description": "Full recipe text (YAML or TOML)." },
                    "target": {
                        "type": "string",
                        "enum": ["ubuntu2404", "ubuntu2604", "rocky9", "rocky10"],
                        "description": "Supplied-facts target snapshot name."
                    },
                    "sudo": { "type": "boolean", "description": "Model passwordless sudo (default false)." }
                },
                "required": ["manifest", "target"],
                "additionalProperties": false
            },
        }),
        json!({
            "name": "sinter_list_targets",
            "description": "List the opaque names of administrator-configured SSH target profiles. Returns names only — never connection details.",
            "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
        }),
        json!({
            "name": "sinter_plan_host",
            "description": "Plan a recipe against a named administrator-configured SSH target. Read-only observation only (Mode::Plan): no mutation, no command-resource execution. The target is an opaque profile name — connection details cannot be supplied.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "manifest": { "type": "string", "description": "Full recipe text (YAML or TOML)." },
                    "target": { "type": "string", "description": "Named target profile from sinter_list_targets." }
                },
                "required": ["manifest", "target"],
                "additionalProperties": false
            },
        }),
        json!({
            "name": "sinter_audit_host",
            "description": "Audit whether a named administrator-configured SSH target currently satisfies a recipe. Read-only: no mutation, no command-resource execution. The target is an opaque profile name — connection details cannot be supplied.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "manifest": { "type": "string", "description": "Full recipe text (YAML or TOML)." },
                    "target": { "type": "string", "description": "Named target profile from sinter_list_targets." }
                },
                "required": ["manifest", "target"],
                "additionalProperties": false
            },
        }),
    ]
}

fn call_tool(name: &str, args: &Value, reg: &TargetRegistry) -> Result<Value, ToolError> {
    match name {
        "sinter_get_version" => tool_get_version(),
        "sinter_classify_platform" => tool_classify_platform(args),
        "sinter_validate_manifest" => tool_validate_manifest(args),
        "sinter_inspect_manifest" => tool_inspect_manifest(args),
        "sinter_plan" => tool_plan(args),
        "sinter_list_targets" => tool_list_targets(reg),
        "sinter_plan_host" => tool_plan_host(args, reg),
        "sinter_audit_host" => tool_audit_host(args, reg),
        _ => Err(ToolError::invalid_request(format!("unknown tool: {name}"))),
    }
}

fn result_text(v: &Value) -> Value {
    json!({
        "content": [{ "type": "text", "text": serde_json::to_string_pretty(v).unwrap_or_default() }],
        "isError": false,
    })
}

fn result_error(e: &ToolError) -> Value {
    json!({
        "content": [{ "type": "text", "text": serde_json::to_string_pretty(&e.to_json()).unwrap_or_default() }],
        "isError": true,
    })
}

/// Handle one decoded JSON-RPC message. Returns Some(response) for requests,
/// None for notifications.
fn handle(msg: &Value, reg: &TargetRegistry) -> Option<Value> {
    let id = msg.get("id").cloned();
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
    let is_request = id.is_some();

    let response = |result: Value| {
        id.clone()
            .map(|i| json!({ "jsonrpc": "2.0", "id": i, "result": result }))
    };
    let error = |code: i64, message: &str| {
        id.clone().map(
            |i| json!({ "jsonrpc": "2.0", "id": i, "error": { "code": code, "message": message } }),
        )
    };

    match method {
        "initialize" => response(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": { "tools": { "listChanged": false } },
            "serverInfo": { "name": "sinter-mcp", "version": env!("CARGO_PKG_VERSION") },
        })),
        "ping" => response(json!({})),
        "tools/list" => response(json!({ "tools": tools() })),
        "tools/call" => {
            let params = msg.get("params").cloned().unwrap_or(Value::Null);
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            if name.is_empty() || !tool_names().contains(&name) {
                return error(-32602, "invalid params: unknown or missing tool name");
            }
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            if !args.is_object() {
                return error(-32602, "invalid params: \"arguments\" must be an object");
            }
            match call_tool(name, &args, reg) {
                Ok(v) => response(result_text(&v)),
                Err(e) => response(result_error(&e)),
            }
        }
        // Client lifecycle notifications: acknowledged, never answered.
        m if m.starts_with("notifications/") => None,
        _ => {
            if is_request {
                error(-32601, &format!("method not found: {method}"))
            } else {
                None
            }
        }
    }
}

/// Serve MCP over stdio until EOF. Protocol frames only on stdout.
/// `targets` is the immutable named-target registry loaded at startup
/// (empty when `--targets-file` was not given — host tools then fail
/// closed as unknown target).
pub fn serve(targets: TargetRegistry) -> Result<(), SinterError> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("sinter-mcp: stdin error: {e}");
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            // MCP 2025-03-26: receivers MUST accept JSON-RPC batches.
            // Sequential processing; notifications produce no response.
            Ok(Value::Array(items)) => {
                if items.is_empty() {
                    Some(json!({
                        "jsonrpc": "2.0", "id": Value::Null,
                        "error": { "code": -32600, "message": "invalid request: empty batch" }
                    }))
                } else {
                    let mut responses = Vec::new();
                    for item in &items {
                        if item.is_object() {
                            if let Some(r) = handle(item, &targets) {
                                responses.push(r);
                            }
                        } else {
                            responses.push(json!({
                                "jsonrpc": "2.0", "id": Value::Null,
                                "error": { "code": -32600, "message": "invalid request" }
                            }));
                        }
                    }
                    if responses.is_empty() {
                        None // notification-only batch: respond with nothing
                    } else {
                        Some(Value::Array(responses))
                    }
                }
            }
            Ok(msg) => handle(&msg, &targets),
            Err(_) => Some(json!({
                "jsonrpc": "2.0", "id": Value::Null,
                "error": { "code": -32700, "message": "parse error" }
            })),
        };
        if let Some(r) = reply {
            let s = serde_json::to_string(&r)
                .map_err(|e| SinterError::unknown(format!("json encode: {e}")))?;
            writeln!(out, "{s}").map_err(|e| SinterError::unknown(format!("stdout: {e}")))?;
            out.flush()
                .map_err(|e| SinterError::unknown(format!("stdout: {e}")))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINI: &str = "version: 1\nresources:\n  - id: a\n    type: file\n    with:\n      path: /etc/a\n      content: x\n";

    #[cfg(unix)]
    #[test]
    fn stage_permissions_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let (stage, path) = stage_manifest(MINI).unwrap();
        let dm = std::fs::metadata(&stage.canonical)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let fm = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(dm, 0o700, "stage dir mode {dm:o}");
        assert_eq!(fm, 0o600, "manifest mode {fm:o}");
    }

    #[test]
    fn stage_names_are_unique_and_unpredictable() {
        let (a, _) = stage_manifest(MINI).unwrap();
        let (b, _) = stage_manifest(MINI).unwrap();
        assert_ne!(a.canonical, b.canonical);
    }

    #[test]
    fn staged_manifest_refuses_existing_entry() {
        // Simulate the pre-staging attack: the recipe path already exists —
        // here as a symlink pointing at a victim file. create_new must fail
        // rather than follow it.
        let (stage, path) = {
            let (s, _) = stage_manifest(MINI).unwrap();
            let p = s.canonical.join("recipe.yaml");
            std::fs::remove_file(&p).unwrap();
            (s, p)
        };
        let victim = stage.canonical.join("victim");
        std::fs::write(&victim, "do not touch").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&victim, &path).unwrap();
        #[cfg(not(unix))]
        std::fs::write(&path, "planted").unwrap();
        assert!(stage.write_manifest("version: 1\n").is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "do not touch");
    }

    #[test]
    fn stage_removed_on_drop() {
        let dir = {
            let (stage, _) = stage_manifest(MINI).unwrap();
            stage.canonical.clone()
        };
        assert!(!dir.exists(), "stage dir must be removed on drop");
    }

    #[test]
    fn concurrent_staging_does_not_collide() {
        let mut handles = Vec::new();
        for _ in 0..8 {
            handles.push(std::thread::spawn(|| {
                let (stage, path) = stage_manifest(MINI).unwrap();
                assert!(path.exists());
                stage.canonical.clone()
            }));
        }
        let dirs: Vec<PathBuf> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let mut uniq = dirs.clone();
        uniq.sort();
        uniq.dedup();
        assert_eq!(dirs.len(), uniq.len(), "stage dirs must be unique");
    }

    #[test]
    fn redaction_covers_whole_stage_dir() {
        let (stage, _path) = stage_manifest(MINI).unwrap();
        let dir = stage.canonical.display().to_string();
        let err = |m: &str| staged_error(SinterError::schema(m), &stage.canonical).message;
        // Manifest entry itself keeps the logical name.
        assert_eq!(err(&format!("{dir}/recipe.yaml: bad")), "recipe: bad");
        // Other staged-relative paths become recipe:/<rel>.
        assert_eq!(
            err(&format!("{dir}/missing.tpl: not found")),
            "recipe:/missing.tpl: not found"
        );
        assert_eq!(
            err(&format!("{dir}/sub/dir/x.yaml: missing")),
            "recipe:/sub/dir/x.yaml: missing"
        );
        // Unrelated paths are untouched.
        let untouched = "/home/user/elsewhere: nope";
        assert_eq!(err(untouched), untouched);
        // Bare dir also collapses.
        assert!(!err(&format!("inside {dir} boom")).contains(&dir));
    }

    // -----------------------------------------------------------------------
    // C2 R1: F-01 source rejection, F-02 content redaction, F-03 overlap-safe
    // profile redaction
    // -----------------------------------------------------------------------

    fn sentinel_profile() -> TargetProfile {
        TargetProfile {
            spec: crate::engine::SshSpec {
                host: "LEAK".to_string(),
                port: 22,
                user: "LEAK-admin".to_string(),
                known_hosts: PathBuf::from("/tmp/secret"),
                identity_files: vec![PathBuf::from("/tmp/secret/key")],
            },
            sudo: false,
        }
    }

    /// Structural-policy unit tests: build a `Document` with the same
    /// production parser the loader uses, then run the host authority check.
    fn host_doc(manifest: &str) -> Document {
        let root = crate::yaml::parse_yaml(manifest).unwrap();
        document_from_value_test(root)
    }

    fn document_from_value_test(root: crate::value::Value) -> Document {
        crate::document::document_from_value(root, Path::new("recipe.yaml"), "recipe")
            .expect("test manifest must parse")
    }

    #[test]
    fn r2_source_rejected_in_every_key_spelling() {
        // The policy sees parsed structure, so all YAML spellings of the
        // `source` key are equivalent.
        for spelling in [
            "source: /x",           // plain
            "\"source\": /x",       // double-quoted
            "'source': /x",         // single-quoted
            "? source\n      : /x", // explicit key
            "!!str source: /x",     // tagged key
        ] {
            let m = format!(
                "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: /t\n      {spelling}\n"
            );
            assert!(
                check_mcp_manifest_authority(&host_doc(&m)).is_err(),
                "source spelling not rejected: {spelling:?}"
            );
        }
        // Flow mappings.
        for with in ["{ source: /x }", "{ \"source\": /x }", "{ 'source': /x }"] {
            let m =
                format!("version: 1\nresources:\n  - id: f\n    type: file\n    with: {with}\n");
            assert!(
                check_mcp_manifest_authority(&host_doc(&m)).is_err(),
                "flow source not rejected: {with:?}"
            );
        }
        // File and template resources alike.
        for ty in ["file", "template"] {
            let m = format!(
                "version: 1\nresources:\n  - id: f\n    type: {ty}\n    with:\n      path: /t\n      source: /x\n"
            );
            assert!(check_mcp_manifest_authority(&host_doc(&m)).is_err(), "{ty}");
        }
    }

    #[test]
    fn r2_include_rejected_in_all_forms() {
        for inc in [
            "include:\n  - /abs/x.yaml\n",
            "include:\n  - ../rel/x.yaml\n",
            "include:\n  - child.yaml\n",
            "include: [/abs/x.yaml]\n",
            "include:\n  - \"quoted.yaml\"\n",
            "include:\n  - a.yaml\n  - b.yaml\n",
        ] {
            let m = format!("version: 1\n{inc}");
            assert!(
                check_mcp_manifest_authority(&host_doc(&m)).is_err(),
                "include form not rejected: {inc:?}"
            );
        }
    }

    #[test]
    fn r2_source_include_words_in_scalars_not_rejected() {
        // The words may appear as data without granting authority.
        for content in [
            "content: \"source: /tmp/x\"",
            "content: \"include: child.yaml\"",
            "content: |\n        source: /tmp/x\n        include: child.yaml",
            "content: \"# source: /tmp/x\"",
        ] {
            let m = format!(
                "version: 1\n# source: /tmp/x\n# include: child.yaml\nresources:\n  - id: f\n    type: file\n    with:\n      path: /t\n      {content}\n"
            );
            assert!(
                check_mcp_manifest_authority(&host_doc(&m)).is_ok(),
                "false positive on scalar content: {content:?}"
            );
        }
        // A resource literally named `source` or using `include` as data.
        let m = "version: 1\nresources:\n  - id: source\n    type: command\n    with:\n      program: /bin/echo\n      args: [\"include:\", \"source:\"]\n";
        assert!(check_mcp_manifest_authority(&host_doc(m)).is_ok());
    }

    #[test]
    fn n3_short_profile_values_redact_at_boundaries() {
        let mut p = sentinel_profile();
        p.spec.user = "u".to_string();
        p.spec.host = "h1".to_string();
        p.spec.known_hosts = PathBuf::from("/k");
        p.spec.identity_files.clear();
        let (stage, _path) = stage_manifest(MINI).unwrap();
        let err = host_error(
            SinterError::connect("connection refused for u@h1: auth failed for user u"),
            &stage.canonical,
            &p,
        );
        // Standalone occurrences masked; ordinary words intact.
        assert_eq!(
            err.message,
            "connection refused for [target]@[target]: auth failed for user [target]"
        );
    }

    #[test]
    fn f02_host_plan_redacts_text_diffs() {
        use crate::engine::{AggregateStatus, RunReport};
        use crate::result::{
            Change, Diff, DiffBody, Disposition, Execution, ResourceResult, Verification,
        };
        let mk = |id: &str, ty: &str, sensitive: bool| ResourceResult {
            id: id.to_string(),
            type_: ty.to_string(),
            origin: "recipe".to_string(),
            execution: Execution::Succeeded,
            change: Change::Changed,
            verification: Verification::NotPerformed,
            disposition: Disposition::Normal,
            reason: None,
            unknown: false,
            sensitive,
            diff: Some(Diff {
                body: DiffBody::Text {
                    removed: vec!["TARGET_SECRET_F02_6B4E".to_string()],
                    added: vec!["DESIRED_SECRET_F02_AA39".to_string()],
                },
            }),
            notes: vec![],
            handler_notifications: vec![],
            loop_index: None,
        };
        let report = RunReport {
            resources: vec![
                mk("plain-file", "file", false),
                mk("tpl", "template", false),
                mk("sens", "file", true),
            ],
            handlers_run: vec![],
            handlers_pending: vec![],
            facts: crate::facts::Facts {
                hostname: "h".to_string(),
                os_name: "ubuntu".to_string(),
                os_family: "debian".to_string(),
                os_version: "24.04".to_string(),
                arch: "x86_64".to_string(),
            },
            status: AggregateStatus::Success,
            commands: vec![],
        };
        // Host boundary: no content, whatever the caller's sensitive flags.
        let host = serde_json::to_string(&plan_report_json(&report, true)).unwrap();
        assert!(!host.contains("TARGET_SECRET_F02_6B4E"), "{host}");
        assert!(!host.contains("DESIRED_SECRET_F02_AA39"), "{host}");
        let v = plan_report_json(&report, true);
        for r in v["resources"].as_array().unwrap() {
            assert_eq!(r["diff"]["kind"], "redacted");
            // Non-content plan information survives.
            assert!(r["id"].is_string() && r["change"].is_string());
        }
        // The offline supplied-facts tool is unchanged.
        let offline = serde_json::to_string(&plan_report_json(&report, false)).unwrap();
        assert!(offline.contains("TARGET_SECRET_F02_6B4E"));
    }

    #[test]
    fn f03_overlapping_profile_values_fully_redacted() {
        let p = sentinel_profile();
        let (stage, _path) = stage_manifest(MINI).unwrap();
        let err = host_error(
            SinterError::connect(
                "auth failed for LEAK-admin@LEAK using /tmp/secret/key (/tmp/secret)",
            ),
            &stage.canonical,
            &p,
        );
        // Complete configured values must not survive, even overlapping.
        assert!(!err.message.contains("LEAK-admin"), "{}", err.message);
        assert!(!err.message.contains("/tmp/secret/key"), "{}", err.message);
        assert!(!err.message.contains("LEAK"), "{}", err.message);
        assert!(!err.message.contains("/tmp/secret"), "{}", err.message);
        assert!(err.message.contains("[target]"), "{}", err.message);
        // Meaning is preserved: still a readable failure line.
        assert!(err.message.contains("auth failed"), "{}", err.message);
    }

    #[test]
    fn f03_empty_profile_values_are_safe() {
        let mut p = sentinel_profile();
        p.spec.identity_files.clear();
        let (stage, _path) = stage_manifest(MINI).unwrap();
        let err = host_error(SinterError::connect("plain failure"), &stage.canonical, &p);
        assert_eq!(err.message, "plain failure");
    }
}
