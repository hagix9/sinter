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

use crate::engine::{Engine, Mode, RunOptions, TargetSpec};
use crate::error::{ErrorKind, SinterError};
use crate::executor::FakeTarget;
use crate::facts::Facts;
use crate::model::load_model;
use crate::platform::PackageBackend;
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

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

/// Replace the staged filesystem path inside a core diagnostic with the
/// logical manifest name — tool output must not leak local paths.
fn staged_error(e: SinterError, staged: &Path) -> ToolError {
    let mut t = ToolError::from_core(&e);
    let sp = staged.display().to_string();
    if t.message.contains(&sp) {
        t.message = t.message.replace(&sp, "recipe");
    }
    t
}

// ---------------------------------------------------------------------------
// Manifest staging
// ---------------------------------------------------------------------------

/// Private temporary directory holding one staged manifest so the existing
/// file-based `load_model` parser can run unchanged. Deleted on drop.
struct Stage(PathBuf);

static STAGE_SEQ: AtomicU64 = AtomicU64::new(0);

impl Stage {
    fn new() -> Result<Self, ToolError> {
        let dir = std::env::temp_dir().join(format!(
            "sinter-mcp-{}-{}",
            std::process::id(),
            STAGE_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).map_err(|e| ToolError {
            category: "internal_error",
            kind: None,
            message: format!("cannot create staging directory: {e}"),
        })?;
        // Canonicalize so staged paths match the canonicalized paths the
        // parser reports in diagnostics (staged_error replaces them).
        let dir = std::fs::canonicalize(&dir).unwrap_or(dir);
        Ok(Self(dir))
    }

    /// Write manifest content into the stage and return the entry path.
    /// Includes, if any, resolve relative to the staging directory; a
    /// manifest that references files not staged fails honestly.
    fn write_manifest(&self, manifest: &str) -> Result<PathBuf, ToolError> {
        let p = self.0.join("recipe.yaml");
        std::fs::write(&p, manifest).map_err(|e| ToolError {
            category: "internal_error",
            kind: None,
            message: format!("cannot stage manifest: {e}"),
        })?;
        Ok(p)
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
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
    let (_stage, path) = stage_manifest(manifest)?;
    match load_model(&path) {
        Ok(model) => Ok(json!({
            "valid": true,
            "resources": model.resources.len(),
            "handlers": model.handlers.len(),
            "vars": model.vars.len(),
        })),
        Err(e) => Ok(json!({
            "valid": false,
            "diagnostics": [staged_error(e, &path).to_json()["error"]],
        })),
    }
}

fn tool_inspect_manifest(args: &Value) -> Result<Value, ToolError> {
    let manifest = require_manifest(args)?;
    let (_stage, path) = stage_manifest(manifest)?;
    let model = load_model(&path).map_err(|e| staged_error(e, &path))?;
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
    let (_stage, path) = stage_manifest(manifest)?;
    let model = load_model(&path).map_err(|e| staged_error(e, &path))?;
    let opts = RunOptions {
        mode: Mode::Plan,
        sudo,
        target: TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(fake),
    };
    let engine = Engine::new(model, opts).map_err(|e| staged_error(e, &path))?;
    let report = engine.run().map_err(|e| staged_error(e, &path))?;
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
    Ok(json!({
        "status": match report.status {
            crate::engine::AggregateStatus::Success => "success",
            crate::engine::AggregateStatus::PlanError => "plan_error",
            crate::engine::AggregateStatus::ApplyFailed => "apply_failed",
            crate::engine::AggregateStatus::Indeterminate => "indeterminate",
        },
        "mode": "plan",
        "target": target_name,
        "facts": {
            "hostname": report.facts.hostname,
            "os_name": report.facts.os_name,
            "os_family": report.facts.os_family,
            "os_version": report.facts.os_version,
            "arch": report.facts.arch,
        },
        "resources": resources,
        "handlers_pending": report.handlers_pending,
    }))
}

// ---------------------------------------------------------------------------
// Registry + protocol
// ---------------------------------------------------------------------------

/// The complete C1 tool surface. The allowlist test in tests/mcp.rs asserts
/// this exact set — no mutation-capable tool may ever appear here.
pub fn tool_names() -> Vec<&'static str> {
    vec![
        "sinter_get_version",
        "sinter_classify_platform",
        "sinter_validate_manifest",
        "sinter_inspect_manifest",
        "sinter_plan",
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
    ]
}

fn call_tool(name: &str, args: &Value) -> Result<Value, ToolError> {
    match name {
        "sinter_get_version" => tool_get_version(),
        "sinter_classify_platform" => tool_classify_platform(args),
        "sinter_validate_manifest" => tool_validate_manifest(args),
        "sinter_inspect_manifest" => tool_inspect_manifest(args),
        "sinter_plan" => tool_plan(args),
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
fn handle(msg: &Value) -> Option<Value> {
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
            match call_tool(name, &args) {
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
pub fn serve() -> Result<(), SinterError> {
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
            Ok(msg) => handle(&msg),
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
