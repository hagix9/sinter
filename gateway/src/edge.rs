//! Public MCP edge contract (RFC §9, Q-2).
//!
//! The Gateway IS the public MCP server. The edge owns protocol lifecycle
//! (initialize/ping/notifications/sessions); tool authority stays with the
//! controller's `sinter mcp`. The edge inspects only JSON-RPC envelope fields
//! (`jsonrpc`, `id`, `method`, `params.name`) — never manifests, arguments,
//! or result contents.
//!
//! Observed backend contract (sinter v0.5.0 `src/mcp.rs`, verified):
//!   methods: initialize, ping, tools/list, tools/call
//!   initialize: constant response, idempotent, protocolVersion "2025-03-26"
//!   notifications/*: consumed, never answered
//!   batches: accepted; answered as one line when responses exist
//!   never emits unsolicited server->client messages
//!
//! Edge decisions that follow from that contract:
//!   - Edge answers initialize itself → controller never sees lifecycle
//!     traffic; sinter's fixed "2025-03-26" cannot leak a version claim the
//!     edge cannot honor, and plugin connect works while controller is down.
//!   - Notifications are 202'd at the edge and NOT forwarded — sinter
//!     produces no reply for them and the stdio child would deadlock waiting.
//!   - Only tools/list + tools/call are forwarded; every other method is a
//!     JSON-RPC -32601 at the edge, keeping the public surface exact.
//!   - JSON-RPC batches are rejected at the edge (-32600): the Streamable
//!     HTTP transport defines a single message per POST; sinter's batch
//!     support remains available on its private stdio leg.

use serde_json::{json, Value};

use crate::id::AccountId;
use crate::proto::TransportError;

/// Protocol versions the edge itself implements for lifecycle semantics.
pub const EDGE_PROTOCOL_VERSIONS: &[&str] = &["2025-03-26", "2025-06-18", "2025-11-25"];
/// Version offered when the client requests one the edge does not know;
/// per MCP negotiation the client decides whether to continue.
pub const EDGE_PREFERRED_VERSION: &str = "2025-11-25";

pub const GATEWAY_SERVER_NAME: &str = "sinter-gateway";
/// Platform profile tool (OpenAI `_meta["openai/profile"]` contract): resolved
/// from the caller's validated identity — a thing only the Gateway can know.
pub const PROFILE_TOOL: &str = "sinter_get_profile";

/// Per-connection lifecycle state. The future HTTP layer holds one per
/// `MCP-Session-Id`; P1 drives it directly in tests.
#[derive(Debug, Default)]
pub struct EdgeSession {
    pub initialized: bool,
    pub negotiated_version: Option<String>,
}

pub enum EdgeAction {
    /// Edge answers directly with this JSON-RPC response object.
    Answer(Value),
    /// Forward the frame verbatim to the account's controller as a work item.
    Forward(Value),
    /// Consumed without a response — HTTP 202 at the transport layer.
    AcceptOnly,
    /// `notifications/cancelled` — the public JSON-RPC id the caller wants
    /// cancelled (RFC §8: edge maps it to the `cancelled` request state).
    /// Still answered 202; cancellation is best-effort against live work.
    Cancel(Value),
}

fn result(id: &Value, r: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": r})
}

fn error(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// Map a transport error to a client-legible JSON-RPC error (-32000 with
/// structured data). Used wherever a forwarded call cannot be completed.
pub fn transport_error_jsonrpc(id: &Value, e: &TransportError) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32000,
            "message": e.message,
            "data": {"code": e.code},
        }
    })
}

/// OpenAI profile-tool definition injected into forwarded `tools/list`
/// responses — the single documented exception to pure pass-through.
pub fn profile_tool_def() -> Value {
    json!({
        "name": PROFILE_TOOL,
        "description": "Return the Sinter account profile represented by the current authenticated credentials.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
        "outputSchema": {
            "type": "object",
            "properties": {
                "id": {"type": "string", "minLength": 1},
                "name": {"type": "string"},
                "email": {"type": "string"},
                "nickname": {"type": "string"}
            },
            "required": ["id"],
            "additionalProperties": false
        },
        "annotations": {"readOnlyHint": true, "destructiveHint": false, "openWorldHint": false},
        "_meta": {"openai/profile": true}
    })
}

/// Append the profile tool to a `tools/list` response. Pass-through on any
/// non-conforming shape (e.g. an error response) — never invents tools.
/// Fail-closed on name conflict: if the backend ever claims the profile tool
/// name itself, the edge returns the response unchanged rather than
/// producing a duplicate-name list (RFC §17 tool-authority rule).
pub fn inject_profile_tool(tools_list_response: &Value) -> Value {
    let mut resp = tools_list_response.clone();
    if let Some(tools) = resp
        .get_mut("result")
        .and_then(|r| r.get_mut("tools"))
        .and_then(|t| t.as_array_mut())
    {
        let conflict = tools
            .iter()
            .any(|t| t.get("name").and_then(Value::as_str) == Some(PROFILE_TOOL));
        if !conflict {
            tools.push(profile_tool_def());
        }
    }
    resp
}

fn profile_result(id: &Value, account: &AccountId) -> Value {
    let profile = json!({"id": account.as_str()});
    result(
        id,
        json!({
            "content": [{"type": "text", "text": profile.to_string()}],
            "structuredContent": profile,
            "isError": false
        }),
    )
}

/// Classify one inbound JSON-RPC frame. Single messages only — arrays are
/// rejected per the Streamable HTTP transport contract.
pub fn handle_frame(session: &mut EdgeSession, account: &AccountId, frame: &Value) -> EdgeAction {
    if frame.is_array() {
        return EdgeAction::Answer(error(
            &Value::Null,
            -32600,
            "invalid request: batches not supported",
        ));
    }
    if !frame.is_object() {
        return EdgeAction::Answer(error(&Value::Null, -32600, "invalid request"));
    }
    let id = frame.get("id");
    let method = frame.get("method").and_then(Value::as_str);
    let version_ok = frame
        .get("jsonrpc")
        .and_then(Value::as_str)
        .is_some_and(|v| v == "2.0");
    if !version_ok {
        return EdgeAction::Answer(error(
            &id.cloned().unwrap_or(Value::Null),
            -32600,
            "invalid request",
        ));
    }

    // Notifications (no id): consumed at the edge, never forwarded — sinter
    // mcp answers none of them and a forwarded one would deadlock stdio.
    let Some(id) = id else {
        return match method {
            Some("notifications/cancelled") => {
                // RFC §8/§9: caller cancellation is edge-mapped to the
                // `cancelled` request state. The public JSON-RPC id is an
                // envelope field — params.requestId is lifecycle metadata,
                // never Sinter payload.
                let rid = frame
                    .get("params")
                    .and_then(|p| p.get("requestId"))
                    .cloned()
                    .unwrap_or(Value::Null);
                EdgeAction::Cancel(rid)
            }
            Some(m) if m.starts_with("notifications/") => EdgeAction::AcceptOnly,
            _ => EdgeAction::Answer(error(&Value::Null, -32600, "invalid notification")),
        };
    };
    let Some(method) = method else {
        return EdgeAction::Answer(error(id, -32600, "invalid request"));
    };

    match method {
        "initialize" => {
            if session.initialized {
                return EdgeAction::Answer(error(id, -32600, "session already initialized"));
            }
            let offered = frame
                .get("params")
                .and_then(|p| p.get("protocolVersion"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let negotiated = if EDGE_PROTOCOL_VERSIONS.contains(&offered) {
                offered.to_string()
            } else {
                EDGE_PREFERRED_VERSION.to_string()
            };
            session.initialized = true;
            session.negotiated_version = Some(negotiated.clone());
            EdgeAction::Answer(result(
                id,
                json!({
                    "protocolVersion": negotiated,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": GATEWAY_SERVER_NAME, "version": env!("CARGO_PKG_VERSION")},
                }),
            ))
        }
        "ping" => EdgeAction::Answer(result(id, json!({}))),
        _ if !session.initialized => {
            EdgeAction::Answer(error(id, -32600, "session not initialized"))
        }
        "tools/list" => EdgeAction::Forward(frame.clone()),
        "tools/call" => {
            let name = frame
                .get("params")
                .and_then(|p| p.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("");
            if name == PROFILE_TOOL {
                EdgeAction::Answer(profile_result(id, account))
            } else {
                // Forwarded verbatim — tool-name validity is sinter's
                // authority, not the gateway's.
                EdgeAction::Forward(frame.clone())
            }
        }
        _ => EdgeAction::Answer(error(id, -32601, "method not found")),
    }
}
