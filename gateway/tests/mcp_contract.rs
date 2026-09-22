//! MCP edge contract tests (Q-2): edge lifecycle vs forwarded tool traffic,
//! plus a LIVE contract proof against the real `sinter mcp` binary over stdio.

use serde_json::{json, Value};
use sinter_gateway::edge::*;
use sinter_gateway::*;

const ACC: &str = "acc_a";

fn session() -> EdgeSession {
    EdgeSession::default()
}

fn acc() -> AccountId {
    AccountId::new(ACC)
}

// ---------- edge-only contract ----------

#[test]
fn initialize_is_edge_answered_with_truthful_contract() {
    let mut s = session();
    let f = json!({"jsonrpc":"2.0","id":1,"method":"initialize",
        "params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"chatgpt","version":"1"}}});
    match handle_frame(&mut s, &f) {
        EdgeAction::Answer(r) => {
            assert_eq!(r["id"], 1);
            let res = &r["result"];
            assert_eq!(res["protocolVersion"], "2025-06-18"); // supported → echoed
            assert_eq!(res["serverInfo"]["name"], "sinter-gateway");
            assert!(res["capabilities"]["tools"].is_object());
        }
        _ => panic!("initialize must be edge-answered"),
    }
    assert!(s.initialized);
    assert_eq!(s.negotiated_version.as_deref(), Some("2025-06-18"));
}

#[test]
fn initialize_negotiates_unknown_version_down_to_edge_preferred() {
    let mut s = session();
    let f = json!({"jsonrpc":"2.0","id":1,"method":"initialize",
        "params":{"protocolVersion":"1999-01-01"}});
    match handle_frame(&mut s, &f) {
        EdgeAction::Answer(r) => {
            assert_eq!(r["result"]["protocolVersion"], "2025-11-25");
        }
        _ => panic!(),
    }
}

#[test]
fn reinitialize_is_rejected() {
    let mut s = session();
    let f = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}});
    let _ = handle_frame(&mut s, &f);
    match handle_frame(&mut s, &f) {
        EdgeAction::Answer(r) => assert_eq!(r["error"]["code"], -32600),
        _ => panic!("re-initialize must fail"),
    }
}

#[test]
fn notifications_are_consumed_never_forwarded() {
    let mut s = session();
    // notifications/initialized — before AND after init, always AcceptOnly.
    let n = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
    assert!(matches!(handle_frame(&mut s, &n), EdgeAction::AcceptOnly));
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}});
    let _ = handle_frame(&mut s, &init);
    assert!(matches!(handle_frame(&mut s, &n), EdgeAction::AcceptOnly));
    // notifications/cancelled is STILL consumed at the edge (never
    // forwarded) but as of P5 maps to EdgeAction::Cancel carrying the
    // caller's public requestId (RFC §8: edge maps it to `cancelled`).
    let cancelled =
        json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"req_x"}});
    match handle_frame(&mut s, &cancelled) {
        EdgeAction::Cancel(id) => assert_eq!(id, json!("req_x")),
        _ => panic!("cancelled notification must surface the requestId"),
    }
}

#[test]
fn ping_is_edge_answered() {
    let mut s = session();
    let f = json!({"jsonrpc":"2.0","id":5,"method":"ping"});
    match handle_frame(&mut s, &f) {
        EdgeAction::Answer(r) => assert_eq!(r["result"], json!({})),
        _ => panic!(),
    }
}

#[test]
fn tools_calls_are_blocked_before_initialize() {
    let mut s = session();
    for f in [
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sinter_get_version","arguments":{}}}),
    ] {
        match handle_frame(&mut s, &f) {
            EdgeAction::Answer(r) => assert_eq!(r["error"]["code"], -32600),
            _ => panic!("pre-init tool traffic must fail closed"),
        }
    }
}

#[test]
fn tools_list_and_call_forward_verbatim_after_init() {
    let mut s = session();
    let init = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}});
    let _ = handle_frame(&mut s, &init);

    let tl = json!({"jsonrpc":"2.0","id":2,"method":"tools/list"});
    match handle_frame(&mut s, &tl) {
        EdgeAction::Forward(f) => assert_eq!(f, tl), // byte-verbatim, caller id intact
        _ => panic!("tools/list must forward"),
    }
    let tc = json!({"jsonrpc":"2.0","id":"weird-id-42","method":"tools/call",
        "params":{"name":"sinter_audit_host","arguments":{"target":"demo","manifest":"m"}}});
    match handle_frame(&mut s, &tc) {
        EdgeAction::Forward(f) => assert_eq!(f, tc),
        _ => panic!("tools/call must forward"),
    }
}

#[test]
fn profile_tool_is_edge_answered_from_account_identity() {
    let mut s = session();
    s.initialized = true;
    let f = json!({"jsonrpc":"2.0","id":9,"method":"tools/call",
        "params":{"name":PROFILE_TOOL,"arguments":{}}});
    match handle_frame(&mut s, &f) {
        EdgeAction::Profile(id) => {
            // The MCP layer answers from the authenticated principal.
            let r = sinter_gateway::edge::profile_result(
                &id,
                &acc(),
                Some("Alice A"),
                Some("a@example.com"),
            );
            assert_eq!(r["result"]["structuredContent"]["id"], ACC);
            assert_eq!(r["result"]["structuredContent"]["name"], "Alice A");
            assert_eq!(r["result"]["structuredContent"]["email"], "a@example.com");
            assert_eq!(r["result"]["isError"], false);
        }
        _ => panic!("profile tool must be edge-classified"),
    }
}

#[test]
fn unsupported_methods_are_edge_rejected_not_forwarded() {
    let mut s = session();
    s.initialized = true;
    for m in [
        "resources/list",
        "prompts/get",
        "sampling/createMessage",
        "exec",
        "",
    ] {
        let f = json!({"jsonrpc":"2.0","id":1,"method":m});
        match handle_frame(&mut s, &f) {
            EdgeAction::Answer(r) => assert_eq!(r["error"]["code"], -32601),
            EdgeAction::Forward(_) => panic!("{m} must not reach the controller"),
            _ => panic!(),
        }
    }
}

#[test]
fn malformed_frames_rejected_at_edge() {
    let mut s = session();
    for f in [
        json!([{"jsonrpc":"2.0","id":1,"method":"ping"}]), // batch — not in Streamable HTTP
        json!(42),                                         // non-object
        json!({"id":1,"method":"ping"}),                   // missing jsonrpc
        json!({"jsonrpc":"1.9","id":1,"method":"ping"}),   // wrong version
        json!({"jsonrpc":"2.0","id":1}),                   // request w/o method
        json!({"jsonrpc":"2.0","method":"explode"}),       // notification w/o prefix
    ] {
        match handle_frame(&mut s, &f) {
            EdgeAction::Answer(r) => assert_eq!(r["error"]["code"], -32600, "frame: {f}"),
            _ => panic!("malformed frame must not be forwarded: {f}"),
        }
    }
}

#[test]
fn profile_tool_injection_into_tools_list() {
    let resp = json!({"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"sinter_get_version"}]}});
    let out = inject_profile_tool(&resp);
    let tools = out["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 2);
    assert_eq!(tools[1]["name"], PROFILE_TOOL);
    assert_eq!(tools[1]["_meta"]["openai/profile"], true);
    assert_eq!(tools[1]["annotations"]["readOnlyHint"], true);
    // Non-conforming input passes through untouched.
    let err = json!({"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"x"}});
    assert_eq!(inject_profile_tool(&err), err);
}

#[test]
fn transport_error_maps_to_structured_jsonrpc_error() {
    let e = TransportError::new(ErrorCode::ControllerOffline, "down");
    let r = transport_error_jsonrpc(&json!(7), &e);
    assert_eq!(r["error"]["code"], -32000);
    assert_eq!(r["error"]["data"]["code"], "controller_offline");
    assert_eq!(r["id"], 7);
}

// ---------- LIVE contract: real sinter mcp over stdio ----------

struct SinterChild {
    stdin: std::process::ChildStdin,
    stdout: std::io::BufReader<std::process::ChildStdout>,
    _proc: std::process::Child,
}

impl SinterChild {
    fn spawn() -> Option<Self> {
        let bin = std::env::var("SINTER_MCP_BIN").unwrap_or_else(|_| {
            "/Volumes/VGX1000 SSD/Codex/Projects/Sinter/target/debug/sinter".into()
        });
        let mut p = std::process::Command::new(&bin)
            .args(["mcp"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()?;
        Some(Self {
            stdin: p.stdin.take().unwrap(),
            stdout: std::io::BufReader::new(p.stdout.take().unwrap()),
            _proc: p,
        })
    }
    fn call(&mut self, frame: &Value) -> Value {
        use std::io::{BufRead, Write};
        writeln!(self.stdin, "{}", frame).unwrap();
        self.stdin.flush().unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    }
}

#[test]
fn live_sinter_backend_contract() {
    let Some(mut child) = SinterChild::spawn() else {
        eprintln!("SKIP: sinter binary not found");
        return;
    };
    // initialize: constant, idempotent, fixed version.
    let r = child.call(&json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}));
    assert_eq!(r["result"]["protocolVersion"], "2025-03-26");
    assert_eq!(r["result"]["serverInfo"]["name"], "sinter-mcp");
    // tools/list: exactly the 8 v0.5.0 tools — the edge forwards to this authority.
    let r = child.call(&json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}));
    let names: Vec<&str> = r["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "sinter_get_version",
            "sinter_classify_platform",
            "sinter_validate_manifest",
            "sinter_inspect_manifest",
            "sinter_plan",
            "sinter_list_targets",
            "sinter_plan_host",
            "sinter_audit_host"
        ]
    );
    // tools/call: real semantics — caller id echoed verbatim.
    let r = child.call(
        &json!({"jsonrpc":"2.0","id":"weird-id-42","method":"tools/call",
        "params":{"name":"sinter_get_version","arguments":{}}}),
    );
    assert_eq!(r["id"], "weird-id-42");
    assert_eq!(r["result"]["isError"], false);
}

#[test]
fn live_notification_produces_no_output_line() {
    // Proves the edge MUST NOT forward notifications: sinter never answers
    // them, and a bridge waiting on a line would deadlock.
    let Some(mut child) = SinterChild::spawn() else {
        eprintln!("SKIP: sinter binary not found");
        return;
    };
    use std::io::Write;
    writeln!(
        child.stdin,
        "{}",
        json!({"jsonrpc":"2.0","method":"notifications/initialized"})
    )
    .unwrap();
    child.stdin.flush().unwrap();
    // Probe aliveness with a ping instead of blocking on a line that never comes.
    let r = child.call(&json!({"jsonrpc":"2.0","id":3,"method":"ping"}));
    assert_eq!(r["id"], 3);
}

#[test]
fn live_edge_to_backend_forwarding_chain() {
    // The complete Q-2 chain without any network: edge classifies → forward
    // verbatim → real sinter answers → caller's JSON-RPC id preserved.
    let Some(mut child) = SinterChild::spawn() else {
        eprintln!("SKIP: sinter binary not found");
        return;
    };
    let mut s = session();
    s.initialized = true;
    let f = json!({"jsonrpc":"2.0","id":77,"method":"tools/call",
        "params":{"name":"sinter_validate_manifest","arguments":
            {"manifest":"version: 1\nresources:\n  - id: tree\n    type: package\n    with:\n      name: tree\n      state: present\n"}}});
    match handle_frame(&mut s, &f) {
        EdgeAction::Forward(frame) => {
            let r = child.call(&frame);
            assert_eq!(r["id"], 77); // caller id preserved end-to-end
            assert_eq!(r["result"]["isError"], false);
        }
        _ => panic!("must forward"),
    }
}
