//! Bounds & wire-shape tests: size limits, malformed envelopes, and the
//! structural proof that no execution-control field can exist in the
//! controller work envelope (I-2).

use serde_json::{json, Value};
use sinter_gateway::*;

fn setup() -> (GatewayCore<TestClock>, AccountId, ControllerId) {
    let c = GatewayCore::with_clock(TestClock::new());
    let acc = AccountId::new("acc_a");
    let ctl = ControllerId::new("ctl_a");
    c.register_controller(&ctl, &acc).unwrap();
    (c, acc, ctl)
}

#[test]
fn oversized_request_rejected() {
    let (c, acc, _ctl) = setup();
    let big =
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"pad":"x".repeat(2 << 20)}});
    let e = c.submit(&acc, big, None).unwrap_err();
    assert_eq!(e.code, "oversized_request");
}

#[test]
fn oversized_response_rejected_without_consuming_request() {
    let (c, acc, ctl) = setup();
    let (rid, _rx) = c
        .submit(&acc, json!({"jsonrpc":"2.0","id":1,"method":"ping"}), None)
        .unwrap();
    c.poll(&ctl).unwrap();
    let big = Outcome::Mcp(json!({"pad": "x".repeat(5 << 20)}));
    let e = c.respond(&ctl, &rid, big).unwrap_err();
    assert_eq!(e.code, "oversized_response");
    // Request still open — a legal response afterwards still completes.
    assert_eq!(c.request_state(&rid), Some(ReqState::Delivered));
    c.respond(&ctl, &rid, Outcome::Mcp(json!({"ok":1})))
        .unwrap();
}

#[test]
fn malformed_respond_bodies_rejected() {
    // both mcp and error set
    let r = RespondRequest {
        v: PROTO_VERSION,
        request_id: "req_x".into(),
        mcp: Some(json!({})),
        error: Some(TransportError::new(ErrorCode::BackendUnavailable, "x")),
    };
    assert_eq!(r.into_outcome().unwrap_err().code, "malformed_request");
    // neither set
    let r = RespondRequest {
        v: PROTO_VERSION,
        request_id: "req_x".into(),
        mcp: None,
        error: None,
    };
    assert!(r.into_outcome().is_err());
    // wrong protocol version
    let r = RespondRequest {
        v: 99,
        request_id: "req_x".into(),
        mcp: Some(json!({})),
        error: None,
    };
    assert_eq!(r.into_outcome().unwrap_err().code, "malformed_request");
}

#[test]
fn work_item_schema_is_exact_and_rejects_unknown_fields() {
    let w = WorkItem {
        v: PROTO_VERSION,
        request_id: "req_abc".into(),
        deadline_unix_ms: 123,
        mcp: json!({"m":1}),
    };
    let s: Value = serde_json::to_value(&w).unwrap();
    let keys: std::collections::BTreeSet<String> = s.as_object().unwrap().keys().cloned().collect();
    assert_eq!(
        keys.into_iter().collect::<Vec<_>>(),
        ["deadline_unix_ms", "mcp", "request_id", "v"]
    );

    // deny_unknown_fields: an injected execution-control key fails to parse.
    let forged = json!({"v":1,"request_id":"req_x","deadline_unix_ms":1,
        "mcp":{},"exec":"/bin/sh","argv":["-c","rm -rf /"]});
    assert!(serde_json::from_value::<WorkItem>(forged).is_err());
}

#[test]
fn no_execution_control_fields_exist_anywhere_in_protocol() {
    // Structural audit: recursively scan every protocol type's serialized
    // shape for keys that could steer execution.
    let banned = [
        "exec", "cmd", "command", "argv", "args", "shell", "env", "binary", "path", "program",
    ];
    for v in [
        serde_json::to_value(WorkItem {
            v: 1,
            request_id: "r".into(),
            deadline_unix_ms: 0,
            mcp: json!(null),
        })
        .unwrap(),
        serde_json::to_value(RespondRequest {
            v: 1,
            request_id: "r".into(),
            mcp: Some(json!(null)),
            error: None,
        })
        .unwrap(),
    ] {
        let mut stack = vec![v];
        while let Some(x) = stack.pop() {
            if let Some(obj) = x.as_object() {
                for (k, val) in obj {
                    if k != "mcp" {
                        assert!(!banned.contains(&k.as_str()), "execution field leaked: {k}");
                    }
                    stack.push(val.clone());
                }
            }
        }
    }
}

#[test]
fn error_codes_are_stable_and_safe() {
    // The full taxonomy exists and serializes to the documented wire names.
    for (code, wire) in [
        (ErrorCode::MalformedRequest, "malformed_request"),
        (ErrorCode::UnsupportedMethod, "unsupported_method"),
        (ErrorCode::InvalidLifecycleState, "invalid_lifecycle_state"),
        (ErrorCode::UnknownRequest, "unknown_request"),
        (ErrorCode::WrongController, "wrong_controller"),
        (ErrorCode::WrongAccount, "wrong_account"),
        (ErrorCode::DuplicateResponse, "duplicate_response"),
        (ErrorCode::ExpiredRequest, "expired_request"),
        (ErrorCode::CancelledRequest, "cancelled_request"),
        (ErrorCode::DeadlineExceeded, "deadline_exceeded"),
        (ErrorCode::OversizedRequest, "oversized_request"),
        (ErrorCode::OversizedResponse, "oversized_response"),
        (ErrorCode::ControllerOffline, "controller_offline"),
        (ErrorCode::BackendUnavailable, "backend_unavailable"),
        (ErrorCode::BackendTerminated, "backend_terminated"),
    ] {
        assert_eq!(serde_json::to_string(&code).unwrap(), format!("\"{wire}\""));
        assert_eq!(code.as_str(), wire);
    }
}
