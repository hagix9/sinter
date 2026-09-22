//! Secret-bearing-log regression test (I-7): run operations whose MCP
//! payloads contain marker secrets; assert diagnostic logs contain only the
//! approved identifiers and never the markers.

use serde_json::json;
use sinter_gateway::*;
use std::io::Write;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn logs_never_contain_payloads_or_secret_material() {
    let cap = Capture(Arc::new(Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(cap.clone())
        .with_ansi(false)
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let c = GatewayCore::new();
        let acc = AccountId::new("acc_a");
        let ctl = ControllerId::new("ctl_a");
        c.register_controller(&ctl, &acc).unwrap();

        // Marker strings standing in for secrets: bearer-like token, manifest
        // content, tool arguments, SSH-like material.
        let markers = [
            "ctrlk_DEADBEEF_SECRET",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "s3cr3t-manifest-content-xyz",
            "ssh-rsa AAAA_marked",
        ];
        let mcp = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
            "name":"sinter_audit_host",
            "arguments":{"target":"t","manifest":markers[2],"auth":markers[0],"key":markers[1]}
        }});
        let (rid, _rx) = c.submit(&acc, mcp, None).unwrap();
        c.poll(&ctl).unwrap();
        c.respond(&ctl, &rid, Outcome::Mcp(json!({"result": markers[3]})))
            .unwrap();
        c.submit(
            &acc,
            json!({"jsonrpc":"2.0","id":2,"method":"ping","secret":markers[0]}),
            None,
        )
        .unwrap();
        c.sweep_expired();
    });

    let logs = String::from_utf8(cap.0.lock().unwrap().clone()).unwrap();
    assert!(!logs.is_empty(), "expected some log output");
    for m in [
        "ctrlk_DEADBEEF_SECRET",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "s3cr3t-manifest-content-xyz",
        "ssh-rsa AAAA_marked",
    ] {
        assert!(!logs.contains(m), "secret leaked into logs: {m}");
    }
    // Sanity: approved identifiers DO appear (logging is working, not blank).
    assert!(
        logs.contains("ctl_a") || logs.contains("req_"),
        "no diagnostic output at all"
    );
}
