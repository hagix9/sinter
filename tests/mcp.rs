//! Core MCP (stdio) tests: protocol surface, tool behavior, error contract,
//! adversarial inputs, determinism, and external-client E2E.
//!
//! Every test talks to the real `sinter mcp` process over newline-delimited
//! JSON-RPC — no internal Rust calls are used for the protocol paths.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};

const VALID: &str = "version: 1\nresources:\n  - id: motd\n    type: file\n    with:\n      path: /etc/motd\n      content: hi\n";
const VALID_PKG: &str = "version: 1\nresources:\n  - id: vim\n    type: package\n    with:\n      name: vim\n      state: present\n";
const BAD_TYPE: &str = "version: 1\nresources:\n  - type: bogus\n";
const BAD_SYNTAX: &str = "version: [\nresources: {{";

struct Mcp {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<std::process::ChildStdout>,
}

impl Mcp {
    fn start() -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_sinter"))
            .arg("mcp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sinter mcp");
        let stdin = Some(child.stdin.take().unwrap());
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            stdin,
            stdout,
        }
    }

    /// Send a request and read the single response frame.
    fn call(&mut self, req: &Value) -> Value {
        let stdin = self.stdin.as_mut().unwrap();
        writeln!(stdin, "{}", serde_json::to_string(req).unwrap()).unwrap();
        stdin.flush().unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        serde_json::from_str(&line).expect("response must be JSON")
    }

    fn tool(&mut self, id: u64, name: &str, arguments: Value) -> Value {
        self.call(&json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": { "name": name, "arguments": arguments },
        }))
    }

    /// Decode the tool payload: (isError, parsed inner JSON).
    fn payload(resp: &Value) -> (bool, Value) {
        let r = &resp["result"];
        let is_err = r["isError"].as_bool().unwrap_or(false);
        let text = r["content"][0]["text"].as_str().unwrap();
        (is_err, serde_json::from_str(text).unwrap())
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn init(m: &mut Mcp) {
    let r = m.call(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": { "protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name":"t","version":"0"} },
    }));
    assert_eq!(r["result"]["protocolVersion"], "2025-03-26");
    assert_eq!(r["result"]["serverInfo"]["name"], "sinter-mcp");
    // notification: must produce no response — verify via a following ping.
    writeln!(
        m.stdin.as_mut().unwrap(),
        "{}",
        serde_json::to_string(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))
            .unwrap()
    )
    .unwrap();
    let p = m.call(&json!({"jsonrpc":"2.0","id":2,"method":"ping"}));
    assert_eq!(p["id"], 2);
    assert!(p["result"].is_object());
}

// ---------------------------------------------------------------------------
// registry / protocol
// ---------------------------------------------------------------------------

#[test]
fn registry_is_exact_c1_allowlist() {
    let mut names = sinter::mcp::tool_names();
    names.sort();
    assert_eq!(
        names,
        vec![
            "sinter_classify_platform",
            "sinter_get_version",
            "sinter_inspect_manifest",
            "sinter_plan",
            "sinter_validate_manifest",
        ]
    );
    // No mutation-capable verb may ever appear in the registry.
    for n in &names {
        for bad in [
            "apply", "execute", "install", "remove", "write", "upload", "restart", "run",
            "command", "exec", "ssh",
        ] {
            assert!(
                !n.contains(bad),
                "registry contains mutation-capable name: {n}"
            );
        }
    }
}

#[test]
fn initialize_list_tools() {
    let mut m = Mcp::start();
    init(&mut m);
    let r = m.call(&json!({"jsonrpc":"2.0","id":3,"method":"tools/list"}));
    let tools = r["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 5);
    for t in tools {
        assert!(t["name"].is_string());
        assert_eq!(t["inputSchema"]["type"], "object");
    }
}

#[test]
fn unknown_tool_rejected() {
    let mut m = Mcp::start();
    init(&mut m);
    // Mutation-looking names are unknown tools, not hidden capabilities.
    for name in [
        "apply",
        "sinter_apply",
        "execute",
        "install_package",
        "run_command",
    ] {
        let r = m.tool(10, name, json!({}));
        assert_eq!(r["error"]["code"], -32602, "{name}");
    }
    let r = m.tool(10, "sinter_get_version", json!({}));
    assert!(r["result"].is_object());
}

#[test]
fn malformed_and_unknown_requests() {
    let mut m = Mcp::start();
    let stdin = m.stdin.as_mut().unwrap();
    writeln!(stdin, "this is not json").unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    m.stdout.read_line(&mut line).unwrap();
    let r: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(r["error"]["code"], -32700);

    let r = m.call(&json!({"jsonrpc":"2.0","id":7,"method":"resources/list"}));
    assert_eq!(r["error"]["code"], -32601);

    // arguments not an object
    let r = m.call(&json!({
        "jsonrpc":"2.0","id":8,"method":"tools/call",
        "params":{"name":"sinter_get_version","arguments":"oops"},
    }));
    assert_eq!(r["error"]["code"], -32602);
}

// ---------------------------------------------------------------------------
// tools
// ---------------------------------------------------------------------------

#[test]
fn get_version_matches_crate() {
    let mut m = Mcp::start();
    init(&mut m);
    let (is_err, v) = Mcp::payload(&m.tool(1, "sinter_get_version", json!({})));
    assert!(!is_err);
    assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(v["readOnly"], true);
}

#[test]
fn classify_platform_truth() {
    let mut m = Mcp::start();
    init(&mut m);
    let cases = [
        (
            "ID=\"ubuntu\"\nID_LIKE=\"debian\"\nVERSION_ID=\"24.04\"",
            "debian",
            Some("apt"),
        ),
        (
            "ID=\"rocky\"\nID_LIKE=\"rhel fedora\"\nVERSION_ID=\"9.4\"",
            "redhat",
            Some("dnf"),
        ),
        (
            "ID=\"rhel\"\nID_LIKE=\"rhel fedora\"\nVERSION_ID=\"10.2\"",
            "redhat",
            Some("dnf"),
        ),
        (
            "ID=\"almalinux\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.8\"",
            "redhat",
            Some("dnf"),
        ),
        // Oracle Linux classifies RHEL-family: manageable, never "accepted".
        (
            "ID=\"ol\"\nID_LIKE=\"fedora\"\nVERSION_ID=\"9.4\"",
            "redhat",
            Some("dnf"),
        ),
        ("ID=\"alpine\"\nVERSION_ID=\"3.20\"", "alpine", None),
    ];
    for (i, (osr, family, backend)) in cases.iter().enumerate() {
        let (is_err, v) = Mcp::payload(&m.tool(
            10 + i as u64,
            "sinter_classify_platform",
            json!({"os_release": osr}),
        ));
        assert!(!is_err);
        assert_eq!(v["os_family"], *family, "{osr}");
        assert_eq!(
            v["package_backend"],
            backend.map(Value::from).unwrap_or(Value::Null)
        );
        assert_eq!(v["manageable"], backend.is_some());
    }
}

#[test]
fn validate_manifest_parity() {
    let mut m = Mcp::start();
    init(&mut m);

    let (is_err, v) =
        Mcp::payload(&m.tool(1, "sinter_validate_manifest", json!({"manifest": VALID})));
    assert!(!is_err && v["valid"] == true && v["resources"] == 1);

    // Parity: the MCP diagnostic must be the authoritative load_model error
    // (staged path replaced by the logical name "recipe").
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("r.yaml");
    std::fs::write(&p, BAD_TYPE).unwrap();
    let core_err = sinter::model::load_model(&p).unwrap_err();
    let (is_err, v) =
        Mcp::payload(&m.tool(2, "sinter_validate_manifest", json!({"manifest": BAD_TYPE})));
    assert!(!is_err && v["valid"] == false);
    let msg = v["diagnostics"][0]["message"].as_str().unwrap();
    let core_tail = core_err
        .message
        .split_once(": ")
        .map(|x| x.1)
        .unwrap_or(&core_err.message);
    assert!(msg.starts_with("recipe:"), "{msg}");
    assert!(msg.ends_with(core_tail), "mcp: {msg} core: {core_tail}");
    assert_eq!(v["diagnostics"][0]["category"], "invalid_manifest");

    // Malformed syntax also reports through the same path.
    let (is_err, v) = Mcp::payload(&m.tool(
        3,
        "sinter_validate_manifest",
        json!({"manifest": BAD_SYNTAX}),
    ));
    assert!(
        !is_err && v["valid"] == false && v["diagnostics"][0]["category"] == "invalid_manifest"
    );
}

#[test]
fn inspect_manifest_structure() {
    let mut m = Mcp::start();
    init(&mut m);
    let manifest = "version: 1\nvars:\n  token:\n    value: sekrit\n    sensitive: true\nresources:\n  - id: a\n    type: file\n    with:\n      path: /etc/a\n      content: x\n  - id: b\n    type: service\n    depends_on: [a]\n    with:\n      name: sshd\n      state: running\n";
    let (is_err, v) =
        Mcp::payload(&m.tool(1, "sinter_inspect_manifest", json!({"manifest": manifest})));
    assert!(!is_err);
    assert_eq!(v["counts"]["resources"], 2);
    assert_eq!(v["resources"][0]["id"], "a");
    assert_eq!(v["resources"][1]["depends_on"], json!(["a"]));
    assert_eq!(v["vars"][0]["name"], "token");
    assert_eq!(v["vars"][0]["sensitive"], true);
    // Values must never be exposed.
    let raw = serde_json::to_string(&v).unwrap();
    assert!(!raw.contains("sekrit"), "sensitive value leaked: {raw}");
}

#[test]
fn plan_is_pure_and_deterministic() {
    let mut m = Mcp::start();
    init(&mut m);
    let args = json!({"manifest": VALID_PKG, "target": "rocky9"});
    let (e1, v1) = Mcp::payload(&m.tool(1, "sinter_plan", args.clone()));
    let (e2, v2) = Mcp::payload(&m.tool(2, "sinter_plan", args));
    assert!(!e1 && !e2);
    assert_eq!(v1["status"], "success");
    assert_eq!(v1["mode"], "plan");
    assert_eq!(v1["facts"]["os_family"], "redhat");
    assert_eq!(v1["resources"][0]["type"], "package");
    assert_eq!(v1, v2, "plan must be deterministic");

    // Unknown target → clean invalid_request.
    let (is_err, v) = Mcp::payload(&m.tool(
        3,
        "sinter_plan",
        json!({"manifest": VALID_PKG, "target": "plan9"}),
    ));
    assert!(is_err && v["error"]["category"] == "invalid_request");

    // All supplied-facts targets work (package resources are modeled on
    // both backend families; filesystem helpers are intentionally not
    // modeled by the fake and fail honestly).
    for t in ["ubuntu2404", "ubuntu2604", "rocky9", "rocky10"] {
        let (is_err, v) = Mcp::payload(&m.tool(
            4,
            "sinter_plan",
            json!({"manifest": VALID_PKG, "target": t}),
        ));
        assert!(!is_err, "{t}");
        assert_eq!(v["target"], t);
    }
}

// ---------------------------------------------------------------------------
// adversarial
// ---------------------------------------------------------------------------

#[test]
fn adversarial_inputs() {
    let mut m = Mcp::start();
    init(&mut m);

    // Oversized manifest → invalid_request, no staging.
    let big = "version: 1\n# ".to_string() + &"x".repeat(5 * 1024 * 1024);
    let (is_err, v) =
        Mcp::payload(&m.tool(1, "sinter_validate_manifest", json!({"manifest": big})));
    assert!(is_err && v["error"]["category"] == "invalid_request");

    // Missing / wrong-typed required params.
    let (is_err, _) = Mcp::payload(&m.tool(2, "sinter_validate_manifest", json!({})));
    assert!(is_err);
    let (is_err, _) = Mcp::payload(&m.tool(3, "sinter_validate_manifest", json!({"manifest": 42})));
    assert!(is_err);
    let (is_err, _) = Mcp::payload(&m.tool(4, "sinter_classify_platform", json!({})));
    assert!(is_err);

    // Shell-looking manifest text is inert data — it parses or fails
    // validation, but nothing executes.
    let (is_err, v) = Mcp::payload(&m.tool(
        5,
        "sinter_validate_manifest",
        json!({"manifest": "version: 1\nresources:\n  - id: c\n    type: command\n    with:\n      program: /bin/echo\n      args: ['; rm -rf /']\n"}),
    ));
    let _ = v;
    let _ = is_err; // either outcome is fine; the point is no execution

    // Diagnostics must never leak local filesystem paths.
    let (_e, v) =
        Mcp::payload(&m.tool(6, "sinter_validate_manifest", json!({"manifest": BAD_TYPE})));
    let raw = serde_json::to_string(&v).unwrap();
    for bad in ["/var/folders", "/tmp", "/private", "sinter-mcp-"] {
        assert!(!raw.contains(bad), "path leaked in diagnostic: {raw}");
    }

    // Server still healthy after all of the above.
    let (is_err, _) = Mcp::payload(&m.tool(7, "sinter_get_version", json!({})));
    assert!(!is_err);
}

#[test]
fn sequential_requests_and_clean_shutdown() {
    let mut m = Mcp::start();
    init(&mut m);
    for i in 10..20 {
        let r = m.call(&json!({"jsonrpc":"2.0","id":i,"method":"ping"}));
        assert_eq!(r["id"], i);
    }
    drop(m.stdin.take()); // close stdin → server sees EOF and exits
    let status = m.child.wait().unwrap();
    assert!(status.success(), "server must exit cleanly on EOF");
}
