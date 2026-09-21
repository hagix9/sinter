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
        Self::start_with(&[])
    }

    fn start_with(extra: &[String]) -> Self {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_sinter"));
        cmd.arg("mcp");
        for a in extra {
            cmd.arg(a);
        }
        let mut child = cmd
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
fn registry_is_exact_allowlist() {
    let mut names = sinter::mcp::tool_names();
    names.sort();
    assert_eq!(
        names,
        vec![
            "sinter_audit_host",
            "sinter_classify_platform",
            "sinter_get_version",
            "sinter_inspect_manifest",
            "sinter_list_targets",
            "sinter_plan",
            "sinter_plan_host",
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
    assert_eq!(tools.len(), 8);
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

// ---------------------------------------------------------------------------
// F-02: staging-path redaction over the protocol
// ---------------------------------------------------------------------------

fn assert_no_stage_leak(v: &Value) {
    let raw = serde_json::to_string(v).unwrap();
    let tmp = std::env::temp_dir();
    let tmp_canon = std::fs::canonicalize(&tmp).unwrap_or_else(|_| tmp.clone());
    for bad in [
        tmp.display().to_string(),
        tmp_canon.display().to_string(),
        "sinter-mcp-".to_string(),
    ] {
        assert!(!raw.contains(&bad), "stage path leaked ({bad}): {raw}");
    }
}

#[test]
fn no_stage_path_in_any_diagnostic() {
    let mut m = Mcp::start();
    init(&mut m);
    let cases = [
        // missing relative include
        "version: 1\ninclude: [missing.yaml]\n",
        // nested relative include
        "version: 1\ninclude: [sub/dir/missing.yaml]\n",
        // unicode relative include
        "version: 1\ninclude: [\"ünïcødé.yaml\"]\n",
        // missing relative template source
        "version: 1\nresources:\n  - id: t\n    type: template\n    with:\n      path: /etc/x\n      source: missing.tpl\n",
        // schema error
        BAD_TYPE,
        // syntax error
        BAD_SYNTAX,
    ];
    for (i, manifest) in cases.iter().enumerate() {
        for tool in ["sinter_validate_manifest", "sinter_inspect_manifest"] {
            let (_e, v) =
                Mcp::payload(&m.tool(100 + i as u64, tool, json!({"manifest": manifest})));
            assert_no_stage_leak(&v);
        }
        let (_e, v) = Mcp::payload(&m.tool(
            200 + i as u64,
            "sinter_plan",
            json!({"manifest": manifest, "target": "rocky9"}),
        ));
        assert_no_stage_leak(&v);
    }
}

#[test]
fn include_is_policy_rejected_without_path_echo() {
    let mut m = Mcp::start();
    init(&mut m);
    let (is_err, v) = Mcp::payload(&m.tool(
        1,
        "sinter_validate_manifest",
        json!({"manifest": "version: 1\ninclude: [missing.yaml]\n"}),
    ));
    // R3: include is a policy rejection — the fixed message must not echo
    // the caller's forbidden path, whether relative or absolute.
    assert!(is_err);
    let msg = v["error"]["message"].as_str().unwrap();
    assert!(msg.contains("controller-local"), "{msg}");
    assert!(
        !msg.contains("missing.yaml"),
        "forbidden path echoed: {msg}"
    );

    // A staged schema error still surfaces with the logical `recipe:` origin.
    let (_e, v) = Mcp::payload(&m.tool(
        2,
        "sinter_validate_manifest",
        json!({"manifest": "version: 1\nresources: {}\n"}),
    ));
    let raw = serde_json::to_string(&v).unwrap();
    assert!(raw.contains("recipe:"), "logical prefix missing: {raw}");
}

// ---------------------------------------------------------------------------
// F-03: JSON-RPC batch receive support (MCP 2025-03-26)
// ---------------------------------------------------------------------------

/// Send one raw line and read one raw response line.
fn raw_roundtrip(m: &mut Mcp, line: &str) -> Value {
    let stdin = m.stdin.as_mut().unwrap();
    writeln!(stdin, "{line}").unwrap();
    stdin.flush().unwrap();
    let mut buf = String::new();
    m.stdout.read_line(&mut buf).unwrap();
    serde_json::from_str(&buf).expect("batch response must be JSON")
}

#[test]
fn batch_requests() {
    let mut m = Mcp::start();
    init(&mut m);

    // Multiple requests: array of responses, IDs preserved.
    let r = raw_roundtrip(
        &mut m,
        r#"[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"sinter_get_version","arguments":{}}},{"jsonrpc":"2.0","id":"abc","method":"ping"}]"#,
    );
    let arr = r.as_array().expect("batch must return an array");
    assert_eq!(arr.len(), 3);
    assert_eq!(arr[0]["id"], 1);
    assert_eq!(arr[1]["id"], 2);
    assert!(arr[1]["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("0.4.1"));
    assert_eq!(arr[2]["id"], "abc");

    // Mixed request + notification: only the request gets a response.
    let r = raw_roundtrip(
        &mut m,
        r#"[{"jsonrpc":"2.0","method":"notifications/initialized"},{"jsonrpc":"2.0","id":9,"method":"ping"}]"#,
    );
    let arr = r.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["id"], 9);

    // Invalid member inside a batch → per-element error, others still served.
    let r = raw_roundtrip(&mut m, r#"[42,{"jsonrpc":"2.0","id":3,"method":"ping"}]"#);
    let arr = r.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["error"]["code"], -32600);
    assert_eq!(arr[1]["id"], 3);
    assert!(arr[1]["result"].is_object());

    // Empty batch → single -32600 error object (not an array).
    let r = raw_roundtrip(&mut m, "[]");
    assert_eq!(r["error"]["code"], -32600);
    assert!(r.as_array().is_none());

    // Notification-only batch → no frame at all; the next request still works.
    raw_roundtrip_no_reply(&mut m);
}

fn raw_roundtrip_no_reply(m: &mut Mcp) {
    const BATCH: &str = r#"[{"jsonrpc":"2.0","method":"notifications/initialized"},{"jsonrpc":"2.0","method":"notifications/cancelled","params":{}}]"#;
    let stdin = m.stdin.as_mut().unwrap();
    writeln!(stdin, "{BATCH}").unwrap();
    stdin.flush().unwrap();
    // If the server emitted anything it would be a line; instead we expect the
    // *next* request's response to be the first bytes back.
    let r = m.call(&json!({"jsonrpc":"2.0","id":77,"method":"ping"}));
    assert_eq!(
        r["id"], 77,
        "notification-only batch must yield no response"
    );
}

// ---------------------------------------------------------------------------
// canary confidentiality
// ---------------------------------------------------------------------------

#[test]
fn canary_secrets_never_disclosed() {
    let mut m = Mcp::start();
    init(&mut m);
    let manifest = "version: 1\nvars:\n  tok:\n    value: CANARY_VAR_ABC123\n    sensitive: true\n  plain:\n    value: CANARY_PLAIN_DEF456\nresources:\n  - id: f\n    type: file\n    with:\n      path: /etc/f\n      content: CANARY_CONTENT_GHI789\n  - id: c\n    type: command\n    with:\n      program: /bin/echo\n      args: [CANARY_ARG_JKL012]\n";
    for tool in ["sinter_inspect_manifest", "sinter_validate_manifest"] {
        let (_e, v) = Mcp::payload(&m.tool(1, tool, json!({"manifest": manifest})));
        let raw = serde_json::to_string(&v).unwrap();
        // inspect/validate must not echo manifest values at all.
        assert!(!raw.contains("CANARY_VAR_ABC123"), "{tool}: {raw}");
        assert!(!raw.contains("CANARY_PLAIN_DEF456"), "{tool}: {raw}");
        assert!(!raw.contains("CANARY_CONTENT_GHI789"), "{tool}: {raw}");
        assert!(!raw.contains("CANARY_ARG_JKL012"), "{tool}: {raw}");
    }
}

// ---------------------------------------------------------------------------
// C2: named-target read-only observation
// ---------------------------------------------------------------------------

fn write_targets(body: &str) -> tempfile::NamedTempFile {
    let f = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(f.path(), body).unwrap();
    f
}

/// Sentinel profile internals — must never reach MCP-facing output.
const SENT_HOST: &str = "sentinel-host.invalid";
const SENT_USER: &str = "sentineluser_xyz";
const SENT_KH: &str = "/sentinel/known_hosts_xyz";
const SENT_ID: &str = "/sentinel/id_xyz";

const TARGETS_OK: &str = "[targets.web01]\n\
    host = \"sentinel-host.invalid\"\n\
    user = \"sentineluser_xyz\"\n\
    known_hosts = \"/sentinel/known_hosts_xyz\"\n\
    identity_files = [\"/sentinel/id_xyz\"]\n\
    [targets.db01]\n\
    host = \"10.9.9.9\"\n\
    user = \"ops\"\n\
    known_hosts = \"/sentinel/known_hosts_xyz\"\n\
    sudo = true\n";

#[test]
fn no_targets_file_eight_tools_and_closed_host_tools() {
    let mut m = Mcp::start();
    init(&mut m);
    let r = m.call(&json!({"jsonrpc":"2.0","id":3,"method":"tools/list"}));
    assert_eq!(r["result"]["tools"].as_array().unwrap().len(), 8);

    let (_e, v) = Mcp::payload(&m.tool(4, "sinter_list_targets", json!({})));
    assert_eq!(v["targets"], json!([]));

    for tool in ["sinter_plan_host", "sinter_audit_host"] {
        let (is_err, v) =
            Mcp::payload(&m.tool(5, tool, json!({"manifest": VALID, "target": "web01"})));
        assert!(is_err, "{tool} must fail closed without a registry");
        assert!(
            v["error"]["message"]
                .as_str()
                .unwrap()
                .contains("unknown target"),
            "{tool}: {v}"
        );
    }
}

#[test]
fn list_targets_returns_sorted_names_only() {
    let f = write_targets(TARGETS_OK);
    let mut m = Mcp::start_with(&["--targets-file".to_string(), f.path().display().to_string()]);
    init(&mut m);
    let resp = m.tool(1, "sinter_list_targets", json!({}));
    let (is_err, v) = Mcp::payload(&resp);
    assert!(!is_err);
    assert_eq!(v["targets"], json!(["db01", "web01"]));
    let raw = serde_json::to_string(&resp).unwrap();
    for leak in [
        SENT_HOST, SENT_USER, SENT_KH, SENT_ID, "10.9.9.9", "ops", "sudo",
    ] {
        assert!(
            !raw.contains(leak),
            "profile detail leaked: {leak} in {raw}"
        );
    }
}

#[test]
fn startup_fails_closed_on_bad_targets_file() {
    // missing file
    let status = Command::new(env!("CARGO_BIN_EXE_sinter"))
        .args(["mcp", "--targets-file", "/nonexistent/targets.toml"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!status.success(), "missing targets file must fail startup");
    // malformed TOML
    let f = write_targets("[targets.x\nhost=");
    let status = Command::new(env!("CARGO_BIN_EXE_sinter"))
        .args(["mcp", "--targets-file"])
        .arg(f.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!status.success(), "malformed TOML must fail startup");
    // structurally invalid profile (missing user)
    let f = write_targets("[targets.a]\nhost=\"h\"\nknown_hosts=\"/k\"\n");
    let status = Command::new(env!("CARGO_BIN_EXE_sinter"))
        .args(["mcp", "--targets-file"])
        .arg(f.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!status.success(), "invalid profile must fail startup");
}

#[test]
fn unknown_target_fails_closed_and_sanitized() {
    let f = write_targets(TARGETS_OK);
    let mut m = Mcp::start_with(&["--targets-file".to_string(), f.path().display().to_string()]);
    init(&mut m);
    for tool in ["sinter_plan_host", "sinter_audit_host"] {
        let resp = m.tool(1, tool, json!({"manifest": VALID, "target": "web99"}));
        let (is_err, v) = Mcp::payload(&resp);
        assert!(is_err, "{tool}");
        assert!(v["error"]["message"]
            .as_str()
            .unwrap()
            .contains("unknown target"));
        let raw = serde_json::to_string(&v).unwrap();
        for leak in [SENT_HOST, SENT_USER, SENT_KH, SENT_ID] {
            assert!(!raw.contains(leak), "{tool} leaked {leak}");
        }
    }
    // Malformed name: rejected without echo.
    let (is_err, v) = Mcp::payload(&m.tool(
        2,
        "sinter_plan_host",
        json!({"manifest": VALID, "target": "../escape\nname"}),
    ));
    assert!(is_err);
    assert!(v["error"]["message"]
        .as_str()
        .unwrap()
        .contains("invalid target name"));
}

#[test]
fn host_tools_reject_connection_parameters() {
    let f = write_targets(TARGETS_OK);
    let mut m = Mcp::start_with(&["--targets-file".to_string(), f.path().display().to_string()]);
    init(&mut m);
    for tool in ["sinter_plan_host", "sinter_audit_host"] {
        for key in [
            "host",
            "port",
            "user",
            "sudo",
            "identity_files",
            "known_hosts",
            "command",
        ] {
            let (is_err, v) = Mcp::payload(&m.tool(
                1,
                tool,
                json!({"manifest": VALID, "target": "web01", key: "x"}),
            ));
            assert!(is_err, "{tool} accepted connection parameter {key}");
            assert!(
                v["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("unexpected parameter"),
                "{tool} {key}: {v}"
            );
        }
    }
}

#[test]
fn host_tool_schemas_expose_only_manifest_and_target() {
    let mut m = Mcp::start();
    init(&mut m);
    let r = m.call(&json!({"jsonrpc":"2.0","id":3,"method":"tools/list"}));
    let tools = r["result"]["tools"].as_array().unwrap();
    for name in ["sinter_plan_host", "sinter_audit_host"] {
        let t = tools.iter().find(|t| t["name"] == name).unwrap();
        let props = t["inputSchema"]["properties"].as_object().unwrap();
        let mut keys: Vec<&str> = props.keys().map(|k| k.as_str()).collect();
        keys.sort();
        assert_eq!(keys, ["manifest", "target"], "{name} schema");
    }
}

#[test]
fn unreachable_host_error_is_sanitized() {
    // 127.0.0.1:1 refuses immediately — exercises the real SSH connect path
    // and its MCP-boundary sanitization without touching a real host.
    let body = "[targets.local]\n\
        host = \"127.0.0.1\"\n\
        port = 1\n\
        user = \"sentineluser_xyz\"\n\
        known_hosts = \"/sentinel/known_hosts_xyz\"\n\
        identity_files = [\"/sentinel/id_xyz\"]\n";
    let f = write_targets(body);
    let mut m = Mcp::start_with(&["--targets-file".to_string(), f.path().display().to_string()]);
    init(&mut m);
    let resp = m.tool(
        1,
        "sinter_plan_host",
        json!({"manifest": VALID, "target": "local"}),
    );
    let (is_err, v) = Mcp::payload(&resp);
    assert!(is_err, "unreachable target must produce a tool error: {v}");
    let raw = serde_json::to_string(&v).unwrap();
    for leak in [SENT_USER, SENT_KH, SENT_ID] {
        assert!(!raw.contains(leak), "connect error leaked {leak}: {raw}");
    }
}

#[test]
fn immutable_registry_across_requests() {
    let f = write_targets(TARGETS_OK);
    let mut m = Mcp::start_with(&["--targets-file".to_string(), f.path().display().to_string()]);
    init(&mut m);
    // No request can add or alter profiles — enumerate twice.
    let (_e, a) = Mcp::payload(&m.tool(1, "sinter_list_targets", json!({})));
    let (_e, b) = Mcp::payload(&m.tool(2, "sinter_list_targets", json!({"target": "evil"})));
    let (_e, c) = Mcp::payload(&m.tool(3, "sinter_list_targets", json!({})));
    assert_eq!(a["targets"], json!(["db01", "web01"]));
    assert_eq!(c["targets"], a["targets"]);
    let _ = b;
}

// ---------------------------------------------------------------------------
// C2 R2: structural manifest-authority boundary (R1-N1 / R1-N2)
// ---------------------------------------------------------------------------

const R2_SOURCE_SENTINEL: &str = "R2_SOURCE_SECRET_83F1";
const R2_INCLUDE_SENTINEL: &str = "R2_INCLUDE_SECRET_6A22";
/// Substring common to both policy rejection messages.
const R2_POLICY: &str = "controller-local";

fn manifest_with(ty: &str, with_lines: &str) -> String {
    format!(
        "version: 1\nresources:\n  - id: x\n    type: {ty}\n    with:\n      path: /tmp/dst\n{with_lines}\n"
    )
}

fn assert_policy_rejection(resp: &Value, forbidden: &[&str]) {
    let (is_err, v) = Mcp::payload(resp);
    assert!(is_err, "manifest must be rejected: {resp}");
    assert_eq!(v["error"]["category"], "invalid_manifest", "{resp}");
    let raw = serde_json::to_string(resp).unwrap();
    assert!(
        raw.contains(R2_POLICY),
        "expected the authority-policy rejection: {raw}"
    );
    for s in forbidden {
        assert!(!raw.contains(s), "sentinel/path leaked: {s} in {raw}");
    }
    // Policy wins over target resolution — proves ordering.
    assert!(!raw.contains("unknown target"), "{raw}");
}

#[test]
fn host_tools_reject_source_in_every_key_spelling() {
    // Sentinel file outside the repository, readable by the MCP process. It
    // must never be opened: `source` is rejected on the parsed structure
    // before resolution, so every YAML spelling the production parser
    // accepts is covered identically.
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("SINTER_MCP_SECRET_R2");
    std::fs::write(&secret, R2_SOURCE_SENTINEL).unwrap();
    let abs = secret.display().to_string();

    let mut m = Mcp::start(); // no registry: policy must fire before resolution
    init(&mut m);
    for tool in ["sinter_plan_host", "sinter_audit_host"] {
        for ty in ["file", "template"] {
            for with in [
                format!("      source: {abs}"),                    // R2-A: plain
                format!("      \"source\": {abs}"),                // R2-B
                format!("      'source': {abs}"),                  // R2-C
                format!("      ? source\n      : {abs}"),          // R2-D: explicit key
                format!("      !!str source: {abs}"),              // tagged key
                "      source: ./relative/secret.txt".to_string(), // relative
            ] {
                let resp = m.tool(
                    7,
                    tool,
                    json!({"manifest": manifest_with(ty, &with), "target": "web01"}),
                );
                assert_policy_rejection(&resp, &[R2_SOURCE_SENTINEL, &abs]);
            }
        }
        // R2-E: flow mappings — file and template.
        for with in [
            format!("    with: {{ path: /tmp/dst, source: {abs} }}"),
            format!("    with: {{ path: /tmp/dst, \"source\": {abs} }}"),
        ] {
            let mf = format!("version: 1\nresources:\n  - id: x\n    type: file\n{with}\n");
            let resp = m.tool(7, tool, json!({"manifest": mf, "target": "web01"}));
            assert_policy_rejection(&resp, &[R2_SOURCE_SENTINEL, &abs]);
        }
    }
}

#[test]
fn host_tools_reject_all_include_forms() {
    let dir = tempfile::tempdir().unwrap();
    let inc = dir.path().join("child.yaml");
    std::fs::write(&inc, format!("version: 1\n# {R2_INCLUDE_SENTINEL}\n")).unwrap();
    let abs = inc.display().to_string();

    let mut m = Mcp::start();
    init(&mut m);
    let forms = [
        format!("version: 1\ninclude:\n  - {abs}\n"),            // R2-J absolute
        "version: 1\ninclude:\n  - ../secret.yaml\n".to_string(), // R2-K relative
        "version: 1\ninclude:\n  - child.yaml\n".to_string(),     // R2-L child
        format!("version: 1\ninclude: [\"{abs}\"]\n"),            // flow + quoted
        format!("version: 1\ninclude:\n  - {abs}\n  - child.yaml\n"), // multiple
        // include + source combination: main rejected before any expansion.
        format!(
            "version: 1\ninclude:\n  - {abs}\nresources:\n  - id: x\n    type: file\n    with:\n      path: /t\n      source: {abs}\n"
        ),
    ];
    for tool in ["sinter_plan_host", "sinter_audit_host"] {
        for mf in &forms {
            let resp = m.tool(7, tool, json!({"manifest": mf, "target": "web01"}));
            assert_policy_rejection(&resp, &[R2_INCLUDE_SENTINEL, R2_SOURCE_SENTINEL, &abs]);
        }
    }
}

#[test]
fn forbidden_authority_rejected_identically_regardless_of_filesystem() {
    // Structural rejection must not depend on the referenced path's state —
    // identical policy errors for existing, missing, directory and
    // unreadable targets prove no controller I/O happened to decide.
    let dir = tempfile::tempdir().unwrap();
    let existing = dir.path().join("exists.yaml");
    std::fs::write(&existing, R2_SOURCE_SENTINEL).unwrap();
    let missing = dir.path().join("missing.yaml").display().to_string();
    let directory = dir.path().display().to_string();
    let unreadable = dir.path().join("unreadable.yaml");
    std::fs::write(&unreadable, R2_SOURCE_SENTINEL).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();
    }
    let un = unreadable.display().to_string();
    let ex = existing.display().to_string();

    let mut m = Mcp::start();
    init(&mut m);
    let mut messages = Vec::new();
    for tool in ["sinter_plan_host", "sinter_audit_host"] {
        for path in [
            ex.as_str(),
            missing.as_str(),
            directory.as_str(),
            un.as_str(),
        ] {
            for mf in [
                manifest_with("file", &format!("      source: {path}")),
                format!("version: 1\ninclude:\n  - {path}\n"),
            ] {
                let resp = m.tool(7, tool, json!({"manifest": mf, "target": "web01"}));
                assert_policy_rejection(&resp, &[R2_SOURCE_SENTINEL, &ex, &un]);
                let (_, v) = Mcp::payload(&resp);
                messages.push(v["error"]["message"].as_str().unwrap().to_string());
            }
        }
    }
    // Every variant produced one of the two fixed policy messages — no
    // filesystem-derived text (errno, "Is a directory", "not found").
    for msg in &messages {
        assert!(
            msg.contains(R2_POLICY),
            "filesystem-dependent error leaked: {msg}"
        );
        assert!(!msg.contains(&ex) && !msg.contains(&un), "{msg}");
    }
}

#[test]
fn source_include_words_in_data_are_not_policy_rejected() {
    // Structural policy ≠ text matching: the words `source`/`include` in
    // scalar content, block scalars, comments and args carry no authority.
    // With no registry these must pass the policy and reach `unknown target`.
    let mut m = Mcp::start();
    init(&mut m);
    let manifests = [
        manifest_with("file", "      content: \"source: /tmp/x\""),
        manifest_with("file", "      content: \"include: child.yaml\""),
        manifest_with(
            "file",
            "      content: |\n        source: /tmp/x\n        include: child.yaml",
        ),
        "version: 1\n# source: /tmp/x\n# include: child.yaml\nresources:\n  - id: x\n    type: file\n    with:\n      path: /t\n      content: ok\n".to_string(),
        "version: 1\nresources:\n  - id: x\n    type: command\n    with:\n      program: /bin/echo\n      args: [\"source:\", \"include:\"]\n".to_string(),
        "version: 1\nvars:\n  v:\n    value: \"source: include:\"\nresources:\n  - id: x\n    type: file\n    with:\n      path: /t\n      content: \"{{ vars.v }}\"\n".to_string(),
    ];
    for tool in ["sinter_plan_host", "sinter_audit_host"] {
        for mf in &manifests {
            let resp = m.tool(7, tool, json!({"manifest": mf, "target": "web01"}));
            let (is_err, v) = Mcp::payload(&resp);
            assert!(is_err, "{tool}: {resp}");
            let msg = v["error"]["message"].as_str().unwrap();
            assert!(
                msg.contains("unknown target"),
                "{tool}: must pass the authority policy and fail at target \
                 resolution, got: {msg} for {mf:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// C2 R1: F-03 protocol-level overlapping profile redaction
// ---------------------------------------------------------------------------

#[test]
fn overlapping_profile_values_fully_redacted_in_errors() {
    // host is a strict prefix of user; known_hosts is a prefix of the
    // identity path. An unreachable host forces an MCP-facing error.
    let f = write_targets(
        "[targets.web01]\n\
         host = \"127.0.0.1\"\n\
         port = 1\n\
         user = \"127.0.0.1-admin\"\n\
         known_hosts = \"/tmp/secret\"\n\
         identity_files = [\"/tmp/secret/key\"]\n",
    );
    let mut m = Mcp::start_with(&["--targets-file".to_string(), f.path().display().to_string()]);
    init(&mut m);
    for tool in ["sinter_plan_host", "sinter_audit_host"] {
        let resp = m.tool(9, tool, json!({"manifest": VALID_PKG, "target": "web01"}));
        let (is_err, _) = Mcp::payload(&resp);
        assert!(is_err, "{tool} must fail against 127.0.0.1:1: {resp}");
        let raw = serde_json::to_string(&resp).unwrap();
        // No complete configured value survives — including the suffix
        // residue the old sequential replacement could leave.
        for leak in ["127.0.0.1-admin", "/tmp/secret/key", "/tmp/secret"] {
            assert!(!raw.contains(leak), "{tool} leaked {leak}: {raw}");
        }
        assert!(
            !raw.contains("127.0.0.1") || raw.contains("[target]"),
            "{tool}: {raw}"
        );
    }
}

// ---------------------------------------------------------------------------
// C2 R3: the structural authority boundary covers ALL manifest-consuming
// tools — validate_manifest, inspect_manifest and plan close the same
// controller-read channel the C2 host tools already enforce.
// ---------------------------------------------------------------------------

const R3_SENTINEL: &str = "C1_AUTHORITY_SECRET_71A2";

/// sinter_plan needs a canned fake platform name as `target`.
fn c1_args(tool: &str, manifest: &str) -> Value {
    if tool == "sinter_plan" {
        json!({"manifest": manifest, "target": "ubuntu2404"})
    } else {
        json!({"manifest": manifest})
    }
}

#[test]
fn c1_manifest_tools_reject_source_and_include() {
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("SINTER_C1_SECRET_R3");
    std::fs::write(&secret, R3_SENTINEL).unwrap();
    let abs = secret.display().to_string();

    let mut m = Mcp::start();
    init(&mut m);
    let tools = [
        "sinter_validate_manifest",
        "sinter_inspect_manifest",
        "sinter_plan",
    ];
    let manifests = [
        // source: plain, quoted, explicit, tagged, flow — file + template
        manifest_with("file", &format!("      source: {abs}")),
        manifest_with("file", &format!("      \"source\": {abs}")),
        manifest_with("file", &format!("      'source': {abs}")),
        manifest_with("file", &format!("      ? source\n      : {abs}")),
        manifest_with("file", &format!("      !!str source: {abs}")),
        format!(
            "version: 1\nresources:\n  - id: x\n    type: file\n    with: {{ path: /t, source: {abs} }}\n"
        ),
        manifest_with("template", &format!("      source: {abs}")),
        manifest_with("file", "      source: ./rel/x"),
        // include: absolute, relative, child, flow, multiple
        format!("version: 1\ninclude:\n  - {abs}\n"),
        "version: 1\ninclude:\n  - ../x.yaml\n".to_string(),
        "version: 1\ninclude:\n  - child.yaml\n".to_string(),
        format!("version: 1\ninclude: [\"{abs}\"]\n"),
        format!("version: 1\ninclude:\n  - {abs}\n  - child.yaml\n"),
    ];
    for tool in tools {
        for mf in &manifests {
            let resp = m.tool(5, tool, c1_args(tool, mf));
            assert_policy_rejection(&resp, &[R3_SENTINEL, &abs]);
        }
    }
}

#[test]
fn c1_tools_reject_identically_regardless_of_filesystem() {
    // Same fixed policy class whether the referenced path exists, is
    // missing, is a directory, or is unreadable — proof no controller I/O
    // participates in the decision.
    let dir = tempfile::tempdir().unwrap();
    let existing = dir.path().join("exists.txt");
    std::fs::write(&existing, R3_SENTINEL).unwrap();
    let missing = dir.path().join("missing.txt").display().to_string();
    let directory = dir.path().display().to_string();
    let unreadable = dir.path().join("unreadable.txt");
    std::fs::write(&unreadable, R3_SENTINEL).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();
    }
    let un = unreadable.display().to_string();
    let ex = existing.display().to_string();

    let mut m = Mcp::start();
    init(&mut m);
    for tool in [
        "sinter_validate_manifest",
        "sinter_inspect_manifest",
        "sinter_plan",
    ] {
        for path in [
            ex.as_str(),
            missing.as_str(),
            directory.as_str(),
            un.as_str(),
        ] {
            for mf in [
                manifest_with("file", &format!("      source: {path}")),
                format!("version: 1\ninclude:\n  - {path}\n"),
            ] {
                let resp = m.tool(5, tool, c1_args(tool, &mf));
                assert_policy_rejection(&resp, &[R3_SENTINEL, &ex, &un]);
            }
        }
    }
}

#[test]
fn c1_inline_manifests_still_work() {
    // Ordinary inline manifests are unaffected: the words `source`/`include`
    // inside scalar data carry no authority and must not be rejected.
    let mut m = Mcp::start();
    init(&mut m);
    let manifests = [
        VALID.to_string(),
        manifest_with("file", "      content: \"source: /tmp/x\""),
        manifest_with("file", "      content: \"include: child.yaml\""),
        manifest_with(
            "file",
            "      content: |\n        source: /tmp/x\n        include: child.yaml",
        ),
        "version: 1\n# source: /tmp/x\n# include: child.yaml\nresources:\n  - id: x\n    type: file\n    with:\n      path: /t\n      content: ok\n".to_string(),
        VALID_PKG.to_string(),
    ];
    for mf in &manifests {
        let (is_err, v) =
            Mcp::payload(&m.tool(1, "sinter_validate_manifest", json!({"manifest": mf})));
        assert!(!is_err, "validate: {v}");
        assert_eq!(
            v["valid"], true,
            "validate rejected inline manifest: {mf:?}"
        );

        let (is_err, v) =
            Mcp::payload(&m.tool(2, "sinter_inspect_manifest", json!({"manifest": mf})));
        assert!(!is_err, "inspect: {v}");
        assert!(v["resources"].is_array(), "inspect: {v}");

        // plan exercises the same boundary; FakeTarget may report resource
        // errors but must never emit the authority-policy message.
        let resp = m.tool(3, "sinter_plan", c1_args("sinter_plan", mf));
        let raw = serde_json::to_string(&resp).unwrap();
        assert!(
            !raw.contains(R2_POLICY),
            "plan policy-rejected inline manifest: {raw}"
        );
    }
}
