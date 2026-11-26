//! The read-only boundary of the Core MCP host tools (v1.15.0 P6, M-4):
//! checked on the commands the engine actually sent, not on result text.
//!
//! The host tools take a scripted target here (`host_fake_target`; a build
//! always connects over SSH) and report the engine's mode, whether it could
//! produce a mutation permit, and every command it recorded (the SSH session
//! setup's own `getent passwd` and `id` lookups are not command records;
//! they are read-only). Every command
//! must be one of the observation forms below; anything else — a known
//! mutation or a command nobody listed — fails the test (no unknown command
//! is treated as safe).

use super::*;
use crate::executor::CommandRecord;
use std::cell::RefCell;

thread_local! {
    static FAKE: RefCell<Option<FakeTarget>> = const { RefCell::new(None) };
    static ENGINES: RefCell<Vec<(Mode, bool)>> = const { RefCell::new(Vec::new()) };
    static COMMANDS: RefCell<Vec<CommandRecord>> = const { RefCell::new(Vec::new()) };
}

pub(super) fn take_fake() -> Option<FakeTarget> {
    FAKE.with(|f| f.borrow_mut().take())
}

pub(super) fn record_engine(engine: &Engine) {
    let permit = engine.fs.mutation_permit().is_ok();
    ENGINES.with(|e| e.borrow_mut().push((engine.opts.mode, permit)));
}

pub(super) fn record_commands(commands: &[CommandRecord]) {
    COMMANDS.with(|c| c.borrow_mut().extend(commands.iter().cloned()));
}

fn reset(fake: Option<FakeTarget>) {
    FAKE.with(|f| *f.borrow_mut() = fake);
    ENGINES.with(|e| e.borrow_mut().clear());
    COMMANDS.with(|c| c.borrow_mut().clear());
}

fn fake_left() -> bool {
    FAKE.with(|f| f.borrow().is_some())
}

fn engines() -> Vec<(Mode, bool)> {
    ENGINES.with(|e| e.borrow().clone())
}

fn commands() -> Vec<CommandRecord> {
    COMMANDS.with(|c| c.borrow().clone())
}

/// A known mutation, with what it is.
fn mutation(c: &CommandRecord) -> Option<&'static str> {
    let prog = c.program.rsplit('/').next().unwrap_or(&c.program);
    let has = |w: &str| c.args.iter().any(|a| a == w);
    let any_prefix = |p: &str| c.args.iter().any(|a| a.starts_with(p));
    match prog {
        "systemctl"
            if [
                "start",
                "stop",
                "restart",
                "reload",
                "try-restart",
                "reload-or-restart",
                "enable",
                "disable",
                "reenable",
                "mask",
                "unmask",
                "daemon-reload",
                "reset-failed",
                "set-property",
                "kill",
                "isolate",
                "edit",
                "preset",
            ]
            .iter()
            .any(|v| has(v)) =>
        {
            Some("systemctl change")
        }
        "nmcli"
            if has("connection")
                && [
                    "modify", "up", "down", "delete", "add", "reload", "load", "import",
                ]
                .iter()
                .any(|v| has(v)) =>
        {
            Some("nmcli change")
        }
        "busctl" if c.args.iter().any(|a| a.starts_with("Checkpoint")) => {
            Some("NetworkManager checkpoint")
        }
        "firewall-cmd"
            if any_prefix("--add-")
                || any_prefix("--remove-")
                || any_prefix("--change-")
                || any_prefix("--set-")
                || any_prefix("--new-")
                || any_prefix("--delete-")
                || has("--reload")
                || has("--complete-reload")
                || has("--runtime-to-permanent") =>
        {
            Some("firewalld change")
        }
        "apt-get" | "apt" | "dnf" | "yum" | "dnf5" | "zypper" => Some("package manager"),
        "dpkg" if !has("--dry-run") => Some("dpkg"),
        "rpm" if has("-e") || has("--erase") || has("-i") || has("-U") => Some("rpm change"),
        "rm" | "mv" | "cp" | "ln" | "mkdir" | "rmdir" | "chmod" | "chown" | "chgrp" | "touch"
        | "truncate" | "tee" | "install" | "setfattr" | "setfacl" | "mktemp" | "sed" => {
            Some("file change")
        }
        "dd" if any_prefix("of=") => Some("file change"),
        "useradd" | "usermod" | "userdel" | "groupadd" | "groupmod" | "groupdel" | "chpasswd"
        | "passwd" | "gpasswd" => Some("account change"),
        "sh" | "bash" | "dash" | "env" | "sudo" | "setpriv" | "psql" | "curl" | "wget" => {
            Some("command execution")
        }
        _ => None,
    }
}

/// The observation forms a host tool may send.
fn observation(c: &CommandRecord) -> bool {
    let prog = c.program.rsplit('/').next().unwrap_or(&c.program);
    let first = c.args.first().map(|s| s.as_str()).unwrap_or("");
    match prog {
        "test" | "cat" | "stat" | "uname" | "hostname" | "id" | "readlink" | "sha256sum"
        | "getfattr" | "getfacl" | "dpkg-query" => true,
        "getent" => !c.args.iter().any(|a| a == "shadow" || a == "gshadow"),
        "systemctl" => first == "show",
        "rpm" => first == "-q",
        _ => false,
    }
}

/// Every command is an observation; none is a mutation.
fn assert_observation_only(cs: &[CommandRecord]) {
    assert!(!cs.is_empty(), "no command recorded");
    for c in cs {
        assert!(
            mutation(c).is_none(),
            "mutation sent ({}): {} {:?}",
            mutation(c).unwrap_or(""),
            c.program,
            c.args
        );
        assert!(
            observation(c),
            "unlisted command sent: {} {:?}",
            c.program,
            c.args
        );
    }
}

#[test]
fn the_mutation_detector_knows_the_mutating_commands() {
    let rec = |p: &str, a: &[&str]| CommandRecord {
        program: p.to_string(),
        args: a.iter().map(|s| s.to_string()).collect(),
        env: Default::default(),
        sudo: false,
        sensitive: false,
    };
    for (p, a) in [
        ("/usr/bin/systemctl", vec!["start", "--", "x.service"]),
        ("/usr/bin/systemctl", vec!["enable", "--", "x.service"]),
        ("/usr/bin/systemctl", vec!["daemon-reload"]),
        ("/usr/bin/systemctl", vec!["stop", "--", "x.service"]),
        ("/usr/bin/systemctl", vec!["restart", "--", "x.service"]),
        ("/usr/bin/systemctl", vec!["disable", "--", "x.service"]),
        ("/usr/bin/nmcli", vec!["connection", "down", "uuid", "u"]),
        ("/usr/bin/nmcli", vec!["connection", "delete", "uuid", "u"]),
        (
            "/usr/bin/nmcli",
            vec!["connection", "add", "type", "ethernet"],
        ),
        ("/usr/sbin/groupadd", vec!["appg"]),
        ("/usr/bin/rpm", vec!["-e", "nginx"]),
        ("/usr/bin/nmcli", vec!["connection", "modify", "uuid", "u"]),
        ("/usr/bin/nmcli", vec!["connection", "up", "uuid", "u"]),
        (
            "/usr/bin/firewall-cmd",
            vec!["--zone=public", "--remove-service=ssh"],
        ),
        ("/usr/bin/firewall-cmd", vec!["--reload"]),
        ("/usr/bin/apt-get", vec!["install", "-y", "nginx"]),
        ("/usr/bin/dnf", vec!["-y", "remove", "nginx"]),
        ("/bin/rm", vec!["-f", "/etc/x"]),
        ("/usr/sbin/useradd", vec!["appu"]),
        ("/bin/sh", vec!["-c", "x"]),
        ("/usr/bin/touch", vec!["/etc/marker"]),
    ] {
        let c = rec(p, &a);
        assert!(mutation(&c).is_some(), "{p} {a:?}");
        assert!(!observation(&c), "{p} {a:?}");
    }
    // An unknown program is neither listed as an observation nor safe, and
    // an abbreviated nmcli form is not an observation either.
    assert!(!observation(&rec("/usr/local/bin/anything", &[])));
    assert!(!observation(&rec("/usr/bin/nmcli", &["con", "up", "x"])));
}

fn registry(dir: &Path) -> TargetRegistry {
    let p = dir.join("targets.toml");
    std::fs::write(
        &p,
        "[targets.web01]\nhost = \"192.0.2.10\"\nuser = \"admin\"\nknown_hosts = \"/nonexistent/known_hosts\"\nsudo = true\n",
    )
    .unwrap();
    TargetRegistry::load(&p).unwrap()
}

/// A host with nothing the manifest wants yet: every resource would change.
fn fake() -> FakeTarget {
    let mut t = FakeTarget::ubuntu2404()
        .as_root()
        .with_fake_fs()
        .with_fs_file("/etc/app.conf", "old\n");
    t.services.insert(
        "nginx.service".into(),
        ("loaded".into(), "inactive".into(), "disabled".into()),
    );
    t
}

/// Every resource type MCP accepts, each wanting a change, and a command.
const CHANGING: &str = "version: 1
resources:
  - id: f
    type: file
    with: { path: /etc/app.conf, content: \"new\\n\", mode: \"0600\" }
  - id: d
    type: directory
    with: { path: /etc/appd }
  - id: l
    type: link
    with: { path: /etc/app-link, target: /etc/app.conf }
  - id: p
    type: package
    with: { name: nginx, state: present }
  - id: s
    type: service
    with: { name: nginx.service, state: running, enabled: true }
  - id: g
    type: group
    with: { name: appg }
  - id: u
    type: user
    with: { name: appu, group: appg }
  - id: c
    type: command
    with: { program: /usr/bin/touch, args: [/etc/marker] }
";

fn call(reg: &TargetRegistry, tool: &str, args: Value) -> Value {
    let msg = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": { "name": tool, "arguments": args },
    });
    handle(&msg, reg).expect("a response")
}

fn is_error(r: &Value) -> bool {
    r.get("error").is_some() || r["result"]["isError"] == json!(true)
}

fn body(r: &Value) -> Value {
    serde_json::from_str(r["result"]["content"][0]["text"].as_str().unwrap_or("{}"))
        .unwrap_or(Value::Null)
}

#[test]
fn plan_host_is_plan_mode_without_a_permit_and_sends_no_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let reg = registry(dir.path());
    reset(Some(fake()));
    let r = call(
        &reg,
        "sinter_plan_host",
        json!({"manifest": CHANGING, "target": "web01"}),
    );
    assert!(!is_error(&r), "{r}");
    assert_eq!(
        engines(),
        [(Mode::Plan, false)],
        "Mode::Plan, no mutation permit"
    );
    let b = body(&r);
    assert_eq!(b["mode"], "plan");
    // The plan does see the changes it would make, so the observations ran.
    let changed = b["resources"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| x["change"] != "none")
        .count();
    assert!(changed >= 6, "{b}");
    let cs = commands();
    assert_observation_only(&cs);
    // The observations of every resource type ran (package, service,
    // account and file observations), so the check above saw real work.
    let progs: std::collections::BTreeSet<&str> = cs
        .iter()
        .map(|c| c.program.rsplit('/').next().unwrap_or(""))
        .collect();
    for p in ["dpkg-query", "systemctl", "getent", "stat"] {
        assert!(progs.contains(p), "{p} not observed: {progs:?}");
    }
    eprintln!("plan_host commands: {} ({:?})", cs.len(), progs);
    // The command resource was never executed.
    assert!(!cs.iter().any(|c| c.args.iter().any(|a| a == "/etc/marker")));
}

#[test]
fn audit_host_is_plan_mode_without_a_permit_and_sends_no_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let reg = registry(dir.path());
    reset(Some(fake()));
    let r = call(
        &reg,
        "sinter_audit_host",
        json!({"manifest": CHANGING, "target": "web01"}),
    );
    assert!(!is_error(&r), "{r}");
    assert_eq!(engines(), [(Mode::Plan, false)]);
    let b = body(&r);
    let statuses: Vec<String> = b["resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| format!("{}={}", x["id"], x["status"]))
        .collect();
    assert!(
        statuses
            .iter()
            .any(|s| s.contains("NOT_AUDITABLE") || s.contains("not_auditable")),
        "{statuses:?}"
    );
    let cs = commands();
    assert_observation_only(&cs);
    assert!(!cs.iter().any(|c| c.args.iter().any(|a| a == "/etc/marker")));
}

#[test]
fn an_apply_mode_engine_is_refused_by_the_audit_runner() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("m.yaml");
    std::fs::write(&p, CHANGING).unwrap();
    let model = load_model(&p).unwrap();
    let opts = RunOptions {
        mode: Mode::Apply,
        sudo: false,
        target: TargetSpec { ssh: None },
        verbose: false,
        fault: None,
        fake_target: Some(fake()),
    };
    let e = Engine::new(model, opts).unwrap();
    assert!(
        e.fs.mutation_permit().is_ok(),
        "an apply engine has a permit"
    );
    assert!(
        run_audit(e).is_err(),
        "run_audit refuses a mutation-capable engine"
    );
    // The host tools themselves never build one: their engines above are
    // Mode::Plan, and the source of both tools names only Mode::Plan.
    let src = include_str!("mcp.rs");
    assert!(
        !src.contains("Mode::Apply"),
        "src/mcp.rs must not name Mode::Apply"
    );
}

/// Manifests every host tool refuses before it connects, with a fragment of
/// the refusal each must give (the reason, not just any error).
fn refused_manifests() -> Vec<(&'static str, String)> {
    let r = |ty: &str, with: &str| {
        format!("version: 1\nresources:\n  - id: x\n    type: {ty}\n    with: {{ {with} }}\n")
    };
    vec![
        ("plugins", "version: 1\nplugins:\n  - id: firewalld\n    version: 0.3.0\nresources:\n  - id: x\n    type: firewalld.service\n    with: { zone: public, service: http }\n".to_string()),
        ("include", "version: 1\ninclude:\n  - other.yaml\nresources: []\n".to_string()),
        ("source", r("file", "path: /etc/x, source: /etc/shadow")),
        ("content secret", r("file", "path: /etc/x, content: { secret: s.age }")),
        ("password_hash secret", r("user", "name: appu, password_hash: { secret: s.age }")),
        ("password_verifier secret", r("postgresql_role", "name: app, password_verifier: { secret: s.age }")),
        ("unknown type", r("bogus", "name: x")),
        ("firewalld type without plugin", r("firewalld.service", "zone: public, service: http")),
        ("systemd_timer", r("systemd_timer", "name: backup, on_calendar: daily")),
        ("nm_connection", r("nm_connection", "name: lan, ifname: eth1")),
        ("file_merge", r("file_merge", "path: /etc/x, merge: line, line: x")),
        ("dnf_repository", r("dnf_repository", "name: crb, file: /etc/yum.repos.d/rocky.repo, enabled: true")),
        ("malformed", "version: 1\nresources: [\n".to_string()),
        ("not a mapping", "- just\n- a list\n".to_string()),
    ]
}

#[test]
fn refused_manifests_never_reach_the_host() {
    let dir = tempfile::tempdir().unwrap();
    let reg = registry(dir.path());
    for tool in ["sinter_plan_host", "sinter_audit_host"] {
        for (what, m) in refused_manifests() {
            reset(Some(fake()));
            let r = call(&reg, tool, json!({"manifest": m, "target": "web01"}));
            assert!(is_error(&r), "{tool} accepted {what}: {r}");
            let msg = body(&r)["error"]["message"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let want = match what {
                "plugins" => "plugins",
                "include" => "include",
                "source" => "source",
                "content secret" | "password_hash secret" | "password_verifier secret" => "decrypt",
                "unknown type" | "firewalld type without plugin" => "unknown resource type",
                "systemd_timer" => "systemd_timer",
                "nm_connection" => "nm_connection",
                "file_merge" => "file_merge",
                "dnf_repository" => "dnf_repository",
                _ => "",
            };
            assert!(
                msg.contains(want),
                "{tool} {what}: refused for another reason: {msg}"
            );
            assert!(fake_left(), "{tool} connected for {what}");
            assert!(
                engines().is_empty() && commands().is_empty(),
                "{tool} {what}"
            );
        }
    }
}

#[test]
fn caller_supplied_connection_details_and_unknown_arguments_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let reg = registry(dir.path());
    let ok = "version: 1\nresources: []\n";
    for tool in ["sinter_plan_host", "sinter_audit_host"] {
        for extra in [
            json!({"host": "203.0.113.9"}),
            json!({"port": 2222}),
            json!({"user": "root"}),
            json!({"sudo": false}),
            json!({"sudo": true}),
            json!({"known_hosts": "/dev/null"}),
            json!({"identity": "/tmp/key"}),
            json!({"identity_files": ["/tmp/key"]}),
            json!({"mode": "apply"}),
            json!({"approval": "x"}),
            json!({"anything": 1}),
        ] {
            reset(Some(fake()));
            let mut args = json!({"manifest": ok, "target": "web01"});
            for (k, v) in extra.as_object().unwrap() {
                args[k] = v.clone();
            }
            let r = call(&reg, tool, args.clone());
            assert!(is_error(&r), "{tool} accepted {extra}: {r}");
            assert!(body(&r).to_string().contains("unexpected parameter"), "{r}");
            assert!(
                fake_left() && engines().is_empty(),
                "{tool} connected with {extra}"
            );
        }
        // Unknown and malformed target names: refused, never a hostname.
        for target in ["web02", "192.0.2.10", "web01;reboot", "", "../x"] {
            reset(Some(fake()));
            let r = call(&reg, tool, json!({"manifest": ok, "target": target}));
            assert!(is_error(&r), "{tool} accepted target {target:?}");
            assert!(fake_left(), "{tool} connected for target {target:?}");
        }
    }
}

#[test]
fn unknown_tools_never_reach_the_host() {
    let dir = tempfile::tempdir().unwrap();
    let reg = registry(dir.path());
    for name in [
        "sinter_apply",
        "sinter_apply_host",
        "sinter_discover",
        "sinter_approve",
        "sinter_approvals",
        "sinter_plugin_install",
        "sinter_plugin_remove",
        "sinter_serve",
        "sinter_exec",
        "sinter_command",
        "",
    ] {
        reset(Some(fake()));
        let r = call(&reg, name, json!({"manifest": CHANGING, "target": "web01"}));
        assert!(is_error(&r), "{name}: {r}");
        assert!(fake_left() && engines().is_empty(), "{name} connected");
    }
    // The surface stays eight tools, each annotated read-only.
    assert_eq!(tool_names().len(), 8);
    for t in tools() {
        assert_eq!(
            t["annotations"]["readOnlyHint"],
            json!(true),
            "{}",
            t["name"]
        );
        assert_eq!(
            t["annotations"]["destructiveHint"],
            json!(false),
            "{}",
            t["name"]
        );
    }
}

#[test]
fn the_other_tools_keep_ignoring_unknown_arguments() {
    // Compatibility (documented): only the two host tools refuse unknown
    // arguments; the other six ignore them, as they always did.
    let dir = tempfile::tempdir().unwrap();
    let reg = registry(dir.path());
    let m = "version: 1\nresources: []\n";
    let os = "ID=ubuntu\nVERSION_ID=\"24.04\"\nNAME=\"Ubuntu\"\nID_LIKE=debian\n";
    for (tool, args) in [
        ("sinter_get_version", json!({"extra": 1})),
        ("sinter_list_targets", json!({"extra": 1})),
        (
            "sinter_classify_platform",
            json!({"os_release": os, "extra": 1}),
        ),
        (
            "sinter_validate_manifest",
            json!({"manifest": m, "extra": 1}),
        ),
        (
            "sinter_inspect_manifest",
            json!({"manifest": m, "extra": 1}),
        ),
        (
            "sinter_plan",
            json!({"manifest": m, "target": "ubuntu2404", "extra": 1}),
        ),
    ] {
        reset(None);
        let r = call(&reg, tool, args);
        assert!(!is_error(&r), "{tool}: {r}");
    }
}
