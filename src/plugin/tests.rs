//! Step 1 tests: loading and verification only. Every test builds its own
//! plugin root inside a fresh temporary directory and uses a test registry
//! of first-party catalogs. The fixture catalog here is not the attested
//! file (it has no header comment), so the production registry refuses it.

use super::protect::sha256_hex;
use super::*;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

const CATALOG: &str = r#"format = 1
id = "firewalld"
version = "0.1.0"

[[op]]
id = "state"
class = "observe"
program = "/usr/bin/firewall-cmd"
argv = ["--state"]
timeout_secs = 30
exit = { "0" = "running", "252" = "not_running" }

[[op]]
id = "zone_defined"
class = "observe"
program = "/usr/bin/firewall-cmd"
argv = ["--permanent", "--info-zone={zone}"]
timeout_secs = 30
slots = { zone = { class = "ident", max_len = 17 } }
exit = { "0" = "defined", "112" = "undefined" }

[[op]]
id = "service_defined"
class = "observe"
program = "/usr/bin/firewall-cmd"
argv = ["--permanent", "--info-service={service}"]
timeout_secs = 30
slots = { service = { class = "ident", max_len = 64 } }
exit = { "0" = "defined", "101" = "undefined" }

[[op]]
id = "query_service_runtime"
class = "observe"
program = "/usr/bin/firewall-cmd"
argv = ["--zone={zone}", "--query-service={service}"]
timeout_secs = 30
slots = { zone = { class = "ident", max_len = 17 }, service = { class = "ident", max_len = 64 } }
exit = { "0" = "present", "1" = "absent" }

[[op]]
id = "query_service_permanent"
class = "observe"
program = "/usr/bin/firewall-cmd"
argv = ["--permanent", "--zone={zone}", "--query-service={service}"]
timeout_secs = 30
slots = { zone = { class = "ident", max_len = 17 }, service = { class = "ident", max_len = 64 } }
exit = { "0" = "present", "1" = "absent" }

[[op]]
id = "add_service_runtime"
class = "mutate"
program = "/usr/bin/firewall-cmd"
argv = ["--zone={zone}", "--add-service={service}"]
timeout_secs = 60
slots = { zone = { class = "ident", max_len = 17 }, service = { class = "ident", max_len = 64 } }
exit = { "0" = "ok" }

[[op]]
id = "add_service_permanent"
class = "mutate"
program = "/usr/bin/firewall-cmd"
argv = ["--permanent", "--zone={zone}", "--add-service={service}"]
timeout_secs = 60
slots = { zone = { class = "ident", max_len = 17 }, service = { class = "ident", max_len = 64 } }
exit = { "0" = "ok" }
"#;

const PLUGIN: &str = r#"format = 1
id = "firewalld"
version = "0.1.0"
catalog = { id = "firewalld", version = "0.1.0" }

[[type]]
name = "firewalld.service"
fields = { zone = { kind = "ident" }, service = { kind = "ident" } }
precheck = [
  { op = "state", expect = "running" },
  { op = "zone_defined", expect = "defined" },
]

[[type.facet]]
name = "runtime"
observe = "query_service_runtime"
want = "present"
ensure = { present = "add_service_runtime" }

[[type.facet]]
name = "permanent"
observe = "query_service_permanent"
want = "present"
ensure = { present = "add_service_permanent" }
"#;

const OBSERVE: &str = r#"["state", "zone_defined", "service_defined", "query_service_runtime", "query_service_permanent"]"#;
const MUTATE: &str = r#"["add_service_runtime", "add_service_permanent"]"#;

/// A plugin root under a fresh temporary directory (the boundary).
struct Root {
    _tmp: tempfile::TempDir,
    boundary: PathBuf,
    root: PathBuf,
}

fn write_mode(p: &Path, body: &[u8], mode: u32) {
    std::fs::write(p, body).unwrap();
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn trust_text(catalog_sha: &str, plugin_sha: &str, observe: &str, mutate: &str) -> String {
    format!(
        "format = 1\n\n[[catalog]]\nid = \"firewalld\"\nversion = \"0.1.0\"\nsha256 = \"{}\"\nattested_observe = {}\nallowed_mutate = {}\n\n[[plugin]]\nid = \"firewalld\"\nversion = \"0.1.0\"\nsha256 = \"{}\"\n",
        catalog_sha, observe, mutate, plugin_sha
    )
}

impl Root {
    fn new(catalog: &str, plugin: &str) -> Root {
        Root::with_trust(catalog, plugin, None)
    }

    fn with_trust(catalog: &str, plugin: &str, trust: Option<String>) -> Root {
        let tmp = tempfile::tempdir().unwrap();
        let boundary = tmp.path().to_path_buf();
        let root = boundary.join("root");
        for d in [&root, &root.join("catalogs"), &root.join("plugins")] {
            std::fs::create_dir(d).unwrap();
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        write_mode(
            &root.join("catalogs/firewalld-0.1.0.catalog.toml"),
            catalog.as_bytes(),
            0o644,
        );
        write_mode(
            &root.join("plugins/firewalld-0.1.0.plugin.toml"),
            plugin.as_bytes(),
            0o644,
        );
        let trust = trust.unwrap_or_else(|| {
            trust_text(
                &sha256_hex(catalog.as_bytes()),
                &sha256_hex(plugin.as_bytes()),
                OBSERVE,
                MUTATE,
            )
        });
        write_mode(&root.join("trust.toml"), trust.as_bytes(), 0o600);
        Root {
            _tmp: tmp,
            boundary,
            root,
        }
    }

    fn open(&self) -> Result<PluginRoot> {
        PluginRoot::open_below(&self.root, &self.boundary)
    }

    fn catalog_path(&self) -> PathBuf {
        self.root.join("catalogs/firewalld-0.1.0.catalog.toml")
    }
    fn plugin_path(&self) -> PathBuf {
        self.root.join("plugins/firewalld-0.1.0.plugin.toml")
    }
}

fn registry_for(catalog: &str) -> Vec<FirstPartyCatalog> {
    let sha: &'static str = Box::leak(sha256_hex(catalog.as_bytes()).into_boxed_str());
    vec![FirstPartyCatalog {
        id: "firewalld",
        version: "0.1.0",
        sha256: sha,
    }]
}

fn fw() -> Vec<PluginRef> {
    vec![PluginRef {
        id: "firewalld".into(),
        version: "0.1.0".into(),
    }]
}

/// Load the root with a registry naming `catalog`'s bytes as first-party.
fn load_root(r: &Root, catalog: &str) -> Result<PluginSet> {
    load_with(&r.open()?, &fw(), &registry_for(catalog), &mut |_| {})
}

fn err(r: Result<PluginSet>) -> String {
    match r {
        Ok(_) => panic!("expected a refusal"),
        Err(e) => {
            assert_eq!(e.kind, crate::error::ErrorKind::Schema, "{}", e.message);
            e.message
        }
    }
}

/// Load with a modified catalog and/or plugin, re-pinned so that the refusal
/// must come from a Core rule, not from the digest.
fn repinned(catalog: &str, plugin: &str) -> String {
    let r = Root::new(catalog, plugin);
    err(load_root(&r, catalog))
}

fn edit(base: &str, from: &str, to: &str) -> String {
    assert!(base.contains(from), "fixture does not contain {:?}", from);
    base.replacen(from, to, 1)
}

// ---------------------------------------------------------------------------
// accepted input
// ---------------------------------------------------------------------------

#[test]
fn valid_plugin_catalog_and_trust_load_into_a_sealed_model() {
    let r = Root::new(CATALOG, PLUGIN);
    let set = load_root(&r, CATALOG).expect("valid input loads");
    assert!(
        set.execution_available(),
        "step 2 has the execution channels"
    );
    assert_eq!(set.plugins().len(), 1);
    let p = &set.plugins()[0];
    assert_eq!((p.id(), p.version()), ("firewalld", "0.1.0"));
    assert_eq!(p.sha256(), sha256_hex(PLUGIN.as_bytes()));
    let (_, t) = set.resource_type("firewalld.service").expect("type");
    assert_eq!(t.facets().len(), 2);
    assert_eq!(t.prechecks().len(), 2);
    let c = set.catalog(p.catalog()).expect("catalog");
    assert_eq!(c.sha256(), sha256_hex(CATALOG.as_bytes()));
    let q = c.op("query_service_runtime").unwrap();
    assert_eq!(q.class(), OpClass::Observe);
    assert!(q.is_enabled());
    assert_eq!(q.slot_max_len("zone"), Some(17));
    assert_eq!(
        q.argv(),
        &[
            ArgToken::Prefixed {
                prefix: "--zone=".into(),
                slot: "zone".into()
            },
            ArgToken::Prefixed {
                prefix: "--query-service=".into(),
                slot: "service".into()
            },
        ]
    );
    assert_eq!(
        c.op("add_service_runtime").unwrap().class(),
        OpClass::Mutate
    );
    let mut ok = BTreeMap::new();
    ok.insert("zone".to_string(), "public".to_string());
    ok.insert("service".to_string(), "http".to_string());
    t.check_values(&ok).expect("valid values");
}

#[test]
fn nothing_enabled_reads_nothing() {
    // No trust file, no directories: with nothing enabled none is read.
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let pr = PluginRoot::open_below(&root, tmp.path()).unwrap();
    let mut opened = 0;
    let set = load_with(&pr, &[], &[], &mut |_| opened += 1).unwrap();
    assert!(set.is_empty());
    assert_eq!(opened, 0);
}

#[test]
fn an_operation_the_owner_did_not_list_loads_but_stays_disabled() {
    let trust = trust_text(
        &sha256_hex(CATALOG.as_bytes()),
        &sha256_hex(PLUGIN.as_bytes()),
        OBSERVE,
        MUTATE,
    );
    let catalog = format!(
        "{}\n[[op]]\nid = \"list_zones\"\nclass = \"observe\"\nprogram = \"/usr/bin/firewall-cmd\"\nargv = [\"--get-zones\"]\ntimeout_secs = 30\nexit = {{ \"0\" = \"ok\" }}\n",
        CATALOG
    );
    let trust = trust.replace(
        &sha256_hex(CATALOG.as_bytes()),
        &sha256_hex(catalog.as_bytes()),
    );
    let r = Root::with_trust(&catalog, PLUGIN, Some(trust));
    let set = load_root(&r, &catalog).unwrap();
    let c = set.catalog(set.plugins()[0].catalog()).unwrap();
    assert!(!c.op("list_zones").unwrap().is_enabled());
}

// ---------------------------------------------------------------------------
// the production registry and the absence of execution
// ---------------------------------------------------------------------------

#[test]
fn the_production_registry_admits_only_the_exact_attested_bytes() {
    // The release registry lists one catalog (firewalld 0.1.0, step 5). The
    // fixture catalog has the same operations but different bytes, so even
    // pinned by the Owner it is refused: the registry is matched by digest.
    assert_eq!(FIRST_PARTY_CATALOGS.len(), 1);
    assert_ne!(
        FIRST_PARTY_CATALOGS[0].sha256,
        sha256_hex(CATALOG.as_bytes())
    );
    const { assert!(EXECUTION_AVAILABLE) };
    assert!(production_enabled());
    let r = Root::new(CATALOG, PLUGIN);
    let m = err(load(&r.open().unwrap(), &fw()));
    assert!(m.contains("not a reviewed first-party catalog"), "{}", m);
}

#[test]
fn the_loader_has_no_path_to_a_target_or_a_process() {
    // Structural guard: the loading code (the three data modules and the
    // `load_with` function of mod.rs) never names the target, executor or
    // process APIs, so loading cannot run a command. Execution lives only in
    // `exec.rs` and `run.rs`.
    let module = include_str!("mod.rs");
    let start = module.find("pub(crate) fn load_with(").expect("load_with");
    let end = module[start..].find("\n}\n").expect("end of load_with") + start;
    for (name, src) in [
        ("mod.rs load_with", &module[start..end]),
        ("format.rs", include_str!("format.rs")),
        ("protect.rs", include_str!("protect.rs")),
        ("verify.rs", include_str!("verify.rs")),
    ] {
        for needle in [
            "targetfs",
            "TargetFs",
            "executor",
            "Executor",
            "std::process",
            "Command::new",
            "MutationPermit",
            "ExecRequest",
        ] {
            assert!(!src.contains(needle), "{} mentions {}", name, needle);
        }
    }
}

#[test]
fn recipes_still_reject_plugin_type_names_without_wiring() {
    // Step 1 does not touch the recipe model: a plugin-shaped type stays an
    // unknown resource type, exactly as in v1.8.0.
    let tmp = tempfile::tempdir().unwrap();
    let p = tmp.path().join("r.yml");
    std::fs::write(
        &p,
        "version: 1\nresources:\n  - id: fw\n    type: firewalld.service\n    with: { zone: public, service: http }\n",
    )
    .unwrap();
    let e = crate::model::load_model(&p).expect_err("refused");
    assert!(e.message.contains("unknown resource type"), "{}", e.message);
}

// ---------------------------------------------------------------------------
// digests, registration and versions
// ---------------------------------------------------------------------------

#[test]
fn a_changed_catalog_or_plugin_no_longer_matches_its_pin() {
    let r = Root::new(CATALOG, PLUGIN);
    let tampered = edit(
        CATALOG,
        "argv = [\"--zone={zone}\", \"--query-service={service}\"]",
        "argv = [\"--zone={zone}\", \"--add-service={service}\"]",
    );
    write_mode(&r.catalog_path(), tampered.as_bytes(), 0o644);
    let m = err(load_root(&r, CATALOG));
    assert!(m.contains("does not match the sha256 pinned"), "{}", m);

    let r = Root::new(CATALOG, PLUGIN);
    write_mode(
        &r.plugin_path(),
        format!("{}# edited\n", PLUGIN).as_bytes(),
        0o644,
    );
    let m = err(load_root(&r, CATALOG));
    assert!(m.contains("does not match the sha256 pinned"), "{}", m);
}

#[test]
fn a_catalog_pinned_by_the_owner_but_not_first_party_is_refused() {
    let r = Root::new(CATALOG, PLUGIN);
    let other = registry_for("some other bytes");
    let m = err(load_with(&r.open().unwrap(), &fw(), &other, &mut |_| {}));
    assert!(m.contains("not a reviewed first-party catalog"), "{}", m);
}

#[test]
fn unregistered_plugins_and_catalogs_are_refused() {
    // plugin not in the trust file
    let r = Root::new(CATALOG, PLUGIN);
    let m = err(load_with(
        &r.open().unwrap(),
        &[PluginRef {
            id: "nmcli".into(),
            version: "0.1.0".into(),
        }],
        &registry_for(CATALOG),
        &mut |_| {},
    ));
    assert!(m.contains("not trusted"), "{}", m);
    // plugin trusted but not installed
    let r = Root::new(CATALOG, PLUGIN);
    std::fs::remove_file(r.plugin_path()).unwrap();
    let m = err(load_root(&r, CATALOG));
    assert!(m.contains("not installed"), "{}", m);
    // catalog the plugin names is not in the trust file
    let trust = format!(
        "format = 1\n\n[[plugin]]\nid = \"firewalld\"\nversion = \"0.1.0\"\nsha256 = \"{}\"\n",
        sha256_hex(PLUGIN.as_bytes())
    );
    let r = Root::with_trust(CATALOG, PLUGIN, Some(trust));
    let m = err(load_root(&r, CATALOG));
    assert!(
        m.contains("catalog firewalld@0.1.0 is not trusted"),
        "{}",
        m
    );
}

#[test]
fn unregistered_capabilities_are_refused() {
    // an operation the plugin uses is not attested
    let trust = trust_text(
        &sha256_hex(CATALOG.as_bytes()),
        &sha256_hex(PLUGIN.as_bytes()),
        r#"["state", "zone_defined", "query_service_runtime"]"#,
        MUTATE,
    );
    let m = err(load_root(
        &Root::with_trust(CATALOG, PLUGIN, Some(trust)),
        CATALOG,
    ));
    assert!(
        m.contains("query_service_permanent is not attested"),
        "{}",
        m
    );
    // a mutate operation the plugin uses is not allowed
    let trust = trust_text(
        &sha256_hex(CATALOG.as_bytes()),
        &sha256_hex(PLUGIN.as_bytes()),
        OBSERVE,
        r#"["add_service_runtime"]"#,
    );
    let m = err(load_root(
        &Root::with_trust(CATALOG, PLUGIN, Some(trust)),
        CATALOG,
    ));
    assert!(m.contains("add_service_permanent is not allowed"), "{}", m);
    // the trust file names an operation the catalog does not define
    let trust = trust_text(
        &sha256_hex(CATALOG.as_bytes()),
        &sha256_hex(PLUGIN.as_bytes()),
        r#"["state", "zone_defined", "query_service_runtime", "query_service_permanent", "ghost"]"#,
        MUTATE,
    );
    let m = err(load_root(
        &Root::with_trust(CATALOG, PLUGIN, Some(trust)),
        CATALOG,
    ));
    assert!(m.contains("does not define"), "{}", m);
    // a mutate operation listed as attested observe
    let trust = trust_text(
        &sha256_hex(CATALOG.as_bytes()),
        &sha256_hex(PLUGIN.as_bytes()),
        r#"["state", "zone_defined", "query_service_runtime", "query_service_permanent", "add_service_runtime"]"#,
        r#"["add_service_permanent"]"#,
    );
    let m = err(load_root(
        &Root::with_trust(CATALOG, PLUGIN, Some(trust)),
        CATALOG,
    ));
    assert!(m.contains("wrong class"), "{}", m);
    // the plugin names an operation the catalog does not have
    let p = edit(
        PLUGIN,
        "observe = \"query_service_runtime\"",
        "observe = \"remove_service_runtime\"",
    );
    let m = repinned(CATALOG, &p);
    assert!(m.contains("is not in catalog"), "{}", m);
}

#[test]
fn version_mismatches_are_refused() {
    let r = Root::new(CATALOG, PLUGIN);
    let m = err(load_with(
        &r.open().unwrap(),
        &[PluginRef {
            id: "firewalld".into(),
            version: "0.2.0".into(),
        }],
        &registry_for(CATALOG),
        &mut |_| {},
    ));
    assert!(m.contains("not trusted"), "{}", m);
    let p = edit(
        PLUGIN,
        "version = \"0.1.0\"\ncatalog",
        "version = \"0.1.1\"\ncatalog",
    );
    let m = repinned(CATALOG, &p);
    assert!(m.contains("different plugin id or version"), "{}", m);
    let c = edit(CATALOG, "version = \"0.1.0\"", "version = \"0.1.2\"");
    let m = repinned(&c, PLUGIN);
    assert!(m.contains("different catalog id or version"), "{}", m);
    for bad in ["1.0", "01.0.0", "1.0.0-rc1", "v1.0.0", ""] {
        let r = Root::new(CATALOG, PLUGIN);
        let m = err(load_with(
            &r.open().unwrap(),
            &[PluginRef {
                id: "firewalld".into(),
                version: bad.into(),
            }],
            &registry_for(CATALOG),
            &mut |_| {},
        ));
        assert!(
            m.contains("valid id and MAJOR.MINOR.PATCH"),
            "{:?}: {}",
            bad,
            m
        );
    }
}

#[test]
fn type_name_collisions_are_refused() {
    let m = repinned(
        CATALOG,
        &edit(PLUGIN, "name = \"firewalld.service\"", "name = \"file\""),
    );
    assert!(m.contains("must be `firewalld.<name>`"), "{}", m);
    let m = repinned(
        CATALOG,
        &edit(
            PLUGIN,
            "name = \"firewalld.service\"",
            "name = \"other.service\"",
        ),
    );
    assert!(m.contains("must be `firewalld.<name>`"), "{}", m);
    let type_block = &PLUGIN[PLUGIN.find("[[type]]").unwrap()..];
    let dup = format!("{}\n{}", PLUGIN, type_block);
    let m = repinned(CATALOG, &dup);
    assert!(m.contains("defined twice"), "{}", m);
    let r = Root::new(CATALOG, PLUGIN);
    let twice = vec![
        fw()[0].clone(),
        PluginRef {
            id: "firewalld".into(),
            version: "0.1.1".into(),
        },
    ];
    let m = err(load_with(
        &r.open().unwrap(),
        &twice,
        &registry_for(CATALOG),
        &mut |_| {},
    ));
    assert!(m.contains("enabled more than once"), "{}", m);
    for b in BUILTIN_RESOURCE_TYPES {
        assert!(
            !b.contains('.'),
            "built-in {} would collide with the plugin namespace rule",
            b
        );
    }
}

// ---------------------------------------------------------------------------
// formats
// ---------------------------------------------------------------------------

#[test]
fn unknown_keys_are_refused_in_every_file() {
    let m = repinned(
        CATALOG,
        &edit(
            PLUGIN,
            "[[type]]\n",
            "program = \"/usr/bin/sh\"\n\n[[type]]\n",
        ),
    );
    assert!(m.contains("unknown field"), "{}", m);
    let m = repinned(
        &edit(
            CATALOG,
            "timeout_secs = 30\nexit = { \"0\" = \"running\"",
            "timeout_secs = 30\nenv = { A = \"1\" }\nexit = { \"0\" = \"running\"",
        ),
        PLUGIN,
    );
    assert!(m.contains("unknown field"), "{}", m);
    let trust = format!(
        "{}trust_everything = true\n",
        trust_text(
            &sha256_hex(CATALOG.as_bytes()),
            &sha256_hex(PLUGIN.as_bytes()),
            OBSERVE,
            MUTATE
        )
    );
    let m = err(load_root(
        &Root::with_trust(CATALOG, PLUGIN, Some(trust)),
        CATALOG,
    ));
    assert!(m.contains("unknown field"), "{}", m);
}

#[test]
fn invalid_formats_are_refused() {
    let trust = "format = 1\n[[plugin]\n".to_string();
    let m = err(load_root(
        &Root::with_trust(CATALOG, PLUGIN, Some(trust)),
        CATALOG,
    ));
    assert!(m.contains("invalid format"), "{}", m);
    let trust = trust_text(
        &sha256_hex(CATALOG.as_bytes()),
        &sha256_hex(PLUGIN.as_bytes()),
        OBSERVE,
        MUTATE,
    )
    .replacen("format = 1", "format = 2", 1);
    let m = err(load_root(
        &Root::with_trust(CATALOG, PLUGIN, Some(trust)),
        CATALOG,
    ));
    assert!(m.contains("unsupported format 2"), "{}", m);
    let r = Root::new(CATALOG, PLUGIN);
    write_mode(&r.root.join("trust.toml"), b"format = 1\n\xff\xfe\n", 0o600);
    let m = err(load_root(&r, CATALOG));
    assert!(m.contains("not valid UTF-8"), "{}", m);
    let trust = trust_text("ABC", &sha256_hex(PLUGIN.as_bytes()), OBSERVE, MUTATE);
    let m = err(load_root(
        &Root::with_trust(CATALOG, PLUGIN, Some(trust)),
        CATALOG,
    ));
    assert!(m.contains("lowercase hex sha256"), "{}", m);
    let t = trust_text(
        &sha256_hex(CATALOG.as_bytes()),
        &sha256_hex(PLUGIN.as_bytes()),
        OBSERVE,
        MUTATE,
    );
    let dup = format!(
        "{}\n[[plugin]]\nid = \"firewalld\"\nversion = \"0.1.0\"\nsha256 = \"{}\"\n",
        t,
        sha256_hex(PLUGIN.as_bytes())
    );
    let m = err(load_root(
        &Root::with_trust(CATALOG, PLUGIN, Some(dup)),
        CATALOG,
    ));
    assert!(m.contains("duplicate plugin entry"), "{}", m);
}

#[test]
fn files_over_the_size_limit_are_refused() {
    let big = format!("{}#{}\n", PLUGIN, "x".repeat(verify::MAX_FILE_BYTES));
    let r = Root::new(CATALOG, &big);
    let m = err(load_root(&r, CATALOG));
    assert!(m.contains("larger than the 65536 byte limit"), "{}", m);
}

// ---------------------------------------------------------------------------
// catalog rules (re-pinned: the Core rule must refuse)
// ---------------------------------------------------------------------------

#[test]
fn catalog_rules_refuse_unsafe_operations_even_when_pinned() {
    let cases: &[(&str, &str, &str, &str)] = &[
        (
            "shell",
            "program = \"/usr/bin/firewall-cmd\"\nargv = [\"--state\"]",
            "program = \"/usr/bin/sh\"\nargv = [\"--state\"]",
            "permitted program",
        ),
        (
            "sudo",
            "program = \"/usr/bin/firewall-cmd\"\nargv = [\"--state\"]",
            "program = \"/usr/bin/sudo\"\nargv = [\"--state\"]",
            "permitted program",
        ),
        (
            "relative",
            "program = \"/usr/bin/firewall-cmd\"\nargv = [\"--state\"]",
            "program = \"firewall-cmd\"\nargv = [\"--state\"]",
            "permitted program",
        ),
        (
            "other dir",
            "program = \"/usr/bin/firewall-cmd\"\nargv = [\"--state\"]",
            "program = \"/opt/bin/firewall-cmd\"\nargv = [\"--state\"]",
            "permitted program",
        ),
        (
            "traversal",
            "program = \"/usr/bin/firewall-cmd\"\nargv = [\"--state\"]",
            "program = \"/usr/bin/../../bin/sh\"\nargv = [\"--state\"]",
            "permitted program",
        ),
        (
            "bare slot",
            "argv = [\"--zone={zone}\", \"--query-service={service}\"]",
            "argv = [\"{zone}\", \"--query-service={service}\"]",
            "must follow a literal",
        ),
        (
            "bad prefix",
            "argv = [\"--zone={zone}\", \"--query-service={service}\"]",
            "argv = [\"-z{zone}\", \"--query-service={service}\"]",
            "--option={name}",
        ),
        (
            "space literal",
            "argv = [\"--state\"]",
            "argv = [\"--state now\"]",
            "printable ASCII",
        ),
        (
            "undeclared slot",
            "argv = [\"--permanent\", \"--info-zone={zone}\"]",
            "argv = [\"--permanent\", \"--info-zone={zone}\", \"--x={other}\"]",
            "used in argv and declared differ",
        ),
        (
            "slot class",
            "slots = { zone = { class = \"ident\", max_len = 17 } }",
            "slots = { zone = { class = \"path\", max_len = 17 } }",
            "class ident",
        ),
        (
            "slot too long",
            "slots = { zone = { class = \"ident\", max_len = 17 } }",
            "slots = { zone = { class = \"ident\", max_len = 65 } }",
            "max_len 1..=64",
        ),
        (
            "class",
            "class = \"observe\"",
            "class = \"admin\"",
            "observe or mutate",
        ),
        (
            "timeout 0",
            "timeout_secs = 30\nexit = { \"0\" = \"running\"",
            "timeout_secs = 0\nexit = { \"0\" = \"running\"",
            "1..=120",
        ),
        (
            "timeout big",
            "timeout_secs = 30\nexit = { \"0\" = \"running\"",
            "timeout_secs = 121\nexit = { \"0\" = \"running\"",
            "1..=120",
        ),
        (
            "exit 256",
            "exit = { \"0\" = \"running\", \"252\" = \"not_running\" }",
            "exit = { \"0\" = \"running\", \"256\" = \"not_running\" }",
            "0..=255",
        ),
        (
            "exit 01",
            "exit = { \"0\" = \"running\", \"252\" = \"not_running\" }",
            "exit = { \"0\" = \"running\", \"01\" = \"not_running\" }",
            "0..=255",
        ),
        (
            "mutate state",
            "exit = { \"0\" = \"ok\" }",
            "exit = { \"0\" = \"ok\", \"11\" = \"already\" }",
            "\"ok\" only",
        ),
        (
            "observe lint",
            "argv = [\"--zone={zone}\", \"--query-service={service}\"]",
            "argv = [\"--zone={zone}\", \"--add-service={service}\"]",
            "mutating-looking",
        ),
        (
            "observe lint word",
            "argv = [\"--state\"]",
            "argv = [\"reload\"]",
            "mutating-looking",
        ),
    ];
    for (label, from, to, expect) in cases {
        let m = repinned(&edit(CATALOG, from, to), PLUGIN);
        assert!(m.contains(expect), "{}: {}", label, m);
    }
}

// ---------------------------------------------------------------------------
// plugin rules (re-pinned)
// ---------------------------------------------------------------------------

#[test]
fn plugin_rules_refuse_misuse_even_when_pinned() {
    let cases: &[(&str, &str, &str, &str)] = &[
        (
            "observe via mutate",
            "observe = \"query_service_runtime\"",
            "observe = \"add_service_runtime\"",
            "is a mutate operation; an observe operation is required",
        ),
        (
            "ensure via observe",
            "present = \"add_service_runtime\"",
            "present = \"query_service_runtime\"",
            "is an observe operation; a mutate operation is required",
        ),
        (
            "impossible want",
            "want = \"present\"\nensure = { present = \"add_service_runtime\" }",
            "want = \"enabled\"\nensure = { present = \"add_service_runtime\" }",
            "cannot report",
        ),
        (
            "no ensure",
            "ensure = { present = \"add_service_runtime\" }",
            "ensure = { }",
            "no ensure operation",
        ),
        (
            "unbound slot",
            "fields = { zone = { kind = \"ident\" }, service = { kind = \"ident\" } }",
            "fields = { zone = { kind = \"ident\" }, svc = { kind = \"ident\" } }",
            "is not filled by a field",
        ),
        (
            "bad kind",
            "zone = { kind = \"ident\" }",
            "zone = { kind = \"path\" }",
            "kind is ident",
        ),
        (
            "precheck state",
            "{ op = \"state\", expect = \"running\" }",
            "{ op = \"state\", expect = \"up\" }",
            "cannot report",
        ),
    ];
    for (label, from, to, expect) in cases {
        let m = repinned(CATALOG, &edit(PLUGIN, from, to));
        assert!(m.contains(expect), "{}: {}", label, m);
    }
    // an enum value longer than the slot it fills
    let c = edit(
        CATALOG,
        "slots = { zone = { class = \"ident\", max_len = 17 } }",
        "slots = { zone = { class = \"ident\", max_len = 3 } }",
    );
    let p = edit(
        PLUGIN,
        "zone = { kind = \"ident\" }",
        "zone = { kind = \"enum\", values = [\"public\"] }",
    );
    let m = repinned(&c, &p);
    assert!(m.contains("does not fit its slot"), "{}", m);
}

// ---------------------------------------------------------------------------
// operands and sensitive values
// ---------------------------------------------------------------------------

#[test]
fn invalid_operands_are_refused_without_showing_the_value() {
    let r = Root::new(CATALOG, PLUGIN);
    let set = load_root(&r, CATALOG).unwrap();
    let (_, t) = set.resource_type("firewalld.service").unwrap();
    let secretish = "S3CR3T-VALUE";
    for bad in [
        "-trusted",
        "public,trusted",
        "a=b",
        "pub lic",
        "../etc",
        "x$(id)",
        "",
        "averyveryverylongzonename",
        "z\u{200b}one",
        "public\n",
    ] {
        let mut v = BTreeMap::new();
        v.insert("zone".to_string(), bad.to_string());
        v.insert("service".to_string(), secretish.to_string());
        let e = t
            .check_values(&v)
            .err()
            .unwrap_or_else(|| panic!("{:?} accepted", bad));
        assert!(e.message.contains("field zone"), "{}", e.message);
        if !bad.is_empty() {
            assert!(!e.message.contains(bad), "{:?} leaked: {}", bad, e.message);
        }
        assert!(!e.message.contains(secretish), "{}", e.message);
    }
    let mut v = BTreeMap::new();
    v.insert("zone".to_string(), "public".to_string());
    v.insert("service".to_string(), "x y".to_string());
    let e = t.check_values(&v).unwrap_err();
    assert!(!e.message.contains("x y"), "{}", e.message);
    let mut v = BTreeMap::new();
    v.insert("zone".to_string(), "public".to_string());
    let e = t.check_values(&v).unwrap_err();
    assert!(e.message.contains("missing field service"), "{}", e.message);
}

#[test]
fn parser_messages_do_not_echo_values() {
    let trust = trust_text(
        &sha256_hex(CATALOG.as_bytes()),
        &sha256_hex(PLUGIN.as_bytes()),
        OBSERVE,
        MUTATE,
    )
    .replacen("format = 1", "format = \"S3CR3T-VALUE\"", 1);
    let m = err(load_root(
        &Root::with_trust(CATALOG, PLUGIN, Some(trust)),
        CATALOG,
    ));
    assert!(m.contains("invalid format"), "{}", m);
    assert!(!m.contains("S3CR3T-VALUE"), "{}", m);
}

// ---------------------------------------------------------------------------
// file protection
// ---------------------------------------------------------------------------

#[test]
fn symlinks_are_refused() {
    let r = Root::new(CATALOG, PLUGIN);
    let real = r.root.join("plugins/real.toml");
    std::fs::rename(r.plugin_path(), &real).unwrap();
    std::os::unix::fs::symlink(&real, r.plugin_path()).unwrap();
    let m = err(load_root(&r, CATALOG));
    assert!(m.contains("refusing a symbolic link"), "{}", m);

    let r = Root::new(CATALOG, PLUGIN);
    let elsewhere = r.boundary.join("elsewhere");
    std::fs::rename(r.root.join("catalogs"), &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, r.root.join("catalogs")).unwrap();
    let m = err(load_root(&r, CATALOG));
    assert!(
        m.contains("refusing a symbolic link or non-directory"),
        "{}",
        m
    );

    let r = Root::new(CATALOG, PLUGIN);
    let t = r.root.join("trust-real.toml");
    std::fs::rename(r.root.join("trust.toml"), &t).unwrap();
    std::os::unix::fs::symlink(&t, r.root.join("trust.toml")).unwrap();
    let m = err(load_root(&r, CATALOG));
    assert!(m.contains("refusing a symbolic link"), "{}", m);
}

#[test]
fn a_symlinked_root_path_is_resolved_once_then_checked() {
    // An operator-configured path may go through a symlink (dotfile
    // managers); the resolved directories are what is checked.
    let r = Root::new(CATALOG, PLUGIN);
    let link = r.boundary.join("link-to-root");
    std::os::unix::fs::symlink(&r.root, &link).unwrap();
    let pr = PluginRoot::open_below(&link, &r.boundary).unwrap();
    load_with(&pr, &fw(), &registry_for(CATALOG), &mut |_| {})
        .expect("loads through the resolved path");
}

#[test]
fn writable_files_and_directories_are_refused() {
    let r = Root::new(CATALOG, PLUGIN);
    std::fs::set_permissions(r.plugin_path(), std::fs::Permissions::from_mode(0o664)).unwrap();
    let m = err(load_root(&r, CATALOG));
    assert!(m.contains("writable by group or others"), "{}", m);

    let r = Root::new(CATALOG, PLUGIN);
    std::fs::set_permissions(
        r.root.join("trust.toml"),
        std::fs::Permissions::from_mode(0o646),
    )
    .unwrap();
    let m = err(load_root(&r, CATALOG));
    assert!(m.contains("writable by group or others"), "{}", m);

    let r = Root::new(CATALOG, PLUGIN);
    std::fs::set_permissions(
        r.root.join("catalogs"),
        std::fs::Permissions::from_mode(0o770),
    )
    .unwrap();
    let m = err(load_root(&r, CATALOG));
    assert!(m.contains("writable by group or others"), "{}", m);

    let r = Root::new(CATALOG, PLUGIN);
    std::fs::set_permissions(&r.root, std::fs::Permissions::from_mode(0o777)).unwrap();
    let m = err(r.open().map(|_| PluginSet::default()));
    assert!(m.contains("writable by group or others"), "{}", m);
}

#[test]
fn ancestors_must_not_be_writable_by_others_unless_sticky() {
    let tmp = tempfile::tempdir().unwrap();
    let mid = tmp.path().join("mid");
    let root = mid.join("root");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&mid, std::fs::Permissions::from_mode(0o777)).unwrap();
    let e = PluginRoot::open_below(&root, tmp.path())
        .err()
        .expect("refused");
    assert!(
        e.message
            .contains("an ancestor of the plugin root is writable"),
        "{}",
        e.message
    );
    std::fs::set_permissions(&mid, std::fs::Permissions::from_mode(0o1777)).unwrap();
    PluginRoot::open_below(&root, tmp.path()).expect("a sticky ancestor (like /tmp) is accepted");
}

#[test]
fn non_regular_files_are_refused() {
    let r = Root::new(CATALOG, PLUGIN);
    std::fs::remove_file(r.plugin_path()).unwrap();
    std::fs::create_dir(r.plugin_path()).unwrap();
    let m = err(load_root(&r, CATALOG));
    assert!(m.contains("not a regular file"), "{}", m);
}

#[test]
fn a_fifo_is_refused_without_blocking() {
    let r = Root::new(CATALOG, PLUGIN);
    std::fs::remove_file(r.plugin_path()).unwrap();
    let c = std::ffi::CString::new(r.plugin_path().to_str().unwrap()).unwrap();
    // SAFETY: `c` is a valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
    let m = err(load_root(&r, CATALOG));
    assert!(m.contains("not a regular file"), "{}", m);
}

#[test]
fn owner_check_accepts_this_user() {
    // Files created by the test belong to this user and are accepted (the
    // valid-load test). A file owned by another non-root user needs root to
    // create, so the refusal path is covered by code review only (see the
    // step 1 report, NOT VERIFIED).
    let r = Root::new(CATALOG, PLUGIN);
    let md = std::fs::metadata(r.plugin_path()).unwrap();
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions.
    assert_eq!(md.uid(), unsafe { libc::geteuid() });
    load_root(&r, CATALOG).unwrap();
}

// ---------------------------------------------------------------------------
// replacement and modification while loading (TOCTOU)
// ---------------------------------------------------------------------------

#[test]
fn replacing_a_file_after_it_was_opened_never_uses_the_replacement() {
    // The checked descriptor is what is read: a rename over the name after
    // the open does not change the bytes that are hashed and parsed.
    let r = Root::new(CATALOG, PLUGIN);
    let evil = edit(
        PLUGIN,
        "observe = \"query_service_runtime\"",
        "observe = \"add_service_runtime\"",
    );
    let staged = r.root.join("plugins/staged.toml");
    write_mode(&staged, evil.as_bytes(), 0o644);
    let target = r.plugin_path();
    let mut seam = |name: &str| {
        if name == "firewalld-0.1.0.plugin.toml" && staged.exists() {
            std::fs::rename(&staged, &target).unwrap();
        }
    };
    // Either the original bytes are used (the descriptor still names the
    // original inode) or, where the rename is visible on that inode (its
    // change time moves when it is unlinked, as on macOS and Linux), the load
    // is refused. The replacement's bytes are never used.
    match load_with(&r.open().unwrap(), &fw(), &registry_for(CATALOG), &mut seam) {
        Ok(set) => assert_eq!(set.plugins()[0].sha256(), sha256_hex(PLUGIN.as_bytes())),
        Err(e) => assert!(
            e.message.contains("changed while it was being read"),
            "{}",
            e.message
        ),
    }
    // The next load sees the replacement, which no longer matches the pin.
    let m = err(load_root(&r, CATALOG));
    assert!(m.contains("does not match the sha256 pinned"), "{}", m);
}

#[test]
fn modifying_a_file_while_it_is_read_is_refused() {
    let r = Root::new(CATALOG, PLUGIN);
    let trust = r.root.join("trust.toml");
    let mut seam = |name: &str| {
        if name == "trust.toml" {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&trust)
                .unwrap();
            f.write_all(b"\n# appended while loading\n").unwrap();
        }
    };
    let m = err(load_with(
        &r.open().unwrap(),
        &fw(),
        &registry_for(CATALOG),
        &mut seam,
    ));
    assert!(m.contains("changed while it was being read"), "{}", m);
}

#[test]
fn a_failed_load_changes_nothing_on_disk() {
    let r = Root::new(CATALOG, PLUGIN);
    write_mode(&r.plugin_path(), b"format = 1\n", 0o644);
    let before: Vec<(PathBuf, Vec<u8>)> = walk(&r.root);
    let _ = load_root(&r, CATALOG).expect_err("refused");
    assert_eq!(walk(&r.root), before);
}

fn walk(d: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![d.to_path_buf()];
    while let Some(p) = stack.pop() {
        for e in std::fs::read_dir(&p).unwrap().flatten() {
            let path = e.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push((path.clone(), std::fs::read(&path).unwrap()));
            }
        }
    }
    out.sort();
    out
}
