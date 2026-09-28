mod common;

use common::*;
use sinter::document::document_from_value;
use sinter::model::load_model;
use sinter::toml_front::parse_toml;
use sinter::value::Value;
use sinter::yaml::parse_yaml;

#[test]
fn yaml_and_toml_produce_identical_ir() {
    // A recipe expressed equivalently in both frontends must produce the same
    // typed IR and the same model.
    let dir = trusted_root("frontend-equivalence");
    std::fs::create_dir_all(dir.join("templates")).unwrap();
    std::fs::write(dir.join("templates/x.conf"), "hello\n").unwrap();

    let yaml = r#"
version: 1
vars:
  name:
    value: nginx
    sensitive: false
  port:
    value: 8080
resources:
  - id: conf
    type: template
    with:
      path: /tmp/x.conf
      source: templates/x.conf
      mode: "0644"
    notify:
      - restart_nginx
handlers:
  - id: restart_nginx
    service: nginx
    action: restart
"#;
    let toml = r#"
version = 1

[vars.name]
value = "nginx"
sensitive = false

[vars.port]
value = 8080

[[resources]]
id = "conf"
type = "template"
notify = ["restart_nginx"]

[resources.with]
path = "/tmp/x.conf"
source = "templates/x.conf"
mode = "0644"

[[handlers]]
id = "restart_nginx"
service = "nginx"
action = "restart"
"#;
    let dir2 = dir.join("y");
    std::fs::create_dir_all(dir2.join("templates")).unwrap();
    std::fs::write(dir2.join("templates/x.conf"), "hello\n").unwrap();
    let ypath = write_recipe(&dir2, "r.yaml", yaml);
    let tpath = write_recipe(&dir2, "r.toml", toml);
    let my = load_model(&ypath);
    let mt = load_model(&tpath);
    assert!(my.is_ok(), "yaml model err: {:?}", my.err());
    assert!(mt.is_ok(), "toml model err: {:?}", mt.err());
    let my = my.unwrap();
    let mt = mt.unwrap();
    assert_eq!(my.resources.len(), mt.resources.len());
    assert_eq!(my.resources[0].type_, mt.resources[0].type_);
    assert_eq!(my.resources[0].with, mt.resources[0].with);
    assert_eq!(my.handlers.len(), mt.handlers.len());
    assert_eq!(my.vars.len(), mt.vars.len());
}

#[test]
fn typed_values_across_frontends() {
    let y = parse_yaml("i: 42\nf: 3.5\nb: true\ns: text\nn: null\nl: [1, 2]\nm: {a: 1}\n").unwrap();
    let m = y.as_map().unwrap();
    assert!(matches!(m["i"], Value::Int(42)));
    assert!(matches!(m["f"], Value::Float(_)));
    assert!(matches!(m["b"], Value::Bool(true)));
    assert!(matches!(m["s"], Value::Str(_)));
    assert!(matches!(m["n"], Value::Null));
    assert!(matches!(m["l"], Value::List(_)));
    assert!(matches!(m["m"], Value::Map(_)));

    let t =
        parse_toml("i = 42\nf = 3.5\nb = true\ns = \"text\"\nl = [1, 2]\n[m]\na = 1\n").unwrap();
    let tm = t.as_map().unwrap();
    assert!(matches!(tm["i"], Value::Int(42)));
    assert!(matches!(tm["f"], Value::Float(_)));
    assert!(matches!(tm["b"], Value::Bool(true)));
    assert!(matches!(tm["s"], Value::Str(_)));
    assert!(matches!(tm["l"], Value::List(_)));
}

#[test]
fn rejects_unknown_top_level_field() {
    let v = parse_yaml("version: 1\nbogus: true\n").unwrap();
    let err = document_from_value(v, std::path::Path::new("x.yaml"), "x.yaml");
    assert!(err.is_err());
}

#[test]
fn rejects_unknown_resource_field() {
    let dir = trusted_root("unknown-field");
    let p = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: f\n    type: file\n    bogus: 1\n    with:\n      path: /tmp/x\n",
    );
    // `bogus` is an unknown common resource field.
    assert!(load_model(&p).is_err());
}

#[test]
fn rejects_unknown_with_field() {
    let dir = trusted_root("unknown-with");
    let p = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: /tmp/x\n      bogus: 1\n",
    );
    assert!(load_model(&p).is_err());
}

#[test]
fn rejects_variable_null() {
    let dir = trusted_root("var-null");
    let p = write_recipe(&dir, "r.yaml", "version: 1\nvars:\n  x:\n    value: null\n");
    assert!(load_model(&p).is_err());
}

#[test]
fn rejects_duplicate_variable_after_include() {
    let dir = trusted_root("dup-var");
    write_recipe(&dir, "a.yaml", "version: 1\nvars:\n  x:\n    value: 1\n");
    let p = write_recipe(
        &dir,
        "main.yaml",
        "version: 1\ninclude:\n  - a.yaml\nvars:\n  x:\n    value: 2\n",
    );
    assert!(load_model(&p).is_err());
}

#[test]
fn rejects_invalid_mode() {
    let dir = trusted_root("bad-mode");
    let p = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: f\n    type: file\n    with:\n      path: /tmp/x\n      mode: \"0644x\"\n",
    );
    assert!(load_model(&p).is_err());
}

#[test]
fn rejects_conflicting_ownership() {
    let dir = trusted_root("conflict");
    let p = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: a\n    type: file\n    with:\n      path: /tmp/x\n  - id: b\n    type: link\n    with:\n      path: /tmp/x\n      target: /tmp/y\n",
    );
    assert!(load_model(&p).is_err());
}

#[test]
fn rejects_yaml_alias_merge_datetime() {
    assert!(parse_yaml("a: &x 1\nb: *x\n").is_err());
    assert!(parse_yaml("base: {x: 1}\nc:\n  <<: {y: 2}\n").is_err());
    assert!(parse_toml("x = 1979-05-27T07:32:00Z\n").is_err());
}

#[test]
fn rejects_non_static_identifiers() {
    let dir = trusted_root("static-id");
    // package name from a fact is forbidden.
    let p = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: \"{{ facts.hostname }}\"\n      state: present\n",
    );
    assert!(load_model(&p).is_err());
}

#[test]
fn conflicting_id_between_resource_and_handler() {
    let dir = trusted_root("id-collision");
    let p = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: x\n    type: file\n    with:\n      path: /tmp/x\nhandlers:\n  - id: x\n    service: nginx\n    action: restart\n",
    );
    assert!(load_model(&p).is_err());
}

#[test]
fn rejects_unsupported_recipe_version() {
    let dir = trusted_root("bad-version");
    let p = write_recipe(&dir, "r.yaml", "version: 2\n");
    assert!(load_model(&p).is_err());
}

#[test]
fn empty_loop_expands_to_zero_resources() {
    let dir = trusted_root("empty-loop");
    let p = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: chk\n    type: command\n    with:\n      program: /bin/true\n    loop: []\n",
    );
    let m = load_model(&p).unwrap();
    assert_eq!(m.resources.len(), 0);
}

#[test]
fn relative_source_relative_to_recipe() {
    let dir = trusted_root("rel-source");
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::write(dir.join("sub/t"), "x").unwrap();
    let p = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: t\n    type: template\n    with:\n      path: /tmp/out\n      source: sub/t\n",
    );
    let m = load_model(&p).unwrap();
    assert!(m.resources[0]
        .controller_source
        .as_ref()
        .unwrap()
        .ends_with("sub/t"));
}

fn link_recipe(dir: &std::path::Path, name: &str, with: &str) -> std::path::PathBuf {
    write_recipe(
        dir,
        name,
        &format!("version: 1\nresources:\n  - id: l\n    type: link\n    with:\n{with}"),
    )
}

#[test]
fn link_without_target_when_present_is_a_validation_error() {
    // Execution refuses a present link without a target; validation rejects
    // it before any target is contacted. An omitted state means present.
    let dir = trusted_root("link-target-required");
    for (name, with) in [
        ("omitted-state.yaml", "      path: /tmp/l\n"),
        ("present.yaml", "      path: /tmp/l\n      state: present\n"),
        (
            "null-target.yaml",
            "      path: /tmp/l\n      state: present\n      target: null\n",
        ),
    ] {
        let e = load_model(&link_recipe(&dir, name, with)).expect_err(name);
        assert!(
            e.message.contains("link target is required when present"),
            "{name}: {}",
            e.message
        );
    }
}

#[test]
fn link_target_rule_keeps_valid_links_valid() {
    let dir = trusted_root("link-target-valid");
    for (name, with) in [
        (
            "with-target.yaml",
            "      path: /tmp/l\n      target: /tmp/t\n",
        ),
        (
            "present-with-target.yaml",
            "      path: /tmp/l\n      state: present\n      target: /tmp/t\n",
        ),
        // Removing a link never needed a target.
        ("absent.yaml", "      path: /tmp/l\n      state: absent\n"),
    ] {
        load_model(&link_recipe(&dir, name, with))
            .unwrap_or_else(|e| panic!("{name}: {}", e.message));
    }
}

#[test]
fn template_rejects_content() {
    let dir = trusted_root("template-content");
    std::fs::write(dir.join("t.conf"), "x\n").unwrap();
    let p = write_recipe(
        &dir,
        "r.yaml",
        "version: 1\nresources:\n  - id: t\n    type: template\n    with:\n      path: /tmp/t.conf\n      source: t.conf\n      content: inline\n",
    );
    let e = load_model(&p).expect_err("template content must be rejected");
    assert!(
        e.message
            .contains("template does not support content; use source"),
        "{}",
        e.message
    );
}

#[test]
fn every_template_field_in_the_field_table_is_accepted() {
    // The field table must not advertise a field that validation rejects.
    let dir = trusted_root("template-fields");
    std::fs::write(dir.join("t.conf"), "x\n").unwrap();
    let mut with = String::new();
    for field in sinter::model::TEMPLATE_FIELDS {
        let value = match *field {
            "path" => "/tmp/t.conf",
            "state" => "present",
            "source" => "t.conf",
            "owner" => "root",
            "group" => "root",
            "mode" => "\"0644\"",
            "vars" => "{ k: v }",
            other => {
                panic!("no sample value for template field {other}; add one if it is supported")
            }
        };
        with.push_str(&format!("      {field}: {value}\n"));
    }
    let p = write_recipe(
        &dir,
        "r.yaml",
        &format!("version: 1\nresources:\n  - id: t\n    type: template\n    with:\n{with}"),
    );
    load_model(&p).unwrap_or_else(|e| panic!("{}", e.message));
}

#[test]
fn link_state_outside_present_or_absent_is_a_validation_error() {
    // Anything other than `absent` used to be applied as `present`.
    let dir = trusted_root("link-state-domain");
    for (name, state) in [
        ("typo.yaml", "presnet"),
        ("word.yaml", "banana"),
        ("empty.yaml", "\"\""),
        ("bool.yaml", "true"),
    ] {
        let with = format!("      path: /tmp/l\n      target: /tmp/t\n      state: {state}\n");
        let e = load_model(&link_recipe(&dir, name, &with)).expect_err(name);
        assert!(
            e.message.contains("link state must be present or absent"),
            "{name}: {}",
            e.message
        );
    }
}

#[test]
fn link_state_valid_forms_stay_valid() {
    let dir = trusted_root("link-state-valid");
    for (name, with) in [
        ("omitted.yaml", "      path: /tmp/l\n      target: /tmp/t\n"),
        (
            "null.yaml",
            "      path: /tmp/l\n      target: /tmp/t\n      state: null\n",
        ),
        (
            "present.yaml",
            "      path: /tmp/l\n      target: /tmp/t\n      state: present\n",
        ),
        ("absent.yaml", "      path: /tmp/l\n      state: absent\n"),
    ] {
        load_model(&link_recipe(&dir, name, with))
            .unwrap_or_else(|e| panic!("{name}: {}", e.message));
    }
    // An interpolated state is resolved when the resource runs.
    let p = write_recipe(
        &dir,
        "interpolated.yaml",
        "version: 1\nvars:\n  s:\n    value: present\nresources:\n  - id: l\n    type: link\n    with:\n      path: /tmp/l\n      target: /tmp/t\n      state: \"{{ vars.s }}\"\n",
    );
    load_model(&p).unwrap_or_else(|e| panic!("interpolated: {}", e.message));
}

fn handler_recipe(dir: &std::path::Path, name: &str, service: &str) -> std::path::PathBuf {
    write_recipe(
        dir,
        name,
        &format!(
            "version: 1\nresources:\n  - id: c\n    type: command\n    with:\n      program: /bin/true\n    notify:\n      - h\nhandlers:\n  - id: h\n    service: \"{service}\"\n    action: restart\n"
        ),
    )
}

#[test]
fn handler_empty_service_is_a_validation_error() {
    let dir = trusted_root("handler-empty-service");
    let e = load_model(&handler_recipe(&dir, "r.yaml", "")).expect_err("empty service");
    assert!(
        e.message.contains("service must not be empty"),
        "{}",
        e.message
    );
}

#[test]
fn handler_service_names_are_otherwise_unchanged() {
    // Names are not trimmed or narrowed, as for a service resource `name`:
    // an ordinary unit validates, and a blank one is left to systemd, which
    // reports it not-found so the handler fails (see tests/platform.rs).
    let dir = trusted_root("handler-service-names");
    for (name, service) in [("unit.yaml", "app.service"), ("blank.yaml", "   ")] {
        let m = load_model(&handler_recipe(&dir, name, service))
            .unwrap_or_else(|e| panic!("{name}: {}", e.message));
        assert_eq!(m.handlers[0].service, service);
    }
}

/// A one-resource recipe of `kind` whose `with` block ends in `extra`. A
/// template source file `t.conf` is created next to it.
fn state_recipe(dir: &std::path::Path, name: &str, kind: &str, extra: &str) -> std::path::PathBuf {
    std::fs::write(dir.join("t.conf"), "x\n").unwrap();
    let base = match kind {
        "file" => "      path: /tmp/f\n",
        "directory" => "      path: /tmp/d\n",
        "template" => "      path: /tmp/t\n      source: t.conf\n",
        other => panic!("no base for {other}"),
    };
    write_recipe(
        dir,
        name,
        &format!(
            "version: 1\nvars:\n  s:\n    value: present\nresources:\n  - id: r\n    type: {kind}\n    with:\n{base}{extra}"
        ),
    )
}

#[test]
fn file_directory_template_state_outside_present_or_absent_is_a_validation_error() {
    // A literal that can never be valid is rejected before any target is
    // contacted (runtime used to be the first place it was noticed).
    let dir = trusted_root("state-domain-invalid");
    for kind in ["file", "directory", "template"] {
        for (n, state) in [("typo", "presnet"), ("empty", "\"\""), ("bool", "true")] {
            let name = format!("{kind}-{n}.yaml");
            let p = state_recipe(&dir, &name, kind, &format!("      state: {state}\n"));
            let e = load_model(&p).expect_err(&name);
            assert!(
                e.message
                    .contains(&format!("{kind} state must be present or absent")),
                "{name}: {}",
                e.message
            );
        }
    }
}

#[test]
fn file_directory_template_valid_states_stay_valid() {
    let dir = trusted_root("state-domain-valid");
    for kind in ["file", "directory", "template"] {
        for (n, extra) in [
            ("omitted", ""),
            ("null", "      state: null\n"),
            ("present", "      state: present\n"),
            ("absent", "      state: absent\n"),
            ("interpolated", "      state: \"{{ vars.s }}\"\n"),
        ] {
            let name = format!("{kind}-{n}.yaml");
            load_model(&state_recipe(&dir, &name, kind, extra))
                .unwrap_or_else(|e| panic!("{name}: {}", e.message));
        }
    }
}

fn service_enabled_recipe(dir: &std::path::Path, name: &str, enabled: &str) -> std::path::PathBuf {
    write_recipe(
        dir,
        name,
        &format!(
            "version: 1\nvars:\n  b:\n    value: true\nresources:\n  - id: s\n    type: service\n    with:\n      name: app\n      enabled: {enabled}\n"
        ),
    )
}

#[test]
fn service_enabled_literal_string_is_a_validation_error() {
    // Only a boolean (or an interpolation resolving to one) is accepted when
    // the resource runs; a literal string never is.
    let dir = trusted_root("service-enabled-string");
    for (name, enabled) in [("yes.yaml", "\"yes\""), ("quoted-true.yaml", "\"true\"")] {
        let e = load_model(&service_enabled_recipe(&dir, name, enabled)).expect_err(name);
        assert!(
            e.message.contains("service enabled must be a boolean"),
            "{name}: {}",
            e.message
        );
    }
    for (name, enabled) in [
        ("true.yaml", "true"),
        ("false.yaml", "false"),
        ("interpolated.yaml", "\"{{ vars.b }}\""),
    ] {
        load_model(&service_enabled_recipe(&dir, name, enabled))
            .unwrap_or_else(|e| panic!("{name}: {}", e.message));
    }
}
