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
