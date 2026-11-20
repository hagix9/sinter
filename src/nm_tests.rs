//! Schema, parsers and comparison of `nm_connection` (DESIGN §45).

use super::*;
use crate::value::Value;
use std::collections::BTreeMap;

fn map(pairs: &[(&str, Value)]) -> BTreeMap<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

fn s(x: &str) -> Value {
    Value::Str(x.into())
}

fn l(xs: &[&str]) -> Value {
    Value::List(xs.iter().map(|x| s(x)).collect())
}

fn ip(pairs: &[(&str, Value)]) -> Value {
    Value::Map(map(pairs))
}

fn check(pairs: &[(&str, Value)]) -> Result<Option<NmSpec>> {
    NmSpec::check(&map(pairs), "r", false)
}

fn err(pairs: &[(&str, Value)], want: &str) {
    match check(pairs) {
        Err(e) => assert!(e.message.contains(want), "{want}: {}", e.message),
        Ok(v) => panic!("{want}: accepted {v:?}"),
    }
}

#[test]
fn schema_accepts_the_declared_fields() {
    let spec = check(&[
        ("name", s("lan 1")),
        ("type", s("ethernet")),
        ("ifname", s("eth1")),
        ("autoconnect", Value::Bool(true)),
        (
            "ipv4",
            ip(&[
                ("method", s("manual")),
                ("addresses", l(&["192.0.2.10/24", "192.0.2.11/24"])),
                ("gateway", s("192.0.2.1")),
                ("dns", l(&["192.0.2.53", "198.51.100.53"])),
                ("dns_search", l(&["example.com", "lab.example.net"])),
            ]),
        ),
        (
            "ipv6",
            ip(&[
                ("method", s("manual")),
                ("addresses", l(&["2001:db8::10/64"])),
                ("gateway", s("2001:db8::1")),
                ("dns", l(&["2001:db8::53"])),
            ]),
        ),
        ("active", Value::Bool(false)),
        ("checkpoint_timeout", Value::Int(120)),
    ])
    .unwrap()
    .unwrap();
    assert_eq!(spec.ifname.as_deref(), Some("eth1"));
    assert_eq!(spec.checkpoint_timeout, 120);
    assert_eq!(
        spec.ipv4.dns.as_deref().unwrap(),
        ["192.0.2.53", "198.51.100.53"]
    );
    let d = check(&[("name", s("x"))]).unwrap().unwrap();
    assert_eq!(d.checkpoint_timeout, DEFAULT_CHECKPOINT_TIMEOUT);
    assert_eq!(d.state, NmState::Present);
}

#[test]
fn schema_refuses_bad_values() {
    err(&[], "requires name");
    err(&[("name", s(""))], "name must be");
    err(&[("name", s("-x"))], "name must be");
    err(&[("name", s(&"a".repeat(65)))], "name must be");
    err(&[("name", s("a\tb"))], "name must be");
    err(&[("name", s(" a"))], "name must be");
    err(&[("name", s("{{ vars.n }}"))], "static");
    err(
        &[("name", s("x")), ("type", s("wifi"))],
        "type must be ethernet",
    );
    err(
        &[("name", s("x")), ("type", s("vlan"))],
        "type must be ethernet",
    );
    err(&[("name", s("x")), ("ifname", s("eth0:1"))], "ifname");
    err(
        &[("name", s("x")), ("ifname", s("a234567890abcdef"))],
        "ifname",
    );
    err(&[("name", s("x")), ("autoconnect", s("yes"))], "boolean");
    err(
        &[("name", s("x")), ("checkpoint_timeout", Value::Int(29))],
        "30 to 600",
    );
    err(
        &[("name", s("x")), ("checkpoint_timeout", Value::Int(601))],
        "30 to 600",
    );
    err(
        &[("name", s("x")), ("password", s("x"))],
        "unknown field password",
    );
    err(&[("name", s("x")), ("802-1x", s("x"))], "unknown field");
    err(&[("name", s("x")), ("wifi", s("x"))], "unknown field");
    err(
        &[
            ("name", s("x")),
            ("ipv4", ip(&[("dhcp_client_id", s("a"))])),
        ],
        "unknown field ipv4.dhcp_client_id",
    );
    err(
        &[
            ("name", s("x")),
            ("ipv6", ip(&[("dns_search", l(&["a.b"]))])),
        ],
        "unknown field ipv6.dns_search",
    );
    err(
        &[("name", s("x")), ("ipv4", ip(&[("method", s("shared"))]))],
        "ipv4.method",
    );
    err(
        &[("name", s("x")), ("ipv6", ip(&[("method", s("dhcp"))]))],
        "ipv6.method",
    );
}

#[test]
fn schema_ipv4_ipv6_and_dns_names() {
    let m = |fam: &str, f: &str, v: Value| {
        check(&[
            ("name", s("x")),
            (
                fam,
                ip(&[
                    ("method", s("manual")),
                    ("addresses", l(&["192.0.2.1/24"])),
                    (f, v),
                ]),
            ),
        ])
    };
    assert!(m("ipv4", "dns", l(&["192.0.2.53"])).is_ok());
    assert!(
        m("ipv4", "dns", l(&["192.000.2.53"])).is_err(),
        "leading zeros"
    );
    assert!(m("ipv4", "dns", l(&["2001:db8::53"])).is_err(), "family");
    assert!(m("ipv4", "gateway", s("192.0.2.1")).is_ok());
    assert!(m("ipv4", "gateway", s("192.0.2.1/24")).is_err());
    assert!(m("ipv4", "gateway", s("")).is_ok(), "empty: no gateway");
    assert!(
        m("ipv4", "dns", l(&["192.0.2.53", "192.0.2.53"])).is_err(),
        "repeat"
    );
    let v6 = |a: &[&str]| {
        check(&[
            ("name", s("x")),
            ("ipv6", ip(&[("method", s("manual")), ("addresses", l(a))])),
        ])
    };
    assert!(v6(&["2001:db8::10/64"]).is_ok());
    assert!(v6(&["2001:DB8::10/64"]).is_err(), "upper case");
    assert!(v6(&["2001:db8:0::10/64"]).is_err(), "not RFC 5952");
    assert!(v6(&["192.0.2.10/24"]).is_err(), "family");
    assert!(v6(&["2001:db8::10"]).is_err(), "prefix");
    for ok in [
        "example.com",
        "a-b.example",
        "x1",
        &format!("{}.com", "a".repeat(63)),
    ] {
        assert!(valid_dns_name(ok), "{ok}");
    }
    for bad in [
        "",
        "Example.com",
        "-a.com",
        "a-.com",
        "a..com",
        "a.com.",
        "a_b.com",
        &format!("{}.com", "a".repeat(64)),
        &vec!["abcdefghi"; 26].join("."),
    ] {
        assert!(!valid_dns_name(bad), "{bad}");
    }
}

#[test]
fn schema_consistency_rules() {
    err(
        &[("name", s("x")), ("ipv4", ip(&[("method", s("manual"))]))],
        "needs at least one address",
    );
    err(
        &[
            (
                "ipv4",
                ip(&[("method", s("auto")), ("addresses", l(&["192.0.2.1/24"]))]),
            ),
            ("name", s("x")),
        ],
        "only with method manual",
    );
    err(
        &[
            ("name", s("x")),
            (
                "ipv4",
                ip(&[("method", s("auto")), ("gateway", s("192.0.2.1"))]),
            ),
        ],
        "only with method manual",
    );
    err(
        &[
            ("name", s("x")),
            (
                "ipv6",
                ip(&[
                    ("method", s("ignore")),
                    ("addresses", l(&["2001:db8::1/64"])),
                ]),
            ),
        ],
        "only with method manual",
    );
    err(
        &[
            ("name", s("x")),
            ("state", s("absent")),
            ("ifname", s("eth1")),
        ],
        "allows only name",
    );
    err(
        &[
            ("name", s("x")),
            ("state", s("absent")),
            ("active", Value::Bool(false)),
        ],
        "allows only name",
    );
    assert!(check(&[("name", s("x")), ("state", s("absent"))])
        .unwrap()
        .is_some());
    // Validation leaves interpolated values for later.
    let v = NmSpec::check(
        &map(&[("name", s("x")), ("ifname", s("{{ vars.nic }}"))]),
        "r",
        true,
    )
    .unwrap();
    assert!(v.is_none());
}

// ---------------------------------------------------------------------------
// parsers
// ---------------------------------------------------------------------------

#[test]
fn terse_escapes_are_strict() {
    assert_eq!(split_terse("a:b").unwrap(), ["a", "b"]);
    assert_eq!(split_terse(r"a\:b:c").unwrap(), ["a:b", "c"]);
    assert_eq!(split_terse(r"a\\:b").unwrap(), [r"a\", "b"]);
    assert_eq!(split_terse("a::").unwrap(), ["a", "", ""]);
    assert!(split_terse(r"a\b").is_err());
    assert!(split_terse("a\\").is_err());
    assert!(split_terse("a\tb").is_err());
    assert_eq!(escape_terse(r"a:b\c"), r"a\:b\\c");
    for x in ["lan:1", r"x\y", "plain", "a:b:c"] {
        assert_eq!(split_terse(&escape_terse(x)).unwrap(), [x]);
    }
}

const U1: &str = "00000000-0000-4000-8000-000000000001";
const U2: &str = "00000000-0000-4000-8000-000000000002";

#[test]
fn profile_list_and_active_list() {
    let t = format!("lan\\:1:{U1}:802-3-ethernet\nwifi:{U2}:802-11-wireless\n");
    let v = parse_list(&t).unwrap();
    assert_eq!(v[0].name, "lan:1");
    assert_eq!(v[1].type_, "802-11-wireless");
    assert!(parse_list("").unwrap().is_empty());
    assert!(parse_list(&format!("a:{U1}\n")).is_err(), "missing field");
    assert!(parse_list(&format!("a:{U1}:t:x\n")).is_err(), "extra field");
    assert!(parse_list("a:not-a-uuid:t\n").is_err());
    assert!(
        parse_list(&format!("a:{U1}:t\nb:{U1}:t\n")).is_err(),
        "uuid twice"
    );
    assert!(
        parse_list(&format!("a:{U1}:t\n\nb:{U2}:t\n")).is_err(),
        "blank line"
    );
    let a = parse_active(&format!("lan:{U1}:eth1:activated\n")).unwrap();
    assert_eq!(a[0].device, "eth1");
    assert!(parse_active(&format!("lan:{U1}:eth1:weird\n")).is_err());
    assert!(parse_active(&format!("lan:{U1}:eth1\n")).is_err());
    assert!(parse_active(&format!("lan:{U1}:-x:activated\n")).is_err());
}

pub(crate) fn profile_text(over: &[(&str, &str)]) -> String {
    let mut m: BTreeMap<&str, String> =
        PROFILE_FIELDS.iter().map(|f| (*f, String::new())).collect();
    m.insert("connection.id", "lan".into());
    m.insert("connection.uuid", U1.into());
    m.insert("connection.type", ETHERNET_SETTING.into());
    m.insert("connection.interface-name", "eth1".into());
    m.insert("connection.autoconnect", "yes".into());
    m.insert("ipv4.method", "auto".into());
    m.insert("ipv6.method", "auto".into());
    for (k, v) in over {
        m.insert(k, v.to_string());
    }
    PROFILE_FIELDS
        .iter()
        .map(|f| format!("{}:{}\n", f, escape_terse(&m[f])))
        .collect()
}

#[test]
fn profile_parser_is_strict_and_normalizes() {
    let p = parse_profile(&profile_text(&[
        ("ipv4.method", "manual"),
        ("ipv4.addresses", "192.0.2.10/24, 192.0.2.11/24"),
        ("ipv4.dns", "192.0.2.53,198.51.100.53"),
        ("ipv6.method", "manual"),
        ("ipv6.addresses", "2001:0db8::10/64"),
        ("ipv6.gateway", "2001:db8:0:0::1"),
    ]))
    .unwrap();
    assert_eq!(p.ipv4.addresses, ["192.0.2.10/24", "192.0.2.11/24"]);
    assert_eq!(p.ipv4.dns, ["192.0.2.53", "198.51.100.53"], "order kept");
    assert_eq!(p.ipv6.addresses, ["2001:db8::10/64"], "canonical");
    assert_eq!(p.ipv6.gateway, "2001:db8::1");
    assert_eq!(p.ifname.as_deref(), Some("eth1"));
    // Empty is unset.
    let q = parse_profile(&profile_text(&[("connection.interface-name", "")])).unwrap();
    assert_eq!(q.ifname, None);
    // Missing, repeated and unknown fields; unknown values.
    let t = profile_text(&[]);
    let without: String = t
        .lines()
        .filter(|l| !l.starts_with("ipv4.dns:"))
        .map(|l| format!("{l}\n"))
        .collect();
    assert!(parse_profile(&without).unwrap_err().contains("missing"));
    assert!(parse_profile(&format!("{t}ipv4.dns:\n"))
        .unwrap_err()
        .contains("more than once"));
    assert!(parse_profile(&format!("{t}802-1x.password:x\n"))
        .unwrap_err()
        .contains("unexpected field"));
    assert!(parse_profile(&profile_text(&[("connection.autoconnect", "maybe")])).is_err());
    assert!(parse_profile(&profile_text(&[("ipv4.method", "bogus")])).is_err());
    assert!(parse_profile(&profile_text(&[("ipv4.addresses", "192.0.2.10")])).is_err());
    assert!(parse_profile(&profile_text(&[("ipv4.addresses", "2001:db8::1/64")])).is_err());
    assert!(
        parse_profile(&profile_text(&[("ipv4.gateway", "--")])).is_err(),
        "-- is not assumed to mean unset"
    );
    assert!(parse_profile(&profile_text(&[("ipv4.addresses", "192.0.2.10/024")])).is_err());
    assert!(parse_profile(&profile_text(&[("connection.uuid", "x")])).is_err());
    assert!(parse_profile("connection.id\n").is_err());
    // An unescaped colon in a value is not what `-e yes` prints.
    assert!(
        parse_profile(&profile_text(&[]).replace("ipv4.dns:\n", "ipv4.dns:192.0.2.1:x\n")).is_err()
    );
    assert!(parse_profile(&profile_text(&[("ipv4.dns-search", "--")])).is_err());
    assert_eq!(
        parse_profile(&profile_text(&[("connection.master", "br0")]))
            .unwrap()
            .master,
        "br0"
    );
}

#[test]
fn busctl_replies() {
    assert_eq!(
        parse_object_reply(
            "o \"/org/freedesktop/NetworkManager/Checkpoint/3\"\n",
            valid_checkpoint_path
        )
        .unwrap(),
        "/org/freedesktop/NetworkManager/Checkpoint/3"
    );
    assert!(parse_object_reply(
        "o \"/org/freedesktop/NetworkManager/Devices/3\"\n",
        valid_checkpoint_path
    )
    .is_err());
    assert!(parse_object_reply("s \"x\"\n", valid_device_path).is_err());
    assert!(parse_object_reply(
        "o \"/org/freedesktop/NetworkManager/Devices/\"\n",
        valid_device_path
    )
    .is_err());
    let p = parse_permissions("a{ss} 2 \"a\" \"yes\" \"b\" \"auth\"\n").unwrap();
    assert_eq!(p["b"], "auth");
    assert!(parse_permissions("a{ss} 3 \"a\" \"yes\"\n").is_err());
    assert!(parse_permissions("a{ss} 1 \"a\" \"yes\"\nmore\n").is_err());
    let r = parse_rollback("a{su} 2 \"/org/freedesktop/NetworkManager/Devices/1\" 0 \"/org/freedesktop/NetworkManager/Devices/2\" 1\n").unwrap();
    assert_eq!(r.values().copied().collect::<Vec<_>>(), [0, 1]);
    assert!(parse_rollback("a{su} 1 \"/x\" 0\n").is_err());
    let d1 = "/org/freedesktop/NetworkManager/Devices/1".to_string();
    let d2 = "/org/freedesktop/NetworkManager/Devices/2".to_string();
    let one = format!("a{{su}} 1 \"{d1}\" 0\n");
    assert!(rollback_ok(&one, std::slice::from_ref(&d1)));
    assert!(
        !rollback_ok(&one, &[d1.clone(), d2.clone()]),
        "a device missing"
    );
    assert!(
        !rollback_ok(&format!("a{{su}} 1 \"{d1}\" 1\n"), &[d1]),
        "result 1"
    );
    assert_eq!(
        parse_devices("eth0:ethernet\nbr0:bridge\n").unwrap()["br0"],
        "bridge"
    );
    assert!(parse_devices("eth0\n").is_err());
    assert!(parse_devices("eth0:ethernet\neth0:ethernet\n").is_err());
    assert!(busctl_tokens("o \"a\\\"b\"").unwrap()[1] == "a\"b");
    assert!(busctl_tokens("o \"unterminated").is_err());
    let intro = "NAME TYPE SIGNATURE RESULT/VALUE FLAGS\n.CheckpointCreate method aouu o -\n.CheckpointDestroy method o - -\n.CheckpointRollback method o a{su} -\n";
    assert!(introspection_has_checkpoints(intro));
    assert!(!introspection_has_checkpoints(
        &intro.replace("aouu", "aou")
    ));
    assert!(!introspection_has_checkpoints(
        ".CheckpointCreate method aouu o -\n"
    ));
}

// ---------------------------------------------------------------------------
// comparison
// ---------------------------------------------------------------------------

fn observed(over: &[(&str, &str)], active: Option<&str>) -> Observed {
    Observed {
        profile: Some(parse_profile(&profile_text(over)).unwrap()),
        active_on: active.map(str::to_string),
    }
}

fn spec(pairs: &[(&str, Value)]) -> NmSpec {
    let mut all = vec![("name", s("lan"))];
    all.extend_from_slice(pairs);
    check(&all).unwrap().unwrap()
}

#[test]
fn only_declared_fields_are_compared_and_lists_keep_order() {
    let o = observed(
        &[
            ("ipv4.dns", "192.0.2.53,198.51.100.53"),
            ("ipv4.dns-search", "a.example"),
        ],
        None,
    );
    // Undeclared fields (dns_search, autoconnect) are left alone.
    let st = steps(
        &spec(&[("ipv4", ip(&[("dns", l(&["192.0.2.53", "198.51.100.53"]))]))]),
        &o,
    )
    .unwrap();
    assert!(st.is_empty(), "{st:?}");
    // Same entries, other order: a change.
    let st = steps(
        &spec(&[("ipv4", ip(&[("dns", l(&["198.51.100.53", "192.0.2.53"]))]))]),
        &o,
    )
    .unwrap();
    assert_eq!(
        st.settings,
        [(
            "ipv4.dns".to_string(),
            "198.51.100.53,192.0.2.53".to_string()
        )]
    );
    assert!(!st.up && !st.create);
}

#[test]
fn steps_for_create_delete_and_active() {
    let none = Observed {
        profile: None,
        active_on: None,
    };
    let st = steps(
        &spec(&[("ifname", s("eth1")), ("active", Value::Bool(true))]),
        &none,
    )
    .unwrap();
    assert!(st.create && st.up);
    assert_eq!(
        add_argv(&spec(&[("ifname", s("eth1"))]), &[])[..8],
        [
            "connection",
            "add",
            "type",
            "ethernet",
            "con-name",
            "lan",
            "ifname",
            "eth1"
        ]
    );
    let st = steps(
        &spec(&[("state", s("absent"))]),
        &observed(&[], Some("eth1")),
    )
    .unwrap();
    assert!(st.delete && !st.down);
    assert!(steps(&spec(&[("state", s("absent"))]), &none)
        .unwrap()
        .is_empty());
    let st = steps(
        &spec(&[("active", Value::Bool(false))]),
        &observed(&[], Some("eth1")),
    )
    .unwrap();
    assert!(st.down && st.settings.is_empty());
    let st = steps(
        &spec(&[("active", Value::Bool(true))]),
        &observed(&[], Some("eth1")),
    )
    .unwrap();
    assert!(st.is_empty(), "already active, nothing changed");
    // A changed profile with active: true is activated again.
    let st = steps(
        &spec(&[
            ("active", Value::Bool(true)),
            ("autoconnect", Value::Bool(false)),
        ]),
        &observed(&[], Some("eth1")),
    )
    .unwrap();
    assert!(st.up);
    // Without active, an active profile is changed but not reactivated.
    let st = steps(
        &spec(&[("autoconnect", Value::Bool(false))]),
        &observed(&[], Some("eth1")),
    )
    .unwrap();
    assert!(!st.up && !st.down && !st.settings.is_empty());
    // Another type is never changed into ethernet.
    let o = observed(&[("connection.type", "802-11-wireless")], None);
    assert!(steps(&spec(&[]), &o).unwrap_err().contains("type"));
    // Addresses with a resulting method other than manual.
    let o = observed(&[], None);
    assert!(steps(
        &spec(&[("ipv4", ip(&[("addresses", l(&["192.0.2.9/24"]))]))]),
        &o
    )
    .is_err());
    let o = observed(
        &[
            ("ipv4.method", "manual"),
            ("ipv4.addresses", "192.0.2.8/24"),
        ],
        None,
    );
    let st = steps(
        &spec(&[("ipv4", ip(&[("addresses", l(&["192.0.2.9/24"]))]))]),
        &o,
    )
    .unwrap();
    assert_eq!(st.settings.len(), 1);
}

#[test]
fn argv_is_fixed() {
    assert_eq!(
        list_argv(),
        [
            "-t",
            "-e",
            "yes",
            "-f",
            "NAME,UUID,TYPE",
            "connection",
            "show"
        ]
    );
    assert_eq!(active_argv()[4], "NAME,UUID,DEVICE,STATE");
    assert_eq!(profile_argv(U1)[7..], ["uuid", U1]);
    assert_eq!(
        modify_argv(U1, &[("ipv4.dns".into(), "".into())]),
        ["connection", "modify", "uuid", U1, "ipv4.dns", ""]
    );
    let c = checkpoint_create_argv(&["/org/freedesktop/NetworkManager/Devices/1".into()], 90);
    assert_eq!(
        c[..6],
        [
            "--system",
            "call",
            NM_BUS,
            NM_PATH,
            NM_BUS,
            "CheckpointCreate"
        ]
    );
    assert_eq!(
        c[6..],
        [
            "aouu",
            "1",
            "/org/freedesktop/NetworkManager/Devices/1",
            "90",
            "6"
        ]
    );
}
