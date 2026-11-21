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
    // The measured form: the colons of a value are not escaped.
    PROFILE_FIELDS
        .iter()
        .map(|f| format!("{}:{}\n", f, m[f]))
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
    // A value that is not an address after the first colon.
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
            "2"
        ]
    );
}

// ---------------------------------------------------------------------------
// P8-R2 real-host regressions (F-1, F-2)
// ---------------------------------------------------------------------------

/// `-t -e yes -f <PROFILE_FIELDS> connection show uuid <uuid>` as measured
/// on Rocky 9.8 (NetworkManager 1.54.3) in P8-R2 for the profile Sinter
/// created in B1 (verbatim; Rocky 10.2 / 1.56.0 printed the same lines with
/// another UUID). The colons of the IPv6 value are not escaped.
const MEASURED_B1_PROFILE: &str = "connection.id:sinter-nm-test
connection.uuid:40a2e191-90c9-4ca1-a946-5dad2f5d4d32
connection.type:802-3-ethernet
connection.interface-name:eth1
connection.autoconnect:no
connection.master:
ipv4.method:manual
ipv4.addresses:192.0.2.30/24
ipv4.gateway:
ipv4.dns:
ipv4.dns-search:
ipv6.method:manual
ipv6.addresses:2001:db8::30/64
ipv6.gateway:
ipv6.dns:
";

/// The loopback profile of the same capture (`ipv6.addresses:::1/128`: the
/// value itself starts with colons).
const MEASURED_LO_PROFILE: &str = "connection.id:lo
connection.uuid:908b9032-b925-4c98-bd06-86cd2a6f41c1
connection.type:loopback
connection.interface-name:lo
connection.autoconnect:yes
connection.master:
ipv4.method:manual
ipv4.addresses:127.0.0.1/8
ipv4.gateway:
ipv4.dns:
ipv4.dns-search:
ipv6.method:manual
ipv6.addresses:::1/128
ipv6.gateway:
ipv6.dns:
";

#[test]
fn f2_measured_real_host_profiles_are_read() {
    let p = parse_profile(MEASURED_B1_PROFILE).unwrap();
    assert_eq!(p.id, "sinter-nm-test");
    assert_eq!(p.uuid, "40a2e191-90c9-4ca1-a946-5dad2f5d4d32");
    assert_eq!(p.type_, ETHERNET_SETTING);
    assert_eq!(p.ifname.as_deref(), Some("eth1"));
    assert!(!p.autoconnect);
    assert_eq!(p.ipv4.method, "manual");
    assert_eq!(p.ipv4.addresses, ["192.0.2.30/24"]);
    assert_eq!(p.ipv6.method, "manual");
    assert_eq!(p.ipv6.addresses, ["2001:db8::30/64"]);
    assert_eq!(p.ipv6.gateway, "");
    assert!(p.ipv6.dns.is_empty());
    let lo = parse_profile(MEASURED_LO_PROFILE).unwrap();
    assert_eq!(lo.ipv6.addresses, ["::1/128"]);
    assert_eq!(lo.type_, "loopback");
}

#[test]
fn f2_a_profile_line_is_split_at_its_first_colon_only() {
    let p = parse_profile(&profile_text(&[
        ("connection.id", "db:net"),
        ("ipv6.method", "manual"),
        ("ipv6.addresses", "2001:db8::30/64"),
        ("ipv6.gateway", "2001:db8::1"),
        ("ipv6.dns", "2001:db8::53"),
    ]))
    .unwrap();
    assert_eq!(p.id, "db:net");
    assert_eq!(p.ipv6.addresses, ["2001:db8::30/64"]);
    assert_eq!(p.ipv6.gateway, "2001:db8::1");
    assert_eq!(p.ipv6.dns, ["2001:db8::53"]);
    // Normalized to the canonical text, as before.
    let q = parse_profile(&profile_text(&[
        ("ipv6.method", "manual"),
        ("ipv6.addresses", "2001:0db8:0:0::30/64"),
    ]))
    .unwrap();
    assert_eq!(q.ipv6.addresses, ["2001:db8::30/64"]);
}

#[test]
fn f2_unmeasured_or_malformed_profile_lines_fail_closed() {
    let ok = profile_text(&[
        ("ipv6.method", "manual"),
        ("ipv6.addresses", "2001:db8::30/64"),
    ]);
    assert!(parse_profile(&ok).is_ok());
    let with = |from: &str, to: &str| {
        assert_eq!(ok.matches(from).count(), 1, "{from}");
        ok.replacen(from, to, 1)
    };
    // The escaping of a backslash (and whether `\:` would ever appear) is not
    // measured: any backslash in a value is refused, not interpreted.
    for bad in [
        r"ipv6.addresses:2001\:db8\:\:30/64",
        r"ipv6.addresses:2001:db8::30/64\\",
    ] {
        let t = with("ipv6.addresses:2001:db8::30/64", bad);
        assert!(
            parse_profile(&t).unwrap_err().contains("backslash"),
            "{bad}"
        );
    }
    assert!(
        parse_profile(&with("connection.id:lan", r"connection.id:a\b"))
            .unwrap_err()
            .contains("backslash")
    );
    // Control characters (tab, carriage return, DEL) in a value.
    for c in ['\t', '\r', '\u{7f}'] {
        let t = with("connection.id:lan", &format!("connection.id:la{c}n"));
        assert!(parse_profile(&t).unwrap_err().contains("control"), "{c:?}");
    }
    // A line without a field name, an empty, unknown, case-changed or padded
    // field name.
    for bad in [
        "connection.id lan",
        ":lan",
        "Connection.id:lan",
        "connection.id :lan",
        " connection.id:lan",
        "connection.name:lan",
    ] {
        let t = with("connection.id:lan", bad);
        assert!(parse_profile(&t).is_err(), "{bad}");
    }
    // A repeated field (two profiles) even when the values differ only after
    // the first colon.
    let t = format!("{ok}ipv6.addresses:2001:db8::31/64\n");
    assert!(parse_profile(&t).unwrap_err().contains("more than once"));
    // Truncated output: a missing last field, a cut address or prefix.
    let cut: String = ok
        .lines()
        .take(PROFILE_FIELDS.len() - 1)
        .map(|l| format!("{l}\n"))
        .collect();
    assert!(parse_profile(&cut).unwrap_err().contains("missing"));
    for bad in [
        "ipv6.addresses:2001:db8::30/",
        "ipv6.addresses:2001:db8::30",
        "ipv6.addresses:2001:db8:",
        "ipv6.addresses:2001:db8::30/129",
        "ipv6.addresses:192.0.2.30/24",
    ] {
        let t = with("ipv6.addresses:2001:db8::30/64", bad);
        assert!(parse_profile(&t).is_err(), "{bad}");
    }
    // Multiple values: only the comma form is read; another separator is not
    // guessed (each entry must be one address).
    for bad in [
        "ipv4.dns:192.0.2.53;198.51.100.53",
        "ipv4.dns:192.0.2.53 198.51.100.53",
        "ipv4.dns:192.0.2.53,,198.51.100.53",
        "ipv4.dns:192.0.2.53,",
    ] {
        let t = with("ipv4.dns:\n", &format!("{bad}\n"));
        assert!(parse_profile(&t).is_err(), "{bad}");
    }
    for bad in [
        "ipv6.dns:2001:db8::53;2001:db8::54",
        "ipv6.dns:2001:db8::53 2001:db8::54",
    ] {
        let t = with("ipv6.dns:\n", &format!("{bad}\n"));
        assert!(parse_profile(&t).is_err(), "{bad}");
    }
    // Not UTF-8 never reaches the parser: the engine refuses it
    // (`stdout_ok`), tested with the engine.
}

#[test]
fn f1_checkpoint_flags_are_delete_new_connections_only() {
    assert_eq!(CHECKPOINT_FLAGS, 0x2);
    assert_eq!(
        CHECKPOINT_FLAGS & 0x4,
        0,
        "never DISCONNECT_NEW_DEVICES with a device list"
    );
    assert_eq!(CHECKPOINT_FLAGS & 0x1, 0, "never DESTROY_ALL");
    assert_eq!(CHECKPOINT_FLAGS & 0x8, 0, "never ALLOW_OVERLAPPING");
    let devs = vec!["/org/freedesktop/NetworkManager/Devices/2".to_string()];
    let a = checkpoint_create_argv(&devs, 30);
    assert_eq!(
        a[6..],
        [
            "aouu",
            "1",
            "/org/freedesktop/NetworkManager/Devices/2",
            "30",
            "2"
        ]
    );
}

#[test]
fn f1_fake_networkmanager_models_the_measured_flag_restriction() {
    use crate::executor::Completion;
    use crate::fakesys::FakeNm;
    let dev = "/org/freedesktop/NetworkManager/Devices/1".to_string();
    let create = |f: &mut FakeNm, devs: &[String], flags: &str| {
        let mut a = vec!["aouu".to_string(), devs.len().to_string()];
        a.extend(devs.iter().cloned());
        a.push("60".into());
        a.push(flags.into());
        f.run(BUSCTL, &call_argv("CheckpointCreate", &a))
    };
    // flags 6 with a device: refused as measured, no checkpoint.
    let mut f = FakeNm::default();
    let o = create(&mut f, std::slice::from_ref(&dev), "6");
    assert_eq!(o.completion, Completion::Exited(1));
    assert!(String::from_utf8_lossy(&o.stderr)
        .contains("the DISCONNECT_NEW_DEVICES flag can only be used with an empty device list"));
    assert!(f.checkpoint.is_none());
    // flags 6 with no device: NetworkManager's rule allows it (Sinter never
    // sends it: an empty list would cover every device).
    let mut f = FakeNm::default();
    assert_eq!(create(&mut f, &[], "6").completion, Completion::Exited(0));
    // flags 2 with a device: accepted.
    let mut f = FakeNm::default();
    assert_eq!(
        create(
            &mut f,
            std::slice::from_ref(&dev),
            &CHECKPOINT_FLAGS.to_string()
        )
        .completion,
        Completion::Exited(0)
    );
    assert_eq!(f.checkpoint.as_ref().unwrap().1, std::slice::from_ref(&dev));
    // A malformed flag or timeout is refused.
    let mut f = FakeNm::default();
    assert_eq!(
        create(&mut f, std::slice::from_ref(&dev), "x").completion,
        Completion::Exited(1)
    );
}

#[test]
fn f1_fake_rollback_removes_new_profiles_only_with_delete_new_connections() {
    use crate::fakesys::FakeNm;
    let dev = "/org/freedesktop/NetworkManager/Devices/2".to_string();
    for (flags, kept) in [(CHECKPOINT_FLAGS, false), (0u32, true)] {
        let mut f = FakeNm::default();
        let mut a = vec!["aouu".to_string(), "1".into(), dev.clone(), "60".into()];
        a.push(flags.to_string());
        let o = f.run(BUSCTL, &call_argv("CheckpointCreate", &a));
        let cp =
            parse_object_reply(&String::from_utf8_lossy(&o.stdout), valid_checkpoint_path).unwrap();
        f.add(FakeNm::profile("new", "eth1"));
        f.run(BUSCTL, &call_argv("CheckpointRollback", &["o".into(), cp]));
        assert_eq!(f.find("new").is_some(), kept, "flags {flags}");
    }
}

#[test]
fn f2_a_name_with_a_backslash_is_refused_at_validation() {
    // The settings output refuses a backslash (not measured), so a profile
    // created with one could never be verified: refused before contact.
    assert!(!valid_name(r"a\b"));
    assert!(valid_name("db:net"));
    let mut m = BTreeMap::new();
    m.insert("name".to_string(), Value::Str(r"lan\1".into()));
    let e = NmSpec::check(&m, "r", false).unwrap_err();
    assert!(e.message.contains("without a backslash"), "{}", e.message);
}
