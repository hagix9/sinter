//! Unit tests of the pure `file_merge` edit and of the field check.

use super::*;

const K1: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsyntheticSYNTHETICsyntheticSYNTHETICsynthetic01 one@example.invalid";
const K2: &str = "from=\"192.0.2.10\",no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsyntheticSYNTHETICsyntheticSYNTHETICsynthetic02 two@example.invalid";
const K3: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsyntheticSYNTHETICsyntheticSYNTHETICsynthetic00 synthetic@example.invalid";

fn line(l: &str, state: MergeState) -> MergeSpec {
    MergeSpec {
        state,
        create: false,
        edit: Edit::Line {
            line: l.to_string(),
        },
    }
}

fn block(marker: &str, prefix: &str, content: Option<&str>, state: MergeState) -> MergeSpec {
    MergeSpec {
        state,
        create: false,
        edit: Edit::Block {
            marker: marker.to_string(),
            prefix: prefix.to_string(),
            content: content.map(content_lines),
        },
    }
}

fn kv(key: &str, sep: &str, value: Option<&str>, state: MergeState) -> MergeSpec {
    MergeSpec {
        state,
        create: false,
        edit: Edit::KeyValue {
            key: key.to_string(),
            separator: sep.to_string(),
            value: value.map(str::to_string),
        },
    }
}

/// The new file as text, or `None` when nothing changes.
fn edit(current: &str, spec: &MergeSpec) -> Option<String> {
    let out = apply_edit(Some(current.as_bytes()), spec).expect("edit refused");
    assert_eq!(out.new_content.is_some(), out.drift.is_some());
    out.new_content.map(|b| String::from_utf8(b).unwrap())
}

fn refused(current: &str, spec: &MergeSpec) -> String {
    apply_edit(Some(current.as_bytes()), spec)
        .expect_err("edit accepted")
        .0
}

use MergeState::{Absent, Present};

// --------------------------------------------------------------------- line

#[test]
fn line_is_appended_and_every_other_byte_is_kept() {
    let cur = format!("{K1}\n{K2}\n");
    assert_eq!(
        edit(&cur, &line(K3, Present)).unwrap(),
        format!("{K1}\n{K2}\n{K3}\n")
    );
}

#[test]
fn line_already_present_changes_nothing_even_when_it_is_there_twice() {
    let cur = format!("{K1}\n{K3}\n{K2}\n{K3}\n");
    assert_eq!(edit(&cur, &line(K3, Present)), None);
    assert_eq!(edit(K3, &line(K3, Present)), None);
}

#[test]
fn line_appended_to_a_file_without_final_line_feed_gets_one_first() {
    assert_eq!(edit("a\nb", &line("c", Present)).unwrap(), "a\nb\nc\n");
    assert_eq!(edit("", &line("c", Present)).unwrap(), "c\n");
}

#[test]
fn line_identity_is_the_exact_whole_line() {
    // A prefix, another comment, other options, other spacing: other lines.
    for other in [
        format!("{K3} "),
        format!(" {K3}"),
        K3.replace("synthetic@example.invalid", "other@example.invalid"),
        format!("no-pty {K3}"),
        K3[..K3.len() - 1].to_string(),
    ] {
        let cur = format!("{other}\n");
        assert_eq!(
            edit(&cur, &line(K3, Present)).unwrap(),
            format!("{other}\n{K3}\n")
        );
        assert_eq!(edit(&cur, &line(K3, Absent)), None);
    }
}

#[test]
fn line_absent_removes_every_exact_occurrence_and_nothing_else() {
    let cur = format!("{K1}\n{K3}\n{K2}\n{K3}\n");
    assert_eq!(
        edit(&cur, &line(K3, Absent)).unwrap(),
        format!("{K1}\n{K2}\n")
    );
    // The last line without a terminator.
    assert_eq!(
        edit(&format!("{K1}\n{K3}"), &line(K3, Absent)).unwrap(),
        format!("{K1}\n")
    );
    // A kept last line keeps its missing terminator.
    assert_eq!(
        edit(&format!("{K3}\n{K1}"), &line(K3, Absent)).unwrap(),
        K1.to_string()
    );
    assert_eq!(edit(&format!("{K1}\n"), &line(K3, Absent)), None);
}

#[test]
fn absent_file_is_new_content_for_present_and_nothing_for_absent() {
    let out = apply_edit(None, &line("x", Present)).unwrap();
    assert_eq!(out.new_content.as_deref(), Some(&b"x\n"[..]));
    assert_eq!(
        apply_edit(None, &line("x", Absent)).unwrap().new_content,
        None
    );
    let out = apply_edit(None, &block("m", "#", Some("a\n"), Present)).unwrap();
    assert_eq!(
        out.new_content.as_deref(),
        Some(&b"# BEGIN SINTER MANAGED BLOCK m\na\n# END SINTER MANAGED BLOCK m\n"[..])
    );
    let out = apply_edit(None, &kv("k", "=", Some("v"), Present)).unwrap();
    assert_eq!(out.new_content.as_deref(), Some(&b"k=v\n"[..]));
}

// --------------------------------------------------------------- text rules

#[test]
fn crlf_non_utf8_nul_and_oversize_files_are_refused_by_every_merge() {
    let specs = [
        line("x", Present),
        line("x", Absent),
        block("m", "#", Some("a"), Present),
        kv("k", "=", Some("v"), Present),
    ];
    for spec in &specs {
        for (bytes, want) in [
            (&b"a\r\nb\r\n"[..], "carriage return"),
            (&b"a\xff\n"[..], "UTF-8"),
            (&b"a\0b\n"[..], "NUL"),
        ] {
            let e = apply_edit(Some(bytes), spec).unwrap_err().0;
            assert!(e.contains(want), "{e}");
        }
        let big = vec![b'a'; MAX_BYTES + 1];
        let e = apply_edit(Some(&big), spec).unwrap_err().0;
        assert!(e.contains("larger than"), "{e}");
    }
}

#[test]
fn a_result_over_the_limit_is_refused() {
    let mut cur = vec![b'a'; MAX_BYTES - 1];
    cur.push(b'\n');
    let e = apply_edit(Some(&cur), &line("x", Present)).unwrap_err().0;
    assert!(e.contains("would be larger"), "{e}");
    // Exactly at the limit, nothing to change: accepted.
    assert_eq!(
        apply_edit(Some(&cur), &line("x", Absent))
            .unwrap()
            .new_content,
        None
    );
}

// -------------------------------------------------------------------- block

const B: &str = "# BEGIN SINTER MANAGED BLOCK hosts";
const E: &str = "# END SINTER MANAGED BLOCK hosts";

#[test]
fn block_is_appended_when_absent() {
    let spec = block(
        "hosts",
        "#",
        Some("192.0.2.10 a.example.invalid\n192.0.2.11 b.example.invalid\n"),
        Present,
    );
    assert_eq!(
        edit("127.0.0.1 localhost", &spec).unwrap(),
        format!("127.0.0.1 localhost\n{B}\n192.0.2.10 a.example.invalid\n192.0.2.11 b.example.invalid\n{E}\n")
    );
}

#[test]
fn block_content_with_and_without_final_line_feed_is_the_same_block() {
    let cur = format!("x\n{B}\na\nb\n{E}\ny\n");
    assert_eq!(
        edit(&cur, &block("hosts", "#", Some("a\nb\n"), Present)),
        None
    );
    assert_eq!(
        edit(&cur, &block("hosts", "#", Some("a\nb"), Present)),
        None
    );
    // An explicit empty last line is content.
    assert_eq!(
        edit(&cur, &block("hosts", "#", Some("a\nb\n\n"), Present)).unwrap(),
        format!("x\n{B}\na\nb\n\n{E}\ny\n")
    );
}

#[test]
fn block_replaces_only_the_lines_between_its_markers() {
    let cur = format!("top\n{B}\nold1\nold2\nold3\n{E}\nbottom");
    assert_eq!(
        edit(&cur, &block("hosts", "#", Some("new"), Present)).unwrap(),
        format!("top\n{B}\nnew\n{E}\nbottom")
    );
    // An empty content keeps both marker lines.
    assert_eq!(
        edit(&cur, &block("hosts", "#", Some(""), Present)).unwrap(),
        format!("top\n{B}\n{E}\nbottom")
    );
    // The END line is the last line and has no terminator.
    let cur = format!("top\n{B}\nold\n{E}");
    assert_eq!(
        edit(&cur, &block("hosts", "#", Some("new"), Present)).unwrap(),
        format!("top\n{B}\nnew\n{E}")
    );
}

#[test]
fn block_absent_removes_the_block_with_both_marker_lines() {
    let cur = format!("top\n{B}\nold\n{E}\nbottom\n");
    assert_eq!(
        edit(&cur, &block("hosts", "#", None, Absent)).unwrap(),
        "top\nbottom\n"
    );
    assert_eq!(
        edit("top\nbottom\n", &block("hosts", "#", None, Absent)),
        None
    );
    let cur = format!("top\n{B}\nold\n{E}");
    assert_eq!(
        edit(&cur, &block("hosts", "#", None, Absent)).unwrap(),
        "top\n"
    );
}

#[test]
fn blocks_of_other_markers_are_unmanaged_content() {
    let other = "# BEGIN SINTER MANAGED BLOCK other\nkeep\n# END SINTER MANAGED BLOCK other\n";
    let cur = format!("{other}{B}\nold\n{E}\n");
    assert_eq!(
        edit(&cur, &block("hosts", "#", Some("new"), Present)).unwrap(),
        format!("{other}{B}\nnew\n{E}\n")
    );
    assert_eq!(
        edit(other, &block("hosts", "#", Some("new"), Present)).unwrap(),
        format!("{other}{B}\nnew\n{E}\n")
    );
    // Another comment prefix of another block is fine too.
    let semi = "; BEGIN SINTER MANAGED BLOCK other\nkeep\n; END SINTER MANAGED BLOCK other\n";
    assert_eq!(edit(semi, &block("hosts", "#", None, Absent)), None);
}

#[test]
fn every_comment_prefix_writes_and_finds_its_own_marker_lines() {
    for p in COMMENT_PREFIXES {
        let spec = block("m.1_a-b", p, Some("x"), Present);
        let made = edit("", &spec).unwrap();
        assert_eq!(
            made,
            format!(
                "{p} BEGIN SINTER MANAGED BLOCK m.1_a-b\nx\n{p} END SINTER MANAGED BLOCK m.1_a-b\n"
            )
        );
        assert_eq!(edit(&made, &spec), None, "{p}");
        assert_eq!(edit(&made, &block("m.1_a-b", p, None, Absent)).unwrap(), "");
    }
}

#[test]
fn damaged_block_markers_are_refused_for_present_and_absent() {
    let cases: Vec<(String, &str)> = vec![
        (format!("{B}\na\n{B}\nb\n{E}\n"), "second BEGIN"),
        (format!("{B}\na\n"), "without an END"),
        (format!("{E}\n"), "without a BEGIN"),
        (format!("{E}\na\n{B}\n"), "without a BEGIN"),
        (format!("{B}\na\n{E}\n{E}\n"), "second END"),
        (format!("{B}\na\n{E}\n{B}\nb\n{E}\n"), "second BEGIN"),
        (format!("{B}\n{B}\na\n{E}\n{E}\n"), "second BEGIN"),
        (
            format!(
                "{B}\n# BEGIN SINTER MANAGED BLOCK other\n{E}\n# END SINTER MANAGED BLOCK other\n"
            ),
            "overlap",
        ),
        (
            "; BEGIN SINTER MANAGED BLOCK hosts\na\n; END SINTER MANAGED BLOCK hosts\n".to_string(),
            "comment prefix",
        ),
        (format!("{B} \na\n{E}\n"), "not a well-formed"),
        (format!(" {B}\na\n{E}\n"), "not a well-formed"),
        (
            "# BEGIN SINTER MANAGED BLOCK\n".to_string(),
            "not a well-formed",
        ),
        (
            "#BEGIN SINTER MANAGED BLOCK hosts\n".to_string(),
            "not a well-formed",
        ),
        (
            "# END SINTER MANAGED BLOCK bad name\n".to_string(),
            "not a well-formed",
        ),
    ];
    for (cur, want) in cases {
        for spec in [
            block("hosts", "#", Some("new"), Present),
            block("hosts", "#", None, Absent),
        ] {
            let e = refused(&cur, &spec);
            assert!(e.contains(want), "{cur:?}: {e}");
        }
    }
}

// ---------------------------------------------------------------- key_value

#[test]
fn key_value_appends_a_missing_key_with_the_declared_separator() {
    for (sep, want) in [
        ("=", "k=v"),
        (" = ", "k = v"),
        (":", "k:v"),
        (": ", "k: v"),
        (" ", "k v"),
    ] {
        assert_eq!(
            edit("other=1", &kv("k", sep, Some("v"), Present)).unwrap(),
            format!("other=1\n{want}\n")
        );
    }
}

#[test]
fn key_value_written_lines_are_read_back_as_unchanged() {
    for sep in SEPARATORS {
        for value in ["v", "", "a b", "x=y", "a:b", "#not a comment", "[x]y"] {
            let spec = kv("some.key-1_x", sep, Some(value), Present);
            let made = edit("", &spec).unwrap();
            assert_eq!(edit(&made, &spec), None, "{sep:?} {value:?}: {made:?}");
            assert_eq!(
                edit(&made, &kv("some.key-1_x", sep, None, Absent)).unwrap(),
                "",
                "{sep:?} {value:?}"
            );
        }
    }
}

#[test]
fn key_value_same_value_with_other_spacing_is_not_rewritten() {
    for cur in ["k=v\n", "k = v\n", "k\t=\tv  \n", "k= v", "k =v\n"] {
        assert_eq!(
            edit(cur, &kv("k", "=", Some("v"), Present)),
            None,
            "{cur:?}"
        );
        assert_eq!(edit(cur, &kv("k", " = ", Some("v"), Present)), None);
    }
    for cur in ["k v\n", "k\tv\n", "k   v  \n"] {
        assert_eq!(
            edit(cur, &kv("k", " ", Some("v"), Present)),
            None,
            "{cur:?}"
        );
    }
    assert_eq!(edit("k:v\n", &kv("k", ": ", Some("v"), Present)), None);
}

#[test]
fn key_value_replaces_only_the_one_line_whose_value_differs() {
    let cur = "# k=comment\na=1\nk = old  \nb=2\n";
    assert_eq!(
        edit(cur, &kv("k", "=", Some("new"), Present)).unwrap(),
        "# k=comment\na=1\nk=new\nb=2\n"
    );
    // The last line keeps its missing terminator.
    assert_eq!(
        edit("a=1\nk=old", &kv("k", " = ", Some("new"), Present)).unwrap(),
        "a=1\nk = new"
    );
    let out = apply_edit(Some(b"k=old\n"), &kv("k", "=", Some("new"), Present)).unwrap();
    let d = out.drift.unwrap();
    assert_eq!(
        (d.dimension, d.observed.as_str(), d.desired.as_str()),
        ("value", "old", "new")
    );
}

#[test]
fn key_value_absent_removes_the_single_line() {
    assert_eq!(
        edit("a=1\nk=v\nb=2\n", &kv("k", "=", None, Absent)).unwrap(),
        "a=1\nb=2\n"
    );
    assert_eq!(edit("a=1\nb=2\n", &kv("k", "=", None, Absent)), None);
}

#[test]
fn key_value_comment_lines_and_longer_keys_never_match() {
    let cur = "#k=1\n ; k=2\nkey=3\nk.sub=4\nk-x=5\nxk=6\n";
    assert_eq!(
        edit(cur, &kv("k", "=", Some("v"), Present)).unwrap(),
        format!("{cur}k=v\n")
    );
    assert_eq!(edit(cur, &kv("k", "=", None, Absent)), None);
}

#[test]
fn key_value_duplicate_keys_are_refused() {
    for spec in [kv("k", "=", Some("v"), Present), kv("k", "=", None, Absent)] {
        let e = refused("k=1\na=2\nk = 1\n", &spec);
        assert!(e.contains("appears 2 times"), "{e}");
        assert!(e.contains("does not guess"), "{e}");
    }
    let e = refused("k 1\nk 2\nk\n", &kv("k", " ", Some("v"), Present));
    assert!(e.contains("appears 3 times"), "{e}");
}

#[test]
fn key_value_a_line_with_another_separator_is_refused() {
    for (cur, sep) in [
        ("k: v\n", "="),
        ("k v\n", "="),
        ("k\n", "="),
        ("k=v\n", ":"),
        ("k = v\n", " "),
        ("k: v\n", " "),
    ] {
        for spec in [kv("k", sep, Some("v"), Present), kv("k", sep, None, Absent)] {
            let e = refused(cur, &spec);
            assert!(e.contains("another separator"), "{cur:?} {sep:?}: {e}");
        }
    }
}

#[test]
fn key_value_refuses_a_file_with_a_section_header() {
    for cur in ["[main]\nk=v\n", "k=v\n  [other]  \n", "[]\n"] {
        for spec in [kv("k", "=", Some("v"), Present), kv("k", "=", None, Absent)] {
            let e = refused(cur, &spec);
            assert!(e.contains("section header"), "{e}");
        }
    }
    // Not a header: a comment, or text around the brackets.
    assert_eq!(
        edit("#[main]\nx=[1]\n", &kv("k", "=", Some("v"), Present)).unwrap(),
        "#[main]\nx=[1]\nk=v\n"
    );
    // The other merges do not care about sections.
    assert_eq!(
        edit("[main]\n", &line("x", Present)).unwrap(),
        "[main]\nx\n"
    );
}

#[test]
fn refusals_never_carry_file_content_or_declared_values() {
    let secret = "s3cr3t-synthetic-value";
    let cur =
        format!("k={secret}\nk={secret}\n[{secret}]\n{secret} BEGIN SINTER MANAGED BLOCK x\n");
    for spec in [
        kv("k", "=", Some(secret), Present),
        kv("k", ":", Some(secret), Present),
        block("m", "#", Some(secret), Present),
    ] {
        let e = refused(&cur, &spec);
        assert!(!e.contains(secret), "{e}");
    }
}

// -------------------------------------------------------------- field check

fn with(pairs: &[(&str, Value)]) -> BTreeMap<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

fn s(v: &str) -> Value {
    Value::Str(v.to_string())
}

fn check_err(pairs: &[(&str, Value)]) -> String {
    MergeSpec::check(&with(pairs), "r", true)
        .expect_err("accepted")
        .message
}

#[test]
fn check_builds_each_merge_with_its_defaults() {
    let spec = MergeSpec::check(&with(&[("merge", s("line")), ("line", s("x"))]), "r", true)
        .unwrap()
        .unwrap();
    assert_eq!(spec, line("x", Present));
    let spec = MergeSpec::check(
        &with(&[
            ("merge", s("block")),
            ("marker", s("m")),
            ("content", s("a\n")),
        ]),
        "r",
        true,
    )
    .unwrap()
    .unwrap();
    assert_eq!(spec, block("m", "#", Some("a\n"), Present));
    let spec = MergeSpec::check(
        &with(&[
            ("merge", s("key_value")),
            ("key", s("k")),
            ("state", s("absent")),
            ("create", Value::Bool(true)),
        ]),
        "r",
        true,
    )
    .unwrap()
    .unwrap();
    assert_eq!(spec.edit, kv("k", "=", None, Absent).edit);
    assert!(spec.create);
    assert_eq!(spec.identity(), Identity::Key("k".into()));
}

#[test]
fn check_leaves_interpolated_fields_for_evaluation() {
    for pairs in [
        vec![("merge", s("line")), ("line", s("{{ vars.key }}"))],
        vec![
            ("merge", s("{{ vars.kind }}")),
            ("bogus_is_not_judged_here", s("x")),
        ],
        vec![
            ("merge", s("line")),
            ("line", s("x")),
            ("state", s("{{ vars.s }}")),
        ],
        vec![
            ("merge", s("line")),
            ("line", s("x")),
            ("create", s("{{ vars.c }}")),
        ],
        vec![
            ("merge", s("key_value")),
            ("key", s("k")),
            ("value", s("{{ vars.v }}")),
        ],
    ] {
        assert_eq!(MergeSpec::check(&with(&pairs), "r", true).unwrap(), None);
    }
    // Evaluated: the same text is a literal.
    let spec = MergeSpec::check(
        &with(&[("merge", s("line")), ("line", s("{{ literal }}"))]),
        "r",
        false,
    )
    .unwrap()
    .unwrap();
    assert_eq!(spec, line("{{ literal }}", Present));
}

#[test]
fn check_refuses_bad_fields_without_echoing_values() {
    let cases: Vec<(Vec<(&str, Value)>, &str)> = vec![
        (vec![("line", s("x"))], "requires merge"),
        (vec![("merge", s("regex"))], "must be one of"),
        (vec![("merge", Value::Int(1))], "must be a string"),
        (vec![("merge", s("line"))], "requires line"),
        (
            vec![("merge", s("line")), ("line", s("a\nb"))],
            "exactly one line",
        ),
        (
            vec![("merge", s("line")), ("line", s("a\n"))],
            "exactly one line",
        ),
        (
            vec![("merge", s("line")), ("line", s("a\rb"))],
            "exactly one line",
        ),
        (vec![("merge", s("line")), ("line", s("a\0b"))], "NUL"),
        (vec![("merge", s("line")), ("line", s(""))], "empty"),
        (
            vec![("merge", s("line")), ("line", s(" \t "))],
            "only whitespace",
        ),
        (
            vec![("merge", s("line")), ("line", Value::Int(3))],
            "must be a string",
        ),
        (
            vec![("merge", s("line")), ("line", s("x")), ("key", s("k"))],
            "does not apply to merge: line",
        ),
        (
            vec![("merge", s("line")), ("line", s("x")), ("state", s("gone"))],
            "present or absent",
        ),
        (
            vec![("merge", s("line")), ("line", s("x")), ("create", s("yes"))],
            "create must be a boolean",
        ),
        (
            vec![("merge", s("block")), ("content", s("a"))],
            "requires marker",
        ),
        (
            vec![("merge", s("block")), ("marker", s("m"))],
            "state: present requires content",
        ),
        (
            vec![
                ("merge", s("block")),
                ("marker", s("bad name")),
                ("content", s("a")),
            ],
            "marker must be",
        ),
        (
            vec![
                ("merge", s("block")),
                ("marker", s("m".repeat(65).as_str())),
                ("content", s("a")),
            ],
            "marker must be",
        ),
        (
            vec![
                ("merge", s("block")),
                ("marker", s("m")),
                ("content", s("a")),
                ("comment_prefix", s("%")),
            ],
            "comment_prefix must be one of",
        ),
        (
            vec![
                ("merge", s("block")),
                ("marker", s("m")),
                ("content", s("a\r\nb")),
            ],
            "carriage return",
        ),
        (
            vec![
                ("merge", s("block")),
                ("marker", s("m")),
                ("content", s("a\n# END SINTER MANAGED BLOCK other\n")),
            ],
            "content line 2",
        ),
        (
            vec![
                ("merge", s("block")),
                ("marker", s("m")),
                ("content", s("x BEGIN SINTER MANAGED BLOCK y z")),
            ],
            "content line 1",
        ),
        (
            vec![("merge", s("key_value")), ("value", s("v"))],
            "requires key",
        ),
        (
            vec![("merge", s("key_value")), ("key", s("k"))],
            "state: present requires value",
        ),
        (
            vec![
                ("merge", s("key_value")),
                ("key", s("a b")),
                ("value", s("v")),
            ],
            "key must be",
        ),
        (
            vec![
                ("merge", s("key_value")),
                ("key", s("k")),
                ("value", s("a\nb")),
            ],
            "one line",
        ),
        (
            vec![
                ("merge", s("key_value")),
                ("key", s("k")),
                ("value", s(" v")),
            ],
            "start or end with a space",
        ),
        (
            vec![
                ("merge", s("key_value")),
                ("key", s("k")),
                ("value", s("=v")),
                ("separator", s(" ")),
            ],
            "may not start with = or :",
        ),
        (
            vec![
                ("merge", s("key_value")),
                ("key", s("k")),
                ("value", s("v")),
                ("separator", s("->")),
            ],
            "separator must be one of",
        ),
    ];
    for (pairs, want) in cases {
        let e = check_err(&pairs);
        assert!(e.starts_with("r: "), "{e}");
        assert!(e.contains(want), "{pairs:?}: {e}");
    }
    let secret = "s3cr3t-synthetic-value";
    for pairs in [
        vec![("merge", s("line")), ("line", s(&format!("{secret}\n")))],
        vec![
            ("merge", s("key_value")),
            ("key", s("k")),
            ("value", s(&format!(" {secret}"))),
        ],
        vec![
            ("merge", s("key_value")),
            ("key", s(&format!("{secret} x"))),
            ("value", s("v")),
        ],
        vec![
            ("merge", s("block")),
            ("marker", s(&format!("{secret} x"))),
            ("content", s("v")),
        ],
        vec![("merge", s(secret))],
    ] {
        let e = check_err(&pairs);
        assert!(!e.contains(secret), "{e}");
    }
}

#[test]
fn absent_state_needs_neither_content_nor_value() {
    for pairs in [
        vec![
            ("merge", s("block")),
            ("marker", s("m")),
            ("state", s("absent")),
        ],
        vec![
            ("merge", s("key_value")),
            ("key", s("k")),
            ("state", s("absent")),
        ],
    ] {
        assert!(MergeSpec::check(&with(&pairs), "r", true)
            .unwrap()
            .is_some());
    }
}

#[test]
fn static_identity_is_known_only_for_literal_fields() {
    let id = |pairs: &[(&str, Value)]| static_identity(&with(pairs));
    assert_eq!(
        id(&[("merge", s("line")), ("line", s("x"))]),
        Some(Identity::Line("x".into()))
    );
    assert_eq!(
        id(&[("merge", s("line")), ("line", s("{{ vars.k }}"))]),
        None
    );
    assert_eq!(
        id(&[("merge", s("block")), ("marker", s("m"))]),
        Some(Identity::Block("m".into()))
    );
    assert_eq!(
        id(&[("merge", s("key_value")), ("key", s("k"))]),
        Some(Identity::Key("k".into()))
    );
    assert_eq!(id(&[("merge", s("{{ vars.m }}")), ("key", s("k"))]), None);
}

#[test]
fn key_value_refuses_an_indented_or_differently_cased_key_line() {
    for state in [Present, Absent] {
        let value = (state == Present).then_some("v");
        for cur in ["  k=v\n", "\tk = other\n", "a=1\n k=v\nk=v\n"] {
            let why = refused(cur, &kv("k", "=", value, state));
            assert!(why.contains("is indented"), "{cur:?}: {why}");
        }
        for cur in [" k v\n", "\tk\n"] {
            let why = refused(cur, &kv("k", " ", value, state));
            assert!(why.contains("is indented"), "{cur:?}: {why}");
        }
        for (cur, key, sep) in [
            ("K=v\n", "k", "="),
            ("port: 1\n", "Port", ": "),
            (
                "passwordauthentication yes\n",
                "PasswordAuthentication",
                " ",
            ),
            ("  Key=v\n", "key", "="),
        ] {
            let why = refused(cur, &kv(key, sep, value, state));
            assert!(why.contains("only in letter case"), "{cur:?}: {why}");
            assert!(!why.contains("yes") && !why.contains("=v"), "{why}");
        }
    }
    // An indented comment, a longer key and a non-ASCII line are no match.
    let cur = "  # k=1\n  kk=2\n  KK=3\n  é=4\n";
    assert_eq!(
        edit(cur, &kv("k", "=", Some("v"), Present)).unwrap(),
        format!("{cur}k=v\n")
    );
}

#[test]
fn line_refuses_the_words_of_a_marker_line() {
    for line in [
        "# BEGIN SINTER MANAGED BLOCK a",
        "// END SINTER MANAGED BLOCK a",
        "text END SINTER MANAGED BLOCK",
    ] {
        let mut with = std::collections::BTreeMap::new();
        with.insert("merge".to_string(), Value::Str("line".into()));
        with.insert("line".to_string(), Value::Str(line.into()));
        for lenient in [true, false] {
            let e = MergeSpec::check(&with, "m", lenient).unwrap_err();
            assert!(e.message.contains("managed-block marker"), "{}", e.message);
        }
    }
}
