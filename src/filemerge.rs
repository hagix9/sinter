//! `file_merge`: the declared part of an existing text file.
//!
//! This module is pure. It checks the fields of a `file_merge` resource and
//! computes, from the bytes a file holds now, the bytes it must hold so that
//! one declared part (an exact line, a marked block, one `key = value`
//! setting) is as declared and every other byte is kept. It reads and writes
//! nothing; `filemerge_engine` observes and publishes.
//!
//! No message built here names a line, a block content or a value: they may
//! be sensitive. Messages name counts, line numbers and the static
//! identifiers the recipe wrote (`marker`, `key`).

use std::collections::BTreeMap;
use std::fmt;

use crate::error::{Result, SinterError};
use crate::expressions::has_interpolation;
use crate::value::Value;

/// Every field `with` accepts.
pub const FIELDS: &[&str] = &[
    "path",
    "merge",
    "state",
    "create",
    "owner",
    "group",
    "mode",
    "line",
    "marker",
    "content",
    "comment_prefix",
    "key",
    "value",
    "separator",
];

/// Fields that must be known when the recipe is loaded (besides `path`).
pub const STATIC_FIELDS: &[&str] = &["merge", "marker", "comment_prefix", "key", "separator"];

/// The values of `merge`.
pub const MERGES: &[&str] = &["line", "block", "key_value"];

/// The values of `comment_prefix`.
pub const COMMENT_PREFIXES: &[&str] = &["#", ";", "//", "--"];

/// The values of `separator`.
pub const SEPARATORS: &[&str] = &["=", " = ", ":", ": ", " "];

const BEGIN_WORDS: &str = "BEGIN SINTER MANAGED BLOCK";
const END_WORDS: &str = "END SINTER MANAGED BLOCK";

/// Largest file `file_merge` reads or writes.
pub const MAX_BYTES: usize = crate::resources::PARTIAL_EDIT_MAX_BYTES as usize;

/// `marker`: 1–64 bytes of `[A-Za-z0-9_.-]`.
pub fn valid_marker(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.bytes().all(ident_byte)
}

/// `key`: 1–128 bytes of `[A-Za-z0-9_.-]`.
pub fn valid_key(s: &str) -> bool {
    (1..=128).contains(&s.len()) && s.bytes().all(ident_byte)
}

fn ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeState {
    Present,
    Absent,
}

/// How a `key_value` line separates the key from the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeparatorStyle {
    Equals,
    Colon,
    Space,
}

fn separator_style(sep: &str) -> SeparatorStyle {
    if sep.contains('=') {
        SeparatorStyle::Equals
    } else if sep.contains(':') {
        SeparatorStyle::Colon
    } else {
        SeparatorStyle::Space
    }
}

/// The managed part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Edit {
    /// One exact line.
    Line { line: String },
    /// The lines between the two marker lines of `marker`. `content` is the
    /// declared lines (required when present).
    Block {
        marker: String,
        prefix: String,
        content: Option<Vec<String>>,
    },
    /// The one line that sets `key`. `value` is required when present.
    KeyValue {
        key: String,
        separator: String,
        value: Option<String>,
    },
}

/// What two `file_merge` resources of one path may not share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    Line(String),
    Block(String),
    Key(String),
}

impl Identity {
    /// The field that carries the identity.
    pub fn field(&self) -> &'static str {
        match self {
            Identity::Line(_) => "line",
            Identity::Block(_) => "marker",
            Identity::Key(_) => "key",
        }
    }
}

/// A fully checked `file_merge` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeSpec {
    pub state: MergeState,
    /// Whether an absent file may be created (`state: present` only).
    pub create: bool,
    pub edit: Edit,
}

/// A field as written or as evaluated.
enum Field<T> {
    Unset,
    /// Still carries `{{ ... }}` (only before evaluation).
    Pending,
    Known(T),
}

fn text_field(
    with: &BTreeMap<String, Value>,
    key: &str,
    ctx: &str,
    lenient: bool,
) -> Result<Field<String>> {
    match with.get(key) {
        None | Some(Value::Null) => Ok(Field::Unset),
        Some(Value::Str(s)) if lenient && has_interpolation(s) => Ok(Field::Pending),
        Some(Value::Str(s)) => Ok(Field::Known(s.clone())),
        Some(_) => Err(SinterError::schema(format!(
            "{}: file_merge {} must be a string (quote a number or a boolean)",
            ctx, key
        ))),
    }
}

fn one_of(ctx: &str, key: &str, value: &str, allowed: &[&str]) -> Result<()> {
    if allowed.contains(&value) {
        return Ok(());
    }
    let list: Vec<String> = allowed.iter().map(|a| format!("{:?}", a)).collect();
    Err(SinterError::schema(format!(
        "{}: file_merge {} must be one of {}",
        ctx,
        key,
        list.join(", ")
    )))
}

/// Whether `line` is a marker line of any block: the kind (`true` for
/// BEGIN), the comment prefix and the marker name.
fn parse_marker_line(line: &str) -> Option<(bool, &'static str, &str)> {
    for prefix in COMMENT_PREFIXES {
        let Some(rest) = line.strip_prefix(prefix) else {
            continue;
        };
        let Some(rest) = rest.strip_prefix(' ') else {
            continue;
        };
        for (words, begin) in [(BEGIN_WORDS, true), (END_WORDS, false)] {
            if let Some(name) = rest.strip_prefix(words).and_then(|r| r.strip_prefix(' ')) {
                if valid_marker(name) {
                    return Some((begin, prefix, name));
                }
            }
        }
    }
    None
}

/// Whether `line` carries the words of a marker line at all. Such a line is
/// either a well-formed marker line or refused: Sinter does not guess what a
/// damaged marker line was.
fn mentions_marker(line: &str) -> bool {
    line.contains(BEGIN_WORDS) || line.contains(END_WORDS)
}

fn marker_line(prefix: &str, begin: bool, marker: &str) -> String {
    format!(
        "{} {} {}",
        prefix,
        if begin { BEGIN_WORDS } else { END_WORDS },
        marker
    )
}

/// The declared block content as lines. One trailing line feed is the end of
/// the last line, not an extra empty line; an empty string is no line.
fn content_lines(content: &str) -> Vec<String> {
    if content.is_empty() {
        return Vec::new();
    }
    content
        .strip_suffix('\n')
        .unwrap_or(content)
        .split('\n')
        .map(str::to_string)
        .collect()
}

fn check_line(ctx: &str, line: &str) -> Result<()> {
    let bad = if line.contains('\n') || line.contains('\r') {
        Some("must be exactly one line (no line feed or carriage return; in YAML use a plain or quoted scalar, not a block scalar)")
    } else if line.contains('\0') {
        Some("may not contain NUL")
    } else if line.trim().is_empty() {
        Some("must not be empty or only whitespace")
    } else {
        None
    };
    match bad {
        Some(why) => Err(SinterError::schema(format!(
            "{}: file_merge line {}",
            ctx, why
        ))),
        None => Ok(()),
    }
}

fn check_content(ctx: &str, content: &str) -> Result<Vec<String>> {
    if content.contains('\r') || content.contains('\0') {
        return Err(SinterError::schema(format!(
            "{}: file_merge content may not contain a carriage return or NUL",
            ctx
        )));
    }
    let lines = content_lines(content);
    if let Some(n) = lines.iter().position(|l| mentions_marker(l)) {
        return Err(SinterError::schema(format!(
            "{}: file_merge content line {} carries the words of a managed-block marker line; a block may not contain marker lines",
            ctx,
            n + 1
        )));
    }
    Ok(lines)
}

fn check_value(ctx: &str, value: &str, separator: &str) -> Result<()> {
    let bad = if value.contains('\n') || value.contains('\r') {
        Some("must be one line (no line feed or carriage return)")
    } else if value.contains('\0') {
        Some("may not contain NUL")
    } else if value.starts_with([' ', '\t']) || value.ends_with([' ', '\t']) {
        // The value of an existing line is compared without surrounding
        // blanks, so such a value would be rewritten on every run.
        Some("may not start or end with a space or tab")
    } else if separator_style(separator) == SeparatorStyle::Space && value.starts_with(['=', ':']) {
        // `key =x` would be read back as an `=` line.
        Some("may not start with = or : when the separator is a space")
    } else {
        None
    };
    match bad {
        Some(why) => Err(SinterError::schema(format!(
            "{}: file_merge value {}",
            ctx, why
        ))),
        None => Ok(()),
    }
}

impl MergeSpec {
    /// Check the fields of a `file_merge` declaration.
    ///
    /// `lenient` is the check of a declaration as written: a field that
    /// still carries `{{ ... }}` is not judged, and `Ok(None)` says the
    /// declaration cannot be completed before evaluation. Without `lenient`
    /// every string is taken as it is and the result is always `Some`.
    /// `path`, `owner`, `group` and `mode` are checked by the caller.
    pub fn check(
        with: &BTreeMap<String, Value>,
        ctx: &str,
        lenient: bool,
    ) -> Result<Option<MergeSpec>> {
        let state = match text_field(with, "state", ctx, lenient)? {
            Field::Unset => Some(MergeState::Present),
            Field::Pending => None,
            Field::Known(s) => match s.as_str() {
                "present" => Some(MergeState::Present),
                "absent" => Some(MergeState::Absent),
                _ => {
                    return Err(SinterError::schema(format!(
                        "{}: file_merge state must be present or absent",
                        ctx
                    )))
                }
            },
        };
        let create = match with.get("create") {
            None | Some(Value::Null) => Some(false),
            Some(Value::Bool(b)) => Some(*b),
            Some(Value::Str(s)) if lenient && has_interpolation(s) => None,
            Some(_) => {
                return Err(SinterError::schema(format!(
                    "{}: file_merge create must be a boolean",
                    ctx
                )))
            }
        };

        let merge = match text_field(with, "merge", ctx, lenient)? {
            Field::Unset => {
                return Err(SinterError::schema(format!(
                    "{}: file_merge requires merge (line, block or key_value)",
                    ctx
                )))
            }
            // Which fields apply is not known yet.
            Field::Pending => return Ok(None),
            Field::Known(m) => {
                one_of(ctx, "merge", &m, MERGES)?;
                m
            }
        };
        let own: &[&str] = match merge.as_str() {
            "line" => &["line"],
            "block" => &["marker", "content", "comment_prefix"],
            _ => &["key", "value", "separator"],
        };
        for other in [
            "line",
            "marker",
            "content",
            "comment_prefix",
            "key",
            "value",
            "separator",
        ] {
            if !own.contains(&other) && with.contains_key(other) {
                return Err(SinterError::schema(format!(
                    "{}: file_merge field {} does not apply to merge: {}",
                    ctx, other, merge
                )));
            }
        }
        let required = |key: &str| {
            SinterError::schema(format!(
                "{}: file_merge with merge: {} requires {}",
                ctx, merge, key
            ))
        };
        let required_present = |key: &str| {
            SinterError::schema(format!(
                "{}: file_merge with merge: {} and state: present requires {}",
                ctx, merge, key
            ))
        };

        let edit = match merge.as_str() {
            "line" => match text_field(with, "line", ctx, lenient)? {
                Field::Unset => return Err(required("line")),
                Field::Pending => None,
                Field::Known(line) => {
                    check_line(ctx, &line)?;
                    Some(Edit::Line { line })
                }
            },
            "block" => {
                let marker = match text_field(with, "marker", ctx, lenient)? {
                    Field::Unset => return Err(required("marker")),
                    Field::Pending => None,
                    Field::Known(m) => {
                        if !valid_marker(&m) {
                            return Err(SinterError::schema(format!(
                                "{}: file_merge marker must be 1 to 64 characters of [A-Za-z0-9_.-]",
                                ctx
                            )));
                        }
                        Some(m)
                    }
                };
                let prefix = match text_field(with, "comment_prefix", ctx, lenient)? {
                    Field::Unset => Some("#".to_string()),
                    Field::Pending => None,
                    Field::Known(p) => {
                        one_of(ctx, "comment_prefix", &p, COMMENT_PREFIXES)?;
                        Some(p)
                    }
                };
                let content = match text_field(with, "content", ctx, lenient)? {
                    Field::Unset => {
                        if state == Some(MergeState::Present) {
                            return Err(required_present("content"));
                        }
                        Some(None)
                    }
                    Field::Pending => None,
                    Field::Known(c) => Some(Some(check_content(ctx, &c)?)),
                };
                match (marker, prefix, content) {
                    (Some(marker), Some(prefix), Some(content)) => Some(Edit::Block {
                        marker,
                        prefix,
                        content,
                    }),
                    _ => None,
                }
            }
            _ => {
                let key = match text_field(with, "key", ctx, lenient)? {
                    Field::Unset => return Err(required("key")),
                    Field::Pending => None,
                    Field::Known(k) => {
                        if !valid_key(&k) {
                            return Err(SinterError::schema(format!(
                                "{}: file_merge key must be 1 to 128 characters of [A-Za-z0-9_.-]",
                                ctx
                            )));
                        }
                        Some(k)
                    }
                };
                let separator = match text_field(with, "separator", ctx, lenient)? {
                    Field::Unset => Some("=".to_string()),
                    Field::Pending => None,
                    Field::Known(s) => {
                        one_of(ctx, "separator", &s, SEPARATORS)?;
                        Some(s)
                    }
                };
                let value = match text_field(with, "value", ctx, lenient)? {
                    Field::Unset => {
                        if state == Some(MergeState::Present) {
                            return Err(required_present("value"));
                        }
                        Some(None)
                    }
                    Field::Pending => None,
                    Field::Known(v) => {
                        if let Some(sep) = &separator {
                            check_value(ctx, &v, sep)?;
                        }
                        Some(Some(v))
                    }
                };
                match (key, separator, value) {
                    (Some(key), Some(separator), Some(value)) => Some(Edit::KeyValue {
                        key,
                        separator,
                        value,
                    }),
                    _ => None,
                }
            }
        };
        match (state, create, edit) {
            (Some(state), Some(create), Some(edit)) => Ok(Some(MergeSpec {
                state,
                create,
                edit,
            })),
            _ => Ok(None),
        }
    }

    /// What no other `file_merge` of the same path may declare too.
    pub fn identity(&self) -> Identity {
        match &self.edit {
            Edit::Line { line } => Identity::Line(line.clone()),
            Edit::Block { marker, .. } => Identity::Block(marker.clone()),
            Edit::KeyValue { key, .. } => Identity::Key(key.clone()),
        }
    }
}

/// The identity of a declaration whose static fields are resolved, when it
/// can be known before evaluation. `line` is taken only as a literal.
pub fn static_identity(with: &BTreeMap<String, Value>) -> Option<Identity> {
    let literal = |key: &str| match with.get(key) {
        Some(Value::Str(s)) if !has_interpolation(s) => Some(s.clone()),
        _ => None,
    };
    match literal("merge")?.as_str() {
        "line" => literal("line").map(Identity::Line),
        "block" => literal("marker").map(Identity::Block),
        "key_value" => literal("key").map(Identity::Key),
        _ => None,
    }
}

/// Why a file is refused. Never carries file content or a declared value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditError(pub String);

impl fmt::Display for EditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn refuse<T>(msg: impl Into<String>) -> std::result::Result<T, EditError> {
    Err(EditError(msg.into()))
}

/// How the managed part differs from the declaration. `observed` and
/// `desired` may carry a value: the caller redacts them for a sensitive
/// resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartDrift {
    /// `line`, `block` or `value`.
    pub dimension: &'static str,
    pub observed: String,
    pub desired: String,
}

/// The result of [`apply_edit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditOutcome {
    /// The whole new file, or `None` when the managed part is already as
    /// declared (the file is then not written at all).
    pub new_content: Option<Vec<u8>>,
    /// Present exactly when `new_content` is.
    pub drift: Option<PartDrift>,
}

impl EditOutcome {
    fn unchanged() -> Self {
        EditOutcome {
            new_content: None,
            drift: None,
        }
    }

    fn changed(new: String, dimension: &'static str, observed: &str, desired: &str) -> Self {
        EditOutcome {
            new_content: Some(new.into_bytes()),
            drift: Some(PartDrift {
                dimension,
                observed: observed.to_string(),
                desired: desired.to_string(),
            }),
        }
    }
}

/// The text rules of every merge: UTF-8, no NUL, no carriage return, within
/// the size limit.
pub fn check_text(current: &[u8]) -> std::result::Result<&str, EditError> {
    if current.len() > MAX_BYTES {
        return refuse(format!(
            "the file is larger than {} bytes; file_merge refuses it",
            MAX_BYTES
        ));
    }
    let Ok(text) = std::str::from_utf8(current) else {
        return refuse("the file is not valid UTF-8; file_merge edits UTF-8 text only");
    };
    if text.contains('\0') {
        return refuse("the file contains a NUL byte; file_merge edits text only");
    }
    if text.contains('\r') {
        return refuse(
            "the file contains a carriage return (CRLF line endings?); file_merge edits LF text only and converts nothing",
        );
    }
    Ok(text)
}

/// A line without its terminator.
fn body(segment: &str) -> &str {
    segment.strip_suffix('\n').unwrap_or(segment)
}

/// `text` followed by `lines`, each ended by a line feed. A text that does
/// not end with a line feed gets one first.
fn appended<S: AsRef<str>>(text: &str, lines: &[S]) -> String {
    let mut out = String::with_capacity(text.len() + 64);
    out.push_str(text);
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    for l in lines {
        out.push_str(l.as_ref());
        out.push('\n');
    }
    out
}

/// Compute the file `spec` asks for from the file as it is (`None`: absent).
///
/// Only the managed part changes; every other byte is kept. A file whose
/// managed part cannot be told apart safely (duplicate keys, damaged
/// markers, CRLF, ...) is refused, never repaired. Whether an absent file
/// may be created is the caller's decision (`spec.create`).
pub fn apply_edit(
    current: Option<&[u8]>,
    spec: &MergeSpec,
) -> std::result::Result<EditOutcome, EditError> {
    let text = match current {
        Some(bytes) => check_text(bytes)?,
        None if spec.state == MergeState::Absent => return Ok(EditOutcome::unchanged()),
        None => "",
    };
    let outcome = match &spec.edit {
        Edit::Line { line } => edit_line(text, line, spec.state),
        Edit::Block {
            marker,
            prefix,
            content,
        } => edit_block(text, marker, prefix, content.as_deref(), spec.state)?,
        Edit::KeyValue {
            key,
            separator,
            value,
        } => edit_key_value(text, key, separator, value.as_deref(), spec.state)?,
    };
    // A file created for a present part exists afterwards even when the part
    // itself adds no byte (an empty block cannot: it has its marker lines).
    if let Some(new) = &outcome.new_content {
        if new.len() > MAX_BYTES {
            return refuse(format!(
                "the edited file would be larger than {} bytes; file_merge refuses it",
                MAX_BYTES
            ));
        }
    }
    Ok(outcome)
}

fn edit_line(text: &str, line: &str, state: MergeState) -> EditOutcome {
    let count = text
        .split_inclusive('\n')
        .filter(|s| body(s) == line)
        .count();
    match state {
        MergeState::Present if count > 0 => EditOutcome::unchanged(),
        MergeState::Present => {
            EditOutcome::changed(appended(text, &[line]), "line", "absent", "present")
        }
        MergeState::Absent if count == 0 => EditOutcome::unchanged(),
        MergeState::Absent => {
            let kept: String = text
                .split_inclusive('\n')
                .filter(|s| body(s) != line)
                .collect();
            EditOutcome::changed(
                kept,
                "line",
                &format!("present ({} time(s))", count),
                "absent",
            )
        }
    }
}

/// The segments of the block of `marker`: the index of its BEGIN line and of
/// its END line, or `None` when the file has no such block.
fn find_block(
    segments: &[&str],
    marker: &str,
    prefix: &str,
) -> std::result::Result<Option<(usize, usize)>, EditError> {
    let mut begin: Option<usize> = None;
    let mut end: Option<usize> = None;
    for (i, seg) in segments.iter().enumerate() {
        let line = body(seg);
        if !mentions_marker(line) {
            continue;
        }
        let n = i + 1;
        let Some((is_begin, line_prefix, name)) = parse_marker_line(line) else {
            return refuse(format!(
                "line {} carries the words of a managed-block marker line but is not a well-formed one; Sinter does not guess what it was",
                n
            ));
        };
        if name != marker {
            if begin.is_some() && end.is_none() {
                return refuse(format!(
                    "line {} is a marker line of another block inside block {}; the blocks overlap",
                    n, marker
                ));
            }
            continue;
        }
        if line_prefix != prefix {
            return refuse(format!(
                "line {} is a marker line of block {} with the comment prefix {:?}, but {:?} is declared",
                n, marker, line_prefix, prefix
            ));
        }
        if is_begin {
            if begin.is_some() {
                return refuse(format!(
                    "block {} has a second BEGIN line (line {})",
                    marker, n
                ));
            }
            begin = Some(i);
        } else {
            if begin.is_none() {
                return refuse(format!(
                    "block {} has an END line (line {}) without a BEGIN line before it",
                    marker, n
                ));
            }
            if end.is_some() {
                return refuse(format!(
                    "block {} has a second END line (line {})",
                    marker, n
                ));
            }
            end = Some(i);
        }
    }
    match (begin, end) {
        (None, _) => Ok(None),
        (Some(b), Some(e)) => Ok(Some((b, e))),
        (Some(b), None) => refuse(format!(
            "block {} has a BEGIN line (line {}) without an END line",
            marker,
            b + 1
        )),
    }
}

fn edit_block(
    text: &str,
    marker: &str,
    prefix: &str,
    content: Option<&[String]>,
    state: MergeState,
) -> std::result::Result<EditOutcome, EditError> {
    let segments: Vec<&str> = text.split_inclusive('\n').collect();
    let found = find_block(&segments, marker, prefix)?;
    let begin_line = marker_line(prefix, true, marker);
    let end_line = marker_line(prefix, false, marker);
    match (state, found) {
        (MergeState::Absent, None) => Ok(EditOutcome::unchanged()),
        (MergeState::Absent, Some((b, e))) => {
            let mut out = String::with_capacity(text.len());
            segments[..b].iter().for_each(|s| out.push_str(s));
            segments[e + 1..].iter().for_each(|s| out.push_str(s));
            Ok(EditOutcome::changed(out, "block", "present", "absent"))
        }
        (MergeState::Present, found) => {
            let Some(content) = content else {
                return refuse("file_merge block content is required when the state is present");
            };
            match found {
                None => {
                    let mut lines: Vec<&str> = Vec::with_capacity(content.len() + 2);
                    lines.push(&begin_line);
                    lines.extend(content.iter().map(String::as_str));
                    lines.push(&end_line);
                    Ok(EditOutcome::changed(
                        appended(text, &lines),
                        "block",
                        "absent",
                        "present",
                    ))
                }
                Some((b, e)) => {
                    let same = e - b - 1 == content.len()
                        && segments[b + 1..e]
                            .iter()
                            .zip(content)
                            .all(|(s, c)| body(s) == c);
                    if same {
                        return Ok(EditOutcome::unchanged());
                    }
                    let mut out = String::with_capacity(text.len() + 64);
                    segments[..=b].iter().for_each(|s| out.push_str(s));
                    for c in content {
                        out.push_str(c);
                        out.push('\n');
                    }
                    segments[e..].iter().for_each(|s| out.push_str(s));
                    Ok(EditOutcome::changed(
                        out,
                        "block",
                        "content differs",
                        "declared content",
                    ))
                }
            }
        }
    }
}

/// Whether `line` sets `key`, in which style, and its value without
/// surrounding blanks. A comment line never does.
fn key_line<'a>(line: &'a str, key: &str) -> Option<(SeparatorStyle, &'a str)> {
    const BLANK: [char; 2] = [' ', '\t'];
    let t = line.trim_start_matches(BLANK);
    if t.starts_with('#') || t.starts_with(';') {
        return None;
    }
    let rest = t.strip_prefix(key)?;
    let after = rest.trim_start_matches(BLANK);
    if let Some(v) = after.strip_prefix('=') {
        Some((SeparatorStyle::Equals, v.trim_matches(BLANK)))
    } else if let Some(v) = after.strip_prefix(':') {
        Some((SeparatorStyle::Colon, v.trim_matches(BLANK)))
    } else if rest.is_empty() || rest.starts_with(BLANK) {
        Some((SeparatorStyle::Space, after.trim_end_matches(BLANK)))
    } else {
        // A longer key that only starts with this one.
        None
    }
}

fn is_section_header(line: &str) -> bool {
    let t = line.trim_matches([' ', '\t']);
    t.len() >= 2 && t.starts_with('[') && t.ends_with(']')
}

fn edit_key_value(
    text: &str,
    key: &str,
    separator: &str,
    value: Option<&str>,
    state: MergeState,
) -> std::result::Result<EditOutcome, EditError> {
    let style = separator_style(separator);
    let segments: Vec<&str> = text.split_inclusive('\n').collect();
    let mut matches: Vec<(usize, &str)> = Vec::new();
    for (i, seg) in segments.iter().enumerate() {
        let line = body(seg);
        if is_section_header(line) {
            return refuse(format!(
                "line {} looks like a section header ([...]); key_value does not edit files with sections (INI-aware editing is not supported)",
                i + 1
            ));
        }
        match key_line(line, key) {
            None => {}
            Some((s, v)) if s == style => matches.push((i, v)),
            Some(_) => {
                return refuse(format!(
                    "line {} sets the key {} with another separator than the declared {:?}; Sinter does not guess which syntax the file uses",
                    i + 1,
                    key,
                    separator
                ))
            }
        }
    }
    if matches.len() > 1 {
        return refuse(format!(
            "the key {} appears {} times; Sinter does not guess which one is in effect",
            key,
            matches.len()
        ));
    }
    match (state, matches.first().copied()) {
        (MergeState::Absent, None) => Ok(EditOutcome::unchanged()),
        (MergeState::Absent, Some((i, _))) => {
            let mut out = String::with_capacity(text.len());
            segments[..i].iter().for_each(|s| out.push_str(s));
            segments[i + 1..].iter().for_each(|s| out.push_str(s));
            Ok(EditOutcome::changed(out, "value", "present", "absent"))
        }
        (MergeState::Present, found) => {
            let Some(value) = value else {
                return refuse("file_merge value is required when the state is present");
            };
            let new_line = format!("{}{}{}", key, separator, value);
            match found {
                None => Ok(EditOutcome::changed(
                    appended(text, &[new_line.as_str()]),
                    "value",
                    "key absent",
                    value,
                )),
                Some((_, current)) if current == value => Ok(EditOutcome::unchanged()),
                Some((i, current)) => {
                    let mut out = String::with_capacity(text.len() + new_line.len());
                    segments[..i].iter().for_each(|s| out.push_str(s));
                    out.push_str(&new_line);
                    if segments[i].ends_with('\n') {
                        out.push('\n');
                    }
                    segments[i + 1..].iter().for_each(|s| out.push_str(s));
                    Ok(EditOutcome::changed(out, "value", current, value))
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "filemerge_tests.rs"]
mod tests;
