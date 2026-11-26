//! A strict, closed reader and editor for one section of an INI-style text
//! file (`dnf_repository`).
//!
//! Pure: no target access. The file is handled as lines that keep their own
//! line ending, so everything an edit does not touch is reproduced byte for
//! byte. Only the target section is parsed; a line there that this module
//! cannot classify with certainty is a refusal, never a guess. Outside the
//! target section only section headers are looked for.
//!
//! Line kinds inside the target section:
//!
//! * blank: only spaces and tabs;
//! * comment: starts in column one with `#` or `;`;
//! * key line: `key=value` or `key = value`, starting in column one;
//! * continuation: starts with a space or tab and directly follows a key
//!   line or another continuation line (a multi-line value).
//!
//! Refused inside the target section: an indented line whose first character
//! is `#` or `;` (it is a comment for some readers and part of a value for
//! others), a continuation that follows a blank or comment line, a line
//! without `=`, a key with other characters than `[A-Za-z0-9_.-]`, a key
//! that appears twice, and any control character other than a tab.
//!
//! No refusal text ever quotes file content: a repository file can hold
//! credentials. Refusals name line numbers only.

/// Why a file is not read or not edited. The text names line numbers and
/// rules, never file content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IniError(pub String);

fn refuse<T>(msg: impl Into<String>) -> Result<T, IniError> {
    Err(IniError(msg.into()))
}

/// The text rules of a file this module edits: valid UTF-8, no NUL, no
/// carriage return, at most `max` bytes.
pub fn check_text(bytes: &[u8], max: u64) -> Result<&str, IniError> {
    if bytes.len() as u64 > max {
        return refuse(format!("the file is larger than {} bytes", max));
    }
    if bytes.contains(&0) {
        return refuse("the file contains a NUL byte");
    }
    if bytes.contains(&b'\r') {
        return refuse("the file contains a carriage return (CR or CRLF line endings)");
    }
    std::str::from_utf8(bytes).or_else(|_| refuse("the file is not valid UTF-8"))
}

fn is_blank(body: &str) -> bool {
    body.chars().all(|c| c == ' ' || c == '\t')
}

fn trim(s: &str) -> &str {
    s.trim_matches(|c| c == ' ' || c == '\t')
}

/// The line without its line feed.
fn body(line: &str) -> &str {
    line.strip_suffix('\n').unwrap_or(line)
}

/// `Some(id)` for a well-formed section header (`[id]`, nothing but spaces
/// and tabs after the bracket), `None` for a line that does not start with
/// `[`, and a refusal for a line that starts with `[` but is not a header.
fn header_id(body: &str, line_no: usize) -> Result<Option<&str>, IniError> {
    if !body.starts_with('[') {
        return Ok(None);
    }
    let malformed = || {
        refuse(format!(
            "line {} starts with [ but is not a section header of the form [id]",
            line_no
        ))
    };
    let Some(close) = body.find(']') else {
        return malformed();
    };
    let id = &body[1..close];
    if id.is_empty() || !is_blank(&body[close + 1..]) {
        return malformed();
    }
    Ok(Some(id))
}

/// One key of the target section with the lines it occupies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    pub name: String,
    /// Index of the key line.
    pub first: usize,
    /// Index after the last line of the value (key line plus continuations).
    pub end: usize,
    /// The value on the key line and on every continuation line, each
    /// without surrounding spaces and tabs.
    pub pieces: Vec<String>,
}

impl Key {
    /// The value as one string: the non-empty pieces joined by a line feed.
    /// A single-line value is that line's value.
    pub fn text(&self) -> String {
        self.pieces
            .iter()
            .filter(|p| !p.is_empty())
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The value as a sequence of whitespace-separated entries (a list
    /// option such as `baseurl` or `gpgkey`).
    pub fn entries(&self) -> Vec<String> {
        self.pieces
            .iter()
            .flat_map(|p| p.split([' ', '\t']))
            .filter(|e| !e.is_empty())
            .map(str::to_string)
            .collect()
    }
}

/// The target section as found in the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// Index of the header line.
    pub header: usize,
    /// Index after the last key or continuation line (after the header when
    /// the section has no key). Blank and comment lines from here to the
    /// next header are not counted as part of the section's content.
    pub body_end: usize,
    pub keys: Vec<Key>,
}

impl Section {
    pub fn get(&self, name: &str) -> Option<&Key> {
        self.keys.iter().find(|k| k.name == name)
    }
}

/// A file split into lines, each with its own line feed (the last line may
/// have none).
#[derive(Debug, Clone)]
pub struct Doc<'a> {
    lines: Vec<&'a str>,
    /// `(line index, id)` of every section header.
    headers: Vec<(usize, &'a str)>,
}

impl<'a> Doc<'a> {
    /// Split the text and find the section headers. A line that starts with
    /// `[` and is not a well-formed header is a refusal anywhere in the file,
    /// because where a section ends would otherwise be a guess.
    pub fn parse(text: &'a str) -> Result<Doc<'a>, IniError> {
        let lines: Vec<&str> = text.split_inclusive('\n').collect();
        let mut headers = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            if let Some(id) = header_id(body(line), i + 1)? {
                headers.push((i, id));
            }
        }
        Ok(Doc { lines, headers })
    }

    /// Whether the file has any section header.
    pub fn has_sections(&self) -> bool {
        !self.headers.is_empty()
    }

    /// The section `id`, parsed strictly, or `None` when the file has no
    /// such header. Two headers for `id`, or a header that equals `id` only
    /// after removing spaces, are refusals.
    pub fn section(&self, id: &str) -> Result<Option<Section>, IniError> {
        let mut found: Option<usize> = None;
        for (pos, (line, hid)) in self.headers.iter().enumerate() {
            if *hid == id {
                if found.is_some() {
                    return refuse(format!(
                        "the section [{}] is defined more than once (second header at line {})",
                        id,
                        line + 1
                    ));
                }
                found = Some(pos);
            } else if trim(hid) == id {
                return refuse(format!(
                    "the section header at line {} names [{}] with extra spaces",
                    line + 1,
                    id
                ));
            }
        }
        let Some(pos) = found else {
            return Ok(None);
        };
        let header = self.headers[pos].0;
        let end = self
            .headers
            .get(pos + 1)
            .map(|(l, _)| *l)
            .unwrap_or(self.lines.len());
        let mut keys: Vec<Key> = Vec::new();
        let mut body_end = header + 1;
        // Whether the previous line was a key line or a continuation.
        let mut in_value = false;
        for i in header + 1..end {
            let b = body(self.lines[i]);
            let no = i + 1;
            if b.chars().any(|c| c.is_control() && c != '\t') {
                return refuse(format!(
                    "line {} of section [{}] contains a control character",
                    no, id
                ));
            }
            if is_blank(b) {
                in_value = false;
                continue;
            }
            let first = b.chars().next().unwrap_or(' ');
            if first == ' ' || first == '\t' {
                let t = trim(b);
                if t.starts_with('#') || t.starts_with(';') {
                    return refuse(format!(
                        "line {} of section [{}] is indented and starts with # or ; (a comment \
                         or part of a value, depending on the reader)",
                        no, id
                    ));
                }
                if !in_value {
                    return refuse(format!(
                        "line {} of section [{}] is indented but does not directly follow a key \
                         line",
                        no, id
                    ));
                }
                let k = keys.last_mut().expect("in_value implies a key");
                k.pieces.push(t.to_string());
                k.end = i + 1;
                body_end = i + 1;
                continue;
            }
            if first == '#' || first == ';' {
                in_value = false;
                continue;
            }
            let Some(eq) = b.find('=') else {
                return refuse(format!(
                    "line {} of section [{}] is not a key=value line",
                    no, id
                ));
            };
            let name = b[..eq].trim_end_matches([' ', '\t']);
            if name.is_empty()
                || !name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
            {
                return refuse(format!(
                    "line {} of section [{}] has a key with characters other than \
                     [A-Za-z0-9_.-]",
                    no, id
                ));
            }
            if keys.iter().any(|k| k.name == name) {
                return refuse(format!(
                    "the key {} appears more than once in section [{}] (again at line {})",
                    name, id, no
                ));
            }
            keys.push(Key {
                name: name.to_string(),
                first: i,
                end: i + 1,
                pieces: vec![trim(&b[eq + 1..]).to_string()],
            });
            body_end = i + 1;
            in_value = true;
        }
        Ok(Some(Section {
            header,
            body_end,
            keys,
        }))
    }

    /// The file with `sets` applied to `sec`: an existing key's lines are
    /// replaced in place, a missing key is added after the section's last
    /// key line, in the order given. Every other line is copied unchanged.
    /// The caller passes only keys whose value differs.
    pub fn set_keys(&self, sec: &Section, sets: &[(String, Vec<String>)]) -> String {
        let mut out = String::new();
        let appended: String = sets
            .iter()
            .filter(|(name, _)| sec.get(name).is_none())
            .map(|(name, values)| render_key(name, values))
            .collect();
        let mut i = 0;
        while i < self.lines.len() {
            if i == sec.body_end {
                push_lines(&mut out, &appended);
            }
            let replaced = sec
                .keys
                .iter()
                .find(|k| k.first == i)
                .and_then(|k| sets.iter().find(|(n, _)| *n == k.name).map(|s| (k, s)));
            match replaced {
                Some((k, (name, values))) => {
                    let mut text = render_key(name, values);
                    // A replaced last line without a line feed stays without.
                    if !self.lines[k.end - 1].ends_with('\n') {
                        text.pop();
                    }
                    out.push_str(&text);
                    i = k.end;
                }
                None => {
                    out.push_str(self.lines[i]);
                    i += 1;
                }
            }
        }
        if sec.body_end >= self.lines.len() {
            push_lines(&mut out, &appended);
        }
        out
    }

    /// The file without `sec`: the header and everything up to the
    /// section's last key line are removed. Blank and comment lines after
    /// that line stay (they may belong to the next section), as do the lines
    /// above the header.
    pub fn remove_section(&self, sec: &Section) -> String {
        let mut out = String::new();
        for (i, line) in self.lines.iter().enumerate() {
            if i < sec.header || i >= sec.body_end {
                out.push_str(line);
            }
        }
        out
    }

    /// The file with a new section `id` at its end. An empty file becomes
    /// exactly the section; otherwise one blank line separates it from what
    /// is there (none is added after a line that is already blank).
    pub fn append_section(&self, id: &str, keys: &[(String, Vec<String>)]) -> String {
        let mut out: String = self.lines.concat();
        if !out.is_empty() {
            if !out.ends_with('\n') {
                out.push('\n');
            }
            let last_blank = self.lines.last().is_some_and(|l| is_blank(body(l)));
            if !last_blank {
                out.push('\n');
            }
        }
        out.push_str(&render_section(id, keys));
        out
    }
}

/// Add complete lines to `out`, first ending an unterminated last line.
fn push_lines(out: &mut String, lines: &str) {
    if lines.is_empty() {
        return;
    }
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(lines);
}

/// `key=value`, or for several values one per line with the later ones
/// indented (a continuation).
pub fn render_key(name: &str, values: &[String]) -> String {
    let mut s = String::new();
    s.push_str(name);
    s.push('=');
    for (i, v) in values.iter().enumerate() {
        if i > 0 {
            s.push_str("        ");
        }
        s.push_str(v);
        s.push('\n');
    }
    if values.is_empty() {
        s.push('\n');
    }
    s
}

/// A whole section: the header and its keys.
pub fn render_section(id: &str, keys: &[(String, Vec<String>)]) -> String {
    let mut s = format!("[{}]\n", id);
    for (name, values) in keys {
        s.push_str(&render_key(name, values));
    }
    s
}

/// Keys whose value is a credential or names one.
const CREDENTIAL_KEYS: [&str; 5] = [
    "password",
    "username",
    "proxy_password",
    "proxy_username",
    "sslclientkey",
];

/// Whether the authority of some URL in `s` has a userinfo part
/// (`scheme://user@host` or `scheme://user:password@host`).
pub fn has_url_userinfo(s: &str) -> bool {
    let mut rest = s;
    while let Some(at) = rest.find("://") {
        rest = &rest[at + 3..];
        let authority = rest
            .split(|c: char| matches!(c, '/' | '?' | '#') || c.is_whitespace())
            .next()
            .unwrap_or("");
        if authority.contains('@') {
            return true;
        }
    }
    false
}

/// Whether any line of the file, in any section and also when commented
/// out, sets a credential key or holds a URL with a userinfo part. Such a
/// file's content must not be shown.
pub fn has_credentials(text: &str) -> bool {
    text.split('\n').any(|line| {
        if has_url_userinfo(line) {
            return true;
        }
        let t = line.trim_start_matches(|c: char| c.is_whitespace() || c == '#' || c == ';');
        match t.find('=') {
            Some(eq) => {
                let key = t[..eq].trim().to_ascii_lowercase();
                CREDENTIAL_KEYS.contains(&key.as_str())
            }
            None => false,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX: u64 = 1024;

    fn sets(pairs: &[(&str, &[&str])]) -> Vec<(String, Vec<String>)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.iter().map(|s| s.to_string()).collect()))
            .collect()
    }

    fn section(text: &str, id: &str) -> Section {
        Doc::parse(text).unwrap().section(id).unwrap().unwrap()
    }

    fn section_err(text: &str, id: &str) -> String {
        match Doc::parse(text).and_then(|d| d.section(id)) {
            Ok(_) => panic!("accepted: {text:?}"),
            Err(e) => e.0,
        }
    }

    #[test]
    fn text_rules_refuse_what_cannot_be_edited_safely() {
        assert_eq!(check_text(b"[a]\nx=1\n", MAX).unwrap(), "[a]\nx=1\n");
        assert_eq!(check_text(b"", MAX).unwrap(), "");
        assert!(check_text(b"[a]\0", MAX).unwrap_err().0.contains("NUL"));
        assert!(check_text(b"[a]\r\nx=1\r\n", MAX)
            .unwrap_err()
            .0
            .contains("carriage return"));
        assert!(check_text(&[0xff, 0xfe], MAX)
            .unwrap_err()
            .0
            .contains("UTF-8"));
        let big = vec![b'#'; MAX as usize + 1];
        assert!(check_text(&big, MAX).unwrap_err().0.contains("larger"));
        assert!(check_text(&big[..MAX as usize], MAX).is_ok());
    }

    #[test]
    fn a_section_is_read_with_both_key_forms_and_continuations() {
        let text = "# top\n[other]\nfoo=bar\n\n[repo]\nname = A repo $releasever\nbaseurl=https://a.example.invalid/x\n        https://b.example.invalid/x\n\tfile:///srv/x\nenabled=1\n; note\ngpgcheck = 1\n\n# next\n[last]\nenabled=0\n";
        let s = section(text, "repo");
        assert_eq!(s.header, 4);
        assert_eq!(s.body_end, 12);
        let names: Vec<&str> = s.keys.iter().map(|k| k.name.as_str()).collect();
        assert_eq!(names, ["name", "baseurl", "enabled", "gpgcheck"]);
        assert_eq!(s.get("name").unwrap().text(), "A repo $releasever");
        assert_eq!(
            s.get("baseurl").unwrap().entries(),
            [
                "https://a.example.invalid/x",
                "https://b.example.invalid/x",
                "file:///srv/x"
            ]
        );
        assert_eq!(
            (
                s.get("baseurl").unwrap().first,
                s.get("baseurl").unwrap().end
            ),
            (6, 9)
        );
        assert_eq!(s.get("gpgcheck").unwrap().text(), "1");
        assert!(s.get("foo").is_none());
    }

    #[test]
    fn list_entries_ignore_how_the_value_is_laid_out() {
        let a = section("[r]\ngpgkey=file:///a file:///b\n", "r");
        let b = section("[r]\ngpgkey=\n   file:///a\n\tfile:///b\n", "r");
        assert_eq!(
            a.get("gpgkey").unwrap().entries(),
            b.get("gpgkey").unwrap().entries()
        );
        assert_eq!(b.get("gpgkey").unwrap().text(), "file:///a\nfile:///b");
    }

    #[test]
    fn an_empty_value_and_a_value_with_equals_signs_are_kept_as_written() {
        let s = section("[r]\nempty=\nurl=https://h.example.invalid/?a=b&c=d\n", "r");
        assert_eq!(s.get("empty").unwrap().text(), "");
        assert!(s.get("empty").unwrap().entries().is_empty());
        assert_eq!(
            s.get("url").unwrap().text(),
            "https://h.example.invalid/?a=b&c=d"
        );
    }

    #[test]
    fn a_missing_section_is_none_and_other_sections_are_not_validated() {
        // The other section holds lines the strict reader would refuse.
        let text = "[other]\nnot a key line\ndup=1\ndup=2\n  # indented\n[repo]\nenabled=1\n";
        let d = Doc::parse(text).unwrap();
        assert!(d.section("absent").unwrap().is_none());
        assert!(d.has_sections());
        assert_eq!(d.section("repo").unwrap().unwrap().keys.len(), 1);
        assert!(d.section("other").is_err());
        assert!(!Doc::parse("# only a comment\n\n").unwrap().has_sections());
    }

    #[test]
    fn the_target_section_is_refused_when_it_is_ambiguous() {
        for (text, want) in [
            ("[r]\nenabled=1\n[x]\n[r]\nenabled=0\n", "more than once"),
            ("[r]\nenabled=1\nenabled=0\n", "appears more than once"),
            ("[r]\njust words\n", "not a key=value line"),
            ("[r]\nkey: value\n", "not a key=value line"),
            ("[r]\n=value\n", "characters other than"),
            ("[r]\nbad key=1\n", "characters other than"),
            (
                "[r]\nenabled=1\n\n  continued\n",
                "does not directly follow",
            ),
            ("[r]\n  orphan\n", "does not directly follow"),
            ("[r]\nbaseurl=a\n  # b\n", "indented and starts with"),
            ("[r]\nbaseurl=a\n\t; b\n", "indented and starts with"),
            ("[r]\nname=a\u{1b}[0m\n", "control character"),
            ("[ r ]\nenabled=1\n", "extra spaces"),
        ] {
            let e = section_err(text, "r");
            assert!(e.contains(want), "{text:?}: {e}");
        }
    }

    #[test]
    fn a_malformed_header_anywhere_refuses_the_file() {
        for text in ["[r]\nenabled=1\n[broken\n", "[x] junk\n[r]\n", "[]\n[r]\n"] {
            let e = Doc::parse(text).unwrap_err().0;
            assert!(e.contains("not a section header"), "{text:?}: {e}");
        }
        // Trailing spaces after the bracket are a header; an indented
        // bracket is not one.
        let d = Doc::parse("[r]  \t\nenabled=1\n  [x]\n").unwrap();
        let s = d.section("r").unwrap().unwrap();
        assert_eq!(s.get("enabled").unwrap().pieces, ["1", "[x]"]);
        assert!(d.section("x").unwrap().is_none());
    }

    #[test]
    fn refusals_never_quote_file_content() {
        let secret = "SYNTHETIC-PASSWORD-VALUE";
        for text in [
            format!("[r]\n{secret}\n"),
            format!("[r]\npassword={secret}\npassword={secret}\n"),
            format!("[r]\n  {secret}\n"),
            format!("[r]\n{secret} x=1\n"),
            format!("[{secret}\n"),
        ] {
            let e = match Doc::parse(&text).and_then(|d| d.section("r")) {
                Err(e) => e.0,
                Ok(_) => panic!("accepted {text:?}"),
            };
            assert!(!e.contains(secret), "{e}");
        }
    }

    #[test]
    fn setting_keys_replaces_in_place_and_keeps_every_other_byte() {
        let text = "# keep me\n[a]\nx = 1\n\n[r]\n# about r\nname = Old name\nenabled=0\nbaseurl=https://old.example.invalid/1\n   https://old.example.invalid/2\ngpgcheck=1\n\n# belongs to z\n[z]\nenabled=0\n";
        let d = Doc::parse(text).unwrap();
        let s = d.section("r").unwrap().unwrap();
        let out = d.set_keys(
            &s,
            &sets(&[
                ("enabled", &["1"]),
                ("baseurl", &["https://new.example.invalid/"]),
                ("gpgkey", &["file:///k1", "file:///k2"]),
                ("metalink", &["https://m.example.invalid/"]),
            ]),
        );
        assert_eq!(
            out,
            "# keep me\n[a]\nx = 1\n\n[r]\n# about r\nname = Old name\nenabled=1\nbaseurl=https://new.example.invalid/\ngpgcheck=1\ngpgkey=file:///k1\n        file:///k2\nmetalink=https://m.example.invalid/\n\n# belongs to z\n[z]\nenabled=0\n"
        );
        // Nothing to set: byte-identical.
        assert_eq!(d.set_keys(&s, &[]), text);
    }

    #[test]
    fn setting_keys_handles_a_last_line_without_a_line_feed() {
        let d = Doc::parse("[r]\nenabled=0").unwrap();
        let s = d.section("r").unwrap().unwrap();
        assert_eq!(
            d.set_keys(&s, &sets(&[("enabled", &["1"])])),
            "[r]\nenabled=1"
        );
        assert_eq!(
            d.set_keys(&s, &sets(&[("gpgcheck", &["1"])])),
            "[r]\nenabled=0\ngpgcheck=1\n"
        );
        let d = Doc::parse("[r]").unwrap();
        let s = d.section("r").unwrap().unwrap();
        assert_eq!(
            d.set_keys(&s, &sets(&[("enabled", &["1"])])),
            "[r]\nenabled=1\n"
        );
        // A key added to a section that is followed by another one.
        let d = Doc::parse("[r]\n[z]\nx=1\n").unwrap();
        let s = d.section("r").unwrap().unwrap();
        assert_eq!(
            d.set_keys(&s, &sets(&[("enabled", &["1"])])),
            "[r]\nenabled=1\n[z]\nx=1\n"
        );
    }

    #[test]
    fn the_edited_text_reads_back_as_the_values_that_were_set() {
        let d = Doc::parse("[r]\nbaseurl=a b\n c\nenabled=0\n").unwrap();
        let s = d.section("r").unwrap().unwrap();
        let out = d.set_keys(&s, &sets(&[("baseurl", &["x", "y"]), ("gpgkey", &["k"])]));
        let s2 = section(&out, "r");
        assert_eq!(s2.get("baseurl").unwrap().entries(), ["x", "y"]);
        assert_eq!(s2.get("gpgkey").unwrap().entries(), ["k"]);
        assert_eq!(s2.get("enabled").unwrap().text(), "0");
    }

    #[test]
    fn removing_a_section_keeps_its_neighbours_and_their_comments() {
        let text = "# file comment\n[a]\nx=1\n\n# about r\n[r]\nenabled=1\n# inside r\ngpgcheck=1\n\n# about z\n[z]\ny=2\n";
        let d = Doc::parse(text).unwrap();
        let s = d.section("r").unwrap().unwrap();
        assert_eq!(
            d.remove_section(&s),
            "# file comment\n[a]\nx=1\n\n# about r\n\n# about z\n[z]\ny=2\n"
        );
        // The only section: the file stays, with what was around it.
        let d = Doc::parse("# header comment\n[r]\nenabled=1\n\n# trailer\n").unwrap();
        let s = d.section("r").unwrap().unwrap();
        let out = d.remove_section(&s);
        assert_eq!(out, "# header comment\n\n# trailer\n");
        assert!(!Doc::parse(&out).unwrap().has_sections());
        let d = Doc::parse("[r]\nenabled=1").unwrap();
        let s = d.section("r").unwrap().unwrap();
        assert_eq!(d.remove_section(&s), "");
    }

    #[test]
    fn a_new_section_is_the_whole_file_or_follows_one_blank_line() {
        let keys = sets(&[
            ("baseurl", &["https://r.example.invalid/"]),
            ("gpgcheck", &["1"]),
        ]);
        let want = "[r]\nbaseurl=https://r.example.invalid/\ngpgcheck=1\n";
        assert_eq!(Doc::parse("").unwrap().append_section("r", &keys), want);
        assert_eq!(
            Doc::parse("[a]\nx=1\n").unwrap().append_section("r", &keys),
            format!("[a]\nx=1\n\n{want}")
        );
        assert_eq!(
            Doc::parse("[a]\nx=1").unwrap().append_section("r", &keys),
            format!("[a]\nx=1\n\n{want}")
        );
        assert_eq!(
            Doc::parse("[a]\nx=1\n\n")
                .unwrap()
                .append_section("r", &keys),
            format!("[a]\nx=1\n\n{want}")
        );
        assert_eq!(render_section("r", &keys), want);
    }

    #[test]
    fn credentials_are_recognized_anywhere_in_the_file() {
        for text in [
            "[x]\npassword=synthetic\n",
            "[x]\nusername = synthetic\n",
            "[x]\nproxy_password=synthetic\n",
            "[x]\nproxy_username=synthetic\n",
            "[x]\nsslclientkey=/etc/pki/synthetic.key\n",
            "[x]\n#password=synthetic\n",
            "[x]\n  ; Password = synthetic\n",
            "[x]\nbaseurl=https://user:synthetic@repo.example.invalid/x\n",
            "[x]\nbaseurl=https://a.example.invalid/\n   https://user@b.example.invalid/\n",
            "[x]\nproxy=http://user:synthetic@proxy.example.invalid:3128\n",
            "# see ftp://user@old.example.invalid/\n",
        ] {
            assert!(has_credentials(text), "{text:?}");
        }
        for text in [
            "",
            "[x]\nbaseurl=https://repo.example.invalid/path@v1/x\n",
            "[x]\nname=Contact admin@example.invalid\n",
            "[x]\nsslverify=1\nsslcacert=/etc/pki/ca.pem\n",
            "[x]\nbaseurl=https://repo.example.invalid/?mail=a@b\n",
            "[x]\npassword_note_only\n",
        ] {
            assert!(!has_credentials(text), "{text:?}");
        }
    }
}
