use crate::result::{Diff, DiffBody};

pub const MAX_DIFF_LINE_BYTES: usize = 256 * 1024;

/// Build a diff between current and desired content.
///
/// Text diff is produced only when both sides are valid UTF-8, neither is
/// sensitive, and each side is <= 256 KiB. Otherwise the difference is
/// summarized. For sensitive content the diff is redacted.
pub fn content_diff(current: Option<&[u8]>, desired: &[u8], sensitive: bool) -> Diff {
    if sensitive {
        return Diff {
            body: DiffBody::Redacted,
        };
    }
    if desired.len() > MAX_DIFF_LINE_BYTES
        || current
            .map(|c| c.len() > MAX_DIFF_LINE_BYTES)
            .unwrap_or(false)
    {
        return Diff {
            body: DiffBody::Summary {
                current: format_bytes(current),
                desired: format_bytes(Some(desired)),
            },
        };
    }
    let cur_str = match current {
        None => String::new(),
        Some(c) => match std::str::from_utf8(c) {
            Ok(s) => s.to_string(),
            Err(_) => {
                return Diff {
                    body: DiffBody::Summary {
                        current: format_bytes(current),
                        desired: format_bytes(Some(desired)),
                    },
                }
            }
        },
    };
    let des_str = match std::str::from_utf8(desired) {
        Ok(s) => s.to_string(),
        Err(_) => {
            return Diff {
                body: DiffBody::Summary {
                    current: format_bytes(current),
                    desired: format_bytes(Some(desired)),
                },
            }
        }
    };
    let (removed, added) = line_diff(&cur_str, &des_str);
    Diff {
        body: DiffBody::Text { removed, added },
    }
}

pub fn format_bytes(b: Option<&[u8]>) -> String {
    match b {
        None => "absent".to_string(),
        Some(bytes) => format!("{} bytes", bytes.len()),
    }
}

/// A simple prefix/suffix-trimming line diff. Truthful about what changed
/// without claiming a minimal edit script.
pub fn line_diff(current: &str, desired: &str) -> (Vec<String>, Vec<String>) {
    let cur: Vec<&str> = current.lines().collect();
    let des: Vec<&str> = desired.lines().collect();
    let mut prefix = 0;
    while prefix < cur.len() && prefix < des.len() && cur[prefix] == des[prefix] {
        prefix += 1;
    }
    let mut suffix = 0;
    while suffix < cur.len() - prefix
        && suffix < des.len() - prefix
        && cur[cur.len() - 1 - suffix] == des[des.len() - 1 - suffix]
    {
        suffix += 1;
    }
    let removed: Vec<String> = cur[prefix..cur.len() - suffix]
        .iter()
        .map(|s| sanitize_line(s))
        .collect();
    let added: Vec<String> = des[prefix..des.len() - suffix]
        .iter()
        .map(|s| sanitize_line(s))
        .collect();
    (removed, added)
}

/// Escape terminal control characters so displayed content cannot alter the
/// terminal state. Covers C0, DEL, and C1 (including U+009B CSI) without
/// corrupting ordinary printable Unicode.
pub fn sanitize_line(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            // C1 controls: 0x80..=0x9F. U+009B is CSI and must never reach a
            // terminal raw. Escape as Unicode so ordinary CJK/Latin stays intact.
            c if (0x80..=0x9f).contains(&(c as u32)) => {
                out.push_str(&format!("\\u{{{:02x}}}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_is_redacted() {
        let d = content_diff(Some(b"secret"), b"newsecret", true);
        assert!(matches!(d.body, DiffBody::Redacted));
    }

    #[test]
    fn text_diff_simple() {
        let d = content_diff(Some(b"a\nb\nc\n"), b"a\nB\nc\n", false);
        match d.body {
            DiffBody::Text { removed, added } => {
                assert_eq!(removed, vec!["b".to_string()]);
                assert_eq!(added, vec!["B".to_string()]);
            }
            _ => panic!("expected text diff"),
        }
    }

    #[test]
    fn non_utf8_summarized() {
        let d = content_diff(Some(&[0xff, 0xfe]), &[0, 1], false);
        assert!(matches!(d.body, DiffBody::Summary { .. }));
    }

    #[test]
    fn controls_escaped() {
        assert_eq!(sanitize_line("a\u{1b}[31m"), "a\\x1b[31m");
    }

    #[test]
    fn c1_csi_escaped() {
        // U+009B is the single-byte CSI equivalent of ESC [.
        assert_eq!(sanitize_line("a\u{9b}31m"), "a\\u{9b}31m");
        assert_eq!(sanitize_line("\u{80}\u{9f}"), "\\u{80}\\u{9f}");
    }

    #[test]
    fn ordinary_unicode_not_corrupted() {
        assert_eq!(sanitize_line("日本語 café"), "日本語 café");
    }
}
