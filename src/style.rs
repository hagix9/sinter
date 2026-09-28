//! Terminal styling for human-readable CLI output.
//!
//! Color is a presentation concern of the `text` format only. It is decided
//! once per output stream by the CLI and passed down through
//! [`RenderOptions`](crate::output::RenderOptions); renderers never probe the
//! terminal themselves.
//!
//! Rules:
//!
//! * color only when the stream is a terminal (pipes, redirects and captured
//!   CI output stay plain bytes);
//! * `NO_COLOR` set to any non-empty value disables color
//!   (<https://no-color.org>); `TERM=dumb` disables color;
//! * JSON output, the MCP server and every library-level renderer default to
//!   no color — a structured document can never carry an escape sequence;
//! * only fixed status tokens produced by Sinter itself are painted, always
//!   after sanitization, so recipe- or target-controlled text is never
//!   wrapped in (or able to forge) an escape sequence.

use std::ffi::OsStr;
use std::io::IsTerminal;

/// Semantic tone of a status token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    /// Success / compliant / completed (green).
    Good,
    /// Needs attention but is not a failure: drift, possible change,
    /// blocked, unknown (yellow).
    Warn,
    /// Failure / error / indeterminate (red).
    Bad,
    /// Informational; never painted.
    Neutral,
}

/// Pure color decision, separated from environment probing for tests.
pub fn color_enabled(is_tty: bool, no_color: Option<&OsStr>, term: Option<&OsStr>) -> bool {
    if !is_tty {
        return false;
    }
    if no_color.is_some_and(|v| !v.is_empty()) {
        return false;
    }
    if term.is_some_and(|t| t == "dumb") {
        return false;
    }
    true
}

fn env_decision(is_tty: bool) -> bool {
    color_enabled(
        is_tty,
        std::env::var_os("NO_COLOR").as_deref(),
        std::env::var_os("TERM").as_deref(),
    )
}

/// Whether human output on stdout may be colored.
pub fn stdout_color() -> bool {
    env_decision(std::io::stdout().is_terminal())
}

/// Whether human diagnostics on stderr may be colored.
pub fn stderr_color() -> bool {
    env_decision(std::io::stderr().is_terminal())
}

/// Classify a Sinter-produced status token. Unknown tokens are neutral.
pub fn tone_for(token: &str) -> Tone {
    match token {
        // resource / aggregate success
        "ok" | "CHANGED" | "success" | "PASS" | "no_drift" | "BACKUP" | "backed_up" | "MATCH" => {
            Tone::Good
        }
        // attention, not failure
        "POSSIBLE" | "blocked" | "?" | "DRIFT" | "drift" | "WARN" | "not_run" | "absent" => {
            Tone::Warn
        }
        // failure
        "FAILED" | "INDET" | "ERROR" | "plan_error" | "apply_failed" | "indeterminate"
        | "error" | "sinter:" => Tone::Bad,
        _ => Tone::Neutral,
    }
}

/// Paint `text` with `tone` when `enabled`. Trailing padding stays outside
/// the escape sequence so column alignment is identical with and without
/// color.
pub fn paint(text: &str, tone: Tone, enabled: bool) -> String {
    let code = match tone {
        Tone::Good => "32",
        Tone::Warn => "33",
        Tone::Bad => "31",
        Tone::Neutral => return text.to_string(),
    };
    if !enabled {
        return text.to_string();
    }
    let trimmed = text.trim_end_matches(' ');
    let pad = &text[trimmed.len()..];
    if trimmed.is_empty() {
        return text.to_string();
    }
    format!("\x1b[{}m{}\x1b[0m{}", code, trimmed, pad)
}

/// Paint a status token using its own tone.
pub fn status(token: &str, enabled: bool) -> String {
    paint(token, tone_for(token.trim_end()), enabled)
}

/// Paint the first whitespace-delimited word of an already sanitized line
/// when it is a known status token (used for renderers that produce whole
/// lines, such as the audit text report).
pub fn leading_token(line: &str, enabled: bool) -> String {
    if !enabled {
        return line.to_string();
    }
    let (head, rest) = match line.find(' ') {
        Some(i) => (&line[..i], &line[i..]),
        None => (line, ""),
    };
    match tone_for(head) {
        Tone::Neutral => line.to_string(),
        t => format!("{}{}", paint(head, t, true), rest),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tty_enables_color() {
        assert!(color_enabled(true, None, None));
        assert!(color_enabled(
            true,
            None,
            Some(OsStr::new("xterm-256color"))
        ));
    }

    #[test]
    fn non_tty_disables_color() {
        assert!(!color_enabled(false, None, None));
        assert!(!color_enabled(false, None, Some(OsStr::new("xterm"))));
    }

    #[test]
    fn no_color_disables_color() {
        assert!(!color_enabled(true, Some(OsStr::new("1")), None));
        assert!(!color_enabled(true, Some(OsStr::new("anything")), None));
        // An empty NO_COLOR does not disable color (no-color.org).
        assert!(color_enabled(true, Some(OsStr::new("")), None));
    }

    #[test]
    fn dumb_terminal_disables_color() {
        assert!(!color_enabled(true, None, Some(OsStr::new("dumb"))));
    }

    #[test]
    fn tones_for_status_tokens() {
        for t in ["ok", "CHANGED", "success", "PASS", "no_drift"] {
            assert_eq!(tone_for(t), Tone::Good, "{t}");
        }
        for t in ["POSSIBLE", "DRIFT", "drift", "blocked", "WARN", "not_run"] {
            assert_eq!(tone_for(t), Tone::Warn, "{t}");
        }
        for t in ["FAILED", "ERROR", "INDET", "apply_failed", "indeterminate"] {
            assert_eq!(tone_for(t), Tone::Bad, "{t}");
        }
        for t in ["skip", "guard", "----", "NOT_AUDITABLE", "web01"] {
            assert_eq!(tone_for(t), Tone::Neutral, "{t}");
        }
    }

    #[test]
    fn paint_keeps_padding_outside_escape() {
        assert_eq!(paint("ok  ", Tone::Good, true), "\x1b[32mok\x1b[0m  ");
        assert_eq!(paint("FAILED", Tone::Bad, true), "\x1b[31mFAILED\x1b[0m");
        assert_eq!(paint("DRIFT", Tone::Warn, true), "\x1b[33mDRIFT\x1b[0m");
    }

    #[test]
    fn disabled_paint_is_identity() {
        for t in ["ok  ", "FAILED", "DRIFT", "x"] {
            assert_eq!(status(t, false), t);
        }
        assert_eq!(leading_token("ERROR a [file]", false), "ERROR a [file]");
    }

    #[test]
    fn neutral_is_never_painted() {
        assert_eq!(paint("skip", Tone::Neutral, true), "skip");
        assert_eq!(
            leading_token("NOT_AUDITABLE c [command]", true),
            "NOT_AUDITABLE c [command]"
        );
    }

    #[test]
    fn leading_token_paints_only_known_status() {
        assert_eq!(
            leading_token("PASS f1 [file]", true),
            "\x1b[32mPASS\x1b[0m f1 [file]"
        );
        assert_eq!(leading_token("    reason: x", true), "    reason: x");
    }
}
