//! FS-2: the fixed staging script and the contract of its answers.
//!
//! Staging, publication and discard of a file or link run as **one call of a
//! fixed shell script** (`fsstage.sh`) per step: a single process that opens the
//! directory and the staging directory once and keeps working on those open
//! directories, so that a name another account swaps in between two commands
//! cannot redirect a later one (DESIGN §23.4).
//!
//! This is a deliberate, limited exception to the argv-only command contract
//! (DESIGN §20): the script is the constant [`SCRIPT`], never built at run
//! time, never extended, and used for these three operations only. Every
//! varying value is an argument (`sh -c <script> sh <op> <args…>`), so no
//! value can become shell syntax. A test pins the script's SHA-256.

use crate::executor::Output;

/// The shell that runs the script. It is also what the command log shows.
pub const PROGRAM: &str = "/bin/sh";

/// The script text (a constant of the binary).
pub const SCRIPT: &str = include_str!("fsstage.sh");

/// SHA-256 of [`SCRIPT`]. A change to the script is a change to this value, which a
/// test pins: the script is reviewed as a whole, never edited in passing.
pub const SCRIPT_SHA256: &str = "7614daf7dcd9365163e46118dbe930d601468db16c60ce9d025005823ce8469e";

/// Exit code: identity not proven. No existing entry was changed or removed and nothing was
/// published; a stage refused after its directory was made leaves that empty directory.
pub const EXIT_REJECT: i32 = 3;
/// Exit code: the publication itself failed; nothing was published. Together with
/// [`EXIT_REJECT`] the only exit of `publish` that proves it; any other code may follow a
/// successful publication.
pub const EXIT_PUBLISH_FAILED: i32 = 4;
/// Exit code: the operation is done, but a second name of the payload remains in
/// the staging directory, or its state is unknown.
pub const EXIT_ATTENTION: i32 = 5;

/// The command line of one step: `-c <script> sh <op> <args…>`.
pub fn argv(op_args: &[String]) -> Vec<String> {
    let mut v = vec!["-c".to_string(), SCRIPT.to_string(), "sh".to_string()];
    v.extend(op_args.iter().cloned());
    v
}

/// The arguments as the command log records them: the constant script is named
/// by its digest instead of being repeated in every record (also when the call
/// is wrapped, for example by `setpriv`).
pub fn loggable_args(args: &[String]) -> Vec<String> {
    args.iter()
        .map(|a| {
            if a == SCRIPT {
                format!("[fsstage.sh sha256:{}]", SCRIPT_SHA256)
            } else {
                a.clone()
            }
        })
        .collect()
}

/// What became of the staging directory, as the script reports it on its last
/// stdout line. It is a fact about the cleanup only: it never says whether the
/// file was published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cleanup {
    /// The staging directory is gone (proved by the link count of the directory
    /// the script held open, not by a name).
    Clean,
    /// The empty staging directory is still at this path (possibly under
    /// another name): harmless, and nothing else was touched.
    Left(String),
    /// The payload could not be removed: a second name of the file stays in the
    /// staging directory at this path.
    LinkRemains(String),
    /// The state could not be determined (or the answer was not understood).
    Unknown,
}

impl Cleanup {
    /// The cleanup left something that needs a person's attention (a second
    /// name of the file, or an unknown state), as opposed to a harmless empty
    /// directory or nothing.
    pub fn needs_attention(&self) -> bool {
        matches!(self, Cleanup::LinkRemains(_) | Cleanup::Unknown)
    }

    /// Whether the staging directory is gone.
    pub fn is_clean(&self) -> bool {
        matches!(self, Cleanup::Clean)
    }

    /// A sentence for a result's reason or note.
    pub fn describe(&self) -> String {
        match self {
            Cleanup::Clean => "staging cleanup succeeded".to_string(),
            Cleanup::Left(p) => format!(
                "the empty staging directory {} was left in place (it is harmless; remove it when convenient)",
                crate::diff::sanitize_line(p)
            ),
            Cleanup::LinkRemains(p) => format!(
                "the staging directory {} still holds a second name for the file and was not removed; \
                 remove that name, then the directory",
                crate::diff::sanitize_line(p)
            ),
            Cleanup::Unknown => {
                "the state of the staging directory could not be determined; look for a stray \
                 .sinter-stage.* directory beside the file"
                    .to_string()
            }
        }
    }
}

/// The cleanup line of an answer: the last non-empty stdout line. Anything that
/// is not exactly one of the four forms is `Unknown` (fail-closed).
pub fn parse_cleanup(out: &Output) -> Cleanup {
    if out.stdout_truncated {
        return Cleanup::Unknown;
    }
    let Ok(text) = std::str::from_utf8(&out.stdout) else {
        return Cleanup::Unknown;
    };
    let Some(line) = text.lines().rev().find(|l| !l.is_empty()) else {
        return Cleanup::Unknown;
    };
    let Some(rest) = line.strip_prefix("CLEANUP:") else {
        return Cleanup::Unknown;
    };
    if rest == "clean" {
        return Cleanup::Clean;
    }
    if rest == "unknown" {
        return Cleanup::Unknown;
    }
    if let Some(p) = rest.strip_prefix("left:") {
        if p.starts_with('/') {
            return Cleanup::Left(p.to_string());
        }
    }
    if let Some(p) = rest.strip_prefix("link-remains:") {
        if p.starts_with('/') {
            return Cleanup::LinkRemains(p.to_string());
        }
    }
    Cleanup::Unknown
}

/// A staging directory the script made and left in place for the next step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Staged {
    /// `.sinter-stage.XXXXXXXX`, a name beside the final path.
    pub name: String,
    /// The creation-time group that identifies the directory (root), or `-`.
    pub group: String,
    /// `device:inode` of the staging directory.
    pub dir_id: String,
    /// `device:inode` of the payload.
    pub payload_id: String,
}

fn is_dev_ino(s: &str) -> bool {
    let mut it = s.split(':');
    let (Some(a), Some(b), None) = (it.next(), it.next(), it.next()) else {
        return false;
    };
    !a.is_empty()
        && !b.is_empty()
        && a.bytes().all(|c| c.is_ascii_digit())
        && b.bytes().all(|c| c.is_ascii_digit())
}

/// The answer of `stage` / `stagelink`: exactly one line of four well-formed
/// fields; anything else is not accepted.
pub fn parse_staged(out: &Output) -> Option<Staged> {
    if out.stdout_truncated {
        return None;
    }
    let text = std::str::from_utf8(&out.stdout).ok()?;
    let line = text.strip_suffix('\n')?;
    if line.contains('\n') {
        return None;
    }
    let f: Vec<&str> = line.split(' ').collect();
    if f.len() != 4 {
        return None;
    }
    let name_ok = f[0]
        .strip_prefix(".sinter-stage.")
        .is_some_and(|s| !s.is_empty() && s.bytes().all(|c| c.is_ascii_alphanumeric()));
    let group_ok = f[1] == "-" || (!f[1].is_empty() && f[1].bytes().all(|c| c.is_ascii_digit()));
    if !(name_ok && group_ok && is_dev_ino(f[2]) && is_dev_ino(f[3])) {
        return None;
    }
    Some(Staged {
        name: f[0].to_string(),
        group: f[1].to_string(),
        dir_id: f[2].to_string(),
        payload_id: f[3].to_string(),
    })
}

/// The reason of a `REJECT:` line on stderr (the script's own wording, which
/// never carries a value), if the script rejected.
pub fn reject_reason(out: &Output) -> Option<String> {
    let text = String::from_utf8_lossy(&out.stderr);
    text.lines()
        .rev()
        .find_map(|l| l.strip_prefix("REJECT: "))
        .map(|r| crate::diff::sanitize_line(r.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::Completion;

    fn out(stdout: &str, stderr: &str) -> Output {
        Output {
            completion: Completion::Exited(0),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
            stdout_truncated: false,
            stderr_truncated: false,
        }
    }

    #[test]
    fn the_script_is_pinned() {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(SCRIPT.as_bytes());
        let hex: String = h.finalize().iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            hex, SCRIPT_SHA256,
            "src/fsstage.sh changed: it is reviewed as a whole; update SCRIPT_SHA256 only with that review"
        );
    }

    #[test]
    fn the_script_is_a_constant_without_interpolation_points() {
        // No placeholder syntax of any template a caller could fill in.
        assert!(!SCRIPT.contains("{}") && !SCRIPT.contains("{0}") && !SCRIPT.contains("%s%s%s"));
        assert!(SCRIPT.starts_with("# Sinter fixed staging script"));
        assert!(SCRIPT.ends_with("esac\n"));
    }

    #[test]
    fn argv_passes_values_only_after_the_script_and_never_inside_it() {
        let v = argv(&["stage".to_string(), "/d; rm -rf /".to_string()]);
        assert_eq!(v[0], "-c");
        assert_eq!(v[1], SCRIPT);
        assert_eq!(v[2], "sh");
        assert_eq!(v[3], "stage");
        assert_eq!(v[4], "/d; rm -rf /");
        assert!(!v[1].contains("rm -rf /"));
    }

    #[test]
    fn the_log_names_the_script_by_digest() {
        let v = argv(&["discard".to_string()]);
        let l = loggable_args(&v);
        assert_eq!(l[1], format!("[fsstage.sh sha256:{}]", SCRIPT_SHA256));
        assert_eq!(l[3], "discard");
        // Anything else is recorded as it is.
        let other = vec!["-c".to_string(), "echo hi".to_string(), "sh".to_string()];
        assert_eq!(loggable_args(&other), other);
        // Wrapped (for example by setpriv), the script is still named, not repeated.
        let mut wrapped = vec![
            "--reuid".to_string(),
            "1001".to_string(),
            PROGRAM.to_string(),
        ];
        wrapped.extend(v.iter().cloned());
        let l = loggable_args(&wrapped);
        assert!(l.iter().all(|a| a != SCRIPT));
        assert!(l.contains(&format!("[fsstage.sh sha256:{}]", SCRIPT_SHA256)));
    }

    #[test]
    fn cleanup_answers_are_parsed_strictly() {
        assert_eq!(parse_cleanup(&out("CLEANUP:clean\n", "")), Cleanup::Clean);
        assert_eq!(
            parse_cleanup(&out("CLEANUP:left:/d/.sinter-stage.AbC\n", "")),
            Cleanup::Left("/d/.sinter-stage.AbC".into())
        );
        assert_eq!(
            parse_cleanup(&out("CLEANUP:link-remains:/d/.sinter-stage.AbC\n", "")),
            Cleanup::LinkRemains("/d/.sinter-stage.AbC".into())
        );
        assert_eq!(
            parse_cleanup(&out("CLEANUP:unknown\n", "")),
            Cleanup::Unknown
        );
        // The last line decides; earlier text is ignored.
        assert_eq!(
            parse_cleanup(&out("noise\nCLEANUP:clean\n", "")),
            Cleanup::Clean
        );
        // Everything else fails closed.
        for bad in [
            "",
            "\n",
            "clean\n",
            "CLEANUP:\n",
            "CLEANUP:cleaned\n",
            "CLEANUP:left:relative\n",
            "CLEANUP:left:\n",
            "CLEANUP:link-remains:\n",
            "CLEANUP:clean\nsomething after\n",
        ] {
            assert_eq!(parse_cleanup(&out(bad, "")), Cleanup::Unknown, "{:?}", bad);
        }
        let mut t = out("CLEANUP:clean\n", "");
        t.stdout_truncated = true;
        assert_eq!(parse_cleanup(&t), Cleanup::Unknown);
        let mut bad_utf8 = out("", "");
        bad_utf8.stdout = vec![0xff, 0xfe];
        assert_eq!(parse_cleanup(&bad_utf8), Cleanup::Unknown);
    }

    #[test]
    fn only_a_second_name_or_an_unknown_state_needs_attention() {
        assert!(!Cleanup::Clean.needs_attention());
        assert!(!Cleanup::Left("/d/.sinter-stage.A".into()).needs_attention());
        assert!(Cleanup::LinkRemains("/d/.sinter-stage.A".into()).needs_attention());
        assert!(Cleanup::Unknown.needs_attention());
        assert!(Cleanup::Clean.is_clean());
        assert!(!Cleanup::Left("/x".into()).is_clean());
    }

    #[test]
    fn staged_answers_are_parsed_strictly() {
        let ok = parse_staged(&out(
            ".sinter-stage.AbCd1234 3000000001 2049:77 2049:78\n",
            "",
        ));
        assert_eq!(
            ok,
            Some(Staged {
                name: ".sinter-stage.AbCd1234".into(),
                group: "3000000001".into(),
                dir_id: "2049:77".into(),
                payload_id: "2049:78".into(),
            })
        );
        assert!(parse_staged(&out(".sinter-stage.AbCd1234 - 2049:77 2049:78\n", "")).is_some());
        for bad in [
            "",
            "\n",
            ".sinter-stage.AbCd1234 - 2049:77 2049:78",
            ".sinter-stage.AbCd1234 - 2049:77\n",
            ".sinter-stage.AbCd1234 - 2049:77 2049:78 x\n",
            ".sinter-stage.AbCd1234 - 2049:77 2049:78\nextra\n",
            "stage.AbCd1234 - 2049:77 2049:78\n",
            ".sinter-stage. - 2049:77 2049:78\n",
            ".sinter-stage.a/b - 2049:77 2049:78\n",
            ".sinter-stage.*  - 2049:77 2049:78\n",
            ".sinter-stage.AbCd1234 x 2049:77 2049:78\n",
            ".sinter-stage.AbCd1234 - 2049 2049:78\n",
            ".sinter-stage.AbCd1234 - 2049:7:7 2049:78\n",
            ".sinter-stage.AbCd1234 - a:77 2049:78\n",
        ] {
            assert!(parse_staged(&out(bad, "")).is_none(), "{:?}", bad);
        }
        let mut t = out(".sinter-stage.AbCd1234 - 2049:77 2049:78\n", "");
        t.stdout_truncated = true;
        assert!(parse_staged(&t).is_none());
    }

    #[test]
    fn a_reject_reason_is_the_scripts_own_line() {
        let o = out("", "REJECT: the directory has the setgid bit\n");
        assert_eq!(
            reject_reason(&o).as_deref(),
            Some("the directory has the setgid bit")
        );
        assert_eq!(reject_reason(&out("", "mv: cannot move\n")), None);
        // Control characters are not carried into a message.
        let o = out("", "REJECT: x\u{1b}[31my\n");
        assert!(!reject_reason(&o).unwrap().contains('\u{1b}'));
    }
}
