//! The fixed script that copies a file out of another account's directory tree
//! into a backup run directory (DESIGN §40.7).
//!
//! Reading and writing are two identities: the source is observed and read as
//! the account that controls it, the destination is written as root. They need
//! one process tree joined by a pipe, so this is, like `fsstage`, a limited
//! exception to the argv-only command contract (DESIGN §20): the script is the
//! constant [`SCRIPT`], never built at run time, and every varying value is an
//! argument, so no value can become shell syntax. A test pins its SHA-256.

/// The shell that runs the script.
pub const PROGRAM: &str = "/bin/sh";

/// The script text (a constant of the binary).
pub const SCRIPT: &str = include_str!("fsbackup.sh");

/// SHA-256 of [`SCRIPT`], pinned by a test: the script is reviewed as a whole.
pub const SCRIPT_SHA256: &str = "e0d5d13f4a66ade8205117cf63ba3450e68fb8142fdeda0a276de8bb81a1a900";

/// Largest file copied this way. The account can write what it likes into the
/// pipe, and the destination is on a disk root's services need.
pub const MAX_BYTES: u64 = 1024 * 1024 * 1024;

/// Exit code: refused, and no partial destination is left.
pub const EXIT_REJECT: i32 = 3;

/// The command line of one copy.
pub fn argv(uid: u32, gid: u32, src: &str, dest: &str, acl: bool) -> Vec<String> {
    vec![
        "-c".to_string(),
        SCRIPT.to_string(),
        "sh".to_string(),
        uid.to_string(),
        gid.to_string(),
        src.to_string(),
        dest.to_string(),
        MAX_BYTES.to_string(),
        if acl { "1" } else { "0" }.to_string(),
    ]
}

/// The arguments as the command log records them: the constant script is named
/// by its digest instead of being repeated in every record.
pub fn loggable_arg(arg: &str) -> Option<String> {
    (arg == SCRIPT).then(|| format!("[fsbackup.sh sha256:{}]", SCRIPT_SHA256))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn the_script_is_the_reviewed_one() {
        let digest = Sha256::digest(SCRIPT.as_bytes());
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, SCRIPT_SHA256);
    }

    #[test]
    fn every_value_is_an_argument() {
        let a = argv(26, 26, "/var/lib/pgsql/.pgpass", "/s/r/.pgpass", false);
        assert_eq!(a[0], "-c");
        assert_eq!(a[1], SCRIPT);
        assert_eq!(a[2], "sh");
        assert_eq!(&a[3..5], ["26", "26"]);
        assert!(!SCRIPT.contains("/var/lib/pgsql"));
    }
}
