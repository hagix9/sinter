use crate::error::{Result, SinterError};

/// Validate a managed filesystem path per DESIGN §4.10.
/// Must be absolute UTF-8, no `.`/`..`, no repeated separators, no trailing slash
/// except root, no NUL, no empty.
pub fn validate_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(SinterError::schema("path must not be empty"));
    }
    if path.contains('\0') {
        return Err(SinterError::schema("path must not contain NUL"));
    }
    if !path.starts_with('/') {
        return Err(SinterError::schema(format!(
            "path must be absolute: {}",
            path
        )));
    }
    if path == "/" {
        return Ok(());
    }
    if path.ends_with('/') {
        return Err(SinterError::schema(format!(
            "path must not have a trailing slash: {}",
            path
        )));
    }
    let body = &path[1..];
    for comp in body.split('/') {
        if comp.is_empty() {
            return Err(SinterError::schema(format!(
                "path must not contain repeated separators: {}",
                path
            )));
        }
        if comp == "." || comp == ".." {
            return Err(SinterError::schema(format!(
                "path must not contain . or .. components: {}",
                path
            )));
        }
    }
    Ok(())
}

/// Split an absolute path into its parent directory and final component.
pub fn parent_and_name(path: &str) -> (String, String) {
    if path == "/" {
        return ("/".to_string(), "".to_string());
    }
    match path.rfind('/') {
        Some(0) => ("/".to_string(), path[1..].to_string()),
        Some(i) => (path[..i].to_string(), path[i + 1..].to_string()),
        None => ("/".to_string(), path.to_string()),
    }
}

/// All ancestor directories of an absolute path, from root to parent, inclusive.
pub fn ancestor_dirs(path: &str) -> Vec<String> {
    if path == "/" {
        return vec!["/".to_string()];
    }
    let mut parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    parts.pop(); // remove final component
    let mut out = vec!["/".to_string()];
    let mut cur = String::new();
    for p in parts {
        cur.push('/');
        cur.push_str(p);
        out.push(cur.clone());
    }
    out
}

pub fn parse_mode(s: &str) -> Result<u32> {
    if s.len() != 4 {
        return Err(SinterError::schema(format!(
            "mode must be a quoted four-digit octal string, got {:?}",
            s
        )));
    }
    let mut v: u32 = 0;
    for c in s.chars() {
        let d = c
            .to_digit(8)
            .ok_or_else(|| SinterError::schema(format!("invalid octal mode: {:?}", s)))?;
        v = v * 8 + d;
    }
    if v > 0o7777 {
        return Err(SinterError::schema(format!("mode out of range: {:?}", s)));
    }
    Ok(v)
}

pub fn mode_to_string(mode: u32) -> String {
    format!("{:04o}", mode & 0o7777)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_paths() {
        assert!(validate_path("/").is_ok());
        assert!(validate_path("/etc/nginx/nginx.conf").is_ok());
    }

    #[test]
    fn rejects_bad_paths() {
        assert!(validate_path("etc/x").is_err());
        assert!(validate_path("/etc/../x").is_err());
        assert!(validate_path("/etc/./x").is_err());
        assert!(validate_path("/etc//x").is_err());
        assert!(validate_path("/etc/x/").is_err());
        assert!(validate_path("/etc/x\0").is_err());
        assert!(validate_path("").is_err());
    }

    #[test]
    fn ancestors() {
        assert_eq!(ancestor_dirs("/a/b/c"), vec!["/", "/a", "/a/b"]);
        assert_eq!(ancestor_dirs("/a"), vec!["/"]);
        assert_eq!(ancestor_dirs("/"), vec!["/"]);
    }

    #[test]
    fn mode_parsing() {
        assert_eq!(parse_mode("0644").unwrap(), 0o644);
        assert_eq!(parse_mode("0600").unwrap(), 0o600);
        assert!(parse_mode("644").is_err());
        assert!(parse_mode("0899").is_err());
    }
}
