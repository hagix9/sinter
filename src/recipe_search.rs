//! The search behind a recipe or bundle name (DESIGN §40.2).
//!
//! [`crate::project::resolve`] runs this only when the rule of v1.10.0 (an exact
//! name in the current directory or directly in a `recipe_paths` directory)
//! found nothing, so a command that worked before means the same file.
//!
//! A name is either a single recipe, written with its extension (`ssh.yaml`),
//! or a bundle, written as the name of its directory (`02_moge`), which holds
//! exactly one `bundle.yaml`, `bundle.yml` or `bundle.toml`. No extension is
//! ever added to a single recipe, and `02_moge.yaml` never means a bundle
//! directory. A name of several components (`security/ssh.yaml`,
//! `common/02_moge`) matches the last components of a path.
//!
//! The current directory is looked at directly (`./02_moge` only); each
//! `recipe_paths` directory is searched below, to a limited depth and number of
//! entries. Symbolic links are never followed, names starting with `.` are not
//! looked at, and a file inside a bundle directory is found only by a name that
//! names that directory. Every match is a candidate, including one that cannot
//! be used: the caller never chooses among several and never passes over a
//! broken one for another. A directory that cannot be read and a tree beyond
//! the limits stop the search; nothing found up to then is used.

use crate::error::{Result, SinterError};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// The conventional file names of a bundle directory.
pub const BUNDLE_NAMES: [&str; 3] = ["bundle.yaml", "bundle.yml", "bundle.toml"];
/// Levels below a `recipe_paths` directory that are searched.
pub const MAX_DEPTH: usize = 6;
/// Directory entries read by one search, over all `recipe_paths` directories.
pub const MAX_ENTRIES: usize = 20_000;
/// Components of a name.
const MAX_COMPONENTS: usize = 8;
/// Bytes of one component of a name.
const MAX_COMPONENT_BYTES: usize = 128;

/// A name to search for, already checked against the name rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    parts: Vec<String>,
    /// No recipe extension: the name of a bundle directory.
    bundle: bool,
}

/// Whether `name` ends in an extension a recipe may have (DESIGN §4).
pub fn has_recipe_extension(name: &str) -> bool {
    Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| matches!(e.to_ascii_lowercase().as_str(), "yaml" | "yml" | "toml"))
}

fn valid_component(c: &str) -> bool {
    let mut chars = c.chars();
    c.len() <= MAX_COMPONENT_BYTES
        && chars.next().is_some_and(|f| f.is_ascii_alphanumeric())
        && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

impl Query {
    /// The argument as a name, or `None` when it is a path: absolute, starting
    /// with `.` or `..`, with an empty, `.` or `..` component, a trailing `/`,
    /// a character outside `[A-Za-z0-9._-]` or more than 8 components.
    pub fn parse(arg: &Path) -> Option<Query> {
        let s = arg.to_str()?;
        if s.is_empty() || s.starts_with('/') || s.ends_with('/') {
            return None;
        }
        let parts: Vec<String> = s.split('/').map(str::to_string).collect();
        if parts.len() > MAX_COMPONENTS || !parts.iter().all(|c| valid_component(c)) {
            return None;
        }
        let bundle = !has_recipe_extension(parts.last().expect("not empty"));
        Some(Query { parts, bundle })
    }

    /// One component.
    pub fn is_bare(&self) -> bool {
        self.parts.len() == 1
    }

    /// The name of a bundle directory, not of a single recipe.
    pub fn is_bundle(&self) -> bool {
        self.bundle
    }

    fn last(&self) -> &str {
        self.parts.last().expect("not empty")
    }

    /// Whether `rel` (components below a search directory) ends in this name,
    /// and the name reaches the nearest bundle directory above it, if any.
    fn matches(&self, rel: &[OsString], bundle_above: Option<usize>) -> bool {
        let k = self.parts.len();
        if rel.len() < k {
            return false;
        }
        let start = rel.len() - k;
        let same = rel[start..]
            .iter()
            .zip(&self.parts)
            .all(|(a, b)| a.as_bytes() == b.as_bytes());
        same && bundle_above.is_none_or(|b| start <= b)
    }
}

impl std::fmt::Display for Query {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.parts.join("/"))
    }
}

/// What a candidate is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A single recipe file, or something else under that name (a link, a
    /// device): it is judged when it is used.
    File,
    /// A directory holding at least one conventional bundle file.
    BundleDirectory,
    /// Under a bundle name, something that is not a directory: never usable.
    NotADirectory,
}

#[derive(Debug, Clone)]
pub struct Candidate {
    pub path: PathBuf,
    pub kind: Kind,
    /// Found in the current directory rather than below a `recipe_paths` one.
    pub here: bool,
    id: Option<(u64, u64)>,
}

/// Every candidate, and files the name would have meant with another spelling
/// (only ever shown, never used).
#[derive(Debug, Default)]
pub struct Outcome {
    pub candidates: Vec<Candidate>,
    pub hints: Vec<PathBuf>,
    /// `recipe_paths` directories that do not exist.
    pub missing: Vec<PathBuf>,
}

/// The entry itself, never what a link points to: a link and its target are two
/// candidates, so a link is never passed over because its target was found (the
/// same file reached through two overlapping `recipe_paths` is still one).
fn identity(path: &Path) -> Option<(u64, u64)> {
    std::fs::symlink_metadata(path)
        .ok()
        .map(|m| (m.dev(), m.ino()))
}

/// Whether the directory holds a conventional bundle file (whatever it is).
fn holds_bundle_file(dir: &Path) -> Result<bool> {
    for name in BUNDLE_NAMES {
        match std::fs::symlink_metadata(dir.join(name)) {
            Ok(_) => return Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(cannot(&dir.join(name), e)),
        }
    }
    Ok(false)
}

fn cannot(path: &Path, e: impl std::fmt::Display) -> SinterError {
    SinterError::schema(format!(
        "recipe search: cannot read {}: {e}; nothing found so far is used, name the recipe by its path",
        path.display()
    ))
}

struct Walk<'a> {
    query: &'a Query,
    entries: usize,
    out: Outcome,
}

impl Walk<'_> {
    fn add(&mut self, path: PathBuf, kind: Kind, here: bool) {
        let id = identity(&path);
        if id.is_some() && self.out.candidates.iter().any(|c| c.id == id) {
            return;
        }
        self.out.candidates.push(Candidate {
            path,
            kind,
            here,
            id,
        });
    }

    fn hint(&mut self, path: PathBuf) {
        if !self.out.hints.contains(&path) {
            self.out.hints.push(path);
        }
    }

    /// Hints: a single recipe written without its extension, or a bundle
    /// directory written with one.
    fn consider_hint(&mut self, name: &OsStr, path: &Path, is_bundle_dir: bool) {
        let Some(name) = name.to_str() else {
            return;
        };
        let last = self.query.last();
        if self.query.bundle {
            if !is_bundle_dir
                && has_recipe_extension(name)
                && Path::new(name).file_stem() == Some(OsStr::new(last))
            {
                self.hint(path.to_path_buf());
            }
        } else if is_bundle_dir && Path::new(last).file_stem() == Some(OsStr::new(name)) {
            self.hint(path.to_path_buf());
        }
    }

    fn dir(&mut self, dir: &Path, rel: &[OsString], bundle_above: Option<usize>) -> Result<()> {
        let entries = std::fs::read_dir(dir).map_err(|e| cannot(dir, e))?;
        let mut sub = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| cannot(dir, e))?;
            self.entries += 1;
            if self.entries > MAX_ENTRIES {
                return Err(SinterError::schema(format!(
                    "recipe search for {} stopped: more than {MAX_ENTRIES} entries under the recipe_paths directories; nothing found so far is used, name the recipe by its path",
                    self.query
                )));
            }
            let name = entry.file_name();
            if name.as_bytes().first() == Some(&b'.') {
                continue;
            }
            let path = entry.path();
            let ft = entry.file_type().map_err(|e| cannot(&path, e))?;
            let mut here: Vec<OsString> = rel.to_vec();
            here.push(name.clone());
            if here.len() > MAX_DEPTH {
                return Err(SinterError::schema(format!(
                    "recipe search for {} stopped: {} is more than {MAX_DEPTH} levels below a recipe_paths directory; nothing found so far is used, name the recipe by its path",
                    self.query,
                    path.display()
                )));
            }
            let named = name.as_bytes() == self.query.last().as_bytes();
            if ft.is_dir() {
                let is_bundle_dir = holds_bundle_file(&path)?;
                if named
                    && self.query.bundle
                    && is_bundle_dir
                    && self.query.matches(&here, bundle_above)
                {
                    self.add(path.clone(), Kind::BundleDirectory, false);
                }
                self.consider_hint(&name, &path, is_bundle_dir);
                let above = if is_bundle_dir {
                    Some(here.len() - 1)
                } else {
                    bundle_above
                };
                sub.push((path, here, above));
            } else {
                if named && self.query.matches(&here, bundle_above) {
                    let kind = if self.query.bundle {
                        Kind::NotADirectory
                    } else {
                        Kind::File
                    };
                    self.add(path.clone(), kind, false);
                }
                self.consider_hint(&name, &path, false);
            }
        }
        // Sorted, so that messages list candidates in a stable order.
        sub.sort_by(|a, b| a.0.cmp(&b.0));
        for (path, here, above) in sub {
            self.dir(&path, &here, above)?;
        }
        Ok(())
    }
}

/// Collect the candidates for `query`: `./<name>` when `here` (a bundle name of
/// one component only), and below every directory of `roots`.
pub fn search(query: &Query, here: bool, roots: &[PathBuf]) -> Result<Outcome> {
    let mut walk = Walk {
        query,
        entries: 0,
        out: Outcome::default(),
    };
    if here && query.is_bare() && query.bundle {
        let p = PathBuf::from(query.last());
        match std::fs::symlink_metadata(&p) {
            Ok(m) if m.is_dir() => {
                if holds_bundle_file(&p)? {
                    walk.add(p, Kind::BundleDirectory, true);
                }
            }
            Ok(_) => walk.add(p, Kind::NotADirectory, true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(cannot(&p, e)),
        }
        for ext in ["yaml", "yml", "toml"] {
            let f = PathBuf::from(format!("{}.{ext}", query.last()));
            if std::fs::symlink_metadata(&f).is_ok() {
                walk.hint(f);
            }
        }
    }
    for root in roots {
        match std::fs::symlink_metadata(root) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                walk.out.missing.push(root.clone());
                continue;
            }
            Err(e) => return Err(cannot(root, e)),
            Ok(_) => {}
        }
        walk.dir(root, &[], None)?;
    }
    walk.out.candidates.sort_by(|a, b| a.path.cmp(&b.path));
    walk.out.hints.sort();
    Ok(walk.out)
}

/// The one conventional bundle file of a bundle directory.
pub fn bundle_file(dir: &Path) -> Result<PathBuf> {
    let mut present = Vec::new();
    for name in BUNDLE_NAMES {
        match std::fs::symlink_metadata(dir.join(name)) {
            Ok(_) => present.push(name),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(cannot(&dir.join(name), e)),
        }
    }
    match present.as_slice() {
        [one] => Ok(dir.join(one)),
        [] => Err(SinterError::schema(format!(
            "bundle directory {} holds no {}",
            dir.display(),
            BUNDLE_NAMES.join(", ")
        ))),
        _ => Err(SinterError::schema(format!(
            "bundle directory {} holds several bundle files ({}); Sinter never picks one, keep one or name the file by its path",
            dir.display(),
            present.join(", ")
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(s: &str) -> Option<Query> {
        Query::parse(Path::new(s))
    }

    #[test]
    fn names_and_paths_are_told_apart() {
        for name in [
            "nginx.yaml",
            "02_moge",
            "security/ssh.yaml",
            "common/02_moge",
            "a.TOML",
        ] {
            assert!(q(name).is_some(), "{name}");
        }
        for path in [
            "/abs.yaml",
            "./nginx.yaml",
            "../nginx.yaml",
            "a/../b.yaml",
            "a/./b.yaml",
            "a//b.yaml",
            "dir/",
            ".hidden.yaml",
            "-x.yaml",
            "sp ace.yaml",
            "a:b.yaml",
            "é.yaml",
            "",
            "a/b/c/d/e/f/g/h/i.yaml",
        ] {
            assert!(q(path).is_none(), "{path}");
        }
        assert!(!q("nginx.yaml").unwrap().is_bundle());
        assert!(!q("nginx.YML").unwrap().is_bundle());
        assert!(q("02_moge").unwrap().is_bundle());
        assert!(
            q("nginx").unwrap().is_bundle(),
            "no extension: a bundle name"
        );
        assert!(q("x.json").unwrap().is_bundle());
    }

    #[test]
    fn a_name_matches_the_last_components_and_reaches_its_bundle() {
        let rel = |s: &str| -> Vec<OsString> { s.split('/').map(OsString::from).collect() };
        let ssh = q("ssh.yaml").unwrap();
        assert!(ssh.matches(&rel("security/ssh.yaml"), None));
        assert!(q("security/ssh.yaml")
            .unwrap()
            .matches(&rel("a/security/ssh.yaml"), None));
        assert!(!q("other/ssh.yaml")
            .unwrap()
            .matches(&rel("security/ssh.yaml"), None));
        // Inside the bundle directory common/02_moge (index 1).
        let member = rel("common/02_moge/packages.yaml");
        assert!(!q("packages.yaml").unwrap().matches(&member, Some(1)));
        assert!(q("02_moge/packages.yaml")
            .unwrap()
            .matches(&member, Some(1)));
        assert!(q("common/02_moge/packages.yaml")
            .unwrap()
            .matches(&member, Some(1)));
    }
}
