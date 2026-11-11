//! The project file and the recipe search (DESIGN §40.1, §40.2).
//!
//! A project file is found only in the current directory, or named with
//! `--config`. It is never searched for upwards. A file that arrives without
//! having been named is held to the rules of [`crate::inventory_detect`], and so
//! is everything a project file names.

use crate::error::{Result, SinterError};
use crate::inventory_detect::{read_candidate_trusted, read_named_trusted, Who};
use crate::value::Value;
use std::path::{Component, Path, PathBuf};

/// The names looked for in the current directory.
pub const PROJECT_NAMES: [&str; 3] = ["sinter.yaml", "sinter.yml", "sinter.toml"];

const FIELDS: &[&str] = &[
    "version",
    "recipe_paths",
    "inventory",
    "vars_files",
    "backup",
    "default_target",
    "allow_implicit_apply",
    "strict_vars",
];

/// Largest project file read.
pub const MAX_PROJECT_BYTES: u64 = 1024 * 1024;

const DETECTED: Who = Who {
    label: "project file",
    ask: "name a file you trust with --config, or ignore it with --no-config",
};
const NAMED: Who = Who {
    label: "file named by the project file",
    ask: "fix its owner or mode, or name it on the command line",
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectSource {
    /// `--config`.
    Explicit,
    /// Found in the current directory.
    Detected,
}

impl ProjectSource {
    pub fn label(self) -> &'static str {
        match self {
            ProjectSource::Explicit => "--config",
            ProjectSource::Detected => "auto-detected",
        }
    }

    pub fn key(self) -> &'static str {
        match self {
            ProjectSource::Explicit => "explicit",
            ProjectSource::Detected => "detected",
        }
    }
}

/// A project file that passed its own checks. Every path is absolute or relative
/// to the current directory as given by `path`'s directory, already joined.
#[derive(Debug, Clone)]
pub struct ProjectFile {
    pub path: PathBuf,
    pub source: ProjectSource,
    pub recipe_paths: Vec<PathBuf>,
    pub inventory: Option<PathBuf>,
    pub vars_files: Vec<PathBuf>,
    pub backup_directory: Option<String>,
    pub default_target: Option<String>,
    pub allow_implicit_apply: bool,
    pub strict_vars: bool,
}

/// Where the recipe argument was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecipeVia {
    /// As given on the command line.
    #[default]
    Given,
    /// Found through `recipe_paths`.
    RecipePaths,
    /// A bundle directory directly in the current directory.
    CurrentDirectory,
}

impl RecipeVia {
    pub fn key(self) -> &'static str {
        match self {
            RecipeVia::Given => "given",
            RecipeVia::RecipePaths => "recipe_paths",
            RecipeVia::CurrentDirectory => "current_directory",
        }
    }
}

/// How the name matched (DESIGN §40.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecipeMatch {
    /// The argument as given, or the exact name of v1.10.0.
    #[default]
    Exact,
    /// A single recipe found below a `recipe_paths` directory, or by a name of
    /// several components.
    Search,
    /// The name of a bundle directory.
    BundleDirectory,
}

impl RecipeMatch {
    pub fn key(self) -> &'static str {
        match self {
            RecipeMatch::Exact => "exact",
            RecipeMatch::Search => "search",
            RecipeMatch::BundleDirectory => "bundle_directory",
        }
    }
}

/// The file a recipe argument means, and how it was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRecipe {
    pub path: PathBuf,
    pub via: RecipeVia,
    pub how: RecipeMatch,
}

fn bad(path: &Path, what: impl std::fmt::Display) -> SinterError {
    SinterError::schema(format!("project file {}: {what}", path.display()))
}

/// Find and read the project file of this command. `Ok(None)` means there is
/// none, and the command is what it was without this feature.
pub fn load_project(explicit: Option<&Path>, no_config: bool) -> Result<Option<ProjectFile>> {
    if no_config {
        return Ok(None);
    }
    if let Some(path) = explicit {
        return load_explicit(path).map(Some);
    }
    let Ok(cwd) = std::env::current_dir() else {
        // A current directory that no longer exists holds no file.
        return Ok(None);
    };
    load_detected(&cwd)
}

fn load_explicit(path: &Path) -> Result<ProjectFile> {
    use std::io::Read;
    let abs = absolute(path)?;
    let meta = std::fs::metadata(&abs).map_err(|e| bad(&abs, format!("cannot read: {e}")))?;
    if !meta.is_file() {
        return Err(bad(&abs, "is not a regular file"));
    }
    let mut bytes = Vec::new();
    std::fs::File::open(&abs)
        .and_then(|f| f.take(MAX_PROJECT_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|e| bad(&abs, format!("cannot read: {e}")))?;
    if bytes.len() as u64 > MAX_PROJECT_BYTES {
        return Err(bad(&abs, format!("larger than {MAX_PROJECT_BYTES} bytes")));
    }
    parse_project(&bytes, &abs, ProjectSource::Explicit)
}

fn load_detected(cwd: &Path) -> Result<Option<ProjectFile>> {
    let mut present = Vec::new();
    for name in PROJECT_NAMES {
        match std::fs::symlink_metadata(cwd.join(name)) {
            Ok(_) => present.push(name),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(bad(&cwd.join(name), format!("cannot inspect it: {e}")));
            }
        }
    }
    if present.is_empty() {
        return Ok(None);
    }
    if present.len() > 1 {
        return Err(SinterError::schema(format!(
            "several project files were found in {} ({}); Sinter never picks one, {}",
            cwd.display(),
            present.join(", "),
            DETECTED.ask
        )));
    }
    let (bytes, path) = read_candidate_trusted(DETECTED, cwd, present[0])?;
    parse_project(&bytes, &path, ProjectSource::Detected).map(Some)
}

/// How far up [`unused_parent_project`] looks.
const PARENT_NOTE_LEVELS: usize = 8;

/// A project file in a directory above `cwd`, which is not used: a command run from
/// a subdirectory should not look as if it had its project's settings. The name is
/// only looked at, never opened, so this cannot change what the command does. Stops
/// at `home` (not looked at) and at a repository's top.
pub fn unused_parent_project(cwd: &Path, home: Option<&Path>) -> Option<PathBuf> {
    for dir in cwd.ancestors().skip(1).take(PARENT_NOTE_LEVELS) {
        if Some(dir) == home {
            return None;
        }
        for name in PROJECT_NAMES {
            let candidate = dir.join(name);
            if std::fs::symlink_metadata(&candidate).is_ok() {
                return Some(candidate);
            }
        }
        if std::fs::symlink_metadata(dir.join(".git")).is_ok() {
            return None;
        }
    }
    None
}

fn absolute(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.components().collect());
    }
    let cwd = std::env::current_dir().map_err(|e| {
        SinterError::schema(format!(
            "cannot determine the current directory for {}: {e}",
            path.display()
        ))
    })?;
    Ok(cwd.join(path).components().collect())
}

/// A path of the file: relative means relative to the file's directory.
fn joined(base: &Path, value: &str) -> PathBuf {
    if Path::new(value).is_absolute() {
        Path::new(value).components().collect()
    } else {
        base.join(value).components().collect()
    }
}

fn path_string(path: &Path, field: &str, v: &Value) -> Result<String> {
    let s = v
        .as_str()
        .ok_or_else(|| bad(path, format!("{field} must be a path string")))?;
    if s.is_empty() || s.contains('\0') || s.chars().any(char::is_control) {
        return Err(bad(
            path,
            format!("{field} must be a non-empty path without control characters"),
        ));
    }
    if s.starts_with('~') || s.contains('$') {
        return Err(bad(
            path,
            format!("{field}: ~ and environment variables are not expanded; write the path"),
        ));
    }
    Ok(s.to_string())
}

fn path_list(path: &Path, base: &Path, field: &str, v: &Value) -> Result<Vec<PathBuf>> {
    let items = v
        .as_list()
        .ok_or_else(|| bad(path, format!("{field} must be a list of paths")))?;
    let mut out: Vec<PathBuf> = Vec::new();
    for (i, item) in items.iter().enumerate() {
        let p = joined(base, &path_string(path, &format!("{field}[{i}]"), item)?);
        if out.contains(&p) {
            return Err(bad(
                path,
                format!("{field} lists {} more than once", p.display()),
            ));
        }
        out.push(p);
    }
    Ok(out)
}

fn flag(path: &Path, field: &str, v: Option<&Value>) -> Result<bool> {
    match v {
        None => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        Some(_) => Err(bad(path, format!("{field} must be true or false"))),
    }
}

/// The schema of a project file. Messages carry field names and paths, and the
/// parsers report positions only.
pub(crate) fn parse_project(
    bytes: &[u8],
    path: &Path,
    source: ProjectSource,
) -> Result<ProjectFile> {
    let text = std::str::from_utf8(bytes).map_err(|_| bad(path, "is not valid UTF-8"))?;
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    let root = match ext.as_deref() {
        Some("yaml" | "yml") => crate::varsfile::parse_yaml_quiet(text),
        Some("toml") => crate::varsfile::parse_toml_quiet(text),
        _ => Err("has an unsupported extension (use .yaml, .yml or .toml)".to_string()),
    }
    .map_err(|e| bad(path, e))?;
    let map = root
        .as_map()
        .ok_or_else(|| bad(path, "the top level must be a map"))?;
    for k in map.keys() {
        if !FIELDS.contains(&k.as_str()) {
            return Err(bad(
                path,
                format!(
                    "unknown field (not shown; allowed: {}). Is this a recipe? {} in the current directory is read as the project file: rename it, or run with --no-config",
                    FIELDS.join(", "),
                    path.file_name().map_or(String::new(), |n| n.to_string_lossy().to_string())
                ),
            ));
        }
    }
    match map.get("version") {
        Some(Value::Int(1)) => {}
        Some(_) => return Err(bad(path, "version must be 1")),
        None => return Err(bad(path, "missing required field version")),
    }
    let base = path.parent().unwrap_or_else(|| Path::new("/"));
    let list = |field: &str| -> Result<Vec<PathBuf>> {
        map.get(field)
            .map_or(Ok(Vec::new()), |v| path_list(path, base, field, v))
    };
    let backup_directory = match map.get("backup") {
        None => None,
        Some(v) => {
            let b = v
                .as_map()
                .ok_or_else(|| bad(path, "backup must be a map"))?;
            for k in b.keys() {
                if k != "directory" {
                    return Err(bad(path, "backup: the only field is directory"));
                }
            }
            match b.get("directory") {
                None => return Err(bad(path, "backup: missing required field directory")),
                Some(Value::Str(s)) => {
                    crate::backup::validate_store_dir(s).map_err(|e| {
                        bad(
                            path,
                            format!(
                                "backup.directory is a path on the target and must be absolute and normalized: {}",
                                e.message
                            ),
                        )
                    })?;
                    Some(s.clone())
                }
                Some(_) => return Err(bad(path, "backup.directory must be a path string")),
            }
        }
    };
    let default_target = match map.get("default_target") {
        None => None,
        Some(Value::Str(s)) => {
            crate::inventory::parse_selector(s)
                .map_err(|e| bad(path, format!("default_target: {}", e.message)))?;
            Some(s.clone())
        }
        Some(_) => return Err(bad(path, "default_target must be a selector string")),
    };
    let allow_implicit_apply = flag(
        path,
        "allow_implicit_apply",
        map.get("allow_implicit_apply"),
    )?;
    let inventory = map
        .get("inventory")
        .map(|v| path_string(path, "inventory", v).map(|s| joined(base, &s)))
        .transpose()?;
    Ok(ProjectFile {
        path: path.to_path_buf(),
        source,
        recipe_paths: list("recipe_paths")?,
        inventory,
        vars_files: list("vars_files")?,
        backup_directory,
        default_target,
        allow_implicit_apply,
        strict_vars: flag(path, "strict_vars", map.get("strict_vars"))?,
    })
}

/// Most files looked at in one directory of `recipe_paths` for variable names.
const MAX_DECLARATION_FILES: usize = 1000;

/// The variable names the recipes in `recipe_paths` declare (DESIGN §40.5): the
/// keys of each file's top-level `vars`, and nothing else. Only the files directly
/// in those directories, held to the rules of a file the project names; `include`
/// is not followed and nothing is run. No value is kept. A file that cannot be read
/// or understood adds nothing and never fails the run: it is not this run's recipe.
pub fn declared_elsewhere(project: &ProjectFile) -> std::collections::BTreeSet<String> {
    let mut names = std::collections::BTreeSet::new();
    for dir in &project.recipe_paths {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten().take(MAX_DECLARATION_FILES) {
            let path = entry.path();
            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .map(str::to_ascii_lowercase);
            let parse: fn(&str) -> std::result::Result<Value, String> = match ext.as_deref() {
                Some("yaml" | "yml") => crate::varsfile::parse_yaml_quiet,
                Some("toml") => crate::varsfile::parse_toml_quiet,
                _ => continue,
            };
            let Ok((bytes, _)) = read_named_trusted(NAMED, &path) else {
                continue;
            };
            let Some(root) = std::str::from_utf8(&bytes).ok().and_then(|t| parse(t).ok()) else {
                continue;
            };
            let vars = root.as_map().and_then(|m| m.get("vars"));
            if let Some(vars) = vars.and_then(Value::as_map) {
                names.extend(vars.keys().cloned());
            }
        }
    }
    names
}

/// A file a project file names, or a recipe found through it: the rules of a
/// detected file, whichever way the project file was found (DESIGN §40.1).
pub fn check_named_file(path: &Path) -> Result<()> {
    read_named_trusted(NAMED, path).map(|_| ())
}

const FOUND: Who = Who {
    label: "recipe file found by name",
    ask: "fix its owner or mode, or name it by its path",
};

/// A recipe or bundle file found by the search of DESIGN §40.2 (also a member
/// of a bundle found that way): the same rules as [`check_named_file`].
pub fn check_found_file(path: &Path) -> Result<()> {
    read_named_trusted(FOUND, path).map(|_| ())
}

/// The check of a file the run reads because of how the argument was resolved:
/// none for a path given on the command line, as before.
pub fn check_resolved_file(via: RecipeVia, path: &Path) -> Result<()> {
    match via {
        RecipeVia::Given => Ok(()),
        RecipeVia::RecipePaths => check_named_file(path),
        RecipeVia::CurrentDirectory => check_found_file(path),
    }
}

type Candidate = (PathBuf, Option<(u64, u64)>, bool);

fn is_search_name(arg: &Path) -> bool {
    let mut parts = arg.components();
    matches!(
        (parts.next(), parts.next()),
        (Some(Component::Normal(_)), None)
    ) && !arg.to_string_lossy().contains('/')
}

/// Which file the recipe argument means (DESIGN §40.2), without how it matched.
pub fn resolve_recipe(arg: &Path, project: Option<&ProjectFile>) -> Result<(PathBuf, RecipeVia)> {
    resolve(arg, project).map(|r| (r.path, r.via))
}

/// Which file the recipe argument means (DESIGN §40.2).
///
/// First the rule of v1.10.0: an argument with a `/` is a path, and a bare name
/// is looked for exactly in the current directory and directly in every
/// `recipe_paths` directory. Only when that finds nothing (a directory is not a
/// recipe, so it is not counted) does the search of [`crate::recipe_search`]
/// run, and then only for a name: a path that does not exist stays a path
/// unless it is a name of several components and the project has
/// `recipe_paths`.
pub fn resolve(arg: &Path, project: Option<&ProjectFile>) -> Result<ResolvedRecipe> {
    let given = || {
        Ok(ResolvedRecipe {
            path: arg.to_path_buf(),
            via: RecipeVia::Given,
            how: RecipeMatch::Exact,
        })
    };
    let roots: &[PathBuf] = project.map_or(&[], |p| p.recipe_paths.as_slice());
    let query = crate::recipe_search::Query::parse(arg);
    if !roots.is_empty() && is_search_name(arg) {
        if let Some(found) = exact(arg, roots)? {
            return Ok(found);
        }
        if query.is_none() {
            // Not a name the search takes: the answer of v1.10.0.
            let places: Vec<String> = std::iter::once("the current directory".to_string())
                .chain(roots.iter().map(|d| d.display().to_string()))
                .collect();
            return Err(SinterError::schema(format!(
                "recipe {} was not found in {} (no other recipe is tried and no extension is added)",
                arg.display(),
                places.join(", ")
            )));
        }
    } else {
        // What the command line names, unless it is a directory, is used as
        // given, as before; a directory never was a recipe.
        match std::fs::symlink_metadata(arg) {
            Ok(m) if !m.is_dir() => return given(),
            _ => {}
        }
    }
    let Some(query) = query else {
        return given();
    };
    if roots.is_empty() && !(query.is_bare() && query.is_bundle()) {
        // Without recipe_paths only a bundle directory in the current directory
        // is new; everything else is what it was.
        return given();
    }
    let outcome = crate::recipe_search::search(&query, true, roots)?;
    if roots.is_empty() && outcome.candidates.is_empty() {
        // No bundle directory here: the argument means what it meant before.
        return given();
    }
    pick(arg, &query, roots, outcome)
}

/// The rule of v1.10.0 for a bare name with `recipe_paths`. `None`: nothing found.
fn exact(arg: &Path, roots: &[PathBuf]) -> Result<Option<ResolvedRecipe>> {
    // (path, device and inode when it can be followed, in the current directory)
    let mut hits: Vec<Candidate> = Vec::new();
    let identity = |p: &Path| {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(p).ok().map(|m| (m.dev(), m.ino()))
    };
    let mut note = |p: PathBuf, here: bool| {
        // Anything at the name counts, a link too: it is judged later, never
        // passed over for another candidate. A directory is not a recipe; it may
        // be a bundle directory, which the search finds.
        if std::fs::symlink_metadata(&p).is_ok_and(|m| !m.is_dir()) {
            let id = identity(&p);
            if !hits.iter().any(|(_, seen, _)| id.is_some() && *seen == id) {
                hits.push((p, id, here));
            }
        }
    };
    note(arg.to_path_buf(), true);
    for dir in roots {
        note(dir.join(arg), false);
    }
    match hits.len() {
        0 => Ok(None),
        1 => {
            let (p, _, here) = hits.remove(0);
            if here {
                return Ok(Some(ResolvedRecipe {
                    path: arg.to_path_buf(),
                    via: RecipeVia::Given,
                    how: RecipeMatch::Exact,
                }));
            }
            check_named_file(&p)?;
            Ok(Some(ResolvedRecipe {
                path: p,
                via: RecipeVia::RecipePaths,
                how: RecipeMatch::Exact,
            }))
        }
        _ => {
            let list: Vec<String> = hits
                .iter()
                .map(|(p, _, _)| p.display().to_string())
                .collect();
            Err(SinterError::schema(format!(
                "recipe {} is ambiguous: {}; Sinter never picks one, write ./{} or a full path",
                arg.display(),
                list.join(", "),
                arg.display()
            )))
        }
    }
}

/// Judge what the search found: exactly one usable candidate, or exit 2.
fn pick(
    arg: &Path,
    query: &crate::recipe_search::Query,
    roots: &[PathBuf],
    mut outcome: crate::recipe_search::Outcome,
) -> Result<ResolvedRecipe> {
    use crate::recipe_search::{bundle_file, Kind, MAX_DEPTH};
    let what = if query.is_bundle() {
        "bundle directory"
    } else {
        "recipe"
    };
    match outcome.candidates.len() {
        0 => {
            let mut places = Vec::new();
            if query.is_bare() && query.is_bundle() {
                places.push("the current directory".to_string());
            }
            places.extend(roots.iter().map(|d| {
                if outcome.missing.contains(d) {
                    format!("{} (does not exist)", d.display())
                } else {
                    format!("{} ({MAX_DEPTH} levels)", d.display())
                }
            }));
            let rule = if query.is_bundle() {
                "a bundle is named by its directory, which holds one bundle.yaml, bundle.yml or bundle.toml, and a single recipe by its file name with the extension, which is never added"
            } else {
                "a single recipe is named with its extension; a bundle directory is named without one (never as <name>.yaml)"
            };
            let hints = if outcome.hints.is_empty() {
                String::new()
            } else {
                let list: Vec<String> = outcome
                    .hints
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect();
                format!("; not used, since the name differs: {}", list.join(", "))
            };
            Err(SinterError::schema(format!(
                "{what} {} was not found in {} ({rule}; no other recipe is tried){hints}",
                arg.display(),
                places.join(", ")
            )))
        }
        1 => {
            let c = outcome.candidates.remove(0);
            let via = if c.here {
                RecipeVia::CurrentDirectory
            } else {
                RecipeVia::RecipePaths
            };
            match c.kind {
                Kind::File => {
                    check_resolved_file(via, &c.path)?;
                    Ok(ResolvedRecipe {
                        path: c.path,
                        via,
                        how: RecipeMatch::Search,
                    })
                }
                Kind::BundleDirectory => {
                    let file = bundle_file(&c.path)?;
                    check_resolved_file(via, &file)?;
                    let value = crate::document::parse_file_value(&file)?;
                    if !crate::bundle::is_bundle_value(&value) {
                        return Err(SinterError::schema(format!(
                            "{} is in the place of a bundle file but has no top-level recipes; a bundle directory holds a bundle",
                            file.display()
                        )));
                    }
                    Ok(ResolvedRecipe {
                        path: file,
                        via,
                        how: RecipeMatch::BundleDirectory,
                    })
                }
                Kind::NotADirectory => Err(SinterError::schema(format!(
                    "{} is not a directory, so it is not the bundle directory {}; name a recipe file with its extension, or by its path",
                    c.path.display(),
                    arg.display()
                ))),
            }
        }
        _ => {
            let list: Vec<String> = outcome
                .candidates
                .iter()
                .map(|c| c.path.display().to_string())
                .collect();
            Err(SinterError::schema(format!(
                "{what} {} is ambiguous: {}; Sinter never picks one, write more of its path (dir/{}) or the path itself",
                arg.display(),
                list.join(", "),
                arg.display()
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn parse(body: &str) -> Result<ProjectFile> {
        parse_project(
            body.as_bytes(),
            Path::new("/p/sinter.yaml"),
            ProjectSource::Explicit,
        )
    }

    #[test]
    fn a_full_file_is_understood_and_paths_are_relative_to_it() {
        let p = parse(
            "version: 1\nrecipe_paths: [/opt/r, ./recipes]\ninventory: ../i/hosts.yaml\nvars_files: [v/a.yaml, /v/b.toml]\nbackup:\n  directory: /var/backups/sinter\ndefault_target: \"@web\"\nallow_implicit_apply: true\nstrict_vars: true\n",
        )
        .unwrap();
        assert_eq!(p.recipe_paths[0], Path::new("/opt/r"));
        assert_eq!(p.recipe_paths[1], Path::new("/p/recipes"));
        assert_eq!(
            p.inventory.as_deref(),
            Some(Path::new("/p/../i/hosts.yaml"))
        );
        assert_eq!(p.vars_files[0], Path::new("/p/v/a.yaml"));
        assert_eq!(p.vars_files[1], Path::new("/v/b.toml"));
        assert_eq!(p.backup_directory.as_deref(), Some("/var/backups/sinter"));
        assert_eq!(p.default_target.as_deref(), Some("@web"));
        assert!(p.allow_implicit_apply && p.strict_vars);
    }

    #[test]
    fn only_a_version_is_required() {
        let p = parse("version: 1\n").unwrap();
        assert!(p.recipe_paths.is_empty() && p.inventory.is_none() && !p.strict_vars);
    }

    #[test]
    fn invalid_files_are_refused() {
        for (body, says) in [
            ("recipe_paths: []\n", "missing required field version"),
            ("version: 2\n", "version must be 1"),
            ("version: 1\nresources: []\n", "unknown field"),
            ("version: 1\nrecipe_paths: x\n", "must be a list"),
            ("version: 1\nrecipe_paths: [1]\n", "must be a path string"),
            ("version: 1\nrecipe_paths: [a, ./a]\n", "more than once"),
            ("version: 1\nvars_files: [\"~/v.yaml\"]\n", "not expanded"),
            (
                "version: 1\nvars_files: [\"$HOME/v.yaml\"]\n",
                "not expanded",
            ),
            ("version: 1\ninventory: 3\n", "must be a path string"),
            ("version: 1\nbackup: /x\n", "backup must be a map"),
            (
                "version: 1\nbackup: {}\n",
                "missing required field directory",
            ),
            (
                "version: 1\nbackup: {dir: /x}\n",
                "the only field is directory",
            ),
            ("version: 1\nbackup: {directory: rel}\n", "absolute"),
            ("version: 1\nbackup: {directory: /a/../b}\n", "normalized"),
            ("version: 1\nbackup: {directory: /}\n", "root directory"),
            ("version: 1\ndefault_target: \"\"\n", "default_target"),
            ("version: 1\nstrict_vars: 1\n", "must be true or false"),
            ("a: b: c\n", "YAML"),
        ] {
            let e = parse(body).expect_err(body);
            assert!(e.message.contains(says), "{body}: {}", e.message);
            assert_eq!(e.kind, crate::error::ErrorKind::Schema);
        }
    }

    #[test]
    fn a_syntax_error_shows_no_content() {
        let e = parse("version: 1\nbackup: {directory: \"SECRET_CANARY\n").unwrap_err();
        assert!(!e.message.contains("SECRET_CANARY"), "{}", e.message);
    }

    fn project(recipe_paths: Vec<PathBuf>) -> ProjectFile {
        ProjectFile {
            path: PathBuf::from("/p/sinter.yaml"),
            source: ProjectSource::Explicit,
            recipe_paths,
            inventory: None,
            vars_files: Vec::new(),
            backup_directory: None,
            default_target: None,
            allow_implicit_apply: false,
            strict_vars: false,
        }
    }

    fn private_dir() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        d
    }

    fn write(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, "version: 1\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        p
    }

    #[test]
    fn a_path_is_never_searched_for() {
        let d = private_dir();
        write(d.path(), "r.yaml");
        let p = project(vec![d.path().to_path_buf()]);
        let (got, via) = resolve_recipe(Path::new("./r.yaml"), Some(&p)).unwrap();
        assert_eq!(got, Path::new("./r.yaml"));
        assert_eq!(via, RecipeVia::Given);
        // A path that exists is used as given, however it is spelt
        // (src/lib.rs exists in the crate directory the tests run in).
        let (got, via) = resolve_recipe(Path::new("src/lib.rs"), Some(&p)).unwrap();
        assert_eq!(got, Path::new("src/lib.rs"));
        assert_eq!(via, RecipeVia::Given);
        // Changed in SR-2 (DESIGN §40.2): a missing `dir/name` with recipe_paths
        // is a name of several components and is searched for; until v1.10.0 it
        // was used as given and failed to load. Either way nothing else runs.
        let e = resolve_recipe(Path::new("sub/r.yaml"), Some(&p)).unwrap_err();
        assert!(e.message.contains("was not found"), "{}", e.message);
        // Without recipe_paths it is still used as given.
        let (got, _) = resolve_recipe(Path::new("sub/r.yaml"), None).unwrap();
        assert_eq!(got, Path::new("sub/r.yaml"));
    }

    #[test]
    fn without_recipe_paths_the_argument_is_used_as_given() {
        let p = project(Vec::new());
        let (got, via) = resolve_recipe(Path::new("missing.yaml"), Some(&p)).unwrap();
        assert_eq!(got, Path::new("missing.yaml"));
        assert_eq!(via, RecipeVia::Given);
        let (got, _) = resolve_recipe(Path::new("missing.yaml"), None).unwrap();
        assert_eq!(got, Path::new("missing.yaml"));
    }

    #[test]
    fn a_name_is_found_in_one_place_and_only_one() {
        let (a, b) = (private_dir(), private_dir());
        let found = write(b.path(), "search-one.yaml");
        let p = project(vec![a.path().to_path_buf(), b.path().to_path_buf()]);
        let (got, via) = resolve_recipe(Path::new("search-one.yaml"), Some(&p)).unwrap();
        assert_eq!(got, found);
        assert_eq!(via, RecipeVia::RecipePaths);

        write(a.path(), "search-one.yaml");
        let e = resolve_recipe(Path::new("search-one.yaml"), Some(&p)).unwrap_err();
        assert!(e.message.contains("ambiguous"), "{}", e.message);
        assert!(e.message.contains(&found.display().to_string()));

        let e = resolve_recipe(Path::new("nowhere.yaml"), Some(&p)).unwrap_err();
        assert!(e.message.contains("was not found"), "{}", e.message);
        assert!(e.message.contains(&a.path().display().to_string()));
        // No extension is added.
        assert!(resolve_recipe(Path::new("search-one"), Some(&p)).is_err());
    }

    #[test]
    fn a_directory_is_not_a_recipe_but_may_be_a_bundle_directory() {
        // Directly in a recipe_paths directory: the exact rule of v1.10.0
        // counted the directory and failed; now it is left to the search.
        let d = private_dir();
        let b = d.path().join("sr2-bundle-dir");
        std::fs::create_dir(&b).unwrap();
        std::fs::set_permissions(&b, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(b.join("bundle.yaml"), "version: 1\nrecipes: [a.yaml]\n").unwrap();
        std::fs::set_permissions(
            b.join("bundle.yaml"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let p = project(vec![d.path().to_path_buf()]);
        let r = resolve(Path::new("sr2-bundle-dir"), Some(&p)).unwrap();
        assert_eq!(r.path, b.join("bundle.yaml"));
        assert_eq!(r.via, RecipeVia::RecipePaths);
        assert_eq!(r.how, RecipeMatch::BundleDirectory);
        // An exact file still wins first and is reported as before.
        write(d.path(), "sr2-exact.yaml");
        let r = resolve(Path::new("sr2-exact.yaml"), Some(&p)).unwrap();
        assert_eq!((r.via, r.how), (RecipeVia::RecipePaths, RecipeMatch::Exact));
    }

    #[test]
    fn the_same_file_reached_twice_is_one_candidate() {
        let a = private_dir();
        let found = write(a.path(), "twice.yaml");
        let alias = a.path().join(".");
        let p = project(vec![a.path().to_path_buf(), alias]);
        assert_eq!(
            resolve_recipe(Path::new("twice.yaml"), Some(&p)).unwrap().0,
            found
        );
    }

    #[test]
    fn a_project_file_above_is_noticed_only_within_its_limits() {
        let top = private_dir();
        let deep = top.path().join("a/b");
        std::fs::create_dir_all(&deep).unwrap();
        assert_eq!(unused_parent_project(&deep, None), None);
        // Content does not matter: it is never opened.
        std::fs::write(top.path().join("sinter.yaml"), "not: [valid\n").unwrap();
        assert_eq!(
            unused_parent_project(&deep, None).as_deref(),
            Some(top.path().join("sinter.yaml").as_path())
        );
        // The current directory itself is not "above".
        assert_eq!(unused_parent_project(top.path(), None), None);
        // Home is not looked at, nor anything above it.
        assert_eq!(unused_parent_project(&deep, Some(top.path())), None);
        // A repository's top ends the walk.
        std::fs::create_dir(top.path().join("a/.git")).unwrap();
        assert_eq!(unused_parent_project(&deep, None), None);
    }

    #[test]
    fn other_recipes_give_their_variable_names_and_nothing_else() {
        let a = private_dir();
        let body = |v: &str| format!("version: 1\nvars:\n  {v}: {{ value: \"SECRET_CANARY\" }}\n");
        let put = |name: &str, text: &str| {
            let p = a.path().join(name);
            std::fs::write(&p, text).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
            p
        };
        put("one.yaml", &body("db_port"));
        put("two.yml", &body("web_port"));
        put("three.toml", "version = 1\n[vars]\ntoml_var = \"x\"\n");
        // None of these may fail anything, or add a name.
        put("broken.yaml", "a: b: c: [\n");
        put("list.yaml", "- not\n- a map\n");
        put("novars.yaml", "version: 1\n");
        put("notes.txt", &body("in_a_text_file"));
        let open = put("open.yaml", &body("from_a_writable_file"));
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o666)).unwrap();
        std::os::unix::fs::symlink(a.path().join("one.yaml"), a.path().join("link.yaml")).unwrap();
        std::fs::create_dir(a.path().join("sub")).unwrap();
        std::fs::write(a.path().join("sub/deep.yaml"), body("below_the_directory")).unwrap();
        let p = project(vec![a.path().to_path_buf(), a.path().join("missing")]);
        let got = declared_elsewhere(&p);
        let want: std::collections::BTreeSet<String> = ["db_port", "toml_var", "web_port"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(got, want);
    }

    #[test]
    fn a_recipe_found_by_search_is_held_to_the_file_rules() {
        let a = private_dir();
        let f = write(a.path(), "shared.yaml");
        let p = project(vec![a.path().to_path_buf()]);
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o666)).unwrap();
        let e = resolve_recipe(Path::new("shared.yaml"), Some(&p)).unwrap_err();
        assert!(
            e.message.contains("writable by group or others"),
            "{}",
            e.message
        );
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(a.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let e = resolve_recipe(Path::new("shared.yaml"), Some(&p)).unwrap_err();
        assert!(
            e.message.contains("its directory is writable"),
            "{}",
            e.message
        );
        std::fs::set_permissions(a.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        // A link is not followed, and is not passed over for another candidate.
        let b = private_dir();
        std::os::unix::fs::symlink(&f, b.path().join("linked.yaml")).unwrap();
        let p = project(vec![b.path().to_path_buf()]);
        let e = resolve_recipe(Path::new("linked.yaml"), Some(&p)).unwrap_err();
        assert!(e.message.contains("symbolic link"), "{}", e.message);
    }
}
