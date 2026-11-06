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

/// How the recipe argument was resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecipeVia {
    /// As given on the command line.
    #[default]
    Given,
    /// Found through `recipe_paths`.
    RecipePaths,
}

impl RecipeVia {
    pub fn key(self) -> &'static str {
        match self {
            RecipeVia::Given => "given",
            RecipeVia::RecipePaths => "recipe_paths",
        }
    }
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

type Candidate = (PathBuf, Option<(u64, u64)>, bool);

fn is_search_name(arg: &Path) -> bool {
    let mut parts = arg.components();
    matches!(
        (parts.next(), parts.next()),
        (Some(Component::Normal(_)), None)
    ) && !arg.to_string_lossy().contains('/')
}

/// Which file the recipe argument means (DESIGN §40.2).
pub fn resolve_recipe(arg: &Path, project: Option<&ProjectFile>) -> Result<(PathBuf, RecipeVia)> {
    let given = || Ok((arg.to_path_buf(), RecipeVia::Given));
    let Some(project) = project else {
        return given();
    };
    if project.recipe_paths.is_empty() || !is_search_name(arg) {
        return given();
    }
    // (path, device and inode when it can be followed, in the current directory)
    let mut hits: Vec<Candidate> = Vec::new();
    let identity = |p: &Path| {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(p).ok().map(|m| (m.dev(), m.ino()))
    };
    let mut note = |p: PathBuf, here: bool| {
        // Anything at the name counts, a link too: it is judged later, never
        // passed over for another candidate.
        if std::fs::symlink_metadata(&p).is_ok() {
            let id = identity(&p);
            if !hits.iter().any(|(_, seen, _)| id.is_some() && *seen == id) {
                hits.push((p, id, here));
            }
        }
    };
    note(arg.to_path_buf(), true);
    for dir in &project.recipe_paths {
        note(dir.join(arg), false);
    }
    match hits.len() {
        0 => {
            let places: Vec<String> = std::iter::once("the current directory".to_string())
                .chain(project.recipe_paths.iter().map(|d| d.display().to_string()))
                .collect();
            Err(SinterError::schema(format!(
                "recipe {} was not found in {} (no other recipe is tried and no extension is added)",
                arg.display(),
                places.join(", ")
            )))
        }
        1 => {
            let (p, _, here) = hits.remove(0);
            if here {
                return given();
            }
            check_named_file(&p)?;
            Ok((p, RecipeVia::RecipePaths))
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
        let (got, _) = resolve_recipe(Path::new("sub/r.yaml"), Some(&p)).unwrap();
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
