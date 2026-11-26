//! Recipe bundles: an ordered list of recipes run as one invocation.
//!
//! ```yaml
//! version: 1
//! name: web-stack          # optional; defaults to the file stem
//! recipes:
//!   - common.yaml          # relative to the bundle file
//!   - nginx.yaml
//!   - app.yaml
//!   - os                   # a nested bundle (here a bundle directory)
//! ```
//!
//! A file is a bundle when its top level has a `recipes` key (never a valid
//! recipe field). A bundle adds no targets of its own: with an inventory,
//! every listed recipe is resolved against its *own* `targets`. An entry may
//! be another bundle: it is expanded where it is listed, depth first, into one
//! flat ordered list of recipes before anything runs (DESIGN §19.3). A recipe
//! or a nested bundle may be reached once in the whole expansion, a cycle is
//! refused, and every recipe must load and validate before anything runs.

use crate::document::{only_fields, parse_file_value, valid_name};
use crate::error::{Result, SinterError};
use crate::model::{prepare_with_plugins, Model, Prepared};
use crate::plugin::PluginContext;
use crate::secret_source::ReferenceCheck;
use crate::value::Value;
use std::path::{Path, PathBuf};

const BUNDLE_FIELDS: &[&str] = &["version", "name", "recipes"];

/// One recipe of a bundle (or the single recipe of a plain invocation).
#[derive(Debug, Clone)]
pub struct RecipeUnit {
    /// Display label: the recipe file stem, prefixed with the labels of the
    /// nested bundles it came from (`os/net/10_hosts`; DESIGN §19.3).
    pub label: String,
    /// The path as listed, joined to the directory of the bundle listing it.
    pub path: PathBuf,
    /// The canonical path, relative to the top bundle's directory when it is
    /// below it (the file name of a plain recipe).
    pub rel_path: String,
    pub model: Model,
    /// The recipe was parsed and checked but not frozen, because no host runs
    /// it (`--limit` left every host of its `targets` out): `model` is then
    /// [`Model::unfrozen_stub`], which carries only `targets`. Such a recipe
    /// has no execution.
    pub unfrozen: bool,
}

#[derive(Debug, Clone)]
pub struct Bundle {
    pub name: String,
    pub path: PathBuf,
    /// Every recipe of the expansion, in run order.
    pub recipes: Vec<RecipeUnit>,
    /// The nested bundles of the expansion, in the order they were reached.
    pub nested: Vec<NestedBundle>,
}

/// A bundle listed by another bundle (DESIGN §19.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NestedBundle {
    /// `name` (default: its file stem, or its directory's name), prefixed
    /// with the labels of the bundles above it except the top one.
    pub label: String,
    /// Its bundle file, as reached.
    pub path: PathBuf,
}

/// What the positional argument named: one recipe, or a bundle.
#[derive(Debug, Clone)]
// One value per loaded recipe or bundle, never stored in bulk: the size of
// the `Recipe` variant (a whole `Model`, which gained the plugin set in
// v1.9.0) does not matter, and boxing it would change every caller.
#[allow(clippy::large_enum_variant)]
pub enum Source {
    Recipe(RecipeUnit),
    Bundle(Bundle),
}

impl Source {
    pub fn units(&self) -> &[RecipeUnit] {
        match self {
            Source::Recipe(u) => std::slice::from_ref(u),
            Source::Bundle(b) => &b.recipes,
        }
    }

    /// The nested bundles of the expansion (none for a plain recipe).
    pub fn nested(&self) -> &[NestedBundle] {
        match self {
            Source::Recipe(_) => &[],
            Source::Bundle(b) => &b.nested,
        }
    }
}

fn stem(p: &Path) -> String {
    p.file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| p.display().to_string())
}

pub(crate) fn is_bundle_value(v: &Value) -> bool {
    v.as_map().is_some_and(|m| m.contains_key("recipes"))
}

/// Load a recipe or bundle, validating everything statically.
pub fn load_source(path: &Path) -> Result<Source> {
    load_source_with(path, ReferenceCheck::Strict)
}

/// [`load_source`] with an explicit secret-reference mode (strict for every
/// caller except `secrets list --recipe`).
pub(crate) fn load_source_with(path: &Path, refs: ReferenceCheck) -> Result<Source> {
    load_source_inner(path, refs, &PluginContext::default())
}

/// [`load_source`] with the controller's plugin context (the CLI; DESIGN
/// §38.7). Without it a recipe that enables plugins is refused.
pub fn load_source_with_plugins(path: &Path, plugins: &PluginContext) -> Result<Source> {
    load_source_inner(path, ReferenceCheck::Strict, plugins)
}

fn load_source_inner(path: &Path, refs: ReferenceCheck, plugins: &PluginContext) -> Result<Source> {
    let load = |p: &Path| prepare_with_plugins(p, refs, plugins)?.freeze_default();
    Ok(match walk_source(path, load)? {
        Walked::Recipe(u) => {
            let rel = file_name(&u.path);
            Source::Recipe(u.into_unit(rel))
        }
        Walked::Bundle {
            name,
            path,
            units,
            rel_paths,
            nested,
        } => Source::Bundle(Bundle {
            name,
            path,
            recipes: units
                .into_iter()
                .zip(rel_paths)
                .map(|(u, r)| u.into_unit(r))
                .collect(),
            nested,
        }),
    })
}

/// One recipe of a source, loaded as `T` (a [`Model`] or a [`Prepared`]).
#[derive(Clone)]
pub struct Loaded<T> {
    pub label: String,
    pub path: PathBuf,
    pub item: T,
}

impl Loaded<Model> {
    fn into_unit(self, rel_path: String) -> RecipeUnit {
        RecipeUnit {
            label: self.label,
            path: self.path,
            rel_path,
            model: self.item,
            unfrozen: false,
        }
    }
}

enum Walked<T> {
    Recipe(Loaded<T>),
    Bundle {
        name: String,
        path: PathBuf,
        units: Vec<Loaded<T>>,
        rel_paths: Vec<String>,
        nested: Vec<NestedBundle>,
    },
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| p.display().to_string())
}

/// A recipe or bundle whose recipes are parsed and include-expanded but not
/// frozen: the variables-file path (DESIGN §19.5) freezes each (recipe, host)
/// execution with its own values.
#[derive(Clone)]
pub struct PreparedSource {
    /// `(name, path)` of the bundle; `None` for a plain recipe.
    pub bundle: Option<(String, PathBuf)>,
    pub units: Vec<Loaded<Prepared>>,
    /// Per unit, [`RecipeUnit::rel_path`].
    pub rel_paths: Vec<String>,
    /// The nested bundles of the expansion.
    pub nested: Vec<NestedBundle>,
}

impl PreparedSource {
    /// The [`Source`] to display and report with, given one frozen model per
    /// recipe (in order). Every part of a model it is read for — `targets`,
    /// `backups`, secret references — is static, so any host's model serves.
    pub fn into_source(self, models: Vec<Model>) -> Source {
        self.into_source_partial(models.into_iter().map(Some).collect())
    }

    /// Like [`PreparedSource::into_source`], where a recipe with no model
    /// (`None`: no host runs it) is kept unfrozen, with a stub that carries
    /// only its `targets` (see [`Model::unfrozen_stub`]).
    pub fn into_source_partial(self, models: Vec<Option<Model>>) -> Source {
        let units: Vec<RecipeUnit> = self
            .units
            .into_iter()
            .zip(models)
            .zip(self.rel_paths)
            .map(|((u, model), rel_path)| {
                let unfrozen = model.is_none();
                RecipeUnit {
                    model: model.unwrap_or_else(|| Model::unfrozen_stub(u.item.targets().cloned())),
                    label: u.label,
                    path: u.path,
                    rel_path,
                    unfrozen,
                }
            })
            .collect();
        match self.bundle {
            None => Source::Recipe(units.into_iter().next().expect("one recipe")),
            Some((name, path)) => Source::Bundle(Bundle {
                name,
                path,
                recipes: units,
                nested: self.nested,
            }),
        }
    }
}

/// Load a recipe or bundle like [`load_source`], without freezing: the same
/// files are read in the same order and fail with the same errors, except the
/// errors that belong to freezing.
pub fn prepare_source(path: &Path) -> Result<PreparedSource> {
    prepare_source_with_plugins(path, &PluginContext::default())
}

/// [`prepare_source`] with the controller's plugin context (the CLI).
pub fn prepare_source_with_plugins(path: &Path, plugins: &PluginContext) -> Result<PreparedSource> {
    Ok(
        match walk_source(path, |p| {
            prepare_with_plugins(p, ReferenceCheck::Strict, plugins)
        })? {
            Walked::Recipe(u) => PreparedSource {
                bundle: None,
                rel_paths: vec![file_name(&u.path)],
                units: vec![u],
                nested: Vec::new(),
            },
            Walked::Bundle {
                name,
                path,
                units,
                rel_paths,
                nested,
            } => PreparedSource {
                bundle: Some((name, path)),
                units,
                rel_paths,
                nested,
            },
        },
    )
}

/// Bundle levels allowed below the top bundle (DESIGN §19.3).
pub const MAX_NESTING: usize = 8;
/// Recipe units one expansion may hold, over every level.
pub const MAX_UNITS: usize = 256;
/// Entries of `recipes` one bundle file may list.
pub const MAX_ENTRIES: usize = 64;

/// Walk a recipe or bundle, loading each recipe with `load` in order. A
/// nested bundle is expanded where it is listed, depth first, so the result
/// is one flat, ordered list of recipe units (DESIGN §19.3).
fn walk_source<T>(path: &Path, load: impl Fn(&Path) -> Result<T>) -> Result<Walked<T>> {
    let value = parse_file_value(path)?;
    if !is_bundle_value(&value) {
        let item = load(path)?;
        return Ok(Walked::Recipe(Loaded {
            label: stem(path),
            path: path.to_path_buf(),
            item,
        }));
    }
    let canon = canonical(path, &format!("bundle {}", path.display()))?;
    let top_dir = canon
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/"));
    let mut walk = Walk {
        load: &load,
        top_dir,
        units: Vec::new(),
        rel_paths: Vec::new(),
        nested: Vec::new(),
        recipes_seen: Vec::new(),
        bundles_seen: Vec::new(),
        stack: Vec::new(),
    };
    let name = walk.bundle(path, &canon, &value, stem(path), None, 0)?;
    Ok(Walked::Bundle {
        name,
        path: path.to_path_buf(),
        units: walk.units,
        rel_paths: walk.rel_paths,
        nested: walk.nested,
    })
}

fn canonical(p: &Path, ctx: &str) -> Result<PathBuf> {
    std::fs::canonicalize(p)
        .map_err(|e| SinterError::schema(format!("{ctx}: {}: {e}", p.display())))
}

/// The state of one expansion.
struct Walk<'l, T> {
    load: &'l dyn Fn(&Path) -> Result<T>,
    /// The canonical directory of the top bundle: paths are shown relative to it.
    top_dir: PathBuf,
    units: Vec<Loaded<T>>,
    rel_paths: Vec<String>,
    nested: Vec<NestedBundle>,
    /// Every recipe reached so far (canonical path) and how it was reached.
    recipes_seen: Vec<(PathBuf, String)>,
    /// Every bundle reached so far, the top one included.
    bundles_seen: Vec<(PathBuf, String)>,
    /// The bundles being expanded, outermost first: (canonical path, shown).
    stack: Vec<(PathBuf, String)>,
}

impl<T> Walk<'_, T> {
    /// `canon` relative to the top bundle's directory, or in full.
    fn shown(&self, canon: &Path) -> String {
        canon
            .strip_prefix(&self.top_dir)
            .map(|r| r.display().to_string())
            .unwrap_or_else(|_| canon.display().to_string())
    }

    /// The chain of the bundles being expanded, ending in `last`.
    fn chain(&self, last: &str) -> String {
        self.stack
            .iter()
            .map(|(_, s)| s.as_str())
            .chain(std::iter::once(last))
            .collect::<Vec<_>>()
            .join(" -> ")
    }

    /// Expand the bundle at `path` (`canon`, already parsed as `value`) at
    /// `depth` (0: the top bundle). `prefix` is the label of the bundle that
    /// lists it (`None` at the top level and for its direct children).
    /// Returns the bundle's name.
    fn bundle(
        &mut self,
        path: &Path,
        canon: &Path,
        value: &Value,
        default_name: String,
        prefix: Option<&str>,
        depth: usize,
    ) -> Result<String> {
        let ctx = format!("bundle {}", path.display());
        let map = value.as_map().expect("checked by the caller");
        only_fields(map, BUNDLE_FIELDS, &ctx)?;
        match map.get("version") {
            Some(Value::Int(1)) => {}
            Some(_) => {
                return Err(SinterError::schema(format!(
                    "{ctx}: unsupported version (bundles require version: 1)"
                )))
            }
            None => {
                return Err(SinterError::schema(format!(
                    "{ctx}: missing required field version"
                )))
            }
        }
        let name = match map.get("name") {
            // The top bundle's name is only shown; a nested bundle's name is
            // part of the label of every recipe below it.
            None if depth == 0 || valid_name(&default_name) => default_name,
            None => {
                return Err(SinterError::schema(format!(
                    "{ctx}: its default name {default_name:?} is not a valid label part; set name ([A-Za-z0-9._-], start alphanumeric, max 64 chars)"
                )))
            }
            Some(Value::Str(s)) if valid_name(s) => s.clone(),
            Some(_) => {
                return Err(SinterError::schema(format!(
                    "{ctx}: name must match [A-Za-z0-9._-], start alphanumeric, max 64 chars"
                )))
            }
        };
        let list = map
            .get("recipes")
            .and_then(Value::as_list)
            .ok_or_else(|| SinterError::schema(format!("{ctx}: recipes must be a list")))?;
        if list.is_empty() {
            return Err(SinterError::schema(format!(
                "{ctx}: recipes must not be empty"
            )));
        }
        if list.len() > MAX_ENTRIES {
            return Err(SinterError::schema(format!(
                "{ctx}: recipes lists {} entries; a bundle lists at most {MAX_ENTRIES} (split it into nested bundles)",
                list.len()
            )));
        }
        // The label of this bundle, the prefix of everything below it.
        let own: Option<String> = match (depth, prefix) {
            (0, _) => None,
            (_, None) => Some(name.clone()),
            (_, Some(p)) => Some(format!("{p}/{name}")),
        };
        if let Some(label) = &own {
            self.nested.push(NestedBundle {
                label: label.clone(),
                path: path.to_path_buf(),
            });
        }
        let shown_self = self.shown(canon);
        let reached = self.chain(&shown_self);
        self.bundles_seen.push((canon.to_path_buf(), reached));
        self.stack.push((canon.to_path_buf(), shown_self));
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        for (i, item) in list.iter().enumerate() {
            let rel = item.as_str().ok_or_else(|| {
                SinterError::schema(format!("{ctx}: recipes[{i}] must be a path string"))
            })?;
            let p = if Path::new(rel).is_absolute() {
                PathBuf::from(rel)
            } else {
                base.join(rel)
            };
            let entry_canon = canonical(&p, &format!("{ctx}: recipes[{i}]"))?;
            let is_dir = std::fs::metadata(&entry_canon).is_ok_and(|m| m.is_dir());
            // (file as reached, canonical file, parsed, default name)
            let (file, file_canon, parsed, default) = if is_dir {
                let named = crate::recipe_search::Query::parse(Path::new(rel))
                    .is_some_and(|q| q.is_bundle());
                if !named {
                    return Err(SinterError::schema(format!(
                        "{ctx}: recipes[{i}] {} is a directory; a bundle directory is listed by its name without an extension (as on the command line), never by a path such as ./name or ../name; list its bundle file instead",
                        p.display()
                    )));
                }
                let file = crate::recipe_search::bundle_file(&p)?;
                let file_canon = canonical(&file, &format!("{ctx}: recipes[{i}]"))?;
                let parsed = parse_file_value(&file_canon)?;
                if !is_bundle_value(&parsed) {
                    return Err(SinterError::schema(format!(
                        "{} is in the place of a bundle file but has no top-level recipes; a bundle directory holds a bundle",
                        file.display()
                    )));
                }
                let dir_name = p
                    .file_name()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_else(|| stem(&p));
                (file, file_canon, parsed, dir_name)
            } else {
                let parsed = parse_file_value(&entry_canon)?;
                let d = stem(&p);
                (p.clone(), entry_canon, parsed, d)
            };
            if is_bundle_value(&parsed) {
                let shown = self.shown(&file_canon);
                if self.stack.iter().any(|(c, _)| *c == file_canon) {
                    return Err(SinterError::schema(format!(
                        "{ctx}: recipes[{i}] {}: bundles form a cycle: {}",
                        file.display(),
                        self.chain(&shown)
                    )));
                }
                if let Some((_, before)) = self.bundles_seen.iter().find(|(c, _)| *c == file_canon)
                {
                    return Err(SinterError::schema(format!(
                        "{ctx}: recipes[{i}]: bundle {shown} is reached twice: {before} and {}; a bundle may be listed once in the whole expansion",
                        self.chain(&shown)
                    )));
                }
                if depth + 1 > MAX_NESTING {
                    return Err(SinterError::schema(format!(
                        "{ctx}: recipes[{i}] {}: bundles nest at most {MAX_NESTING} levels below the top bundle: {}",
                        file.display(),
                        self.chain(&shown)
                    )));
                }
                self.bundle(
                    &file,
                    &file_canon,
                    &parsed,
                    default,
                    own.as_deref(),
                    depth + 1,
                )?;
                continue;
            }
            let shown = self.shown(&file_canon);
            if let Some((_, before)) = self.recipes_seen.iter().find(|(c, _)| *c == file_canon) {
                let now = self.chain(&shown);
                if *before == now {
                    return Err(SinterError::schema(format!(
                        "{ctx}: recipe {} is listed more than once",
                        p.display()
                    )));
                }
                return Err(SinterError::schema(format!(
                    "{ctx}: recipes[{i}]: recipe {shown} is reached twice: {before} and {now}; a recipe may be listed once in the whole expansion"
                )));
            }
            if self.units.len() >= MAX_UNITS {
                return Err(SinterError::schema(format!(
                    "{ctx}: recipes[{i}]: the expansion holds more than {MAX_UNITS} recipes"
                )));
            }
            let reached = self.chain(&shown);
            self.recipes_seen.push((file_canon.clone(), reached));
            let item = (self.load)(&file_canon)?;
            let label = match &own {
                None => stem(&p),
                Some(b) => format!("{b}/{}", stem(&p)),
            };
            self.units.push(Loaded {
                label,
                path: p,
                item,
            });
            self.rel_paths.push(shown);
        }
        self.stack.pop();
        Ok(name)
    }
}

/// The last part of a label: the recipe's file stem.
pub fn label_stem(label: &str) -> &str {
    label.rsplit_once('/').map_or(label, |(_, s)| s)
}

/// The label of the nested bundle a recipe came from (`None` at the top).
pub fn label_bundle(label: &str) -> Option<&str> {
    label.rsplit_once('/').map(|(b, _)| b)
}

/// How a name the user gave (`--skip-recipe`, the recipe of a
/// `--skip-resource recipe/id`, a `recipe_vars` key) meets the recipes of a
/// run (DESIGN §19.3): the full label first, a nested bundle's label next,
/// and only when neither matches, a file stem that one recipe alone has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelMatch {
    /// Nothing of the run.
    None,
    /// Exactly one recipe.
    Unit(usize),
    /// Several recipes carry exactly this label.
    SameLabel(Vec<usize>),
    /// No recipe has this label and several end in this stem.
    SharedStem(Vec<usize>),
    /// The label of a nested bundle: every recipe below it, in order.
    Bundle(Vec<usize>),
    /// Both the label of these recipes and a nested bundle's label.
    UnitAndBundle(Vec<usize>),
}

pub fn match_label(labels: &[&str], name: &str) -> LabelMatch {
    let pick = |f: &dyn Fn(&str) -> bool| -> Vec<usize> {
        labels
            .iter()
            .enumerate()
            .filter(|(_, l)| f(l))
            .map(|(i, _)| i)
            .collect()
    };
    let exact = pick(&|l| l == name);
    let below = format!("{name}/");
    let in_bundle = pick(&|l| label_bundle(l).is_some_and(|b| b == name || b.starts_with(&below)));
    match (exact.len(), in_bundle.is_empty()) {
        (1.., false) => LabelMatch::UnitAndBundle(exact),
        (1, true) => LabelMatch::Unit(exact[0]),
        (2.., true) => LabelMatch::SameLabel(exact),
        (0, false) => LabelMatch::Bundle(in_bundle),
        (0, true) => {
            let stems = pick(&|l| label_stem(l) == name);
            match stems.len() {
                0 => LabelMatch::None,
                1 => LabelMatch::Unit(stems[0]),
                _ => LabelMatch::SharedStem(stems),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        for (n, b) in [
            ("common.yaml", "version: 1\ntargets:\n  groups: [linux]\n"),
            ("nginx.yaml", "version: 1\ntargets:\n  groups: [web]\n"),
            ("plain.yaml", "version: 1\n"),
        ] {
            std::fs::write(d.path().join(n), b).unwrap();
        }
        d
    }

    fn write(d: &tempfile::TempDir, n: &str, b: &str) -> PathBuf {
        let p = d.path().join(n);
        std::fs::write(&p, b).unwrap();
        p
    }

    #[test]
    fn plain_recipe_is_a_single_unit() {
        let d = dir();
        match load_source(&d.path().join("nginx.yaml")).unwrap() {
            Source::Recipe(u) => {
                assert_eq!(u.label, "nginx");
                assert!(u.model.targets.is_some());
            }
            Source::Bundle(_) => panic!("not a bundle"),
        }
    }

    #[test]
    fn bundle_keeps_declared_order() {
        let d = dir();
        let b = write(
            &d,
            "stack.yaml",
            "version: 1\nname: web-stack\nrecipes:\n  - nginx.yaml\n  - common.yaml\n",
        );
        let Source::Bundle(b) = load_source(&b).unwrap() else {
            panic!("bundle expected")
        };
        assert_eq!(b.name, "web-stack");
        let labels: Vec<_> = b.recipes.iter().map(|r| r.label.as_str()).collect();
        assert_eq!(labels, vec!["nginx", "common"]);
    }

    #[test]
    fn invalid_bundles_fail() {
        let d = dir();
        write(&d, "inner.yaml", "version: 1\nrecipes: [common.yaml]\n");
        write(&d, "broken.yaml", "version: 1\nresources: 3\n");
        for body in [
            "version: 1\nrecipes: []\n",
            "version: 1\nrecipes: common.yaml\n",
            "version: 1\nrecipes: [1]\n",
            "version: 1\nrecipes: [missing.yaml]\n",
            "version: 1\nrecipes: [common.yaml, ./common.yaml]\n",
            "version: 1\nrecipes: [broken.yaml]\n",
            "version: 2\nrecipes: [common.yaml]\n",
            "recipes: [common.yaml]\n",
            "version: 1\nname: \"bad name\"\nrecipes: [common.yaml]\n",
            "version: 1\nrecipes: [common.yaml]\ntargets:\n  groups: [web]\n",
        ] {
            let p = write(&d, "b.yaml", body);
            let e = load_source(&p).expect_err(body);
            assert_eq!(
                e.kind,
                crate::error::ErrorKind::Schema,
                "{body}: {}",
                e.message
            );
        }
        // A bundle cannot list itself: a cycle of one.
        let p = write(&d, "self.yaml", "version: 1\nrecipes: [self.yaml]\n");
        assert!(load_source(&p).is_err());
    }

    // ---- nested bundles (DESIGN §19.3) -----------------------------------

    fn put(d: &Path, rel: &str, body: &str) -> PathBuf {
        let p = d.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, body).unwrap();
        p
    }

    fn bundle_of(p: &Path) -> Bundle {
        match load_source(p).unwrap() {
            Source::Bundle(b) => b,
            Source::Recipe(_) => panic!("bundle expected"),
        }
    }

    fn labels(b: &Bundle) -> Vec<String> {
        b.recipes.iter().map(|u| u.label.clone()).collect()
    }

    fn err(p: &Path) -> String {
        let e = load_source(p).expect_err("must be refused");
        assert_eq!(e.kind, crate::error::ErrorKind::Schema, "{}", e.message);
        e.message
    }

    const R: &str = "version: 1\n";

    #[test]
    fn a_two_level_bundle_expands_in_declaration_order_depth_first() {
        let d = tempfile::tempdir().unwrap();
        let d = d.path();
        for r in ["a.yaml", "os/10_sysctl.yaml", "os/20_motd.yaml", "z.yaml"] {
            put(d, r, R);
        }
        put(
            d,
            "os/bundle.yaml",
            "version: 1\nrecipes: [10_sysctl.yaml, 20_motd.yaml]\n",
        );
        let top = put(
            d,
            "site.yaml",
            "version: 1\nname: site\nrecipes: [a.yaml, os/bundle.yaml, z.yaml]\n",
        );
        let b = bundle_of(&top);
        assert_eq!(b.name, "site");
        // The nested bundle's default name is its file stem.
        assert_eq!(labels(&b), ["a", "bundle/10_sysctl", "bundle/20_motd", "z"]);
        assert_eq!(b.nested.len(), 1);
        assert_eq!(b.nested[0].label, "bundle");
        let rel: Vec<&str> = b.recipes.iter().map(|u| u.rel_path.as_str()).collect();
        assert_eq!(
            rel,
            ["a.yaml", "os/10_sysctl.yaml", "os/20_motd.yaml", "z.yaml"]
        );
    }

    #[test]
    fn a_three_level_bundle_joins_the_nested_names_and_never_the_top_name() {
        let d = tempfile::tempdir().unwrap();
        let d = d.path();
        put(d, "os/net/10_hosts.yaml", R);
        put(
            d,
            "os/net/bundle.yaml",
            "version: 1\nrecipes: [10_hosts.yaml]\n",
        );
        put(d, "os/05_base.yaml", R);
        put(
            d,
            "os/bundle.yaml",
            "version: 1\nname: os\nrecipes: [05_base.yaml, net]\n",
        );
        put(d, "app.yaml", R);
        let top = put(
            d,
            "site.yaml",
            "version: 1\nname: site\nrecipes: [os, app.yaml]\n",
        );
        let b = bundle_of(&top);
        // `os` and `net` are bundle directories: the directory names them.
        assert_eq!(labels(&b), ["os/05_base", "os/net/10_hosts", "app"]);
        let nested: Vec<&str> = b.nested.iter().map(|n| n.label.as_str()).collect();
        assert_eq!(nested, ["os", "os/net"]);
        // The prepared form is the same expansion.
        let p = prepare_source(&top).unwrap();
        let pl: Vec<&str> = p.units.iter().map(|u| u.label.as_str()).collect();
        assert_eq!(pl, ["os/05_base", "os/net/10_hosts", "app"]);
        assert_eq!(
            p.rel_paths,
            ["os/05_base.yaml", "os/net/10_hosts.yaml", "app.yaml"]
        );
        assert_eq!(p.nested, b.nested);
    }

    #[test]
    fn each_entry_is_relative_to_the_bundle_that_lists_it() {
        let d = tempfile::tempdir().unwrap();
        let d = d.path();
        put(d, "shared/x.yaml", R);
        put(d, "sub/y.yaml", R);
        put(
            d,
            "sub/bundle.yaml",
            "version: 1\nname: sub\nrecipes: [../shared/x.yaml, y.yaml]\n",
        );
        let top = put(d, "site.yaml", "version: 1\nrecipes: [sub/bundle.yaml]\n");
        let b = bundle_of(&top);
        assert_eq!(labels(&b), ["sub/x", "sub/y"]);
        assert_eq!(b.recipes[0].rel_path, "shared/x.yaml");
        // An absolute entry is taken as it is.
        let abs = d.join("shared/x.yaml").canonicalize().unwrap();
        let top = put(
            d,
            "abs.yaml",
            &format!("version: 1\nrecipes: [{}]\n", abs.display()),
        );
        assert_eq!(labels(&bundle_of(&top)), ["x"]);
    }

    #[test]
    fn a_bundle_that_lists_itself_is_a_cycle_of_one() {
        let d = tempfile::tempdir().unwrap();
        let top = put(d.path(), "site.yaml", "version: 1\nrecipes: [site.yaml]\n");
        let m = err(&top);
        assert!(m.contains("cycle: site.yaml -> site.yaml"), "{m}");
    }

    #[test]
    fn an_indirect_cycle_names_the_whole_chain() {
        let d = tempfile::tempdir().unwrap();
        let d = d.path();
        put(d, "r.yaml", R);
        put(
            d,
            "os/bundle.yaml",
            "version: 1\nname: os\nrecipes: [../r.yaml, ../site.yaml]\n",
        );
        let top = put(d, "site.yaml", "version: 1\nrecipes: [os/bundle.yaml]\n");
        let m = err(&top);
        assert!(
            m.contains("cycle: site.yaml -> os/bundle.yaml -> site.yaml"),
            "{m}"
        );
    }

    #[test]
    fn a_symbolic_link_or_another_spelling_cannot_hide_a_cycle() {
        let d = tempfile::tempdir().unwrap();
        let d = d.path();
        put(d, "a/r.yaml", R);
        // b.yaml lists the top bundle through a link.
        std::os::unix::fs::symlink(d.join("site.yaml"), d.join("a/link.yaml")).unwrap();
        put(
            d,
            "b.yaml",
            "version: 1\nname: b\nrecipes: [a/r.yaml, a/link.yaml]\n",
        );
        let top = put(d, "site.yaml", "version: 1\nrecipes: [b.yaml]\n");
        let m = err(&top);
        assert!(m.contains("cycle: site.yaml -> b.yaml -> site.yaml"), "{m}");
        // ./a/../b.yaml is b.yaml.
        put(
            d,
            "b.yaml",
            "version: 1\nname: b\nrecipes: [a/r.yaml, ./a/../site.yaml]\n",
        );
        let m = err(&top);
        assert!(m.contains("cycle: site.yaml -> b.yaml -> site.yaml"), "{m}");
        put(
            d,
            "c.yaml",
            "version: 1\nname: c\nrecipes: [./a/../c.yaml]\n",
        );
        let top = put(d, "top2.yaml", "version: 1\nrecipes: [a//r.yaml, c.yaml]\n");
        let m = err(&top);
        assert!(m.contains("cycle: top2.yaml -> c.yaml -> c.yaml"), "{m}");
    }

    #[test]
    fn a_recipe_reached_through_two_sub_bundles_is_refused_with_both_chains() {
        let d = tempfile::tempdir().unwrap();
        let d = d.path();
        put(d, "shared/x.yaml", R);
        put(
            d,
            "a/bundle.yaml",
            "version: 1\nname: a\nrecipes: [../shared/x.yaml]\n",
        );
        put(
            d,
            "b/bundle.yaml",
            "version: 1\nname: b\nrecipes: [../shared//x.yaml]\n",
        );
        let top = put(d, "site.yaml", "version: 1\nrecipes: [a, b]\n");
        let m = err(&top);
        assert!(
            m.contains("recipe shared/x.yaml is reached twice: site.yaml -> a/bundle.yaml -> shared/x.yaml and site.yaml -> b/bundle.yaml -> shared/x.yaml"),
            "{m}"
        );
        // Listed twice by one bundle: the message of a flat bundle.
        put(
            d,
            "dup.yaml",
            "version: 1\nrecipes: [shared/x.yaml, ./shared/x.yaml]\n",
        );
        assert!(err(&d.join("dup.yaml")).contains("is listed more than once"));
    }

    #[test]
    fn a_diamond_of_bundles_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let d = d.path();
        put(d, "c/r.yaml", R);
        put(
            d,
            "c/bundle.yaml",
            "version: 1\nname: c\nrecipes: [r.yaml]\n",
        );
        put(
            d,
            "a/bundle.yaml",
            "version: 1\nname: a\nrecipes: [../c/bundle.yaml]\n",
        );
        put(
            d,
            "b/bundle.yaml",
            "version: 1\nname: b\nrecipes: [../c/bundle.yaml]\n",
        );
        let top = put(d, "site.yaml", "version: 1\nrecipes: [a, b]\n");
        let m = err(&top);
        assert!(
            m.contains("bundle c/bundle.yaml is reached twice: site.yaml -> a/bundle.yaml -> c/bundle.yaml and site.yaml -> b/bundle.yaml -> c/bundle.yaml"),
            "{m}"
        );
    }

    /// A chain of `levels` bundles below `site.yaml`, the last listing r.yaml.
    fn chain(d: &Path, levels: usize) -> PathBuf {
        put(d, "r.yaml", R);
        for l in (1..=levels).rev() {
            let next = if l == levels {
                "r.yaml".to_string()
            } else {
                format!("b{}.yaml", l + 1)
            };
            put(
                d,
                &format!("b{l}.yaml"),
                &format!("version: 1\nrecipes: [{next}]\n"),
            );
        }
        put(d, "site.yaml", "version: 1\nrecipes: [b1.yaml]\n")
    }

    #[test]
    fn bundles_nest_at_most_eight_levels_below_the_top() {
        let d = tempfile::tempdir().unwrap();
        let top = chain(d.path(), MAX_NESTING);
        let b = bundle_of(&top);
        assert_eq!(labels(&b), ["b1/b2/b3/b4/b5/b6/b7/b8/r"]);
        let d = tempfile::tempdir().unwrap();
        let top = chain(d.path(), MAX_NESTING + 1);
        let m = err(&top);
        assert!(m.contains("nest at most 8 levels"), "{m}");
    }

    #[test]
    fn the_expansion_holds_at_most_256_recipes_and_a_bundle_lists_at_most_64() {
        let d = tempfile::tempdir().unwrap();
        let d = d.path();
        let mut subs = Vec::new();
        for s in 0..5 {
            let names: Vec<String> = (0..52).map(|i| format!("r{i}.yaml")).collect();
            for n in &names {
                put(d, &format!("s{s}/{n}"), R);
            }
            put(
                d,
                &format!("s{s}/bundle.yaml"),
                &format!("version: 1\nname: s{s}\nrecipes: [{}]\n", names.join(", ")),
            );
            subs.push(format!("s{s}"));
        }
        // 4 x 52 = 208 recipes: fine; 5 x 52 = 260: refused.
        let ok = put(
            d,
            "ok.yaml",
            &format!("version: 1\nrecipes: [{}]\n", subs[..4].join(", ")),
        );
        assert_eq!(bundle_of(&ok).recipes.len(), 208);
        let top = put(
            d,
            "site.yaml",
            &format!("version: 1\nrecipes: [{}]\n", subs.join(", ")),
        );
        assert!(err(&top).contains("more than 256 recipes"));
        let many: Vec<String> = (0..65).map(|i| format!("s0/r{}.yaml", i % 52)).collect();
        let top = put(
            d,
            "wide.yaml",
            &format!("version: 1\nrecipes: [{}]\n", many.join(", ")),
        );
        assert!(err(&top).contains("at most 64"));
    }

    #[test]
    fn a_directory_entry_is_a_bundle_directory_only_when_named_like_one() {
        let d = tempfile::tempdir().unwrap();
        let d = d.path();
        put(d, "os/r.yaml", R);
        put(d, "os/bundle.toml", "version = 1\nrecipes = [\"r.yaml\"]\n");
        put(d, "plain/r.yaml", R);
        put(d, "plain/bundle.yaml", R);
        put(
            d,
            "two/bundle.yaml",
            "version: 1\nrecipes: [../os/r.yaml]\n",
        );
        put(d, "two/bundle.yml", "version: 1\nrecipes: [../os/r.yaml]\n");
        let top = put(d, "a.yaml", "version: 1\nrecipes: [os]\n");
        assert_eq!(labels(&bundle_of(&top)), ["os/r"]);
        for (body, want) in [
            ("version: 1\nrecipes: [./os]\n", "is a directory"),
            ("version: 1\nrecipes: [os/../os]\n", "is a directory"),
            ("version: 1\nrecipes: [plain]\n", "has no top-level recipes"),
            ("version: 1\nrecipes: [two]\n", "several bundle files"),
            ("version: 1\nrecipes: [nothing]\n", "recipes[0]"),
        ] {
            let top = put(d, "b.yaml", body);
            let m = err(&top);
            assert!(m.contains(want), "{body}: {m}");
        }
    }

    #[test]
    fn a_nested_bundle_without_a_usable_name_must_set_one() {
        let d = tempfile::tempdir().unwrap();
        let d = d.path();
        put(d, "r.yaml", R);
        put(d, "bad name.yaml", "version: 1\nrecipes: [r.yaml]\n");
        let top = put(d, "site.yaml", "version: 1\nrecipes: [\"bad name.yaml\"]\n");
        assert!(err(&top).contains("set name"));
        put(
            d,
            "bad name.yaml",
            "version: 1\nname: good\nrecipes: [r.yaml]\n",
        );
        assert_eq!(labels(&bundle_of(&top)), ["good/r"]);
    }

    #[test]
    fn labels_match_by_full_label_then_bundle_then_unique_stem() {
        let l = [
            "a",
            "pg/03_package",
            "web/03_package",
            "os/net/10_hosts",
            "os/05",
        ];
        assert_eq!(match_label(&l, "a"), LabelMatch::Unit(0));
        assert_eq!(match_label(&l, "pg/03_package"), LabelMatch::Unit(1));
        assert_eq!(
            match_label(&l, "03_package"),
            LabelMatch::SharedStem(vec![1, 2])
        );
        assert_eq!(match_label(&l, "10_hosts"), LabelMatch::Unit(3));
        assert_eq!(match_label(&l, "os"), LabelMatch::Bundle(vec![3, 4]));
        assert_eq!(match_label(&l, "os/net"), LabelMatch::Bundle(vec![3]));
        assert_eq!(match_label(&l, "net"), LabelMatch::None);
        assert_eq!(match_label(&l, "o"), LabelMatch::None);
        assert_eq!(
            match_label(&["x", "x"], "x"),
            LabelMatch::SameLabel(vec![0, 1])
        );
        assert_eq!(
            match_label(&["os", "os/a"], "os"),
            LabelMatch::UnitAndBundle(vec![0])
        );
        assert_eq!(label_stem("os/net/10_hosts"), "10_hosts");
        assert_eq!(label_bundle("os/net/10_hosts"), Some("os/net"));
        assert_eq!(label_bundle("a"), None);
    }
}
