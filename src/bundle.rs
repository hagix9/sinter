//! Recipe bundles: an ordered list of recipes run as one invocation.
//!
//! ```yaml
//! version: 1
//! name: web-stack          # optional; defaults to the file stem
//! recipes:
//!   - common.yaml          # relative to the bundle file
//!   - nginx.yaml
//!   - app.yaml
//! ```
//!
//! A file is a bundle when its top level has a `recipes` key (never a valid
//! recipe field). A bundle adds no targets of its own: with an inventory,
//! every listed recipe is resolved against its *own* `targets`. Bundles do
//! not nest, a recipe may be listed once, and every listed recipe must load
//! and validate before anything runs.

use crate::document::{only_fields, parse_file_value, valid_name};
use crate::error::{Result, SinterError};
use crate::model::{load_model_with, Model};
use crate::secret_source::ReferenceCheck;
use crate::value::Value;
use std::path::{Path, PathBuf};

const BUNDLE_FIELDS: &[&str] = &["version", "name", "recipes"];

/// One recipe of a bundle (or the single recipe of a plain invocation).
#[derive(Debug, Clone)]
pub struct RecipeUnit {
    /// Display label: the recipe file stem.
    pub label: String,
    pub path: PathBuf,
    pub model: Model,
}

#[derive(Debug, Clone)]
pub struct Bundle {
    pub name: String,
    pub path: PathBuf,
    pub recipes: Vec<RecipeUnit>,
}

/// What the positional argument named: one recipe, or a bundle.
#[derive(Debug, Clone)]
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
}

fn stem(p: &Path) -> String {
    p.file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| p.display().to_string())
}

fn is_bundle_value(v: &Value) -> bool {
    v.as_map().is_some_and(|m| m.contains_key("recipes"))
}

/// Load a recipe or bundle, validating everything statically.
pub fn load_source(path: &Path) -> Result<Source> {
    load_source_with(path, ReferenceCheck::Strict)
}

/// [`load_source`] with an explicit secret-reference mode (strict for every
/// caller except `secrets list --recipe`).
pub(crate) fn load_source_with(path: &Path, refs: ReferenceCheck) -> Result<Source> {
    let value = parse_file_value(path)?;
    if !is_bundle_value(&value) {
        let model = load_model_with(path, refs)?;
        return Ok(Source::Recipe(RecipeUnit {
            label: stem(path),
            path: path.to_path_buf(),
            model,
        }));
    }
    let ctx = format!("bundle {}", path.display());
    let map = value.as_map().expect("checked above");
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
        None => stem(path),
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
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    let mut seen: Vec<PathBuf> = Vec::new();
    let mut recipes = Vec::new();
    for (i, item) in list.iter().enumerate() {
        let rel = item.as_str().ok_or_else(|| {
            SinterError::schema(format!("{ctx}: recipes[{i}] must be a path string"))
        })?;
        let p = if Path::new(rel).is_absolute() {
            PathBuf::from(rel)
        } else {
            base.join(rel)
        };
        let canon = std::fs::canonicalize(&p).map_err(|e| {
            SinterError::schema(format!("{ctx}: recipes[{i}] {}: {e}", p.display()))
        })?;
        if seen.contains(&canon) {
            return Err(SinterError::schema(format!(
                "{ctx}: recipe {} is listed more than once",
                p.display()
            )));
        }
        seen.push(canon.clone());
        if is_bundle_value(&parse_file_value(&canon)?) {
            return Err(SinterError::schema(format!(
                "{ctx}: recipes[{i}] {} is a bundle; bundles do not nest",
                p.display()
            )));
        }
        let model = load_model_with(&canon, refs)?;
        recipes.push(RecipeUnit {
            label: stem(&p),
            path: p,
            model,
        });
    }
    Ok(Source::Bundle(Bundle {
        name,
        path: path.to_path_buf(),
        recipes,
    }))
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
            "version: 1\nrecipes: [inner.yaml]\n",
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
        // A bundle cannot list itself (it is a bundle, and bundles do not nest).
        let p = write(&d, "self.yaml", "version: 1\nrecipes: [self.yaml]\n");
        assert!(load_source(&p).is_err());
    }
}
