//! Partial runs: `--skip-recipe` and `--skip-resource` (DESIGN §40.8).
//!
//! Everything here happens before `ssh -G` or a connection, on the models the
//! run will execute. A request that matches nothing, is ambiguous, or would leave
//! an included resource without what it depends on stops the run; nothing is
//! ignored and nothing is excluded that was not asked for.

use crate::diff::sanitize_line;
use crate::error::{Result, SinterError};
use crate::model::{FrozenResource, Model};
use crate::style;
use std::collections::BTreeSet;
use std::io::Write;

/// The reason an exclusion carries in output.
pub const REASON: &str = "SKIPPED_BY_USER";

#[derive(Debug, Clone, Default)]
pub struct SkipRequest {
    pub recipes: Vec<String>,
    pub resources: Vec<String>,
}

impl SkipRequest {
    pub fn is_empty(&self) -> bool {
        self.recipes.is_empty() && self.resources.is_empty()
    }
}

/// One recipe of the run, with every model it may execute with.
pub struct UnitView<'a> {
    pub label: &'a str,
    /// No host runs it: its resources are not known here.
    pub unfrozen: bool,
    pub models: Vec<&'a Model>,
}

/// An included resource that depends on an excluded one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blocked {
    pub recipe: String,
    pub resource: String,
    pub depends_on: String,
}

#[derive(Debug, Clone, Default)]
struct UnitSkip {
    label: String,
    /// `--skip-recipe`.
    whole: bool,
    /// Every resource of the recipe is excluded, one by one.
    emptied: bool,
    /// Resource ids excluded, by full id.
    excluded: BTreeSet<String>,
    /// What runs, in declaration order, from the first model.
    included: Vec<String>,
    /// Every resource id of the recipe, in declaration order.
    all: Vec<String>,
    /// No host runs this recipe in any case.
    unfrozen: bool,
}

/// A checked request, and what it means for each recipe of the run.
#[derive(Debug, Clone, Default)]
pub struct SkipPlan {
    request: SkipRequest,
    units: Vec<UnitSkip>,
    /// Non-empty means the run must not start.
    pub blocked: Vec<Blocked>,
}

/// The id a loop's instances share (`id[3]` -> `id`).
fn loop_base(r: &FrozenResource) -> Option<&str> {
    if r.loop_index.is_some() {
        r.id.rsplit_once('[').map(|(base, _)| base)
    } else {
        None
    }
}

fn matches(r: &FrozenResource, name: &str) -> bool {
    r.id == name || loop_base(r) == Some(name)
}

fn in_unit(u: &UnitView<'_>, name: &str) -> bool {
    u.models
        .iter()
        .any(|m| m.resources.iter().any(|r| matches(r, name)))
}

fn is_handler(u: &UnitView<'_>, name: &str) -> bool {
    u.models.iter().any(|m| m.handler_index.contains_key(name))
}

fn unit_by_label(units: &[UnitView<'_>], label: &str, option: &str) -> Result<Option<usize>> {
    let hits: Vec<usize> = units
        .iter()
        .enumerate()
        .filter(|(_, u)| u.label == label)
        .map(|(i, _)| i)
        .collect();
    match hits.len() {
        0 => Ok(None),
        1 => Ok(Some(hits[0])),
        n => Err(SinterError::schema(format!(
            "{option}: {} recipes of this bundle are named {label}; rename a file to tell them apart",
            n
        ))),
    }
}

/// `recipe/id` when `recipe` is a recipe of the run.
fn qualified<'n>(units: &[UnitView<'_>], name: &'n str) -> Result<Option<(usize, &'n str)>> {
    let Some((label, rest)) = name.split_once('/') else {
        return Ok(None);
    };
    Ok(unit_by_label(units, label, "--skip-resource")?.map(|i| (i, rest)))
}

impl SkipPlan {
    /// Check `request` against the recipes of the run.
    pub fn build(request: &SkipRequest, units: &[UnitView<'_>]) -> Result<SkipPlan> {
        let mut out: Vec<UnitSkip> = units
            .iter()
            .map(|u| UnitSkip {
                label: u.label.to_string(),
                unfrozen: u.unfrozen,
                ..UnitSkip::default()
            })
            .collect();
        for name in &request.recipes {
            match unit_by_label(units, name, "--skip-recipe")? {
                Some(i) => out[i].whole = true,
                None => {
                    let known: Vec<&str> = units.iter().map(|u| u.label).collect();
                    return Err(SinterError::schema(format!(
                        "--skip-recipe {}: this run has no such recipe (it has: {})",
                        sanitize_line(name),
                        known.join(", ")
                    )));
                }
            }
        }
        // Per recipe, the names to exclude.
        let mut names: Vec<BTreeSet<String>> = vec![BTreeSet::new(); units.len()];
        for name in &request.resources {
            let plain: Vec<usize> = units
                .iter()
                .enumerate()
                .filter(|(_, u)| in_unit(u, name))
                .map(|(i, _)| i)
                .collect();
            let prefixed = qualified(units, name)?;
            let prefixed_hit = prefixed.filter(|(i, rest)| in_unit(&units[*i], rest));
            let shown = sanitize_line(name);
            if !plain.is_empty() && prefixed_hit.is_some() {
                return Err(SinterError::schema(format!(
                    "--skip-resource {shown}: this is both a resource id and a recipe with a resource; rename one of them"
                )));
            }
            if plain.len() > 1 {
                let labels: Vec<String> = plain
                    .iter()
                    .map(|i| format!("{}/{}", units[*i].label, shown))
                    .collect();
                return Err(SinterError::schema(format!(
                    "--skip-resource {shown}: several recipes have this id; say which: {}",
                    labels.join(", ")
                )));
            }
            if let Some(i) = plain.first() {
                names[*i].insert(name.clone());
                continue;
            }
            if let Some((i, rest)) = prefixed_hit {
                names[i].insert(rest.to_string());
                continue;
            }
            let bare = prefixed.map_or(name.as_str(), |(_, rest)| rest);
            let handler = match prefixed {
                Some((i, rest)) => is_handler(&units[i], rest),
                None => units.iter().any(|u| is_handler(u, bare)),
            };
            if handler {
                return Err(SinterError::schema(format!(
                    "--skip-resource {shown}: this is a handler, not a resource; a handler runs \
                     only when an included resource notifies it, and skipping it alone would \
                     leave a change without its action"
                )));
            }
            // Named through a recipe no host runs: nothing of it runs anyway, and
            // its resources are not known. Kept in the report, not an exclusion.
            if prefixed.is_some_and(|(i, _)| units[i].unfrozen) {
                continue;
            }
            let unfrozen = units.iter().filter(|u| u.unfrozen).count();
            return Err(SinterError::schema(format!(
                "--skip-resource {shown}: no recipe of this run has such a resource{}",
                if unfrozen > 0 {
                    format!(
                        " ({unfrozen} recipe(s) that no selected host runs were not looked at; a recipe/id names one)"
                    )
                } else {
                    String::new()
                }
            )));
        }
        let mut blocked = Vec::new();
        for (i, u) in units.iter().enumerate() {
            let skip = &mut out[i];
            for m in &u.models {
                let excluded_here: BTreeSet<&str> = m
                    .resources
                    .iter()
                    .filter(|r| skip.whole || names[i].iter().any(|n| matches(r, n)))
                    .map(|r| r.id.as_str())
                    .collect();
                for id in &excluded_here {
                    skip.excluded.insert(id.to_string());
                }
                for r in &m.resources {
                    if !skip.all.contains(&r.id) {
                        skip.all.push(r.id.clone());
                    }
                    if excluded_here.contains(r.id.as_str()) {
                        continue;
                    }
                    if !skip.included.contains(&r.id) {
                        skip.included.push(r.id.clone());
                    }
                    for d in &r.depends_on {
                        if excluded_here.contains(d.as_str()) {
                            let edge = Blocked {
                                recipe: u.label.to_string(),
                                resource: r.id.clone(),
                                depends_on: d.clone(),
                            };
                            if !blocked.contains(&edge) {
                                blocked.push(edge);
                            }
                        }
                    }
                }
            }
            skip.emptied = !skip.whole && !skip.excluded.is_empty() && skip.included.is_empty();
        }
        let plan = SkipPlan {
            request: request.clone(),
            units: out,
            blocked,
        };
        Ok(plan)
    }

    /// Whether anything of recipe `unit` runs.
    pub fn runs(&self, unit: usize) -> bool {
        self.units.get(unit).is_none_or(|u| !u.whole && !u.emptied)
    }

    /// Nothing at all would run.
    pub fn runs_nothing(&self) -> bool {
        self.units
            .iter()
            .all(|u| u.whole || u.emptied || u.unfrozen)
    }

    /// The error of a request that cannot run.
    pub fn refusal(&self) -> Option<SinterError> {
        if !self.blocked.is_empty() {
            let edges: Vec<String> = self
                .blocked
                .iter()
                .map(|b| {
                    format!(
                        "{}/{} depends on {}",
                        sanitize_line(&b.recipe),
                        sanitize_line(&b.resource),
                        sanitize_line(&b.depends_on)
                    )
                })
                .collect();
            return Some(SinterError::schema(format!(
                "the exclusions would break dependencies: {}; exclude the dependent resources as \
                 well, or do not exclude what they need (nothing is excluded automatically); no \
                 host was contacted",
                edges.join("; ")
            )));
        }
        if self.runs_nothing() {
            return Some(SinterError::schema(
                "the exclusions leave nothing to run; no host was contacted",
            ));
        }
        None
    }

    /// `model` with the excluded resources removed. A handler stays: it runs only
    /// if an included resource notifies it.
    pub fn filter(&self, unit: usize, mut model: Model) -> Model {
        if let Some(u) = self.units.get(unit) {
            model.resources.retain(|r| !u.excluded.contains(&r.id));
        }
        model
    }

    /// Whether the run really left something out.
    pub fn excluded_count(&self) -> (usize, usize) {
        let recipes = self.units.iter().filter(|u| u.whole).count();
        let resources = self.units.iter().map(|u| u.excluded.len()).sum();
        (recipes, resources)
    }

    /// `PARTIAL_APPLY` and its kin.
    pub fn summary_token(phase: &str) -> String {
        format!("PARTIAL_{}", phase.to_ascii_uppercase())
    }

    pub fn summary_line(&self, phase: &str, color: bool) -> String {
        let (recipes, resources) = self.excluded_count();
        format!(
            "{}: {recipes} recipe(s) and {resources} resource(s) excluded by the user: not observed, not changed, not verified",
            style::status(&Self::summary_token(phase), color)
        )
    }

    /// What is included, excluded and blocked.
    pub fn render(&self, color: bool, out: &mut dyn Write) -> std::io::Result<()> {
        let many = self.units.len() > 1;
        let name = |u: &UnitSkip, id: &str| {
            if many {
                format!("{}/{}", sanitize_line(&u.label), sanitize_line(id))
            } else {
                sanitize_line(id)
            }
        };
        writeln!(out, "Included:")?;
        let mut any = false;
        for u in self.units.iter().filter(|u| !u.whole) {
            for id in &u.included {
                writeln!(out, "  {}", name(u, id))?;
                any = true;
            }
        }
        if !any {
            writeln!(out, "  none")?;
        }
        writeln!(out, "Excluded:")?;
        let mut rows: Vec<String> = Vec::new();
        for u in &self.units {
            if u.whole {
                rows.push(format!("{}/*", sanitize_line(&u.label)));
            } else {
                for id in u.all.iter().filter(|id| u.excluded.contains(*id)) {
                    rows.push(name(u, id));
                }
            }
        }
        let width = rows.iter().map(|r| r.chars().count()).max().unwrap_or(0);
        if rows.is_empty() {
            writeln!(out, "  none")?;
        }
        for r in rows {
            writeln!(out, "  {r:width$}  {}", style::status(REASON, color))?;
        }
        writeln!(out, "Blocked dependencies:")?;
        if self.blocked.is_empty() {
            writeln!(out, "  none")?;
        }
        for b in &self.blocked {
            writeln!(
                out,
                "  {}/{} depends on {}  {}",
                sanitize_line(&b.recipe),
                sanitize_line(&b.resource),
                sanitize_line(&b.depends_on),
                style::status("BLOCKED", color)
            )?;
        }
        Ok(())
    }

    /// The `skips` object of JSON documents.
    pub fn json(&self) -> serde_json::Value {
        let mut excluded = Vec::new();
        let mut included = Vec::new();
        for u in &self.units {
            if u.whole {
                excluded.push(serde_json::json!({
                    "recipe": u.label, "resource": null, "reason": REASON,
                }));
            }
            for id in u.all.iter().filter(|id| u.excluded.contains(*id)) {
                excluded.push(serde_json::json!({
                    "recipe": u.label, "resource": id, "reason": REASON,
                }));
            }
            if !u.whole {
                for id in &u.included {
                    included.push(serde_json::json!({ "recipe": u.label, "resource": id }));
                }
            }
        }
        serde_json::json!({
            "partial": true,
            "requested": {
                "recipes": self.request.recipes,
                "resources": self.request.resources,
            },
            "included": included,
            "excluded": excluded,
            "blocked": self.blocked.iter().map(|b| serde_json::json!({
                "recipe": b.recipe, "resource": b.resource, "depends_on": b.depends_on,
            })).collect::<Vec<_>>(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::load_model;

    fn model(body: &str) -> (tempfile::TempDir, Model) {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("r.yaml");
        std::fs::write(&p, format!("version: 1\n{body}")).unwrap();
        let m = load_model(&p).unwrap();
        (d, m)
    }

    fn res(id: &str, extra: &str) -> String {
        format!(
            "  - id: {id}\n    type: file\n    with:\n      path: /etc/{id}\n      content: x\n{extra}"
        )
    }

    fn recipe() -> (tempfile::TempDir, Model) {
        let body = format!(
            "resources:\n{}{}{}handlers:\n  - id: restart\n    service: nginx\n    action: restart\n",
            res("a", ""),
            res("b", "    depends_on: [a]\n    notify: [restart]\n"),
            res("c", ""),
        );
        model(&body)
    }

    fn req(recipes: &[&str], resources: &[&str]) -> SkipRequest {
        SkipRequest {
            recipes: recipes.iter().map(|s| s.to_string()).collect(),
            resources: resources.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn view<'a>(label: &'a str, m: &'a Model) -> UnitView<'a> {
        UnitView {
            label,
            unfrozen: false,
            models: vec![m],
        }
    }

    #[test]
    fn a_resource_is_excluded_and_the_rest_stays() {
        let (_d, m) = recipe();
        let p = SkipPlan::build(&req(&[], &["c"]), &[view("r", &m)]).unwrap();
        assert!(p.refusal().is_none());
        let f = p.filter(0, m.clone());
        let ids: Vec<&str> = f.resources.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["a", "b"]);
        assert!(p.runs(0));
        assert_eq!(p.excluded_count(), (0, 1));
    }

    #[test]
    fn an_excluded_dependency_blocks_and_nothing_is_cascaded() {
        let (_d, m) = recipe();
        let p = SkipPlan::build(&req(&[], &["a"]), &[view("r", &m)]).unwrap();
        assert_eq!(
            p.blocked,
            [Blocked {
                recipe: "r".into(),
                resource: "b".into(),
                depends_on: "a".into()
            }]
        );
        let e = p.refusal().unwrap();
        assert!(e.message.contains("r/b depends on a"), "{}", e.message);
        // Excluding the dependent as well is what the operator can ask for.
        let p = SkipPlan::build(&req(&[], &["a", "b"]), &[view("r", &m)]).unwrap();
        assert!(p.refusal().is_none());
    }

    #[test]
    fn excluding_a_dependent_alone_is_fine() {
        let (_d, m) = recipe();
        let p = SkipPlan::build(&req(&[], &["b"]), &[view("r", &m)]).unwrap();
        assert!(p.refusal().is_none());
    }

    #[test]
    fn unknown_names_are_never_ignored() {
        let (_d, m) = recipe();
        let e = SkipPlan::build(&req(&["nope"], &[]), &[view("r", &m)]).unwrap_err();
        assert!(e.message.contains("no such recipe"), "{}", e.message);
        let e = SkipPlan::build(&req(&[], &["nope"]), &[view("r", &m)]).unwrap_err();
        assert!(e.message.contains("no recipe of this run"), "{}", e.message);
        let e = SkipPlan::build(&req(&[], &["r/nope"]), &[view("r", &m)]).unwrap_err();
        assert!(e.message.contains("no recipe of this run"), "{}", e.message);
    }

    #[test]
    fn a_handler_is_not_a_resource() {
        let (_d, m) = recipe();
        for name in ["restart", "r/restart"] {
            let e = SkipPlan::build(&req(&[], &[name]), &[view("r", &m)]).unwrap_err();
            assert!(e.message.contains("this is a handler"), "{}", e.message);
        }
    }

    #[test]
    fn the_same_id_in_two_recipes_needs_a_recipe_name() {
        let (_d1, m1) = recipe();
        let (_d2, m2) = recipe();
        let units = [view("one", &m1), view("two", &m2)];
        let e = SkipPlan::build(&req(&[], &["c"]), &units).unwrap_err();
        assert!(e.message.contains("one/c, two/c"), "{}", e.message);
        let p = SkipPlan::build(&req(&[], &["two/c"]), &units).unwrap();
        assert_eq!(p.filter(0, m1.clone()).resources.len(), 3);
        assert_eq!(p.filter(1, m2.clone()).resources.len(), 2);
    }

    #[test]
    fn two_recipes_with_one_label_cannot_be_told_apart() {
        let (_d1, m1) = recipe();
        let (_d2, m2) = recipe();
        let units = [view("same", &m1), view("same", &m2)];
        let e = SkipPlan::build(&req(&["same"], &[]), &units).unwrap_err();
        assert!(e.message.contains("2 recipes"), "{}", e.message);
        let e = SkipPlan::build(&req(&[], &["same/c"]), &units).unwrap_err();
        assert!(e.message.contains("2 recipes"), "{}", e.message);
    }

    #[test]
    fn a_string_that_reads_both_ways_is_refused() {
        let (_d1, m1) = model(&format!(
            "resources:\n{}",
            "  - id: x/y\n    type: file\n    with:\n      path: /etc/xy\n      content: a\n"
        ));
        let (_d2, m2) = model(&format!("resources:\n{}", res("y", "")));
        let units = [view("w", &m1), view("x", &m2)];
        let e = SkipPlan::build(&req(&[], &["x/y"]), &units).unwrap_err();
        assert!(e.message.contains("both"), "{}", e.message);
    }

    #[test]
    fn a_loop_is_named_by_its_base_or_by_an_instance() {
        let (_d, m) = model(
            "resources:\n  - id: f\n    type: file\n    loop: [a, b]\n    with:\n      path: \"/etc/{{ item }}\"\n      content: x\n  - id: g\n    type: file\n    with:\n      path: /etc/g\n      content: x\n",
        );
        let p = SkipPlan::build(&req(&[], &["f"]), &[view("r", &m)]).unwrap();
        assert_eq!(p.filter(0, m.clone()).resources.len(), 1);
        let p = SkipPlan::build(&req(&[], &["f[1]"]), &[view("r", &m)]).unwrap();
        let ids: Vec<String> = p
            .filter(0, m.clone())
            .resources
            .iter()
            .map(|r| r.id.clone())
            .collect();
        assert_eq!(ids, ["f[0]", "g"]);
    }

    #[test]
    fn nothing_left_is_refused() {
        let (_d, m) = recipe();
        let p = SkipPlan::build(&req(&["r"], &[]), &[view("r", &m)]).unwrap();
        assert!(!p.runs(0));
        assert!(p.refusal().unwrap().message.contains("nothing to run"));
        let p = SkipPlan::build(&req(&[], &["a", "b", "c"]), &[view("r", &m)]).unwrap();
        assert!(!p.runs(0));
        assert!(p.refusal().is_some());
    }

    #[test]
    fn a_recipe_no_host_runs_is_named_but_not_guessed_at() {
        let (_d, m) = recipe();
        let stub = Model::unfrozen_stub(None);
        let units = [
            view("r", &m),
            UnitView {
                label: "idle",
                unfrozen: true,
                models: vec![&stub],
            },
        ];
        assert!(SkipPlan::build(&req(&[], &["idle/x"]), &units).is_ok());
        let e = SkipPlan::build(&req(&[], &["x"]), &units).unwrap_err();
        assert!(e.message.contains("no selected host runs"), "{}", e.message);
    }

    #[test]
    fn the_preview_says_what_happens_and_json_carries_the_reason() {
        let (_d1, m1) = recipe();
        let (_d2, m2) = recipe();
        let units = [view("nginx", &m1), view("ssh-hardening", &m2)];
        let p = SkipPlan::build(&req(&["ssh-hardening"], &["nginx/c"]), &units).unwrap();
        let mut out = Vec::new();
        p.render(false, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Included:\n  nginx/a\n  nginx/b\n"), "{text}");
        assert!(text.contains("ssh-hardening/*"), "{text}");
        assert!(text.contains("nginx/c"), "{text}");
        assert!(text.contains(REASON), "{text}");
        assert!(text.contains("Blocked dependencies:\n  none\n"), "{text}");
        let j = p.json();
        assert_eq!(j["partial"], true);
        assert_eq!(j["excluded"][0]["reason"], REASON);
        assert_eq!(j["requested"]["recipes"][0], "ssh-hardening");
        assert!(p
            .summary_line("apply", false)
            .starts_with("PARTIAL_APPLY: 1 recipe(s)"));
    }
}
