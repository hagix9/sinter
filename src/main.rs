use clap::{Args, Parser, Subcommand};
use sinter::audit::{run_audit, AuditReport};
use sinter::bundle::{load_source, RecipeUnit, Source};
use sinter::diff::sanitize_line;
use sinter::engine::{Engine, Mode, RunOptions, RunReport, SshSpec, TargetSpec};
use sinter::error::{ErrorKind, SinterError};
use sinter::inventory::{load_inventory, Resolution};
use sinter::model::Model;
use sinter::output::{
    audit_report_json, render_apply, render_audit, render_plan, run_report_json, OutputFormat,
    RenderOptions,
};
use sinter::sshconfig::TargetRequest;
use sinter::style;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "sinter",
    version,
    about = "Sinter: a lightweight, agentless configuration-management tool"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Validate a recipe or bundle without connecting to a target.
    ///
    /// Only the recipe (or bundle and its recipes) is checked. Target options
    /// (--host, --inventory, --user, --port, --identity, ...) are accepted for
    /// a uniform command line and ignored: no host, inventory, key or
    /// known_hosts file is read.
    Validate(ValidateArgs),
    /// Preview changes against a target without mutating it.
    Plan(TargetArgs),
    /// Apply a recipe to a target.
    Apply(TargetArgs),
    /// Audit whether a target already satisfies a recipe. Read-only.
    Audit(TargetArgs),
    /// Serve a read-only MCP (Model Context Protocol) endpoint on stdio.
    Mcp(McpArgs),
}

#[derive(Args, Debug)]
struct McpArgs {
    /// Named SSH target profiles for read-only plan/audit tools (TOML).
    /// Omitted: host tools are registered but fail closed as unknown target.
    #[arg(long)]
    targets_file: Option<PathBuf>,
}

/// Execution-target options shared by validate, plan, apply and audit.
/// Every phase accepts the same set; each uses only what it needs
/// (validate uses none of them).
#[derive(Args, Debug, Default, Clone)]
struct ExecOpts {
    /// SSH host or ~/.ssh/config Host alias. If omitted (and no inventory is
    /// given), the target is localhost.
    #[arg(long)]
    host: Option<String>,
    /// Inventory file (YAML or TOML) defining hosts and groups. Each recipe
    /// runs only on the hosts its own `targets` select. Mutually exclusive
    /// with --host.
    #[arg(long, visible_alias = "hosts", value_name = "PATH")]
    inventory: Option<PathBuf>,
    /// SSH port [default: inventory port, ssh_config Port, else 22].
    #[arg(long)]
    port: Option<u16>,
    /// SSH user [default: inventory user, ssh_config User, else $USER].
    #[arg(long)]
    user: Option<String>,
    /// known_hosts file [default: inventory known_hosts, ssh_config
    /// UserKnownHostsFile, else ~/.ssh/known_hosts].
    #[arg(long)]
    known_hosts: Option<PathBuf>,
    /// SSH identity file (may be repeated); replaces inventory and
    /// ssh_config IdentityFile.
    #[arg(long = "identity")]
    identity: Vec<PathBuf>,
    /// Do not consult the OpenSSH client configuration (`ssh -G`).
    #[arg(long)]
    no_ssh_config: bool,
    /// Enable passwordless sudo (non-interactive `sudo -n`).
    #[arg(long)]
    sudo: bool,
}

#[derive(Args, Debug)]
struct ValidateArgs {
    /// Recipe or bundle file.
    recipe: PathBuf,
    /// Output format: text or json.
    #[arg(long, default_value = "text")]
    format: String,
    /// Accepted for a uniform command line; validate output is unchanged.
    #[arg(long)]
    verbose: bool,
    /// Accepted and ignored by validate.
    #[command(flatten)]
    exec: ExecOpts,
}

#[derive(Args, Debug)]
struct TargetArgs {
    /// Recipe or bundle file.
    recipe: PathBuf,
    #[command(flatten)]
    exec: ExecOpts,
    /// Verbose output.
    #[arg(long)]
    verbose: bool,
    /// Output format: text or json.
    #[arg(long, default_value = "text")]
    format: String,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!(
                "{} {}",
                style::status("sinter:", style::stderr_color()),
                sanitize_line(&e.message)
            );
            ExitCode::from(e.kind.exit_code() as u8)
        }
    }
}

fn run(cli: Cli) -> Result<u8, SinterError> {
    match cli.command {
        Command::Validate(a) => validate(&a),
        Command::Plan(a) => run_phase(Phase::Plan, &a),
        Command::Apply(a) => run_phase(Phase::Apply, &a),
        Command::Audit(a) => run_phase(Phase::Audit, &a),
        Command::Mcp(a) => {
            // Load once, fail closed: a missing/unreadable/malformed targets
            // file aborts startup; the registry is immutable while serving.
            let targets = match &a.targets_file {
                Some(p) => sinter::targets::TargetRegistry::load(p)?,
                None => sinter::targets::TargetRegistry::default(),
            };
            sinter::mcp::serve(targets)?;
            Ok(0)
        }
    }
}

/// Static validation only: `a.exec` and `a.verbose` are intentionally unused.
fn validate(a: &ValidateArgs) -> Result<u8, SinterError> {
    let format = parse_format(&a.format)?;
    let source = load_source(&a.recipe)?;
    let color = style::stdout_color();
    let counts = |m: &Model| (m.resources.len(), m.handlers.len(), m.vars.len());
    match (&source, format) {
        (Source::Recipe(u), OutputFormat::Json) => {
            let (r, h, v) = counts(&u.model);
            let doc = serde_json::json!({
                "command": "validate",
                "status": "ok",
                "resources": r,
                "handlers": h,
                "vars": v,
            });
            println!("{}", serde_json::to_string_pretty(&doc).unwrap());
        }
        (Source::Recipe(u), OutputFormat::Text) => {
            let (r, h, v) = counts(&u.model);
            println!(
                "{}: {} resource(s), {} handler(s), {} var(s)",
                style::status("ok", color),
                r,
                h,
                v
            );
        }
        (Source::Bundle(b), OutputFormat::Json) => {
            let recipes: Vec<serde_json::Value> = b
                .recipes
                .iter()
                .map(|u| {
                    let (r, h, v) = counts(&u.model);
                    serde_json::json!({
                        "recipe": u.label,
                        "path": u.path.display().to_string(),
                        "resources": r,
                        "handlers": h,
                        "vars": v,
                        "targets": u.model.targets.as_ref().map(|t| serde_json::json!({
                            "hosts": t.hosts,
                            "groups": t.groups,
                        })),
                    })
                })
                .collect();
            let total =
                |f: fn(&Model) -> usize| b.recipes.iter().map(|u| f(&u.model)).sum::<usize>();
            let doc = serde_json::json!({
                "command": "validate",
                "status": "ok",
                "resources": total(|m| m.resources.len()),
                "handlers": total(|m| m.handlers.len()),
                "vars": total(|m| m.vars.len()),
                "bundle": b.name,
                "recipes": recipes,
            });
            println!("{}", serde_json::to_string_pretty(&doc).unwrap());
        }
        (Source::Bundle(b), OutputFormat::Text) => {
            println!(
                "{}: bundle {}: {} recipe(s)",
                style::status("ok", color),
                sanitize_line(&b.name),
                b.recipes.len()
            );
            for u in &b.recipes {
                let (r, h, v) = counts(&u.model);
                let targets = match &u.model.targets {
                    None => "targets: none".to_string(),
                    Some(t) => format!(
                        "targets: hosts [{}] groups [{}]",
                        t.hosts.join(", "),
                        t.groups.join(", ")
                    ),
                };
                println!(
                    "  {}  {}: {} resource(s), {} handler(s), {} var(s); {}",
                    style::status("ok", color),
                    sanitize_line(&u.label),
                    r,
                    h,
                    v,
                    targets
                );
            }
        }
    }
    Ok(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Plan,
    Apply,
    Audit,
}

impl Phase {
    fn name(self) -> &'static str {
        match self {
            Phase::Plan => "plan",
            Phase::Apply => "apply",
            Phase::Audit => "audit",
        }
    }
}

enum Outcome {
    Run(Box<RunReport>),
    Audit(AuditReport),
}

impl Outcome {
    fn exit_code(&self) -> u8 {
        match self {
            Outcome::Run(r) => report_status_code(&r.status),
            Outcome::Audit(report) => report.exit_code(),
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Outcome::Run(r) => aggregate_label(r.status),
            Outcome::Audit(r) => r.aggregate_label(),
        }
    }

    fn render(&self, phase: Phase, ro: &RenderOptions) -> Result<(), SinterError> {
        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        match (self, phase) {
            (Outcome::Audit(r), _) => render_audit(r, ro, &mut lock),
            (Outcome::Run(r), Phase::Apply) => render_apply(r, ro, &mut lock),
            (Outcome::Run(r), _) => render_plan(r, ro, &mut lock),
        }
        .map_err(io_error)
    }

    fn json(&self, phase: Phase) -> serde_json::Value {
        match self {
            Outcome::Run(r) => run_report_json(r, phase.name()),
            Outcome::Audit(r) => audit_report_json(r),
        }
    }
}

fn run_phase(phase: Phase, a: &TargetArgs) -> Result<u8, SinterError> {
    let format = parse_format(&a.format)?;
    if a.exec.host.is_some() && a.exec.inventory.is_some() {
        return Err(SinterError::schema(
            "--host and --inventory (--hosts) are mutually exclusive: give one host, or select hosts through the recipe targets and an inventory",
        ));
    }
    let source = load_source(&a.recipe)?;
    let ro = RenderOptions {
        verbose: a.verbose,
        format,
        color: format == OutputFormat::Text && style::stdout_color(),
    };
    if let Some(inv) = &a.exec.inventory {
        let plan = inventory_plan(&source, a, inv)?;
        return run_executions(phase, &source, plan, a, &ro);
    }
    let target = single_target(a)?;
    match &source {
        Source::Recipe(u) => {
            // The established single-target path: one document, unchanged.
            let outcome = execute(phase, u.model.clone(), target.spec, a, None)?;
            outcome.render(phase, &ro)?;
            Ok(outcome.exit_code())
        }
        Source::Bundle(b) => {
            // One explicit target (--host or localhost): every recipe of the
            // bundle, in order, on that target.
            let executions = (0..b.recipes.len())
                .map(|i| Execution {
                    unit: i,
                    target: target.clone(),
                })
                .collect();
            let plan = ExecutionPlan {
                inventory: None,
                resolutions: Vec::new(),
                executions,
            };
            run_executions(phase, &source, plan, a, &ro)
        }
    }
}

/// A connection target with its display identity.
#[derive(Clone)]
struct Target {
    name: String,
    spec: TargetSpec,
}

impl Target {
    fn describe(&self) -> String {
        match &self.spec.ssh {
            Some(s) => format!(
                "{}@{}:{}",
                sanitize_line(&s.user),
                sanitize_line(&s.host),
                s.port
            ),
            None => "local".to_string(),
        }
    }

    fn json(&self) -> serde_json::Value {
        match &self.spec.ssh {
            Some(s) => serde_json::json!({
                "name": self.name, "host": s.host, "port": s.port, "user": s.user,
            }),
            None => serde_json::json!({
                "name": self.name, "host": null, "port": null, "user": null,
            }),
        }
    }
}

fn single_target(a: &TargetArgs) -> Result<Target, SinterError> {
    Ok(match &a.exec.host {
        None => Target {
            name: "localhost".to_string(),
            spec: TargetSpec { ssh: None },
        },
        Some(host) => {
            let req = TargetRequest {
                label: host.clone(),
                host: host.clone(),
                port: a.exec.port,
                user: a.exec.user.clone(),
                known_hosts: a.exec.known_hosts.clone(),
                identity_files: a.exec.identity.clone(),
            };
            Target {
                name: host.clone(),
                spec: TargetSpec {
                    ssh: Some(resolve_request(&req, !a.exec.no_ssh_config)?),
                },
            }
        }
    })
}

/// Resolve one target through the precedence chain documented in
/// `sinter::sshconfig`: explicit CLI > inventory > ssh_config > default.
fn resolve_request(req: &TargetRequest, use_ssh_config: bool) -> Result<SshSpec, SinterError> {
    let view = if use_ssh_config {
        sinter::sshconfig::query_openssh(&req.host, req.user.as_deref(), req.port)?
    } else {
        None
    };
    let home = std::env::var_os("HOME").map(PathBuf::from);
    sinter::sshconfig::resolve(
        req,
        view.as_ref(),
        std::env::var("USER").ok(),
        home.as_deref(),
    )
}

/// One (recipe, target) pair to run.
struct Execution {
    unit: usize,
    target: Target,
}

struct ExecutionPlan {
    inventory: Option<PathBuf>,
    /// Per recipe (same order as the source's units), inventory mode only.
    resolutions: Vec<Resolution>,
    executions: Vec<Execution>,
}

/// Inventory mode, fail closed. Before anything connects:
///
/// * every recipe must declare `targets`, naming only inventory hosts and
///   groups, and select at least one host;
/// * every *selected* host is resolved (`ssh -G` included); hosts no recipe
///   selects are never resolved or contacted;
/// * two selected hosts may not resolve to the same address and port.
///
/// Executions are recipe-major (bundle order), hosts in name order.
fn inventory_plan(
    source: &Source,
    a: &TargetArgs,
    inv_path: &Path,
) -> Result<ExecutionPlan, SinterError> {
    let inv = load_inventory(inv_path)?;
    let mut resolutions = Vec::new();
    for u in source.units() {
        resolutions.push(sinter::inventory::resolve(
            &inv,
            u.model.targets.as_ref(),
            &u.label,
        )?);
    }
    let mut targets: BTreeMap<String, Target> = BTreeMap::new();
    for r in &resolutions {
        for name in r.selected() {
            if targets.contains_key(name) {
                continue;
            }
            let h = &inv.hosts[name];
            let req = TargetRequest {
                label: name.to_string(),
                host: h.address.clone(),
                port: a.exec.port.or(h.port),
                user: a.exec.user.clone().or(h.user.clone()),
                known_hosts: a.exec.known_hosts.clone().or(h.known_hosts.clone()),
                identity_files: if a.exec.identity.is_empty() {
                    h.identity_files.clone()
                } else {
                    a.exec.identity.clone()
                },
            };
            let spec = resolve_request(&req, !a.exec.no_ssh_config).map_err(|e| SinterError {
                message: format!("host {}: {}", name, e.message),
                ..e
            })?;
            if let Some(other) = targets.values().find(|t| {
                t.spec
                    .ssh
                    .as_ref()
                    .is_some_and(|s| s.host == spec.host && s.port == spec.port)
            }) {
                return Err(SinterError::schema(format!(
                    "inventory hosts {} and {} resolve to the same address {}:{}",
                    other.name, name, spec.host, spec.port
                )));
            }
            targets.insert(
                name.to_string(),
                Target {
                    name: name.to_string(),
                    spec: TargetSpec { ssh: Some(spec) },
                },
            );
        }
    }
    let mut executions = Vec::new();
    for (i, r) in resolutions.iter().enumerate() {
        for name in r.selected() {
            executions.push(Execution {
                unit: i,
                target: targets[name].clone(),
            });
        }
    }
    Ok(ExecutionPlan {
        inventory: Some(inv.path.clone()),
        resolutions,
        executions,
    })
}

fn print_resolution(source: &Source, plan: &ExecutionPlan, ro: &RenderOptions) {
    if let Source::Bundle(b) = source {
        println!(
            "== bundle {} ({}) ==",
            sanitize_line(&b.name),
            sanitize_line(&b.path.display().to_string())
        );
    }
    if plan.inventory.is_some() {
        println!("== target resolution ==");
        for (u, r) in source.units().iter().zip(&plan.resolutions) {
            println!(
                "recipe {} ({})",
                sanitize_line(&u.label),
                sanitize_line(&u.path.display().to_string())
            );
            let width = r.hosts.iter().map(|h| h.name.len()).max().unwrap_or(0);
            for h in &r.hosts {
                if h.selected() {
                    println!(
                        "  {:width$}  {}  {}",
                        h.name,
                        style::status("MATCH", ro.color),
                        h.reasons.join(", ")
                    );
                } else {
                    println!("  {:width$}  SKIP   no matching target", h.name);
                }
            }
            let selected = r.selected().count();
            println!(
                "  selected {}, excluded {}",
                selected,
                r.hosts.len() - selected
            );
        }
    }
    let hosts = plan.resolutions.first().map(|r| r.hosts.len()).unwrap_or(1);
    println!(
        "executions: {} ({} recipe(s), {} host(s))",
        plan.executions.len(),
        source.units().len(),
        hosts
    );
    println!();
}

/// Backup run id for one execution: the invocation id, suffixed with the
/// recipe position and name when several recipes run, so each recipe gets
/// its own run directory on a host.
fn backup_id(run_id: &str, units: &[RecipeUnit], unit: usize) -> String {
    if units.len() == 1 {
        return run_id.to_string();
    }
    let label: String = units[unit]
        .label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(40)
        .collect();
    format!("{}-{:02}-{}", run_id, unit + 1, label)
}

struct ExecResult {
    unit: usize,
    target: Target,
    exit_code: Option<u8>,
    label: &'static str,
    json: serde_json::Value,
    /// Execution-level `backup` record (see [`backup_record`]).
    backup: serde_json::Value,
}

/// Execution-level `backup` record of the aggregate document. It is built
/// only from this execution's own report or error, so records of different
/// hosts and recipes can never mix, and it holds paths, statuses, kinds and
/// locations only — never content.
///
/// * `null` — the recipe declares no backup, or the phase is audit;
/// * `planned` — plan (nothing is copied);
/// * `completed` — apply copied every declared path;
/// * `failed` — apply's backup step failed (per-path `failed` / `not_run`);
/// * `not_started` — apply failed before the backup step (e.g. connection);
/// * `not_run` — the execution was not run (apply stopped earlier).
fn backup_record(
    phase: Phase,
    unit: &RecipeUnit,
    outcome: Option<&Result<Outcome, SinterError>>,
) -> serde_json::Value {
    use sinter::backup::{planned, BackupStatus};
    if phase == Phase::Audit || unit.model.backups.is_empty() {
        return serde_json::Value::Null;
    }
    let not_run = || {
        let mut r = planned(&unit.model.backups);
        for e in &mut r.entries {
            e.status = BackupStatus::NotRun;
        }
        r
    };
    let (status, report) = match outcome {
        None => ("not_run", not_run()),
        Some(Ok(Outcome::Run(r))) => match (&r.backup, phase) {
            (Some(b), Phase::Plan) => ("planned", b.clone()),
            (Some(b), _) => ("completed", b.clone()),
            (None, _) => return serde_json::Value::Null,
        },
        Some(Ok(Outcome::Audit(_))) => return serde_json::Value::Null,
        Some(Err(e)) => match (&e.backup, phase) {
            (Some(b), _) => ("failed", (**b).clone()),
            (None, Phase::Plan) => ("planned", planned(&unit.model.backups)),
            (None, _) => ("not_started", not_run()),
        },
    };
    let mut v = sinter::output::backup_json(&report);
    v["status"] = serde_json::Value::from(status);
    v
}

/// Run an execution plan sequentially.
///
/// * plan and audit are read-only and attempt every execution.
/// * apply stops at the first execution that does not exit 0 (connection,
///   backup, apply failure or indeterminate result); every later execution
///   is reported as `not_run`.
/// * The exit code is the most severe execution exit code
///   (6 > 5 > 4 > 3 > 2 > 7 > 0); a partial failure is never exit 0.
fn run_executions(
    phase: Phase,
    source: &Source,
    plan: ExecutionPlan,
    a: &TargetArgs,
    ro: &RenderOptions,
) -> Result<u8, SinterError> {
    let text = ro.format == OutputFormat::Text;
    let units = source.units();
    if text {
        print_resolution(source, &plan, ro);
    }
    let run_id = sinter::backup::new_run_id();
    let mut results: Vec<ExecResult> = Vec::new();
    let mut stopped_by: Option<String> = None;
    for ex in plan.executions {
        let u = &units[ex.unit];
        let what = format!("{} @ {}", u.label, ex.target.name);
        if let Some(culprit) = &stopped_by {
            results.push(ExecResult {
                unit: ex.unit,
                target: ex.target,
                exit_code: None,
                label: "not_run",
                json: serde_json::json!({ "reason": format!("apply stopped after {} failed", culprit) }),
                backup: backup_record(phase, u, None),
            });
            continue;
        }
        if text {
            println!("== {} ({}) ==", sanitize_line(&what), ex.target.describe());
        }
        let id = backup_id(&run_id, units, ex.unit);
        let executed = execute(phase, u.model.clone(), ex.target.spec.clone(), a, Some(&id));
        let backup = backup_record(phase, u, Some(&executed));
        let (code, label, json) = match executed {
            Ok(outcome) => {
                if text {
                    outcome.render(phase, ro)?;
                }
                (
                    outcome.exit_code(),
                    outcome.label(),
                    serde_json::json!({ "result": outcome.json(phase) }),
                )
            }
            Err(e) => {
                eprintln!(
                    "{} [{}] {}",
                    style::status("sinter:", style::stderr_color()),
                    sanitize_line(&what),
                    sanitize_line(&e.message)
                );
                if text {
                    println!(
                        "{}: {}",
                        style::status("error", ro.color),
                        sanitize_line(&e.message)
                    );
                }
                (
                    e.kind.exit_code() as u8,
                    "error",
                    serde_json::json!({ "error": { "kind": kind_label(e.kind), "message": e.message } }),
                )
            }
        };
        if text {
            println!();
        }
        if stops_remaining(phase, code) {
            stopped_by = Some(what);
        }
        results.push(ExecResult {
            unit: ex.unit,
            target: ex.target,
            exit_code: Some(code),
            label,
            json,
            backup,
        });
    }

    let overall = results
        .iter()
        .filter_map(|r| r.exit_code)
        .max_by_key(|c| severity(*c))
        .unwrap_or(0);
    if text {
        println!("== executions ==");
        let rw = results
            .iter()
            .map(|r| units[r.unit].label.len())
            .max()
            .unwrap_or(0);
        let tw = results
            .iter()
            .map(|r| r.target.name.len())
            .max()
            .unwrap_or(0);
        for r in &results {
            println!(
                "{:rw$}  {:tw$}  {}  exit={}  {}",
                sanitize_line(&units[r.unit].label),
                sanitize_line(&r.target.name),
                style::status(r.label, ro.color),
                r.exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                r.target.describe(),
            );
        }
        let zero = results.iter().filter(|r| r.exit_code == Some(0)).count();
        let not_run = results.iter().filter(|r| r.exit_code.is_none()).count();
        println!(
            "executions: {} total, {} exit 0, {} non-zero, {} not run",
            results.len(),
            zero,
            results.len() - zero - not_run,
            not_run
        );
    } else {
        let executions: Vec<serde_json::Value> = results
            .iter()
            .map(|r| {
                let mut o = serde_json::json!({
                    "recipe": units[r.unit].label,
                    "target": r.target.json(),
                    "status": r.label,
                    "exit_code": r.exit_code,
                    "backup": r.backup,
                });
                if let (Some(obj), Some(extra)) = (o.as_object_mut(), r.json.as_object()) {
                    for (k, v) in extra {
                        obj.insert(k.clone(), v.clone());
                    }
                }
                o
            })
            .collect();
        let resolution: Option<Vec<serde_json::Value>> = plan.inventory.as_ref().map(|_| {
            units
                .iter()
                .zip(&plan.resolutions)
                .map(|(u, r)| {
                    serde_json::json!({
                        "recipe": u.label,
                        "path": u.path.display().to_string(),
                        "hosts": r.hosts.iter().map(|h| serde_json::json!({
                            "name": h.name,
                            "selected": h.selected(),
                            "reasons": h.reasons,
                        })).collect::<Vec<_>>(),
                    })
                })
                .collect()
        });
        let bundle = match source {
            Source::Bundle(b) => serde_json::json!({
                "name": b.name,
                "path": b.path.display().to_string(),
            }),
            Source::Recipe(_) => serde_json::Value::Null,
        };
        let doc = serde_json::json!({
            "mode": phase.name(),
            "exit_code": overall,
            "bundle": bundle,
            "inventory": plan.inventory.as_ref().map(|p| p.display().to_string()),
            "resolution": resolution,
            "executions": executions,
        });
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
    }
    Ok(overall)
}

fn execute(
    phase: Phase,
    model: Model,
    target: TargetSpec,
    a: &TargetArgs,
    backup_run_id: Option<&str>,
) -> Result<Outcome, SinterError> {
    // Audit uses Plan-mode construction: a read-only TargetFs, and run_audit
    // additionally refuses any engine that can produce a mutation permit, so
    // audit is mutation-free by construction twice over.
    let mode = if phase == Phase::Apply {
        Mode::Apply
    } else {
        Mode::Plan
    };
    let opts = RunOptions {
        mode,
        sudo: a.exec.sudo,
        target,
        verbose: a.verbose,
        fault: None,
        fake_target: None,
    };
    let mut engine = Engine::new(model, opts)?;
    if let Some(id) = backup_run_id {
        engine = engine.with_backup_run_id(id.to_string());
    }
    Ok(match phase {
        Phase::Audit => Outcome::Audit(run_audit(engine)?),
        _ => Outcome::Run(Box::new(engine.run()?)),
    })
}

/// Apply fail-fast rule: during apply, any execution that does not exit 0
/// (validation 2, connection/capability 3, plan 4, apply or backup failure
/// 5, indeterminate 6) stops the sequence; every later execution is
/// reported `not_run` and never contacted. plan and audit never stop.
fn stops_remaining(phase: Phase, code: u8) -> bool {
    phase == Phase::Apply && code != 0
}

/// Rank execution exit codes for the aggregate: indeterminate first, then
/// apply failure, plan failure, connection, validation, drift, success.
fn severity(code: u8) -> u8 {
    match code {
        6 => 7,
        5 => 6,
        4 => 5,
        3 => 4,
        2 => 3,
        7 => 2,
        0 => 0,
        _ => 1,
    }
}

fn kind_label(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::Schema => "schema",
        ErrorKind::Connect => "connect",
        ErrorKind::Plan => "plan",
        ErrorKind::Apply => "apply",
        ErrorKind::Indeterminate => "indeterminate",
        ErrorKind::Unknown => "unknown",
    }
}

fn parse_format(s: &str) -> Result<OutputFormat, SinterError> {
    match s {
        "text" => Ok(OutputFormat::Text),
        "json" => Ok(OutputFormat::Json),
        other => Err(SinterError::schema(format!(
            "unsupported output format: {} (expected text or json)",
            other
        ))),
    }
}

fn io_error(e: std::io::Error) -> SinterError {
    SinterError::apply(format!("output error: {}", e))
}

fn aggregate_label(status: sinter::engine::AggregateStatus) -> &'static str {
    use sinter::engine::AggregateStatus::*;
    match status {
        Success => "success",
        PlanError => "plan_error",
        ApplyFailed => "apply_failed",
        Indeterminate => "indeterminate",
    }
}

fn report_status_code(status: &sinter::engine::AggregateStatus) -> u8 {
    use sinter::engine::AggregateStatus::*;
    match status {
        Success => 0,
        PlanError => ErrorKind::Plan.exit_code() as u8,
        ApplyFailed => ErrorKind::Apply.exit_code() as u8,
        Indeterminate => ErrorKind::Indeterminate.exit_code() as u8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_stops_on_every_non_zero_exit_code() {
        for code in [2u8, 3, 4, 5, 6, 7] {
            assert!(stops_remaining(Phase::Apply, code), "apply, exit {code}");
        }
        assert!(!stops_remaining(Phase::Apply, 0));
    }

    #[test]
    fn read_only_phases_never_stop() {
        for code in [0u8, 2, 3, 4, 5, 6, 7] {
            assert!(!stops_remaining(Phase::Plan, code), "plan, exit {code}");
            assert!(!stops_remaining(Phase::Audit, code), "audit, exit {code}");
        }
    }

    #[test]
    fn aggregate_exit_code_is_the_most_severe() {
        let worst = |codes: &[u8]| codes.iter().copied().max_by_key(|c| severity(*c)).unwrap();
        assert_eq!(worst(&[0, 7, 3]), 3);
        assert_eq!(worst(&[4, 5]), 5);
        assert_eq!(worst(&[5, 6, 0]), 6);
        assert_eq!(worst(&[0, 7]), 7);
        assert_eq!(worst(&[2, 7]), 2);
        assert_eq!(worst(&[0, 0]), 0);
    }
}
