use clap::{Args, Parser, Subcommand};
use sinter::audit::{run_audit, AuditReport};
use sinter::bundle::{load_source, prepare_source, RecipeUnit, Source};
use sinter::diff::sanitize_line;
use sinter::engine::{Engine, Mode, RunOptions, RunReport, SshSpec, TargetSpec};
use sinter::error::{ErrorKind, SinterError};
use sinter::inventory::{load_inventory, Inventory, Resolution};
use sinter::model::Model;
use sinter::output::{
    audit_report_json, render_apply, render_audit, render_plan, run_report_json, OutputFormat,
    RenderOptions,
};
use sinter::progress::{ProgressSink, RunKind, RunOutcome};
use sinter::progress_plain::stderr_plain_consumer_factory;
use sinter::progress_session::{
    mode_from_environment, outcome_of_audit, outcome_of_error, outcome_of_report,
    references_secrets, ConsumerFactory, ProgressMode, ProgressOptions, ProgressSession,
    SessionInfo,
};
use sinter::progress_tty::stderr_consumer_factory;
use sinter::sshconfig::TargetRequest;
use sinter::style;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

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
    /// known_hosts file is read. With --vars-file the recipes are checked with
    /// the values that file gives, exactly as plan, apply and audit check them
    /// before contacting a host; the variables file and, with --inventory, the
    /// inventory are then read (and --host and --inventory stay exclusive).
    /// Nothing is contacted and ssh is not run.
    Validate(ValidateArgs),
    /// Preview changes against a target without mutating it.
    Plan(TargetArgs),
    /// Apply a recipe to a target.
    Apply(TargetArgs),
    /// Audit whether a target already satisfies a recipe. Read-only.
    Audit(TargetArgs),
    /// Serve a read-only MCP (Model Context Protocol) endpoint on stdio.
    Mcp(McpArgs),
    /// Encrypt, decrypt and list secret files (standard age format).
    Secrets(SecretsArgs),
}

#[derive(Args, Debug)]
struct SecretsArgs {
    #[command(subcommand)]
    command: SecretsCommand,
}

#[derive(Subcommand, Debug)]
enum SecretsCommand {
    /// Encrypt FILE (or stdin, `-`) to a new age file, FILE.age by default.
    ///
    /// With no --passphrase and no -r, the nearest recipients.txt (inside the
    /// repository) is used; otherwise a terminal is asked. The original file
    /// is never changed or deleted. An existing output is never replaced
    /// silently.
    Encrypt(SecretsEncryptArgs),
    /// Decrypt FILE to stdout. Refuses a terminal; never writes a file.
    ///
    /// A passphrase-encrypted secret asks for the passphrase on the terminal.
    /// A recipient-encrypted secret uses an identity: --identity, then
    /// SINTER_IDENTITY (a path), then the default identity
    /// (~/.config/sinter/identity), then a passphrase-protected identity.age in
    /// the repository.
    Decrypt(SecretsDecryptArgs),
    /// List age files (derived from the files; nothing is decrypted).
    List(SecretsListArgs),
}

#[derive(Args, Debug)]
struct SecretsEncryptArgs {
    /// File to encrypt, or `-` for stdin (then -o is required).
    file: PathBuf,
    /// Encrypt with a passphrase typed on the terminal (never argv, env or stdin).
    #[arg(long, conflicts_with = "recipient")]
    passphrase: bool,
    /// age recipient (age1...); may be repeated.
    #[arg(short = 'r', long = "recipient", value_name = "RECIPIENT")]
    recipient: Vec<String>,
    /// Output file [default: FILE.age].
    #[arg(short = 'o', long, value_name = "OUT")]
    output: Option<PathBuf>,
    /// Replace an existing age file at the output.
    #[arg(short = 'f', long)]
    force: bool,
}

#[derive(Args, Debug)]
struct SecretsDecryptArgs {
    /// Secret file to decrypt.
    file: PathBuf,
    /// Identity file (private key, or passphrase-protected private key).
    #[arg(short = 'i', long, value_name = "PATH")]
    identity: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct SecretsListArgs {
    /// Files or directories [default: current directory]. Directories list
    /// their *.age files.
    paths: Vec<PathBuf>,
    /// Output format: text or json.
    #[arg(long, default_value = "text")]
    format: String,
    /// Also report which resources of this recipe (or bundle) use each
    /// secret, and which listed secrets it does not reference. Repeatable;
    /// only the recipes named are considered. Never decrypts.
    #[arg(long, value_name = "FILE")]
    recipe: Vec<PathBuf>,
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
/// (validate uses none of them, except --vars-file and what that needs:
/// --inventory and --host).
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
    /// Enable passwordless sudo (non-interactive `sudo -n`). A target user that
    /// is already root runs directly, without sudo.
    #[arg(long)]
    sudo: bool,
    /// Variables file (YAML or TOML): common (`vars`), per-group (`groups`,
    /// needs --inventory) and per-host (`hosts`) values for variables the
    /// recipes declare. Every host is checked before any is contacted. Plain
    /// text: never put secrets in it; sensitive variables cannot be set here.
    #[arg(long, value_name = "PATH")]
    vars_file: Option<PathBuf>,
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
    /// Accepted by validate and ignored, except --vars-file (with --inventory
    /// or --host), which validate checks.
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
        Command::Secrets(a) => secrets_command(a),
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

fn secrets_command(a: SecretsArgs) -> Result<u8, SinterError> {
    use sinter::secrets_cli as sc;
    use std::io::IsTerminal;
    let env = sc::Env::from_process();
    // Raw, unbuffered descriptors: plaintext must not pass through the standard
    // library's stdin/stdout buffers (extra copies that nothing zeroizes). The
    // `File`s are not closed on drop.
    use std::os::fd::FromRawFd;
    let mut stdin = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(0) });
    let stdin_is_tty = std::io::stdin().is_terminal();
    let mut stdout = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(1) });
    let stdout_is_tty = std::io::stdout().is_terminal();
    let mut stderr = std::io::stderr().lock();
    let mut prompter = sc::TtyPrompter;
    let mut io = sc::Io {
        stdin: &mut *stdin,
        stdin_is_tty,
        stdout: &mut *stdout,
        stdout_is_tty,
        stderr: &mut stderr,
        prompter: &mut prompter,
        env: &env,
    };
    match a.command {
        SecretsCommand::Encrypt(e) => sc::encrypt(
            &sc::EncryptArgs {
                file: e.file,
                output: e.output,
                passphrase: e.passphrase,
                recipients: e.recipient,
                force: e.force,
            },
            &mut io,
        ),
        SecretsCommand::Decrypt(d) => sc::decrypt(
            &sc::DecryptArgs {
                file: d.file,
                identity: d.identity,
            },
            &mut io,
        ),
        SecretsCommand::List(l) => {
            let json = matches!(parse_format(&l.format)?, OutputFormat::Json);
            sc::list_for_recipes(
                &sc::ListArgs {
                    paths: l.paths,
                    json,
                },
                &l.recipe,
                &mut io,
            )
        }
    }
}

/// What `validate --vars-file` reports besides the usual document: the file
/// as given, how many (recipe, host) executions were checked with it, and
/// each recipe's warnings over all of them (DESIGN §19.5).
struct VarsReport {
    file: String,
    executions: usize,
    /// Per recipe, in order: its executions' warnings, without repeats.
    warnings: Vec<Vec<String>>,
}

/// Most warnings of one recipe `validate --vars-file` lists; the rest are
/// counted (`warnings_omitted`).
const MAX_VALIDATE_WARNINGS: usize = 50;

/// Static validation. Without `--vars-file` only the recipe (or bundle) is
/// checked and every target option is accepted and ignored: no inventory, key
/// or known_hosts file is read. With `--vars-file` the recipes are checked
/// with the values the file gives, by the very static gate `plan`, `apply`
/// and `audit` run before they contact a host (DESIGN §19.5): the
/// variables file and, with `--inventory`, the inventory are read, and still
/// nothing is contacted and no `ssh -G` runs.
fn validate(a: &ValidateArgs) -> Result<u8, SinterError> {
    let format = parse_format(&a.format)?;
    let Some(vars_path) = &a.exec.vars_file else {
        let source = load_source(&a.recipe)?;
        return print_validate(&source, format, None);
    };
    exclusive_target_options(&a.exec)?;
    let gate = vars_gate(&a.recipe, &a.exec, vars_path)?;
    // The first thing `plan` checks of `--host` after the gate (a pure check).
    if let Some(host) = &a.exec.host {
        sinter::sshconfig::validate_host_arg(host)?;
    }
    let mut warnings: Vec<Vec<String>> = vec![Vec::new(); gate.source.units().len()];
    for f in &gate.frozen {
        if let Some(list) = warnings.get_mut(f.unit) {
            for w in &f.model.warnings {
                if !list.contains(w) {
                    list.push(w.clone());
                }
            }
        }
    }
    let report = VarsReport {
        file: vars_path.display().to_string(),
        executions: gate.frozen.len(),
        warnings,
    };
    print_validate(&gate.source, format, Some(&report))
}

/// A recipe's warnings to show, and how many more are left out.
fn shown_warnings(vars: Option<&VarsReport>, i: usize, u: &RecipeUnit) -> (Vec<String>, usize) {
    match vars {
        None => (u.model.warnings.clone(), 0),
        Some(v) => {
            let all = v.warnings.get(i).cloned().unwrap_or_default();
            let omitted = all.len().saturating_sub(MAX_VALIDATE_WARNINGS);
            (
                all.into_iter().take(MAX_VALIDATE_WARNINGS).collect(),
                omitted,
            )
        }
    }
}

/// `variables` is present only when `--vars-file` was given.
fn add_variables(doc: &mut serde_json::Value, vars: Option<&VarsReport>) {
    if let Some(v) = vars {
        doc["variables"] = serde_json::json!({
            "file": v.file,
            "executions": v.executions,
        });
    }
}

fn print_validate(
    source: &Source,
    format: OutputFormat,
    vars: Option<&VarsReport>,
) -> Result<u8, SinterError> {
    let color = style::stdout_color();
    let counts = |m: &Model| (m.resources.len(), m.handlers.len(), m.vars.len());
    match (source, format) {
        (Source::Recipe(u), OutputFormat::Json) => {
            let (r, h, v) = counts(&u.model);
            let mut doc = serde_json::json!({
                "command": "validate",
                "status": "ok",
                "resources": r,
                "handlers": h,
                "vars": v,
            });
            let (warnings, omitted) = shown_warnings(vars, 0, u);
            if !warnings.is_empty() {
                doc["warnings"] = serde_json::json!(warnings);
                if omitted > 0 {
                    doc["warnings_omitted"] = serde_json::json!(omitted);
                }
            }
            add_variables(&mut doc, vars);
            println!("{}", serde_json::to_string_pretty(&doc).unwrap());
        }
        (Source::Recipe(u), OutputFormat::Text) => {
            let (warnings, omitted) = shown_warnings(vars, 0, u);
            for w in &warnings {
                eprintln!("warning: {}", sanitize_line(w));
            }
            if omitted > 0 {
                eprintln!("warning: ... and {omitted} more warning(s)");
            }
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
                .enumerate()
                .map(|(i, u)| {
                    let (r, h, v) = counts(&u.model);
                    let mut rec = serde_json::json!({
                        "recipe": u.label,
                        "path": u.path.display().to_string(),
                        "resources": r,
                        "handlers": h,
                        "vars": v,
                        "targets": u.model.targets.as_ref().map(|t| serde_json::json!({
                            "hosts": t.hosts,
                            "groups": t.groups,
                        })),
                    });
                    let (warnings, omitted) = shown_warnings(vars, i, u);
                    if !warnings.is_empty() {
                        rec["warnings"] = serde_json::json!(warnings);
                        if omitted > 0 {
                            rec["warnings_omitted"] = serde_json::json!(omitted);
                        }
                    }
                    rec
                })
                .collect();
            let total =
                |f: fn(&Model) -> usize| b.recipes.iter().map(|u| f(&u.model)).sum::<usize>();
            let mut doc = serde_json::json!({
                "command": "validate",
                "status": "ok",
                "resources": total(|m| m.resources.len()),
                "handlers": total(|m| m.handlers.len()),
                "vars": total(|m| m.vars.len()),
                "bundle": b.name,
                "recipes": recipes,
            });
            add_variables(&mut doc, vars);
            println!("{}", serde_json::to_string_pretty(&doc).unwrap());
        }
        (Source::Bundle(b), OutputFormat::Text) => {
            for (i, u) in b.recipes.iter().enumerate() {
                let (warnings, omitted) = shown_warnings(vars, i, u);
                for w in &warnings {
                    eprintln!("warning: {}: {}", sanitize_line(&u.label), sanitize_line(w));
                }
                if omitted > 0 {
                    eprintln!(
                        "warning: {}: ... and {omitted} more warning(s)",
                        sanitize_line(&u.label)
                    );
                }
            }
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
    if let (Some(v), OutputFormat::Text) = (vars, format) {
        println!(
            "{}: variables file {} checked: {} execution(s)",
            style::status("ok", color),
            sanitize_line(&v.file),
            v.executions
        );
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

    fn kind(self) -> RunKind {
        match self {
            Phase::Plan => RunKind::Plan,
            Phase::Apply => RunKind::Apply,
            Phase::Audit => RunKind::Audit,
        }
    }
}

/// Progress facts about one recipe, known before it runs.
fn unit_info(phase: Phase, unit: &RecipeUnit) -> SessionInfo {
    SessionInfo {
        kind: phase.kind(),
        references_secrets: references_secrets(&unit.model),
    }
}

/// Progress facts about a whole source (the resolution scope of a multi-
/// execution invocation).
fn source_info(phase: Phase, source: &Source) -> SessionInfo {
    SessionInfo {
        kind: phase.kind(),
        references_secrets: source.units().iter().any(|u| references_secrets(&u.model)),
    }
}

/// How a progress scope that ran `result` ended. Closed vocabulary only.
fn scope_outcome<T>(result: &Result<T, SinterError>) -> RunOutcome {
    match result {
        Ok(_) => RunOutcome::Completed,
        Err(e) => outcome_of_error(e),
    }
}

/// How an execution ended, for progress: a report maps through its status, a
/// returned error is never a completed run.
fn run_outcome_of(result: &Result<Outcome, SinterError>) -> RunOutcome {
    match result {
        Ok(outcome) => outcome.run_outcome(),
        Err(e) => outcome_of_error(e),
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

    /// Closed run outcome for progress; never carries report content.
    fn run_outcome(&self) -> RunOutcome {
        match self {
            Outcome::Run(r) => outcome_of_report(r),
            Outcome::Audit(r) => outcome_of_audit(r),
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

/// The renderer that belongs to the decided mode. The decision itself is
/// `mode_from_environment`, once per invocation; this only maps its result to
/// the consumer, and neither renderer looks at the terminal, `TERM`, the
/// format or the environment again. Neither builds a surface for a recipe that
/// references secrets (OQ-5).
fn consumer_factory_for(mode: ProgressMode) -> ConsumerFactory {
    match mode {
        ProgressMode::Plain => stderr_plain_consumer_factory(),
        // `Disabled` never builds a consumer; any other mode is the terminal one.
        _ => stderr_consumer_factory(),
    }
}

fn run_phase(phase: Phase, a: &TargetArgs) -> Result<u8, SinterError> {
    let format = parse_format(&a.format)?;
    // Phase 1 of the progress decision (see `sinter::progress_session`): JSON
    // means no progress at all; otherwise `SINTER_PROGRESS=plain` asks for the
    // plain renderer (S5) and without it an eligible terminal gets the
    // transient line (S4) and everything else (pipes, CI, TERM=dumb) none.
    let mode = mode_from_environment(format == OutputFormat::Json);
    let progress = ProgressOptions::new(mode).with_consumer_factory(consumer_factory_for(mode));
    run_phase_with(phase, a, format, &progress)
}

/// `--host` names one target and `--inventory` selects several through the
/// recipes' `targets`: giving both is a validation error (exit 2).
fn exclusive_target_options(exec: &ExecOpts) -> Result<(), SinterError> {
    if exec.host.is_some() && exec.inventory.is_some() {
        return Err(SinterError::schema(
            "--host and --inventory (--hosts) are mutually exclusive: give one host, or select hosts through the recipe targets and an inventory",
        ));
    }
    Ok(())
}

fn run_phase_with(
    phase: Phase,
    a: &TargetArgs,
    format: OutputFormat,
    progress: &ProgressOptions,
) -> Result<u8, SinterError> {
    exclusive_target_options(&a.exec)?;
    let ro = RenderOptions {
        verbose: a.verbose,
        format,
        color: format == OutputFormat::Text && style::stdout_color(),
    };
    if let Some(vars) = &a.exec.vars_file {
        return run_phase_vars(phase, a, vars, &ro, progress);
    }
    let source = load_source(&a.recipe)?;
    if let Some(inv) = &a.exec.inventory {
        // Several executions follow, so target resolution is a progress scope
        // of its own; each execution then gets its own.
        let session = progress.begin(source_info(phase, &source));
        let planned = inventory_plan(&source, a, inv, &session);
        session.end(scope_outcome(&planned));
        return run_executions(phase, &source, planned?, a, &ro, progress);
    }
    run_one_target(phase, &source, None, a, &ro, progress)
}

/// One explicit target (`--host` or localhost). `models`, one per recipe,
/// replace the recipes' own models (a variables file, DESIGN §19.5).
fn run_one_target(
    phase: Phase,
    source: &Source,
    frozen: Option<Vec<FrozenExecution>>,
    a: &TargetArgs,
    ro: &RenderOptions,
    progress: &ProgressOptions,
) -> Result<u8, SinterError> {
    // Checked before `ssh -G` or anything else runs: exactly one model per
    // recipe, frozen for this very target, in recipe order.
    let mut models = match frozen {
        Some(f) => Some(models_for_one_target(f, source, one_target_name(&a.exec))?.into_iter()),
        None => None,
    };
    match source {
        Source::Recipe(u) => {
            // The established single-target path: one document, unchanged. One
            // execution, so one progress scope covers resolution (if any) and
            // the run; it ends before anything is rendered.
            let model = match models.as_mut() {
                Some(m) => m
                    .next()
                    .ok_or_else(|| model_mismatch("no model for the recipe"))?,
                None => u.model.clone(),
            };
            let session = progress.begin(unit_info(phase, u));
            let executed = single_target(a, Some(&session))
                .and_then(|target| execute(phase, model, target.spec, a, None, session.sink()));
            session.end(run_outcome_of(&executed));
            let outcome = executed?;
            outcome.render(phase, ro)?;
            Ok(outcome.exit_code())
        }
        Source::Bundle(b) => {
            // One explicit target (--host or localhost): every recipe of the
            // bundle, in order, on that target.
            let target = match &a.exec.host {
                None => single_target(a, None)?,
                Some(_) => {
                    let session = progress.begin(source_info(phase, source));
                    let resolved = single_target(a, Some(&session));
                    session.end(scope_outcome(&resolved));
                    resolved?
                }
            };
            let mut executions = Vec::with_capacity(b.recipes.len());
            for i in 0..b.recipes.len() {
                let model = match models.as_mut() {
                    Some(m) => Some(
                        m.next()
                            .ok_or_else(|| model_mismatch("no model for a recipe"))?,
                    ),
                    None => None,
                };
                executions.push(Execution {
                    unit: i,
                    target: target.clone(),
                    model,
                });
            }
            let plan = ExecutionPlan {
                inventory: None,
                resolutions: Vec::new(),
                executions,
            };
            run_executions(phase, source, plan, a, ro, progress)
        }
    }
}

/// The static gate of a run with a variables file (DESIGN §19.5), shared by
/// `plan`, `apply`, `audit` and `validate --vars-file`. Before `ssh -G` or any
/// contact with a host, in this order: every recipe is loaded unfrozen, the
/// inventory is loaded, the variables file is read, targets are resolved,
/// and every (recipe, host) execution is checked and frozen with its own
/// values. One problem anywhere is exit 2 with nothing contacted.
struct VarsGate {
    /// The recipes, each with its first execution's model: the static parts a
    /// display or report reads.
    source: Source,
    inventory: Option<Inventory>,
    /// Inventory mode: the recipes' target resolutions. Single mode: empty.
    resolutions: Vec<Resolution>,
    /// One model per (recipe, host) execution, bound to the pair it was
    /// frozen for.
    frozen: Vec<FrozenExecution>,
}

fn vars_gate(recipe: &Path, exec: &ExecOpts, vars_path: &Path) -> Result<VarsGate, SinterError> {
    use sinter::varsfile::{freeze_executions, load_vars_file, Mode as VarsMode};
    let prepared = prepare_source(recipe)?;
    let inventory = match &exec.inventory {
        Some(p) => Some(load_inventory(p)?),
        None => None,
    };
    let vars = load_vars_file(vars_path).map_err(static_failure)?;
    let (resolutions, pairs): (Vec<Resolution>, Vec<(usize, String)>) = match &inventory {
        Some(inv) => {
            let resolutions = resolve_targets(
                inv,
                prepared
                    .units
                    .iter()
                    .map(|u| (u.label.as_str(), u.item.targets())),
            )?;
            let pairs = resolutions
                .iter()
                .enumerate()
                .flat_map(|(i, r)| r.selected().map(move |h| (i, h.to_string())))
                .collect();
            (resolutions, pairs)
        }
        None => {
            let name = one_target_name(exec);
            let pairs = (0..prepared.units.len())
                .map(|i| (i, name.to_string()))
                .collect();
            (Vec::new(), pairs)
        }
    };
    let mode = match &inventory {
        Some(inv) => VarsMode::Inventory(inv),
        None => VarsMode::Single,
    };
    let models =
        freeze_executions(&prepared.units, &vars, &mode, &pairs).map_err(static_failure)?;
    // From here on a model travels with the (recipe, host) it was frozen
    // for; it is only ever assigned by that key, never by position alone.
    #[allow(unused_mut)]
    let mut frozen = bind_models(pairs, models)?;
    #[cfg(test)]
    tests::tamper_frozen(&mut frozen);
    // Display and reporting read only static parts of a recipe's model
    // (targets, backups, secret references): its first execution's serves.
    let mut first: Vec<Option<Model>> = vec![None; prepared.units.len()];
    for f in &frozen {
        match first.get_mut(f.unit) {
            Some(slot) => {
                slot.get_or_insert_with(|| f.model.clone());
            }
            None => return Err(model_mismatch("a model belongs to no recipe of this run")),
        }
    }
    let first = first
        .into_iter()
        .collect::<Option<Vec<Model>>>()
        .ok_or_else(|| model_mismatch("a recipe of this run has no frozen model"))?;
    let source = prepared.into_source(first);
    Ok(VarsGate {
        source,
        inventory,
        resolutions,
        frozen,
    })
}

/// A run with a variables file (DESIGN §19.5): the static gate, then the run
/// proceeds exactly as without a variables file.
fn run_phase_vars(
    phase: Phase,
    a: &TargetArgs,
    vars_path: &Path,
    ro: &RenderOptions,
    progress: &ProgressOptions,
) -> Result<u8, SinterError> {
    let VarsGate {
        source,
        inventory,
        resolutions,
        frozen,
    } = vars_gate(&a.recipe, &a.exec, vars_path)?;
    let Some(inv) = inventory else {
        return run_one_target(phase, &source, Some(frozen), a, ro, progress);
    };
    let session = progress.begin(source_info(phase, &source));
    let planned = inventory_targets(&inv, resolutions, a, &session);
    session.end(scope_outcome(&planned));
    let mut plan = planned?;
    // Checked in every build, before any execution connects.
    attach_models(&mut plan.executions, frozen, source.units())?;
    run_executions(phase, &source, plan, a, ro, progress)
}

/// A model frozen for one planned execution: recipe `unit` on host `host`.
struct FrozenExecution {
    unit: usize,
    host: String,
    model: Model,
}

/// Pair each frozen model with the (recipe, host) it was frozen for. The
/// static gate returns one model per planned pair; any other count is an
/// internal inconsistency and stops the run.
fn bind_models(
    pairs: Vec<(usize, String)>,
    models: Vec<Model>,
) -> Result<Vec<FrozenExecution>, SinterError> {
    if pairs.len() != models.len() {
        return Err(model_mismatch(&format!(
            "{} planned executions, {} frozen models",
            pairs.len(),
            models.len()
        )));
    }
    Ok(pairs
        .into_iter()
        .zip(models)
        .map(|((unit, host), model)| FrozenExecution { unit, host, model })
        .collect())
}

/// Give every planned execution the model frozen for its own recipe and
/// host. The counts must match and each position must name the same recipe
/// and host; otherwise nothing is assigned and the run stops (fail closed,
/// no host contacted). Recipe labels and host names only — never a value.
fn attach_models(
    executions: &mut [Execution],
    frozen: Vec<FrozenExecution>,
    units: &[RecipeUnit],
) -> Result<(), SinterError> {
    if executions.len() != frozen.len() {
        return Err(model_mismatch(&format!(
            "{} planned executions, {} frozen models",
            executions.len(),
            frozen.len()
        )));
    }
    for (i, (ex, f)) in executions.iter().zip(&frozen).enumerate() {
        if ex.unit != f.unit || ex.target.name != f.host {
            return Err(model_mismatch(&format!(
                "execution {} is {} @ {}, its model was frozen for {} @ {}",
                i + 1,
                unit_label(units, ex.unit),
                ex.target.name,
                unit_label(units, f.unit),
                f.host
            )));
        }
    }
    for (ex, f) in executions.iter_mut().zip(frozen) {
        ex.model = Some(f.model);
    }
    Ok(())
}

/// The models of a single-target run, one per recipe in order, each frozen
/// for `target` (the `--host` string or `localhost`).
fn models_for_one_target(
    frozen: Vec<FrozenExecution>,
    source: &Source,
    target: &str,
) -> Result<Vec<Model>, SinterError> {
    let units = source.units();
    if frozen.len() != units.len() {
        return Err(model_mismatch(&format!(
            "{} recipes on one target, {} frozen models",
            units.len(),
            frozen.len()
        )));
    }
    frozen
        .into_iter()
        .enumerate()
        .map(|(i, f)| {
            if f.unit != i || f.host != target {
                return Err(model_mismatch(&format!(
                    "execution {} is {} @ {}, its model was frozen for {} @ {}",
                    i + 1,
                    unit_label(units, i),
                    target,
                    unit_label(units, f.unit),
                    f.host
                )));
            }
            Ok(f.model)
        })
        .collect()
}

/// The name of the one explicit target: the `--host` string, or localhost.
fn one_target_name(exec: &ExecOpts) -> &str {
    exec.host.as_deref().unwrap_or("localhost")
}

fn unit_label(units: &[RecipeUnit], unit: usize) -> String {
    units
        .get(unit)
        .map(|u| u.label.clone())
        .unwrap_or_else(|| format!("recipe #{}", unit + 1))
}

/// An internal inconsistency between the planned executions and the frozen
/// models. Exit 2 like every static failure; nothing has run.
fn model_mismatch(detail: &str) -> SinterError {
    SinterError::schema(format!(
        "internal error: the planned executions do not match the frozen models ({detail}); no host was contacted"
    ))
}

/// Report every problem of a variables-file static gate on stderr (none
/// carries a value from the file) and fail the run before any contact.
fn static_failure(problems: sinter::varsfile::Problems) -> SinterError {
    for line in &problems.0 {
        eprintln!(
            "{} {}",
            style::status("sinter:", style::stderr_color()),
            sanitize_line(line)
        );
    }
    SinterError::schema(
        "variables: the static checks failed (problems listed above); no host was contacted",
    )
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

/// The explicit target of a single-target invocation. `session` is the progress
/// scope when one exists: the `Resolve` stage covers the local `ssh -G`
/// evaluation (the only real wait here) and is absent with `--no-ssh-config`
/// and for localhost.
fn single_target(a: &TargetArgs, session: Option<&ProgressSession>) -> Result<Target, SinterError> {
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
            let use_ssh_config = !a.exec.no_ssh_config;
            let mut stage = session
                .filter(|_| use_ssh_config)
                .map(|s| s.resolve_stage(1));
            if let Some(stage) = stage.as_mut() {
                stage.host_started();
            }
            // On error `stage` is dropped here and ends `Failed`.
            let ssh = resolve_request(&req, use_ssh_config)?;
            if let Some(stage) = stage {
                stage.end();
            }
            Target {
                name: host.clone(),
                spec: TargetSpec { ssh: Some(ssh) },
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
    /// This execution's own model (a variables file, DESIGN §19.5); `None`
    /// runs the recipe's model.
    model: Option<Model>,
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
    session: &ProgressSession,
) -> Result<ExecutionPlan, SinterError> {
    let inv = load_inventory(inv_path)?;
    let resolutions = resolve_targets(
        &inv,
        source
            .units()
            .iter()
            .map(|u| (u.label.as_str(), u.model.targets.as_ref())),
    )?;
    inventory_targets(&inv, resolutions, a, session)
}

/// Resolve each recipe's `targets` (label, selector) against the inventory,
/// in order; the first failure stops.
fn resolve_targets<'a>(
    inv: &Inventory,
    recipes: impl Iterator<Item = (&'a str, Option<&'a sinter::document::TargetSelector>)>,
) -> Result<Vec<Resolution>, SinterError> {
    recipes
        .map(|(label, targets)| sinter::inventory::resolve(inv, targets, label))
        .collect()
}

/// Resolve every selected host (`ssh -G` included) and list the executions:
/// recipe-major, hosts in name order.
fn inventory_targets(
    inv: &Inventory,
    resolutions: Vec<Resolution>,
    a: &TargetArgs,
    session: &ProgressSession,
) -> Result<ExecutionPlan, SinterError> {
    let mut targets: BTreeMap<String, Target> = BTreeMap::new();
    // `Resolve` stage: one item per distinct selected host, each of which costs
    // a local `ssh -G` evaluation. Absent when that evaluation is skipped.
    let distinct: BTreeSet<&str> = resolutions.iter().flat_map(|r| r.selected()).collect();
    let mut stage = (!a.exec.no_ssh_config && !distinct.is_empty())
        .then(|| session.resolve_stage(distinct.len()));
    for r in &resolutions {
        for name in r.selected() {
            if targets.contains_key(name) {
                continue;
            }
            if let Some(stage) = stage.as_mut() {
                stage.host_started();
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
    if let Some(stage) = stage {
        stage.end();
    }
    let mut executions = Vec::new();
    for (i, r) in resolutions.iter().enumerate() {
        for name in r.selected() {
            executions.push(Execution {
                unit: i,
                target: targets[name].clone(),
                model: None,
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
    progress: &ProgressOptions,
) -> Result<u8, SinterError> {
    let text = ro.format == OutputFormat::Text;
    let units = source.units();
    if text {
        print_resolution(source, &plan, ro);
    }
    let run_id = sinter::backup::new_run_id();
    let mut results: Vec<ExecResult> = Vec::new();
    let mut stopped_by: Option<String> = None;
    for mut ex in plan.executions {
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
        // One progress scope per executed (recipe, target) pair, ended before
        // anything of this execution is rendered. Executions that are not run
        // have no scope.
        let session = progress.begin(unit_info(phase, u));
        let model = ex.model.take().unwrap_or_else(|| u.model.clone());
        let executed = execute(
            phase,
            model,
            ex.target.spec.clone(),
            a,
            Some(&id),
            session.sink(),
        );
        session.end(run_outcome_of(&executed));
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
    progress: Arc<dyn ProgressSink>,
) -> Result<Outcome, SinterError> {
    #[cfg(test)]
    tests::EXECUTED_MODELS.with(|m| m.borrow_mut().push(model.clone()));
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
        fake_target: test_fake_target(),
    };
    // Secrets are opened lazily: a recipe that names none never touches an
    // identity or the terminal.
    let mut engine = Engine::new_with_progress(model, opts, progress)?
        .with_secrets(sinter::secret_source::process_secrets());
    if let Some(id) = backup_run_id {
        engine = engine.with_backup_run_id(id.to_string());
    }
    Ok(match phase {
        Phase::Audit => Outcome::Audit(run_audit(engine)?),
        _ => Outcome::Run(Box::new(engine.run()?)),
    })
}

/// The CLI never runs against a scripted target; unit tests of this file do.
#[cfg(not(test))]
fn test_fake_target() -> Option<sinter::executor::FakeTarget> {
    None
}

#[cfg(test)]
fn test_fake_target() -> Option<sinter::executor::FakeTarget> {
    tests::FAKE_TARGETS.with(|f| f.borrow_mut().pop_front())
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

    thread_local! {
        /// Scripted targets for [`execute`], one per execution, in order
        /// (compiled in tests only).
        pub(super) static FAKE_TARGETS: std::cell::RefCell<std::collections::VecDeque<sinter::executor::FakeTarget>> =
            const { std::cell::RefCell::new(std::collections::VecDeque::new()) };
        /// Every model [`execute`] received, in order (compiled in tests only).
        pub(super) static EXECUTED_MODELS: std::cell::RefCell<Vec<Model>> =
            const { std::cell::RefCell::new(Vec::new()) };
        /// Corrupts the frozen models of a variables-file run right after
        /// they are bound, to prove a mismatch stops the run (tests only).
        static TAMPER: std::cell::Cell<Option<Tamper>> =
            const { std::cell::Cell::new(None) };
    }

    /// Corrupts a run's frozen models (may add or remove some, so a `Vec`).
    type Tamper = fn(&mut Vec<FrozenExecution>);

    pub(super) fn tamper_frozen(frozen: &mut Vec<FrozenExecution>) {
        if let Some(f) = TAMPER.with(std::cell::Cell::get) {
            f(frozen);
        }
    }

    // -----------------------------------------------------------------------
    // WP-PROGRESS S3: the real `run_phase_with` wiring, driven in-process.
    //
    // Each execution runs against a scripted target (`FAKE_TARGETS`); the
    // consumer records every session's stream. What a session streams is the
    // contract here; what reaches stdout/stderr is proven by the binary-level
    // tests in `tests/progress_cli_output.rs`.
    // -----------------------------------------------------------------------

    use sinter::executor::FakeTarget;
    use sinter::progress::{validate_stream, ProgressEvent, Stage};
    use sinter::progress_session::{ProgressConsumer, ProgressMode};
    use std::sync::Mutex;

    type Stream = Arc<Mutex<Vec<ProgressEvent>>>;

    struct Rec(Stream);

    impl ProgressConsumer for Rec {
        fn consume(&mut self, event: &ProgressEvent) {
            self.0.lock().unwrap().push(event.clone());
        }
    }

    struct Wiring {
        streams: Arc<Mutex<Vec<Stream>>>,
        infos: Arc<Mutex<Vec<SessionInfo>>>,
        opts: ProgressOptions,
    }

    fn wiring(mode: ProgressMode) -> Wiring {
        let streams: Arc<Mutex<Vec<Stream>>> = Arc::default();
        let infos: Arc<Mutex<Vec<SessionInfo>>> = Arc::default();
        let (s, i) = (streams.clone(), infos.clone());
        let opts = ProgressOptions::new(mode).with_consumer_factory(Arc::new(move |info| {
            i.lock().unwrap().push(*info);
            let stream: Stream = Arc::default();
            s.lock().unwrap().push(stream.clone());
            Box::new(Rec(stream))
        }));
        Wiring {
            streams,
            infos,
            opts,
        }
    }

    impl Wiring {
        fn streams(&self) -> Vec<Vec<String>> {
            self.streams
                .lock()
                .unwrap()
                .iter()
                .map(|s| {
                    let ev = s.lock().unwrap().clone();
                    validate_stream(&ev).unwrap_or_else(|e| panic!("{e}: {ev:#?}"));
                    shape(&ev)
                })
                .collect()
        }
    }

    fn shape(events: &[ProgressEvent]) -> Vec<String> {
        events
            .iter()
            .map(|e| match e {
                ProgressEvent::RunStarted { command } => format!("run start {command:?}"),
                ProgressEvent::RunEnded { outcome } => format!("run end {outcome:?}"),
                ProgressEvent::StageStarted { stage, total } => {
                    format!("{} start {total:?}", stage.label())
                }
                ProgressEvent::Progress { stage, done, .. } if *stage == Stage::Resolve => {
                    format!("resolve item {done}")
                }
                ProgressEvent::Progress { .. } => "item".to_string(),
                ProgressEvent::StageEnded {
                    stage,
                    outcome,
                    done,
                } => format!("{} end {outcome:?} {done}", stage.label()),
                _ => "other".to_string(),
            })
            .collect()
    }

    fn target_args(phase: Phase, argv: &[&str]) -> TargetArgs {
        let mut full = vec!["sinter", phase.name()];
        full.extend_from_slice(argv);
        match Cli::try_parse_from(full).unwrap().command {
            Command::Plan(a) | Command::Apply(a) | Command::Audit(a) => a,
            _ => unreachable!(),
        }
    }

    fn base() -> FakeTarget {
        FakeTarget::ubuntu2404()
            .with_fake_fs()
            .with_fs_dir("/etc/perf")
    }

    /// Run the real wiring. `targets` are consumed one per execution.
    fn drive(
        phase: Phase,
        argv: &[&str],
        w: &Wiring,
        targets: Vec<FakeTarget>,
    ) -> Result<u8, SinterError> {
        let a = target_args(phase, argv);
        let format = parse_format(&a.format).unwrap();
        FAKE_TARGETS.with(|f| *f.borrow_mut() = targets.into());
        let r = run_phase_with(phase, &a, format, &w.opts);
        FAKE_TARGETS.with(|f| f.borrow_mut().clear());
        r
    }

    const RECIPE: &str = "version: 1\nresources:\n  - id: a\n    type: file\n    with:\n      path: /etc/perf/a\n      content: x\n";
    /// Needs the package backend, so a target without one fails at connect.
    const PKG_RECIPE: &str = "version: 1\nresources:\n  - id: p\n    type: package\n    with:\n      name: jq\n      state: present\n";
    const WEB_RECIPE: &str = "version: 1\ntargets:\n  groups: [web]\nresources:\n  - id: p\n    type: package\n    with:\n      name: jq\n      state: present\n";

    fn fixture() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn write(dir: &tempfile::TempDir, name: &str, body: &str) -> String {
        let p = dir.path().join(name);
        std::fs::write(&p, body).unwrap();
        p.display().to_string()
    }

    fn inventory(dir: &tempfile::TempDir) -> String {
        let kh = write(dir, "known_hosts", "");
        write(
            dir,
            "hosts.yaml",
            &format!(
                "hosts:\n  web01:\n    address: 127.0.0.1\n    port: 20101\n    user: u\n    known_hosts: {kh}\n  web02:\n    address: 127.0.0.1\n    port: 20102\n    user: u\n    known_hosts: {kh}\ngroups:\n  web:\n    hosts: [web01, web02]\n"
            ),
        )
    }

    fn web_recipe(dir: &tempfile::TempDir, name: &str) -> String {
        write(dir, name, WEB_RECIPE)
    }

    #[test]
    fn single_recipe_is_one_valid_run_covering_connect_and_resources() {
        let dir = fixture();
        let r = write(&dir, "r.yaml", RECIPE);
        let w = wiring(ProgressMode::Tty);
        let code = drive(Phase::Plan, &[&r, "--format", "json"], &w, vec![base()]).unwrap();
        assert_eq!(code, 0);
        let streams = w.streams();
        assert_eq!(streams.len(), 1);
        assert_eq!(
            streams[0],
            [
                "run start Plan",
                "connect start None",
                "connect end Completed 0",
                "resources start Some(1)",
                "item",
                "resources end Completed 1",
                "run end Completed"
            ]
        );
        assert_eq!(
            w.infos.lock().unwrap().as_slice(),
            &[SessionInfo {
                kind: RunKind::Plan,
                references_secrets: false
            }]
        );
    }

    #[test]
    fn each_command_reports_its_own_run_kind() {
        let dir = fixture();
        let r = write(&dir, "r.yaml", RECIPE);
        for (phase, want) in [
            (Phase::Plan, "run start Plan"),
            (Phase::Apply, "run start Apply"),
            (Phase::Audit, "run start Audit"),
        ] {
            let w = wiring(ProgressMode::Tty);
            let _ = drive(phase, &[&r, "--format", "json"], &w, vec![base()]);
            assert_eq!(w.streams()[0][0], want);
        }
    }

    #[test]
    fn audit_drift_completes_the_run() {
        let dir = fixture();
        let r = write(&dir, "r.yaml", RECIPE);
        let w = wiring(ProgressMode::Tty);
        // /etc/perf/a is absent: drift, exit 7, which is a finding not a failure.
        let code = drive(Phase::Audit, &[&r, "--format", "json"], &w, vec![base()]).unwrap();
        assert_eq!(code, 7);
        assert_eq!(w.streams()[0].last().unwrap(), "run end Completed");
    }

    #[test]
    fn a_connect_failure_ends_the_run_and_returns_the_unchanged_error() {
        let dir = fixture();
        let r = write(&dir, "r.yaml", PKG_RECIPE);
        let w = wiring(ProgressMode::Tty);
        let err = drive(
            Phase::Apply,
            &[&r, "--format", "json"],
            &w,
            vec![FakeTarget::unsupported()],
        )
        .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Connect);
        assert_eq!(
            w.streams(),
            vec![vec![
                "run start Apply".to_string(),
                "connect start None".into(),
                "connect end Failed 0".into(),
                "run end Failed".into()
            ]]
        );
    }

    #[test]
    fn a_disabled_mode_builds_no_session_at_all() {
        let dir = fixture();
        let r = write(&dir, "r.yaml", RECIPE);
        let inv = inventory(&dir);
        let q = web_recipe(&dir, "web.yaml");
        let w = wiring(ProgressMode::Disabled);
        drive(Phase::Plan, &[&r, "--format", "json"], &w, vec![base()]).unwrap();
        drive(
            Phase::Plan,
            &[&q, "--hosts", &inv, "--no-ssh-config", "--format", "json"],
            &w,
            vec![base(), base()],
        )
        .unwrap();
        assert!(w.infos.lock().unwrap().is_empty());
        assert!(w.streams().is_empty());
    }

    #[test]
    fn json_never_enables_progress_whatever_the_terminal() {
        assert_eq!(mode_from_environment(true), ProgressMode::Disabled);
    }

    #[test]
    fn single_host_resolution_is_a_stage_of_the_run() {
        let dir = fixture();
        let r = write(&dir, "r.yaml", RECIPE);
        let w = wiring(ProgressMode::Tty);
        // `ssh -G 127.0.0.1` really runs; the engine uses the scripted target.
        let code = drive(
            Phase::Plan,
            &[&r, "--host", "127.0.0.1", "--port", "1", "--format", "json"],
            &w,
            vec![base()],
        )
        .unwrap();
        assert_eq!(code, 0);
        let s = w.streams();
        assert_eq!(s.len(), 1);
        assert_eq!(
            s[0][..5],
            [
                "run start Plan",
                "resolve start Some(1)",
                "resolve item 0",
                "resolve end Completed 1",
                "connect start None"
            ]
        );
        assert_eq!(s[0].last().unwrap(), "run end Completed");
    }

    #[test]
    fn without_ssh_config_there_is_no_resolve_stage() {
        let dir = fixture();
        let r = write(&dir, "r.yaml", RECIPE);
        let w = wiring(ProgressMode::Tty);
        drive(
            Phase::Plan,
            &[
                &r,
                "--host",
                "127.0.0.1",
                "--port",
                "1",
                "--no-ssh-config",
                "--format",
                "json",
            ],
            &w,
            vec![base()],
        )
        .unwrap();
        assert_eq!(
            w.streams()[0][..2],
            ["run start Plan", "connect start None"]
        );
    }

    #[test]
    fn a_resolve_failure_ends_the_run() {
        let dir = fixture();
        let r = write(&dir, "r.yaml", RECIPE);
        // Rejected before `ssh` is spawned: a deterministic resolve failure.
        let w = wiring(ProgressMode::Tty);
        let err = drive(
            Phase::Plan,
            &[&r, "--host=-bad", "--format", "json"],
            &w,
            vec![],
        )
        .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Schema);
        assert_eq!(
            w.streams(),
            vec![vec![
                "run start Plan".to_string(),
                "resolve start Some(1)".into(),
                "resolve item 0".into(),
                "resolve end Failed 1".into(),
                "run end Failed".into()
            ]]
        );
        // The same failure without the OpenSSH evaluation has no stage but
        // still ends the run that began.
        let w = wiring(ProgressMode::Tty);
        let err = drive(
            Phase::Plan,
            &[&r, "--host=-bad", "--no-ssh-config", "--format", "json"],
            &w,
            vec![],
        )
        .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Schema);
        assert_eq!(
            w.streams(),
            vec![vec!["run start Plan".to_string(), "run end Failed".into()]]
        );
    }

    #[test]
    fn inventory_runs_have_a_resolution_scope_then_one_scope_per_execution() {
        let dir = fixture();
        let inv = inventory(&dir);
        let q = web_recipe(&dir, "web.yaml");
        let w = wiring(ProgressMode::Tty);
        let code = drive(
            Phase::Plan,
            &[&q, "--hosts", &inv, "--format", "json"],
            &w,
            vec![base(), base()],
        )
        .unwrap();
        assert_eq!(code, 0);
        let s = w.streams();
        assert_eq!(s.len(), 3, "resolution + two executions: {s:#?}");
        assert_eq!(
            s[0],
            [
                "run start Plan",
                "resolve start Some(2)",
                "resolve item 0",
                "resolve item 1",
                "resolve end Completed 2",
                "run end Completed"
            ]
        );
        for exec in &s[1..] {
            assert_eq!(exec[0], "run start Plan");
            assert_eq!(exec[1], "connect start None");
            assert_eq!(exec.last().unwrap(), "run end Completed");
            assert_eq!(exec.iter().filter(|e| e.starts_with("run ")).count(), 2);
        }
    }

    #[test]
    fn without_ssh_config_the_resolution_scope_has_no_stage() {
        let dir = fixture();
        let inv = inventory(&dir);
        let q = web_recipe(&dir, "web.yaml");
        let w = wiring(ProgressMode::Tty);
        drive(
            Phase::Plan,
            &[&q, "--hosts", &inv, "--no-ssh-config", "--format", "json"],
            &w,
            vec![base(), base()],
        )
        .unwrap();
        assert_eq!(w.streams()[0], ["run start Plan", "run end Completed"]);
    }

    #[test]
    fn a_failing_execution_does_not_disturb_the_others_in_plan() {
        let dir = fixture();
        let inv = inventory(&dir);
        let q = web_recipe(&dir, "web.yaml");
        let w = wiring(ProgressMode::Tty);
        // web01 succeeds, web02 cannot connect; plan attempts both.
        let code = drive(
            Phase::Plan,
            &[&q, "--hosts", &inv, "--no-ssh-config", "--format", "json"],
            &w,
            vec![base(), FakeTarget::unsupported()],
        )
        .unwrap();
        assert_eq!(code, 3, "the most severe execution code");
        let s = w.streams();
        assert_eq!(s.len(), 3);
        assert_eq!(s[1].last().unwrap(), "run end Completed");
        assert_eq!(
            s[2],
            [
                "run start Plan",
                "connect start None",
                "connect end Failed 0",
                "run end Failed"
            ]
        );
    }

    #[test]
    fn apply_that_stops_gives_the_unrun_executions_no_session() {
        let dir = fixture();
        let inv = inventory(&dir);
        let q = web_recipe(&dir, "web.yaml");
        let w = wiring(ProgressMode::Tty);
        let code = drive(
            Phase::Apply,
            &[&q, "--hosts", &inv, "--no-ssh-config", "--format", "json"],
            &w,
            vec![FakeTarget::unsupported(), base()],
        )
        .unwrap();
        assert_eq!(code, 3);
        // resolution + web01 only: web02 was never run, so it has no scope.
        assert_eq!(w.streams().len(), 2);
        assert_eq!(w.infos.lock().unwrap().len(), 2);
    }

    #[test]
    fn an_inventory_failure_ends_the_resolution_scope() {
        let dir = fixture();
        let q = web_recipe(&dir, "web.yaml");
        let missing = dir.path().join("nope.yaml").display().to_string();
        let w = wiring(ProgressMode::Tty);
        let err = drive(
            Phase::Plan,
            &[&q, "--hosts", &missing, "--format", "json"],
            &w,
            vec![],
        )
        .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Schema);
        assert_eq!(
            w.streams(),
            vec![vec!["run start Plan".to_string(), "run end Failed".into()]]
        );
    }

    #[test]
    fn a_bundle_on_localhost_has_one_scope_per_recipe_and_no_resolution_scope() {
        let dir = fixture();
        write(&dir, "a.yaml", RECIPE);
        write(&dir, "b.yaml", RECIPE);
        let b = write(
            &dir,
            "stack.yaml",
            "version: 1\nname: stack\nrecipes: [a.yaml, b.yaml]\n",
        );
        let w = wiring(ProgressMode::Tty);
        let code = drive(
            Phase::Plan,
            &[&b, "--format", "json"],
            &w,
            vec![base(), base()],
        )
        .unwrap();
        assert_eq!(code, 0);
        let s = w.streams();
        assert_eq!(s.len(), 2);
        for exec in &s {
            assert_eq!(exec[0], "run start Plan");
            assert_eq!(exec.last().unwrap(), "run end Completed");
        }
    }

    #[test]
    fn a_secret_reference_is_reported_to_the_consumer_and_stays_out_of_every_stream() {
        let dir = fixture();
        std::fs::create_dir_all(dir.path().join("secrets")).unwrap();
        let id = sinter::secrets::generate_identity();
        let ct = sinter::secrets::encrypt_to_recipients(
            b"MAIN-CANARY-SECRET-PLAINTEXT",
            std::slice::from_ref(&id.recipient),
        )
        .unwrap();
        std::fs::write(dir.path().join("secrets/MAINCANARYREF.age"), ct).unwrap();
        let r = write(
            &dir,
            "r.yaml",
            "version: 1\nresources:\n  - id: acct\n    type: user\n    with:\n      name: app\n      password_hash: { secret: secrets/MAINCANARYREF.age }\n",
        );
        let w = wiring(ProgressMode::Tty);
        // Fails at target resolution, before the engine exists: the secret is
        // never opened (a test must not reach for a real identity or a tty).
        let _ = drive(
            Phase::Plan,
            &[&r, "--host=-bad", "--no-ssh-config", "--format", "json"],
            &w,
            vec![],
        );
        assert_eq!(
            w.infos.lock().unwrap().as_slice(),
            &[SessionInfo {
                kind: RunKind::Plan,
                references_secrets: true
            }]
        );
        let all = format!("{:?}", w.streams());
        for canary in ["MAINCANARYREF", "MAIN-CANARY-SECRET-PLAINTEXT", "secrets/"] {
            assert!(!all.contains(canary), "{canary} in {all}");
        }
    }

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
    // -----------------------------------------------------------------------
    // WP-PROGRESS S4: the TTY renderer through the real `run_phase_with`
    // wiring, drawing on a memory surface. What reaches a real terminal is
    // proven by the binary-level pty tests in `tests/progress_tty.rs`.
    // -----------------------------------------------------------------------

    use sinter::progress_plain::plain_consumer_factory;
    use sinter::progress_tty::{consumer_factory, Surface};

    /// The wire contract of the transient line, restated here on purpose: an
    /// independent oracle for the renderer's own constant.
    const CLEAR: &str = "\r\x1b[2K";
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone, Default)]
    struct Screen {
        bytes: Arc<Mutex<Vec<u8>>>,
        /// Surfaces created (a renderer was started).
        made: Arc<AtomicUsize>,
        /// Sessions begun, and how many of them reported a secret reference.
        sessions: Arc<AtomicUsize>,
        secret_sessions: Arc<AtomicUsize>,
    }

    struct ScreenSurface(Screen);

    impl Surface for ScreenSurface {
        fn write_frame(&mut self, bytes: &[u8]) -> std::io::Result<()> {
            self.0.bytes.lock().unwrap().extend_from_slice(bytes);
            Ok(())
        }
        fn columns(&mut self) -> Option<usize> {
            Some(80)
        }
    }

    impl Screen {
        fn options_for(&self, mode: ProgressMode) -> ProgressOptions {
            let screen = self.clone();
            let inner = consumer_factory({
                let screen = self.clone();
                Arc::new(move || {
                    screen.made.fetch_add(1, Ordering::SeqCst);
                    Box::new(ScreenSurface(screen.clone()))
                })
            });
            ProgressOptions::new(mode).with_consumer_factory(Arc::new(move |info| {
                screen.sessions.fetch_add(1, Ordering::SeqCst);
                if info.references_secrets {
                    screen.secret_sessions.fetch_add(1, Ordering::SeqCst);
                }
                inner(info)
            }))
        }

        fn options(&self) -> ProgressOptions {
            self.options_for(ProgressMode::Tty)
        }

        /// The S5 plain renderer on the same memory surface, counting sessions
        /// and secret-bearing sessions the same way.
        fn plain_options(&self) -> ProgressOptions {
            let screen = self.clone();
            let inner = plain_consumer_factory({
                let screen = self.clone();
                Arc::new(move || {
                    screen.made.fetch_add(1, Ordering::SeqCst);
                    Box::new(ScreenSurface(screen.clone()))
                })
            });
            ProgressOptions::new(ProgressMode::Plain).with_consumer_factory(Arc::new(move |info| {
                screen.sessions.fetch_add(1, Ordering::SeqCst);
                if info.references_secrets {
                    screen.secret_sessions.fetch_add(1, Ordering::SeqCst);
                }
                inner(info)
            }))
        }

        fn text(&self) -> String {
            String::from_utf8(self.bytes.lock().unwrap().clone()).unwrap()
        }

        fn sessions(&self) -> usize {
            self.sessions.load(Ordering::SeqCst)
        }

        fn secret_sessions(&self) -> usize {
            self.secret_sessions.load(Ordering::SeqCst)
        }

        fn surfaces(&self) -> usize {
            self.made.load(Ordering::SeqCst)
        }
    }

    fn drive_with(
        phase: Phase,
        argv: &[&str],
        opts: &ProgressOptions,
        targets: Vec<FakeTarget>,
    ) -> Result<u8, SinterError> {
        let a = target_args(phase, argv);
        let format = parse_format(&a.format).unwrap();
        FAKE_TARGETS.with(|f| *f.borrow_mut() = targets.into());
        let r = run_phase_with(phase, &a, format, opts);
        FAKE_TARGETS.with(|f| f.borrow_mut().clear());
        r
    }

    /// Every frame between clears is one printable line.
    fn assert_only_clean_frames(text: &str) {
        let rest = text.replace(CLEAR, "");
        assert!(
            rest.bytes().all(|b| (0x20..=0x7e).contains(&b)),
            "unexpected bytes: {text:?}"
        );
    }

    const SECRET_RECIPE: &str = "version: 1\nresources:\n  - id: acct\n    type: user\n    with:\n      name: app\n      password_hash: { secret: secrets/S4CANARYREF.age }\n";

    /// A secret-referencing recipe whose secret file exists, so that the model
    /// loads and the run reaches its progress scope (never a prompt: no test
    /// below gets as far as opening the secret).
    fn secret_recipe(dir: &tempfile::TempDir, name: &str) -> String {
        std::fs::create_dir_all(dir.path().join("secrets")).unwrap();
        let id = sinter::secrets::generate_identity();
        let ct = sinter::secrets::encrypt_to_recipients(
            b"S4-CANARY-PLAINTEXT",
            std::slice::from_ref(&id.recipient),
        )
        .unwrap();
        std::fs::write(dir.path().join("secrets/S4CANARYREF.age"), ct).unwrap();
        write(dir, name, SECRET_RECIPE)
    }

    #[test]
    fn an_eligible_run_draws_a_transient_line_and_leaves_the_terminal_clean() {
        let dir = fixture();
        let r = write(&dir, "r.yaml", RECIPE);
        for phase in [Phase::Plan, Phase::Apply, Phase::Audit] {
            let screen = Screen::default();
            let _ = drive_with(phase, &[&r], &screen.options(), vec![base()]).unwrap();
            let text = screen.text();
            assert!(text.starts_with(&format!("{CLEAR}connect")), "{text:?}");
            assert!(text.ends_with(CLEAR), "{text:?}");
            assert_only_clean_frames(&text);
            assert_eq!(screen.surfaces(), 1);
        }
    }

    #[test]
    fn the_line_is_erased_on_every_failure_path() {
        let dir = fixture();
        let r = write(&dir, "r.yaml", PKG_RECIPE);
        // connect failure
        let screen = Screen::default();
        let err = drive_with(
            Phase::Apply,
            &[&r],
            &screen.options(),
            vec![FakeTarget::unsupported()],
        )
        .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Connect);
        assert!(screen.text().ends_with(CLEAR), "{:?}", screen.text());
        assert_only_clean_frames(&screen.text());
        // resolve failure, before any engine
        let screen = Screen::default();
        let err = drive_with(
            Phase::Plan,
            &[&r, "--host=-bad", "--no-ssh-config"],
            &screen.options(),
            vec![],
        )
        .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Schema);
        assert_eq!(screen.text(), "", "no stage ever started, nothing drawn");
    }

    #[test]
    fn a_secret_bearing_recipe_never_draws_on_a_terminal() {
        let dir = fixture();
        let r = secret_recipe(&dir, "r.yaml");
        let pkg = write(&dir, "p.yaml", PKG_RECIPE);
        let screen = Screen::default();
        // Target resolution fails (one scope, the recipe is loaded).
        let err = drive_with(
            Phase::Plan,
            &[&r, "--host=-bad", "--no-ssh-config"],
            &screen.options(),
            vec![],
        )
        .unwrap_err();
        assert!(err.message.contains("-bad"), "{}", err.message);
        // The run fails in every command (one scope each).
        for phase in [Phase::Plan, Phase::Apply, Phase::Audit] {
            // Ends before the secret could be opened (a password hash needs
            // sudo): a test never reaches a prompt. Error or report, either way.
            let result = drive_with(
                phase,
                &[&r],
                &screen.options(),
                vec![FakeTarget::unsupported()],
            );
            if let Err(err) = result {
                assert!(!err.message.contains("S4-CANARY"), "{}", err.message);
            }
        }
        assert_eq!(screen.sessions(), 4, "every run reached its progress scope");
        assert_eq!(
            screen.secret_sessions(),
            4,
            "and reported the secret reference"
        );
        assert_eq!(screen.surfaces(), 0, "no renderer was even started");
        assert_eq!(screen.text(), "", "not one byte, not even a clear");
        // A secret-free recipe on the same options does draw (control).
        let _ = drive_with(
            Phase::Plan,
            &[&pkg],
            &screen.options(),
            vec![FakeTarget::unsupported()],
        );
        let text = screen.text();
        assert_eq!(screen.surfaces(), 1, "only the control run built a surface");
        assert!(text.contains("connect"), "{text:?}");
        for forbidden in ["S4CANARYREF", "S4-CANARY", "acct", "secrets/", "password"] {
            assert!(!text.contains(forbidden), "{forbidden} in {text:?}");
        }
    }

    #[test]
    fn a_bundle_with_one_secret_recipe_suppresses_its_resolution_scope() {
        let dir = fixture();
        secret_recipe(&dir, "secret.yaml");
        write(&dir, "plain.yaml", WEB_RECIPE);
        let bundle = write(
            &dir,
            "bundle.yaml",
            "version: 1\nrecipes:\n  - secret.yaml\n  - plain.yaml\n",
        );
        let screen = Screen::default();
        // `--host` makes a resolution scope over the whole bundle; it fails.
        let err = drive_with(
            Phase::Plan,
            &[&bundle, "--host=-bad", "--no-ssh-config"],
            &screen.options(),
            vec![],
        )
        .unwrap_err();
        // The bundle loaded: the failure is the host argument, not the file.
        assert!(err.message.contains("-bad"), "{}", err.message);
        assert_eq!(screen.sessions(), 1);
        assert_eq!(
            screen.secret_sessions(),
            1,
            "one secret recipe makes the whole resolution scope secret-bearing"
        );
        assert_eq!(screen.surfaces(), 0);
        assert_eq!(screen.text(), "");
    }

    #[test]
    fn multiple_executions_leave_one_clean_line_each_and_no_accumulation() {
        let dir = fixture();
        let inv = inventory(&dir);
        let q = web_recipe(&dir, "web.yaml");
        let screen = Screen::default();
        let code = drive_with(
            Phase::Plan,
            &[&q, "--hosts", &inv, "--no-ssh-config"],
            &screen.options(),
            vec![base(), base()],
        )
        .unwrap();
        assert_eq!(code, 0);
        let text = screen.text();
        // Resolution scope is empty (no ssh -G), then two execution scopes, each
        // its own consumer: every draw is followed by its clear before the next
        // scope starts.
        assert_eq!(screen.surfaces(), 3);
        assert_only_clean_frames(&text);
        let draws = text.matches(&format!("{CLEAR}connect")).count();
        assert_eq!(draws, 2, "{text:?}");
        assert!(text.ends_with(CLEAR));
        // Strip every frame: nothing is left.
        let mut left = String::new();
        for seg in text.split(CLEAR) {
            if seg.starts_with("connect") || seg.is_empty() || seg.starts_with("plan") {
                continue;
            }
            left.push_str(seg);
        }
        assert_eq!(left, "");
    }

    #[test]
    fn json_and_disabled_modes_never_reach_the_renderer() {
        let dir = fixture();
        let r = write(&dir, "r.yaml", RECIPE);
        let screen = Screen::default();
        let off = screen.options_for(ProgressMode::Disabled);
        let _ = drive_with(Phase::Plan, &[&r], &off, vec![base()]).unwrap();
        assert_eq!(screen.sessions(), 0);
        assert_eq!(screen.surfaces(), 0);
        assert_eq!(screen.text(), "");
        assert_eq!(mode_from_environment(true), ProgressMode::Disabled);
    }
    // -----------------------------------------------------------------------
    // WP-PROGRESS S5: the plain renderer through the real `run_phase_with`
    // wiring (`ProgressMode::Plain`), on a memory surface. The environment
    // switch and the bytes a real process writes are covered by
    // `tests/progress_plain_output.rs`.
    // -----------------------------------------------------------------------

    /// What the plain renderer wrote, as lines; every one is a bounded ASCII
    /// `progress:` line (no escape, no carriage return, no `sinter:`).
    fn plain_lines(screen: &Screen) -> Vec<String> {
        let text = screen.text();
        assert!(
            text.is_empty() || text.ends_with('\n'),
            "output must be whole lines: {text:?}"
        );
        assert!(
            text.bytes()
                .all(|b| (0x20..=0x7e).contains(&b) || b == b'\n'),
            "unexpected bytes: {text:?}"
        );
        text.lines()
            .map(|l| {
                assert!(l.starts_with("progress: "), "{l:?}");
                l.to_string()
            })
            .collect()
    }

    /// The line with the elapsed time cut off (it varies from run to run).
    fn without_time(line: &str) -> &str {
        line.rsplit_once(" (").map_or(line, |(head, _)| head)
    }

    #[test]
    fn a_plain_run_prints_bounded_lines_for_every_command() {
        let dir = fixture();
        let r = write(&dir, "r.yaml", RECIPE);
        for (phase, word) in [
            (Phase::Plan, "plan"),
            (Phase::Apply, "apply"),
            (Phase::Audit, "audit"),
        ] {
            let screen = Screen::default();
            let _ = drive_with(phase, &[&r], &screen.plain_options(), vec![base()]).unwrap();
            let lines = plain_lines(&screen);
            let shaped: Vec<&str> = lines.iter().map(|l| without_time(l)).collect();
            assert_eq!(
                shaped.first().copied(),
                Some(&*format!("progress: run: {word} started"))
            );
            assert_eq!(
                shaped.last().copied(),
                Some(&*format!("progress: run: {word} completed")),
                "{lines:?}"
            );
            assert!(shaped.contains(&"progress: connect: start"), "{lines:?}");
            assert!(shaped.contains(&"progress: connect: done"), "{lines:?}");
            assert!(
                lines.len() <= 20,
                "bounded by stages, not by resources: {lines:?}"
            );
            assert_eq!(screen.surfaces(), 1);
        }
    }

    #[test]
    fn plain_progress_reports_every_failure_with_a_word_and_never_a_message() {
        let dir = fixture();
        let r = write(&dir, "r.yaml", PKG_RECIPE);
        // connect failure
        let screen = Screen::default();
        let err = drive_with(
            Phase::Apply,
            &[&r],
            &screen.plain_options(),
            vec![FakeTarget::unsupported()],
        )
        .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Connect);
        let lines = plain_lines(&screen);
        let shaped: Vec<&str> = lines.iter().map(|l| without_time(l)).collect();
        assert_eq!(
            shaped,
            [
                "progress: run: apply started",
                "progress: connect: start",
                "progress: connect: failed",
                "progress: run: apply failed",
            ]
        );
        for l in &lines {
            assert!(!l.contains(&err.message), "no error text in progress: {l}");
        }
        // resolution failure, before any engine: only the run's own two lines
        let screen = Screen::default();
        let err = drive_with(
            Phase::Plan,
            &[&r, "--host=-bad", "--no-ssh-config"],
            &screen.plain_options(),
            vec![],
        )
        .unwrap_err();
        assert_eq!(err.kind, ErrorKind::Schema);
        let lines = plain_lines(&screen);
        let shaped: Vec<&str> = lines.iter().map(|l| without_time(l)).collect();
        assert_eq!(
            shaped,
            ["progress: run: plan started", "progress: run: plan failed"]
        );
    }

    #[test]
    fn a_secret_bearing_recipe_prints_no_plain_progress_either() {
        let dir = fixture();
        let r = secret_recipe(&dir, "r.yaml");
        let pkg = write(&dir, "p.yaml", PKG_RECIPE);
        let screen = Screen::default();
        let err = drive_with(
            Phase::Plan,
            &[&r, "--host=-bad", "--no-ssh-config"],
            &screen.plain_options(),
            vec![],
        )
        .unwrap_err();
        assert!(err.message.contains("-bad"), "{}", err.message);
        for phase in [Phase::Plan, Phase::Apply, Phase::Audit] {
            let _ = drive_with(
                phase,
                &[&r],
                &screen.plain_options(),
                vec![FakeTarget::unsupported()],
            );
        }
        assert_eq!(screen.sessions(), 4);
        assert_eq!(screen.secret_sessions(), 4);
        assert_eq!(screen.surfaces(), 0, "no surface, so no descriptor either");
        assert_eq!(screen.text(), "", "not one byte");
        // Control: the same options do write for a secret-free recipe.
        let _ = drive_with(
            Phase::Plan,
            &[&pkg],
            &screen.plain_options(),
            vec![FakeTarget::unsupported()],
        );
        let text = screen.text();
        assert_eq!(screen.surfaces(), 1);
        assert!(text.contains("progress: connect: start"), "{text:?}");
        for forbidden in ["S4CANARYREF", "S4-CANARY", "acct", "secrets/", "password"] {
            assert!(!text.contains(forbidden), "{forbidden} in {text:?}");
        }
    }

    #[test]
    fn plain_multiple_executions_are_delimited_run_by_run() {
        let dir = fixture();
        let inv = inventory(&dir);
        let q = web_recipe(&dir, "web.yaml");
        let screen = Screen::default();
        let code = drive_with(
            Phase::Plan,
            &[&q, "--hosts", &inv, "--no-ssh-config"],
            &screen.plain_options(),
            vec![base(), base()],
        )
        .unwrap();
        assert_eq!(code, 0);
        let lines = plain_lines(&screen);
        let shaped: Vec<&str> = lines.iter().map(|l| without_time(l)).collect();
        // A resolution scope (no `ssh -G`, so no stage), then one scope per host.
        assert_eq!(screen.surfaces(), 3);
        let starts = shaped
            .iter()
            .filter(|l| **l == "progress: run: plan started")
            .count();
        let ends = shaped
            .iter()
            .filter(|l| **l == "progress: run: plan completed")
            .count();
        assert_eq!((starts, ends), (3, 3), "{lines:?}");
        // Strictly sequential: each started run ends before the next starts.
        let mut open = 0i32;
        for l in &shaped {
            match *l {
                "progress: run: plan started" => {
                    open += 1;
                    assert_eq!(open, 1, "runs overlap: {lines:?}");
                }
                "progress: run: plan completed" => open -= 1,
                _ => assert_eq!(open, 1, "a line outside any run: {l}"),
            }
        }
    }

    #[test]
    fn json_stays_silent_whatever_mode_a_plain_request_would_pick() {
        let dir = fixture();
        let r = write(&dir, "r.yaml", RECIPE);
        let screen = Screen::default();
        // The decision, not the renderer, keeps JSON silent: a `Disabled` mode
        // never builds a consumer even though the plain factory is installed.
        let opts = ProgressOptions::new(ProgressMode::Disabled).with_consumer_factory(
            plain_consumer_factory(Arc::new({
                let screen = screen.clone();
                move || Box::new(ScreenSurface(screen.clone()))
            })),
        );
        let _ = drive_with(Phase::Plan, &[&r, "--format", "json"], &opts, vec![base()]).unwrap();
        assert_eq!(screen.text(), "");
        assert_eq!(
            sinter::progress_session::decide_mode(&sinter::progress_session::ModeInputs {
                json: true,
                stderr_is_tty: false,
                term_is_dumb: false,
                plain_requested: true,
            }),
            ProgressMode::Disabled
        );
    }

    // -----------------------------------------------------------------------
    // WP-VARS (DESIGN §19.5): the real wiring with a variables file.
    // -----------------------------------------------------------------------

    const CANARY: &str = "SINTER_VARS_CANARY_DO_NOT_PRINT_20261019";

    /// A recipe whose static path and content come from variables.
    const VARS_RECIPE: &str = "version: 1\ntargets:\n  groups: [web]\nvars:\n  name: { value: CHANGE_ME }\n  port: { value: 80 }\nresources:\n  - id: a\n    type: file\n    with:\n      path: \"/etc/perf/{{ vars.name }}\"\n      content: \"port {{ vars.port }}\\n\"\n";

    struct VarsRun {
        result: Result<u8, SinterError>,
        /// Scripted targets nobody consumed (each execution consumes one).
        untouched_targets: usize,
        models: Vec<Model>,
    }

    fn drive_vars(phase: Phase, argv: &[&str], targets: usize) -> VarsRun {
        let a = target_args(phase, argv);
        let format = parse_format(&a.format).unwrap();
        let w = wiring(ProgressMode::Disabled);
        FAKE_TARGETS.with(|f| *f.borrow_mut() = (0..targets).map(|_| base()).collect());
        EXECUTED_MODELS.with(|m| m.borrow_mut().clear());
        let result = run_phase_with(phase, &a, format, &w.opts);
        let untouched_targets = FAKE_TARGETS.with(|f| f.borrow_mut().drain(..).count());
        let models = EXECUTED_MODELS.with(|m| std::mem::take(&mut *m.borrow_mut()));
        VarsRun {
            result,
            untouched_targets,
            models,
        }
    }

    fn paths(models: &[Model]) -> Vec<String> {
        models
            .iter()
            .map(|m| m.resources[0].path.clone().unwrap())
            .collect()
    }

    #[test]
    fn every_inventory_host_runs_its_own_model() {
        let dir = fixture();
        let r = write(&dir, "r.yaml", VARS_RECIPE);
        let inv = inventory(&dir);
        let v = write(
            &dir,
            "v.yaml",
            "version: 1\ngroups:\n  web: { port: 8081 }\nhosts:\n  web01: { name: one }\n  web02: { name: two, port: 9 }\n",
        );
        let mut seen = Vec::new();
        for phase in [Phase::Plan, Phase::Audit, Phase::Apply] {
            let run = drive_vars(
                phase,
                &[
                    &r,
                    "--hosts",
                    &inv,
                    "--vars-file",
                    &v,
                    "--no-ssh-config",
                    "--format",
                    "json",
                ],
                2,
            );
            assert!(run.result.is_ok(), "{phase:?}: {:?}", run.result.err());
            assert_eq!(run.untouched_targets, 0);
            assert_eq!(paths(&run.models), ["/etc/perf/one", "/etc/perf/two"]);
            assert_eq!(
                run.models[0].vars["port"].value,
                sinter::value::Value::Int(8081)
            );
            assert_eq!(
                run.models[1].vars["port"].value,
                sinter::value::Value::Int(9)
            );
            // Host A's value never reaches host B's model (the engine's
            // variables are built from it).
            assert_eq!(
                run.models[1].vars["name"].value,
                sinter::value::Value::Str("two".into())
            );
            seen.push(format!("{:?}", run.models));
        }
        // plan, audit and apply evaluate each host identically.
        assert!(seen.windows(2).all(|w| w[0] == w[1]));
    }

    #[test]
    fn without_a_variables_file_the_recipe_model_runs_unchanged() {
        let dir = fixture();
        let r = write(&dir, "r.yaml", &VARS_RECIPE.replace("CHANGE_ME", "fixed"));
        let inv = inventory(&dir);
        let run = drive_vars(
            Phase::Plan,
            &[&r, "--hosts", &inv, "--no-ssh-config", "--format", "json"],
            2,
        );
        assert!(run.result.is_ok());
        let established = format!("{:?}", sinter::model::load_model(Path::new(&r)).unwrap());
        assert_eq!(run.models.len(), 2);
        for m in &run.models {
            assert_eq!(format!("{m:?}"), established);
        }
    }

    #[test]
    fn a_static_failure_on_one_host_contacts_no_host_in_any_phase() {
        let dir = fixture();
        let r = write(&dir, "r.yaml", VARS_RECIPE);
        let inv = inventory(&dir);
        let cases = [
            // unparsable file
            ("bad.yaml", format!("version: 1\nhosts: {{ web01: {{ name: \"{CANARY}\n")),
            // schema
            ("schema.yaml", "version: 2\n".to_string()),
            // override problem
            ("unknown.yaml", "version: 1\nvars: { nope: 1 }\nhosts: { web01: { name: a }, web02: { name: b } }\n".to_string()),
            // one host's freeze fails (relative path), the other is fine
            ("one.yaml", format!("version: 1\nhosts:\n  web01: {{ name: ok }}\n  web02: {{ name: \"../{CANARY}\" }}\n")),
        ];
        let rel = write(
            &dir,
            "rel.yaml",
            "version: 1\ntargets:\n  groups: [web]\nvars:\n  dir: { value: CHANGE_ME }\nresources:\n  - id: a\n    type: file\n    with: { path: \"{{ vars.dir }}/a\", content: x }\n",
        );
        let cases: Vec<(&str, String, &str)> = cases
            .into_iter()
            .map(|(n, b)| (n, b, r.as_str()))
            // a default that only fails where nothing overrides it
            .chain([(
                "partial.yaml",
                "version: 1\nhosts:\n  web01: { dir: /etc/perf }\n".to_string(),
                rel.as_str(),
            )])
            .collect();
        for (name, body, r) in cases {
            let v = write(&dir, name, &body);
            for phase in [Phase::Plan, Phase::Audit, Phase::Apply] {
                let run = drive_vars(
                    phase,
                    &[
                        r,
                        "--hosts",
                        &inv,
                        "--vars-file",
                        &v,
                        "--no-ssh-config",
                        "--format",
                        "json",
                    ],
                    2,
                );
                let e = run.result.expect_err(name);
                assert_eq!(e.kind, ErrorKind::Schema, "{name}");
                assert!(!e.message.contains(CANARY), "{name}");
                assert_eq!(
                    run.untouched_targets, 2,
                    "{name} {phase:?}: a target was contacted"
                );
                assert!(run.models.is_empty(), "{name} {phase:?}");
            }
        }
    }

    #[test]
    fn single_target_and_bundles_take_the_host_layer() {
        let dir = fixture();
        let r = write(&dir, "r.yaml", VARS_RECIPE);
        write(
            &dir,
            "r2.yaml",
            "version: 1\nvars:\n  port: { value: 1 }\nresources:\n  - id: b\n    type: file\n    with: { path: /etc/perf/b, content: \"{{ vars.port }}\" }\n",
        );
        let bundle = write(&dir, "b.yaml", "version: 1\nrecipes: [r.yaml, r2.yaml]\n");
        let v = write(
            &dir,
            "v.yaml",
            "version: 1\nvars: { port: 7 }\nhosts:\n  localhost: { name: local }\n  srv1: { name: remote }\n",
        );
        // Local target: hosts.localhost.
        let run = drive_vars(Phase::Plan, &[&r, "--vars-file", &v, "--format", "json"], 1);
        assert!(run.result.is_ok(), "{:?}", run.result.err());
        assert_eq!(paths(&run.models), ["/etc/perf/local"]);
        // --host: hosts.<that string>.
        let run = drive_vars(
            Phase::Plan,
            &[
                &r,
                "--host",
                "srv1",
                "--no-ssh-config",
                "--vars-file",
                &v,
                "--format",
                "json",
            ],
            1,
        );
        assert_eq!(paths(&run.models), ["/etc/perf/remote"]);
        // A bundle on one target: every recipe gets the host's values.
        let run = drive_vars(
            Phase::Plan,
            &[&bundle, "--vars-file", &v, "--format", "json"],
            2,
        );
        assert!(run.result.is_ok(), "{:?}", run.result.err());
        assert_eq!(paths(&run.models), ["/etc/perf/local", "/etc/perf/b"]);
        for m in &run.models {
            assert_eq!(m.vars["port"].value, sinter::value::Value::Int(7));
        }
        // A freeze failure on the local target starts no executor.
        let bad = write(
            &dir,
            "bad.yaml",
            "version: 1\nhosts: { localhost: { name: \"../x\" } }\n",
        );
        let run = drive_vars(
            Phase::Apply,
            &[&r, "--vars-file", &bad, "--format", "json"],
            1,
        );
        assert_eq!(run.result.unwrap_err().kind, ErrorKind::Schema);
        assert_eq!(run.untouched_targets, 1);
        assert!(run.models.is_empty());
        // Group values need an inventory: refused before anything runs.
        let g = write(
            &dir,
            "g.yaml",
            "version: 1\ngroups: { web: { port: 1 } }\nhosts: { localhost: { name: x } }\n",
        );
        let run = drive_vars(
            Phase::Apply,
            &[&r, "--vars-file", &g, "--format", "json"],
            1,
        );
        assert!(run.result.is_err());
        assert_eq!(run.untouched_targets, 1);
        assert!(run.models.is_empty());
    }

    #[test]
    fn apply_stays_fail_fast_with_a_variables_file() {
        let dir = fixture();
        // The first scripted target is unsupported: its execution fails at
        // connect.
        let r = write(
            &dir,
            "r.yaml",
            "version: 1\ntargets:\n  groups: [web]\nvars:\n  pkg: { value: jq }\nresources:\n  - id: p\n    type: package\n    with: { name: \"{{ vars.pkg }}\", state: present }\n",
        );
        let inv = inventory(&dir);
        let v = write(
            &dir,
            "v.yaml",
            "version: 1\nhosts: { web01: { pkg: curl }, web02: { pkg: git } }\n",
        );
        let a = target_args(
            Phase::Apply,
            &[
                &r,
                "--hosts",
                &inv,
                "--vars-file",
                &v,
                "--no-ssh-config",
                "--format",
                "json",
            ],
        );
        let w = wiring(ProgressMode::Disabled);
        FAKE_TARGETS.with(|f| *f.borrow_mut() = vec![FakeTarget::unsupported(), base()].into());
        EXECUTED_MODELS.with(|m| m.borrow_mut().clear());
        let code = run_phase_with(Phase::Apply, &a, OutputFormat::Json, &w.opts).unwrap();
        let left = FAKE_TARGETS.with(|f| f.borrow_mut().drain(..).count());
        let models = EXECUTED_MODELS.with(|m| std::mem::take(&mut *m.borrow_mut()));
        assert_ne!(code, 0);
        // web02 was never contacted: it is reported not_run.
        assert_eq!(left, 1);
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].resources[0].package_name.as_deref(), Some("curl"));
    }

    // -----------------------------------------------------------------------
    // WP-VARS A-1: models are bound to (recipe, host) and checked in every
    // build before anything connects.
    // -----------------------------------------------------------------------

    /// A model whose variable `tag` identifies it.
    fn tagged(tag: &str) -> Model {
        let dir = fixture();
        let p = write(
            &dir,
            "t.yaml",
            &format!("version: 1\nvars:\n  tag: {{ value: {tag} }}\nresources: []\n"),
        );
        sinter::model::load_model(Path::new(&p)).unwrap()
    }

    fn tag_of(m: &Model) -> String {
        match &m.vars["tag"].value {
            sinter::value::Value::Str(s) => s.clone(),
            v => panic!("{v:?}"),
        }
    }

    fn planned(list: &[(usize, &str)]) -> Vec<Execution> {
        list.iter()
            .map(|(unit, host)| Execution {
                unit: *unit,
                target: Target {
                    name: host.to_string(),
                    spec: TargetSpec { ssh: None },
                },
                model: None,
            })
            .collect()
    }

    fn frozen(list: &[(usize, &str)]) -> Vec<FrozenExecution> {
        list.iter()
            .map(|(unit, host)| FrozenExecution {
                unit: *unit,
                host: host.to_string(),
                model: tagged(&format!("u{unit}-{host}")),
            })
            .collect()
    }

    fn units(n: usize) -> Vec<RecipeUnit> {
        (0..n)
            .map(|i| RecipeUnit {
                label: format!("r{i}"),
                path: PathBuf::from(format!("r{i}.yaml")),
                model: tagged("display"),
            })
            .collect()
    }

    const PLAN: &[(usize, &str)] = &[(0, "web01"), (0, "web02"), (1, "web01"), (1, "web02")];

    #[test]
    fn matching_models_are_attached_to_their_own_execution() {
        let mut ex = planned(PLAN);
        attach_models(&mut ex, frozen(PLAN), &units(2)).unwrap();
        let got: Vec<String> = ex
            .iter()
            .map(|e| tag_of(e.model.as_ref().unwrap()))
            .collect();
        assert_eq!(got, ["u0-web01", "u0-web02", "u1-web01", "u1-web02"]);
    }

    #[test]
    fn any_mismatch_attaches_nothing_and_fails_closed() {
        let cases: Vec<(&str, Vec<(usize, &str)>)> = vec![
            ("too few models", PLAN[..3].to_vec()),
            ("too many models", [PLAN, &[(1, "web03")]].concat()),
            (
                "other recipe",
                vec![(0, "web01"), (0, "web02"), (0, "web01"), (1, "web02")],
            ),
            (
                "other host",
                vec![(0, "web01"), (0, "web03"), (1, "web01"), (1, "web02")],
            ),
            (
                "swapped order",
                vec![(0, "web02"), (0, "web01"), (1, "web01"), (1, "web02")],
            ),
            (
                "recipe out of range",
                vec![(0, "web01"), (0, "web02"), (1, "web01"), (7, "web02")],
            ),
        ];
        for (what, list) in cases {
            let mut ex = planned(PLAN);
            let e = attach_models(&mut ex, frozen(&list), &units(2)).expect_err(what);
            assert_eq!(e.kind, ErrorKind::Schema, "{what}");
            assert!(
                e.message.starts_with(
                    "internal error: the planned executions do not match the frozen models"
                ),
                "{what}: {}",
                e.message
            );
            assert!(e.message.ends_with("no host was contacted"), "{what}");
            assert!(
                ex.iter().all(|e| e.model.is_none()),
                "{what}: a model was attached"
            );
        }
        // The plan itself shorter than the models is the same failure.
        let mut ex = planned(&PLAN[..3]);
        assert!(attach_models(&mut ex, frozen(PLAN), &units(2)).is_err());
        assert!(ex.iter().all(|e| e.model.is_none()));
    }

    #[test]
    fn binding_requires_one_model_per_planned_pair() {
        let pairs = |n: usize| (0..n).map(|i| (0, format!("h{i}"))).collect::<Vec<_>>();
        let models = |n: usize| (0..n).map(|i| tagged(&format!("m{i}"))).collect::<Vec<_>>();
        assert!(bind_models(pairs(2), models(1)).is_err());
        assert!(bind_models(pairs(1), models(2)).is_err());
        let b = bind_models(pairs(2), models(2)).unwrap();
        assert_eq!(
            (b[1].unit, b[1].host.as_str(), tag_of(&b[1].model).as_str()),
            (0, "h1", "m1")
        );
    }

    #[test]
    fn one_target_models_must_name_that_target_in_recipe_order() {
        let dir = fixture();
        let a = write(&dir, "a.yaml", "version: 1\nresources: []\n");
        write(&dir, "b.yaml", "version: 1\nresources: []\n");
        let bundle = write(&dir, "x.yaml", "version: 1\nrecipes: [a.yaml, b.yaml]\n");
        let source = load_source(Path::new(&bundle)).unwrap();
        let ok = models_for_one_target(frozen(&[(0, "srv"), (1, "srv")]), &source, "srv").unwrap();
        assert_eq!(
            ok.iter().map(tag_of).collect::<Vec<_>>(),
            ["u0-srv", "u1-srv"]
        );
        for (what, list) in [
            ("too few", vec![(0, "srv")]),
            ("too many", vec![(0, "srv"), (1, "srv"), (1, "srv")]),
            ("other host", vec![(0, "srv"), (1, "localhost")]),
            ("swapped", vec![(1, "srv"), (0, "srv")]),
        ] {
            assert!(
                models_for_one_target(frozen(&list), &source, "srv").is_err(),
                "{what}"
            );
        }
        let single = load_source(Path::new(&a)).unwrap();
        assert!(models_for_one_target(frozen(&[(0, "other")]), &single, "localhost").is_err());
    }

    fn drop_last(f: &mut Vec<FrozenExecution>) {
        f.pop();
    }
    fn duplicate_last(f: &mut Vec<FrozenExecution>) {
        let last = f.last().unwrap();
        let copy = FrozenExecution {
            unit: last.unit,
            host: last.host.clone(),
            model: last.model.clone(),
        };
        f.push(copy);
    }
    #[allow(clippy::ptr_arg)] // a `Tamper`
    fn swap_first_two(f: &mut Vec<FrozenExecution>) {
        f.swap(0, 1);
    }
    #[allow(clippy::ptr_arg)] // a `Tamper`
    fn other_host(f: &mut Vec<FrozenExecution>) {
        f[0].host = "elsewhere".into();
    }
    /// Recipe 0 <-> 1 on the last model: another recipe of a bundle, or no
    /// recipe of a plain run.
    #[allow(clippy::ptr_arg)] // a `Tamper`
    fn other_recipe(f: &mut Vec<FrozenExecution>) {
        let last = f.len() - 1;
        f[last].unit = 1 - f[last].unit.min(1);
    }
    #[allow(clippy::ptr_arg)] // a `Tamper`
    fn no_recipe(f: &mut Vec<FrozenExecution>) {
        f[0].unit = 99;
    }

    /// A run whose frozen models are corrupted by `tamper`.
    fn drive_tampered(phase: Phase, argv: &[&str], targets: usize, tamper: Tamper) -> VarsRun {
        TAMPER.with(|t| t.set(Some(tamper)));
        let run = drive_vars(phase, argv, targets);
        TAMPER.with(|t| t.set(None));
        run
    }

    const TAMPERS: &[(&str, Tamper)] = &[
        ("drop last", drop_last),
        ("duplicate last", duplicate_last),
        ("swap first two", swap_first_two),
        ("other host", other_host),
        ("other recipe", other_recipe),
        ("no recipe", no_recipe),
    ];

    #[test]
    fn a_mismatch_in_any_mode_and_phase_runs_nothing() {
        let dir = fixture();
        let r = write(&dir, "r.yaml", VARS_RECIPE);
        let r2 = write(
            &dir,
            "r2.yaml",
            &VARS_RECIPE
                .replace("id: a", "id: b")
                .replace("/etc/perf/", "/etc/perf/b-"),
        );
        let _ = r2;
        let bundle = write(&dir, "b.yaml", "version: 1\nrecipes: [r.yaml, r2.yaml]\n");
        let inv = inventory(&dir);
        let vi = write(
            &dir,
            "vi.yaml",
            "version: 1\nhosts:\n  web01: { name: one }\n  web02: { name: two }\n",
        );
        let vs = write(
            &dir,
            "vs.yaml",
            "version: 1\nhosts:\n  web01: { name: one }\n  localhost: { name: here }\n",
        );
        // (source, mode arguments, executions)
        let runs: Vec<(&str, Vec<&str>, usize, &String)> = vec![
            (r.as_str(), vec!["--hosts", &inv, "--no-ssh-config"], 2, &vi),
            (
                bundle.as_str(),
                vec!["--hosts", &inv, "--no-ssh-config"],
                4,
                &vi,
            ),
            (r.as_str(), vec![], 1, &vs),
            (bundle.as_str(), vec![], 2, &vs),
            (
                bundle.as_str(),
                vec!["--host", "web01", "--no-ssh-config"],
                2,
                &vs,
            ),
        ];
        for (src, mode, n, v) in &runs {
            for (what, tamper) in TAMPERS {
                if *what == "swap first two" && *n < 2 {
                    continue; // one execution has no order to swap
                }
                for phase in [Phase::Plan, Phase::Audit, Phase::Apply] {
                    let mut argv = vec![*src, "--vars-file", v.as_str(), "--format", "json"];
                    argv.extend(mode.iter().copied());
                    let run = drive_tampered(phase, &argv, *n, *tamper);
                    let ctx = format!("{src} {mode:?} {what} {phase:?}");
                    let e = run.result.expect_err(&ctx);
                    assert_eq!(e.kind, ErrorKind::Schema, "{ctx}");
                    assert!(
                        e.message.starts_with("internal error:"),
                        "{ctx}: {}",
                        e.message
                    );
                    assert_eq!(run.untouched_targets, *n, "{ctx}: a target was contacted");
                    assert!(run.models.is_empty(), "{ctx}: something ran");
                }
            }
            // Untampered, the same run executes every execution.
            let mut argv = vec![*src, "--vars-file", v.as_str(), "--format", "json"];
            argv.extend(mode.iter().copied());
            let run = drive_vars(Phase::Plan, &argv, *n);
            assert!(run.result.is_ok(), "{src} {mode:?}: {:?}", run.result.err());
            assert_eq!(run.untouched_targets, 0);
            assert_eq!(run.models.len(), *n);
        }
    }

    #[allow(clippy::ptr_arg)] // a `Tamper`
    fn drop_all(f: &mut Vec<FrozenExecution>) {
        f.clear();
    }

    /// `validate --vars-file` goes through the same gate, including its
    /// check that every recipe has a model bound to the pair it was frozen
    /// for: an inconsistency is an internal error (exit 2) and nothing is
    /// reported.
    #[test]
    fn validate_with_a_variables_file_stops_on_an_inconsistent_gate() {
        let dir = fixture();
        let r = write(&dir, "r.yaml", VARS_RECIPE);
        let inv = inventory(&dir);
        let v = write(
            &dir,
            "v.yaml",
            "version: 1\nhosts:\n  web01: { name: one }\n  web02: { name: two }\n",
        );
        let a = match Cli::try_parse_from([
            "sinter",
            "validate",
            &r,
            "--vars-file",
            &v,
            "--hosts",
            &inv,
        ])
        .unwrap()
        .command
        {
            Command::Validate(a) => a,
            _ => unreachable!(),
        };
        assert!(validate(&a).is_ok(), "untampered");
        for (what, tamper) in [("no recipe", no_recipe as Tamper), ("drop all", drop_all)] {
            TAMPER.with(|t| t.set(Some(tamper)));
            let result = validate(&a);
            TAMPER.with(|t| t.set(None));
            let e = result.expect_err(what);
            assert_eq!(e.kind, ErrorKind::Schema, "{what}");
            assert!(
                e.message.starts_with("internal error:"),
                "{what}: {}",
                e.message
            );
        }
    }

    #[test]
    fn bundles_on_several_hosts_run_each_recipe_with_its_hosts_values() {
        let dir = fixture();
        write(&dir, "r.yaml", VARS_RECIPE);
        write(
            &dir,
            "r2.yaml",
            &VARS_RECIPE
                .replace("id: a", "id: b")
                .replace("/etc/perf/", "/etc/perf/b-"),
        );
        let bundle = write(&dir, "b.yaml", "version: 1\nrecipes: [r.yaml, r2.yaml]\n");
        let inv = inventory(&dir);
        let v = write(
            &dir,
            "v.yaml",
            "version: 1\nhosts:\n  web01: { name: one, port: 1 }\n  web02: { name: two, port: 2 }\n",
        );
        for phase in [Phase::Plan, Phase::Audit, Phase::Apply] {
            let run = drive_vars(
                phase,
                &[
                    &bundle,
                    "--hosts",
                    &inv,
                    "--vars-file",
                    &v,
                    "--no-ssh-config",
                    "--format",
                    "json",
                ],
                4,
            );
            assert!(run.result.is_ok(), "{phase:?}: {:?}", run.result.err());
            assert_eq!(
                paths(&run.models),
                [
                    "/etc/perf/one",
                    "/etc/perf/two",
                    "/etc/perf/b-one",
                    "/etc/perf/b-two"
                ],
                "{phase:?}"
            );
            let ports: Vec<_> = run
                .models
                .iter()
                .map(|m| m.vars["port"].value.clone())
                .collect();
            use sinter::value::Value::Int;
            assert_eq!(ports, [Int(1), Int(2), Int(1), Int(2)], "{phase:?}");
        }
    }

    /// Evidence of the build the mismatch tests ran in: they hold with debug
    /// assertions on and off (`cargo test --release`).
    #[test]
    fn mismatch_checks_do_not_depend_on_debug_assertions() {
        eprintln!("A-1 build: debug_assertions={}", cfg!(debug_assertions));
        let mut ex = planned(PLAN);
        assert!(attach_models(&mut ex, frozen(&PLAN[..3]), &units(2)).is_err());
        assert!(ex.iter().all(|e| e.model.is_none()));
    }
}
