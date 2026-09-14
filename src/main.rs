use clap::{Args, Parser, Subcommand};
use sinter::diff::sanitize_line;
use sinter::engine::{Engine, Mode, RunOptions, SshSpec, TargetSpec};
use sinter::error::{ErrorKind, SinterError};
use sinter::model::load_model;
use sinter::output::{render_apply, render_plan, OutputFormat, RenderOptions};
use std::path::PathBuf;
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
    /// Validate a recipe without connecting to a target.
    Validate(ValidateArgs),
    /// Preview changes against a target without mutating it.
    Plan(TargetArgs),
    /// Apply a recipe to a target.
    Apply(TargetArgs),
}

#[derive(Args, Debug)]
struct ValidateArgs {
    recipe: PathBuf,
    /// Emit structured JSON output.
    #[arg(long, default_value = "text")]
    format: String,
}

#[derive(Args, Debug)]
struct TargetArgs {
    recipe: PathBuf,
    /// SSH host. If omitted, the target is localhost.
    #[arg(long)]
    host: Option<String>,
    /// SSH port.
    #[arg(long, default_value_t = 22)]
    port: u16,
    /// SSH user.
    #[arg(long)]
    user: Option<String>,
    /// known_hosts file (defaults to ~/.ssh/known_hosts).
    #[arg(long)]
    known_hosts: Option<PathBuf>,
    /// Additional SSH identity file (may be repeated).
    #[arg(long = "identity")]
    identity: Vec<PathBuf>,
    /// Enable passwordless sudo (non-interactive `sudo -n`).
    #[arg(long)]
    sudo: bool,
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
            eprintln!("sinter: {}", sanitize_line(&e.message));
            ExitCode::from(e.kind.exit_code() as u8)
        }
    }
}

fn run(cli: Cli) -> Result<u8, SinterError> {
    match cli.command {
        Command::Validate(a) => {
            let format = parse_format(&a.format)?;
            let model = load_model(&a.recipe)?;
            if format == OutputFormat::Json {
                let doc = serde_json::json!({
                    "command": "validate",
                    "status": "ok",
                    "resources": model.resources.len(),
                    "handlers": model.handlers.len(),
                    "vars": model.vars.len(),
                });
                println!("{}", serde_json::to_string_pretty(&doc).unwrap());
            } else {
                println!(
                    "ok: {} resource(s), {} handler(s), {} var(s)",
                    model.resources.len(),
                    model.handlers.len(),
                    model.vars.len()
                );
            }
            Ok(0)
        }
        Command::Plan(a) => {
            let format = parse_format(&a.format)?;
            let model = load_model(&a.recipe)?;
            let opts = build_opts(&a, Mode::Plan)?;
            let engine = Engine::new(model, opts)?;
            let report = engine.run()?;
            let ro = RenderOptions {
                verbose: a.verbose,
                format,
            };
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            render_plan(&report, &ro, &mut lock).map_err(io_error)?;
            Ok(report_status_code(&report.status))
        }
        Command::Apply(a) => {
            let format = parse_format(&a.format)?;
            let model = load_model(&a.recipe)?;
            let opts = build_opts(&a, Mode::Apply)?;
            let engine = Engine::new(model, opts)?;
            let report = engine.run()?;
            let ro = RenderOptions {
                verbose: a.verbose,
                format,
            };
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            render_apply(&report, &ro, &mut lock).map_err(io_error)?;
            Ok(report_status_code(&report.status))
        }
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

fn build_opts(a: &TargetArgs, mode: Mode) -> Result<RunOptions, SinterError> {
    let target = match &a.host {
        None => TargetSpec { ssh: None },
        Some(host) => {
            let user = match &a.user {
                Some(u) => u.clone(),
                None => std::env::var("USER")
                    .map_err(|_| SinterError::connect("--user is required when USER is not set"))?,
            };
            let known_hosts = match &a.known_hosts {
                Some(p) => p.clone(),
                None => {
                    let home = std::env::var_os("HOME")
                        .map(PathBuf::from)
                        .ok_or_else(|| SinterError::connect("HOME is not set"))?;
                    home.join(".ssh/known_hosts")
                }
            };
            TargetSpec {
                ssh: Some(SshSpec {
                    host: host.clone(),
                    port: a.port,
                    user,
                    known_hosts,
                    identity_files: a.identity.clone(),
                }),
            }
        }
    };
    Ok(RunOptions {
        mode,
        sudo: a.sudo,
        target,
        verbose: a.verbose,
        fault: None,
        fake_target: None,
    })
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
