//! `sinter-bridge` — production controller-side bridge for the Sinter
//! public plugin. Outbound HTTPS only: long-polls the Gateway, forwards
//! opaque MCP work to the fixed `sinter mcp` child, posts responses.
//!
//! Thin glue over `sinter_gateway::bridge`: configuration, credential
//! injection, logging, lifecycle. See PRODUCTION_DEPLOYMENT.md.

use std::path::PathBuf;
use std::process::exit;

use sinter_gateway::bridge::{self, BridgeConfig};

const USAGE: &str = "\
sinter-bridge — Sinter public plugin controller bridge

USAGE:
  sinter-bridge                          run (env-configured)
  sinter-bridge register                 exchange a registration token for
                                         a controller credential; the token
                                         is read from SINTER_BRIDGE_REG_TOKEN
                                         or prompted on stdin — never argv
                                         (printed once)
  sinter-bridge --check                  validate config + child spawn, exit
  sinter-bridge --version
  sinter-bridge --help

ENVIRONMENT (required):
  SINTER_BRIDGE_GATEWAY_URL      Gateway base URL, e.g. https://gw.example.com
  SINTER_BRIDGE_CREDENTIAL_FILE  file containing the controller credential
                                 (preferred; chmod 600)
  SINTER_BRIDGE_CREDENTIAL       credential via environment (alternative)

ENVIRONMENT (optional):
  SINTER_BRIDGE_SINTER_BIN       sinter executable [sinter]
  SINTER_BRIDGE_TARGETS_FILE     local targets file for the mcp child
  SINTER_BRIDGE_ALLOW_HTTP=1     dev-only: permit http:// to LOOPBACK only
  SINTER_BRIDGE_LOG              tracing filter [info]

Never pass the controller credential, registration token, or any secret
as a command-line argument.
";

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn fail(msg: &str) -> ! {
    eprintln!("sinter-bridge: {msg}");
    exit(2)
}

fn allow_http() -> bool {
    matches!(
        env("SINTER_BRIDGE_ALLOW_HTTP").as_deref(),
        Some("1") | Some("true")
    )
}

/// Load the controller credential without ever putting it in argv or
/// logs. File preferred; env var supported for secret-manager injection.
fn load_credential() -> Result<String, String> {
    if let Some(path) = env("SINTER_BRIDGE_CREDENTIAL_FILE") {
        let raw =
            std::fs::read_to_string(&path).map_err(|e| format!("read credential file: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(md) = std::fs::metadata(&path) {
                if md.permissions().mode() & 0o077 != 0 {
                    eprintln!(
                        "sinter-bridge: warning: credential file {path} is \
                         group/world-accessible — chmod 600 recommended"
                    );
                }
            }
        }
        let cred = raw.trim().to_string();
        if cred.is_empty() {
            return Err("credential file is empty".to_string());
        }
        Ok(cred)
    } else if let Some(c) = env("SINTER_BRIDGE_CREDENTIAL") {
        Ok(c.trim().to_string())
    } else {
        Err(
            "missing controller credential — set SINTER_BRIDGE_CREDENTIAL_FILE \
             or SINTER_BRIDGE_CREDENTIAL"
                .to_string(),
        )
    }
}

fn config() -> Result<BridgeConfig, String> {
    let url = env("SINTER_BRIDGE_GATEWAY_URL")
        .ok_or_else(|| "missing SINTER_BRIDGE_GATEWAY_URL".to_string())?;
    let cred = load_credential()?;
    let bin = env("SINTER_BRIDGE_SINTER_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("sinter"));
    let targets = env("SINTER_BRIDGE_TARGETS_FILE").map(PathBuf::from);
    BridgeConfig::new(&url, cred, bin, targets, allow_http())
}

fn init_log() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("SINTER_BRIDGE_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => {}
        [a] if a == "--help" || a == "-h" => {
            print!("{USAGE}");
            return;
        }
        [a] if a == "--version" || a == "-V" => {
            println!("sinter-bridge {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        [a] if a == "--check" => {
            match config().and_then(|c| bridge::McpChild::spawn(&c).map(|_| ())) {
                Ok(()) => {
                    println!("ok");
                    return;
                }
                Err(e) => fail(&e),
            }
        }
        [a] if a == "register" => {
            init_log();
            let url = match env("SINTER_BRIDGE_GATEWAY_URL") {
                Some(u) => u,
                None => fail("missing SINTER_BRIDGE_GATEWAY_URL"),
            };
            // Token comes from env or stdin — never argv (process list /
            // shell-history exposure).
            let token = match env("SINTER_BRIDGE_REG_TOKEN") {
                Some(t) => t.trim().to_string(),
                None => {
                    eprint!("registration token: ");
                    let mut t = String::new();
                    if std::io::stdin().read_line(&mut t).is_err() || t.trim().is_empty() {
                        fail("no registration token on stdin");
                    }
                    t.trim().to_string()
                }
            };
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap_or_else(|e| fail(&format!("runtime: {e}")));
            match rt.block_on(bridge::register_controller(&url, &token, allow_http())) {
                Ok(cred) => {
                    // Printed once to the operator; store it in the
                    // credential file (chmod 600).
                    println!("{cred}");
                    return;
                }
                Err(e) => fail(&e),
            }
        }
        _ => {
            eprintln!("{USAGE}");
            exit(64);
        }
    }

    init_log();
    let cfg = match config() {
        Ok(c) => c,
        Err(e) => fail(&e),
    };
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| fail(&format!("runtime: {e}")));
    rt.block_on(async {
        let (tx, rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            shutdown_signal().await;
            let _ = tx.send(true);
        });
        if let Err(e) = bridge::run(cfg, rx).await {
            fail(&e);
        }
    });
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(t) => t,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
