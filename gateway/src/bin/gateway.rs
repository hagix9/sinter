//! `sinter-gateway` — production assembly of the accepted P1–P7 Gateway
//! library into a deployable executable. Thin by design: configuration,
//! dependency construction, listener startup, lifecycle, logging.
//!
//! Configuration is environment-only (see PRODUCTION_DEPLOYMENT.md).
//! All required values must be present and valid — the process fails
//! closed rather than running with insecure defaults.
//!
//! Admin subcommands (operator-side, local):
//!   --issue-registration-token <account>   mint a single-use controller
//!                                          registration token (printed once)
//!   --revoke-controller <controller_id>    revoke a controller binding

use std::collections::HashSet;
use std::process::exit;
use std::sync::Arc;

use sinter_gateway::config::GwConfig;
use sinter_gateway::oauth::OAuthConfig;
use sinter_gateway::{
    AccountId, ControllerAuth, ControllerId, GatewayCore, GatewayHttp, GatewayServer, SqliteStore,
    SystemClock,
};

const USAGE: &str = "\
sinter-gateway — Sinter public plugin gateway

USAGE:
  sinter-gateway                          serve (env-configured, see docs)
  sinter-gateway --issue-registration-token <account>
  sinter-gateway --revoke-controller <controller-id>
  sinter-gateway --version
  sinter-gateway --help

ENVIRONMENT (required):
  SINTER_GW_BIND             listener bind, e.g. 127.0.0.1:8443
  SINTER_GW_SQLITE           durable identity store path
  SINTER_GW_PUBLIC_URL       external public URL (RFC 9728 resource)
  SINTER_GW_OAUTH_ISSUER     trusted token issuer (exact iss match)
  SINTER_GW_OAUTH_AUDIENCE   expected aud (RFC 8707 resource indicator)
  SINTER_GW_OAUTH_JWKS_URI   pinned JWKS document URI (https)

ENVIRONMENT (optional):
  SINTER_GW_OAUTH_ACCOUNT_CLAIM   account binding claim [sinter_account]
  SINTER_GW_ALLOWED_ORIGINS       comma-separated Origin allowlist
  SINTER_GW_RATE_* / SINTER_GW_METRICS_* / SINTER_GW_CLEANUP_*
                                  P7 operational knobs (see RFC §M)
";

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn req_env(name: &str) -> Result<String, String> {
    env(name).ok_or_else(|| format!("missing required env {name}"))
}

fn fail(msg: &str) -> ! {
    eprintln!("sinter-gateway: {msg}");
    exit(2);
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
            println!(
                "sinter-gateway {} (test-auth: {})",
                env!("CARGO_PKG_VERSION"),
                if cfg!(feature = "test-auth") {
                    "ON"
                } else {
                    "off"
                }
            );
            return;
        }
        [a, account] if a == "--issue-registration-token" => admin_issue(account),
        [a, id] if a == "--revoke-controller" => admin_revoke(id),
        _ => {
            eprintln!("{USAGE}");
            exit(64);
        }
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| fail(&format!("runtime: {e}")));
    if let Err(e) = rt.block_on(serve()) {
        fail(&e);
    }
}

fn open_store() -> Result<Arc<SqliteStore>, String> {
    let path = req_env("SINTER_GW_SQLITE")?;
    SqliteStore::open(&path)
        .map(Arc::new)
        .map_err(|e| format!("open sqlite store {path}: {e:?}"))
}

/// Operator-side: mint a single-use registration token for `account`.
/// The plaintext token is printed once — it is never stored or logged.
fn admin_issue(account: &str) -> ! {
    let store = match open_store() {
        Ok(s) => s,
        Err(e) => fail(&e),
    };
    let auth = ControllerAuth::new(store, SystemClock);
    match auth.issue_registration_token(&AccountId::new(account)) {
        Ok(t) => {
            println!("{}", t.expose());
            exit(0);
        }
        Err(e) => fail(&format!("issue token: {e}")),
    }
}

fn admin_revoke(id: &str) -> ! {
    let store = match open_store() {
        Ok(s) => s,
        Err(e) => fail(&e),
    };
    let auth = ControllerAuth::new(store, SystemClock);
    match auth.revoke_controller(&ControllerId::new(id)) {
        Ok(()) => {
            eprintln!("controller {id} revoked");
            exit(0);
        }
        Err(e) => fail(&format!("revoke controller: {e}")),
    }
}

async fn serve() -> Result<(), String> {
    // ---- required configuration (fail closed) ----
    let bind = req_env("SINTER_GW_BIND")?;
    let store = open_store()?;
    let public_url = req_env("SINTER_GW_PUBLIC_URL")?;
    let issuer = req_env("SINTER_GW_OAUTH_ISSUER")?;
    let audience = req_env("SINTER_GW_OAUTH_AUDIENCE")?;
    let jwks_uri = req_env("SINTER_GW_OAUTH_JWKS_URI")?;
    let gw_cfg = GwConfig::from_env().map_err(|e| format!("config: {e}"))?;

    let origins: HashSet<String> = env("SINTER_GW_ALLOWED_ORIGINS")
        .map(|s| s.split(',').map(|o| o.trim().to_string()).collect())
        .unwrap_or_default();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("SINTER_GW_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let authn = Arc::new(ControllerAuth::new(store.clone(), SystemClock));
    let core = Arc::new(GatewayCore::new());
    let http = GatewayHttp::new(core, authn, store);

    // Public auth: production OAuth. When built with the `test-auth`
    // feature (non-production builds only), SINTER_GW_TEST_PRINCIPALS
    // supplies a loopback/test principal map instead — the production
    // artifact never carries this code path.
    #[cfg(feature = "test-auth")]
    let http = match env("SINTER_GW_TEST_PRINCIPALS") {
        Some(spec) => {
            let mut auth = sinter_gateway::TestPublicAuth::new();
            for pair in spec.split(',') {
                let (tok, rest) = pair.split_once('=').ok_or_else(|| {
                    "SINTER_GW_TEST_PRINCIPALS: expected token=acct:sub".to_string()
                })?;
                let (acct, sub) = rest.split_once(':').ok_or_else(|| {
                    "SINTER_GW_TEST_PRINCIPALS: expected token=acct:sub".to_string()
                })?;
                auth.add(tok, acct, sub);
            }
            http.with_public_auth(std::sync::Arc::new(auth), origins)
                .with_config(&gw_cfg)
        }
        None => oauth_http(
            http,
            &issuer,
            &audience,
            &public_url,
            &jwks_uri,
            &gw_cfg,
            origins,
        )?,
    };
    #[cfg(not(feature = "test-auth"))]
    let http = oauth_http(
        http,
        &issuer,
        &audience,
        &public_url,
        &jwks_uri,
        &gw_cfg,
        origins,
    )?;

    let server = GatewayServer::start(http, &bind)
        .await
        .map_err(|e| format!("bind {bind}: {e}"))?;
    tracing::info!("sinter-gateway serving on {}", server.addr);
    if let Some(m) = server.metrics_addr {
        tracing::info!("metrics on {m}");
    }
    shutdown_signal().await;
    server.shutdown().await;
    Ok(())
}

fn oauth_http(
    http: GatewayHttp,
    issuer: &str,
    audience: &str,
    public_url: &str,
    jwks_uri: &str,
    gw_cfg: &GwConfig,
    origins: HashSet<String>,
) -> Result<GatewayHttp, String> {
    let mut oauth = OAuthConfig::new(issuer, audience, public_url, jwks_uri);
    if let Some(claim) = env("SINTER_GW_OAUTH_ACCOUNT_CLAIM") {
        oauth.account_claim = claim;
    }
    let jwks =
        sinter_gateway::oauth::HttpJwksSource::new().map_err(|e| format!("jwks source: {e}"))?;
    http.with_oauth(oauth, Box::new(jwks), origins)
        .map_err(|e| format!("oauth config: {e}"))
        .map(|h| h.with_config(gw_cfg))
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
