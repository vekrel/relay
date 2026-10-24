mod accounts;
// shortcut: the relay protocol core has no routes until Task 9 (link, connect); drop the allows then.
#[allow(dead_code)]
mod auth;
mod config;
mod db;
mod http;
#[allow(dead_code)]
mod jws;
mod keygen;
#[cfg(test)]
mod test_logs;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "vekrel-relay", version, about = "Vekrel relay")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the HTTP server (default).
    Serve,
    /// Print a fresh Ed25519 private key (PKCS#8 PEM) and its public JWK.
    Keygen {
        /// Instead print one `AUTH_SIGNING_KEYS` entry (`status: next`) with this kid.
        #[arg(long, value_name = "KID")]
        auth_kid: Option<String>,
    },
}

#[tokio::main]
async fn main() {
    match Cli::parse().command.unwrap_or(Command::Serve) {
        Command::Keygen {
            auth_kid: Some(kid),
        } => println!("{}", keygen::auth_signing_key(&kid)),
        Command::Keygen { auth_kid: None } => {
            let kp = keygen::generate();
            print!("{}", kp.private_pem);
            println!("{}", kp.public_jwk);
        }
        Command::Serve => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "info".into()),
                )
                .init();
            if let Err(e) = serve().await {
                tracing::error!(error = %e, "relay stopped");
                std::process::exit(1);
            }
        }
    }
}

async fn serve() -> Result<(), String> {
    let config = config::Config::from_env()?;
    let database_url = config
        .database_url
        .as_deref()
        .ok_or("DATABASE_URL is required")?;
    let keys = accounts::keys::SigningKeys::from_env()?;
    let pool = db::connect(database_url).await?;
    let versions = db::migrate(&pool).await?;
    tracing::info!(?versions, "migrations applied");
    let listener = tokio::net::TcpListener::bind(config.addr)
        .await
        .map_err(|e| format!("bind {}: {e}", config.addr))?;
    tracing::info!(addr = %config.addr, origin = %config.relay_origin, "relay listening");
    axum::serve(listener, http::router(pool, &keys, &config.relay_origin))
        .with_graceful_shutdown(shutdown())
        .await
        .map_err(|e| e.to_string())
}

async fn shutdown() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        tokio::select! { _ = ctrl_c => {}, _ = term.recv() => {} }
    }
    #[cfg(not(unix))]
    let _ = ctrl_c.await;
    tracing::info!("shutting down");
}
