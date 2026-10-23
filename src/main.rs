mod config;
mod http;
mod keygen;

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
    Keygen,
}

#[tokio::main]
async fn main() {
    match Cli::parse().command.unwrap_or(Command::Serve) {
        Command::Keygen => {
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
    let listener = tokio::net::TcpListener::bind(config.addr)
        .await
        .map_err(|e| format!("bind {}: {e}", config.addr))?;
    tracing::info!(addr = %config.addr, origin = %config.relay_origin, database_configured = config.database_url.is_some(), "relay listening");
    axum::serve(listener, http::router())
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
