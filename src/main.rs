//! opslab gateway: carries students' traffic (terminals, web endpoints, IDE)
//! into their instances, after verifying the api's access tokens.

mod app;
mod config;
mod keys;
mod terminal;

use std::sync::Arc;

use anyhow::Context;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use crate::app::AppState;
use crate::config::Config;
use crate::keys::KeyStore;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::from_env()?;
    init_tracing(config.log_json);

    let keys = KeyStore::default();
    tokio::spawn(keys::refresh_forever(
        keys.clone(),
        reqwest::Client::new(),
        config.jwks_url.clone(),
        config.jwks_refresh,
    ));

    let client = kube::Client::try_default()
        .await
        .context("connecting to Kubernetes")?;
    let app = app::router(AppState {
        keys,
        machines: Arc::new(terminal::Kube(client)),
        idle_timeout: config.terminal_idle,
    });
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("binding {}", config.listen))?;
    tracing::info!(address = %config.listen, jwks = %config.jwks_url, "listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn init_tracing(json: bool) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if json {
        builder.json().init();
    } else {
        builder.init();
    }
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("installing the SIGTERM handler");
    tokio::select! {
        _ = ctrl_c => {},
        _ = term.recv() => {},
    }
    tracing::info!("shutting down");
}
