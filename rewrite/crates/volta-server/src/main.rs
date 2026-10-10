//! crates/volta-server/src/main.rs - volta-server entry point.
//!
//! Dual licensed under AGPL-3.0-only OR Apache-2.0.
//!
//! Usage: `volta-server --config <path>` (or `$VOLTA_CONFIG`).
//! Configuration validation (including proxy chains, CHAIN-0)
//! runs at load: a misconfigured server refuses to start, it
//! does not start degraded.

#![forbid(unsafe_code)]

use std::sync::Arc;

use volta_core::config::ServerConfig;
use volta_server::app::router;
use volta_server::state::AppState;

#[tokio::main]
async fn main() {
    let config_path = std::env::args()
        .skip(1)
        .collect::<Vec<String>>()
        .windows(2)
        .find(|pair| pair[0] == "--config")
        .map(|pair| pair[1].clone())
        .or_else(|| std::env::var("VOLTA_CONFIG").ok())
        .unwrap_or_else(|| "volta.toml".to_string());
    let config = match ServerConfig::load(std::path::Path::new(&config_path)) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("volta-server: {error} (code {})", error.code());
            std::process::exit(2);
        }
    };
    let bind = config.bind.clone();
    let state = match AppState::new(config) {
        Ok(state) => Arc::new(state),
        Err(error) => {
            eprintln!("volta-server: {error} (code {})", error.code());
            std::process::exit(2);
        }
    };
    if !state.operator.any_credentials() {
        eprintln!(
            "volta-server: no operator credentials registered; bootstrap token: {}",
            state.bootstrap_token
        );
    }
    let listener = match tokio::net::TcpListener::bind(&bind).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("volta-server: bind {bind}: {error}");
            std::process::exit(2);
        }
    };
    eprintln!("volta-server: listening on {bind}");
    if let Err(error) = axum::serve(listener, router(state)).await {
        eprintln!("volta-server: serve: {error}");
        std::process::exit(1);
    }
}
