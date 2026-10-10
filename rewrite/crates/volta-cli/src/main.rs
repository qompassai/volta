//! crates/volta-cli/src/main.rs - voltactl, the operator CLI.
//!
//! Dual licensed under AGPL-3.0-only OR Apache-2.0.
//!
//! SPEC 15.1. Help and version never touch configuration (CLI-1);
//! a run that needs missing configuration exits 2 with one
//! structured stderr line (CLI-2); nothing panics.

#![forbid(unsafe_code)]

mod delete;

use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use clap::{Parser, Subcommand};
use serde_json::{Map, Value, json};
use volta_core::config::ServerConfig;
use volta_core::error::VoltaError;
use volta_core::store::Store;
use volta_server::state::AppState;

/// voltactl: operate a volta instance.
#[derive(Parser)]
#[command(name = "voltactl", version, about)]
struct Cli {
    /// Configuration file.
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,
    /// Environment name (informational).
    #[arg(short, long, global = true)]
    env: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Read the audit log.
    Audit {
        /// Only entries for this operator/principal.
        #[arg(long)]
        operator: Option<String>,
        /// Only entries at or after this unix timestamp.
        #[arg(long)]
        since: Option<u64>,
        /// Verify the hash chain and report the first break.
        #[arg(long)]
        verify_chain: bool,
    },
    /// Delete a binding or a certificate (SPEC 15.2).
    Delete {
        /// Delete all bindings AND the key.
        #[arg(long)]
        all: bool,
        /// Delete all bindings for the queried key.
        #[arg(long)]
        all_bindings: bool,
        /// Email address, fingerprint, or KeyID.
        query: String,
    },
    /// Bulk import of keyring files.
    Import {
        /// Parse and report only; store nothing.
        #[arg(short = 'n', long)]
        dry_run: bool,
        /// Keyring files (armored certificates).
        files: Vec<PathBuf>,
    },
    /// MCP server over stdio (SPEC 8.1, MCP-3).
    Mcp {
        /// Run with operator rights, given a live session token
        /// file (without it, the stdio principal is read-only).
        #[arg(long)]
        operator: Option<PathBuf>,
        /// Use the stdio transport (the only one voltactl serves).
        #[arg(long)]
        stdio: bool,
    },
    /// Operator (WebAuthn) administration.
    Operator {
        #[command(subcommand)]
        action: OperatorAction,
    },
    /// Rebuild + verify derived indexes from stored certificates.
    Regenerate,
    /// Drive relay synchronization manually.
    RelaySync {
        /// Show the change-feed diff; change nothing locally.
        #[arg(long)]
        dry_run: bool,
        /// The configured peer name.
        #[arg(long)]
        peer: String,
    },
    /// Print store statistics.
    Stats,
}

#[derive(Subcommand)]
enum OperatorAction {
    /// Print a one-time first-operator bootstrap token.
    Bootstrap,
    /// List registered operator credentials.
    List,
    /// Break-glass recovery (SPEC 10.5): wipe all operator
    /// credentials so enrollment can start over. Local-host
    /// only, destructive, audited on stderr.
    Recover {
        /// Confirm the destructive reset.
        #[arg(long)]
        yes: bool,
    },
    /// Lock a credential by id (revocation).
    RevokeCredential {
        /// The credential id (base64url).
        credential_id: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let code = run(cli);
    std::process::exit(code);
}

fn run(cli: Cli) -> i32 {
    let Some(command) = cli.command else {
        // No subcommand: print help, exit 0 (CLI-1 spirit; the
        // predecessor panicked here, C-8).
        let mut cmd = <Cli as clap::CommandFactory>::command();
        let _ = cmd.write_long_help(&mut std::io::stdout());
        return 0;
    };
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let outcome = runtime.block_on(dispatch(&cli.config, command));
    match outcome {
        Ok(value) => {
            println!("{value}");
            0
        }
        Err(error) => {
            eprintln!(
                "{}",
                json!({"code": error.code(), "detail": error.to_string()})
            );
            2
        }
    }
}

async fn dispatch(config_arg: &Option<PathBuf>, command: Command) -> Result<Value, VoltaError> {
    match command {
        Command::Audit {
            operator,
            since,
            verify_chain,
        } => {
            let config = load_config(config_arg)?;
            audit(&config, operator, since, verify_chain)
        }
        Command::Delete {
            all,
            all_bindings,
            query,
        } => {
            let config = load_config(config_arg)?;
            let mut store = Store::open(&config.data_dir)?;
            delete::delete(&mut store, &query, all, all_bindings)
        }
        Command::Import { dry_run, files } => {
            let config = load_config(config_arg)?;
            import(&config, &files, dry_run)
        }
        Command::Mcp { operator, stdio } => {
            if !stdio {
                return Err(VoltaError::Validation(
                    "voltactl mcp requires --stdio".to_string(),
                ));
            }
            let config = load_config(config_arg)?;
            mcp_stdio(config, operator).await
        }
        Command::Operator { action } => {
            let config = load_config(config_arg)?;
            operator(config, action)
        }
        Command::Regenerate => {
            let config = load_config(config_arg)?;
            regenerate(&config)
        }
        Command::RelaySync { dry_run, peer } => {
            let config = load_config(config_arg)?;
            relay_sync(&config, &peer, dry_run).await
        }
        Command::Stats => {
            let config = load_config(config_arg)?;
            let store = Store::open(&config.data_dir)?;
            let stats = store.stats();
            Ok(json!({
                "certificates": stats.certificates,
                "published_addresses": stats.published_addresses,
                "revoked_certificates": stats.revoked_certificates,
            }))
        }
    }
}

/// Resolve and load the configuration (CLI-2 on absence).
fn load_config(config_arg: &Option<PathBuf>) -> Result<ServerConfig, VoltaError> {
    let candidates: Vec<PathBuf> = match config_arg {
        Some(path) => vec![path.clone()],
        None => {
            let mut list = vec![PathBuf::from("volta.toml")];
            if let Ok(env_path) = std::env::var("VOLTA_CONFIG") {
                list.insert(0, PathBuf::from(env_path));
            }
            if let Some(home) = std::env::var_os("HOME") {
                list.push(PathBuf::from(home).join(".config/volta/volta.toml"));
            }
            list
        }
    };
    for candidate in &candidates {
        if candidate.exists() {
            return ServerConfig::load(candidate);
        }
    }
    Err(VoltaError::ConfigInvalid(format!(
        "no config file found (tried {})",
        candidates
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<String>>()
            .join(", ")
    )))
}

/// Read `<data_dir>/audit.jsonl` (SPEC 12.6 format: hash-chained
/// JSON lines). The writer side lives in the server's audit
/// module; this reader verifies the chain independently.
fn audit(
    config: &ServerConfig,
    operator: Option<String>,
    since: Option<u64>,
    verify_chain: bool,
) -> Result<Value, VoltaError> {
    let path = config.data_dir.join("audit.jsonl");
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let mut entries: Vec<Value> = Vec::new();
    let mut previous_hash = String::new();
    let mut chain_ok = true;
    let mut broken_at: Option<u64> = None;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let entry: Value = serde_json::from_str(line)
            .map_err(|_| VoltaError::Validation("audit line".to_string()))?;
        if verify_chain {
            let stated = entry.get("hash").and_then(Value::as_str).unwrap_or("");
            let mut material = entry.clone();
            if let Value::Object(map) = &mut material {
                map.remove("hash");
            }
            let computed = volta_server::http_util::sha256_hex(
                format!("{previous_hash}{material}").as_bytes(),
            );
            if computed != stated {
                chain_ok = false;
                if broken_at.is_none() {
                    broken_at = entry.get("seq").and_then(Value::as_u64);
                }
            }
            previous_hash = stated.to_string();
        }
        if let Some(operator) = &operator {
            if entry.get("actor").and_then(Value::as_str) != Some(operator.as_str()) {
                continue;
            }
        }
        if let Some(since) = since {
            if entry.get("at").and_then(Value::as_u64).unwrap_or(0) < since {
                continue;
            }
        }
        entries.push(entry);
    }
    let mut out = Map::new();
    out.insert("entries".to_string(), Value::Array(entries));
    if verify_chain {
        out.insert("chain_ok".to_string(), json!(chain_ok));
        out.insert("broken_at".to_string(), json!(broken_at));
    }
    Ok(Value::Object(out))
}

/// Bulk import through the core ingest pipeline (SPEC 12.4).
fn import(config: &ServerConfig, files: &[PathBuf], dry_run: bool) -> Result<Value, VoltaError> {
    let mut store = if dry_run {
        None
    } else {
        Some(Store::open(&config.data_dir)?)
    };
    let mut reports = Vec::new();
    let mut total = 0usize;
    for file in files {
        let text = std::fs::read_to_string(file)
            .map_err(|error| VoltaError::Validation(format!("{}: {error}", file.display())))?;
        let blocks = volta_server::hkp::armor_blocks(&text);
        let mut fingerprints = Vec::new();
        for block in &blocks {
            let parsed = volta_core::pgp_key::parse_and_check(block.as_bytes())?;
            fingerprints.push(parsed.meta.fingerprint.clone());
            if let Some(store) = store.as_mut() {
                let cleaned = volta_core::pgp_key::clean_served_form(
                    &parsed.signed_key,
                    &std::collections::BTreeSet::new(),
                );
                let binary = volta_core::pgp_key::to_binary(&cleaned)?;
                let armor = volta_core::pgp_key::to_armor(&cleaned)?;
                store.put_certificate(
                    parsed.meta.clone(),
                    &binary,
                    &armor,
                    volta_server::http_util::unix_now() as i64,
                )?;
            }
            total += 1;
        }
        reports.push(json!({
            "certificates": fingerprints.len(),
            "file": file.display().to_string(),
            "fingerprints": fingerprints,
        }));
    }
    Ok(json!({"dry_run": dry_run, "files": reports, "imported": total}))
}

/// The stdio MCP transport (SPEC 8.1): newline-delimited JSON-RPC
/// over stdin/stdout, sharing dispatch with the HTTP transport.
async fn mcp_stdio(config: ServerConfig, operator: Option<PathBuf>) -> Result<Value, VoltaError> {
    let state = Arc::new(AppState::new(config)?);
    let caller = match &operator {
        Some(session_file) => {
            let token = std::fs::read_to_string(session_file)
                .map_err(|error| VoltaError::Validation(error.to_string()))?;
            match state.operator.session_operator(token.trim()) {
                Some(operator_id) => volta_server::auth::Caller::Operator { operator_id },
                None => {
                    return Err(VoltaError::AuthRequired);
                }
            }
        }
        None => volta_server::auth::Caller::Anonymous,
    };
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();
    while let Some(line) = lines
        .next_line()
        .await
        .map_err(|e| VoltaError::Validation(e.to_string()))?
    {
        if line.trim().is_empty() {
            continue;
        }
        let request: Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let method = request.get("method").and_then(Value::as_str).unwrap_or("");
        if method.starts_with("notifications/") {
            continue;
        }
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let params = request.get("params").cloned().unwrap_or(json!({}));
        let response = match method {
            "initialize" => json!({
                "id": id, "jsonrpc": "2.0",
                "result": {
                    "capabilities": {"resources": {}, "tools": {"listChanged": true}},
                    "protocolVersion": volta_server::mcp::PROTOCOL_VERSION,
                    "serverInfo": {"name": "volta", "version": env!("CARGO_PKG_VERSION")},
                },
            }),
            "ping" => json!({"id": id, "jsonrpc": "2.0", "result": {}}),
            "tools/call" => {
                let name = params.get("name").and_then(Value::as_str).unwrap_or("");
                let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
                match volta_server::mcp::dispatch_tool(&state, &caller, name, &arguments).await {
                    Ok(value) => json!({
                        "id": id, "jsonrpc": "2.0",
                        "result": {"content": [{"text": value.to_string(), "type": "text"}], "isError": false},
                    }),
                    Err(error) => json!({
                        "id": id, "jsonrpc": "2.0",
                        "result": {"content": [{"text": json!({"detail": error.to_string(), "error_code": error.code()}).to_string(), "type": "text"}], "isError": true},
                    }),
                }
            }
            "tools/list" => json!({
                "id": id, "jsonrpc": "2.0",
                "result": volta_server::mcp::tools_list_json_pub(),
            }),
            _ => json!({
                "error": {"code": -32601, "message": format!("method {method}")},
                "id": id, "jsonrpc": "2.0",
            }),
        };
        let mut out = response.to_string();
        out.push('\n');
        stdout
            .write_all(out.as_bytes())
            .await
            .map_err(|e| VoltaError::Validation(e.to_string()))?;
        stdout
            .flush()
            .await
            .map_err(|e| VoltaError::Validation(e.to_string()))?;
    }
    Ok(json!({"mcp": "stdio session ended"}))
}

/// Operator administration against the local operator store.
fn operator(config: ServerConfig, action: OperatorAction) -> Result<Value, VoltaError> {
    let store = volta_server::webauthn::OperatorStore::open(&config.data_dir, &config)?;
    match action {
        OperatorAction::Bootstrap => {
            if store.any_credentials() {
                return Err(VoltaError::Forbidden(
                    "operator credentials already enrolled".to_string(),
                ));
            }
            if store.has_bootstrap() {
                return Err(VoltaError::Forbidden(
                    "a bootstrap token is already outstanding".to_string(),
                ));
            }
            let mut bytes = [0u8; 24];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
            let token = B64.encode(bytes);
            let token = token.replace('+', "-").replace('/', "_").replace('=', "");
            store.set_bootstrap_hash(&volta_server::http_util::sha256_hex(token.as_bytes()))?;
            Ok(json!({
                "bootstrap_token": token,
                "note": "one-time: present as X-Volta-Bootstrap to POST /api/v1/operator/webauthn/register/options",
            }))
        }
        OperatorAction::List => {
            let db = config.data_dir.join("operator.db");
            let conn = rusqlite::Connection::open(db)
                .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
            let mut stmt = conn
                .prepare("SELECT cred_id, operator_id, nickname, locked FROM wa_credentials ORDER BY operator_id, cred_id")
                .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok(json!({
                        "credential_id": row.get::<_, String>(0)?,
                        "locked": row.get::<_, i64>(3)? != 0,
                        "nickname": row.get::<_, String>(2)?,
                        "operator_id": row.get::<_, String>(1)?,
                    }))
                })
                .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?);
            }
            Ok(json!({"credentials": out}))
        }
        OperatorAction::Recover { yes } => {
            if !yes {
                return Err(VoltaError::Validation(
                    "recover wipes ALL operator credentials; re-run with --yes".to_string(),
                ));
            }
            let db = config.data_dir.join("operator.db");
            let conn = rusqlite::Connection::open(db)
                .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
            let wiped = conn
                .execute("DELETE FROM wa_credentials", [])
                .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
            store.clear_bootstrap()?;
            eprintln!("voltactl: BREAK-GLASS recover wiped {wiped} operator credential(s)");
            Ok(json!({
                "credentials_wiped": wiped,
                "next": "run `voltactl operator bootstrap` and re-enroll a passkey",
            }))
        }
        OperatorAction::RevokeCredential { credential_id } => {
            store.lock_credential(&credential_id)?;
            Ok(json!({"credential_id": credential_id, "locked": true}))
        }
    }
}

/// Rebuild derived indexes from the stored certificates and
/// verify blob integrity (SCALE-2's new meaning of `regenerate`).
fn regenerate(config: &ServerConfig) -> Result<Value, VoltaError> {
    let db = config.data_dir.join("index.sqlite3");
    let fingerprints: Vec<String> = {
        let conn = rusqlite::Connection::open(&db)
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        let mut stmt = conn
            .prepare("SELECT fingerprint FROM certificates ORDER BY fingerprint")
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?);
        }
        out
    };
    let mut store = Store::open(&config.data_dir)?;
    let mut reindexed = 0usize;
    let mut corrupt = 0usize;
    for fingerprint in &fingerprints {
        let record = store.get_by_fingerprint(fingerprint)?;
        let blob_path = config.data_dir.join("blobs").join(&record.content_sha256);
        match std::fs::read(&blob_path) {
            Ok(bytes) if Store::content_address(&bytes) == record.content_sha256 => {}
            _ => {
                corrupt += 1;
                continue;
            }
        }
        store.put_certificate(
            record.meta.clone(),
            &record.binary,
            &record.armor,
            volta_server::http_util::unix_now() as i64,
        )?;
        reindexed += 1;
    }
    Ok(json!({
        "certificates": fingerprints.len(),
        "mismatches_fixed": reindexed,
        "mismatches_remaining": corrupt,
        "reindexed": reindexed,
    }))
}

/// Manual relay sync (SPEC 12.4): fetch the peer's root and
/// change feed through the configured chain (never direct unless
/// the routing table says so in words, CHAIN-2).
async fn relay_sync(
    config: &ServerConfig,
    peer_name: &str,
    dry_run: bool,
) -> Result<Value, VoltaError> {
    let peer = config
        .relay_peers
        .iter()
        .find(|peer| peer.name == peer_name)
        .ok_or_else(|| VoltaError::Validation(format!("unknown peer {peer_name}")))?;
    let url = url::Url::parse(&peer.base_uri)
        .map_err(|_| VoltaError::ConfigInvalid("peer base_uri".to_string()))?;
    let host = url.host_str().unwrap_or("").to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    let fetch = |path: String| {
        let proxy = config.proxy.clone();
        let host = host.clone();
        async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let dialed = volta_proxy::dial(&proxy, "relay-sync", &host, port).await?;
            let mut stream = dialed.stream;
            let request = format!(
                "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
            );
            stream
                .write_all(request.as_bytes())
                .await
                .map_err(|e| VoltaError::ProxyHopFailed(e.to_string()))?;
            let mut raw = Vec::new();
            let mut buffer = [0u8; 8192];
            loop {
                let read = stream
                    .read(&mut buffer)
                    .await
                    .map_err(|e| VoltaError::ProxyHopFailed(e.to_string()))?;
                if read == 0 {
                    break;
                }
                raw.extend_from_slice(&buffer[..read]);
                if raw.len() > 2 * 1_048_576 {
                    return Err(VoltaError::UploadTooLarge);
                }
            }
            let text = String::from_utf8_lossy(&raw).to_string();
            let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
            serde_json::from_str::<Value>(&body).map_err(|_| VoltaError::RelayPeerMismatch)
        }
    };
    let root = fetch("/relay/v1/root".to_string()).await?;
    let changes = fetch("/relay/v1/changes?since=0".to_string()).await?;
    Ok(json!({
        "changes": changes,
        "dry_run": dry_run,
        "note": if dry_run { "diff shown; nothing applied" } else { "feed fetched; application of remote certificates is operator-reviewed (no silent merge)" },
        "peer": peer_name,
        "root": root,
    }))
}
