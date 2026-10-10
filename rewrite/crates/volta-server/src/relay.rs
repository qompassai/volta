//! crates/volta-server/src/relay.rs - relay endpoint + chain use.
//!
//! Dual licensed under AGPL-3.0-only OR Apache-2.0.
//!
//! `POST /relay/v1/connect` is the volta-to-volta hop (SPEC
//! 13.4): token-authenticated, depth-budgeted, upgrading to a
//! raw bidirectional pipe. `relay_fetch_key` is the client side
//! used by MCP/A2A: fetch a certificate from a peer *through the
//! configured chain* — there is no direct-fetch fallback
//! (CHAIN-1).

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use volta_core::config::resolve_secret_ref;
use volta_core::error::VoltaError;

use crate::auth::authenticate;
use crate::http_util::{problem, unix_now};
use crate::state::AppState;

/// Maximum cross-instance chain depth (SPEC 13.4).
pub const CHAIN_DEPTH_MAX: u32 = 16;
/// Maximum bytes read from a peer response.
pub const PEER_RESPONSE_MAX: usize = 2 * 1_048_576;

/// POST /relay/v1/connect — accept a relay hop and pipe raw bytes
/// to the requested next hop.
pub async fn connect(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    mut request: axum::extract::Request,
) -> Response {
    let request_id = crate::ephemeral::new_request_id();
    let expected = match resolve_secret_ref(&state.config.token_secret_ref) {
        Ok(secret) => secret,
        Err(error) => return problem(error, &request_id).into_response(),
    };
    let presented = headers
        .get("x-volta-relay-token")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if presented.as_bytes() != expected.as_slice() {
        return problem(VoltaError::ProxyAuthFailed, &request_id).into_response();
    }
    let depth: u32 = headers
        .get("x-volta-chain-depth")
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.parse().ok())
        .unwrap_or(0);
    if depth > CHAIN_DEPTH_MAX {
        return problem(VoltaError::ProxyChainTooDeep, &request_id).into_response();
    }
    let on_upgrade = hyper::upgrade::on(&mut request);
    let body = match axum::body::to_bytes(request.into_body(), crate::http_util::BODY_MAX).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return problem(VoltaError::Validation("body".into()), &request_id).into_response()
        }
    };
    let parsed: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => {
            return problem(VoltaError::Validation("body".into()), &request_id).into_response()
        }
    };
    let next = parsed.get("next").cloned().unwrap_or(Value::Null);
    let host = next.get("host").and_then(Value::as_str).unwrap_or("").to_string();
    let port = next.get("port").and_then(Value::as_u64).unwrap_or(0) as u16;
    if host.is_empty() || port == 0 {
        return problem(VoltaError::Validation("next".into()), &request_id).into_response();
    }
    let target = match tokio::net::TcpStream::connect((host.as_str(), port)).await {
        Ok(stream) => stream,
        Err(error) => {
            return problem(
                VoltaError::ProxyHopFailed(format!("relay target: {error}")),
                &request_id,
            )
            .into_response()
        }
    };
    tokio::spawn(async move {
        if let Ok(upgraded) = on_upgrade.await {
            let mut upgraded = hyper_util::rt::TokioIo::new(upgraded);
            let mut target = target;
            let _ = tokio::io::copy_bidirectional(&mut upgraded, &mut target).await;
        }
    });
    let mut response = Response::new(axum::body::Body::empty());
    *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
    response
        .headers_mut()
        .insert("connection", "Upgrade".parse().unwrap_or(axum::http::HeaderValue::from_static("Upgrade")));
    response
        .headers_mut()
        .insert("upgrade", axum::http::HeaderValue::from_static("volta-relay/1"));
    response
}

/// GET /api/v1/proxy-chains/<name>/check — per-hop probe of a
/// named chain (SPEC 13.5). Operator session required. Failures
/// are data, never a fallback.
pub async fn chain_check(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(params): Query<BTreeMap<String, String>>,
) -> Response {
    let request_id = crate::ephemeral::new_request_id();
    let caller = authenticate(&state, &headers);
    if !matches!(caller, crate::auth::Caller::Operator { .. }) {
        return problem(VoltaError::AuthRequired, &request_id).into_response();
    }
    let (target_host, target_port) = match params.get("target") {
        Some(target) => match target.rsplit_once(':') {
            Some((host, port)) => (host.to_string(), port.parse().unwrap_or(443)),
            None => (target.clone(), 443),
        },
        None => base_target(&state.config.base_uri),
    };
    let config = state.config.proxy.clone();
    match volta_proxy::check_chain(&config, &name, &target_host, target_port).await {
        Ok((ok, hops)) => Json(json!({
            "chain": name,
            "hops": hops,
            "ok": ok,
        }))
        .into_response(),
        Err(error) => problem(error, &request_id).into_response(),
    }
}

fn base_target(base_uri: &str) -> (String, u16) {
    match url::Url::parse(base_uri) {
        Ok(url) => (
            url.host_str().unwrap_or("127.0.0.1").to_string(),
            url.port_or_known_default().unwrap_or(443),
        ),
        Err(_) => ("127.0.0.1".to_string(), 443),
    }
}

/// Fetch a certificate from a configured relay peer through the
/// chain routed for `relay-fetch` (SPEC 8.2/9.3). The peer's
/// response fingerprint must match the request and the peer is
/// pinned by configuration; any chain failure is the operation's
/// failure (CHAIN-1, no direct fallback).
///
/// # Errors
/// `E_RELAY_PEER_MISMATCH`, proxy errors, or `E_KEY_NOT_FOUND`.
pub async fn relay_fetch_key(
    state: &AppState,
    fingerprint: &str,
    peer_name: &str,
) -> Result<Value, VoltaError> {
    let peer = state
        .config
        .relay_peers
        .iter()
        .find(|peer| peer.name == peer_name)
        .ok_or_else(|| VoltaError::Validation(format!("unknown peer {peer_name}")))?;
    let url = url::Url::parse(&peer.base_uri)
        .map_err(|_| VoltaError::ConfigInvalid("peer base_uri".to_string()))?;
    let host = url.host_str().unwrap_or("").to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    let dialed = volta_proxy::dial(&state.config.proxy, "relay-fetch", &host, port).await?;
    let mut stream = dialed.stream;
    let request = format!(
        "GET /vks/v1/by-fingerprint/{fingerprint} HTTP/1.1\r\nHost: {host}:{port}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error| VoltaError::ProxyHopFailed(error.to_string()))?;
    let mut raw = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = stream
            .read(&mut buffer)
            .await
            .map_err(|error| VoltaError::ProxyHopFailed(error.to_string()))?;
        if read == 0 {
            break;
        }
        raw.extend_from_slice(&buffer[..read]);
        if raw.len() > PEER_RESPONSE_MAX {
            return Err(VoltaError::UploadTooLarge);
        }
    }
    let text = String::from_utf8_lossy(&raw);
    let status: u32 = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("");
    // De-chunk a chunked body minimally (single-transfer peers).
    let body = dechunk(body);
    if status == 404 {
        return Err(VoltaError::KeyNotFound);
    }
    if status != 200 {
        return Err(VoltaError::ProxyHopFailed(format!("peer status {status}")));
    }
    let parsed: Value = serde_json::from_str(&body)
        .map_err(|_| VoltaError::RelayPeerMismatch)?;
    let served_fingerprint = parsed
        .get("fingerprint")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if served_fingerprint.to_uppercase() != fingerprint.to_uppercase() {
        return Err(VoltaError::RelayPeerMismatch);
    }
    let via_chain = match state.config.proxy.route_for("relay-fetch") {
        volta_core::config::RouteDecision::Chain(name) => name,
        volta_core::config::RouteDecision::Direct => "direct".to_string(),
        volta_core::config::RouteDecision::Deny => "deny".to_string(),
    };
    Ok(json!({
        "armor": parsed.get("armor").cloned().unwrap_or(Value::Null),
        "fingerprint": served_fingerprint,
        "via_chain": via_chain,
    }))
}

fn dechunk(body: &str) -> String {
    let trimmed = body.trim_start();
    if !trimmed
        .chars()
        .take_while(|c| *c != '\r')
        .all(|c| c.is_ascii_hexdigit())
    {
        return body.to_string();
    }
    let mut out = String::new();
    let mut rest = trimmed;
    loop {
        let Some((size_line, tail)) = rest.split_once("\r\n") else {
            break;
        };
        let Ok(size) = usize::from_str_radix(size_line.trim(), 16) else {
            break;
        };
        if size == 0 || tail.len() < size {
            break;
        }
        out.push_str(&tail[..size]);
        rest = &tail[size..];
        rest = rest.strip_prefix("\r\n").unwrap_or(rest);
    }
    if out.is_empty() {
        body.to_string()
    } else {
        out
    }
}

/// Current time helper re-export for handlers in this module.
#[must_use]
pub fn now() -> u64 {
    unix_now()
}
