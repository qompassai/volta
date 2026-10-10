//! crates/volta-server/src/mcp.rs - MCP surface (SPEC 8).
//!
//! Dual licensed under AGPL-3.0-only OR Apache-2.0.
//!
//! Streamable HTTP at `POST /mcp`: JSON-RPC 2.0, initialize
//! handshake, exactly the 13 tools of SPEC 8.2 (alphabetical),
//! tool-level auth enforced per call (MCP-2/8.3), and the three
//! resources of SPEC 8.4. Decapsulation is deliberately NOT a
//! tool (MCP-5).

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Map, Value};
use volta_core::error::VoltaError;
use volta_crypto::policy::policy_json;

use crate::auth::{authenticate_with_body, Caller};
use crate::ephemeral::{issue_key, key_record_json, IssueBody, PublicMaterialBody};
use crate::hkp::lookup_exact;
use crate::http_util::unix_now;
use crate::state::AppState;

/// The MCP protocol version volta negotiates.
pub const PROTOCOL_VERSION: &str = "2025-03-26";

/// One tool definition.
struct Tool {
    auth: &'static str,
    description: &'static str,
    name: &'static str,
    properties: Value,
    required: Vec<&'static str>,
}

fn tool(name: &'static str, auth: &'static str, description: &'static str, properties: Value, required: Vec<&'static str>) -> Tool {
    Tool { auth, description, name, properties, required }
}

/// The 13 tools (SPEC 8.2, alphabetical).
fn tools() -> Vec<Tool> {
    vec![
        tool("volta_ephemeral_issue", "agent", "Issue an ephemeral key (SPEC 7.3 POST)", json!({
            "audience": {"type": "string"}, "custody": {"enum": ["local", "server"], "type": "string"},
            "owner_id": {"type": "string"}, "public_material": {"type": "object"},
            "purpose": {"type": "string"}, "suite": {"type": "string"}, "ttl_seconds": {"type": "integer"}
        }), vec!["purpose", "suite"]),
        tool("volta_ephemeral_revoke", "owner", "Revoke an ephemeral key", json!({
            "key_id": {"type": "string"}
        }), vec!["key_id"]),
        tool("volta_ephemeral_rotate", "owner", "Rotate an ephemeral key", json!({
            "key_id": {"type": "string"}, "public_material": {"type": "object"}
        }), vec!["key_id"]),
        tool("volta_ephemeral_status", "public", "Fetch public material + metadata for an ephemeral key", json!({
            "key_id": {"type": "string"}
        }), vec!["key_id"]),
        tool("volta_key_delete_request", "agent", "Open a deletion/unpublish request for a certificate", json!({
            "fingerprint": {"type": "string"}, "scope": {"enum": ["addresses", "bindings", "total"], "type": "string"}
        }), vec!["fingerprint", "scope"]),
        tool("volta_key_lookup_by_email", "public", "VKS by-email lookup", json!({
            "email": {"type": "string"}
        }), vec!["email"]),
        tool("volta_key_lookup_by_fingerprint", "public", "VKS by-fingerprint lookup", json!({
            "fingerprint": {"type": "string"}
        }), vec!["fingerprint"]),
        tool("volta_key_lookup_by_keyid", "public", "VKS by-keyid lookup", json!({
            "keyid": {"type": "string"}
        }), vec!["keyid"]),
        tool("volta_key_publish", "public", "VKS upload of a certificate", json!({
            "keytext": {"type": "string"}
        }), vec!["keytext"]),
        tool("volta_key_request_verify", "public", "VKS request-verify for uploaded addresses", json!({
            "addresses": {"items": {"type": "string"}, "type": "array"},
            "locale": {"type": "string"}, "token": {"type": "string"}
        }), vec!["addresses", "token"]),
        tool("volta_proxy_chain_check", "operator", "Per-hop probe of a named proxy chain", json!({
            "chain": {"type": "string"}, "target": {"type": "string"}
        }), vec!["chain"]),
        tool("volta_relay_fetch_key", "agent", "Fetch a certificate from a relay peer through the configured chain", json!({
            "fingerprint": {"type": "string"}, "peer": {"type": "string"}
        }), vec!["fingerprint", "peer"]),
        tool("volta_wkd_lookup", "public", "WKD lookup for an email address", json!({
            "email": {"type": "string"}
        }), vec!["email"]),
    ]
}

fn tools_list_json() -> Value {
    let list: Vec<Value> = tools()
        .iter()
        .map(|tool| {
            json!({
                "description": tool.description,
                "inputSchema": {
                    "additionalProperties": false,
                    "properties": tool.properties,
                    "required": tool.required,
                    "type": "object",
                },
                "name": tool.name,
            })
        })
        .collect();
    json!({"tools": list})
}

/// POST /mcp.
pub async fn handle(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if let Some(origin) = headers.get("origin").and_then(|value| value.to_str().ok()) {
        if origin != state.config.origin {
            return rpc_error(None, -32000, VoltaError::Forbidden("origin".to_string()));
        }
    }
    let request: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return rpc_error(None, -32700, VoltaError::Validation("json-rpc body".into())),
    };
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let params = request.get("params").cloned().unwrap_or(Value::Null);
    if method.starts_with("notifications/") {
        return StatusCode::ACCEPTED.into_response();
    }
    let caller = authenticate_with_body(&state, &headers, "POST", "/mcp", &body);
    match method {
        "initialize" => {
            let mut response = Json(json!({
                "id": id,
                "jsonrpc": "2.0",
                "result": {
                    "capabilities": {"resources": {}, "tools": {"listChanged": true}},
                    "protocolVersion": PROTOCOL_VERSION,
                    "serverInfo": {"name": "volta", "version": env!("CARGO_PKG_VERSION")},
                },
            }))
            .into_response();
            if let Ok(session) = axum::http::HeaderValue::from_str(&uuid::Uuid::now_v7().to_string()) {
                response.headers_mut().insert("mcp-session-id", session);
            }
            response
        }
        "ping" => rpc_result(id, json!({})),
        "resources/list" => rpc_result(
            id,
            json!({"resources": [
                {"mimeType": "application/json", "name": "Agent Card", "uri": "volta://agent-card"},
                {"mimeType": "application/json", "name": "Crypto policy", "uri": "volta://crypto-policy"},
                {"mimeType": "application/pgp-keys", "name": "Key by fingerprint", "uri": "volta://keys/<fingerprint>"},
            ]}),
        ),
        "resources/read" => {
            let uri = params.get("uri").and_then(Value::as_str).unwrap_or("");
            match read_resource(&state, uri) {
                Ok((mime, text)) => rpc_result(
                    id,
                    json!({"contents": [{"mimeType": mime, "text": text, "uri": uri}]}),
                ),
                Err(error) => rpc_error(Some(id), -32000, error),
            }
        }
        "tools/call" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
            let outcome = call_tool(&state, &caller, name, &arguments).await;
            match outcome {
                Ok(value) => rpc_result(
                    id,
                    json!({
                        "content": [{"text": value.to_string(), "type": "text"}],
                        "isError": false,
                    }),
                ),
                Err(error) => rpc_result(
                    id,
                    json!({
                        "content": [{"text": json!({"detail": error.to_string(), "error_code": error.code()}).to_string(), "type": "text"}],
                        "isError": true,
                    }),
                ),
            }
        }
        "tools/list" => rpc_result(id, tools_list_json()),
        _ => rpc_error(Some(id), -32601, VoltaError::Validation(format!("method {method}"))),
    }
}

fn rpc_result(id: Value, result: Value) -> Response {
    Json(json!({"id": id, "jsonrpc": "2.0", "result": result})).into_response()
}

fn rpc_error(id: Option<Value>, code: i64, error: VoltaError) -> Response {
    Json(json!({
        "error": {"code": code, "data": {"error_code": error.code()}, "message": error.to_string()},
        "id": id.unwrap_or(Value::Null),
        "jsonrpc": "2.0",
    }))
    .into_response()
}

fn read_resource(state: &AppState, uri: &str) -> Result<(String, String), VoltaError> {
    match uri {
        "volta://agent-card" => {
            let card = crate::a2a::signed_card(state)?;
            Ok(("application/json".to_string(), card.to_string()))
        }
        "volta://crypto-policy" => Ok(("application/json".to_string(), policy_json().to_string())),
        _ => {
            if let Some(fingerprint) = uri.strip_prefix("volta://keys/") {
                let record = lookup_exact(state, fingerprint, false)?;
                return Ok(("application/pgp-keys".to_string(), record.armor));
            }
            Err(VoltaError::NotFound)
        }
    }
}

/// Enforce a tool's auth class (SPEC 8.2) before dispatch.
fn authorize(caller: &Caller, tool: &Tool) -> Result<(), VoltaError> {
    match tool.auth {
        "public" => Ok(()),
        "agent" => match caller {
            Caller::Anonymous => Err(VoltaError::AuthRequired),
            _ => Ok(()),
        },
        "operator" => match caller {
            Caller::Operator { .. } => Ok(()),
            Caller::Anonymous => Err(VoltaError::AuthRequired),
            _ => Err(VoltaError::Forbidden("operator tool".to_string())),
        },
        "owner" => match caller {
            Caller::Anonymous => Err(VoltaError::AuthRequired),
            _ => Ok(()),
        },
        _ => Err(VoltaError::Forbidden("tool auth".to_string())),
    }
}

async fn call_tool(
    state: &AppState,
    caller: &Caller,
    name: &str,
    arguments: &Value,
) -> Result<Value, VoltaError> {
    let tool = tools()
        .into_iter()
        .find(|tool| tool.name == name)
        .ok_or_else(|| VoltaError::Validation(format!("unknown tool {name}")))?;
    authorize(caller, &tool)?;
    match name {
        "volta_ephemeral_issue" => {
            let owner = arguments
                .get("owner_id")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| caller.id());
            if let Caller::Principal { name, .. } = caller {
                if owner != *name {
                    return Err(VoltaError::Forbidden("owner_id must be the caller".into()));
                }
            }
            let body = IssueBody {
                audience: arguments.get("audience").and_then(Value::as_str).map(str::to_string),
                custody: arguments.get("custody").and_then(Value::as_str).map(str::to_string),
                owner_id: owner.clone(),
                public_material: arguments.get("public_material").and_then(|value| {
                    serde_json::from_value::<PublicMaterialBody>(value.clone()).ok()
                }),
                purpose: string_arg(arguments, "purpose")?,
                rotation_interval_seconds: None,
                suite: string_arg(arguments, "suite")?,
                ttl_seconds: arguments.get("ttl_seconds").and_then(Value::as_u64),
            };
            let record = issue_key(state, &owner, &body, None)?;
            Ok(key_record_json(&record, false, true))
        }
        "volta_ephemeral_revoke" => {
            let key_id = string_arg(arguments, "key_id")?;
            let record = state.ephemeral.get_key(&key_id)?.ok_or(VoltaError::KeyNotFound)?;
            require_key_owner(caller, &record.owner_id)?;
            if record.status == "active" || record.status == "superseded" {
                state.ephemeral.set_status(&key_id, "revoked")?;
            }
            Ok(json!({"key_id": key_id, "status": "revoked"}))
        }
        "volta_ephemeral_rotate" => {
            let key_id = string_arg(arguments, "key_id")?;
            let record = state.ephemeral.get_key(&key_id)?.ok_or(VoltaError::KeyNotFound)?;
            require_key_owner(caller, &record.owner_id)?;
            if record.status != "active" {
                return Err(VoltaError::KeyExpired);
            }
            let body = IssueBody {
                audience: record.audience.clone(),
                custody: Some(record.custody.clone()),
                owner_id: record.owner_id.clone(),
                public_material: arguments.get("public_material").and_then(|value| {
                    serde_json::from_value::<PublicMaterialBody>(value.clone()).ok()
                }),
                purpose: record.purpose.clone(),
                rotation_interval_seconds: None,
                suite: record.suite.clone(),
                ttl_seconds: Some(record.expires_unix - record.created_unix),
            };
            let successor = issue_key(state, &record.owner_id, &body, Some(key_id.clone()))?;
            state.ephemeral.set_status(&key_id, "superseded")?;
            Ok(key_record_json(&successor, false, true))
        }
        "volta_ephemeral_status" => {
            let key_id = string_arg(arguments, "key_id")?;
            let record = state.ephemeral.get_key(&key_id)?.ok_or(VoltaError::KeyNotFound)?;
            Ok(key_record_json(&record, false, record.status == "active"))
        }
        "volta_key_delete_request" => {
            let fingerprint = string_arg(arguments, "fingerprint")?;
            let scope = string_arg(arguments, "scope")?;
            let record = lookup_exact(state, &fingerprint, false)?;
            let request_id = format!("del_{}", uuid::Uuid::now_v7());
            let mut tasks = state.tasks.lock().map_err(|_| VoltaError::ConfigInvalid("lock".into()))?;
            tasks.insert(
                request_id.clone(),
                crate::state::TaskRecord {
                    artifacts: vec![],
                    context_id: String::new(),
                    created_unix: unix_now(),
                    history: vec![],
                    id: request_id.clone(),
                    owner: caller.id(),
                    skill: format!("key-delete-request:{scope}"),
                    state: "auth-required".to_string(),
                },
            );
            Ok(json!({
                "fingerprint": record.meta.fingerprint,
                "request_id": request_id,
                "status": "awaiting-operator",
            }))
        }
        "volta_key_lookup_by_email" => {
            let email = string_arg(arguments, "email")?;
            state.rate_check("by-email", &email)?;
            let record = lookup_exact(state, &email, true)?;
            Ok(json!({"armor": record.armor, "fingerprint": record.meta.fingerprint}))
        }
        "volta_key_lookup_by_fingerprint" => {
            let fingerprint = string_arg(arguments, "fingerprint")?;
            let record = lookup_exact(state, &fingerprint, false)?;
            Ok(json!({"armor": record.armor, "fingerprint": record.meta.fingerprint}))
        }
        "volta_key_lookup_by_keyid" => {
            let keyid = string_arg(arguments, "keyid")?;
            let record = lookup_exact(state, &keyid, false)?;
            Ok(json!({"armor": record.armor, "fingerprint": record.meta.fingerprint}))
        }
        "volta_key_publish" => {
            let keytext = string_arg(arguments, "keytext")?;
            let records = crate::hkp::ingest_armor(state, &keytext)?;
            let record = records.into_iter().next().ok_or(VoltaError::KeyNotFound)?;
            let addresses: Vec<String> = record
                .meta
                .user_ids
                .iter()
                .filter_map(|uid| uid.email.clone())
                .collect();
            let token = state.sealer.seal(&volta_core::sealed::TokenPayload {
                addresses,
                created_at: unix_now() as i64,
                fingerprint: record.meta.fingerprint.clone(),
                token_type: "manage".to_string(),
            })?;
            Ok(json!({
                "key_fpr": record.meta.fingerprint,
                "status": "unpublished",
                "token": token,
            }))
        }
        "volta_key_request_verify" => {
            let token = string_arg(arguments, "token")?;
            let addresses: Vec<String> = arguments
                .get("addresses")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let now = unix_now() as i64;
            let payload = state.sealer.unseal_and_check(
                &token,
                Some("manage"),
                now,
                state.config.token_validity_seconds,
            )?;
            let mut status = Map::new();
            let mut store = state.store.lock().map_err(|_| VoltaError::ConfigInvalid("lock".into()))?;
            for address in &addresses {
                if !payload.addresses.iter().any(|a| a == address) {
                    return Err(VoltaError::VerificationAddressMismatch);
                }
                store.set_binding_status(
                    address,
                    &payload.fingerprint,
                    volta_core::model::BindingStatus::Pending,
                    None,
                )?;
                status.insert(address.clone(), json!("pending"));
            }
            Ok(Value::Object(status))
        }
        "volta_proxy_chain_check" => {
            let chain = string_arg(arguments, "chain")?;
            let (host, port) = match arguments.get("target").and_then(Value::as_str) {
                Some(target) => match target.rsplit_once(':') {
                    Some((host, port)) => (host.to_string(), port.parse().unwrap_or(443)),
                    None => (target.to_string(), 443),
                },
                None => ("127.0.0.1".to_string(), 9),
            };
            let (ok, hops) = volta_proxy::check_chain(&state.config.proxy, &chain, &host, port)
                .await?;
            Ok(json!({"hops": hops, "ok": ok}))
        }
        "volta_relay_fetch_key" => {
            if !caller.has_permission("relay-fetch") {
                return Err(VoltaError::Forbidden("relay-fetch permission".to_string()));
            }
            let fingerprint = string_arg(arguments, "fingerprint")?;
            let peer = string_arg(arguments, "peer")?;
            crate::relay::relay_fetch_key(state, &fingerprint, &peer).await
        }
        "volta_wkd_lookup" => {
            let email = string_arg(arguments, "email")?;
            let (local, _domain) = volta_core::wkd::split_email(&email)
                .ok_or_else(|| VoltaError::Validation("email".to_string()))?;
            let hash = volta_core::wkd::wkd_hash(&local);
            let record = {
                let store = state.store.lock().map_err(|_| VoltaError::ConfigInvalid("lock".into()))?;
                store.get_by_wkd_hash(&hash)?
            };
            Ok(json!({
                "fingerprint": record.meta.fingerprint,
                "key_binary_b64": crate::http_util::b64_encode(&record.binary),
            }))
        }
        _ => Err(VoltaError::Validation(format!("unknown tool {name}"))),
    }
}

fn require_key_owner(caller: &Caller, owner_id: &str) -> Result<(), VoltaError> {
    match caller {
        Caller::Operator { .. } => Ok(()),
        Caller::Principal { name, .. } if name == owner_id => Ok(()),
        Caller::Anonymous => Err(VoltaError::AuthRequired),
        _ => Err(VoltaError::Forbidden("not the key owner".to_string())),
    }
}

fn string_arg(arguments: &Value, field: &str) -> Result<String, VoltaError> {
    arguments
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| VoltaError::Validation(field.to_string()))
}
