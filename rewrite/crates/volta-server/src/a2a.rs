//! crates/volta-server/src/a2a.rs - A2A surface (SPEC 9).
//!
//! Dual licensed under AGPL-3.0-only OR Apache-2.0.
//!
//! A signed Agent Card (mandatory: A2A-1) and the JSON-RPC task
//! endpoint. Card signatures are JWS objects over the RFC 8785
//! (JCS) canonicalization of the card without `signatures`.
//! Tasks are ownership-scoped: another principal's task id is a
//! 404, never an existence oracle (SPEC 9.4).

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};
use volta_core::error::VoltaError;
use volta_core::sealed::TokenPayload;
use volta_crypto::signing::IdentitySuite;

use crate::auth::{Caller, authenticate_with_body};
use crate::ephemeral::{IssueBody, PublicMaterialBody, issue_key, key_record_json};
use crate::hkp::lookup_exact;
use crate::http_util::{b64u_encode, problem, unix_now};
use crate::jcs::canonicalize;
use crate::state::{AppState, TaskRecord};

/// Build the unsigned card (SPEC 9.1), keys alphabetical.
#[must_use]
pub fn unsigned_card(state: &AppState) -> Value {
    let base = state.config.base_uri.trim_end_matches('/');
    json!({
        "capabilities": {"pushNotifications": false, "stateTransitionHistory": true, "streaming": true},
        "defaultInputModes": ["application/json", "text/plain"],
        "defaultOutputModes": ["application/json", "text/plain"],
        "description": "OpenPGP key server for humans and agents: verified key publication, ephemeral hybrid-PQC session keys, chained-proxy relay.",
        "name": "volta",
        "provider": {"organization": "Qompass AI", "url": base},
        "securitySchemes": {
            "agentSignature": {"in": "header", "name": "X-Volta-Agent-Signature", "type": "apiKey"},
            "ephemeralSession": {"scheme": "bearer", "type": "http"},
        },
        "skills": [
            {"description": "Issue, fetch, rotate, revoke hard-TTL hybrid-PQC ephemeral keys (SPEC 7).", "id": "ephemeral-key-exchange", "inputModes": ["application/json"], "name": "Ephemeral key exchange", "outputModes": ["application/json"], "tags": ["ephemeral", "ml-kem", "pqc"]},
            {"description": "Exact lookup by email, fingerprint, or long KeyID under the publication rules (SPEC 6).", "id": "key-lookup", "inputModes": ["application/json", "text/plain"], "name": "Key lookup", "outputModes": ["application/json", "text/plain"], "tags": ["hkp", "openpgp", "vks", "wkd"]},
            {"description": "Upload a certificate and run email verification (SPEC 6.2).", "id": "key-publication", "inputModes": ["application/json"], "name": "Key publication", "outputModes": ["application/json"], "tags": ["openpgp", "publication", "verification"]},
            {"description": "Fetch certificates from peer volta instances through configured proxy chains (SPEC 13).", "id": "relay-fetch", "inputModes": ["application/json"], "name": "Relay fetch", "outputModes": ["application/json"], "tags": ["proxy-chain", "relay"]},
        ],
        "supportedInterfaces": [
            {"protocolBinding": "JSONRPC", "protocolVersion": "1.0", "url": format!("{base}/a2a/v1")},
            {"protocolBinding": "HTTP+JSON", "protocolVersion": "1.0", "url": format!("{base}/a2a/v1")},
        ],
        "url": format!("{base}/a2a/v1"),
        "version": env!("CARGO_PKG_VERSION"),
    })
}

/// The signed card: unsigned card + `signatures[]` (A2A-2). With
/// a volta-native identity the single signature uses the
/// `VOLTA-MLDSA87-ED25519` profile; a plain Ed25519 identity
/// emits the `EdDSA` interop profile.
///
/// # Errors
/// `E_CARD_UNSIGNED` when no identity is configured (A2A-1).
pub fn signed_card(state: &AppState) -> Result<Value, VoltaError> {
    let signer = state.identity.as_ref().ok_or(VoltaError::CardUnsigned)?;
    let kid = state
        .identity_fingerprint
        .clone()
        .ok_or(VoltaError::CardUnsigned)?;
    let mut card = unsigned_card(state);
    let canonical = canonicalize(&card);
    let payload_b64 = b64u_encode(canonical.as_bytes());
    let alg = match signer.suite() {
        IdentitySuite::EddsaEd25519 => "EdDSA",
        IdentitySuite::VoltaMlDsa87Ed25519 => "VOLTA-MLDSA87-ED25519",
    };
    let protected = json!({"alg": alg, "kid": kid, "typ": "agent-card+jws"});
    let protected_b64 = b64u_encode(protected.to_string().as_bytes());
    let signing_input = format!("{protected_b64}.{payload_b64}");
    let signature = signer.sign(signing_input.as_bytes());
    if let Value::Object(map) = &mut card {
        map.insert(
            "signatures".to_string(),
            json!([{"protected": protected_b64, "signature": b64u_encode(&signature)}]),
        );
    }
    Ok(card)
}

/// GET /.well-known/agent-card.json.
pub async fn agent_card(State(state): State<Arc<AppState>>) -> Response {
    let request_id = crate::ephemeral::new_request_id();
    match signed_card(&state) {
        Ok(card) => {
            let mut response = Json(card).into_response();
            response.headers_mut().insert(
                "cache-control",
                axum::http::HeaderValue::from_static("public, max-age=300"),
            );
            response
        }
        Err(error) => problem(error, &request_id).into_response(),
    }
}

/// POST /a2a/v1 — the JSON-RPC task endpoint.
pub async fn rpc(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let request: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => {
            return rpc_error(
                Value::Null,
                -32700,
                VoltaError::Validation("json-rpc body".into()),
            );
        }
    };
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let params = request.get("params").cloned().unwrap_or(json!({}));
    let caller = authenticate_with_body(&state, &headers, "POST", "/a2a/v1", &body);
    match method {
        "message/send" => match send_message(&state, &caller, &params).await {
            Ok(task) => rpc_result(id, task_json(&task)),
            Err(error) => rpc_error(id, -32000, error),
        },
        "message/stream" => match send_message(&state, &caller, &params).await {
            Ok(task) => {
                let working = json!({"id": id, "jsonrpc": "2.0", "result": task_json_with_state(&task, "working")});
                let final_event = json!({"id": id, "jsonrpc": "2.0", "result": task_json(&task)});
                let body = format!("data: {working}\n\ndata: {final_event}\n\n");
                (
                    StatusCode::OK,
                    [("content-type", "text/event-stream")],
                    body,
                )
                    .into_response()
            }
            Err(error) => rpc_error(id, -32000, error),
        },
        "tasks/cancel" => match task_action(&state, &caller, &params, "cancel") {
            Ok(task) => rpc_result(id, task_json(&task)),
            Err(error) => rpc_error(id, -32000, error),
        },
        "tasks/get" | "tasks/resubscribe" => match task_action(&state, &caller, &params, "get") {
            Ok(task) => rpc_result(id, task_json(&task)),
            Err(error) => rpc_error(id, -32000, error),
        },
        "tasks/list" => {
            let tasks = state.tasks.lock().map(|map| {
                map.values()
                    .filter(|task| {
                        task.owner == caller.id() || matches!(caller, Caller::Operator { .. })
                    })
                    .map(task_json)
                    .collect::<Vec<Value>>()
            });
            match tasks {
                Ok(tasks) => rpc_result(id, json!({"tasks": tasks})),
                Err(_) => rpc_error(id, -32000, VoltaError::ConfigInvalid("lock".into())),
            }
        }
        _ => rpc_error(
            id,
            -32601,
            VoltaError::Validation(format!("method {method}")),
        ),
    }
}

fn rpc_result(id: Value, result: Value) -> Response {
    Json(json!({"id": id, "jsonrpc": "2.0", "result": result})).into_response()
}

fn rpc_error(id: Value, code: i64, error: VoltaError) -> Response {
    Json(json!({
        "error": {"code": code, "data": {"error_code": error.code()}, "message": error.to_string()},
        "id": id,
        "jsonrpc": "2.0",
    }))
    .into_response()
}

/// Execute a message/send: dispatch on the skill, record the
/// task, and return it.
async fn send_message(
    state: &AppState,
    caller: &Caller,
    params: &Value,
) -> Result<TaskRecord, VoltaError> {
    let message = params.get("message").cloned().unwrap_or(json!({}));
    let metadata = params.get("metadata").cloned().unwrap_or(json!({}));
    let skill = metadata
        .get("volta.skill")
        .and_then(Value::as_str)
        .or_else(|| {
            message
                .get("metadata")
                .and_then(|m| m.get("volta.skill"))
                .and_then(Value::as_str)
        })
        .unwrap_or("")
        .to_string();
    let context_id = params
        .get("contextId")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let parts = message
        .get("parts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let data = parts
        .iter()
        .find(|part| part.get("kind").and_then(Value::as_str) == Some("data"))
        .and_then(|part| part.get("data").cloned())
        .unwrap_or(json!({}));
    let task_id = format!("tsk_{}", uuid::Uuid::now_v7());
    let mut task = TaskRecord {
        artifacts: vec![],
        context_id,
        created_unix: unix_now(),
        history: vec![
            json!({"state": "submitted", "timestamp": crate::http_util::rfc3339(unix_now())}),
        ],
        id: task_id,
        owner: caller.id(),
        skill: skill.clone(),
        state: "working".to_string(),
    };
    let outcome = run_skill(state, caller, &skill, &parts, &data, &mut task).await;
    match outcome {
        Ok(artifact) => {
            task.artifacts.push(artifact);
            task.state = "completed".to_string();
        }
        Err(error) => {
            task.state = "failed".to_string();
            task.history.push(json!({
                "error_code": error.code(),
                "state": "failed",
                "timestamp": crate::http_util::rfc3339(unix_now()),
            }));
        }
    }
    let mut tasks = state
        .tasks
        .lock()
        .map_err(|_| VoltaError::ConfigInvalid("lock".into()))?;
    tasks.insert(task.id.clone(), task.clone());
    Ok(task)
}

/// Run one skill synchronously, returning its artifact.
async fn run_skill(
    state: &AppState,
    caller: &Caller,
    skill: &str,
    parts: &[Value],
    data: &Value,
    _task: &mut TaskRecord,
) -> Result<Value, VoltaError> {
    match skill {
        "ephemeral-key-exchange" => {
            if matches!(caller, Caller::Anonymous) {
                return Err(VoltaError::AuthRequired);
            }
            let intent = data
                .get("intent")
                .and_then(Value::as_str)
                .unwrap_or("issue");
            match intent {
                "fetch" => {
                    let key_id = data.get("key_id").and_then(Value::as_str).unwrap_or("");
                    let record = state
                        .ephemeral
                        .get_key(key_id)?
                        .ok_or(VoltaError::KeyNotFound)?;
                    Ok(artifact(
                        "ephemeral-key",
                        key_record_json(&record, false, true),
                    ))
                }
                "issue" => {
                    let body = IssueBody {
                        audience: data
                            .get("audience")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                        custody: data
                            .get("custody")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                        owner_id: caller.id(),
                        public_material: data.get("public_material").and_then(|value| {
                            serde_json::from_value::<PublicMaterialBody>(value.clone()).ok()
                        }),
                        purpose: data
                            .get("purpose")
                            .and_then(Value::as_str)
                            .unwrap_or("a2a-session")
                            .to_string(),
                        rotation_interval_seconds: None,
                        suite: data
                            .get("suite")
                            .and_then(Value::as_str)
                            .unwrap_or("hybrid-mlkem768-x25519")
                            .to_string(),
                        ttl_seconds: data.get("ttl_seconds").and_then(Value::as_u64),
                    };
                    let record = issue_key(state, &caller.id(), &body, None)?;
                    Ok(artifact(
                        "ephemeral-key",
                        key_record_json(&record, false, true),
                    ))
                }
                "rotate" => {
                    let key_id = data.get("key_id").and_then(Value::as_str).unwrap_or("");
                    let record = state
                        .ephemeral
                        .get_key(key_id)?
                        .ok_or(VoltaError::KeyNotFound)?;
                    if caller.id() != record.owner_id && !matches!(caller, Caller::Operator { .. })
                    {
                        return Err(VoltaError::Forbidden("not the key owner".to_string()));
                    }
                    let body = IssueBody {
                        audience: record.audience.clone(),
                        custody: Some(record.custody.clone()),
                        owner_id: record.owner_id.clone(),
                        public_material: data.get("public_material").and_then(|value| {
                            serde_json::from_value::<PublicMaterialBody>(value.clone()).ok()
                        }),
                        purpose: record.purpose.clone(),
                        rotation_interval_seconds: None,
                        suite: record.suite.clone(),
                        ttl_seconds: Some(record.expires_unix - record.created_unix),
                    };
                    let successor =
                        issue_key(state, &record.owner_id, &body, Some(key_id.to_string()))?;
                    state.ephemeral.set_status(key_id, "superseded")?;
                    Ok(artifact(
                        "ephemeral-key",
                        key_record_json(&successor, false, true),
                    ))
                }
                _ => Err(VoltaError::Validation(format!("intent {intent}"))),
            }
        }
        "key-lookup" => {
            let by = data
                .get("by")
                .and_then(Value::as_str)
                .unwrap_or("fingerprint");
            let query = data
                .get("query")
                .and_then(Value::as_str)
                .or_else(|| {
                    parts
                        .iter()
                        .find(|part| part.get("kind").and_then(Value::as_str) == Some("text"))
                        .and_then(|part| part.get("text"))
                        .and_then(Value::as_str)
                })
                .unwrap_or("");
            if by == "email" {
                state.rate_check("by-email", query)?;
            }
            let record = lookup_exact(state, query, by == "email")?;
            Ok(artifact(
                "key-lookup",
                json!({"armor": record.armor, "fingerprint": record.meta.fingerprint}),
            ))
        }
        "key-publication" => {
            let keytext = parts
                .iter()
                .find(|part| part.get("kind").and_then(Value::as_str) == Some("file"))
                .and_then(|part| part.get("file"))
                .and_then(|file| file.get("bytes"))
                .and_then(Value::as_str)
                .and_then(|bytes| crate::http_util::b64_decode(bytes).ok())
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .or_else(|| {
                    data.get("keytext")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .ok_or_else(|| VoltaError::Validation("keytext".to_string()))?;
            let records = crate::hkp::ingest_armor(state, &keytext)?;
            let record = records.into_iter().next().ok_or(VoltaError::KeyNotFound)?;
            let addresses: Vec<String> = record
                .meta
                .user_ids
                .iter()
                .filter_map(|uid| uid.email.clone())
                .collect();
            let token = state.sealer.seal(&TokenPayload {
                addresses,
                created_at: unix_now() as i64,
                fingerprint: record.meta.fingerprint.clone(),
                token_type: "manage".to_string(),
            })?;
            Ok(artifact(
                "key-publication",
                json!({"key_fpr": record.meta.fingerprint, "status": "unpublished", "token": token}),
            ))
        }
        "relay-fetch" => {
            if matches!(caller, Caller::Anonymous) {
                return Err(VoltaError::AuthRequired);
            }
            if !caller.has_permission("relay-fetch") {
                return Err(VoltaError::Forbidden("relay-fetch permission".to_string()));
            }
            let fingerprint = data
                .get("fingerprint")
                .and_then(Value::as_str)
                .unwrap_or("");
            let peer = data.get("peer").and_then(Value::as_str).unwrap_or("");
            let fetched = crate::relay::relay_fetch_key(state, fingerprint, peer).await?;
            Ok(artifact("relay-fetch", fetched))
        }
        _ => Err(VoltaError::Validation(format!("unknown skill {skill}"))),
    }
}

fn artifact(kind: &str, data: Value) -> Value {
    json!({
        "kind": kind,
        "parts": [{"data": data, "kind": "data"}],
    })
}

fn task_action(
    state: &AppState,
    caller: &Caller,
    params: &Value,
    action: &str,
) -> Result<TaskRecord, VoltaError> {
    let id = params
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| VoltaError::Validation("id".to_string()))?;
    let mut tasks = state
        .tasks
        .lock()
        .map_err(|_| VoltaError::ConfigInvalid("lock".into()))?;
    let task = tasks.get_mut(id).ok_or(VoltaError::NotFound)?;
    if task.owner != caller.id() && !matches!(caller, Caller::Operator { .. }) {
        return Err(VoltaError::NotFound);
    }
    if action == "cancel"
        && !matches!(
            task.state.as_str(),
            "canceled" | "completed" | "failed" | "rejected"
        )
    {
        task.state = "canceled".to_string();
        task.history.push(json!({
            "state": "canceled",
            "timestamp": crate::http_util::rfc3339(unix_now()),
        }));
    }
    Ok(task.clone())
}

/// The A2A task object (SPEC 9.3).
#[must_use]
pub fn task_json(task: &TaskRecord) -> Value {
    task_json_with_state(task, &task.state)
}

fn task_json_with_state(task: &TaskRecord, state_name: &str) -> Value {
    let mut metadata = Map::new();
    metadata.insert("volta.skill".to_string(), json!(task.skill));
    json!({
        "artifacts": task.artifacts,
        "contextId": task.context_id,
        "history": task.history,
        "id": task.id,
        "kind": "task",
        "metadata": metadata,
        "status": {"state": state_name, "timestamp": crate::http_util::rfc3339(task.created_unix)},
    })
}
