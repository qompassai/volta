//! crates/volta-server/src/vks.rs - VKS surface (SPEC 6.2).
//!
//! Dual licensed under AGPL-3.0-only OR Apache-2.0.
//!
//! JSON API per the keys.openpgp.org VKS specification, with the
//! C-5 error asymmetry preserved: by-email discloses nothing
//! about unpublished bindings, while by-fingerprint/by-keyid
//! serve any stored certificate (possession of the fingerprint
//! is the capability).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use volta_core::error::VoltaError;
use volta_core::model::BindingStatus;
use volta_core::sealed::TokenPayload;

use crate::hkp::{ingest_armor, lookup_exact};
use crate::http_util::{problem, unix_now};
use crate::state::AppState;

/// GET /vks/v1/by-email/<email>.
pub async fn by_email(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(email): Path<String>,
) -> Response {
    let request_id = crate::ephemeral::new_request_id();
    if let Err(error) = state.rate_check("by-email", &email) {
        return problem(error, &request_id).into_response();
    }
    let _ = &headers;
    match lookup_exact(&state, &email, true) {
        Ok(record) => Json(json!({
            "armor": record.armor,
            "fingerprint": record.meta.fingerprint,
        }))
        .into_response(),
        Err(error) => problem(error, &request_id).into_response(),
    }
}

/// GET /vks/v1/by-fingerprint/<fpr>.
pub async fn by_fingerprint(
    State(state): State<Arc<AppState>>,
    Path(fingerprint): Path<String>,
) -> Response {
    let request_id = crate::ephemeral::new_request_id();
    if let Err(error) = state.rate_check("by-fingerprint", &fingerprint) {
        return problem(error, &request_id).into_response();
    }
    match lookup_exact(&state, &fingerprint, false) {
        Ok(record) => {
            let mut response = Json(json!({
                "armor": record.armor,
                "fingerprint": record.meta.fingerprint,
            }))
            .into_response();
            if let Ok(etag) = axum::http::HeaderValue::from_str(&format!(
                "\"{}-{}\"",
                record.content_sha256, record.revision
            )) {
                response.headers_mut().insert("etag", etag);
            }
            response
        }
        Err(error) => problem(error, &request_id).into_response(),
    }
}

/// GET /vks/v1/by-keyid/<keyid>.
pub async fn by_keyid(
    State(state): State<Arc<AppState>>,
    Path(key_id): Path<String>,
) -> Response {
    let request_id = crate::ephemeral::new_request_id();
    if let Err(error) = state.rate_check("by-fingerprint", &key_id) {
        return problem(error, &request_id).into_response();
    }
    match lookup_exact(&state, &key_id, false) {
        Ok(record) => Json(json!({
            "armor": record.armor,
            "fingerprint": record.meta.fingerprint,
        }))
        .into_response(),
        Err(error) => problem(error, &request_id).into_response(),
    }
}

/// Upload request body.
#[derive(Debug, Deserialize)]
pub struct UploadBody {
    /// Armored certificate(s).
    pub keytext: String,
}

/// POST /vks/v1/upload — store unpublished; returns the manage/
/// verify token for the certificate's addresses (VKS 6.2.2).
pub async fn upload(
    State(state): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Response {
    let request_id = crate::ephemeral::new_request_id();
    let parsed: UploadBody = match serde_json::from_slice(&body) {
        Ok(parsed) => parsed,
        Err(_) => {
            return problem(VoltaError::Validation("keytext".into()), &request_id).into_response()
        }
    };
    let result = (|| -> Result<Value, VoltaError> {
        let records = ingest_armor(&state, &parsed.keytext)?;
        let record = records.into_iter().next().ok_or(VoltaError::KeyNotFound)?;
        let addresses: Vec<String> = record
            .meta
            .user_ids
            .iter()
            .filter_map(|uid| uid.email.clone())
            .collect();
        let token = state.sealer.seal(&TokenPayload {
            addresses: addresses.clone(),
            created_at: unix_now() as i64,
            fingerprint: record.meta.fingerprint.clone(),
            token_type: "manage".to_string(),
        })?;
        let status = if addresses.is_empty() {
            "no-addresses"
        } else if record.meta.user_ids.iter().any(|uid| uid.verified) {
            "published"
        } else {
            "unpublished"
        };
        Ok(json!({
            "key_fpr": record.meta.fingerprint,
            "status": status,
            "token": token,
        }))
    })();
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => problem(error, &request_id).into_response(),
    }
}

/// Request-verify request body.
#[derive(Debug, Deserialize)]
pub struct RequestVerifyBody {
    /// Addresses to verify (must be covered by the token).
    pub addresses: Vec<String>,
    /// Locale (accepted, informational in the single-locale build).
    pub locale: Option<String>,
    /// The upload/manage token.
    pub token: String,
}

/// POST /vks/v1/request-verify — mark addresses pending and issue
/// per-address verify tokens (SPEC 6.2.3). Delivery is by mail
/// through the configured chain when SMTP submission is
/// configured; in the no-SMTP development profile the tokens are
/// returned in `dev_tokens` so the flow is exercisable end to
/// end (documented in the book as a dev-only behavior).
pub async fn request_verify(
    State(state): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Response {
    let request_id = crate::ephemeral::new_request_id();
    let parsed: RequestVerifyBody = match serde_json::from_slice(&body) {
        Ok(parsed) => parsed,
        Err(_) => {
            return problem(VoltaError::Validation("body".into()), &request_id).into_response()
        }
    };
    let result = (|| -> Result<Value, VoltaError> {
        let now = unix_now() as i64;
        let payload = state.sealer.unseal_and_check(
            &parsed.token,
            Some("manage"),
            now,
            state.config.token_validity_seconds as i64,
        )?;
        let mut status = Map::new();
        let mut dev_tokens = Map::new();
        let mut store = state.store.lock().map_err(|_| VoltaError::ConfigInvalid("lock".into()))?;
        for address in &parsed.addresses {
            let address = address.to_lowercase();
            if !payload.addresses.iter().any(|a| *a == address) {
                return Err(VoltaError::VerificationAddressMismatch);
            }
            store.set_binding_status(&address, &payload.fingerprint, BindingStatus::Pending, None)?;
            let verify_token = state.sealer.seal(&TokenPayload {
                addresses: vec![address.clone()],
                created_at: now,
                fingerprint: payload.fingerprint.clone(),
                token_type: "verify".to_string(),
            })?;
            status.insert(address.clone(), json!("pending"));
            if state.config.smtp_submit_address.is_none() {
                dev_tokens.insert(address, json!(verify_token));
            }
        }
        let mut out = Map::new();
        out.insert("status".to_string(), Value::Object(status));
        if !dev_tokens.is_empty() {
            out.insert("dev_tokens".to_string(), Value::Object(dev_tokens));
        }
        Ok(Value::Object(out))
    })();
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => problem(error, &request_id).into_response(),
    }
}

/// GET /vks/v1/verify/<token> — the mailed-link target (also
/// served under /verify/<token> in the web surface).
pub async fn verify_token(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
) -> Response {
    let request_id = crate::ephemeral::new_request_id();
    match publish_from_verify_token(&state, &token) {
        Ok(address) => Json(json!({"address": address, "status": "published"})).into_response(),
        Err(error) => problem(error, &request_id).into_response(),
    }
}

/// Publish the address carried by a verify token.
///
/// # Errors
/// The sealed-token errors (TOK-2/TOK-4) or `E_KEY_NOT_FOUND`.
pub fn publish_from_verify_token(state: &AppState, token: &str) -> Result<String, VoltaError> {
    let now = unix_now() as i64;
    let payload = state.sealer.unseal_and_check(
        token,
        Some("verify"),
        now,
        state.config.token_validity_seconds as i64,
    )?;
    let address = payload
        .addresses
        .first()
        .cloned()
        .ok_or(VoltaError::TokenInvalid)?;
    let mut store = state.store.lock().map_err(|_| VoltaError::ConfigInvalid("lock".into()))?;
    store.publish_address(&address, &payload.fingerprint, now)?;
    Ok(address)
}

/// POST /vks/v1/request-manage — issue a fresh manage token for a
/// certificate's addresses (the caller proves control of one
/// address by presenting a still-valid earlier token).
pub async fn request_manage(
    State(state): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Response {
    let request_id = crate::ephemeral::new_request_id();
    let parsed: RequestVerifyBody = match serde_json::from_slice(&body) {
        Ok(parsed) => parsed,
        Err(_) => {
            return problem(VoltaError::Validation("body".into()), &request_id).into_response()
        }
    };
    let result = (|| -> Result<Value, VoltaError> {
        let now = unix_now() as i64;
        let payload = state.sealer.unseal_and_check(
            &parsed.token,
            Some("manage"),
            now,
            state.config.token_validity_seconds as i64,
        )?;
        let token = state.sealer.seal(&TokenPayload {
            addresses: payload.addresses.clone(),
            created_at: now,
            fingerprint: payload.fingerprint.clone(),
            token_type: "manage".to_string(),
        })?;
        Ok(json!({"token": token}))
    })();
    match result {
        Ok(value) => (StatusCode::OK, Json(value)).into_response(),
        Err(error) => problem(error, &request_id).into_response(),
    }
}
