//! crates/volta-server/src/web.rs - minimal web surface (SPEC 4).
//!
//! Dual licensed under AGPL-3.0-only OR Apache-2.0.
//!
//! Server-rendered pages only; no JavaScript framework, no
//! trackers. The manage flow's irreversible actions require a
//! WebAuthn step-up (SPEC 10.3 WA-4).

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use serde::Deserialize;
use volta_core::error::VoltaError;
use volta_core::model::BindingStatus;
use volta_core::sealed::TokenPayload;

use crate::auth::{authenticate, require_step_up};
use crate::hkp::{ingest_armor, lookup_exact};
use crate::http_util::{problem, unix_now};
use crate::state::AppState;
use crate::vks::publish_from_verify_token;

fn page(title: &str, body: &str) -> Html<String> {
    Html(format!(
        "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
         <title>{title} — volta</title></head><body>\
         <header><strong>volta</strong> — post-quantum key server</header>\
         <main>{body}</main></body></html>"
    ))
}

/// Escape text for HTML interpolation.
#[must_use]
pub fn esc(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// GET / — landing page with live counts.
pub async fn index(State(state): State<Arc<AppState>>) -> Response {
    let stats =
        state
            .store
            .lock()
            .map(|store| store.stats())
            .unwrap_or(volta_core::store::StoreStats {
                certificates: 0,
                published_addresses: 0,
                revoked_certificates: 0,
            });
    page(
        "volta",
        &format!(
            "<h1>volta</h1><p>An OpenPGP key server for humans and agents: \
             verified publication, ephemeral hybrid-PQC session keys, \
             chained-proxy relay.</p><ul>\
             <li>{} certificates stored</li>\
             <li>{} published addresses</li></ul>\
             <p><a href=\"/about\">About</a> · <a href=\"/search\">Search</a> · \
             <a href=\"/upload\">Upload</a></p>",
            stats.certificates, stats.published_addresses
        ),
    )
    .into_response()
}

/// GET /about.
pub async fn about() -> Response {
    page(
        "About",
        "<h1>About volta</h1><p>Volta publishes and serves OpenPGP \
         certificates under verified email bindings (VKS/WKD/HKP), mints \
         hard-TTL ephemeral hybrid post-quantum session keys for MCP and \
         A2A agents, and routes its own egress through configurable \
         fail-closed proxy chains. Biometric authentication is WebAuthn: \
         biometrics never leave the operator's authenticator.</p>",
    )
    .into_response()
}

/// Search query.
#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    /// The search term (fingerprint, key id, or email).
    pub q: Option<String>,
}

/// GET /search?q=...
pub async fn search(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SearchQuery>,
) -> Response {
    let term = query.q.unwrap_or_default();
    if term.is_empty() {
        return page(
            "Search",
            "<h1>Search</h1><form method=\"get\" action=\"/search\">\
             <input name=\"q\" size=\"48\" placeholder=\"fingerprint, key id, or email\">\
             <button type=\"submit\">Search</button></form>",
        )
        .into_response();
    }
    match lookup_exact(&state, &term, true) {
        Ok(record) => page(
            "Search",
            &format!(
                "<h1>Result</h1><p>Fingerprint: {}</p><pre>{}</pre>",
                esc(&record.meta.fingerprint),
                esc(&record.armor)
            ),
        )
        .into_response(),
        Err(_) => page(
            "Search",
            "<h1>Result</h1><p>No key found for that term.</p>",
        )
        .into_response(),
    }
}

/// GET /upload — the upload form.
pub async fn upload_form() -> Response {
    page(
        "Upload",
        "<h1>Upload a certificate</h1>\
         <form method=\"post\" action=\"/upload\">\
         <textarea name=\"keytext\" rows=\"12\" cols=\"72\"></textarea><br>\
         <button type=\"submit\">Upload</button></form>\
         <p>Uploaded certificates are stored unpublished until an \
         address is verified.</p>",
    )
    .into_response()
}

/// POST /upload — form upload; shows the manage token once.
pub async fn upload_submit(State(state): State<Arc<AppState>>, body: String) -> Response {
    let request_id = crate::ephemeral::new_request_id();
    let keytext = crate::hkp::extract_form_field(&body, "keytext").unwrap_or(body);
    let result = (|| -> Result<String, VoltaError> {
        let records = ingest_armor(&state, &keytext)?;
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
        Ok(format!(
            "<h1>Stored (unpublished)</h1><p>Fingerprint: {}</p>\
             <p>Manage token (keep it; it is shown once):</p><pre>{}</pre>\
             <p><a href=\"/manage/{}\">Manage this certificate</a></p>",
            esc(&record.meta.fingerprint),
            esc(&token),
            esc(&token)
        ))
    })();
    match result {
        Ok(html) => page("Upload", &html).into_response(),
        Err(error) => problem(error, &request_id).into_response(),
    }
}

/// GET /verify/<token> — publish the token's address.
pub async fn verify_page(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
) -> Response {
    match publish_from_verify_token(&state, &token) {
        Ok(address) => page(
            "Verified",
            &format!(
                "<h1>Verified</h1><p>{} is now published.</p>",
                esc(&address)
            ),
        )
        .into_response(),
        Err(error) => page(
            "Verification failed",
            &format!("<h1>Verification failed</h1><p>{}</p>", esc(error.code())),
        )
        .into_response(),
    }
}

/// GET /manage/<token> — bindings view for a manage token.
pub async fn manage_page(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
) -> Response {
    let request_id = crate::ephemeral::new_request_id();
    let result = (|| -> Result<String, VoltaError> {
        let now = unix_now() as i64;
        let payload = state.sealer.unseal_and_check(
            &token,
            Some("manage"),
            now,
            state.config.token_validity_seconds,
        )?;
        let store = state
            .store
            .lock()
            .map_err(|_| VoltaError::ConfigInvalid("lock".into()))?;
        let bindings = store.bindings_of(&payload.fingerprint);
        let mut rows = String::new();
        for (address, status) in &bindings {
            rows.push_str(&format!("<li>{} — {}</li>", esc(address), status.as_str()));
        }
        Ok(format!(
            "<h1>Manage {}</h1><ul>{}</ul>\
             <p>Unpublish and delete require a WebAuthn operator step-up.</p>",
            esc(&payload.fingerprint),
            rows
        ))
    })();
    match result {
        Ok(html) => page("Manage", &html).into_response(),
        Err(error) => problem(error, &request_id).into_response(),
    }
}

/// Manage action form.
#[derive(Debug, Deserialize)]
pub struct ManageActionForm {
    /// `unpublish` or `delete`.
    pub action: String,
    /// The address (for unpublish).
    pub address: Option<String>,
    /// The manage token.
    pub token: String,
}

/// POST /manage/action — unpublish (step-up) or delete (step-up).
pub async fn manage_action(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let request_id = crate::ephemeral::new_request_id();
    let caller = authenticate(&state, &headers);
    let form = parse_manage_form(&body);
    let result = (|| -> Result<String, VoltaError> {
        require_step_up(&state, &caller, &headers)?;
        let now = unix_now() as i64;
        let payload = state.sealer.unseal_and_check(
            &form.token,
            Some("manage"),
            now,
            state.config.token_validity_seconds,
        )?;
        let mut store = state
            .store
            .lock()
            .map_err(|_| VoltaError::ConfigInvalid("lock".into()))?;
        match form.action.as_str() {
            "unpublish" => {
                let address = form
                    .address
                    .clone()
                    .ok_or_else(|| VoltaError::Validation("address".to_string()))?;
                if !payload.addresses.contains(&address) {
                    return Err(VoltaError::VerificationAddressMismatch);
                }
                store.set_binding_status(
                    &address,
                    &payload.fingerprint,
                    BindingStatus::Unpublished,
                    None,
                )?;
                Ok(format!("{} unpublished.", esc(&address)))
            }
            "delete" => {
                store.delete_certificate(&payload.fingerprint)?;
                Ok("Certificate deleted.".to_string())
            }
            _ => Err(VoltaError::Validation("action".to_string())),
        }
    })();
    match result {
        Ok(html) => page("Manage", &html).into_response(),
        Err(error) => problem(error, &request_id).into_response(),
    }
}

fn parse_manage_form(body: &str) -> ManageActionForm {
    ManageActionForm {
        action: crate::hkp::extract_form_field(body, "action").unwrap_or_default(),
        address: crate::hkp::extract_form_field(body, "address"),
        token: crate::hkp::extract_form_field(body, "token").unwrap_or_default(),
    }
}

/// GET /metrics — counts only (SPEC 12.6: no labels that leak
/// identities).
pub async fn metrics(State(state): State<Arc<AppState>>) -> Response {
    let stats =
        state
            .store
            .lock()
            .map(|store| store.stats())
            .unwrap_or(volta_core::store::StoreStats {
                certificates: 0,
                published_addresses: 0,
                revoked_certificates: 0,
            });
    (
        axum::http::StatusCode::OK,
        [("content-type", "text/plain")],
        format!(
            "volta_certificates {}\nvolta_published_addresses {}\nvolta_revoked_certificates {}\n",
            stats.certificates, stats.published_addresses, stats.revoked_certificates
        ),
    )
        .into_response()
}

/// GET /healthz.
pub async fn healthz() -> Response {
    axum::Json(serde_json::json!({"status": "ok"})).into_response()
}

/// GET /readyz — readiness, including the A2A signing state
/// (A2A-1: an unsigned card is a readiness failure for section 9).
pub async fn readyz(State(state): State<Arc<AppState>>) -> Response {
    let identity = if state.identity.is_some() {
        "configured"
    } else {
        "absent"
    };
    axum::Json(serde_json::json!({
        "identity": identity,
        "status": "ready",
        "uptime_seconds": unix_now().saturating_sub(state.started_unix),
    }))
    .into_response()
}
