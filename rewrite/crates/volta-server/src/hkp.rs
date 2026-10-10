//! crates/volta-server/src/hkp.rs - HKP surface (SPEC 6.1).
//!
//! Dual licensed under AGPL-3.0-only OR Apache-2.0.
//!
//! HKP semantics per the HKP draft: exact lookups only, the
//! `mr` machine-readable index form, atomic multi-key add.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use volta_core::error::VoltaError;
use volta_core::model::StoredCertificate;
use volta_core::pgp_key::{
    clean_served_form, is_fingerprint, is_long_key_id, normalize_hex_id, parse_and_check, to_armor,
    to_binary,
};

use crate::http_util::{problem, unix_now};
use crate::state::AppState;

/// Extract armored blocks from a text body.
#[must_use]
pub fn armor_blocks(text: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        if line.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----") {
            current = Some(String::new());
        }
        if let Some(block) = current.as_mut() {
            block.push_str(line);
            block.push('\n');
        }
        if line.starts_with("-----END PGP PUBLIC KEY BLOCK-----") {
            if let Some(block) = current.take() {
                blocks.push(block);
            }
        }
    }
    blocks
}

/// Ingest armored text atomically (all-or-nothing): parse and
/// policy-check every block before storing any of them.
/// Returns the stored records.
///
/// # Errors
/// The first parse/policy error encountered (nothing is stored).
pub fn ingest_armor(state: &AppState, text: &str) -> Result<Vec<StoredCertificate>, VoltaError> {
    if text.len() > volta_core::config::UPLOAD_BYTES_MAX {
        return Err(VoltaError::UploadTooLarge);
    }
    let blocks = armor_blocks(text);
    if blocks.is_empty() {
        return Err(VoltaError::KeyMalformed(
            "no certificate blocks".to_string(),
        ));
    }
    let mut parsed = Vec::with_capacity(blocks.len());
    for block in &blocks {
        parsed.push(parse_and_check(block.as_bytes())?);
    }
    let mut store = state
        .store
        .lock()
        .map_err(|_| VoltaError::ConfigInvalid("lock".into()))?;
    let now = unix_now() as i64;
    let mut stored = Vec::with_capacity(parsed.len());
    for parsed_key in &parsed {
        // The served form is derived once, here at ingest
        // (SCALE-1): self-issued signatures only, no third-party
        // certifications. Nothing is verified yet, so the verified
        // set is empty; self-signed user ids are retained.
        let cleaned = clean_served_form(&parsed_key.signed_key, &std::collections::BTreeSet::new());
        let binary = to_binary(&cleaned)?;
        let armor = to_armor(&cleaned)?;
        let record = store.put_certificate(parsed_key.meta.clone(), &binary, &armor, now)?;
        stored.push(record);
    }
    Ok(stored)
}

/// Resolve an HKP/VKS search term to a stored certificate.
/// Grammar (HKP-2): a fingerprint (40/64 hex, optional 0x), a
/// 16-hex long key id, or an exact email address. Nothing else —
/// no substring or short-id searches.
pub fn lookup_exact(
    state: &AppState,
    search: &str,
    published_only: bool,
) -> Result<StoredCertificate, VoltaError> {
    let store = state
        .store
        .lock()
        .map_err(|_| VoltaError::ConfigInvalid("lock".into()))?;
    let normalized = normalize_hex_id(search);
    if is_fingerprint(&normalized) {
        let record = store.get_by_fingerprint(&normalized)?;
        return Ok(record);
    }
    if is_long_key_id(&normalized) {
        let record = store.get_by_key_id(&normalized)?;
        return Ok(record);
    }
    if search.contains('@') {
        let address = search.to_lowercase();
        let record = store.get_by_email(&address)?;
        if published_only {
            // The bindings table is the source of truth for
            // publication (DM-PUB-1), not the ingest-time meta.
            let status = store.binding_status(&address, &record.meta.fingerprint);
            if status != Some(volta_core::model::BindingStatus::Published) {
                return Err(VoltaError::KeyNotFound);
            }
        }
        return Ok(record);
    }
    Err(VoltaError::HkpBadSearch)
}

/// Served armor for a record (cleaned served form, SPEC 5.4).
#[must_use]
pub fn served_armor(record: &StoredCertificate) -> String {
    record.armor.clone()
}

/// GET /pks/lookup.
pub async fn lookup(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<BTreeMap<String, String>>,
) -> Response {
    let request_id = crate::ephemeral::new_request_id();
    let op = params.get("op").map(String::as_str).unwrap_or("");
    let internal = is_internal(&state, &headers);
    match op {
        "get" => {
            let search = params.get("search").cloned().unwrap_or_default();
            match lookup_exact(&state, &search, !internal) {
                Ok(record) => (
                    StatusCode::OK,
                    [("content-type", "application/pgp-keys")],
                    served_armor(&record),
                )
                    .into_response(),
                Err(error) => hkp_error(error, &request_id),
            }
        }
        "index" | "vindex" => {
            if op == "vindex" {
                return hkp_error(VoltaError::HkpUnsupportedOp, &request_id);
            }
            let search = params.get("search").cloned().unwrap_or_default();
            match lookup_exact(&state, &search, !internal) {
                Ok(record) => {
                    let machine = params
                        .get("options")
                        .map(|options| options.split(',').any(|o| o.trim() == "mr"))
                        .unwrap_or(false);
                    if machine {
                        (
                            StatusCode::OK,
                            [("content-type", "text/plain")],
                            mr_index(&record),
                        )
                            .into_response()
                    } else {
                        (
                            StatusCode::OK,
                            [("content-type", "text/plain")],
                            human_index(&record),
                        )
                            .into_response()
                    }
                }
                Err(error) => hkp_error(error, &request_id),
            }
        }
        "stats" => {
            let stats = state.store.lock().map(|store| store.stats()).unwrap_or(
                volta_core::store::StoreStats {
                    certificates: 0,
                    published_addresses: 0,
                    revoked_certificates: 0,
                },
            );
            axum::Json(serde_json::json!({
                "certificates": stats.certificates,
                "published_addresses": stats.published_addresses,
                "revoked_certificates": stats.revoked_certificates,
            }))
            .into_response()
        }
        _ => hkp_error(VoltaError::HkpUnsupportedOp, &request_id),
    }
}

/// Whether the request is an edge-forwarded internal call
/// (loopback is enforced by deployment; the header is the edge's
/// attestation, SPEC 6.1 internal routes).
#[must_use]
pub fn is_internal(_state: &AppState, headers: &HeaderMap) -> bool {
    headers
        .get("x-volta-internal")
        .and_then(|value| value.to_str().ok())
        == Some("1")
}

fn hkp_error(error: VoltaError, request_id: &str) -> Response {
    // HKP clients expect plain text; the code still rides the
    // X-Volta-Error-Code header.
    let status = StatusCode::from_u16(error.http_status()).unwrap_or(StatusCode::BAD_REQUEST);
    let mut response = (status, format!("Error: {}\n", error.code())).into_response();
    if let Ok(value) = axum::http::HeaderValue::from_str(error.code()) {
        response.headers_mut().insert("x-volta-error-code", value);
    }
    let _ = request_id;
    response
}

/// The machine-readable (`mr`) index form. Field order is the
/// protocol's (documented exception to alphabetical order).
#[must_use]
pub fn mr_index(record: &StoredCertificate) -> String {
    let meta = &record.meta;
    let mut out = String::from("info:1:1\n");
    // The numeric algorithm id is mapped from the stored name;
    // bit length is not retained in metadata and is reported 0.
    out.push_str(&format!(
        "pub:{}:0:{}:{}:{}:\n",
        algorithm_id(&meta.primary_algorithm),
        meta.key_id,
        meta.primary_created_at,
        meta.primary_expires_at
            .map(|value| value.to_string())
            .unwrap_or_default(),
    ));
    for uid in &meta.user_ids {
        out.push_str(&format!(
            "uid:{}:{}::\n",
            escape_uid(&uid.raw),
            meta.primary_created_at,
        ));
    }
    out
}

/// The human-readable index form.
#[must_use]
pub fn human_index(record: &StoredCertificate) -> String {
    let meta = &record.meta;
    let mut out = format!(
        "pub  {} {} [{}]\n     Fingerprint: {}\n",
        meta.primary_algorithm, meta.primary_created_at, meta.key_id, meta.fingerprint
    );
    for uid in &meta.user_ids {
        out.push_str(&format!("uid           {}\n", uid.raw));
    }
    out
}

/// Map a stored algorithm name to its OpenPGP algorithm id for
/// the index form (RFC 9580 / RFC 9980 registries).
#[must_use]
pub fn algorithm_id(name: &str) -> u32 {
    match name {
        "rsa" => 1,
        "elgamal" => 16,
        "dsa" => 17,
        "ecdh" => 18,
        "ecdsa" => 19,
        "ed25519" => 27,
        "ed448" => 28,
        "ml-dsa-65-ed25519" => 30,
        "ml-dsa-87-ed448" => 31,
        "slh-dsa" => 32,
        "ml-kem-768-x25519" => 35,
        "ml-kem-1024-x448" => 36,
        _ => 0,
    }
}

/// Escape a user id for the index forms (%XX for `%`, `:`, and
/// non-printable bytes).
#[must_use]
pub fn escape_uid(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte == b'%' || byte == b':' || !(0x20..=0x7e).contains(&byte) {
            out.push_str(&format!("%{byte:02X}"));
        } else {
            out.push(byte as char);
        }
    }
    out
}

/// POST /pks/add — atomic multi-key add (form field `keytext`).
pub async fn add(State(state): State<Arc<AppState>>, body: String) -> Response {
    let request_id = crate::ephemeral::new_request_id();
    let keytext = extract_form_field(&body, "keytext").unwrap_or(body.clone());
    match ingest_armor(&state, &keytext) {
        Ok(records) => {
            let mut out = String::new();
            for record in &records {
                out.push_str(&format!("Key {} imported\n", record.meta.fingerprint));
            }
            (StatusCode::OK, out).into_response()
        }
        Err(error) => problem(error, &request_id).into_response(),
    }
}

/// Extract one field from an `application/x-www-form-urlencoded`
/// body (minimal decoder for the HKP form contract).
#[must_use]
pub fn extract_form_field(body: &str, field: &str) -> Option<String> {
    for pair in body.split('&') {
        let (name, value) = pair.split_once('=')?;
        if name == field {
            return Some(url_decode(value));
        }
    }
    None
}

fn url_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => out.push(byte),
                    Err(_) => out.push(bytes[index]),
                }
                index += 3;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

/// GET /pks/internal/get-armor-by-fingerprint/<fpr> — edge-only.
pub async fn internal_get_armor(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(fingerprint): axum::extract::Path<String>,
) -> Response {
    let request_id = crate::ephemeral::new_request_id();
    if !is_internal(&state, &headers) {
        return problem(VoltaError::InternalOnly, &request_id).into_response();
    }
    match lookup_exact(&state, &fingerprint, false) {
        Ok(record) => (
            StatusCode::OK,
            [("content-type", "application/pgp-keys")],
            record.armor,
        )
            .into_response(),
        Err(error) => problem(error, &request_id).into_response(),
    }
}
