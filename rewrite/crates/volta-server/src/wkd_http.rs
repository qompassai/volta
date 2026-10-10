//! crates/volta-server/src/wkd_http.rs - WKD surface (SPEC 6.3).
//!
//! Dual licensed under AGPL-3.0-only OR Apache-2.0.
//!
//! Web Key Directory: the served (cleaned) binary form under the
//! hashed `hu/` path, advanced and direct modes, plus the policy
//! file. The hash is SHA-1 of the lowercased local part, z-base-32
//! encoded — a protocol-mandated naming hash (C-2), never a
//! content integrity mechanism.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use volta_core::error::VoltaError;
use volta_core::wkd::wkd_hash;

use crate::http_util::problem;
use crate::state::AppState;

/// The policy file body: exactly these two lines (SPEC 6.3).
pub const POLICY_BODY: &str = "mailbox-only\nprotocol-version: 1\n";

/// GET /.well-known/openpgpkey/<domain>/policy and the direct
/// /.well-known/openpgpkey/policy.
pub async fn policy() -> Response {
    (
        StatusCode::OK,
        [("content-type", "text/plain")],
        POLICY_BODY,
    )
        .into_response()
}

/// GET /.well-known/openpgpkey/<domain>/hu/<hash>?l=<local> and
/// the direct /.well-known/openpgpkey/hu/<hash>?l=<local>.
pub async fn hu(
    State(state): State<Arc<AppState>>,
    Path(hash): Path<String>,
    Query(params): Query<BTreeMap<String, String>>,
) -> Response {
    let request_id = crate::ephemeral::new_request_id();
    let result = (|| -> Result<Vec<u8>, VoltaError> {
        // When the caller names the local part, cross-check the
        // hash binding (WKD-2): a mismatched pair is a 404, not a
        // disclosure. The store itself enforces published-only.
        if let Some(local) = params.get("l") {
            if wkd_hash(&local.to_lowercase()) != hash {
                return Err(VoltaError::KeyNotFound);
            }
        }
        let record = {
            let store = state
                .store
                .lock()
                .map_err(|_| VoltaError::ConfigInvalid("lock".into()))?;
            store.get_by_wkd_hash(&hash)?
        };
        Ok(record.binary)
    })();
    match result {
        Ok(binary) => (
            StatusCode::OK,
            [("content-type", "application/octet-stream")],
            binary,
        )
            .into_response(),
        Err(error) => problem(error, &request_id).into_response(),
    }
}

/// Advanced mode: the domain segment is accepted and routed to
/// the same handler (this node serves its own domain set).
pub async fn hu_advanced(
    State(state): State<Arc<AppState>>,
    Path((_domain, hash)): Path<(String, String)>,
    Query(params): Query<BTreeMap<String, String>>,
) -> Response {
    hu(State(state), Path(hash), Query(params)).await
}
