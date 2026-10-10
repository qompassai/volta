//! crates/volta-cli/src/delete.rs - deletion semantics (SPEC 15.2).
//!
//! Dual licensed under AGPL-3.0-only OR Apache-2.0.
//!
//! Shared by `voltactl delete` and the `volta-delete` binary.
//! An address query without flags unpublishes that binding (the
//! store's binding row is retained for audit; see the named gap
//! in the handoff). `--all-bindings` unpublishes every binding of
//! the key; `--all` removes the certificate entirely. A
//! fingerprint or KeyID query implies `--all`.

use serde_json::{Value, json};
use volta_core::error::VoltaError;
use volta_core::model::BindingStatus;
use volta_core::pgp_key::{is_fingerprint, is_long_key_id, normalize_hex_id};
use volta_core::store::Store;

/// Execute a deletion against an open store.
///
/// # Errors
/// `E_KEY_NOT_FOUND` when the query resolves to nothing.
pub fn delete(
    store: &mut Store,
    query: &str,
    all: bool,
    all_bindings: bool,
) -> Result<Value, VoltaError> {
    let normalized = normalize_hex_id(query);
    if is_fingerprint(&normalized) || is_long_key_id(&normalized) {
        let record = if is_fingerprint(&normalized) {
            store.get_by_fingerprint(&normalized)?
        } else {
            store.get_by_key_id(&normalized)?
        };
        let fingerprint = record.meta.fingerprint.clone();
        store.delete_certificate(&fingerprint)?;
        return Ok(json!({
            "action": "delete-certificate",
            "fingerprint": fingerprint,
            "query": query,
        }));
    }
    if query.contains('@') {
        let address = query.to_lowercase();
        let record = store.get_by_email(&address)?;
        let fingerprint = record.meta.fingerprint.clone();
        if all {
            store.delete_certificate(&fingerprint)?;
            return Ok(json!({
                "action": "delete-certificate",
                "fingerprint": fingerprint,
                "query": query,
            }));
        }
        if all_bindings {
            let bindings = store.bindings_of(&fingerprint);
            for (bound_address, _) in &bindings {
                store.set_binding_status(
                    bound_address,
                    &fingerprint,
                    BindingStatus::Unpublished,
                    None,
                )?;
            }
            return Ok(json!({
                "action": "unpublish-all-bindings",
                "bindings": bindings.len(),
                "fingerprint": fingerprint,
                "query": query,
            }));
        }
        store.set_binding_status(&address, &fingerprint, BindingStatus::Unpublished, None)?;
        return Ok(json!({
            "action": "unpublish-binding",
            "address": address,
            "fingerprint": fingerprint,
            "query": query,
        }));
    }
    Err(VoltaError::KeyNotFound)
}
