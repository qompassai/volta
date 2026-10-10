//! crates/volta-server/src/auth.rs - caller authentication.
//!
//! Dual licensed under AGPL-3.0-only OR Apache-2.0.
//!
//! Three credential forms (SPEC 7.5, 8.3, 9.4): an agent
//! principal's detached signature over the canonical request, an
//! operator session token (Bearer or cookie, SPEC 10.3), or
//! nothing (anonymous: public surfaces only). Authorization is
//! deterministic and checked before any operation executes.

use axum::http::HeaderMap;
use volta_core::config::PrincipalConfig;
use volta_core::error::VoltaError;
use volta_crypto::signing::{canonical_request, verify, IdentitySuite};

use crate::http_util::{b64_decode, unix_now};
use crate::state::AppState;

/// Signature freshness window in seconds (SPEC 7.5).
pub const SIGNATURE_WINDOW_SECONDS: i64 = 300;
/// Step-up freshness window in seconds (SPEC 10.3, WA-4).
pub const STEP_UP_WINDOW_SECONDS: u64 = 300;

/// Who is calling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Caller {
    /// No credential: public surfaces only.
    Anonymous,
    /// An operator holding a session (SPEC 10.3).
    Operator {
        /// The operator id.
        operator_id: String,
    },
    /// An agent principal authenticated by signature.
    Principal {
        /// The principal's configured name.
        name: String,
        /// The principal's permissions.
        permissions: Vec<String>,
    },
}

impl Caller {
    /// The stable caller id used for ownership checks.
    #[must_use]
    pub fn id(&self) -> String {
        match self {
            Self::Anonymous => "anonymous".to_string(),
            Self::Operator { operator_id } => format!("operator:{operator_id}"),
            Self::Principal { name, .. } => name.clone(),
        }
    }

    /// Whether the caller holds a permission.
    #[must_use]
    pub fn has_permission(&self, permission: &str) -> bool {
        match self {
            Self::Operator { .. } => true,
            Self::Principal { permissions, .. } => {
                permissions.iter().any(|p| p == permission || p == "*")
            }
            Self::Anonymous => false,
        }
    }
}

/// Authenticate a caller from headers alone (no body-bound
/// signature): operator session token, else anonymous. Used by
/// GET handlers; mutating handlers use `authenticate_with_body`.
#[must_use]
pub fn authenticate(state: &AppState, headers: &HeaderMap) -> Caller {
    if let Some(operator_id) = operator_session(state, headers) {
        return Caller::Operator { operator_id };
    }
    Caller::Anonymous
}

/// The operator id for a valid session token in the headers
/// (Bearer or `volta_operator` cookie), when one exists.
#[must_use]
pub fn operator_session(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let token = bearer_token(headers).or_else(|| cookie_token(headers))?;
    state.operator.session_operator(&token)
}

/// Extract an `Authorization: Bearer` token.
fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get("authorization")?.to_str().ok()?;
    value.strip_prefix("Bearer ").map(str::to_string)
}

/// Extract the `volta_operator` cookie value.
fn cookie_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get("cookie")?.to_str().ok()?;
    for part in value.split(';') {
        if let Some(token) = part.trim().strip_prefix("volta_operator=") {
            return Some(token.to_string());
        }
    }
    None
}

/// Verify an agent principal's detached signature over the
/// canonical request (SPEC 7.5) and return the caller.
///
/// # Errors
/// `E_AUTH_REQUIRED` when headers are missing or stale;
/// `E_FORBIDDEN` when the signature does not verify or the
/// principal is unknown.
pub fn verify_agent_signature(
    state: &AppState,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<Caller, VoltaError> {
    let name = header(headers, "x-volta-principal").ok_or(VoltaError::AuthRequired)?;
    let timestamp: i64 = header(headers, "x-volta-timestamp")
        .and_then(|text| text.parse().ok())
        .ok_or(VoltaError::AuthRequired)?;
    let signature_b64 = header(headers, "x-volta-signature").ok_or(VoltaError::AuthRequired)?;
    let now = unix_now() as i64;
    if (now - timestamp).abs() > SIGNATURE_WINDOW_SECONDS {
        return Err(VoltaError::AuthRequired);
    }
    let principal: &PrincipalConfig = state
        .config
        .principals
        .iter()
        .find(|p| p.name == name)
        .ok_or_else(|| VoltaError::Forbidden(format!("unknown principal {name}")))?;
    let suite = IdentitySuite::parse(&principal.identity_suite)?;
    let public = b64_decode(&principal.identity_public_b64)?;
    let signature = b64_decode(&signature_b64)?;
    let canonical = canonical_request(method, path, timestamp, body);
    verify(suite, &public, &canonical, &signature)?;
    Ok(Caller::Principal {
        name: principal.name.clone(),
        permissions: principal.permissions.clone(),
    })
}

/// Authenticate a mutating call: operator session first, then an
/// agent signature over the body, else anonymous.
#[must_use]
pub fn authenticate_with_body(
    state: &AppState,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    body: &[u8],
) -> Caller {
    if let Some(operator_id) = operator_session(state, headers) {
        return Caller::Operator { operator_id };
    }
    if headers.contains_key("x-volta-principal") {
        if let Ok(caller) = verify_agent_signature(state, headers, method, path, body) {
            return caller;
        }
    }
    Caller::Anonymous
}

/// Require an authenticated caller (agent or operator).
///
/// # Errors
/// `E_AUTH_REQUIRED` for anonymous callers.
pub fn require_authenticated(caller: &Caller) -> Result<(), VoltaError> {
    match caller {
        Caller::Anonymous => Err(VoltaError::AuthRequired),
        _ => Ok(()),
    }
}

/// Require a fresh step-up (SPEC 10.3 WA-4): for operators, a
/// WebAuthn assertion within the window; for agent principals,
/// the request signature itself is the fresh proof (its 300 s
/// window is enforced at verification).
///
/// # Errors
/// `E_AUTH_REQUIRED` for anonymous callers; `E_FORBIDDEN` when an
/// operator session's step-up is stale.
pub fn require_step_up(state: &AppState, caller: &Caller, headers: &HeaderMap) -> Result<(), VoltaError> {
    match caller {
        Caller::Anonymous => Err(VoltaError::AuthRequired),
        Caller::Principal { .. } => Ok(()),
        Caller::Operator { .. } => {
            let token = bearer_token(headers)
                .or_else(|| cookie_token(headers))
                .ok_or(VoltaError::AuthRequired)?;
            match state.operator.session_step_up_unix(&token) {
                Some(step_up) if unix_now().saturating_sub(step_up) <= STEP_UP_WINDOW_SECONDS => {
                    Ok(())
                }
                _ => Err(VoltaError::Forbidden(
                    "fresh WebAuthn step-up required".to_string(),
                )),
            }
        }
    }
}

/// Read a header as an owned string.
fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get(name)?.to_str().ok().map(str::to_string)
}
