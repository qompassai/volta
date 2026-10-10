//! crates/volta-server/src/http_util.rs - shared HTTP helpers.
//!
//! Dual licensed under AGPL-3.0-only OR Apache-2.0.

use axum::Json;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::json;
use sha2::{Digest, Sha256};
use volta_core::error::VoltaError;

/// Maximum JSON body the new surfaces accept (1 MiB).
pub const BODY_MAX: usize = 1_048_576;

/// Standard base64 encode.
#[must_use]
pub fn b64_encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Standard base64 decode.
pub fn b64_decode(text: &str) -> Result<Vec<u8>, VoltaError> {
    STANDARD
        .decode(text.trim())
        .map_err(|_| VoltaError::Validation("base64 body".to_string()))
}

/// Base64url (no pad) encode.
#[must_use]
pub fn b64u_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Base64url (no pad) decode.
pub fn b64u_decode(text: &str) -> Result<Vec<u8>, VoltaError> {
    URL_SAFE_NO_PAD
        .decode(text.trim())
        .map_err(|_| VoltaError::Validation("base64url value".to_string()))
}

/// Format a unix timestamp as RFC 3339 UTC (`YYYY-MM-DDTHH:MM:SSZ`).
#[must_use]
pub fn rfc3339(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let secs = unix % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

/// Howard Hinnant's civil-from-days algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Lowercase hex SHA-256 of bytes.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Current unix time in seconds.
#[must_use]
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// RFC 9457 problem response for a `VoltaError` (SPEC 14.1):
/// always JSON on the new surfaces, always carrying the code in
/// the `X-Volta-Error-Code` header as well as the body.
pub struct Problem {
    /// The error being rendered.
    pub error: VoltaError,
    /// The request id (uuid v7) for correlation.
    pub request_id: String,
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.error.http_status())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = json!({
            "code": self.error.code(),
            "detail": self.error.to_string(),
            "request_id": self.request_id,
            "status": status.as_u16(),
            "title": self.error.code(),
            "type": "about:blank",
        });
        let mut response = (status, Json(body)).into_response();
        if let Ok(value) = HeaderValue::from_str(self.error.code()) {
            response.headers_mut().insert("x-volta-error-code", value);
        }
        if let Ok(value) = HeaderValue::from_str(&self.request_id) {
            response.headers_mut().insert("x-request-id", value);
        }
        response
    }
}

/// Convenience: build a `Problem` from an error + request id.
#[must_use]
pub fn problem(error: VoltaError, request_id: &str) -> Problem {
    Problem {
        error,
        request_id: request_id.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_known_instants() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_762_000_000), "2025-11-01T12:26:40Z");
    }
}
