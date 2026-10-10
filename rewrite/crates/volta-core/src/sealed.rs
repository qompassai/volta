// #################################################################
// /qompassai/volta/rewrite/crates/volta-core/src/sealed.rs
// Qompass AI Volta — Sealed Tokens (SPEC 5.4)
// SPDX-License-Identifier: AGPL-3.0-only OR Apache-2.0
// Copyright (c) 2026 Qompass AI
// #################################################################

//! Sealed tokens for verify/manage links, wire-compatible with the
//! predecessor's documented construction (TOK-1): AES-256-GCM under
//! an HKDF-SHA256 key derived from the configured token secret with
//! salt `b"volta"`. Tokens are stateless; validity is the two-sided
//! lifetime check of TOK-4.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{VoltaError, VoltaResult};

/// Maximum plaintext accepted by sealing (TOK-2).
pub const SEALED_LEN_MAX: usize = 64 * 1024;
/// Nonce length of the wire format (TOK-1).
const NONCE_LEN: usize = 12;

/// The token payload (TOK-3). JSON keys serialize alphabetically.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TokenPayload {
    /// Addresses the token acts on.
    pub addresses: Vec<String>,
    /// Unix seconds at sealing time.
    pub created_at: i64,
    /// Fingerprint the token acts on.
    pub fingerprint: String,
    /// `manage` or `verify` (TOK-5).
    #[serde(rename = "type")]
    pub token_type: String,
}

/// A sealer/unsealer bound to one token secret. The secret itself is
/// held zeroizing and never logged (TOK-5, GLOB-4).
pub struct TokenSealer {
    cipher: Aes256Gcm,
}

impl TokenSealer {
    /// Derive the sealing key from a configured secret (TOK-1).
    #[must_use]
    pub fn new(secret: &[u8]) -> Self {
        let hkdf = Hkdf::<Sha256>::new(Some(b"volta"), secret);
        let mut key_bytes = Zeroizing::new([0u8; 32]);
        hkdf.expand(&[], key_bytes.as_mut())
            .expect("32-byte HKDF output is always in bounds");
        let cipher = Aes256Gcm::new_from_slice(key_bytes.as_ref())
            .expect("32-byte key is the AES-256 key size");
        Self { cipher }
    }

    /// Seal a payload; returns the base64url wire token (TOK-1).
    ///
    /// # Errors
    /// `E_VALIDATION` when the payload exceeds `SEALED_LEN_MAX`.
    pub fn seal(&self, payload: &TokenPayload) -> VoltaResult<String> {
        let plaintext = serde_json::to_vec(payload)
            .map_err(|e| VoltaError::Validation(e.to_string()))?;
        if plaintext.len() > SEALED_LEN_MAX {
            return Err(VoltaError::Validation("token payload too large".to_string()));
        }
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(
                nonce,
                Payload {
                    aad: &[],
                    msg: &plaintext,
                },
            )
            .map_err(|_| VoltaError::TokenInvalid)?;
        let mut wire = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        wire.extend_from_slice(&nonce_bytes);
        wire.extend_from_slice(&ciphertext);
        Ok(URL_SAFE_NO_PAD.encode(&wire))
    }

    /// Unseal and fully validate a token: construction (TOK-2),
    /// payload type (TOK-3, when `expected_type` is given), and the
    /// two-sided lifetime check (TOK-4).
    ///
    /// # Errors
    /// `E_TOKEN_INVALID`, `E_TOKEN_EXPIRED`, `E_TOKEN_FUTURE_DATED`,
    /// or `E_TOKEN_TYPE_MISMATCH`, per SPEC 14.2.
    pub fn unseal_and_check(
        &self,
        token: &str,
        expected_type: Option<&str>,
        now_unix: i64,
        validity_seconds: i64,
    ) -> VoltaResult<TokenPayload> {
        let payload = self.unseal(token)?;
        if let Some(expected) = expected_type {
            if payload.token_type != expected {
                return Err(VoltaError::TokenTypeMismatch);
            }
        }
        if payload.created_at > now_unix {
            return Err(VoltaError::TokenFutureDated);
        }
        if now_unix - payload.created_at > validity_seconds {
            return Err(VoltaError::TokenExpired);
        }
        Ok(payload)
    }

    fn unseal(&self, token: &str) -> VoltaResult<TokenPayload> {
        if token.len() > SEALED_LEN_MAX * 2 {
            return Err(VoltaError::TokenInvalid);
        }
        let wire = URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|_| VoltaError::TokenInvalid)?;
        if wire.len() <= NONCE_LEN + 16 {
            return Err(VoltaError::TokenInvalid);
        }
        let (nonce_bytes, ciphertext) = wire.split_at(NONCE_LEN);
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = self
            .cipher
            .decrypt(
                nonce,
                Payload {
                    aad: &[],
                    msg: ciphertext,
                },
            )
            .map_err(|_| VoltaError::TokenInvalid)?;
        if plaintext.len() > SEALED_LEN_MAX {
            return Err(VoltaError::TokenInvalid);
        }
        serde_json::from_slice(&plaintext).map_err(|_| VoltaError::TokenInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(created_at: i64, token_type: &str) -> TokenPayload {
        TokenPayload {
            addresses: vec!["ada@example.org".to_string()],
            created_at,
            fingerprint: "A".repeat(40),
            token_type: token_type.to_string(),
        }
    }

    #[test]
    fn round_trip() {
        let sealer = TokenSealer::new(b"test-secret");
        let token = sealer.seal(&payload(1_000, "verify")).expect("seal");
        let out = sealer
            .unseal_and_check(&token, Some("verify"), 1_500, 3600)
            .expect("unseal");
        assert_eq!(out.fingerprint, "A".repeat(40));
    }

    #[test]
    fn tampered_token_is_invalid_never_panics() {
        let sealer = TokenSealer::new(b"test-secret");
        let mut token = sealer.seal(&payload(1_000, "verify")).expect("seal");
        token.push('A');
        assert!(matches!(
            sealer.unseal_and_check(&token, None, 1_500, 3600),
            Err(VoltaError::TokenInvalid)
        ));
    }

    #[test]
    fn wrong_secret_is_invalid() {
        let token = TokenSealer::new(b"one").seal(&payload(1_000, "verify")).expect("seal");
        assert!(matches!(
            TokenSealer::new(b"two").unseal_and_check(&token, None, 1_500, 3600),
            Err(VoltaError::TokenInvalid)
        ));
    }

    #[test]
    fn expired_and_future_dated_are_distinct() {
        let sealer = TokenSealer::new(b"s");
        let old = sealer.seal(&payload(1_000, "verify")).expect("seal");
        assert!(matches!(
            sealer.unseal_and_check(&old, None, 1_000 + 3601, 3600),
            Err(VoltaError::TokenExpired)
        ));
        let future = sealer.seal(&payload(5_000, "verify")).expect("seal");
        assert!(matches!(
            sealer.unseal_and_check(&future, None, 4_000, 3600),
            Err(VoltaError::TokenFutureDated)
        ));
    }

    #[test]
    fn type_mismatch_is_distinct() {
        let sealer = TokenSealer::new(b"s");
        let token = sealer.seal(&payload(1_000, "manage")).expect("seal");
        assert!(matches!(
            sealer.unseal_and_check(&token, Some("verify"), 1_500, 3600),
            Err(VoltaError::TokenTypeMismatch)
        ));
    }
}
