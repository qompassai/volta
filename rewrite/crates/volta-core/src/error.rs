// #################################################################
// /qompassai/volta/rewrite/crates/volta-core/src/error.rs
// Qompass AI Volta — Error Taxonomy (SPEC section 14)
// SPDX-License-Identifier: AGPL-3.0-only OR Apache-2.0
// Copyright (c) 2026 Qompass AI
// #################################################################

#![allow(clippy::module_name_repetitions)]

//! The single error type for all volta surfaces. Every variant maps
//! to exactly one stable error code (SPEC ERR-1), one HTTP status,
//! and one retryable flag (SPEC ERR-2). Error values never carry
//! secret material (SPEC ERR-3).

use thiserror::Error;

/// Volta's structured error. The `code` is the machine-readable
/// contract; the message is for humans and logs.
#[derive(Debug, Error)]
pub enum VoltaError {
    /// `E_AUDIENCE_MISMATCH` — ephemeral key used outside its
    /// audience or purpose (EPH-3).
    #[error("ephemeral key used outside its audience or purpose")]
    AudienceMismatch,
    /// `E_AUTH_REQUIRED` — no or insufficient credential.
    #[error("authentication required")]
    AuthRequired,
    /// `E_CARD_UNSIGNED` — A2A card signing unavailable (A2A-1).
    #[error("agent card is unsigned; A2A endpoints refuse to serve")]
    CardUnsigned,
    /// `E_CONFIG_INVALID` — configuration failed validation.
    #[error("invalid configuration: {0}")]
    ConfigInvalid(String),
    /// `E_CRYPTO_NOT_ALLOWED` — algorithm or suite rejected (SPEC 11).
    #[error("algorithm or suite not allowed: {0}")]
    CryptoNotAllowed(String),
    /// `E_CUSTODY_MISMATCH` — operation incompatible with custody.
    #[error("operation incompatible with the key's custody mode")]
    CustodyMismatch,
    /// `E_FORBIDDEN` — authenticated but lacking the permission.
    #[error("forbidden: {0}")]
    Forbidden(String),
    /// `E_HKP_BAD_SEARCH` — HKP search outside the HKP-2 grammar.
    #[error("HKP search outside the accepted grammar")]
    HkpBadSearch,
    /// `E_HKP_UNSUPPORTED_OP` — HKP op outside get/index/stats.
    #[error("HKP operation not supported")]
    HkpUnsupportedOp,
    /// `E_INTERNAL_ONLY` — internal surface reached without the edge.
    #[error("internal surface reached without the local edge")]
    InternalOnly,
    /// `E_KEY_EXPIRED` — ephemeral key past its hard TTL (EPH-1).
    #[error("key expired")]
    KeyExpired,
    /// `E_KEY_MALFORMED` — unparseable OpenPGP material.
    #[error("unparseable OpenPGP material: {0}")]
    KeyMalformed(String),
    /// `E_KEY_NOT_FOUND` — no visible key for the query.
    #[error("key not found")]
    KeyNotFound,
    /// `E_KEY_REVOKED` — ephemeral key revoked.
    #[error("key revoked")]
    KeyRevoked,
    /// `E_NOT_FOUND` — unknown route on a new surface (ERR-4).
    #[error("not found")]
    NotFound,
    /// `E_PROXY_AUTH_FAILED` — hop authentication rejected.
    #[error("proxy hop authentication failed")]
    ProxyAuthFailed,
    /// `E_PROXY_CHAIN_TOO_DEEP` — cross-instance depth budget spent.
    #[error("proxy chain depth budget exceeded")]
    ProxyChainTooDeep,
    /// `E_PROXY_DNS_FAILED` — in-chain name resolution failed.
    #[error("proxy chain name resolution failed")]
    ProxyDnsFailed,
    /// `E_PROXY_HOP_FAILED` — hop refused, reset, or closed.
    #[error("proxy hop failed: {0}")]
    ProxyHopFailed(String),
    /// `E_PROXY_TIMEOUT` — per-hop or whole-chain deadline exceeded.
    #[error("proxy chain timed out")]
    ProxyTimeout,
    /// `E_PROXY_TLS_PIN_MISMATCH` — SPKI pin mismatch on a TLS hop.
    #[error("proxy TLS SPKI pin mismatch")]
    ProxyTlsPinMismatch,
    /// `E_RATE_LIMITED` — a rate layer rejected the request.
    #[error("rate limited")]
    RateLimited,
    /// `E_RELAY_PEER_MISMATCH` — peer identity differs from its pin.
    #[error("relay peer identity does not match its pinned fingerprint")]
    RelayPeerMismatch,
    /// `E_TOKEN_EXPIRED` — sealed token past validity (TOK-4).
    #[error("sealed token expired")]
    TokenExpired,
    /// `E_TOKEN_FUTURE_DATED` — sealed token created in the future.
    #[error("sealed token is future-dated")]
    TokenFutureDated,
    /// `E_TOKEN_INVALID` — sealed token fails unsealing (TOK-2).
    #[error("sealed token invalid")]
    TokenInvalid,
    /// `E_TOKEN_TYPE_MISMATCH` — verify token in a manage flow etc.
    #[error("sealed token used in the wrong flow")]
    TokenTypeMismatch,
    /// `E_TTL_OUT_OF_BOUNDS` — TTL outside the section 7.2 bounds.
    #[error("ttl_seconds outside the allowed bounds")]
    TtlOutOfBounds,
    /// `E_UPLOAD_TOO_LARGE` — body over the upload cap.
    #[error("upload body too large")]
    UploadTooLarge,
    /// `E_VALIDATION` — request schema violation; names the field.
    #[error("validation failed at field: {0}")]
    Validation(String),
    /// `E_VERIFICATION_ADDRESS_MISMATCH` — VKS-7.
    #[error("verification requested for an address not in the key")]
    VerificationAddressMismatch,
    /// `E_VERIFICATION_REQUIRED` — needs a published binding.
    #[error("operation requires a published address binding")]
    VerificationRequired,
    /// `E_WEBAUTHN_ASSERTION_INVALID` — assertion check failed.
    #[error("WebAuthn assertion invalid: {0}")]
    WebauthnAssertionInvalid(String),
    /// `E_WEBAUTHN_CHALLENGE_INVALID` — challenge bad/reused/stale.
    #[error("WebAuthn challenge invalid")]
    WebauthnChallengeInvalid,
    /// `E_WEBAUTHN_CLONE_DETECTED` — sign counter did not increase.
    #[error("WebAuthn clone detected; credential locked")]
    WebauthnCloneDetected,
    /// `E_WEBAUTHN_ORIGIN_MISMATCH` — origin differs from config.
    #[error("WebAuthn origin mismatch")]
    WebauthnOriginMismatch,
    /// `E_WEBAUTHN_UV_REQUIRED` — assertion lacks the UV flag (WA-2).
    #[error("WebAuthn user verification required but not performed")]
    WebauthnUvRequired,
}

impl VoltaError {
    /// The stable machine-readable code (SPEC 14.2).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::AudienceMismatch => "E_AUDIENCE_MISMATCH",
            Self::AuthRequired => "E_AUTH_REQUIRED",
            Self::CardUnsigned => "E_CARD_UNSIGNED",
            Self::ConfigInvalid(_) => "E_CONFIG_INVALID",
            Self::CryptoNotAllowed(_) => "E_CRYPTO_NOT_ALLOWED",
            Self::CustodyMismatch => "E_CUSTODY_MISMATCH",
            Self::Forbidden(_) => "E_FORBIDDEN",
            Self::HkpBadSearch => "E_HKP_BAD_SEARCH",
            Self::HkpUnsupportedOp => "E_HKP_UNSUPPORTED_OP",
            Self::InternalOnly => "E_INTERNAL_ONLY",
            Self::KeyExpired => "E_KEY_EXPIRED",
            Self::KeyMalformed(_) => "E_KEY_MALFORMED",
            Self::KeyNotFound => "E_KEY_NOT_FOUND",
            Self::KeyRevoked => "E_KEY_REVOKED",
            Self::NotFound => "E_NOT_FOUND",
            Self::ProxyAuthFailed => "E_PROXY_AUTH_FAILED",
            Self::ProxyChainTooDeep => "E_PROXY_CHAIN_TOO_DEEP",
            Self::ProxyDnsFailed => "E_PROXY_DNS_FAILED",
            Self::ProxyHopFailed(_) => "E_PROXY_HOP_FAILED",
            Self::ProxyTimeout => "E_PROXY_TIMEOUT",
            Self::ProxyTlsPinMismatch => "E_PROXY_TLS_PIN_MISMATCH",
            Self::RateLimited => "E_RATE_LIMITED",
            Self::RelayPeerMismatch => "E_RELAY_PEER_MISMATCH",
            Self::TokenExpired => "E_TOKEN_EXPIRED",
            Self::TokenFutureDated => "E_TOKEN_FUTURE_DATED",
            Self::TokenInvalid => "E_TOKEN_INVALID",
            Self::TokenTypeMismatch => "E_TOKEN_TYPE_MISMATCH",
            Self::TtlOutOfBounds => "E_TTL_OUT_OF_BOUNDS",
            Self::UploadTooLarge => "E_UPLOAD_TOO_LARGE",
            Self::Validation(_) => "E_VALIDATION",
            Self::VerificationAddressMismatch => "E_VERIFICATION_ADDRESS_MISMATCH",
            Self::VerificationRequired => "E_VERIFICATION_REQUIRED",
            Self::WebauthnAssertionInvalid(_) => "E_WEBAUTHN_ASSERTION_INVALID",
            Self::WebauthnChallengeInvalid => "E_WEBAUTHN_CHALLENGE_INVALID",
            Self::WebauthnCloneDetected => "E_WEBAUTHN_CLONE_DETECTED",
            Self::WebauthnOriginMismatch => "E_WEBAUTHN_ORIGIN_MISMATCH",
            Self::WebauthnUvRequired => "E_WEBAUTHN_UV_REQUIRED",
        }
    }

    /// The HTTP status for the code (SPEC 14.2).
    #[must_use]
    pub fn http_status(&self) -> u16 {
        match self {
            Self::AudienceMismatch
            | Self::Forbidden(_)
            | Self::InternalOnly
            | Self::RelayPeerMismatch
            | Self::VerificationRequired => 403,
            Self::AuthRequired
            | Self::WebauthnAssertionInvalid(_)
            | Self::WebauthnCloneDetected
            | Self::WebauthnOriginMismatch
            | Self::WebauthnUvRequired => 401,
            Self::CardUnsigned => 503,
            Self::ConfigInvalid(_)
            | Self::CryptoNotAllowed(_)
            | Self::CustodyMismatch
            | Self::HkpBadSearch
            | Self::HkpUnsupportedOp
            | Self::KeyMalformed(_)
            | Self::TokenFutureDated
            | Self::TokenInvalid
            | Self::TokenTypeMismatch
            | Self::TtlOutOfBounds
            | Self::Validation(_)
            | Self::VerificationAddressMismatch
            | Self::WebauthnChallengeInvalid => 400,
            Self::KeyExpired | Self::KeyRevoked | Self::TokenExpired => 410,
            Self::KeyNotFound | Self::NotFound => 404,
            Self::ProxyAuthFailed
            | Self::ProxyChainTooDeep
            | Self::ProxyDnsFailed
            | Self::ProxyHopFailed(_)
            | Self::ProxyTlsPinMismatch => 502,
            Self::ProxyTimeout => 504,
            Self::RateLimited => 429,
            Self::UploadTooLarge => 413,
        }
    }

    /// Whether retrying the identical request can succeed (ERR-2).
    /// For proxy errors a retry re-runs the same chain (CHAIN-2).
    #[must_use]
    pub fn retryable(&self) -> bool {
        matches!(
            self,
            Self::CardUnsigned | Self::ProxyHopFailed(_) | Self::ProxyTimeout | Self::RateLimited
        )
    }
}

/// Convenience alias used across the rewrite.
pub type VoltaResult<T> = Result<T, VoltaError>;
