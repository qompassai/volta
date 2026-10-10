// #################################################################
// /qompassai/volta/rewrite/crates/volta-core/src/model.rs
// Qompass AI Volta — Data Model (SPEC section 5)
// SPDX-License-Identifier: AGPL-3.0-only OR Apache-2.0
// Copyright (c) 2026 Qompass AI
// #################################################################

//! Entity records exchanged between the store and the surfaces.
//! Field order is alphabetical within each record (ORD-1).

use serde::{Deserialize, Serialize};

/// Publication status of one (address, certificate) binding (SPEC 5.2).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BindingStatus {
    /// Verification mail sent, link not yet followed.
    Pending,
    /// Verified; the address is searchable (DM-PUB-1).
    Published,
    /// The certificate carrying this address was revoked.
    Revoked,
    /// Stored but not verified; never disclosed (DM-PUB-1).
    Unpublished,
}

impl BindingStatus {
    /// The VKS vocabulary string (SPEC 5.2).
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Published => "published",
            Self::Revoked => "revoked",
            Self::Unpublished => "unpublished",
        }
    }

    /// Parse the VKS vocabulary string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "published" => Some(Self::Published),
            "revoked" => Some(Self::Revoked),
            "unpublished" => Some(Self::Unpublished),
            _ => None,
        }
    }
}

/// Metadata for one subkey of a stored certificate.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SubkeyMeta {
    /// RFC 9580/9980 algorithm name.
    pub algorithm: String,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds, when the subkey expires.
    pub expires_at: Option<i64>,
    /// Full fingerprint, uppercase hex.
    pub fingerprint: String,
    /// Long KeyID: low 16 hex chars of the fingerprint (DM-2).
    pub key_id: String,
    /// Whether a valid revocation for this subkey is on file.
    pub revoked: bool,
}

/// Metadata for one User ID of a stored certificate.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserIdMeta {
    /// The email address parsed from the User ID, when present.
    pub email: Option<String>,
    /// The raw User ID string as it appears in the certificate.
    pub raw: String,
    /// Whether the address binding is published (DM-PUB-1).
    pub verified: bool,
}

/// A stored certificate's metadata (SPEC 5.2 Certificate).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CertificateMeta {
    /// Unix seconds of first ingest.
    pub created_at: i64,
    /// Full fingerprint, uppercase hex (DM-1). Primary key.
    pub fingerprint: String,
    /// Long KeyID of the primary key (DM-2).
    pub key_id: String,
    /// Unix seconds of last ingest change.
    pub modified_at: i64,
    /// RFC 9580/9980 algorithm name of the primary key.
    pub primary_algorithm: String,
    /// Unix seconds; the primary key's creation time.
    pub primary_created_at: i64,
    /// Unix seconds; the primary key's expiration, when set.
    pub primary_expires_at: Option<i64>,
    /// Whether a valid revocation for the primary key is on file.
    pub revoked: bool,
    /// Subkey metadata, in certificate order (protocol order).
    pub subkeys: Vec<SubkeyMeta>,
    /// User ID metadata, in certificate order (protocol order).
    pub user_ids: Vec<UserIdMeta>,
    /// Non-fatal ingest warnings, e.g. `legacy-algorithm:rsa-3072`.
    pub warnings: Vec<String>,
}

/// A certificate as served: metadata plus the pre-rendered served
/// form (SCALE-1: derived once at ingest, never on the read path).
#[derive(Clone, Debug)]
pub struct StoredCertificate {
    /// ASCII armor of the served form (the `armor_cache`).
    pub armor: String,
    /// Canonical binary of the served form.
    pub binary: Vec<u8>,
    /// SHA-256 of `binary`, lowercase hex — the content address.
    pub content_sha256: String,
    /// The certificate's metadata.
    pub meta: CertificateMeta,
    /// Monotonic per-certificate revision, for ETags (VKS-3).
    pub revision: i64,
}
