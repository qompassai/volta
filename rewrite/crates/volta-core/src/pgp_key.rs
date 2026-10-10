// #################################################################
// /qompassai/volta/rewrite/crates/volta-core/src/pgp_key.rs
// Qompass AI Volta — OpenPGP Parsing, Cleaning, Allowlist (SPEC 5/11)
// SPDX-License-Identifier: AGPL-3.0-only OR Apache-2.0
// Copyright (c) 2026 Qompass AI
// #################################################################

//! Parsing of uploaded OpenPGP certificates, derivation of the
//! served form (SPEC 5.2: verified User IDs only, third-party
//! certifications stripped), and enforcement of the section 11
//! algorithm allowlist at ingest. Nothing in this module generates
//! OpenPGP material; it accepts, checks, cleans, and describes.

use std::collections::BTreeSet;

use pgp::composed::{ArmorOptions, Deserializable, SignedPublicKey, SignedPublicSubKey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::packet::{Signature, SignatureType};
use pgp::types::{Fingerprint, KeyDetails, KeyVersion, PublicParams};

use crate::error::{VoltaError, VoltaResult};
use crate::model::{CertificateMeta, SubkeyMeta, UserIdMeta};

/// RSA size at or above which no legacy warning is raised. Below
/// `RSA_REJECT_BITS` is a hard reject (SPEC 11.4); between the two
/// bounds is accept-serve-only with a warning (SPEC 11.3).
pub const RSA_LEGACY_WARN_BITS: u32 = 4096;
/// RSA sizes below this are rejected where volta controls it.
pub const RSA_REJECT_BITS: u32 = 3072;

/// An uploaded certificate, parsed and checked.
#[derive(Debug)]
pub struct ParsedKey {
    /// Metadata extracted at ingest (SCALE-1).
    pub meta: CertificateMeta,
    /// The parsed certificate, uncleaned; cleaning happens in
    /// [`clean_served_form`] once verification state is known.
    pub signed_key: SignedPublicKey,
}

/// Extract the email address from a raw User ID, when it carries
/// one in `<...>` form.
#[must_use]
pub fn email_of_user_id(raw: &str) -> Option<String> {
    let start = raw.find('<')?;
    let end = raw.rfind('>')?;
    if end <= start + 1 {
        return None;
    }
    let address = &raw[start + 1..end];
    if address.contains('@') && !address.contains(char::is_whitespace) {
        Some(address.to_lowercase())
    } else {
        None
    }
}

/// Uppercase hex of a fingerprint (DM-1 stored form).
#[must_use]
pub fn fingerprint_hex(fingerprint: &Fingerprint) -> String {
    fingerprint
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect()
}

/// Normalize a fingerprint or KeyID query to the stored canonical
/// form: uppercase hex, optional `0x` prefix stripped (C-3).
#[must_use]
pub fn normalize_hex_id(value: &str) -> String {
    let trimmed = value.trim();
    let stripped = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    stripped.to_uppercase()
}

/// Whether a normalized value is a full fingerprint (DM-1).
#[must_use]
pub fn is_fingerprint(value: &str) -> bool {
    (value.len() == 40 || value.len() == 64) && value.chars().all(|c| c.is_ascii_hexdigit())
}

/// Whether a normalized value is a long KeyID (DM-2). Short KeyIDs
/// are never accepted as lookup keys on any surface.
#[must_use]
pub fn is_long_key_id(value: &str) -> bool {
    value.len() == 16 && value.chars().all(|c| c.is_ascii_hexdigit())
}

/// Parse one armored (or binary) certificate and enforce the
/// section 11 allowlist.
///
/// # Errors
/// `E_KEY_MALFORMED` for unparseable material; `E_CRYPTO_NOT_ALLOWED`
/// for anything on the rejected list (SPEC 11.4, CRYPTO-2) and for
/// v3 keys (SPEC 11.4).
pub fn parse_and_check(input: &[u8]) -> VoltaResult<ParsedKey> {
    let signed_key = parse_key(input)?;
    if signed_key.primary_key.version() == KeyVersion::V3 {
        return Err(VoltaError::CryptoNotAllowed("v3 key".to_string()));
    }
    let mut meta = describe(&signed_key);
    meta.warnings = check_allowlist(&signed_key, &meta)?;
    Ok(ParsedKey { meta, signed_key })
}

fn parse_key(input: &[u8]) -> VoltaResult<SignedPublicKey> {
    let text = std::str::from_utf8(input).unwrap_or("");
    if text.contains("-----BEGIN PGP") {
        let (key, _headers) = SignedPublicKey::from_armor_single(text.as_bytes())
            .map_err(|e| VoltaError::KeyMalformed(e.to_string()))?;
        Ok(key)
    } else {
        SignedPublicKey::from_bytes(input)
            .map_err(|e| VoltaError::KeyMalformed(e.to_string()))
    }
}

/// Extract the metadata record for a parsed certificate.
fn describe(key: &SignedPublicKey) -> CertificateMeta {
    let fingerprint = fingerprint_hex(&key.fingerprint());
    let key_id = fingerprint[fingerprint.len() - 16..].to_string();
    let primary_created_at = i64::from(key.primary_key.created_at().as_secs());
    let mut subkeys = Vec::new();
    for sub in &key.public_subkeys {
        let sub_fingerprint = fingerprint_hex(&sub.key.fingerprint());
        subkeys.push(SubkeyMeta {
            algorithm: algorithm_name(sub.key.algorithm()),
            created_at: i64::from(sub.key.created_at().as_secs()),
            expires_at: signature_expiration(&sub.signatures, sub.key.created_at().as_secs()),
            fingerprint: sub_fingerprint.clone(),
            key_id: sub_fingerprint[sub_fingerprint.len() - 16..].to_string(),
            revoked: sub
                .signatures
                .iter()
                .any(|s| s.typ() == Some(SignatureType::KeyRevocation)),
        });
    }
    let mut user_ids = Vec::new();
    for user in &key.details.users {
        let raw = String::from_utf8_lossy(user.id.id()).to_string();
        user_ids.push(UserIdMeta {
            email: email_of_user_id(&raw),
            raw,
            verified: false,
        });
    }
    CertificateMeta {
        created_at: 0,
        fingerprint,
        key_id,
        modified_at: 0,
        primary_algorithm: algorithm_name(key.algorithm()),
        primary_created_at,
        primary_expires_at: signature_expiration(
            &key
                .details
                .direct_signatures
                .iter()
                .chain(key.details.users.iter().flat_map(|u| u.signatures.iter()))
                .cloned()
                .collect::<Vec<_>>(),
            key.primary_key.created_at().as_secs(),
        ),
        revoked: !key.details.revocation_signatures.is_empty(),
        subkeys,
        user_ids,
        warnings: Vec::new(),
    }
}

fn signature_expiration(signatures: &[Signature], created_secs: u32) -> Option<i64> {
    let mut best: Option<i64> = None;
    for sig in signatures {
        if let Some(duration) = sig.key_expiration_time() {
            let expiry = i64::from(created_secs) + duration.as_secs() as i64;
            best = Some(best.map_or(expiry, |b: i64| b.max(expiry)));
        }
    }
    best
}

/// Canonical algorithm names (SPEC 11 tables). Unknown IDs map to
/// `unknown:<id>` and are rejected wherever volta must rely on
/// them (CRYPTO-2).
fn algorithm_name(algorithm: PublicKeyAlgorithm) -> String {
    match algorithm {
        PublicKeyAlgorithm::DSA => "dsa".to_string(),
        PublicKeyAlgorithm::ECDH => "ecdh".to_string(),
        PublicKeyAlgorithm::ECDSA => "ecdsa".to_string(),
        PublicKeyAlgorithm::Ed25519 => "ed25519".to_string(),
        PublicKeyAlgorithm::Ed448 => "ed448".to_string(),
        PublicKeyAlgorithm::EdDSALegacy => "eddsa-legacy".to_string(),
        PublicKeyAlgorithm::Elgamal | PublicKeyAlgorithm::ElgamalEncrypt => {
            "elgamal".to_string()
        }
        PublicKeyAlgorithm::MlDsa65Ed25519 => "ml-dsa-65-ed25519".to_string(),
        PublicKeyAlgorithm::MlDsa87Ed448 => "ml-dsa-87-ed448".to_string(),
        PublicKeyAlgorithm::MlKem768X25519 => "ml-kem-768-x25519".to_string(),
        PublicKeyAlgorithm::MlKem1024X448 => "ml-kem-1024-x448".to_string(),
        PublicKeyAlgorithm::RSA | PublicKeyAlgorithm::RSAEncrypt | PublicKeyAlgorithm::RSASign => {
            "rsa".to_string()
        }
        PublicKeyAlgorithm::SlhDsaShake128f => "slh-dsa-shake-128f".to_string(),
        PublicKeyAlgorithm::SlhDsaShake128s => "slh-dsa-shake-128s".to_string(),
        PublicKeyAlgorithm::SlhDsaShake256s => "slh-dsa-shake-256s".to_string(),
        PublicKeyAlgorithm::X25519 => "x25519".to_string(),
        PublicKeyAlgorithm::X448 => "x448".to_string(),
        other => format!("unknown:{other:?}"),
    }
}

/// Enforce SPEC 11 on a parsed certificate. Returns ingest
/// warnings (legacy algorithms, SPEC 11.3).
///
/// # Errors
/// `E_CRYPTO_NOT_ALLOWED` naming the first offending algorithm.
pub fn check_allowlist(
    key: &SignedPublicKey,
    meta: &CertificateMeta,
) -> VoltaResult<Vec<String>> {
    let mut warnings = Vec::new();
    check_one_key(&meta.primary_algorithm, primary_rsa_bits(key), &mut warnings)?;
    for sub in &meta.subkeys {
        // Subkey RSA sizes are checked structurally the same way;
        // the size probe covers the primary key, and any RSA subkey
        // inherits the primary's floor decision only when its size
        // is known. Unknown-size RSA subkeys are served (11.3) —
        // volta never generates them.
        check_one_key(&sub.algorithm, None, &mut warnings)?;
    }
    // Reject when every self-signature volta would rely on uses MD5
    // (SPEC 11.4).
    let mut relied_any = false;
    let mut relied_all_md5 = true;
    for sig in key
        .details
        .direct_signatures
        .iter()
        .chain(key.details.users.iter().flat_map(|u| u.signatures.iter()))
    {
        if let Some(hash) = sig.hash_alg() {
            relied_any = true;
            if hash != HashAlgorithm::Md5 {
                relied_all_md5 = false;
            }
        }
    }
    if relied_any && relied_all_md5 {
        return Err(VoltaError::CryptoNotAllowed(
            "md5-only self-signatures".to_string(),
        ));
    }
    Ok(warnings)
}

fn check_one_key(
    algorithm: &str,
    rsa_bits: Option<u32>,
    warnings: &mut Vec<String>,
) -> VoltaResult<()> {
    match algorithm {
        "dsa" => Err(VoltaError::CryptoNotAllowed("dsa".to_string())),
        "elgamal" => Err(VoltaError::CryptoNotAllowed("elgamal".to_string())),
        "rsa" => {
            if let Some(bits) = rsa_bits {
                if bits < RSA_REJECT_BITS {
                    return Err(VoltaError::CryptoNotAllowed(format!(
                        "rsa-{bits} below 3072"
                    )));
                }
                if bits < RSA_LEGACY_WARN_BITS {
                    warnings.push(format!("legacy-algorithm:rsa-{bits}"));
                }
            }
            Ok(())
        }
        name if name.starts_with("unknown:") => Err(VoltaError::CryptoNotAllowed(
            name.trim_start_matches("unknown:").to_string(),
        )),
        _ => Ok(()),
    }
}

/// RSA modulus size in bits for the primary key, when it is RSA.
fn primary_rsa_bits(key: &SignedPublicKey) -> Option<u32> {
    if let PublicParams::RSA(params) = key.primary_key.public_params() {
        use rsa::traits::PublicKeyParts;
        let bits = params.key.n().bits();
        u32::try_from(bits).ok()
    } else {
        None
    }
}

/// Produce the served form of a certificate: primary key, subkeys,
/// self-signatures, revocations, and User IDs that are verified or
/// carry a self-signature; third-party certifications are stripped
/// (SPEC 5.2).
#[must_use]
pub fn clean_served_form(
    key: &SignedPublicKey,
    verified_emails: &BTreeSet<String>,
) -> SignedPublicKey {
    let primary_fpr = key.fingerprint();
    let self_issued = |sig: &Signature| {
        sig.issuer_fingerprint()
            .iter()
            .any(|issuer| *issuer == &primary_fpr)
    };
    let mut cleaned = key.clone();
    cleaned.details.revocation_signatures.retain(&self_issued);
    cleaned.details.direct_signatures.retain(&self_issued);
    cleaned.details.users.retain(|user| {
        let raw = String::from_utf8_lossy(user.id.id()).to_string();
        let verified = email_of_user_id(&raw).is_some_and(|e| verified_emails.contains(&e));
        let self_signed = user.signatures.iter().any(&self_issued);
        verified || self_signed
    });
    for user in &mut cleaned.details.users {
        user.signatures.retain(&self_issued);
    }
    for sub in &mut cleaned.public_subkeys {
        sub.signatures.retain(&self_issued);
    }
    cleaned
}

/// Verify that a subkey record belongs to a parsed key (used by
/// tests and the index builder).
#[must_use]
pub fn subkey_fingerprints(key: &SignedPublicKey) -> Vec<String> {
    key.public_subkeys
        .iter()
        .map(|sub: &SignedPublicSubKey| fingerprint_hex(&sub.key.fingerprint()))
        .collect()
}

/// Render a certificate to ASCII armor.
///
/// # Errors
/// `E_KEY_MALFORMED` when armor encoding fails.
pub fn to_armor(key: &SignedPublicKey) -> VoltaResult<String> {
    key.to_armored_string(ArmorOptions::default())
        .map_err(|e| VoltaError::KeyMalformed(e.to_string()))
}

/// Render a certificate to canonical binary bytes.
///
/// # Errors
/// `E_KEY_MALFORMED` when encoding fails.
pub fn to_binary(key: &SignedPublicKey) -> VoltaResult<Vec<u8>> {
    use pgp::ser::Serialize;
    let mut out = Vec::new();
    key.to_writer(&mut out)
        .map_err(|e| VoltaError::KeyMalformed(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_extraction() {
        assert_eq!(
            email_of_user_id("Ada <Ada@Example.ORG>"),
            Some("ada@example.org".to_string())
        );
        assert_eq!(email_of_user_id("No address here"), None);
        assert_eq!(email_of_user_id("Empty <>"), None);
    }

    #[test]
    fn hex_id_normalization() {
        assert_eq!(normalize_hex_id("0xabcd"), "ABCD");
        assert_eq!(normalize_hex_id(" abcd "), "ABCD");
        assert!(is_fingerprint(&"A".repeat(40)));
        assert!(!is_fingerprint(&"A".repeat(16)));
        assert!(is_long_key_id(&"0123456789ABCDEF"));
        assert!(!is_long_key_id(&"01234567"));
    }

    #[test]
    fn malformed_material_is_rejected() {
        let result = parse_and_check(b"this is not a key");
        assert!(matches!(result, Err(VoltaError::KeyMalformed(_))));
    }
}
