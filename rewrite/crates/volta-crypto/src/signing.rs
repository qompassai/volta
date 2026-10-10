// #################################################################
// /qompassai/volta/rewrite/crates/volta-crypto/src/signing.rs
// Qompass AI Volta — Identity Signing (SPEC 9.2, 11.2)
// SPDX-License-Identifier: AGPL-3.0-only OR Apache-2.0
// Copyright (c) 2026 Qompass AI
// #################################################################

//! Native-domain signing: Ed25519 alone, or the volta-native
//! composite Ed25519 + ML-DSA-87 (C-1: labeled non-standard
//! wherever it appears; never encoded as an RFC 9980 algorithm).
//! Composite signatures are `ed25519_sig (64) || ml_dsa_sig`;
//! composite verifying keys are `ml_dsa_vk || ed25519_vk (32)`.
//! A composite verifies only if BOTH halves verify.

use ed25519_dalek::{Signer as EdSigner, SigningKey as EdSigningKey, Verifier as EdVerifier, VerifyingKey as EdVerifyingKey, Signature as EdSignature};
use ml_dsa::{Keypair as _, MlDsa87, Signature as MlDsaSignature, SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use volta_core::error::{VoltaError, VoltaResult};

/// Ed25519 seed / verifying key / signature lengths.
pub const ED25519_LEN: usize = 32;
/// Ed25519 signature length.
pub const ED25519_SIGNATURE_LEN: usize = 64;
/// ML-DSA-87 seed length.
pub const MLDSA87_SEED_LEN: usize = 32;
/// ML-DSA-87 signature encoded length (FIPS 204).
pub const MLDSA87_SIGNATURE_LEN: usize = 4627;
/// ML-DSA-87 verifying key encoded length (FIPS 204).
pub const MLDSA87_VERIFYING_LEN: usize = 2592;
/// Domain-separation context for ML-DSA signatures.
const MLDSA_CONTEXT: &[u8] = b"volta-native-v1";

/// A native identity suite (SPEC 5.2 identity suites, native half).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentitySuite {
    /// Ed25519 alone (`eddsa-ed25519`).
    EddsaEd25519,
    /// Volta-native composite ML-DSA-87 + Ed25519 (C-1).
    VoltaMlDsa87Ed25519,
}

impl IdentitySuite {
    /// Parse the exact suite string (CRYPTO-3).
    ///
    /// # Errors
    /// `E_CRYPTO_NOT_ALLOWED` for any other string.
    pub fn parse(value: &str) -> VoltaResult<Self> {
        match value {
            "eddsa-ed25519" => Ok(Self::EddsaEd25519),
            "volta-mldsa87-ed25519" => Ok(Self::VoltaMlDsa87Ed25519),
            other => Err(VoltaError::CryptoNotAllowed(format!(
                "identity suite {other}"
            ))),
        }
    }

    /// The exact suite string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EddsaEd25519 => "eddsa-ed25519",
            Self::VoltaMlDsa87Ed25519 => "volta-mldsa87-ed25519",
        }
    }

    /// Expected verifying-key length for the suite.
    #[must_use]
    pub fn verifying_key_len(&self) -> usize {
        match self {
            Self::EddsaEd25519 => ED25519_LEN,
            Self::VoltaMlDsa87Ed25519 => MLDSA87_VERIFYING_LEN + ED25519_LEN,
        }
    }

    /// Expected signature length for the suite.
    #[must_use]
    pub fn signature_len(&self) -> usize {
        match self {
            Self::EddsaEd25519 => ED25519_SIGNATURE_LEN,
            Self::VoltaMlDsa87Ed25519 => ED25519_SIGNATURE_LEN + MLDSA87_SIGNATURE_LEN,
        }
    }
}

/// A signing identity. Seeds are held zeroizing.
pub struct IdentitySigner {
    ed25519: EdSigningKey,
    mldsa: Option<MlDsaSigningKey<MlDsa87>>,
    suite: IdentitySuite,
}

impl IdentitySigner {
    /// Build a signer from seed material: Ed25519 takes a 32-byte
    /// seed; the composite takes `ml_dsa_seed (32) || ed_seed (32)`.
    ///
    /// # Errors
    /// `E_CRYPTO_NOT_ALLOWED` on wrong seed length.
    pub fn from_seed(suite: IdentitySuite, seed: &[u8]) -> VoltaResult<Self> {
        match suite {
            IdentitySuite::EddsaEd25519 => {
                let seed: [u8; ED25519_LEN] = seed.try_into().map_err(|_| {
                    VoltaError::CryptoNotAllowed("ed25519 seed length".to_string())
                })?;
                Ok(Self {
                    ed25519: EdSigningKey::from_bytes(&seed),
                    mldsa: None,
                    suite,
                })
            }
            IdentitySuite::VoltaMlDsa87Ed25519 => {
                if seed.len() != MLDSA87_SEED_LEN + ED25519_LEN {
                    return Err(VoltaError::CryptoNotAllowed(
                        "composite seed length".to_string(),
                    ));
                }
                let mldsa_seed = ml_dsa::Seed::try_from(&seed[..MLDSA87_SEED_LEN])
                    .map_err(|_| VoltaError::CryptoNotAllowed("ml-dsa seed".to_string()))?;
                let ed_seed: [u8; ED25519_LEN] = seed[MLDSA87_SEED_LEN..]
                    .try_into()
                    .map_err(|_| VoltaError::CryptoNotAllowed("ed25519 seed".to_string()))?;
                Ok(Self {
                    ed25519: EdSigningKey::from_bytes(&ed_seed),
                    mldsa: Some(MlDsaSigningKey::<MlDsa87>::from_seed(&mldsa_seed)),
                    suite,
                })
            }
        }
    }

    /// Generate a fresh identity from the OS RNG.
    #[must_use]
    pub fn generate(suite: IdentitySuite) -> Self {
        let mut seed = Zeroizing::new(vec![
            0u8;
            match suite {
                IdentitySuite::EddsaEd25519 => ED25519_LEN,
                IdentitySuite::VoltaMlDsa87Ed25519 => MLDSA87_SEED_LEN + ED25519_LEN,
            }
        ]);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
        Self::from_seed(suite, &seed).expect("generated seed has the suite's length")
    }

    /// The suite this signer belongs to.
    #[must_use]
    pub fn suite(&self) -> IdentitySuite {
        self.suite
    }

    /// The verifying key bytes (layout in the module docs).
    #[must_use]
    pub fn verifying_key_bytes(&self) -> Vec<u8> {
        match self.suite {
            IdentitySuite::EddsaEd25519 => self.ed25519.verifying_key().to_bytes().to_vec(),
            IdentitySuite::VoltaMlDsa87Ed25519 => {
                let mldsa = self.mldsa.as_ref().expect("composite signer holds ml-dsa");
                let mut out = mldsa.verifying_key().encode().to_vec();
                out.extend_from_slice(&self.ed25519.verifying_key().to_bytes());
                out
            }
        }
    }

    /// The identity fingerprint: SHA-256 of the verifying key,
    /// uppercase hex (SPEC 5.2 native-suite identity fingerprint).
    #[must_use]
    pub fn fingerprint(&self) -> String {
        fingerprint_of(&self.verifying_key_bytes())
    }

    /// Sign a message. Composite output layout in module docs.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let ed_signature = self.ed25519.sign(message);
        match self.suite {
            IdentitySuite::EddsaEd25519 => ed_signature.to_bytes().to_vec(),
            IdentitySuite::VoltaMlDsa87Ed25519 => {
                let mldsa = self.mldsa.as_ref().expect("composite signer holds ml-dsa");
                // Domain separation for the ML-DSA half: the
                // context string is framed into the message, so
                // the signature crate's default (empty) ML-DSA
                // context is consistent between sign and verify.
                let mut framed = MLDSA_CONTEXT.to_vec();
                framed.extend_from_slice(message);
                let mldsa_signature =
                    ml_dsa::Signer::sign(mldsa, &framed) as ml_dsa::Signature<MlDsa87>;
                let mut out = ed_signature.to_bytes().to_vec();
                out.extend_from_slice(&mldsa_signature.encode());
                out
            }
        }
    }
}

/// SHA-256 fingerprint (uppercase hex) of verifying-key bytes.
#[must_use]
pub fn fingerprint_of(verifying_key: &[u8]) -> String {
    Sha256::digest(verifying_key)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect()
}

/// Verify a signature under a suite verifying key. Strict length
/// checks first; a composite verifies only if both halves verify.
///
/// # Errors
/// `E_CRYPTO_NOT_ALLOWED` on malformed key or signature lengths.
/// A well-formed but wrong signature is `Ok(false)`, not an error.
pub fn verify(
    suite: IdentitySuite,
    verifying_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> VoltaResult<bool> {
    if verifying_key.len() != suite.verifying_key_len() || signature.len() != suite.signature_len()
    {
        return Err(VoltaError::CryptoNotAllowed(
            "identity key/signature length".to_string(),
        ));
    }
    match suite {
        IdentitySuite::EddsaEd25519 => {
            let vk = EdVerifyingKey::from_bytes(
                verifying_key
                    .try_into()
                    .map_err(|_| VoltaError::CryptoNotAllowed("ed25519 key".to_string()))?,
            )
            .map_err(|_| VoltaError::CryptoNotAllowed("ed25519 key".to_string()))?;
            let sig = EdSignature::from_bytes(
                signature
                    .try_into()
                    .map_err(|_| VoltaError::CryptoNotAllowed("ed25519 sig".to_string()))?,
            );
            Ok(vk.verify(message, &sig).is_ok())
        }
        IdentitySuite::VoltaMlDsa87Ed25519 => {
            let (mldsa_vk_bytes, ed_vk_bytes) = verifying_key.split_at(MLDSA87_VERIFYING_LEN);
            let (ed_sig_bytes, mldsa_sig_bytes) = signature.split_at(ED25519_SIGNATURE_LEN);
            let ed_vk = EdVerifyingKey::from_bytes(
                ed_vk_bytes
                    .try_into()
                    .map_err(|_| VoltaError::CryptoNotAllowed("ed25519 key".to_string()))?,
            )
            .map_err(|_| VoltaError::CryptoNotAllowed("ed25519 key".to_string()))?;
            let ed_sig = EdSignature::from_bytes(
                ed_sig_bytes
                    .try_into()
                    .map_err(|_| VoltaError::CryptoNotAllowed("ed25519 sig".to_string()))?,
            );
            let ed_ok = ed_vk.verify(message, &ed_sig).is_ok();
            let encoded_vk = ml_dsa::EncodedVerifyingKey::<MlDsa87>::try_from(mldsa_vk_bytes)
                .map_err(|_| VoltaError::CryptoNotAllowed("ml-dsa key".to_string()))?;
            let mldsa_vk = MlDsaVerifyingKey::<MlDsa87>::decode(&encoded_vk);
            let encoded_sig = ml_dsa::EncodedSignature::<MlDsa87>::try_from(mldsa_sig_bytes)
                .map_err(|_| VoltaError::CryptoNotAllowed("ml-dsa sig".to_string()))?;
            let mldsa_sig = MlDsaSignature::<MlDsa87>::decode(&encoded_sig)
                .ok_or_else(|| VoltaError::CryptoNotAllowed("ml-dsa sig".to_string()))?;
            let mut framed = MLDSA_CONTEXT.to_vec();
            framed.extend_from_slice(message);
            let mldsa_ok: bool =
                ml_dsa::Verifier::verify(&mldsa_vk, &framed, &mldsa_sig).is_ok();
            Ok(ed_ok && mldsa_ok)
        }
    }
}

/// The canonical request string an agent signs (SPEC 7.5):
/// `method \n path \n timestamp \n sha256hex(body)`.
#[must_use]
pub fn canonical_request(method: &str, path: &str, timestamp: i64, body: &[u8]) -> Vec<u8> {
    let body_hash: String = Sha256::digest(body)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("{method}\n{path}\n{timestamp}\n{body_hash}").into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(suite: IdentitySuite) {
        let signer = IdentitySigner::generate(suite);
        let vk = signer.verifying_key_bytes();
        let sig = signer.sign(b"agent card");
        assert_eq!(sig.len(), suite.signature_len());
        assert!(verify(suite, &vk, b"agent card", &sig).expect("verify"));
        assert!(!verify(suite, &vk, b"tampered", &sig).expect("verify"));
        let mut bad = sig.clone();
        bad[0] ^= 0x01;
        assert!(!verify(suite, &vk, b"agent card", &bad).expect("verify"));
    }

    #[test]
    fn ed25519_round_trip() {
        round_trip(IdentitySuite::EddsaEd25519);
    }

    #[test]
    fn composite_round_trip() {
        round_trip(IdentitySuite::VoltaMlDsa87Ed25519);
    }

    #[test]
    fn composite_fails_when_one_half_is_swapped() {
        let suite = IdentitySuite::VoltaMlDsa87Ed25519;
        let signer_a = IdentitySigner::generate(suite);
        let signer_b = IdentitySigner::generate(suite);
        let sig_a = signer_a.sign(b"card");
        let sig_b = signer_b.sign(b"card");
        // Ed25519 half from A, ML-DSA half from B: must fail.
        let mut mixed = sig_a[..ED25519_SIGNATURE_LEN].to_vec();
        mixed.extend_from_slice(&sig_b[ED25519_SIGNATURE_LEN..]);
        assert!(
            !verify(suite, &signer_a.verifying_key_bytes(), b"card", &mixed)
                .expect("verify")
        );
    }
}
