// #################################################################
// /qompassai/volta/rewrite/crates/volta-crypto/src/suites.rs
// Qompass AI Volta — Ephemeral KEM Suites (SPEC 7.1, 11.2)
// SPDX-License-Identifier: AGPL-3.0-only OR Apache-2.0
// Copyright (c) 2026 Qompass AI
// #################################################################

//! The ephemeral-key suites. Hybrid suites bind both component
//! secrets and both transcripts into an HKDF-SHA-512 combiner, so a
//! session is valid only if both halves succeed — a failed half is
//! a failed session, never a downgrade (SPEC 7.1, GLOB-3). Suite
//! identifiers are the exact strings of the spec; aliases are not
//! accepted (CRYPTO-3).

use hkdf::Hkdf;
use kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768, MlKem1024};
use rand_core::CryptoRngCore;
use sha2::Sha512;
use x25519_dalek::{
    EphemeralSecret as X25519Ephemeral, PublicKey as X25519Public, StaticSecret as X25519Static,
};
use zeroize::Zeroizing;

use volta_core::error::{VoltaError, VoltaResult};

/// ML-KEM-1024 ciphertext length in bytes (FIPS 203).
pub const MLKEM1024_CIPHERTEXT_LEN: usize = 1568;
/// ML-KEM-1024 encapsulation key length in bytes (FIPS 203).
pub const MLKEM1024_PUBLIC_LEN: usize = 1568;
/// ML-KEM-768 ciphertext length in bytes (FIPS 203).
pub const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
/// ML-KEM-768 encapsulation key length in bytes (FIPS 203).
pub const MLKEM768_PUBLIC_LEN: usize = 1184;
/// Shared secret length produced by every suite.
pub const SHARED_SECRET_LEN: usize = 32;
/// X25519 public/ciphertext length.
pub const X25519_LEN: usize = 32;
/// X448 public/ciphertext length.
pub const X448_LEN: usize = 56;

/// An ephemeral suite identifier (SPEC 7.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Suite {
    /// ML-KEM-1024 + X448 (RFC 9980 alg 36 profile).
    HybridMlKem1024X448,
    /// ML-KEM-768 + X25519 (RFC 9980 alg 35 profile). Default.
    HybridMlKem768X25519,
    /// ML-KEM-1024 alone; PSK derivation only (Rosenpass
    /// composition supplies the classical layer).
    MlKem1024,
    /// Volta-native ML-KEM-1024 + X25519 (C-1: never encoded as an
    /// OpenPGP algorithm).
    VoltaHybridMlKem1024X25519,
}

impl Suite {
    /// Parse the exact suite string (CRYPTO-3).
    ///
    /// # Errors
    /// `E_CRYPTO_NOT_ALLOWED` for any other string, including
    /// aliases and rejected algorithms.
    pub fn parse(value: &str) -> VoltaResult<Self> {
        match value {
            "hybrid-mlkem1024-x448" => Ok(Self::HybridMlKem1024X448),
            "hybrid-mlkem768-x25519" => Ok(Self::HybridMlKem768X25519),
            "mlkem1024" => Ok(Self::MlKem1024),
            "volta-hybrid-mlkem1024-x25519" => Ok(Self::VoltaHybridMlKem1024X25519),
            other => Err(VoltaError::CryptoNotAllowed(format!("suite {other}"))),
        }
    }

    /// The exact suite string.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HybridMlKem1024X448 => "hybrid-mlkem1024-x448",
            Self::HybridMlKem768X25519 => "hybrid-mlkem768-x25519",
            Self::MlKem1024 => "mlkem1024",
            Self::VoltaHybridMlKem1024X25519 => "volta-hybrid-mlkem1024-x25519",
        }
    }

    /// Length of the classical public/ciphertext component.
    #[must_use]
    pub fn classical_len(&self) -> usize {
        match self {
            Self::HybridMlKem1024X448 => X448_LEN,
            Self::HybridMlKem768X25519 | Self::VoltaHybridMlKem1024X25519 => X25519_LEN,
            Self::MlKem1024 => 0,
        }
    }

    /// Length of the ML-KEM ciphertext component.
    #[must_use]
    pub fn kem_ciphertext_len(&self) -> usize {
        match self {
            Self::HybridMlKem768X25519 => MLKEM768_CIPHERTEXT_LEN,
            _ => MLKEM1024_CIPHERTEXT_LEN,
        }
    }

    /// Length of the ML-KEM encapsulation key.
    #[must_use]
    pub fn kem_public_len(&self) -> usize {
        match self {
            Self::HybridMlKem768X25519 => MLKEM768_PUBLIC_LEN,
            _ => MLKEM1024_PUBLIC_LEN,
        }
    }
}

/// A generated ephemeral keypair. Private material is zeroizing
/// and, in `server` custody, never leaves process memory (EPH-4).
pub struct KemKeypair {
    /// Classical public key bytes (empty for `mlkem1024`).
    pub classical_public: Vec<u8>,
    /// ML-KEM encapsulation key bytes.
    pub kem_public: Vec<u8>,
    /// Private material: encoded decapsulation key, then the KEM
    /// public key (combiner transcript), then (for hybrid suites)
    /// the classical secret bytes.
    pub secret_material: Zeroizing<Vec<u8>>,
    /// The suite.
    pub suite: Suite,
}

/// Generate a fresh ephemeral keypair for a suite.
#[must_use]
pub fn generate_keypair(suite: Suite, rng: &mut impl CryptoRngCore) -> KemKeypair {
    match suite {
        Suite::HybridMlKem768X25519 => {
            let (dk, ek) = MlKem768::generate(rng);
            let classical = X25519Static::random_from_rng(&mut *rng);
            let mut secret = dk.as_bytes().to_vec();
            secret.extend_from_slice(ek.as_bytes().as_slice());
            secret.extend_from_slice(&classical.to_bytes());
            KemKeypair {
                classical_public: X25519Public::from(&classical).as_bytes().to_vec(),
                kem_public: ek.as_bytes().to_vec(),
                secret_material: Zeroizing::new(secret),
                suite,
            }
        }
        Suite::HybridMlKem1024X448 | Suite::MlKem1024 | Suite::VoltaHybridMlKem1024X25519 => {
            let (dk, ek) = MlKem1024::generate(rng);
            let mut secret = dk.as_bytes().to_vec();
            secret.extend_from_slice(ek.as_bytes().as_slice());
            let classical_public = match suite {
                Suite::HybridMlKem1024X448 => {
                    let mut classical_bytes = [0u8; X448_LEN];
                    rng.fill_bytes(&mut classical_bytes);
                    let classical = x448::StaticSecret::from(classical_bytes);
                    let public = x448::PublicKey::from(&classical);
                    secret.extend_from_slice(classical.as_bytes());
                    public.as_bytes().to_vec()
                }
                Suite::VoltaHybridMlKem1024X25519 => {
                    let classical = X25519Static::random_from_rng(&mut *rng);
                    secret.extend_from_slice(&classical.to_bytes());
                    X25519Public::from(&classical).as_bytes().to_vec()
                }
                _ => Vec::new(),
            };
            KemKeypair {
                classical_public,
                kem_public: ek.as_bytes().to_vec(),
                secret_material: Zeroizing::new(secret),
                suite,
            }
        }
    }
}

/// Encapsulate against a peer's public material. Returns the
/// ciphertext (classical component first, then the ML-KEM
/// ciphertext) and the derived shared secret.
///
/// # Errors
/// `E_CRYPTO_NOT_ALLOWED` for malformed public material; a failed
/// classical half fails the whole encapsulation (no downgrade).
pub fn encapsulate(
    suite: Suite,
    classical_public: &[u8],
    kem_public: &[u8],
    rng: &mut impl CryptoRngCore,
) -> VoltaResult<(Vec<u8>, Zeroizing<[u8; SHARED_SECRET_LEN]>)> {
    if kem_public.len() != suite.kem_public_len() {
        return Err(VoltaError::CryptoNotAllowed(
            "kem public material length".to_string(),
        ));
    }
    let (classical_ct, classical_ss): (Vec<u8>, Vec<u8>) = match suite {
        Suite::MlKem1024 => (Vec::new(), Vec::new()),
        Suite::HybridMlKem768X25519 | Suite::VoltaHybridMlKem1024X25519 => {
            if classical_public.len() != X25519_LEN {
                return Err(VoltaError::CryptoNotAllowed(
                    "x25519 public material length".to_string(),
                ));
            }
            let peer =
                X25519Public::from(<[u8; X25519_LEN]>::try_from(classical_public).map_err(
                    |_| VoltaError::CryptoNotAllowed("x25519 public material".to_string()),
                )?);
            let ephemeral = X25519Ephemeral::random_from_rng(&mut *rng);
            let ct = X25519Public::from(&ephemeral).as_bytes().to_vec();
            let ss = ephemeral.diffie_hellman(&peer);
            if !ss.was_contributory() {
                return Err(VoltaError::CryptoNotAllowed(
                    "x25519 non-contributory shared secret".to_string(),
                ));
            }
            (ct, ss.as_bytes().to_vec())
        }
        Suite::HybridMlKem1024X448 => {
            if classical_public.len() != X448_LEN {
                return Err(VoltaError::CryptoNotAllowed(
                    "x448 public material length".to_string(),
                ));
            }
            let peer = x448::PublicKey::from_bytes(classical_public)
                .ok_or_else(|| VoltaError::CryptoNotAllowed("x448 public material".to_string()))?;
            let mut ephemeral_bytes = [0u8; X448_LEN];
            rng.fill_bytes(&mut ephemeral_bytes);
            let ephemeral = x448::StaticSecret::from(ephemeral_bytes);
            let ct = x448::PublicKey::from(&ephemeral).as_bytes().to_vec();
            let ss = ephemeral.diffie_hellman(&peer);
            if ss.as_bytes().iter().all(|b| *b == 0) {
                return Err(VoltaError::CryptoNotAllowed(
                    "x448 all-zero shared secret".to_string(),
                ));
            }
            (ct, ss.as_bytes().to_vec())
        }
    };
    let (kem_ct, kem_ss): (Vec<u8>, Vec<u8>) = match suite {
        Suite::HybridMlKem768X25519 => {
            let encoded =
                ml_kem::Encoded::<<MlKem768 as KemCore>::EncapsulationKey>::try_from(kem_public)
                    .map_err(|_| VoltaError::CryptoNotAllowed("ml-kem-768 public length".into()))?;
            let ek = <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&encoded);
            let (ct, ss) = ek
                .encapsulate(rng)
                .map_err(|()| VoltaError::CryptoNotAllowed("ml-kem-768 encapsulate".into()))?;
            (ct.to_vec(), ss.to_vec())
        }
        _ => {
            let encoded =
                ml_kem::Encoded::<<MlKem1024 as KemCore>::EncapsulationKey>::try_from(kem_public)
                    .map_err(|_| VoltaError::CryptoNotAllowed("ml-kem-1024 public length".into()))?;
            let ek = <MlKem1024 as KemCore>::EncapsulationKey::from_bytes(&encoded);
            let (ct, ss) = ek
                .encapsulate(rng)
                .map_err(|()| VoltaError::CryptoNotAllowed("ml-kem-1024 encapsulate".into()))?;
            (ct.to_vec(), ss.to_vec())
        }
    };
    let mut ciphertext = classical_ct.clone();
    ciphertext.extend_from_slice(&kem_ct);
    let shared = combine(
        suite,
        &classical_ss,
        &kem_ss,
        &classical_ct,
        &kem_ct,
        classical_public,
        kem_public,
    );
    Ok((ciphertext, shared))
}

/// Decapsulate a ciphertext with the keypair's secret material.
///
/// # Errors
/// `E_CRYPTO_NOT_ALLOWED` for malformed ciphertext or secret
/// material; a failed half fails the whole decapsulation.
pub fn decapsulate(
    suite: Suite,
    secret_material: &[u8],
    ciphertext: &[u8],
) -> VoltaResult<Zeroizing<[u8; SHARED_SECRET_LEN]>> {
    let classical_len = suite.classical_len();
    let expected = classical_len + suite.kem_ciphertext_len();
    if ciphertext.len() != expected {
        return Err(VoltaError::CryptoNotAllowed(
            "ciphertext length".to_string(),
        ));
    }
    let (classical_ct, kem_ct) = ciphertext.split_at(classical_len);
    // Split the secret material: decapsulation key, then the KEM
    // public key (kept so the combiner transcript binds the exact
    // bytes the peer encapsulated to), then the classical secret
    // (its length mirrors the public component).
    let kem_public_len = suite.kem_public_len();
    let dk_len = secret_material
        .len()
        .checked_sub(classical_len + kem_public_len)
        .ok_or_else(|| VoltaError::CryptoNotAllowed("secret material length".to_string()))?;
    let (dk_bytes, rest) = secret_material.split_at(dk_len);
    let (kem_public_bytes, classical_secret) = rest.split_at(kem_public_len);
    let peer_classical_public = classical_ct;
    let classical_ss: Vec<u8> = match suite {
        Suite::MlKem1024 => Vec::new(),
        Suite::HybridMlKem768X25519 | Suite::VoltaHybridMlKem1024X25519 => {
            if classical_secret.len() != X25519_LEN || classical_ct.len() != X25519_LEN {
                return Err(VoltaError::CryptoNotAllowed(
                    "x25519 secret/ciphertext length".to_string(),
                ));
            }
            let secret = X25519Static::from(
                <[u8; X25519_LEN]>::try_from(classical_secret)
                    .map_err(|_| VoltaError::CryptoNotAllowed("x25519 secret".to_string()))?,
            );
            let peer = X25519Public::from(
                <[u8; X25519_LEN]>::try_from(classical_ct)
                    .map_err(|_| VoltaError::CryptoNotAllowed("x25519 ciphertext".to_string()))?,
            );
            let ss = secret.diffie_hellman(&peer);
            if !ss.was_contributory() {
                return Err(VoltaError::CryptoNotAllowed(
                    "x25519 non-contributory shared secret".to_string(),
                ));
            }
            ss.as_bytes().to_vec()
        }
        Suite::HybridMlKem1024X448 => {
            if classical_secret.len() != X448_LEN || classical_ct.len() != X448_LEN {
                return Err(VoltaError::CryptoNotAllowed(
                    "x448 secret/ciphertext length".to_string(),
                ));
            }
            let secret = x448::StaticSecret::from(
                <[u8; X448_LEN]>::try_from(classical_secret)
                    .map_err(|_| VoltaError::CryptoNotAllowed("x448 secret".to_string()))?,
            );
            let peer = x448::PublicKey::from_bytes(classical_ct)
                .ok_or_else(|| VoltaError::CryptoNotAllowed("x448 ciphertext".to_string()))?;
            let ss = secret.diffie_hellman(&peer);
            if ss.as_bytes().iter().all(|b| *b == 0) {
                return Err(VoltaError::CryptoNotAllowed(
                    "x448 all-zero shared secret".to_string(),
                ));
            }
            ss.as_bytes().to_vec()
        }
    };
    let kem_ss: Vec<u8> = match suite {
        Suite::HybridMlKem768X25519 => {
            let encoded =
                ml_kem::Encoded::<<MlKem768 as KemCore>::DecapsulationKey>::try_from(dk_bytes)
                    .map_err(|_| VoltaError::CryptoNotAllowed("ml-kem-768 secret length".into()))?;
            let dk = <MlKem768 as KemCore>::DecapsulationKey::from_bytes(&encoded);
            let ct = ml_kem::Ciphertext::<MlKem768>::try_from(kem_ct)
                .map_err(|_| VoltaError::CryptoNotAllowed("ml-kem-768 ciphertext length".into()))?;
            let ss = dk
                .decapsulate(&ct)
                .map_err(|()| VoltaError::CryptoNotAllowed("ml-kem-768 decapsulate".into()))?;
            ss.to_vec()
        }
        _ => {
            let encoded =
                ml_kem::Encoded::<<MlKem1024 as KemCore>::DecapsulationKey>::try_from(dk_bytes)
                    .map_err(|_| {
                        VoltaError::CryptoNotAllowed("ml-kem-1024 secret length".into())
                    })?;
            let dk = <MlKem1024 as KemCore>::DecapsulationKey::from_bytes(&encoded);
            let ct = ml_kem::Ciphertext::<MlKem1024>::try_from(kem_ct).map_err(|_| {
                VoltaError::CryptoNotAllowed("ml-kem-1024 ciphertext length".into())
            })?;
            let ss = dk
                .decapsulate(&ct)
                .map_err(|()| VoltaError::CryptoNotAllowed("ml-kem-1024 decapsulate".into()))?;
            ss.to_vec()
        }
    };
    // The combiner binds the public material: the classical
    // public is reconstructed from the secret, and the KEM public
    // travels inside the secret material (see generate_keypair).
    let classical_public = classical_public_of(suite, classical_secret);
    Ok(combine(
        suite,
        &classical_ss,
        &kem_ss,
        peer_classical_public,
        kem_ct,
        &classical_public,
        kem_public_bytes,
    ))
}

fn classical_public_of(suite: Suite, classical_secret: &[u8]) -> Vec<u8> {
    match suite {
        Suite::HybridMlKem768X25519 | Suite::VoltaHybridMlKem1024X25519 => {
            if classical_secret.len() == X25519_LEN {
                let secret = X25519Static::from(
                    <[u8; X25519_LEN]>::try_from(classical_secret)
                        .expect("length checked by caller"),
                );
                X25519Public::from(&secret).as_bytes().to_vec()
            } else {
                Vec::new()
            }
        }
        Suite::HybridMlKem1024X448 => {
            if classical_secret.len() == X448_LEN {
                let secret = x448::StaticSecret::from(
                    <[u8; X448_LEN]>::try_from(classical_secret).expect("length checked by caller"),
                );
                x448::PublicKey::from(&secret).as_bytes().to_vec()
            } else {
                Vec::new()
            }
        }
        Suite::MlKem1024 => Vec::new(),
    }
}

/// The hybrid combiner (SPEC 7.1): HKDF-SHA-512 over both secrets
/// and both transcripts, salted with the suite ID. For the pure
/// `mlkem1024` suite the ML-KEM shared secret is the session
/// secret directly (Rosenpass composition).
fn combine(
    suite: Suite,
    classical_ss: &[u8],
    kem_ss: &[u8],
    classical_ct: &[u8],
    kem_ct: &[u8],
    classical_pk: &[u8],
    kem_pk: &[u8],
) -> Zeroizing<[u8; SHARED_SECRET_LEN]> {
    if suite == Suite::MlKem1024 {
        let mut out = Zeroizing::new([0u8; SHARED_SECRET_LEN]);
        out.copy_from_slice(&kem_ss[..SHARED_SECRET_LEN]);
        return out;
    }
    let mut ikm = Vec::with_capacity(
        classical_ss.len()
            + kem_ss.len()
            + classical_ct.len()
            + kem_ct.len()
            + classical_pk.len()
            + kem_pk.len(),
    );
    ikm.extend_from_slice(classical_ss);
    ikm.extend_from_slice(kem_ss);
    ikm.extend_from_slice(classical_ct);
    ikm.extend_from_slice(kem_ct);
    ikm.extend_from_slice(classical_pk);
    ikm.extend_from_slice(kem_pk);
    let hkdf = Hkdf::<Sha512>::new(Some(suite.as_str().as_bytes()), &ikm);
    let mut out = Zeroizing::new([0u8; SHARED_SECRET_LEN]);
    hkdf.expand(b"volta-ephemeral-v1", out.as_mut())
        .expect("32-byte HKDF-SHA-512 output is always in bounds");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(suite: Suite) {
        let mut rng = rand::rngs::OsRng;
        let keypair = generate_keypair(suite, &mut rng);
        let (ciphertext, secret_a) = encapsulate(
            suite,
            &keypair.classical_public,
            &keypair.kem_public,
            &mut rng,
        )
        .expect("encapsulate");
        let secret_b =
            decapsulate(suite, &keypair.secret_material, &ciphertext).expect("decapsulate");
        assert_eq!(*secret_a, *secret_b);
        assert_ne!(*secret_a, [0u8; SHARED_SECRET_LEN]);
    }

    #[test]
    fn all_suites_round_trip() {
        round_trip(Suite::HybridMlKem1024X448);
        round_trip(Suite::HybridMlKem768X25519);
        round_trip(Suite::MlKem1024);
        round_trip(Suite::VoltaHybridMlKem1024X25519);
    }

    #[test]
    fn aliases_and_weak_suites_are_rejected() {
        for bad in ["kyber1024", "pqc", "rsa", "ecdh", "mlkem512", ""] {
            assert!(
                matches!(Suite::parse(bad), Err(VoltaError::CryptoNotAllowed(_))),
                "suite {bad} must be rejected"
            );
        }
    }

    #[test]
    fn bit_flipped_ciphertext_does_not_yield_the_same_secret() {
        let mut rng = rand::rngs::OsRng;
        let suite = Suite::HybridMlKem768X25519;
        let keypair = generate_keypair(suite, &mut rng);
        let (mut ciphertext, secret_a) = encapsulate(
            suite,
            &keypair.classical_public,
            &keypair.kem_public,
            &mut rng,
        )
        .expect("encapsulate");
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0x01;
        // ML-KEM implicit rejection: decapsulation succeeds with a
        // different secret — the combiner output must differ.
        let secret_b = decapsulate(suite, &keypair.secret_material, &ciphertext)
            .expect("implicit rejection decapsulates");
        assert_ne!(*secret_a, *secret_b);
    }

    #[test]
    fn wrong_length_material_is_rejected() {
        let mut rng = rand::rngs::OsRng;
        let suite = Suite::MlKem1024;
        assert!(encapsulate(suite, &[], &[0u8; 10], &mut rng).is_err());
        assert!(decapsulate(suite, &[0u8; 10], &[0u8; 10]).is_err());
    }
}
