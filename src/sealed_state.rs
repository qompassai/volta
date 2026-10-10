// #################################################################
// /qompassai/volta/src/sealed_state.rs
// Qompass AI Volta Sealed State (AES-256-GCM Token Sealing)
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Qompass AI
//
// Volta is derived from Hagrid, the software behind
// keys.openpgp.org, and this material is licensed under the
// GNU Affero General Public License, version 3 only (see
// LICENSE-AGPL). Contributions authored by Qompass AI are
// dual-licensed under AGPL-3.0 or Apache-2.0 at the
// recipient's choice (see NOTICE); that choice does not
// extend to upstream-derived material, which remains
// AGPL-3.0 only.

use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf::{HKDF_SHA256, KeyType, Salt};
use ring::rand::{SecureRandom, SystemRandom};

// Wire format: nonce (NONCE_LEN bytes) || ciphertext || GCM tag. The key is
// derived from the operator secret with HKDF-SHA256 (salt "volta", empty
// info). Both the layout and the derivation are compatibility contracts:
// tokens sealed by earlier releases must keep unsealing.
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
/// Upper bound on a sealed blob accepted by `unseal` (defense in depth
/// against memory exhaustion via attacker-supplied token strings).
const SEALED_LEN_MAX: usize = 64 * 1024;

struct DerivedKeyLen;

impl KeyType for DerivedKeyLen {
    fn len(&self) -> usize {
        KEY_LEN
    }
}

pub struct SealedState {
    key: LessSafeKey,
}

impl SealedState {
    pub fn new(secret: &str) -> Self {
        let salt = Salt::new(HKDF_SHA256, b"volta");
        let prk = salt.extract(secret.as_bytes());
        let okm = prk
            .expand(&[b""], DerivedKeyLen)
            .expect("HKDF expand with a 32-byte length cannot fail");
        let mut key_bytes = [0u8; KEY_LEN];
        okm.fill(&mut key_bytes)
            .expect("HKDF fill of a fixed-size buffer cannot fail");
        let key = LessSafeKey::new(
            UnboundKey::new(&AES_256_GCM, &key_bytes).expect("32-byte AES-256-GCM key"),
        );
        SealedState { key }
    }

    pub fn unseal(&self, mut data: Vec<u8>) -> Result<String, &'static str> {
        if data.len() < NONCE_LEN || data.len() > SEALED_LEN_MAX {
            return Err("invalid key/nonce/value: bad seal");
        }
        let (nonce_bytes, sealed) = data.split_at_mut(NONCE_LEN);
        let mut nonce_array = [0u8; NONCE_LEN];
        nonce_array.copy_from_slice(nonce_bytes);
        let nonce = Nonce::assume_unique_for_key(nonce_array);
        let unsealed = self
            .key
            .open_in_place(nonce, Aad::empty(), sealed)
            .map_err(|_| "invalid key/nonce/value: bad seal")?;

        ::std::str::from_utf8(unsealed)
            .map(|s| s.to_string())
            .map_err(|_| "bad unsealed utf8")
    }

    pub fn seal(&self, input: &str) -> Vec<u8> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        // A failed OS RNG fill means the platform cannot provide entropy;
        // sealing with a weak nonce would be worse than failing loudly.
        SystemRandom::new()
            .fill(&mut nonce_bytes)
            .expect("couldn't random fill nonce");
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = Vec::with_capacity(input.len() + AES_256_GCM.tag_len());
        in_out.extend_from_slice(input.as_bytes());
        self.key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .expect("in-place seal with a valid key and nonce cannot fail");

        let mut data = Vec::with_capacity(NONCE_LEN + in_out.len());
        data.extend_from_slice(&nonce_bytes);
        data.extend_from_slice(&in_out);
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let sv = SealedState::new("swag");

        let sealed = sv.seal("test");
        let unsealed = sv.unseal(sealed).unwrap();

        assert_eq!("test", unsealed);
    }

    #[test]
    fn test_unseal_rejects_short_and_empty() {
        let sv = SealedState::new("swag");
        assert!(sv.unseal(Vec::new()).is_err());
        assert!(sv.unseal(vec![0u8; NONCE_LEN - 1]).is_err());
        assert!(sv.unseal(vec![0u8; NONCE_LEN]).is_err());
    }

    #[test]
    fn test_unseal_rejects_tampered_ciphertext() {
        let sv = SealedState::new("swag");
        let mut sealed = sv.seal("test");
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(sv.unseal(sealed).is_err());
    }

    #[test]
    fn test_unseal_rejects_wrong_secret() {
        let sealed = SealedState::new("swag").seal("test");
        assert!(SealedState::new("other").unseal(sealed).is_err());
    }

    #[test]
    fn unseal_rejects_oversized_input() {
        let state = SealedState::new("secret");
        let oversized = vec![7u8; SEALED_LEN_MAX + 1];
        assert!(state.unseal(oversized).is_err());
    }

    #[test]
    fn unseal_rejects_nonce_tamper() {
        let state = SealedState::new("secret");
        let mut sealed = state.seal("attack at dawn");
        sealed[0] ^= 0x01;
        assert!(state.unseal(sealed).is_err());
    }
}
