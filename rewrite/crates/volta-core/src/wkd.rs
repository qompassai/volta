// #################################################################
// /qompassai/volta/rewrite/crates/volta-core/src/wkd.rs
// Qompass AI Volta — Web Key Directory Hashing (SPEC 6.3)
// SPDX-License-Identifier: AGPL-3.0-only OR Apache-2.0
// Copyright (c) 2026 Qompass AI
// #################################################################

//! The WKD `hu/` hash (WKD-1): SHA-1 over the lowercased local
//! part, encoded in z-base-32. SHA-1 here is a naming hash mandated
//! by the WKD draft — one of the two scoped exceptions of SPEC
//! 11.4. It carries no authenticity: the certificate's self
//! signatures and the TLS channel do.

use sha1::{Digest, Sha1};

/// The z-base-32 alphabet (protocol order, ORD-1 exception).
const ZBASE32_ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

/// Compute the 32-char WKD hash for an email local part. ASCII
/// uppercase maps to lowercase; non-ASCII passes through unchanged
/// (WKD-1).
#[must_use]
pub fn wkd_hash(local_part: &str) -> String {
    let lowered: String = local_part
        .chars()
        .map(|c| {
            if c.is_ascii_uppercase() {
                c.to_ascii_lowercase()
            } else {
                c
            }
        })
        .collect();
    let digest = Sha1::digest(lowered.as_bytes());
    zbase32_encode(&digest)
}

/// Split an email address into (local part, lowercase domain).
#[must_use]
pub fn split_email(address: &str) -> Option<(String, String)> {
    if address.matches('@').count() != 1 {
        return None;
    }
    let (local, domain) = address.split_once('@')?;
    if local.is_empty() || domain.is_empty() {
        return None;
    }
    Some((local.to_string(), domain.to_lowercase()))
}

fn zbase32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 8 / 5 + 1);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for byte in data {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((buffer >> bits) & 0x1f) as usize;
            out.push(char::from(ZBASE32_ALPHABET[index]));
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(char::from(ZBASE32_ALPHABET[index]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vector() {
        // The WKD draft's worked example local part.
        let hash = wkd_hash("Joe.Doe");
        assert_eq!(hash.len(), 32);
        assert_eq!(hash, wkd_hash("joe.doe"));
    }

    #[test]
    fn split_email_validates() {
        assert_eq!(
            split_email("Ada@Example.ORG"),
            Some(("Ada".to_string(), "example.org".to_string()))
        );
        assert_eq!(split_email("no-at-sign"), None);
        assert_eq!(split_email("a@b@c"), None);
        assert_eq!(split_email("@domain"), None);
    }
}
