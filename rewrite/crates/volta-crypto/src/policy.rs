// #################################################################
// /qompassai/volta/rewrite/crates/volta-crypto/src/policy.rs
// Qompass AI Volta — Crypto Policy Constants (SPEC 11)
// SPDX-License-Identifier: AGPL-3.0-only OR Apache-2.0
// Copyright (c) 2026 Qompass AI
// #################################################################

//! The machine-readable crypto policy (also served as the MCP
//! resource `volta://crypto-policy`). There is no negotiation
//! below this policy on volta's own surfaces (CRYPTO-1).

/// WebAuthn COSE algorithms volta accepts (SPEC 10.2, 11.2):
/// EdDSA only, or ES256; RS256 and all others are absent by design.
pub const COSE_ALGORITHMS_ALLOWED: [i64; 2] = [-8, -7];

/// TLS floor for every volta surface and volta-initiated
/// connection, including inside proxy chains (SPEC 11.4).
pub const TLS_VERSION_MIN: &str = "1.3";

/// TLS 1.3 groups in preference order (SPEC 11.2). The first entry
/// is the hybrid post-quantum group.
pub const TLS_GROUPS_PREFERENCE: [&str; 4] =
    ["X25519MLKEM768", "x25519", "secp384r1", "x448"];

/// Whether a WebAuthn COSE algorithm is allowed.
#[must_use]
pub fn cose_allowed(algorithm: i64) -> bool {
    COSE_ALGORITHMS_ALLOWED.contains(&algorithm)
}

/// The policy as a JSON document (MCP resource content).
#[must_use]
pub fn policy_json() -> serde_json::Value {
    serde_json::json!({
        "native_allowlist": {
            "identity_suites": ["eddsa-ed25519", "volta-mldsa87-ed25519"],
            "kem_suites": [
                "hybrid-mlkem1024-x448",
                "hybrid-mlkem768-x25519",
                "mlkem1024",
                "volta-hybrid-mlkem1024-x25519"
            ],
            "signatures": ["ed25519", "ml-dsa-87"],
            "tls_groups": TLS_GROUPS_PREFERENCE,
            "tls_version_min": TLS_VERSION_MIN,
            "webauthn_cose": COSE_ALGORITHMS_ALLOWED
        },
        "openpgp_allowlist": [
            "ed25519", "ed448", "eddsa-legacy", "ml-dsa-65-ed25519",
            "ml-dsa-87-ed448", "ml-kem-768-x25519", "ml-kem-1024-x448",
            "slh-dsa-shake-128f", "slh-dsa-shake-128s", "slh-dsa-shake-256s",
            "x25519", "x448", "ecdh", "ecdsa", "rsa>=3072 (legacy warning <4096)"
        ],
        "rejected": [
            "3des", "blowfish", "cast5", "dsa", "elgamal", "idea",
            "md5 self-signatures", "rsa<3072", "seipdv0", "sha-1 signature digests",
            "tls<1.3", "v3 keys", "v5/librepgp keys", "webauthn cose rs256"
        ],
        "sha1_scoped_exceptions": [
            "wkd hu/ naming hash (availability only, SPEC 11.4)",
            "v4 fingerprint computation (identifier only, SPEC 11.4)"
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cose_allowlist_is_exact() {
        assert!(cose_allowed(-8));
        assert!(cose_allowed(-7));
        assert!(!cose_allowed(-257));
        assert!(!cose_allowed(-65535));
    }
}
