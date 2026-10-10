# Cryptography: the allowlist

Volta's rule is simple: **an algorithm is usable because it is on
the list, not because a peer offered it.** Everything else is
rejected at parse/validation time with `E_CRYPTO_NOT_ALLOWED`.

<details>
<summary>Allowed, and where</summary>

| Use | Algorithms |
|---|---|
| Ephemeral KEM suites | `hybrid-mlkem768-x25519` (RFC 9980 alg 35 lineage), `hybrid-mlkem1024-x448` (alg 36), `mlkem1024`, `volta-hybrid-mlkem1024-x25519` (volta-native) |
| Identity signatures | Ed25519 (`eddsa-ed25519`), `volta-mldsa87-ed25519` composite |
| OpenPGP interop | The RFC 9580 / RFC 9980 registry: Ed25519/Ed448, ECDH/ECDSA on strong curves, RSA ≥ 3072, the composite ML-DSA/ML-KEM algorithms (30/31/35/36) |
| Sealed tokens | AES-256-GCM, HKDF-SHA256 |
| Session combiner | HKDF-SHA-512 over both halves' secrets, ciphertexts, and public keys, salted with the suite id |
| WebAuthn credentials | COSE −8 (EdDSA) and −7 (ES256) only |
| TLS | 1.3 only |

Hybrid combiners bind **both** transcripts: a session is valid
only if both halves succeed. A failed half is a failed session —
never a downgrade to the surviving half. Non-contributory
(all-zero) Diffie-Hellman output is a hard failure.

</details>

<details>
<summary>Rejected, with reasons</summary>

- **RSA < 3072** in surfaces volta controls (RSA 3072–4095 is
  accepted for OpenPGP interop with a `legacy-algorithm`
  warning; below that, refused).
- **DSA, ElGamal**, and unknown algorithm ids — refused at parse.
- **MD5** — a certificate whose self-signatures are MD5-only is
  refused.
- **SHA-1 as a security mechanism** — refused everywhere except
  the two scoped naming exceptions below.
- **TLS < 1.3**, and any KEM/signature suite not in the table.

</details>

<details>
<summary>Premise conflict C-1: the pairings that do not exist</summary>

RFC 9980 pairs ML-KEM-768 with X25519 (alg 35) and ML-KEM-1024
with **X448** (alg 36); its signature pairs are ML-DSA-65+Ed25519
(alg 30) and ML-DSA-87+**Ed448** (alg 31). The combinations
"X25519+ML-KEM-1024" and "Ed25519+ML-DSA-87" have **no OpenPGP
algorithm ids**. Volta's resolution: on OpenPGP surfaces, only
the RFC pairings exist. The other two combinations live as
*volta-native* suites (`volta-hybrid-mlkem1024-x25519`,
`volta-mldsa87-ed25519`) on volta's own surfaces, and are never
encoded as RFC ids.

</details>

<details>
<summary>Scoped exception C-2: SHA-1 names, never protects</summary>

Two protocol mandates use SHA-1: the WKD `hu/` hash, and the v4
fingerprint format itself. Both are *identifiers* — lookup keys,
not integrity mechanisms. Volta treats them exactly that way:
authenticity comes from self-signatures and the TLS channel,
never from the fingerprint or the directory hash.

</details>

<details>
<summary>An honest note on WebAuthn and PQC</summary>

There is, as of this writing, **no post-quantum WebAuthn
credential type**: no authenticator produces ML-DSA passkeys.
Biometric operator auth is therefore classical *by protocol
constraint* (EdDSA/ES256), and the book says so rather than
implying otherwise. Volta's *own* signatures — Agent Cards,
agent request signatures — are hybrid post-quantum where the
identity suite says so.

</details>

<details>
<summary>Implementations</summary>

No hand-rolled primitives, ever. KEM and signatures come from
the RustCrypto `ml-kem` / `ml-dsa` crates (pure Rust, FIPS
203/204 — chosen over liboqs bindings for hermetic nix builds),
OpenPGP from rpgp with its RFC 9980 draft support, WebAuthn from
webauthn-rs 0.5.5 (the floor set by a patched origin-validation
advisory), TLS from rustls with the ring provider.

</details>
