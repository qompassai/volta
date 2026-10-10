# Clean-room rewrite commissioned (2026-10-10)

Matt commissioned a clean-room rewrite of volta on branch
`cleanroom/volta-20261010`, living under `rewrite/` so `main` and
the Hagrid-derived predecessor tree stay intact as a black-box
oracle only.

Decisions of record (from the spec, `rewrite/docs/SPEC.md`):

- Volta is a secure key server FOR MCP and A2A: OpenPGP key service
  (HKP/VKS/WKD) plus ephemeral hybrid-PQC keys with hard TTL
  (30 s min, 120 s default, 3600 s cap, no renewal — Rosenpass
  semantics over ML-KEM, not Rosenpass wire compatibility).
- Crypto allowlist by design; rejected algorithms fail at
  parse/validation with structured errors. RFC 9980 pairings govern
  OpenPGP surfaces; Matt's X25519+ML-KEM-1024 and Ed25519+ML-DSA-87
  combinations are volta-native suites, never encoded as RFC IDs.
- WebAuthn/FIDO2 passkeys are the only operator credential;
  biometrics never leave the authenticator.
- Proxy chains are per-operation, DNS-through-chain, fail-closed;
  there is no direct-fallback code path.
- Homa transport: assessed, conditional no-build (see the book's
  appendix). Mojo: assessed, no-build (same appendix).
- Licensing: the rewrite is original Qompass work, dual
  AGPL-3.0-only OR Apache-2.0 (`rewrite/NOTICE`).
