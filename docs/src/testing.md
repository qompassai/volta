# Testing

Gate set (all on primo, pinned nightly, nettle 3 via pkg-config):

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
mdbook build
```

## Suite shape

63 tests at the time of writing — 32 in the server binary target,
29 in `volta-database`, plus doc-tests:

- **Validation (~40).** The Rocket integration tests in
  `src/web/mod.rs` drive the real stack: `basics` (front page,
  about family), `about_translation`, `maintenance`,
  `upload_verify_single`, `upload_verify_two`, `upload_verify_lang`
  (German mail flow), `upload_verify_onion`, `upload_two`; the mail
  suites check verification and management emails in en/de/ja;
  `tokens` covers create/check/ok/bad-type; the database crate's
  suites cover import, merge, lookup by fingerprint/key ID/email,
  deletion, and WKD generation.
- **Adversarial (~23).** Sealed-state: empty, short, and nonce-only
  inputs, ciphertext bit-flip, nonce bit-flip, wrong secret,
  oversized input (> 64 KiB) — all rejected. Tokens: expired and
  future-dated rejected; wrong token type rejected. Uploads:
  malformed key material rejected; unverified addresses stay
  unpublished.

Route coverage by name: HKP lookup/add, VKS upload + verify +
by-fingerprint/by-email/by-keyid, WKD policy, manage/unpublish, and
the web upload→verify→publish round trip are all exercised in the
integration suite; the binary smoke (Operations chapter) covers the
running server.

## Repairs the suite needed (2026-10)

- The seven `about/*` templates the code renders did not exist in
  `dist/templates/`; first-party Qompass pages were written (they
  carry provenance comments and are the only first-party files in
  `dist/`).
- The de/ja gettext catalogs were untranslated skeletons; the mail
  flows are now fully translated in both (16 entries each).
- The test suite could not run at all as committed:
  `.cargo/config.toml` routed test binaries through a `zig` runner,
  and the multipart test header was built with a rocket 0.5.0-rc API
  shape that silently dropped the boundary (0.5.1's
  `ContentType::with_params` on a *known* media type renders without
  parameters — the test now builds the type fresh; details in
  `src/web/mod.rs`).
- Deprecated sequoia APIs were modernized (`email2`,
  `self_signatures2` et al., `attest_certifications2`,
  `PacketParser::processed`), including the policy-verified
  signature iterators.
