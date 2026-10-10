# Contracts and Bounds

- **Sealed tokens** (`sealed_state.rs`). Wire format:
  `nonce (12 B) ‖ ciphertext ‖ GCM tag (16 B)`, AES-256-GCM. The key
  is HKDF-SHA256 over the configured token secret with salt
  `b"volta"` and empty info, 32 bytes — unchanged from the ring
  0.13-era construction, so tokens sealed by old builds remain
  readable. Inputs are capped at `SEALED_LEN_MAX = 64 KiB`; unsealing
  anything shorter than a nonce, oversized, bit-flipped, or sealed
  under another secret fails with an error, never a panic (the
  pre-2026 code split the input at byte 12 unconditionally).
- **Token lifetime.** Stateless tokens carry a creation timestamp;
  `check` rejects expired tokens and — since the 2026-10 fix —
  future-dated ones (the previous `now - creation` subtraction could
  underflow-panic on a forged or clock-skewed token).
- **Publication rule.** An uploaded key's user IDs become searchable
  only after per-address verification; unverified addresses are
  stored but not disclosed by email lookup. Management tokens gate
  deletion/unpublishing.
- **Upload handling.** Uploads are size-limited by Rocket data
  limits and parsed as OpenPGP transferable keys; unparseable
  material is rejected with the `400-pks-invalid` error page (web) or
  a JSON error (VKS), never stored.
- **Internationalization.** Supported locales are compiled from the
  gettext catalogs: debug builds carry en/de/ja, release builds en
  only (pre-existing upstream design, kept). Mail subjects and bodies
  come from the catalogs; the de and ja catalogs were completed for
  all mail flows in the 2026-10 pass.
