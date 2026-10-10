# Architecture

Three workspace members:

- **`volta`** (root package) — the Rocket 0.5 server: two binaries,
  `volta` (the server) and `volta-delete` (single-key removal).
- **`volta-database`** (`database/`) — the storage crate: a
  filesystem-backed key store keyed by fingerprint, key ID, and
  email, with Sequoia-OpenPGP parsing, cleaning (stripping
  unverified and revoked material per policy), WKD hashing, and
  stateful on-disk tokens.
- **`voltactl`** — operator CLI wrapping the database crate: bulk
  import of key material and regeneration of the derived directory
  layout for the debug/staging/release profiles.

Server internals (`src/`):

- `web/` — one module per surface: `hkp`, `vks_api`, `vks_web`,
  `wkd`, `manage`, `maintenance`, `debug_web`, plus `mod.rs` with
  the Rocket factory, figment configuration extraction, the upload
  pipeline, and the integration tests.
- `tokens.rs` + `sealed_state.rs` — stateless, sealed verification /
  management tokens (see Contracts).
- `mail.rs` — verification and management emails, localized through
  gettext catalogs (`po/volta/{en,de,ja}.po`) rendered into the
  `dist/email-templates/`.
- `i18n.rs` — the in-tree replacement for the former `rocket_i18n`
  dependency: `Accept-Language` negotiation against the compiled
  catalogs, with the handlebars `{{text}}` helper in
  `i18n_helpers.rs`.
- `rate_limiter.rs`, `counters.rs`, `anonymize_utils.rs`,
  `dump.rs` (an OpenPGP packet dump utility used by the debug
  surface).

Web assets and templates live in `dist/` (pages, email templates,
error pages). The `dist/` tree is upstream Hagrid material and keeps
its own provenance; the `about/` page family is first-party Qompass
content written in 2026 (see Testing).
