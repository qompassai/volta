# Operations

## Build

```sh
cargo build --release        # or: nix build / nix develop
```

Toolchain: `rust-toolchain.toml` pins nightly-2026-09-25
(rustc 1.100.0-nightly); all three crates are edition 2024 with
`rust-version = "1.89"`. Building outside Nix needs a nettle 3.x
development package for sequoia-openpgp's `crypto-nettle` backend
(nixpkgs' current nettle 4 removed the OpenPGP helper headers
sequoia's bindgen requires — the flake pins a nettle-3 source for
exactly this reason; see the Nix chapter).

## Configure and run

Volta is a Rocket application: configuration is figment (a
`Rocket.toml` beside the binary, or `ROCKET_*` environment). The
Volta-specific keys (see `src/web/mod.rs`) include `root`,
`template_dir`, `email_template_dir`, `assets_dir`,
`keys_internal_dir`, `keys_external_dir`, `tmp_dir`, `token_dir`,
`maintenance_file`, `base-URI`, `base-URI-Onion`, `from`,
`token_secret`, `token_validity`, and the mail transport
(`filemail_into` for file-spool delivery in development).
`Rocket.toml.dist` documents a starting point.

```sh
ROCKET_ADDRESS=127.0.0.1 ROCKET_PORT=8080 ./volta
```

## Smoke evidence (2026-10, this tree)

Against the real binary on loopback with a throwaway state root:
`GET /` → 200, `GET /about` → 200,
`GET /vks/v1/by-fingerprint/<unknown>` → 404 "No key found for
fingerprint …", `GET /.well-known/openpgpkey/example.com/policy` →
200, `GET /pks/lookup?op=get&search=0x…` → 404; clean shutdown on
SIGTERM.
