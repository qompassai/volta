<p align="center">
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white" alt="Rust"></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache 2.0"></a>
</p>

# Volta

**An OpenPGP key server** — derived from
[Hagrid](https://gitlab.com/hagrid-keyserver/hagrid), the software
behind keys.openpgp.org. It serves the HKP protocol
(`/pks/lookup`, `/pks/add`), the verifying-keyserver API
(`/vks/v1/*`), and Web Key Directory (`/.well-known/openpgpkey/*`),
with email-verified publication: an address becomes searchable only
after its owner confirms it via a mailed token link.

> Earlier descriptions of this repository called it a reverse
> proxy. It is not one and never has been — the code is a key
> server, and the docs now say so.

## Quickstart

```sh
cargo build --release
ROCKET_ADDRESS=127.0.0.1 ROCKET_PORT=8080 ./target/release/volta
```

Or with Nix: `nix build` / `nix develop` (the flake also supplies
the nettle 3 that sequoia-openpgp's backend requires — see the
book's Nix chapter).

## Documentation

The full documentation is an mdBook under [`docs/src/`](docs/src/)
(the key-server verdict with route evidence, architecture, contracts
and bounds, security model, operations, Nix usage, and the testing
story — including the sealed-token fixture regeneration):

```sh
mdbook build   # renders to book/ (gitignored)
```

<details>
<summary>Toolchain</summary>

Pinned by `rust-toolchain.toml`: nightly-2026-09-25
(rustc 1.100.0-nightly), edition 2024 across all three crates
(`volta`, `volta-database`, `voltactl`). Gates: `cargo build`,
`cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`,
`mdbook build` — all green.

</details>

<details>
<summary>License</summary>

Apache-2.0 — see [LICENSE](LICENSE). Copyright 2026 Qompass AI.
Volta is Hagrid-derived; the `dist/` asset tree is upstream material
and retains its own provenance.

</details>
