<p align="center">
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white" alt="Rust"></a>
  <a href="./NOTICE"><img src="https://img.shields.io/badge/License-AGPL%203.0%20%7C%20Apache%202.0-blue.svg" alt="License: AGPL 3.0 | Apache 2.0"></a>
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

Dual-licensed where Qompass AI holds the copyright — material
authored by Qompass AI is available under AGPL-3.0
([LICENSE-AGPL](LICENSE-AGPL)) **or** Apache-2.0
([LICENSE](LICENSE)), at your choice. Volta is Hagrid-derived, and
the upstream-derived portions remain AGPL-3.0 only: the Apache
choice does not extend to them, so Volta as a combined work is
distributed under AGPL-3.0. See [NOTICE](NOTICE) for the exact
boundary. The `dist/` asset tree is upstream material and retains
its own provenance. Copyright 2026 Qompass AI.

</details>
