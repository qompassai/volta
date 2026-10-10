# Nix Flake

`flake.nix` packages the server and provides the development shell.
The Rust toolchain comes from fenix's `fromToolchainFile` against
the repo's own `rust-toolchain.toml` — the same nightly the gates
ran under.

```sh
nix build                 # packages.default -> volta (+ volta-delete, voltactl)
nix develop               # shell: pinned toolchain, nettle 3, pkg-config, mdbook
nix develop --command cargo --version
nix flake check
```

`shell.nix` is the standard flake-compat shim over the same shell.

**The nettle constraint.** sequoia-openpgp 1.x with the
`crypto-nettle` backend needs nettle 3.x headers (nettle 4 removed
`nettle/pgp.h`, which `nettle-sys`' bindgen consumes). The flake
therefore takes nettle from a pinned older nixpkgs input used only
for that library; everything else tracks the main nixpkgs input.
The same constraint applies to non-Nix builds and is why the
development shell exports it through pkg-config.
