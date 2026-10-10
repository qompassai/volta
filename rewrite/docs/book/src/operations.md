# Operations

<details>
<summary>Running the server</summary>

`volta --config volta.toml` (or `$VOLTA_CONFIG`). Startup is
all-or-nothing: configuration (including every proxy chain,
CHAIN-0), storage, the token secret, and identity loading are
validated before the listener opens; any failure is a startup
refusal with the error code on stderr, never a half-up server.
The first operator enrolls with the bootstrap token the server
prints to its console (or `voltactl operator bootstrap`).

</details>

<details>
<summary>voltactl</summary>

Subcommands (alphabetical): `audit`, `delete`, `import`
(`--dry-run` stores nothing), `mcp --stdio [--operator <token
file>]`, `operator bootstrap|list|recover|revoke-credential`,
`regenerate`, `relay-sync --peer <name> [--dry-run]`, `stats`.
`volta-delete [--all] [--all-bindings] <base> <query>` remains
its own binary. Help and version work with no configuration
present; a missing configuration is one structured stderr line
and exit 2 — the predecessor's panic-on-missing-config is a
named premise conflict (C-8) and is fixed by design.

</details>

<details>
<summary>Configuration</summary>

One TOML file: base URI, bind, data dir, origin + RP id (WebAuthn),
the token secret reference, the identity (suite + secret
reference + fingerprint), agent principals (name, suite,
verifying key, permissions), relay peers (name, base URI, pinned
fingerprint), and the proxy table (chains + per-operation
routes). Secrets are always references (`env:`, `file:`) —
never values. Unknown keys are rejected
(`deny_unknown_fields`), as are invalid chains, at load.

</details>

<details>
<summary>Nix</summary>

The flake pins the toolchain (fenix, nightly-2026-09-25) and
builds `volta` (server) and `voltactl`/`volta-delete` packages
with a locked `Cargo.lock`; `nix build` and `nix flake check`
are part of the gate set, alongside `cargo test --workspace`,
clippy with warnings denied, rustfmt, and the headless-Neovim
IDE gate (rust-analyzer + bacon-ls + crates-ls over the live
diver configuration).

</details>

<details>
<summary>Observability</summary>

`/healthz` (liveness), `/readyz` (readiness incl. signing
state), `/metrics` (counts only — no labels that could leak
identities). Requests carry uuid-v7 ids; errors carry the same
id in body and logs.

</details>
