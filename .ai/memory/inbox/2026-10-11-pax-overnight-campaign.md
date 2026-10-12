# Overnight campaign pass — 2026-10-11 (Pax)

Primo checkout: clean, in sync at 1b1a5d5 == origin/main (inventory wave
pulled the ff 6b0ebb5 -> 1b1a5d5).

Environment finding: a bare-environment cargo build fails in nettle-sys
bindgen (nettle/pgp.h not found). That is by design, not breakage: primo
has no system nettle, and flake.nix pins nettle 3.10 (nixos-24.11)
because nettle 4 removed nettle/pgp.h, which sequoia-openpgp's
crypto-nettle backend consumes via nettle-sys.

Gates under nix develop (the repo-defined environment):
- cargo build -> rc 0
- cargo test -> rc 0 (34 passed / 0 failed, 2 suites)
- cargo clippy -- -D warnings -> rc 0
- cargo fmt --check -> rc 0

SCIP: rust-analyzer scip under nix develop (rc 0, 1,262,285 bytes). Not
committed: no index.scip pattern in this repo. Artifact: /tmp/volta-index.scip on primo (ephemeral).

Still Matt's: the six Dependabot alert dismissals (GitHub UI) were not attempted.
