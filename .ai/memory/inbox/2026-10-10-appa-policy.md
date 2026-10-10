# OpenAPPA policy profile — 2026-10-10

Matt directed (2026-10-10) that the estate's OpenAPPA adaptation
be propagated to volta, vongola, and fathom. The adaptation is the
primo pilot (`~/openappa-pilot`, report dated 2026-10-01): a
per-repo OpenAPPA profile — claude-code battery included, repo
root rules added — validated offline with the pinned engine and
kept as a second, deterministic gate under the harness's own
permissions. It was never in phlow.

Added here, new files only:

- `policy/appa.toml` — volta's worker policy on the pilot's image
  profile shape: battery include (relative, resolving to the
  pinned pilot tree), root Bash allows for cargo build/test/
  clippy/fmt, nix build, and mdbook build; hard denies
  (`attention = ["blocked"]`) for the pilot's destructive set
  plus network egress (curl/wget/nc/gh, git push); volta's secret
  classes (sealed state, identity signing keys, relay token
  secrets, operator bootstrap tokens) labeled `self` on Read/Grep;
  Write/Edit staging zones (tmp family, lookalike repo dirs) that
  require a still-public session audience; volta's 13 MCP tools
  tiered (7 read-only allowed, 6 mutating `hitl` ask-tier) and
  decapsulation hard-denied under four enumerated names (volta
  has no such tool, by design; undeclared spellings are refused
  by the covered registry).
- `policy/replay/` — 13 scenario files, 25 expectations:
  13 allow, 2 ask-tier, 10 deny, across validation workflows and
  the lumen design's adversarial classes (exfiltration, label
  confusion, sink spoofing).
- `policy/README.md` — the pin (appa 0.30.0 @
  `5060566a0d9fed034a5e68ec782a1b00714c7014`), the exact gate
  commands, the proposal → replay → approval change rule, and
  the known expressiveness gaps.

Gates, with the pinned binary: `describe --check` exit 0
(configuration loadable; the session-tool inventory cross-check
is unavailable in this layout, noted in the README), `replay`
13/13 files ok, exit 0. Nothing else in the repo changed. The
profile is not wired into dispatch; runtime enforcement is a
separate, Matt-gated step, as it was for the pilot.
