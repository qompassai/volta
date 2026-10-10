# 2026-10-10 — Dual licensing (AGPL-3.0 / Apache-2.0)

Matt ruled (2026-10-10): dual AGPL-3.0 + Apache-2.0 for volta if
possible, superseding the Oct 9 sole-Apache normalization.

Feasibility, as implemented:

- Qompass-authored material (Oct 9 docs, Nix flake, in-tree i18n
  module, new code contributions) is dual-licensed AGPL-3.0 OR
  Apache-2.0 at the recipient's choice; recorded in NOTICE.
- All three crates (volta, volta-database, voltactl) arrived in the
  May-2025 Hagrid import and are substantially upstream-derived;
  their manifests declare AGPL-3.0-only. Apache terms cannot be
  granted over Hagrid's code, so the combined work remains AGPL-3.0.
- LICENSE-AGPL restored byte-identically from git history
  (pre-91d0633). LICENSE stays the canonical Apache-2.0 text.
  LICENSE-QCDA is NOT restored; the Q-CDA scheme is retired here.
- Per-file headers: Qompass-authored files carry the dual SPDX
  line; derived files carry AGPL-3.0-only plus a pointer to NOTICE.
- .ai/memory/current.md still says "License: Apache-2.0 (SPDX)";
  curated memory left untouched per protocol — this note is the
  correction of record.
