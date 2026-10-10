# CLAUDE.md

<!-- SPDX-License-Identifier: AGPL-3.0-only OR Apache-2.0 -->
<!-- Copyright (c) 2026 Qompass AI -->

Read `AGENTS.md` first (project memory protocol), then
`.ai/memory/current.md` and `.ai/memory/decisions.md`.

The clean-room rewrite lives in `rewrite/`. Its behavior contract is
`rewrite/docs/SPEC.md` (copied from the clean-room spec of
2026-10-10); implementation follows the spec, never the predecessor
tree's source. Tiger Style Rust applies to all rewrite code;
alphabetical order applies to modules, files, functions, constants,
commands, and list entries (dependency order only where Rust
requires it).
