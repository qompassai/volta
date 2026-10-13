# Terminology: plain naming (Matt, 2026-10-12; applied 2026-10-13)

Matt's standing rule: never describe volta — or any Qompass project —
as "clean room" / "clean-room". Volta is a rewrite.

Applied in commit e154205 (docs(terminology)): the term was scrubbed
from standing project text — CLAUDE.md, policy/appa.toml, rewrite/
NOTICE line 1, workspace + crate Cargo.toml headers/descriptions,
crate lib.rs header comments, flake.nix (comments + description),
rust-toolchain.toml, docs/SPEC.md (status line + §1 heading, now
"Provenance"), and the mdBook introduction.

Deliberately left, per the fathom precedent: rewrite/docs/
ASSESSMENTS.md is a dated assessment record (2026-10-10) and keeps
its wording as history (its line 487 is additionally a literal path
reference outside this repo). Git history and branch names are not
rewritten.

Gates after the scrub (rewrite/ workspace): fmt clean, clippy
-D warnings clean, cargo test 43 passed / 0 failed, mdBook builds.
