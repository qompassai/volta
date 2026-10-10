// #################################################################
// /qompassai/volta/rewrite/crates/volta-crypto/src/lib.rs
// Qompass AI Volta — Cryptography
// SPDX-License-Identifier: AGPL-3.0-only OR Apache-2.0
// Copyright (c) 2026 Qompass AI
//
// Original work of Qompass AI (clean-room rewrite, 2026-10-10).
// No hand-rolled primitives: every algorithm comes from a
// maintained crate (RustCrypto ml-kem / ml-dsa / dalek lines).
// #################################################################

#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Volta cryptography: the SPEC 11 policy, the SPEC 7.1 hybrid
//! PQC ephemeral suites, and native-domain identity signing.

pub mod policy;
pub mod signing;
pub mod suites;
