// #################################################################
// /qompassai/volta/rewrite/crates/volta-core/src/lib.rs
// Qompass AI Volta — Core Library
// SPDX-License-Identifier: AGPL-3.0-only OR Apache-2.0
// Copyright (c) 2026 Qompass AI
//
// Original work of Qompass AI (clean-room rewrite, 2026-10-10),
// written from the behavior/interface specification in
// rewrite/docs/SPEC.md, which derives from public protocol
// specifications and the predecessor's published documentation.
// #################################################################

#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Volta core: configuration (incl. proxy-chain schema and its
//! fail-closed validation), the data model, OpenPGP parsing and
//! allowlist enforcement, sealed tokens, the content-addressed
//! store, and the error taxonomy shared by every surface.

pub mod config;
pub mod error;
pub mod model;
pub mod pgp_key;
pub mod sealed;
pub mod store;
pub mod wkd;

/// The workspace version, single-sourced (C-7).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Current unix time in seconds.
#[must_use]
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Format unix seconds as an RFC 3339 UTC timestamp.
#[must_use]
pub fn rfc3339(unix_seconds: i64) -> String {
    chrono::DateTime::from_timestamp(unix_seconds, 0)
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default()
}
