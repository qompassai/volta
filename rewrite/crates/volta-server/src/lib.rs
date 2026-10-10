//! crates/volta-server/src/lib.rs - volta HTTP surfaces.
//!
//! Dual licensed under AGPL-3.0-only OR Apache-2.0.
//!
//! Implements SPEC sections 6-10 and 13.5: HKP, VKS, WKD, the
//! ephemeral-key API, MCP, A2A, WebAuthn operator auth, the relay
//! endpoint, and the minimal web surface. All state lives behind
//! `AppState`; handlers are thin over volta-core's store.

#![forbid(unsafe_code)]

pub mod a2a;
pub mod app;
pub mod auth;
pub mod ephemeral;
pub mod hkp;
pub mod http_util;
pub mod jcs;
pub mod mcp;
pub mod relay;
pub mod state;
pub mod vks;
pub mod web;
pub mod webauthn;
pub mod wkd_http;
