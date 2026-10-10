#![recursion_limit = "1024"]
// #################################################################
// /qompassai/volta/src/main.rs
// Qompass AI Volta Keyserver Entry Point
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 Qompass AI
//
// Volta is derived from Hagrid, the software behind
// keys.openpgp.org, and this material is licensed under the
// GNU Affero General Public License, version 3 only (see
// LICENSE-AGPL). Contributions authored by Qompass AI are
// dual-licensed under AGPL-3.0 or Apache-2.0 at the
// recipient's choice (see NOTICE); that choice does not
// extend to upstream-derived material, which remains
// AGPL-3.0 only.

#[macro_use]
extern crate anyhow;
use anyhow::Result;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate rocket;

#[cfg(test)]
extern crate regex;

extern crate volta_database as database;

use gettext_macros::init_i18n;

#[cfg(debug_assertions)]
init_i18n!("volta", en, de, ja);

#[cfg(not(debug_assertions))]
init_i18n!("volta", en);

mod anonymize_utils;
mod counters;
mod dump;
mod gettext_strings;
mod i18n;
mod i18n_helpers;
mod mail;
mod rate_limiter;
mod sealed_state;
mod template_helpers;
mod tokens;
mod web;

#[launch]
fn rocket() -> _ {
    web::serve().expect("Rocket config must succeed")
}
