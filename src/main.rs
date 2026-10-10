#![recursion_limit = "1024"]
// #################################################################
// /qompassai/volta/src/main.rs
// Qompass AI Volta Keyserver Entry Point
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Qompass AI
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
