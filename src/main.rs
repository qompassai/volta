#![recursion_limit = "1024"]

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
init_i18n!("volta", en );

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
