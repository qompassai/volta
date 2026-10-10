// #################################################################
// /qompassai/volta/src/web/wkd.rs
// Qompass AI Wkd
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

use crate::database::{Database, KeyDatabase};
use crate::web::MyResponse;

// WKD queries
#[get("/.well-known/openpgpkey/<domain>/hu/<wkd_hash>")]
pub fn wkd_query(db: &rocket::State<KeyDatabase>, domain: String, wkd_hash: String) -> MyResponse {
    match db.by_domain_and_hash_wkd(&domain, &wkd_hash) {
        Some(key) => MyResponse::wkd(key, &wkd_hash),
        None => MyResponse::not_found_plain("No key found for this email address."),
    }
}

// Policy requests.
// 200 response with an empty body.
#[get("/.well-known/openpgpkey/<_domain>/policy")]
pub fn wkd_policy(_domain: String) -> MyResponse {
    MyResponse::plain("".to_string())
}
