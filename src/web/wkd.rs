// #################################################################
// /qompassai/volta/src/web/wkd.rs
// Qompass AI Wkd
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
