// #################################################################
// /qompassai/volta/src/web/debug_web.rs
// Qompass AI Debug Web
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

use std::io;

use crate::i18n::I18n;

use crate::dump::{self, Kind};
use crate::i18n_helpers::describe_query_error;
use crate::web::MyResponse;

use crate::database::{Database, KeyDatabase, Query};

#[get("/debug?<q>")]
pub fn debug_info(db: &rocket::State<KeyDatabase>, i18n: I18n, q: String) -> MyResponse {
    let query = match q.parse::<Query>() {
        Ok(query) => query,
        Err(_) => return MyResponse::bad_request_plain("bad request"),
    };
    let fp = match db.lookup_primary_fingerprint(&query) {
        Some(fp) => fp,
        None => return MyResponse::not_found_plain(describe_query_error(&i18n, &query)),
    };

    let armored_key = match db.by_fpr(&fp) {
        Some(armored_key) => armored_key,
        None => return MyResponse::not_found_plain(describe_query_error(&i18n, &query)),
    };

    let mut result = Vec::new();
    let dump_result = dump::dump(
        &mut io::Cursor::new(armored_key.as_bytes()),
        &mut result,
        false,
        false,
        None,
        32 * 4 + 80,
    );
    match dump_result {
        Ok(Kind::Cert) => match String::from_utf8(result) {
            Ok(dump_text) => MyResponse::plain(dump_text),
            Err(e) => MyResponse::ise(e.into()),
        },
        Ok(_) => MyResponse::ise(anyhow!("Internal parsing error!")),
        Err(e) => MyResponse::ise(e),
    }
}
