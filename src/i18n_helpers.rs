// #################################################################
// /qompassai/volta/src/i18n_helpers.rs
// Qompass AI I18n Helpers
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

use crate::database::Query;
use crate::i18n::I18n;
use gettext_macros::i18n;

pub fn describe_query_error(i18n: &I18n, q: &Query) -> String {
    match q {
        Query::ByFingerprint(fpr) => {
            i18n!(i18n.catalog, "No key found for fingerprint {}"; fpr)
        }
        Query::ByKeyID(key_id) => {
            i18n!(i18n.catalog, "No key found for key id {}"; key_id)
        }
        Query::ByEmail(email) => {
            i18n!(i18n.catalog, "No key found for email address {}"; email)
        }
        Query::InvalidShort() => {
            i18n!(i18n.catalog, "Search by Short Key ID is not supported.")
        }
        Query::Invalid() => i18n!(i18n.catalog, "Invalid search query."),
    }
}
