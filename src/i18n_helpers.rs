// #################################################################
// /qompassai/volta/src/i18n_helpers.rs
// Qompass AI I18n Helpers
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
