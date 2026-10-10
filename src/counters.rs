// #################################################################
// /qompassai/volta/src/counters.rs
// Qompass AI Counters
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

use lazy_static::lazy_static;
use rocket_prometheus::prometheus;

use crate::anonymize_utils;

use crate::database::types::Email;

lazy_static! {
    static ref KEY_UPLOAD: LabelCounter =
        LabelCounter::new("volta_key_upload", "Uploaded keys", &["result"]);
    static ref MAIL_SENT: LabelCounter = LabelCounter::new(
        "volta_mail_sent",
        "Sent verification mails",
        &["type", "domain"]
    );
    static ref KEY_ADDRESS_PUBLISHED: LabelCounter = LabelCounter::new(
        "volta_key_address_published",
        "Verified email addresses",
        &["domain"]
    );
    static ref KEY_ADDRESS_UNPUBLISHED: LabelCounter = LabelCounter::new(
        "volta_key_address_unpublished",
        "Unpublished email addresses",
        &["domain"]
    );
}

pub fn register_counters(registry: &prometheus::Registry) {
    KEY_UPLOAD.register(registry);

    MAIL_SENT.register(registry);

    KEY_ADDRESS_PUBLISHED.register(registry);
    KEY_ADDRESS_UNPUBLISHED.register(registry);
}

pub fn inc_key_upload(upload_result: &str) {
    KEY_UPLOAD.inc(&[upload_result]);
}

pub fn inc_mail_sent(mail_type: &str, email: &Email) {
    let anonymized_adddress = anonymize_utils::anonymize_address_fallback(email);
    MAIL_SENT.inc(&[mail_type, &anonymized_adddress]);
}

pub fn inc_address_published(email: &Email) {
    let anonymized_adddress = anonymize_utils::anonymize_address_fallback(email);
    KEY_ADDRESS_PUBLISHED.inc(&[&anonymized_adddress]);
}

pub fn inc_address_unpublished(email: &Email) {
    let anonymized_adddress = anonymize_utils::anonymize_address_fallback(email);
    KEY_ADDRESS_UNPUBLISHED.inc(&[&anonymized_adddress]);
}

struct LabelCounter {
    prometheus_counter: prometheus::IntCounterVec,
}

impl LabelCounter {
    fn new(name: &str, help: &str, labels: &[&str]) -> Self {
        let opts = prometheus::Opts::new(name, help);
        let prometheus_counter = prometheus::IntCounterVec::new(opts, labels).unwrap();
        Self { prometheus_counter }
    }

    fn register(&self, registry: &prometheus::Registry) {
        registry
            .register(Box::new(self.prometheus_counter.clone()))
            .unwrap();
    }

    fn inc(&self, values: &[&str]) {
        self.prometheus_counter.with_label_values(values).inc();
    }
}
