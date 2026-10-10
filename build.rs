// #################################################################
// /qompassai/volta/build.rs
// Qompass AI Build Script (Version Stamping)
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

extern crate vergen;

use vergen::{ConstantsFlags, generate_cargo_keys};

fn main() {
    // Generate the 'cargo:' key output
    generate_cargo_keys(ConstantsFlags::all()).expect("Unable to generate the cargo keys!");
}
