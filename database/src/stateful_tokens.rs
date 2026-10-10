// #################################################################
// /qompassai/volta/database/src/stateful_tokens.rs
// Qompass AI Stateful Tokens
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

use anyhow::Result;
use std::fs::{File, create_dir_all, remove_file};
use std::io::{Read, Write};
use std::path::PathBuf;

use std::str;

pub struct StatefulTokens {
    token_dir: PathBuf,
}

impl StatefulTokens {
    pub fn new(token_dir: impl Into<PathBuf>) -> Result<Self> {
        let token_dir = token_dir.into();
        create_dir_all(&token_dir)?;

        info!("Opened stateful token store");
        info!("token_dir: '{}'", token_dir.display());

        Ok(StatefulTokens { token_dir })
    }

    pub fn new_token(&self, token_type: &str, payload: &[u8]) -> Result<String> {
        use rand::distributions::Alphanumeric;
        use rand::{Rng, thread_rng};

        let mut rng = thread_rng();
        // samples from [a-zA-Z0-9]
        // 43 chars ~ 256 bit
        let name: String = rng.sample_iter(&Alphanumeric).take(43).collect();
        let dir = self.token_dir.join(token_type);
        create_dir_all(&dir)?;

        let mut fd = File::create(dir.join(&name))?;
        fd.write_all(payload)?;

        Ok(name)
    }

    pub fn pop_token(&self, token_type: &str, token: &str) -> Result<String> {
        let path = self.token_dir.join(token_type).join(token);
        let buf = {
            let mut fd = File::open(&path)?;
            let mut buf = Vec::default();

            fd.read_to_end(&mut buf)?;
            buf.into_boxed_slice()
        };

        remove_file(path)?;

        Ok(str::from_utf8(&buf)?.to_string())
    }
}
