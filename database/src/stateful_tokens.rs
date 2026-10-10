// #################################################################
// /qompassai/volta/database/src/stateful_tokens.rs
// Qompass AI Stateful Tokens
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
