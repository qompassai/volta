// #################################################################
// /qompassai/volta/database/src/wkd.rs
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

use super::Result;
use crate::openpgp::types::HashAlgorithm;
use zbase32;

// cannibalized from
// https://gitlab.com/sequoia-pgp/sequoia/blob/master/net/src/wkd.rs

pub fn encode_wkd(address: impl AsRef<str>) -> Result<(String, String)> {
    let (local_part, domain) = split_address(address)?;

    let local_part_encoded = encode_local_part(local_part);

    Ok((local_part_encoded, domain))
}

fn split_address(email_address: impl AsRef<str>) -> Result<(String, String)> {
    let email_address = email_address.as_ref();
    let v: Vec<&str> = email_address.split('@').collect();
    if v.len() != 2 {
        return Err(anyhow!("Malformed email address".to_owned()));
    };

    // Convert to lowercase without tailoring, i.e. without taking any
    // locale into account. See:
    // https://doc.rust-lang.org/std/primitive.str.html#method.to_lowercase
    let local_part = v[0].to_lowercase();
    let domain = v[1].to_lowercase();

    Ok((local_part, domain))
}

fn encode_local_part<S: AsRef<str>>(local_part: S) -> String {
    let local_part = local_part.as_ref();

    let mut digest = vec![0; 20];
    let mut ctx = HashAlgorithm::SHA1.context().expect("must be implemented");
    ctx.update(local_part.as_bytes());
    let _ = ctx.digest(&mut digest);

    // After z-base-32 encoding 20 bytes, it will be 32 bytes long.
    zbase32::encode_full_bytes(&digest[..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_local_part_succed() {
        let encoded_part = encode_local_part("test1");
        assert_eq!("stnkabub89rpcphiz4ppbxixkwyt1pic", encoded_part);
        assert_eq!(32, encoded_part.len());
    }

    #[test]
    fn email_address_from() {
        let (local_part, domain) = split_address("test1@example.com").unwrap();
        assert_eq!(local_part, "test1");
        assert_eq!(domain, "example.com");
    }
}
