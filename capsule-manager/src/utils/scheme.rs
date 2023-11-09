// Copyright 2023 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::error::errors::{Error, ErrorCode, ErrorLocation};
use crate::{errno, return_errno};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub enum AsymmetricScheme {
    #[default]
    RSA,
    SM2,
}

impl FromStr for AsymmetricScheme {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "RSA" => Ok(AsymmetricScheme::RSA),
            "SM2" => Ok(AsymmetricScheme::SM2),
            _ => return_errno!(
                ErrorCode::InternalErr,
                "unsupported asymmetric scheme: {}",
                s
            ),
        }
    }
}

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub enum HmacScheme {
    #[default]
    SHA256,
    SM3,
}

impl FromStr for HmacScheme {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "SHA256" => Ok(HmacScheme::SHA256),
            "SM3" => Ok(HmacScheme::SM3),
            _ => return_errno!(ErrorCode::InternalErr, "unsupported hmac schema: {}", s),
        }
    }
}
