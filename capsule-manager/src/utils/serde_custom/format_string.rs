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

//! Serialize a sequence of bytes as base64 URL encoding vice-versa for
//! deserialization
use std::{fmt, str};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::de::{self, DeserializeOwned};
use serde::{Deserialize, Deserializer, Serialize};

pub fn deserialize_from_str<'de, S, D>(deserializer: D) -> Result<Option<S>, D::Error>
where
    S: Serialize + DeserializeOwned,
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    if s.is_empty() {
        Ok(None)
    } else {
        let r: S = serde_json::from_str(s.as_str()).map_err(de::Error::custom)?;
        Ok(Some(r))
    }
}

/// Deserialize a byte sequence from Base64 encoded string
pub fn deserialize_from_base64_str<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BytesVisitor;

    impl<'de> de::Visitor<'de> for BytesVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a URL safe base64 encoding of a byte sequence")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let bytes = STANDARD.decode(value.as_bytes()).map_err(E::custom)?;
            Ok(bytes)
        }
    }

    deserializer.deserialize_str(BytesVisitor)
}
