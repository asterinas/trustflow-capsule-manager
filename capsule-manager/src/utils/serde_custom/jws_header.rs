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
use std::fmt;

use crate::utils::jwt::jws;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{de, Deserializer, Serializer};

/// Serialize a jws header into Base64 URL encoded string
pub fn serialize<S>(value: &jws::RegisteredHeader, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let value_str = serde_json::to_string(value)
        .map_err(|_| serde::ser::Error::custom("jws header to json failed."))?;
    let base64 = URL_SAFE_NO_PAD.encode(&value_str);
    serializer.serialize_str(&base64)
}

/// Deserialize a byte sequence from Base64 URL encoded string
pub fn deserialize<'de, D>(deserializer: D) -> Result<jws::RegisteredHeader, D::Error>
where
    D: Deserializer<'de>,
{
    struct JwsHeaderVisitor;

    impl<'de> de::Visitor<'de> for JwsHeaderVisitor {
        type Value = jws::RegisteredHeader;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a URL safe base64 encoding of a jws header")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let bytes = URL_SAFE_NO_PAD
                .decode(value.as_bytes())
                .map_err(E::custom)?;

            let header: Self::Value = serde_json::from_slice(&bytes).map_err(E::custom)?;
            Ok(header)
        }
    }

    deserializer.deserialize_str(JwsHeaderVisitor)
}
