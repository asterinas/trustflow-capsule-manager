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

use super::jwa::{Secret, SignatureAlgorithm};
use crate::error::errors::{Error, ErrorCode, ErrorLocation};
use crate::utils::serde_custom;
use crate::utils::tool::verify_cert_chain;
use crate::{cm_assert, cm_assert_eq, errno};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use openssl::pkey::{PKey, Public};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

pub const SEPARATOR: &str = ".";

#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
/// Registered JWS header fields.
/// The alg defaults to HS256 and typ is automatically
/// set to `JWT`. All the other fields are optional.
/// The fields are defined by [RFC7519#5](https://tools.ietf.org/html/rfc7519#section-5) and additionally in
/// [RFC7515#4.1](https://tools.ietf.org/html/rfc7515#section-4.1).
// TODO: Implement verification for registered headers and support custom
// headers
pub struct RegisteredHeader {
    /// Algorithms, as defined in [RFC 7518](https://tools.ietf.org/html/rfc7518), used to sign or encrypt the JWT
    /// Serialized to `alg`.
    /// Defined in [RFC7515#4.1.1](https://tools.ietf.org/html/rfc7515#section-4.1.1).
    #[serde(rename = "alg")]
    pub algorithm: SignatureAlgorithm,

    /// X.509 public key certificate chain. This is currently not implemented
    /// (correctly). Serialized to `x5c`.
    /// Defined in [RFC7515#4.1.6](https://tools.ietf.org/html/rfc7515#section-4.1.6).
    #[serde(rename = "x5c", skip_serializing_if = "Option::is_none")]
    pub x509_chain: Option<Vec<String>>,
}

static FIELDS_NUM: usize = 3;
/// This is for serialization, and deserialisation when the signature
/// hasn't been verified, not exposed externally
#[derive(Serialize, Deserialize, Debug)]
pub struct Jws {
    #[serde(rename = "protected", with = "serde_custom::byte_sequence")]
    protected_header: Vec<u8>,

    #[serde(with = "serde_custom::byte_sequence")]
    payload: Vec<u8>,

    #[serde(with = "serde_custom::byte_sequence")]
    signature: Vec<u8>,
}

impl Jws {
    // Create json web signature from original data
    pub fn create_from_signing(
        header: &RegisteredHeader,
        secret: &Secret,
        payload: &[u8],
    ) -> Result<Jws, Error> {
        let protected_header = serde_json::to_string(&header)?;
        let sign_input = vec![
            URL_SAFE_NO_PAD.encode(&protected_header),
            URL_SAFE_NO_PAD.encode(payload),
        ]
        .join(SEPARATOR);

        let signature = header.algorithm.sign(sign_input.as_bytes(), secret)?;
        Ok(Jws {
            protected_header: protected_header.as_bytes().to_vec(),
            payload: payload.to_owned(),
            signature,
        })
    }

    pub fn payload<'a>(&'a self) -> &'a [u8] {
        self.payload.as_ref()
    }

    pub fn has_x5c(&self) -> Result<bool, Error> {
        let header: RegisteredHeader = serde_json::from_slice(&self.protected_header)?;
        Ok(!header.x509_chain.is_none())
    }

    pub fn public_key(&self) -> Result<PKey<Public>, Error> {
        let header: RegisteredHeader = serde_json::from_slice(&self.protected_header)?;
        match header.x509_chain.as_ref() {
            Some(x509_chain) => {
                let origin_cert_chain: Result<Vec<Vec<u8>>, _> =
                    x509_chain.iter().map(|x| STANDARD.decode(x)).collect();
                let origin_cert_chain = origin_cert_chain?;
                verify_cert_chain(&origin_cert_chain, "DER")?;

                let cert = openssl::x509::X509::from_der(
                    &origin_cert_chain
                        .get(0)
                        .ok_or(errno!(ErrorCode::InvalidArgument, "cert chain is empty"))?,
                )?;
                return Ok(cert.public_key()?);
            }
            None => return Err(errno!(ErrorCode::InvalidArgument, "cert chain is empty")),
        }
    }

    pub fn root_public_key(&self) -> Result<PKey<Public>, Error> {
        let header: RegisteredHeader = serde_json::from_slice(&self.protected_header)?;
        match header.x509_chain.as_ref() {
            Some(x509_chain) => {
                let origin_cert_chain: Result<Vec<Vec<u8>>, _> =
                    x509_chain.iter().map(|x| STANDARD.decode(x)).collect();
                let origin_cert_chain = origin_cert_chain?;
                verify_cert_chain(&origin_cert_chain, "DER")?;

                let cert = openssl::x509::X509::from_der(
                    &origin_cert_chain
                        .get(x509_chain.len() - 1)
                        .ok_or(errno!(ErrorCode::InvalidArgument, "cert chain is empty"))?,
                )?;
                return Ok(cert.public_key()?);
            }
            None => return Err(errno!(ErrorCode::InvalidArgument, "cert chain is empty")),
        }
    }

    pub fn verify(&self, secret: &Secret) -> Result<(), Error> {
        let header: RegisteredHeader = serde_json::from_slice(&self.protected_header)?;
        let sign_input = vec![
            URL_SAFE_NO_PAD.encode(&self.protected_header),
            URL_SAFE_NO_PAD.encode(&self.payload),
        ]
        .join(SEPARATOR);
        header
            .algorithm
            .verify(&self.signature, sign_input.as_bytes(), secret)?;
        Ok(())
    }

    pub fn decode_from_compact(compact: &[u8]) -> Result<Jws, Error> {
        let compact_str = std::str::from_utf8(compact)
            .map_err(|_| errno!(ErrorCode::DecodeError, "UTF8 decode error"))?;
        // split the jws compact format
        let parts: Result<VecDeque<Vec<u8>>, _> = compact_str
            .split(SEPARATOR)
            .map(|s| URL_SAFE_NO_PAD.decode(s))
            .collect();
        let mut parts = parts?;

        // make sure it's have `FIELDS_NUM` fields.
        cm_assert_eq!(parts.len(), FIELDS_NUM);
        Ok(Jws {
            protected_header: serde_json::from_slice(parts.pop_front().unwrap().as_ref())?,
            payload: parts.pop_front().unwrap(),
            signature: parts.pop_front().unwrap(),
        })
    }

    pub fn encode_to_compact(&self) -> Result<String, Error> {
        let compact = vec![
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&self.protected_header)?),
            URL_SAFE_NO_PAD.encode(&self.payload),
            URL_SAFE_NO_PAD.encode(&self.signature),
        ]
        .join(SEPARATOR);
        Ok(compact)
    }
}

#[cfg(test)]
mod tests {
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;

    use crate::utils::jwt::jwa::{Secret, SignatureAlgorithm};

    use super::{Jws, RegisteredHeader};

    #[test]
    fn test_sign_rsa() {
        let keypair = Rsa::generate(2048).unwrap();
        let keypair = PKey::from_rsa(keypair).unwrap();
        let pub_key = keypair.public_key_to_pem().unwrap();

        let header = RegisteredHeader {
            algorithm: SignatureAlgorithm::RS256,
            ..Default::default()
        };
        let secret = Secret::PrivateKey(keypair);
        let payload = b"hello";
        // Create json web signature
        let jws = Jws::create_from_signing(&header, &secret, payload).unwrap();
        // Encode compact format
        let jws_compact = jws.encode_to_compact().unwrap();
        // Decode from compact format
        let jws2 = Jws::decode_from_compact(&jws_compact.as_bytes()).unwrap();
        let secret = Secret::public_key_from_pem(pub_key.as_ref()).unwrap();
        // verify
        jws2.verify(&secret).unwrap();
    }
}
