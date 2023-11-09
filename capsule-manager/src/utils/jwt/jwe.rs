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

use super::jwa::{ContentEncryptionAlgorithm, EncryptionResult, KeyManagementAlgorithm, Secret};
use crate::error::errors::Error;
use crate::utils::serde_custom;
use serde::{Deserialize, Serialize};

/// Registered JWE header fields.
/// The fields are defined by [RFC 7516#4.1](https://tools.ietf.org/html/rfc7516#section-4.1)
#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredHeader {
    /// Algorithm used to encrypt or determine the value of the Content
    /// Encryption Key
    #[serde(rename = "alg")]
    pub cek_algorithm: KeyManagementAlgorithm,

    /// Content encryption algorithm used to perform authenticated encryption
    /// on the plaintext to produce the ciphertext and the Authentication Tag
    #[serde(rename = "enc")]
    pub enc_algorithm: ContentEncryptionAlgorithm,
}

/// This is for serialization, and deserialisation when the signature
/// hasn't been verified, not exposed externally
#[derive(Serialize, Deserialize, Debug)]
pub struct Jwe {
    #[serde(rename = "protected", with = "serde_custom::jwe_header")]
    protected_header: RegisteredHeader,

    #[serde(with = "serde_custom::byte_sequence")]
    encrypted_key: Vec<u8>,

    #[serde(flatten)]
    encrypted: EncryptionResult,
}

impl Jwe {
    pub fn create_from_encrypting(
        header: &RegisteredHeader,
        secret: &Secret,
        plaintext_payload: &[u8],
    ) -> Result<Jwe, Error> {
        let cek = header.enc_algorithm.generate_key()?;
        let options = header.enc_algorithm.random_encryption_options()?;
        let encrypted = header
            .enc_algorithm
            .encrypt(plaintext_payload, b"", &cek, &options)?;
        let encrypted_key = header.cek_algorithm.encrypt(&cek, secret)?;

        Ok(Jwe {
            protected_header: header.to_owned(),
            encrypted_key,
            encrypted,
        })
    }

    pub fn decrypt(&self, secret: &Secret) -> Result<Vec<u8>, Error> {
        let cek = self
            .protected_header
            .cek_algorithm
            .decrypt(&self.encrypted_key, secret)?;
        self.protected_header
            .enc_algorithm
            .decrypt(&self.encrypted, &cek)
    }
}

#[cfg(test)]
mod tests {

    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;

    use crate::utils::jwt::jwa::{ContentEncryptionAlgorithm, KeyManagementAlgorithm, Secret};

    use super::{Jwe, RegisteredHeader};

    #[test]
    fn test_encrypt_rsa() {
        let keypair = Rsa::generate(2048).unwrap();
        let keypair = PKey::from_rsa(keypair).unwrap();
        let pub_key = keypair.public_key_to_pem().unwrap();

        let header = RegisteredHeader {
            cek_algorithm: KeyManagementAlgorithm::RSA_OAEP,
            enc_algorithm: ContentEncryptionAlgorithm::A256GCM,
            ..Default::default()
        };
        let secret = Secret::public_key_from_pem(pub_key.as_ref()).unwrap();
        let payload = b"hello";
        // create json web signature
        let jwe = Jwe::create_from_encrypting(&header, &secret, payload).unwrap();
        // test serialization
        serde_json::to_string(&jwe).unwrap();
        // decrypt
        let secret = Secret::PrivateKey(keypair);
        jwe.decrypt(&secret).unwrap();
    }
}
