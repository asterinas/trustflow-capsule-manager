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

use crate::errno;
use crate::error::errors::{Error, ErrorCode, ErrorLocation};
use crate::utils::serde_custom;

use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Padding;
use openssl::sign::RsaPssSaltlen;
use serde::{Deserialize, Serialize};

/// AES GCM Tag Size, in bytes
const AES_GCM_TAG_SIZE: usize = 128 / 8;
/// AES GCM Nonce length, in bytes
const AES_GCM_NONCE_LENGTH: usize = 96 / 8;

#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
/// Algorithms described by [RFC 7518](https://tools.ietf.org/html/rfc7518).
/// This enum is serialized `untagged`.
#[serde(untagged)]
pub enum Algorithm {
    /// Algorithms meant for Digital signature or MACs
    /// See [RFC7518#3](https://tools.ietf.org/html/rfc7518#section-3)
    Signature(SignatureAlgorithm),
    /// Algorithms meant for key management. The algorithms are either meant to
    /// encrypt a content encryption key or determine the content encryption
    /// key. See [RFC7518#4](https://tools.ietf.org/html/rfc7518#section-4)
    KeyManagement(KeyManagementAlgorithm),
    /// Algorithms meant for content encryption.
    /// See [RFC7518#5](https://tools.ietf.org/html/rfc7518#section-5)
    ContentEncryption(ContentEncryptionAlgorithm),
}

/// Options to be passed in while performing an encryption operation, if
/// required by the algorithm.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[derive(Default)]
pub enum EncryptionOptions {
    /// No options are required. Most algorithms do not require additional
    /// parameters
    #[default]
    None,
    /// Options for AES GCM encryption.
    AES_GCM {
        /// Initialization vector, or nonce for the AES GCM encryption. _MUST
        /// BE_ 96 bits long.
        ///
        /// AES GCM encryption operations should not reuse the nonce, or
        /// initialization vector. Users should keep track of previously
        /// used nonces and not reuse them. A simple way to keep track
        /// is to simply increment the nonce as a 96 bit counter.
        nonce: Vec<u8>,
    },
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
/// The algorithms supported for digital signature and MACs, defined by
/// [RFC7518#3](https://tools.ietf.org/html/rfc7518#section-3).
#[derive(Default)]
pub enum SignatureAlgorithm {
    /// No encryption/signature is included for the JWT.
    /// During verification, the signature _MUST BE_ empty or verification  will
    /// fail.
    #[serde(rename = "none")]
    None,
    /// HMAC using SHA-256
    #[default]
    HS256,
    /// HMAC using SHA-384
    HS384,
    /// HMAC using SHA-512
    HS512,
    /// RSASSA-PKCS1-v1_5 using SHA-256
    RS256,
    /// RSASSA-PKCS1-v1_5 using SHA-384
    RS384,
    /// RSASSA-PKCS1-v1_5 using SHA-512
    RS512,
    /// ECDSA using P-256 and SHA-256
    ES256,
    /// ECDSA using P-384 and SHA-384
    ES384,
    /// ECDSA using P-521 and SHA-512 --
    /// This variant is [unsupported](https://github.com/briansmith/ring/issues/268) and will probably never be.
    ES512,
    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
    /// The size of the salt value is the same size as the hash function output.
    PS256,
    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    /// The size of the salt value is the same size as the hash function output.
    PS384,
    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
    /// The size of the salt value is the same size as the hash function output.
    PS512,
}

/// Algorithms for key management as defined in [RFC7518#4](https://tools.ietf.org/html/rfc7518#section-4)
#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
#[derive(Default)]
pub enum KeyManagementAlgorithm {
    /// RSAES-PKCS1-v1_5
    RSA1_5,
    /// RSAES OAEP using default parameters
    #[serde(rename = "RSA-OAEP")]
    RSA_OAEP,
    /// RSAES OAEP using SHA-256 and MGF1 with SHA-256
    #[serde(rename = "RSA-OAEP-256")]
    RSA_OAEP_256,
    /// AES Key Wrap using 128-bit key. _Unsupported_
    A128KW,
    /// AES Key Wrap using 192-bit key. _Unsupported_.
    /// This is [not supported](https://github.com/briansmith/ring/issues/112) by `ring`.
    A192KW,
    /// AES Key Wrap using 256-bit key. _Unsupported_
    A256KW,
    /// Direct use of a shared symmetric key
    #[serde(rename = "dir")]
    #[default]
    DirectSymmetricKey,
    /// ECDH-ES using Concat KDF
    #[serde(rename = "ECDH-ES")]
    ECDH_ES,
    /// ECDH-ES using Concat KDF and "A128KW" wrapping
    #[serde(rename = "ECDH-ES+A128KW")]
    ECDH_ES_A128KW,
    /// ECDH-ES using Concat KDF and "A192KW" wrapping
    #[serde(rename = "ECDH-ES+A192KW")]
    ECDH_ES_A192KW,
    /// ECDH-ES using Concat KDF and "A256KW" wrapping
    #[serde(rename = "ECDH-ES+A256KW")]
    ECDH_ES_A256KW,
    /// Key wrapping with AES GCM using 128-bit key alg
    A128GCMKW,
    /// Key wrapping with AES GCM using 192-bit key alg.
    /// This is [not supported](https://github.com/briansmith/ring/issues/112) by `ring`.
    A192GCMKW,
    /// Key wrapping with AES GCM using 256-bit key alg
    A256GCMKW,
    /// PBES2 with HMAC SHA-256 and "A128KW" wrapping
    #[serde(rename = "PBES2-HS256+A128KW")]
    PBES2_HS256_A128KW,
    /// PBES2 with HMAC SHA-384 and "A192KW" wrapping
    #[serde(rename = "PBES2-HS384+A192KW")]
    PBES2_HS384_A192KW,
    /// PBES2 with HMAC SHA-512 and "A256KW" wrapping
    #[serde(rename = "PBES2-HS512+A256KW")]
    PBES2_HS512_A256KW,
}

impl KeyManagementAlgorithm {
    pub fn encrypt(self, data: &[u8], secret: &Secret) -> Result<Vec<u8>, Error> {
        use self::KeyManagementAlgorithm::*;

        match self {
            RSA1_5 | RSA_OAEP | RSA_OAEP_256 => Self::encrypt_rsa(data, secret, self),
            _ => Err(errno!(
                ErrorCode::Unknown,
                "unknown sign algorithm: {:?}",
                self
            )),
        }
    }

    pub fn decrypt(self, data: &[u8], secret: &Secret) -> Result<Vec<u8>, Error> {
        use self::KeyManagementAlgorithm::*;

        match self {
            RSA1_5 | RSA_OAEP | RSA_OAEP_256 => Self::decrypt_rsa(data, secret, self),
            _ => Err(errno!(
                ErrorCode::Unknown,
                "unknown sign algorithm: {:?}",
                self
            )),
        }
    }

    fn encrypt_rsa(
        data: &[u8],
        secret: &Secret,
        algorithm: KeyManagementAlgorithm,
    ) -> Result<Vec<u8>, Error> {
        use self::KeyManagementAlgorithm::*;
        let key = match *secret {
            Secret::PublicKey(ref key) => {
                // make sure it's a rsa private key
                key.rsa()?;
                key
            }
            _ => Err(errno!(
                ErrorCode::InvalidArgument,
                "Invalid secret type. A PublicKey is required"
            ))?,
        };
        let mut encrypter = openssl::encrypt::Encrypter::new(key)?;

        match algorithm {
            RSA1_5 => {
                encrypter.set_rsa_padding(Padding::PKCS1)?;
            }
            RSA_OAEP => {
                encrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
            }
            RSA_OAEP_256 => {
                encrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
                encrypter.set_rsa_oaep_md(openssl::hash::MessageDigest::sha256())?;
            }
            _ => unreachable!("Should not happen"),
        }

        // Create an output buffer
        let buffer_len = encrypter.encrypt_len(data)?;
        let mut encrypted = vec![0; buffer_len];
        // Encrypt and truncate the buffer
        let encrypted_len = encrypter.encrypt(data, &mut encrypted)?;
        encrypted.truncate(encrypted_len);
        Ok(encrypted)
    }

    pub fn decrypt_rsa(
        ciphertext: &[u8],
        secret: &Secret,
        algorithm: KeyManagementAlgorithm,
    ) -> Result<Vec<u8>, Error> {
        use self::KeyManagementAlgorithm::*;
        let key = match *secret {
            Secret::PrivateKey(ref key) => {
                // make sure it's a rsa private key
                key.rsa()?;
                key
            }
            _ => Err(errno!(
                ErrorCode::InvalidArgument,
                "Invalid secret type. A PrivateKey is required"
            ))?,
        };
        let mut decrypter = openssl::encrypt::Decrypter::new(key)?;

        match algorithm {
            RSA1_5 => {
                decrypter.set_rsa_padding(Padding::PKCS1)?;
            }
            RSA_OAEP => {
                decrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
            }
            RSA_OAEP_256 => {
                decrypter.set_rsa_padding(Padding::PKCS1_OAEP)?;
                decrypter.set_rsa_oaep_md(openssl::hash::MessageDigest::sha256())?;
            }
            _ => unreachable!("Should not happen"),
        }
        // Create an output buffer
        let buffer_len = decrypter.decrypt_len(&ciphertext)?;
        let mut decrypted = vec![0u8; buffer_len];
        // Encrypt and truncate the buffer
        let decrypted_len = decrypter.decrypt(&ciphertext, &mut decrypted)?;
        decrypted.truncate(decrypted_len);
        Ok(decrypted)
    }
}

/// Algorithms meant for content encryption.
/// See [RFC7518#5](https://tools.ietf.org/html/rfc7518#section-5)
#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
#[derive(Default)]
pub enum ContentEncryptionAlgorithm {
    /// AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm enc
    #[serde(rename = "A128CBC-HS256")]
    A128CBC_HS256,
    /// AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm enc
    #[serde(rename = "A192CBC-HS384")]
    A192CBC_HS384,
    /// AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm enc
    #[serde(rename = "A256CBC-HS512")]
    A256CBC_HS512,
    /// AES GCM using 128-bit key
    #[default]
    A128GCM,
    /// AES GCM using 192-bit key
    /// This is [not supported](https://github.com/briansmith/ring/issues/112) by `ring`.
    A192GCM,
    /// AES GCM using 256-bit key
    A256GCM,
}

/// The result returned from an encryption operation
// TODO: Might have to turn this into an enum
#[derive(Clone, Debug, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct EncryptionResult {
    /// The initialization vector, or nonce used in the encryption
    #[serde(rename = "iv", with = "serde_custom::byte_sequence")]
    pub nonce: Vec<u8>,
    /// The encrypted payload
    #[serde(rename = "ciphertext", with = "serde_custom::byte_sequence")]
    pub encrypted: Vec<u8>,
    /// The authentication tag
    #[serde(rename = "tag", with = "serde_custom::byte_sequence")]
    pub tag: Vec<u8>,
    /// Additional authenticated data that is integrity protected but not
    /// encrypted
    #[serde(rename = "aad", with = "serde_custom::byte_sequence")]
    pub additional_data: Vec<u8>,
}

/// The secrets used to sign and/or encrypt tokens
#[derive(Clone)]
pub enum Secret {
    /// Used with the `None` algorithm variant.
    None,
    /// Bytes used for HMAC secret. Can be constructed from a string literal
    Bytes(Vec<u8>),
    /// A private key constructed from a PEM-encoded PKCS#8 private key
    PrivateKey(PKey<Private>),
    /// A private key constructed from a PEM-encoded X.509 public key
    PublicKey(PKey<Public>),
}

impl Secret {
    pub fn public_key_from_pem(pem: &[u8]) -> Result<Secret, Error> {
        Ok(Secret::PublicKey(PKey::public_key_from_pem(pem)?))
    }

    pub fn public_key_from_cert_pem(pem: &[u8]) -> Result<Secret, Error> {
        Ok(Secret::PublicKey(
            openssl::x509::X509::from_pem(pem)?.public_key()?,
        ))
    }

    pub fn keypair_from_pem(pem: &[u8]) -> Result<Secret, Error> {
        Ok(Secret::PrivateKey(PKey::private_key_from_pem(pem)?))
    }
}

impl SignatureAlgorithm {
    /// Take some bytes and sign it according to the algorithm and secret
    /// provided.
    pub fn sign(&self, data: &[u8], secret: &Secret) -> Result<Vec<u8>, Error> {
        use self::SignatureAlgorithm::*;

        match self {
            HS256 | HS384 | HS512 => Err(errno!(ErrorCode::UnsupportedErr, "unsupport hmac now")),
            RS256 | RS384 | RS512 | PS256 | PS384 | PS512 => Self::sign_rsa(data, secret, self),
            ES256 | ES384 | ES512 => Err(errno!(ErrorCode::UnsupportedErr, "unsupport ecdsa now")),
            _ => Err(errno!(
                ErrorCode::Unknown,
                "unknown sign algorithm: {:?}",
                self
            )),
        }
    }

    /// Verify signature based on the algorithm and secret provided.
    pub fn verify(
        &self,
        expected_signature: &[u8],
        data: &[u8],
        key: &Secret,
    ) -> Result<(), Error> {
        use self::SignatureAlgorithm::*;

        match self {
            HS256 | HS384 | HS512 => Err(errno!(ErrorCode::UnsupportedErr, "unsupport hmac now")),
            RS256 | RS384 | RS512 | PS256 | PS384 | PS512 => {
                Self::verify_rsa(expected_signature, data, key, self)
            }
            ES256 | ES384 | ES512 => Err(errno!(ErrorCode::UnsupportedErr, "unsupport ecdsa now")),
            _ => Err(errno!(
                ErrorCode::Unknown,
                "unknown sign algorithm: {:?}",
                self
            )),
        }
    }

    fn sign_rsa(
        data: &[u8],
        secret: &Secret,
        algorithm: &SignatureAlgorithm,
    ) -> Result<Vec<u8>, Error> {
        let key = match *secret {
            Secret::PrivateKey(ref key) => {
                // make sure it's a rsa private key
                key.rsa()?;
                key
            }
            _ => Err(errno!(
                ErrorCode::InvalidArgument,
                "Invalid secret type. A PrivateKey is required"
            ))?,
        };

        use openssl::hash::MessageDigest;
        let mut signer = match algorithm {
            SignatureAlgorithm::RS256 => {
                let mut signer = openssl::sign::Signer::new(MessageDigest::sha256(), key)?;
                signer.set_rsa_padding(Padding::PKCS1)?;
                signer
            }
            SignatureAlgorithm::RS384 => {
                let mut signer = openssl::sign::Signer::new(MessageDigest::sha384(), key)?;
                signer.set_rsa_padding(Padding::PKCS1)?;
                signer
            }
            SignatureAlgorithm::RS512 => {
                let mut signer = openssl::sign::Signer::new(MessageDigest::sha512(), key)?;
                signer.set_rsa_padding(Padding::PKCS1)?;
                signer
            }
            SignatureAlgorithm::PS256 => {
                let mut signer = openssl::sign::Signer::new(MessageDigest::sha256(), key)?;
                signer.set_rsa_padding(Padding::PKCS1_PSS)?;
                signer.set_rsa_mgf1_md(MessageDigest::sha256())?;
                signer.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
                signer
            }
            SignatureAlgorithm::PS384 => {
                let mut signer = openssl::sign::Signer::new(MessageDigest::sha384(), key)?;
                signer.set_rsa_padding(Padding::PKCS1_PSS)?;
                signer.set_rsa_mgf1_md(MessageDigest::sha384())?;
                signer.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
                signer
            }
            SignatureAlgorithm::PS512 => {
                let mut signer = openssl::sign::Signer::new(MessageDigest::sha512(), key)?;
                signer.set_rsa_padding(Padding::PKCS1_PSS)?;
                signer.set_rsa_mgf1_md(MessageDigest::sha384())?;
                signer.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
                signer
            }
            _ => unreachable!("Should not happen"),
        };
        signer.update(data)?;
        let signature = signer.sign_to_vec()?;
        Ok(signature)
    }

    fn verify_rsa(
        expected_signature: &[u8],
        data: &[u8],
        key: &Secret,
        algorithm: &SignatureAlgorithm,
    ) -> Result<(), Error> {
        let key = match *key {
            Secret::PublicKey(ref key) => {
                // make sure it's a rsa public key
                key.rsa()?;
                key
            }
            _ => Err(errno!(
                ErrorCode::InvalidArgument,
                "Invalid secret type. A PublicKey is required"
            ))?,
        };

        use openssl::hash::MessageDigest;
        let mut verify = match algorithm {
            SignatureAlgorithm::RS256 => {
                let mut verify = openssl::sign::Verifier::new(MessageDigest::sha256(), key)?;
                verify.set_rsa_padding(Padding::PKCS1)?;
                verify
            }
            SignatureAlgorithm::RS384 => {
                let mut verify = openssl::sign::Verifier::new(MessageDigest::sha384(), key)?;
                verify.set_rsa_padding(Padding::PKCS1)?;
                verify
            }
            SignatureAlgorithm::RS512 => {
                let mut verify = openssl::sign::Verifier::new(MessageDigest::sha512(), key)?;
                verify.set_rsa_padding(Padding::PKCS1)?;
                verify
            }
            SignatureAlgorithm::PS256 => {
                let mut verify = openssl::sign::Verifier::new(MessageDigest::sha256(), key)?;
                verify.set_rsa_padding(Padding::PKCS1_PSS)?;
                verify.set_rsa_mgf1_md(MessageDigest::sha256())?;
                verify.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
                verify
            }
            SignatureAlgorithm::PS384 => {
                let mut verify = openssl::sign::Verifier::new(MessageDigest::sha384(), key)?;
                verify.set_rsa_padding(Padding::PKCS1_PSS)?;
                verify.set_rsa_mgf1_md(MessageDigest::sha384())?;
                verify.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
                verify
            }
            SignatureAlgorithm::PS512 => {
                let mut verify = openssl::sign::Verifier::new(MessageDigest::sha512(), key)?;
                verify.set_rsa_padding(Padding::PKCS1_PSS)?;
                verify.set_rsa_mgf1_md(MessageDigest::sha384())?;
                verify.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
                verify
            }
            _ => unreachable!("Should not happen"),
        };
        verify.update(data)?;
        let res = verify.verify(expected_signature)?;
        if !res {
            return Err(errno!(ErrorCode::CryptoErr, "Signature verify failed."));
        }
        Ok(())
    }
}

pub(crate) fn random_aes_gcm_nonce() -> Result<Vec<u8>, Error> {
    let mut nonce: Vec<u8> = vec![0; AES_GCM_NONCE_LENGTH];
    openssl::rand::rand_bytes(&mut nonce)?;
    Ok(nonce)
}

impl ContentEncryptionAlgorithm {
    /// Convenience function to generate a new random key with the required
    /// length
    pub fn generate_key(&self) -> Result<Vec<u8>, Error> {
        use self::ContentEncryptionAlgorithm::*;

        let length: usize = match self {
            A128GCM => 128 / 8,
            A256GCM => 256 / 8,
            _ => Err(errno!(
                ErrorCode::UnsupportedErr,
                "Unsupported encryption method: {:?}",
                self
            ))?,
        };

        let mut key: Vec<u8> = vec![0; length];
        openssl::rand::rand_bytes(&mut key)?;
        Ok(key)
    }

    /// Encrypt some payload with the provided algorithm
    pub fn encrypt(
        &self,
        payload: &[u8],
        aad: &[u8],
        key: &[u8],
        options: &EncryptionOptions,
    ) -> Result<EncryptionResult, Error> {
        use self::ContentEncryptionAlgorithm::*;

        match self {
            A128GCM | A192GCM | A256GCM => self.aes_gcm_encrypt(payload, aad, key, options),
            _ => Err(errno!(
                ErrorCode::UnsupportedErr,
                "Unsupported encryption method: {:?}",
                self
            )),
        }
    }

    /// Decrypt some payload with the provided algorithm
    pub fn decrypt(&self, encrypted: &EncryptionResult, key: &[u8]) -> Result<Vec<u8>, Error> {
        use self::ContentEncryptionAlgorithm::*;

        match self {
            A128GCM | A192GCM | A256GCM => self.aes_gcm_decrypt(encrypted, key),
            _ => Err(errno!(
                ErrorCode::UnsupportedErr,
                "Unsupported encryption method: {:?}",
                self
            )),
        }
    }

    /// Generate a new random `EncryptionOptions` based on the algorithm
    pub(crate) fn random_encryption_options(&self) -> Result<EncryptionOptions, Error> {
        use self::ContentEncryptionAlgorithm::*;
        match self {
            A128GCM | A192GCM | A256GCM => Ok(EncryptionOptions::AES_GCM {
                nonce: random_aes_gcm_nonce()?,
            }),
            _ => Err(errno!(
                ErrorCode::UnsupportedErr,
                "Unsupported encryption method: {:?}",
                self
            )),
        }
    }

    fn aes_gcm_encrypt(
        &self,
        payload: &[u8],
        aad: &[u8],
        key: &[u8],
        options: &EncryptionOptions,
    ) -> Result<EncryptionResult, Error> {
        use self::ContentEncryptionAlgorithm::*;

        let algorithm = match self {
            A128GCM => openssl::symm::Cipher::aes_128_gcm(),
            A256GCM => openssl::symm::Cipher::aes_256_gcm(),
            _ => Err(errno!(
                ErrorCode::UnsupportedErr,
                "Unsupported encryption method: {:?}",
                self
            ))?,
        };

        let nonce = match *options {
            EncryptionOptions::AES_GCM { ref nonce } => Ok(nonce),
            _ => Err(errno!(
                ErrorCode::UnsupportedErr,
                "Unsupported encryption mode"
            )),
        }?;

        let mut tag = [0u8; AES_GCM_TAG_SIZE];
        let cipher =
            openssl::symm::encrypt_aead(algorithm, key, Some(nonce), aad, payload, &mut tag)?;
        Ok(EncryptionResult {
            nonce: nonce.to_vec(),
            encrypted: cipher,
            tag: tag.as_ref().to_vec(),
            additional_data: aad.to_vec(),
        })
    }

    fn aes_gcm_decrypt(&self, encrypted: &EncryptionResult, key: &[u8]) -> Result<Vec<u8>, Error> {
        use self::ContentEncryptionAlgorithm::*;

        let algorithm = match self {
            A128GCM => openssl::symm::Cipher::aes_128_gcm(),
            A256GCM => openssl::symm::Cipher::aes_256_gcm(),
            _ => Err(errno!(
                ErrorCode::UnsupportedErr,
                "Unsupported encryption method: {:?}",
                self
            ))?,
        };

        let plaintext = openssl::symm::decrypt_aead(
            algorithm,
            key,
            Some(&encrypted.nonce),
            &encrypted.additional_data,
            &encrypted.encrypted,
            &encrypted.tag,
        )?;
        Ok(plaintext)
    }
}
