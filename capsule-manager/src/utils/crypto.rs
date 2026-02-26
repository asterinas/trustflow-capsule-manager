// Copyright 2024 Ant Group Co., Ltd.
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

use openssl::asn1::Asn1Time;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier};
use openssl::x509::{X509NameBuilder, X509};

use crate::common::constants;
use crate::error::errors::{AuthResult, Error, ErrorCode, ErrorLocation};
use rand::prelude::StdRng;
use rand::SeedableRng;
use rsa::pkcs1::EncodeRsaPrivateKey;

use sm4::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit};

pub fn create_cert(
    key_pair: &openssl::pkey::PKey<openssl::pkey::Private>,
    x509_names: std::collections::hash_map::Iter<&str, &str>,
    days: u32,
) -> Result<X509, ErrorStack> {
    let mut x509_name = X509NameBuilder::new()?;
    for (&k, &v) in x509_names {
        x509_name.append_entry_by_text(k, v)?;
    }
    let x509_name = x509_name.build();
    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;

    cert_builder.set_subject_name(&x509_name)?;
    cert_builder.set_issuer_name(&x509_name)?;
    cert_builder.set_pubkey(&key_pair)?;
    let not_before: Asn1Time = Asn1Time::from_unix(*constants::FIRST_SIGN_TIME)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after: Asn1Time =
        Asn1Time::from_unix(*constants::FIRST_SIGN_TIME + days as i64 * 24 * 60 * 60)?;
    cert_builder.set_not_after(&not_after)?;
    cert_builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .digital_signature()
            .build()?,
    )?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    cert_builder.sign(&key_pair, MessageDigest::sha256())?;
    let cert = cert_builder.build();
    Ok(cert)
}

// return pkcs8 private key and X509 cert from seed
pub fn gen_rsa_key_pair_from_seed(seed: [u8; 32]) -> AuthResult<(String, String)> {
    let mut rng = StdRng::from_seed(seed);
    let rsa_pri_key = rsa::RsaPrivateKey::new(&mut rng, constants::RSA_BIT_LEN as usize)?;

    // rsa::pkcs1::error is a private module, can not impl From <rsa::pkcs1::error:Error> for Error
    // so we convert it to rsa::errors::Error first and then convert it to capsule manager's Error
    let pkcs1_res = rsa_pri_key.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF);
    let pkcs1_pri_key = match pkcs1_res {
        Ok(pkcs1_pri_key) => Ok(pkcs1_pri_key),
        Err(e) => Err(rsa::errors::Error::from(e)),
    }?;

    let openssl_pri_key = openssl::rsa::Rsa::private_key_from_pem(pkcs1_pri_key.as_bytes())?;
    let openssl_pkey = openssl::pkey::PKey::from_rsa(openssl_pri_key)?;

    // convert private key to pkcs8
    let pkcs8_pri_key = String::from_utf8(openssl_pkey.private_key_to_pem_pkcs8()?)?;

    let x509_cert = create_cert(
        &openssl_pkey,
        constants::X509NAME.iter(),
        constants::CERT_DAYS,
    )?;
    let x509_cert_pem = String::from_utf8(x509_cert.to_pem()?)?;

    Ok((pkcs8_pri_key, x509_cert_pem))
}

type Sm4EcbEnc = ecb::Encryptor<sm4::Sm4>;
type Sm4EcbDec = ecb::Decryptor<sm4::Sm4>;
type Sm4CbcEnc = cbc::Encryptor<sm4::Sm4>;
type Sm4CbcDec = cbc::Decryptor<sm4::Sm4>;

/// SM4-ECB encrypt with PKCS7 padding.
/// key: 16 bytes.
pub fn sm4_ecb_encrypt(key: &[u8], plaintext: &[u8]) -> AuthResult<Vec<u8>> {
    let encryptor =
        Sm4EcbEnc::new_from_slice(key).map_err(|e| crate::errno!(ErrorCode::CryptoErr, "{}", e))?;
    Ok(encryptor.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
}

/// SM4-ECB decrypt with PKCS7 unpadding.
/// key: 16 bytes.
pub fn sm4_ecb_decrypt(key: &[u8], ciphertext: &[u8]) -> AuthResult<Vec<u8>> {
    let decryptor =
        Sm4EcbDec::new_from_slice(key).map_err(|e| crate::errno!(ErrorCode::CryptoErr, "{}", e))?;
    decryptor
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|e| crate::errno!(ErrorCode::CryptoErr, "{}", e))
}

/// SM4-CBC encrypt with PKCS7 padding.
/// key: 16 bytes, iv: 16 bytes.
pub fn sm4_cbc_encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> AuthResult<Vec<u8>> {
    let encryptor = Sm4CbcEnc::new_from_slices(key, iv)
        .map_err(|e| crate::errno!(ErrorCode::CryptoErr, "{}", e))?;
    Ok(encryptor.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
}

/// SM4-CBC decrypt with PKCS7 unpadding.
/// key: 16 bytes, iv: 16 bytes.
pub fn sm4_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> AuthResult<Vec<u8>> {
    let decryptor = Sm4CbcDec::new_from_slices(key, iv)
        .map_err(|e| crate::errno!(ErrorCode::CryptoErr, "{}", e))?;
    decryptor
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|e| crate::errno!(ErrorCode::CryptoErr, "{}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== SM4-ECB tests ==========

    #[test]
    fn test_sm4_ecb_basic() {
        let key = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
        let plaintext = b"hello sm4 ecb!!";
        let ciphertext = sm4_ecb_encrypt(&key, plaintext).unwrap();
        let decrypted = sm4_ecb_decrypt(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_sm4_ecb_block_aligned() {
        let key = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
        let plaintext = b"1234567890abcdef"; // exactly 16 bytes
        let ciphertext = sm4_ecb_encrypt(&key, plaintext).unwrap();
        assert_eq!(ciphertext.len(), 32); // PKCS7 adds a full block
        let decrypted = sm4_ecb_decrypt(&key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_sm4_ecb_empty() {
        let key = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
        let ciphertext = sm4_ecb_encrypt(&key, b"").unwrap();
        assert_eq!(ciphertext.len(), 16);
        let decrypted = sm4_ecb_decrypt(&key, &ciphertext).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_sm4_ecb_invalid_key() {
        assert!(sm4_ecb_encrypt(&[0u8; 15], b"test").is_err());
        assert!(sm4_ecb_decrypt(&[0u8; 15], &[0u8; 16]).is_err());
    }

    // ========== SM4-CBC tests ==========

    #[test]
    fn test_sm4_cbc_basic() {
        let key = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
        let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let plaintext = b"hello sm4 cbc mode test!";
        let ciphertext = sm4_cbc_encrypt(&key, &iv, plaintext).unwrap();
        let decrypted = sm4_cbc_decrypt(&key, &iv, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_sm4_cbc_block_aligned() {
        let key = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
        let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let plaintext = b"1234567890abcdef";
        let ciphertext = sm4_cbc_encrypt(&key, &iv, plaintext).unwrap();
        assert_eq!(ciphertext.len(), 32);
        let decrypted = sm4_cbc_decrypt(&key, &iv, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_sm4_cbc_empty() {
        let key = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
        let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let ciphertext = sm4_cbc_encrypt(&key, &iv, b"").unwrap();
        assert_eq!(ciphertext.len(), 16);
        let decrypted = sm4_cbc_decrypt(&key, &iv, &ciphertext).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_sm4_cbc_invalid_key() {
        let iv = [0u8; 16];
        assert!(sm4_cbc_encrypt(&[0u8; 15], &iv, b"test").is_err());
        assert!(sm4_cbc_decrypt(&[0u8; 15], &iv, &[0u8; 16]).is_err());
    }

    #[test]
    fn test_sm4_cbc_invalid_iv() {
        let key = [0u8; 16];
        assert!(sm4_cbc_encrypt(&key, &[0u8; 12], b"test").is_err());
        assert!(sm4_cbc_decrypt(&key, &[0u8; 12], &[0u8; 16]).is_err());
    }

    #[test]
    fn test_sm4_cbc_wrong_key() {
        let key = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
        let wrong_key = hex::decode("fedcba98765432100123456789abcdef").unwrap();
        let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let ciphertext = sm4_cbc_encrypt(&key, &iv, b"secret data").unwrap();
        let result = sm4_cbc_decrypt(&wrong_key, &iv, &ciphertext);
        // wrong key -> padding error or wrong plaintext
        match result {
            Err(_) => {}
            Ok(d) => assert_ne!(d, b"secret data"),
        }
    }

    #[test]
    fn test_sm4_cbc_large_data() {
        let key = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
        let iv = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let plaintext = vec![0xABu8; 1024];
        let ciphertext = sm4_cbc_encrypt(&key, &iv, &plaintext).unwrap();
        let decrypted = sm4_cbc_decrypt(&key, &iv, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
