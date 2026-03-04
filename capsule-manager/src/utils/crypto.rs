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

use sm4::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

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

type Sm4CbcEnc = cbc::Encryptor<sm4::Sm4>;
type Sm4CbcDec = cbc::Decryptor<sm4::Sm4>;

const SM4_BLOCK_SIZE: usize = 16;

/// PKCS7 pad `data` to a multiple of `block_size`.
fn pkcs7_pad(data: &[u8], block_size: usize) -> Vec<u8> {
    let pad_len = block_size - (data.len() % block_size);
    let mut out = Vec::with_capacity(data.len() + pad_len);
    out.extend_from_slice(data);
    out.resize(data.len() + pad_len, pad_len as u8);
    out
}

/// Remove PKCS7 padding.
fn pkcs7_unpad(data: &[u8]) -> AuthResult<&[u8]> {
    if data.is_empty() {
        return Err(crate::errno!(
            ErrorCode::CryptoErr,
            "empty data for pkcs7 unpad"
        ));
    }
    let pad_len = *data.last().unwrap() as usize;
    if pad_len == 0 || pad_len > SM4_BLOCK_SIZE || pad_len > data.len() {
        return Err(crate::errno!(ErrorCode::CryptoErr, "invalid pkcs7 padding"));
    }
    if !data[data.len() - pad_len..]
        .iter()
        .all(|&b| b == pad_len as u8)
    {
        return Err(crate::errno!(
            ErrorCode::CryptoErr,
            "invalid pkcs7 padding bytes"
        ));
    }
    Ok(&data[..data.len() - pad_len])
}

/// Salted SM4-CBC encrypt.
///
/// 1. Generate random 16-byte salt and 16-byte iv.
/// 2. PKCS7-pad (salt || plaintext).
/// 3. SM4/CBC/NoPadding encrypt.
/// 4. Return salt || iv || ciphertext.
pub fn sm4_cbc_salt_encrypt(key: &[u8], plaintext: &[u8]) -> AuthResult<Vec<u8>> {
    use rand::RngCore;
    let mut salt = [0u8; SM4_BLOCK_SIZE];
    let mut iv = [0u8; SM4_BLOCK_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut iv);

    // salt || plaintext -> PKCS7 pad
    let mut salted_plain = Vec::with_capacity(SM4_BLOCK_SIZE + plaintext.len());
    salted_plain.extend_from_slice(&salt);
    salted_plain.extend_from_slice(plaintext);
    let padded = pkcs7_pad(&salted_plain, SM4_BLOCK_SIZE);

    // SM4 key must be exactly 16 bytes; truncate if longer.
    let key = &key[..SM4_BLOCK_SIZE.min(key.len())];
    // SM4/CBC/NoPadding encrypt
    let encryptor = Sm4CbcEnc::new_from_slices(key, &iv)
        .map_err(|e| crate::errno!(ErrorCode::CryptoErr, "{}", e))?;
    let encrypted = encryptor.encrypt_padded_vec_mut::<NoPadding>(&padded);

    // output: salt || iv || encrypted
    let mut result = Vec::with_capacity(SM4_BLOCK_SIZE + SM4_BLOCK_SIZE + encrypted.len());
    result.extend_from_slice(&salt);
    result.extend_from_slice(&iv);
    result.extend_from_slice(&encrypted);
    Ok(result)
}

/// Salted SM4-CBC decrypt.
///
/// Input format: salt(16) || iv(16) || ciphertext.
/// 1. Extract salt, iv, ciphertext.
/// 2. SM4/CBC/NoPadding decrypt -> salt || plaintext || padding.
/// 3. Remove salt (first 16 bytes) and PKCS7 padding.
pub fn sm4_cbc_salt_decrypt(key: &[u8], data: &[u8]) -> AuthResult<Vec<u8>> {
    if data.len() < SM4_BLOCK_SIZE * 3 {
        return Err(crate::errno!(
            ErrorCode::CryptoErr,
            "salted SM4-CBC ciphertext too short ({})",
            data.len()
        ));
    }
    let iv = &data[SM4_BLOCK_SIZE..SM4_BLOCK_SIZE * 2];
    let ciphertext = &data[SM4_BLOCK_SIZE * 2..];

    if ciphertext.len() % SM4_BLOCK_SIZE != 0 {
        return Err(crate::errno!(
            ErrorCode::CryptoErr,
            "salted SM4-CBC ciphertext not block-aligned"
        ));
    }

    // SM4 key must be exactly 16 bytes; truncate if longer.
    let key = &key[..SM4_BLOCK_SIZE.min(key.len())];
    // SM4/CBC/NoPadding decrypt
    let decryptor = Sm4CbcDec::new_from_slices(key, iv)
        .map_err(|e| crate::errno!(ErrorCode::CryptoErr, "{}", e))?;
    let decrypted = decryptor
        .decrypt_padded_vec_mut::<NoPadding>(ciphertext)
        .map_err(|e| crate::errno!(ErrorCode::CryptoErr, "{}", e))?;

    // decrypted = salt(16) || plaintext || pkcs7_padding
    // remove PKCS7 padding first, then strip salt
    let unpadded = pkcs7_unpad(&decrypted)?;
    if unpadded.len() < SM4_BLOCK_SIZE {
        return Err(crate::errno!(
            ErrorCode::CryptoErr,
            "decrypted data shorter than salt size"
        ));
    }
    Ok(unpadded[SM4_BLOCK_SIZE..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== Salted SM4-CBC tests ==========

    #[test]
    fn test_sm4_cbc_salt_basic() {
        let key = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
        let plaintext = b"hello salted sm4!";
        let encrypted = sm4_cbc_salt_encrypt(&key, plaintext).unwrap();
        // output = salt(16) + iv(16) + ciphertext(>=16)
        assert!(encrypted.len() >= 48);
        let decrypted = sm4_cbc_salt_decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_sm4_cbc_salt_empty_plaintext() {
        let key = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
        let encrypted = sm4_cbc_salt_encrypt(&key, b"").unwrap();
        let decrypted = sm4_cbc_salt_decrypt(&key, &encrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_sm4_cbc_salt_block_aligned() {
        let key = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
        let plaintext = b"1234567890abcdef"; // 16 bytes
        let encrypted = sm4_cbc_salt_encrypt(&key, plaintext).unwrap();
        let decrypted = sm4_cbc_salt_decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_sm4_cbc_salt_large_data() {
        let key = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
        let plaintext = vec![0xCDu8; 1024];
        let encrypted = sm4_cbc_salt_encrypt(&key, &plaintext).unwrap();
        let decrypted = sm4_cbc_salt_decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_sm4_cbc_salt_too_short() {
        let key = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
        assert!(sm4_cbc_salt_decrypt(&key, &[0u8; 32]).is_err());
    }

    #[test]
    fn test_sm4_cbc_salt_wrong_key() {
        let key = hex::decode("0123456789abcdeffedcba9876543210").unwrap();
        let wrong_key = hex::decode("fedcba98765432100123456789abcdef").unwrap();
        let encrypted = sm4_cbc_salt_encrypt(&key, b"secret").unwrap();
        let result = sm4_cbc_salt_decrypt(&wrong_key, &encrypted);
        assert!(result.is_err() || result.unwrap() != b"secret");
    }
}
