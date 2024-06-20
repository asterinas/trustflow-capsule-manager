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

use base64::engine::general_purpose;
use base64::Engine as _;
use openssl::pkey::{PKey, Public};
use openssl::sha::Sha256;
use openssl::x509::X509;

use crate::error::errors::{AuthResult, Error, ErrorCode, ErrorLocation};
use crate::{cm_assert, errno, return_errno};

pub fn sha256(buf: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(buf);
    hasher.finish()
}

pub fn sha256_with_base64_encode(buf: &[u8]) -> String {
    general_purpose::STANDARD.encode(sha256(buf))
}

pub fn get_cert_from_cert_chain(
    cert_chain: &Vec<Vec<u8>>,
    index: usize,
    format: &str,
) -> AuthResult<X509> {
    let cert = match format {
        "PEM" => openssl::x509::X509::from_pem(cert_chain.get(index).ok_or(errno!(
            ErrorCode::InvalidArgument,
            "cert chain index{} is empty",
            index
        ))?)?,
        "DER" => openssl::x509::X509::from_der(cert_chain.get(index).ok_or(errno!(
            ErrorCode::InvalidArgument,
            "cert chain index{} is empty",
            index
        ))?)?,
        _ => return_errno!(ErrorCode::InvalidArgument, "format {} not support", format),
    };
    Ok(cert)
}

pub fn get_public_key_from_cert_chain(
    cert_chain: &Vec<Vec<u8>>,
    index: usize,
    format: &str,
) -> AuthResult<PKey<Public>> {
    let cert = get_cert_from_cert_chain(cert_chain, index, format)?;
    Ok(cert.public_key()?)
}

pub fn verify_cert_chain(cert_chain: &Vec<Vec<u8>>, format: &str) -> AuthResult<()> {
    cm_assert!(!cert_chain.is_empty(), "cert chain is empty");

    for index in 0..(cert_chain.len() - 1) {
        let parent_pk = get_public_key_from_cert_chain(cert_chain, index + 1, format)?;
        let current_cert = get_cert_from_cert_chain(cert_chain, index, format)?;
        // verify certification signature
        cm_assert!(
            current_cert.verify(&parent_pk)?,
            "certification-{} verify signature failed",
            index
        );
    }
    Ok(())
}

pub fn vec_str_to_vec_u8(vec_str: &Vec<String>) -> Vec<Vec<u8>> {
    return vec_str.iter().map(|x| x.clone().into_bytes()).collect();
}

// generate party_id from cert
// RFC4648 BASE32(SHA256(DER(X.509 public key)))
pub fn gen_party_id(pk: &PKey<Public>) -> AuthResult<String> {
    Ok(base32::encode(
        base32::Alphabet::RFC4648 { padding: false },
        &sha256(&pk.public_key_to_der()?),
    ))
}