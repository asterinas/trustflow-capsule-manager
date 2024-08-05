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

mod key_management_impl;
mod policy_management_impl;
mod ra_impl;

use async_trait::async_trait;

use crate::common::constants;
use crate::core::policy_enforcer::PolicyEnforcer;
use crate::error::errors::{AuthResult, Error, ErrorCode, ErrorLocation};
use crate::storage::in_memory_storage::InMemoryStorage;
use crate::storage::storage_engine::StorageEngine;
use crate::utils::jwt::jwa::{ContentEncryptionAlgorithm, KeyManagementAlgorithm, Secret};
use crate::utils::jwt::jwe::{Jwe, RegisteredHeader};
use crate::utils::jwt::{jwe, jws};
use crate::utils::tool::gen_party_id;
use crate::utils::type_convert::from;
use crate::{cm_assert, errno, return_errno};
use log::{debug, info};
use openssl::rsa::Rsa;
use sdc_apis::secretflowapis::v2::sdc::capsule_manager;
use sdc_apis::secretflowapis::v2::sdc::{
    UnifiedAttestationGenerationParams, UnifiedAttestationReportParams,
};
use sdc_apis::secretflowapis::v2::{Code, Status};

#[async_trait]
pub trait CapsuleManagerService {
    async fn get_ra_cert(
        &self,
        request: &capsule_manager::GetRaCertRequest,
    ) -> AuthResult<capsule_manager::GetRaCertResponse>;

    async fn create_data_keys(
        &self,
        request: &capsule_manager::EncryptedRequest,
    ) -> AuthResult<capsule_manager::EncryptedResponse>;

    async fn get_data_keys(
        &self,
        request: &capsule_manager::EncryptedRequest,
    ) -> AuthResult<capsule_manager::EncryptedResponse>;

    async fn delete_data_key(
        &self,
        request: &capsule_manager::EncryptedRequest,
    ) -> AuthResult<capsule_manager::EncryptedResponse>;

    async fn get_export_data_key(
        &self,
        request: &capsule_manager::EncryptedRequest,
    ) -> AuthResult<capsule_manager::EncryptedResponse>;

    // warning: the rpc interface only take effect for party cert,
    // doesn't take effect for certs derived from the party cert
    async fn register_cert(
        &self,
        request: &capsule_manager::EncryptedRequest,
    ) -> AuthResult<capsule_manager::EncryptedResponse>;

    async fn create_data_policy(
        &self,
        request: &capsule_manager::EncryptedRequest,
    ) -> AuthResult<capsule_manager::EncryptedResponse>;

    async fn list_data_policy(
        &self,
        request: &capsule_manager::EncryptedRequest,
    ) -> AuthResult<capsule_manager::EncryptedResponse>;

    async fn add_data_rule(
        &self,
        request: &capsule_manager::EncryptedRequest,
    ) -> AuthResult<capsule_manager::EncryptedResponse>;

    async fn delete_data_policy(
        &self,
        request: &capsule_manager::EncryptedRequest,
    ) -> AuthResult<capsule_manager::EncryptedResponse>;

    async fn delete_data_rule(
        &self,
        request: &capsule_manager::EncryptedRequest,
    ) -> AuthResult<capsule_manager::EncryptedResponse>;

    async fn create_result_data_key(
        &self,
        request: &capsule_manager::EncryptedRequest,
    ) -> AuthResult<capsule_manager::EncryptedResponse>;
}

fn get_request<T: prost::Message + std::default::Default + for<'a> serde::Deserialize<'a>>(
    private_key_pem: &[u8],
    encrypt_request: &capsule_manager::EncryptedRequest,
) -> AuthResult<(T, Option<jws::Jws>)> {
    let content = encrypt_request
        .message
        .as_ref()
        .ok_or(errno!(ErrorCode::NotFound, "Request content"))?;

    let jwe: jwe::Jwe = from(&content)?;
    log::debug!(target: "capsule_manager_log", "{:?}", &jwe);
    let secret = Secret::keypair_from_pem(private_key_pem)?;
    let plain_text = jwe.decrypt(&secret)?;
    if encrypt_request.has_signature {
        log::debug!(target: "capsule_manager_log", "{}", String::from_utf8(plain_text.clone())?);
        let jws: jws::Jws = serde_json::from_slice(plain_text.as_ref())?;
        return Ok((serde_json::from_slice(jws.payload())?, Some(jws)));
    } else {
        return Ok((serde_json::from_slice(plain_text.as_ref())?, None));
    }
}

fn encrypt_response<T: prost::Message + std::default::Default + for<'a> serde::Serialize>(
    secret: Secret,
    response: &T,
) -> AuthResult<capsule_manager::EncryptedResponse> {
    let header = RegisteredHeader {
        cek_algorithm: KeyManagementAlgorithm::RSA_OAEP,
        enc_algorithm: ContentEncryptionAlgorithm::A128GCM,
    };
    // create json web signature
    let jwe =
        Jwe::create_from_encrypting(&header, &secret, serde_json::to_vec(&response)?.as_ref())?;
    // serialization
    let json_content = serde_json::to_string(&jwe)?;
    Ok(capsule_manager::EncryptedResponse {
        status: Some(Status {
            code: Code::Ok as i32,
            message: "success".to_owned(),
            details: vec![],
        }),
        message: serde_json::from_str(&json_content)?,
    })
}

/// Verify the JWS using a given key(`public_key_pem`), or using the
/// self-contained certificate chain.
fn verify_signature(
    party_id: &str,
    public_key_pem: Option<&[u8]>,
    jws: &jws::Jws,
) -> AuthResult<()> {
    if public_key_pem.is_none() && !jws.has_x5c()? {
        return_errno!(
            ErrorCode::NotFound,
            "party {} public key is empty",
            party_id
        );
    }

    let secret = match public_key_pem {
        Some(pem) => Secret::public_key_from_pem(pem)?,
        None => Secret::PublicKey(jws.public_key()?),
    };
    jws.verify(&secret)?;

    // Make sure the party id is derived from the public key
    cm_assert!(
        party_id == gen_party_id(&jws.root_public_key()?)?,
        "party_id {} is wrong derived from public key",
        party_id
    );

    Ok(())
}

#[derive(Debug, Clone)]
pub struct CapsuleManagerImpl {
    // root certificate
    kek_cert: Vec<u8>,
    // root private key
    kek_pri: Vec<u8>,
    // data storage client
    storage_engine: std::sync::Arc<dyn StorageEngine>,
    // run mode for authmanager
    // Production Mode: need RA
    // Simulation Mode: doesn't need RA
    mode: String,
    // policy enforer
    policy_enforcer: PolicyEnforcer,
}

impl Default for CapsuleManagerImpl {
    fn default() -> Self {
        // get public-private key pair
        let (cert_pem, private_key) = {
            let rsa = Rsa::generate(constants::RSA_BIT_LEN).expect("create rsa key pair failed");

            let key_pair = openssl::pkey::PKey::from_rsa(rsa).unwrap();

            let cert = crate::utils::crypto::create_cert(
                &key_pair,
                constants::X509NAME.iter(),
                constants::CERT_DAYS,
            )
            .unwrap();

            let cert_pem = cert.to_pem().expect("create x509 cert pem failed");
            let prikey_pem = key_pair
                .private_key_to_pem_pkcs8()
                .expect("create private key pem failed");
            (cert_pem, prikey_pem)
        };
        let storage_engine: std::sync::Arc<dyn StorageEngine> =
            std::sync::Arc::new(InMemoryStorage::new());
        Self {
            kek_cert: cert_pem,
            kek_pri: private_key,
            storage_engine: storage_engine.clone(),
            mode: "simulation".to_owned(),
            policy_enforcer: PolicyEnforcer::new(),
        }
    }
}

/// At startup, verify that the remote attestation
/// report can be generated normally.
fn launch_check() -> AuthResult<()> {
    // fill report params
    let report_params = UnifiedAttestationGenerationParams {
        // tee instance id: unused field, filled with empty string
        tee_identity: "".to_owned(),
        report_type: "Passport".to_owned(),
        report_hex_nonce: "".to_owned(),
        report_params: Some(UnifiedAttestationReportParams {
            str_report_identity: "".to_owned(),
            hex_user_data: "".to_owned(),
            json_nested_reports: "".to_owned(),
            hex_spid: "".to_owned(),
            pem_public_key: "".to_owned(),
        }),
    };

    trustflow_attestation_rs::generate_attestation_report(
        serde_json::to_string(&report_params)
            .map_err(|e| {
                errno!(
                    ErrorCode::InternalErr,
                    "report_params {:?} to json err: {:?}",
                    &report_params,
                    e
                )
            })?
            .as_str(),
    )
    .map_err(|e| {
        errno!(
            ErrorCode::InternalErr,
            "runified_attestation_generate_auth_report err: {:?}",
            e
        )
    })?;
    info!(target: "capsule_manager_log", "generate_attestation_report success.");
    return Ok(());
}

impl CapsuleManagerImpl {
    pub fn new(
        storage_engine: std::sync::Arc<dyn StorageEngine>,
        mode: &str,
        cert_pem: &[u8],
        private_key: &[u8],
    ) -> Result<Self, Error> {
        cm_assert!(
            mode == "simulation" || mode == "production",
            "mode {} is not supported",
            mode
        );

        if mode == "production" {
            launch_check()?;
        }

        debug!(target: "capsule_manager_log", "cert:\n {:?}", String::from_utf8(cert_pem.to_owned()));

        Ok(Self {
            kek_cert: cert_pem.to_owned(),
            kek_pri: private_key.to_owned(),
            storage_engine: storage_engine.clone(),
            mode: mode.to_owned(),
            policy_enforcer: PolicyEnforcer::new(),
        })
    }
}

#[async_trait]
impl CapsuleManagerService for CapsuleManagerImpl {
    async fn get_ra_cert(
        &self,
        request: &capsule_manager::GetRaCertRequest,
    ) -> AuthResult<capsule_manager::GetRaCertResponse> {
        self.get_ra_cert_impl(request).await
    }

    async fn create_data_keys(
        &self,
        request: &capsule_manager::EncryptedRequest,
    ) -> AuthResult<capsule_manager::EncryptedResponse> {
        self.create_data_keys_impl(request).await
    }

    async fn get_data_keys(
        &self,
        request: &capsule_manager::EncryptedRequest,
    ) -> AuthResult<capsule_manager::EncryptedResponse> {
        self.get_data_keys_impl(request).await
    }

    async fn delete_data_key(
        &self,
        request: &capsule_manager::EncryptedRequest,
    ) -> AuthResult<capsule_manager::EncryptedResponse> {
        self.delete_data_key_impl(request).await
    }

    async fn get_export_data_key(
        &self,
        request: &capsule_manager::EncryptedRequest,
    ) -> AuthResult<capsule_manager::EncryptedResponse> {
        self.get_export_data_key_impl(request).await
    }

    // warning: the rpc interface only take effect for party cert,
    // doesn't take effect for certs derived from the party cert
    async fn register_cert(
        &self,
        request: &capsule_manager::EncryptedRequest,
    ) -> AuthResult<capsule_manager::EncryptedResponse> {
        self.register_cert_impl(request).await
    }

    async fn create_data_policy(
        &self,
        request: &capsule_manager::EncryptedRequest,
    ) -> AuthResult<capsule_manager::EncryptedResponse> {
        self.create_data_policy_impl(request).await
    }

    async fn list_data_policy(
        &self,
        request: &capsule_manager::EncryptedRequest,
    ) -> AuthResult<capsule_manager::EncryptedResponse> {
        self.list_data_policy_impl(request).await
    }

    async fn add_data_rule(
        &self,
        request: &capsule_manager::EncryptedRequest,
    ) -> AuthResult<capsule_manager::EncryptedResponse> {
        self.add_data_rule_impl(request).await
    }

    async fn delete_data_policy(
        &self,
        request: &capsule_manager::EncryptedRequest,
    ) -> AuthResult<capsule_manager::EncryptedResponse> {
        self.delete_data_policy(request).await
    }

    async fn delete_data_rule(
        &self,
        request: &capsule_manager::EncryptedRequest,
    ) -> AuthResult<capsule_manager::EncryptedResponse> {
        self.delete_data_rule_impl(request).await
    }

    async fn create_result_data_key(
        &self,
        request: &capsule_manager::EncryptedRequest,
    ) -> AuthResult<capsule_manager::EncryptedResponse> {
        self.create_result_data_key_impl(&request).await
    }
}
