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

mod constant;
mod key_management_impl;
mod policy_management_impl;
mod ra_impl;

use self::constant::RSA_BIT_LEN;
use crate::utils::jwt::{jwe, jws};
use crate::utils::scheme::AsymmetricScheme;
use capsule_manager::core::policy_enforcer::PolicyEnforcer;
use capsule_manager::error::errors::{AuthResult, Error, ErrorCode, ErrorLocation};
use capsule_manager::storage::in_memory_storage::InMemoryStorage;
use capsule_manager::storage::storage_engine::StorageEngine;
use capsule_manager::utils::jwt::jwa::{
    ContentEncryptionAlgorithm, KeyManagementAlgorithm, Secret,
};
use capsule_manager::utils::jwt::jwe::{Jwe, RegisteredHeader};
use capsule_manager::utils::tool::gen_party_id;
use capsule_manager::utils::type_convert::from;
use capsule_manager::{cm_assert, errno, return_errno};
use capsule_manager_tonic::secretflowapis::v2::sdc::capsule_manager::*;
use capsule_manager_tonic::secretflowapis::v2::{Code, Status};
use log::debug;
use openssl::rsa::Rsa;
use std::str::FromStr;
use tonic::{Request, Response};

fn get_request<T: prost::Message + std::default::Default + for<'a> serde::Deserialize<'a>>(
    private_key_pem: &[u8],
    encrypt_request: &EncryptedRequest,
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
) -> AuthResult<EncryptedResponse> {
    let header = RegisteredHeader {
        cek_algorithm: KeyManagementAlgorithm::RSA_OAEP,
        enc_algorithm: ContentEncryptionAlgorithm::A128GCM,
    };
    // create json web signature
    let jwe =
        Jwe::create_from_encrypting(&header, &secret, serde_json::to_vec(&response)?.as_ref())?;
    // serialization
    let json_content = serde_json::to_string(&jwe)?;
    Ok(EncryptedResponse {
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

#[derive(Debug)]
pub struct CapsuleManagerImpl {
    // root certificate
    kek_cert: Vec<u8>,
    // root private key
    kek_pri: Vec<u8>,
    // public-private key algorithm: SM2/RSA
    scheme: AsymmetricScheme,
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
            let rsa = Rsa::generate(RSA_BIT_LEN).expect("create rsa key pair failed");

            let key_pair = openssl::pkey::PKey::from_rsa(rsa).unwrap();

            let cert = crate::utils::crypto::create_cert(
                &key_pair,
                constant::X509NAME.iter(),
                constant::CERT_DAYS,
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
            scheme: AsymmetricScheme::from_str("RSA").unwrap(),
            storage_engine: storage_engine.clone(),
            mode: "simulation".to_owned(),
            policy_enforcer: PolicyEnforcer::new(),
        }
    }
}

impl CapsuleManagerImpl {
    pub fn new(
        scheme: AsymmetricScheme,
        storage_engine: std::sync::Arc<dyn StorageEngine>,
        mode: &str,
    ) -> Result<Self, Error> {
        // get public-private key pair
        let (cert_pem, private_key) = {
            let rsa = Rsa::generate(RSA_BIT_LEN)?;

            let key_pair = openssl::pkey::PKey::from_rsa(rsa)?;

            let cert = crate::utils::crypto::create_cert(
                &key_pair,
                constant::X509NAME.iter(),
                constant::CERT_DAYS,
            )?;

            let cert_pem = cert.to_pem()?;
            let prikey_pem = key_pair.private_key_to_pem_pkcs8()?;
            (cert_pem, prikey_pem)
        };
        cm_assert!(
            mode == "simulation" || mode == "production",
            "mode {} is not supported",
            mode
        );

        debug!(target: "capsule_manager_log", "cert:\n {:?}", String::from_utf8(cert_pem.clone()));

        Ok(Self {
            kek_cert: cert_pem,
            kek_pri: private_key,
            scheme,
            storage_engine: storage_engine.clone(),
            mode: mode.to_owned(),
            policy_enforcer: PolicyEnforcer::new(),
        })
    }
}

// interface implementation for GRPC service
#[tonic::async_trait]
impl capsule_manager_server::CapsuleManager for CapsuleManagerImpl {
    async fn get_ra_cert(
        &self,
        request: Request<GetRaCertRequest>,
    ) -> Result<Response<GetRaCertResponse>, tonic::Status> {
        let request_body = request.into_inner();
        let reply = match self.get_ra_cert_impl(&request_body).await {
            Ok(response) => response,
            Err(e) => GetRaCertResponse {
                status: Some(Status {
                    code: e.errcode(),
                    message: e.to_string(),
                    details: vec![],
                }),
                attestation_report: None,
                cert: "".to_owned(),
            },
        };
        if let Some(ref status) = reply.status {
            log::info!(target: "monitor", "|get_ra_cert|{:?}|{:?}", status.code, status.message);
        }

        Ok(Response::new(reply))
    }

    async fn delete_data_key(
        &self,
        request: Request<EncryptedRequest>,
    ) -> Result<Response<EncryptedResponse>, tonic::Status> {
        let request_body = request.into_inner();
        let reply = match self.delete_data_key_impl(&request_body).await {
            Ok(response) => response,
            Err(e) => EncryptedResponse {
                status: Some(Status {
                    code: e.errcode(),
                    message: e.to_string(),
                    details: vec![],
                }),
                message: None,
            },
        };
        if let Some(ref status) = reply.status {
            log::info!(target: "monitor", "|delete_data_key|{:?}|{:?}", status.code, status.message);
        }
        Ok(Response::new(reply))
    }

    async fn create_data_keys(
        &self,
        request: Request<EncryptedRequest>,
    ) -> Result<Response<EncryptedResponse>, tonic::Status> {
        let request_body = request.into_inner();
        let reply = match self.create_data_keys_impl(&request_body).await {
            Ok(response) => response,
            Err(e) => EncryptedResponse {
                status: Some(Status {
                    code: e.errcode(),
                    message: e.to_string(),
                    details: vec![],
                }),
                message: None,
            },
        };
        if let Some(ref status) = reply.status {
            log::info!(target: "monitor", "|create_data_keys|{:?}|{:?}", status.code, status.message);
        }
        Ok(Response::new(reply))
    }

    async fn get_export_data_key(
        &self,
        request: Request<EncryptedRequest>,
    ) -> Result<Response<EncryptedResponse>, tonic::Status> {
        let request_body = request.into_inner();
        let reply = match self.get_export_data_key_impl(&request_body).await {
            Ok(response) => response,
            Err(e) => EncryptedResponse {
                status: Some(Status {
                    code: e.errcode(),
                    message: e.to_string(),
                    details: vec![],
                }),
                message: None,
            },
        };
        if let Some(ref status) = reply.status {
            log::info!(target: "monitor", "|get_export_data_key|{:?}|{:?}", status.code, status.message);
        }
        Ok(Response::new(reply))
    }

    // warning: the rpc interface only take effect for party cert,
    // doesn't take effect for certs derived from the party cert
    async fn register_cert(
        &self,
        request: Request<EncryptedRequest>,
    ) -> Result<Response<EncryptedResponse>, tonic::Status> {
        let request_body = request.into_inner();
        let reply = match self.register_cert_impl(&request_body).await {
            Ok(response) => response,
            Err(e) => EncryptedResponse {
                status: Some(Status {
                    code: e.errcode(),
                    message: e.to_string(),
                    details: vec![],
                }),
                message: None,
            },
        };
        if let Some(ref status) = reply.status {
            log::info!(target: "monitor", "|register_cert|{:?}|{:?}", status.code, status.message);
        }
        Ok(Response::new(reply))
    }

    async fn get_data_keys(
        &self,
        request: Request<EncryptedRequest>,
    ) -> Result<Response<EncryptedResponse>, tonic::Status> {
        let request_body = request.into_inner();
        let reply = match self.get_data_keys_impl(&request_body).await {
            Ok(response) => response,
            Err(e) => EncryptedResponse {
                status: Some(Status {
                    code: e.errcode(),
                    message: e.to_string(),
                    details: vec![],
                }),
                message: None,
            },
        };
        if let Some(ref status) = reply.status {
            log::info!(target: "monitor", "|get_data_keys|{:?}|{:?}", status.code, status.message);
        }
        Ok(Response::new(reply))
    }

    async fn create_data_policy(
        &self,
        request: Request<EncryptedRequest>,
    ) -> Result<Response<EncryptedResponse>, tonic::Status> {
        let request_body = request.into_inner();
        let reply = match self.create_data_policy_impl(&request_body).await {
            Ok(response) => response,
            Err(e) => EncryptedResponse {
                status: Some(Status {
                    code: e.errcode(),
                    message: e.to_string(),
                    details: vec![],
                }),
                message: None,
            },
        };
        if let Some(ref status) = reply.status {
            log::info!(target: "monitor", "|create_data_policy|{:?}|{:?}", status.code, status.message);
        }
        Ok(Response::new(reply))
    }

    async fn list_data_policy(
        &self,
        request: Request<EncryptedRequest>,
    ) -> Result<Response<EncryptedResponse>, tonic::Status> {
        let request_body = request.into_inner();
        let reply = match self.list_data_policy_impl(&request_body).await {
            Ok(response) => response,
            Err(e) => EncryptedResponse {
                status: Some(Status {
                    code: e.errcode(),
                    message: e.to_string(),
                    details: vec![],
                }),
                message: None,
            },
        };
        if let Some(ref status) = reply.status {
            log::info!(target: "monitor", "|list_data_policy|{:?}|{:?}", status.code, status.message);
        }
        Ok(Response::new(reply))
    }

    async fn add_data_rule(
        &self,
        request: Request<EncryptedRequest>,
    ) -> Result<Response<EncryptedResponse>, tonic::Status> {
        let request_body = request.into_inner();
        let reply = match self.add_data_rule_impl(&request_body).await {
            Ok(response) => response,
            Err(e) => EncryptedResponse {
                status: Some(Status {
                    code: e.errcode(),
                    message: e.to_string(),
                    details: vec![],
                }),
                message: None,
            },
        };
        if let Some(ref status) = reply.status {
            log::info!(target: "monitor", "|add_data_rule|{:?}|{:?}", status.code, status.message);
        }
        Ok(Response::new(reply))
    }

    async fn delete_data_policy(
        &self,
        request: Request<EncryptedRequest>,
    ) -> Result<Response<EncryptedResponse>, tonic::Status> {
        let request_body = request.into_inner();
        let reply = match self.delete_data_policy_impl(&request_body).await {
            Ok(response) => response,
            Err(e) => EncryptedResponse {
                status: Some(Status {
                    code: e.errcode(),
                    message: e.to_string(),
                    details: vec![],
                }),
                message: None,
            },
        };
        if let Some(ref status) = reply.status {
            log::info!(target: "monitor", "|delete_data_policy|{:?}|{:?}", status.code, status.message);
        }
        Ok(Response::new(reply))
    }

    async fn delete_data_rule(
        &self,
        request: Request<EncryptedRequest>,
    ) -> Result<Response<EncryptedResponse>, tonic::Status> {
        let request_body = request.into_inner();
        let reply = match self.delete_data_rule_impl(&request_body).await {
            Ok(response) => response,
            Err(e) => EncryptedResponse {
                status: Some(Status {
                    code: e.errcode(),
                    message: e.to_string(),
                    details: vec![],
                }),
                message: None,
            },
        };
        if let Some(ref status) = reply.status {
            log::info!(target: "monitor", "|delete_data_rule|{:?}|{:?}", status.code, status.message);
        }
        Ok(Response::new(reply))
    }

    async fn create_result_data_key(
        &self,
        request: Request<EncryptedRequest>,
    ) -> Result<Response<EncryptedResponse>, tonic::Status> {
        let request_body = request.into_inner();
        let reply = match self.create_result_data_key_impl(&request_body).await {
            Ok(response) => response,
            Err(e) => EncryptedResponse {
                status: Some(Status {
                    code: e.errcode(),
                    message: e.to_string(),
                    details: vec![],
                }),
                message: None,
            },
        };
        if let Some(ref status) = reply.status {
            log::info!(target: "monitor", "|create_result_data_key|{:?}|{:?}", status.code, status.message);
        }
        Ok(Response::new(reply))
    }
}
