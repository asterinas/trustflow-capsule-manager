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

use crate::utils::tool;
use capsule_manager::storage::sql_storage::SqlStoreEngineBuilder;
use capsule_manager::storage::storage_engine::StorageEngine;
use capsule_manager::utils;
use capsule_manager::{server::CapsuleManagerService, storage::in_memory_storage::InMemoryStorage};
use log::info;
use sdc_apis::secretflowapis::v2::{
    sdc::capsule_manager::{
        capsule_manager_server::{self, CapsuleManagerServer},
        EncryptedRequest, EncryptedResponse, GetRaCertRequest, GetRaCertResponse,
    },
    Status,
};
use std::fs;
use std::time::Instant;
use tonic::{transport::Server, Request, Response};

use capsule_manager::{common::constants, config, server};

#[tokio::main(worker_threads = 16)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse whole args with clap
    let mut cfg = config::Config::new();
    // set mode according to cfg
    if cfg!(feature = "production") {
        cfg.mode = Some("production".to_owned());
    } else {
        cfg.mode = Some("simulation".to_owned());
    }
    log::info!("config {:#?}", cfg);

    // init log
    utils::log::init_log(
        &cfg.log_config.log_dir.unwrap(),
        &cfg.log_config.log_level.unwrap(),
        cfg.log_config.enable_console_logger.unwrap(),
    );

    let addr = format!("0.0.0.0:{}", cfg.port.unwrap()).parse()?;

    let (cm_cert, cm_private_key) = if cfg.enable_inject_cm_key.unwrap() {
        let cm_cert: Vec<u8> = fs::read_to_string(cfg.cm_cert_path.as_ref().unwrap())
            .unwrap()
            .into();
        let cm_private_key: Vec<u8> = fs::read_to_string(cfg.cm_private_key_path.as_ref().unwrap())
            .unwrap()
            .into();
        (cm_cert, cm_private_key)
    } else {
        // get public-private key pair
        let rsa = openssl::rsa::Rsa::generate(constants::RSA_BIT_LEN)?;
        let key_pair = openssl::pkey::PKey::from_rsa(rsa)?;
        let cert = crate::utils::crypto::create_cert(
            &key_pair,
            constants::X509NAME.iter(),
            constants::CERT_DAYS,
        )?;
        let cert_pem = cert.to_pem()?;
        let prikey_pem = key_pair.private_key_to_pem_pkcs8()?;
        (cert_pem, prikey_pem)
    };

    // get backend storage client
    let storage_engine: std::sync::Arc<dyn StorageEngine> = match cfg
        .storage_config
        .storage_backend
        .as_ref()
        .unwrap()
        .as_str()
    {
        "inmemory" => std::sync::Arc::new(InMemoryStorage::new()),
        "mysql" => {
            // use SHA256(SHA256(private key)) as seal key
            let seal_key = tool::sha256(tool::sha256(cm_private_key.as_slice()).as_slice());
            std::sync::Arc::new(
                SqlStoreEngineBuilder::new()
                    .db_url(cfg.storage_config.db_url.as_ref().expect("miss db url"))
                    .password(cfg.storage_config.password.as_ref())
                    .seal_key(&seal_key[0..16])
                    .build()
                    .await
                    .expect("connect to mysql failed"),
            )
        }
        _ => panic!("unsupport storage engine"),
    };

    let capsule_manager_service = server::CapsuleManagerImpl::new(
        storage_engine.clone(),
        &cfg.mode.as_ref().unwrap().as_str(),
        cm_cert.as_ref(),
        cm_private_key.as_ref(),
    )
    .expect("capsule_manager init error");

    info!("Server run at: {:?} mode {:?}", addr, cfg.mode);
    if cfg.tls_config.enable_tls.unwrap() {
        // Configure the server certificate for the client to verify the server
        let svr_cert =
            fs::read_to_string(cfg.tls_config.server_cert_path.as_ref().unwrap()).unwrap();
        let svr_key =
            fs::read_to_string(cfg.tls_config.server_private_key_path.as_ref().unwrap()).unwrap();
        let id = tonic::transport::Identity::from_pem(svr_cert.as_bytes(), svr_key.as_bytes());
        // Configure the client CA certificate to verify the client certificate
        let mut client_pem_vec: Vec<u8> = vec![];
        for entry in fs::read_dir(cfg.tls_config.client_ca_cert_path.as_ref().unwrap())? {
            let path = entry?.path();
            let mut client_ca_pem = fs::read_to_string(&path).unwrap().as_bytes().to_vec();
            client_pem_vec.append(&mut client_ca_pem);
        }
            "read client ca pem {:?}",
            std::str::from_utf8(&client_pem_vec)?
        );

        let client_ca_cert = tonic::transport::Certificate::from_pem(client_pem_vec);
        let tls_config = tonic::transport::ServerTlsConfig::new()
            .identity(id)
            .client_ca_root(client_ca_cert);
        Server::builder()
            .tls_config(tls_config)?
            .add_service(CapsuleManagerServer::new(CapsuleManagerGrpcServer {
                capsule_manager_service,
            }))
            .serve(addr)
            .await?;
    } else {
        Server::builder()
            .add_service(CapsuleManagerServer::new(CapsuleManagerGrpcServer {
                capsule_manager_service,
            }))
            .serve(addr)
            .await?;
    }

    Ok(())
}

#[derive(Clone)]
struct CapsuleManagerGrpcServer {
    capsule_manager_service: server::CapsuleManagerImpl,
}

// interface implementation for GRPC service
#[tonic::async_trait]
impl capsule_manager_server::CapsuleManager for CapsuleManagerGrpcServer {
    async fn get_ra_cert(
        &self,
        request: Request<GetRaCertRequest>,
    ) -> Result<Response<GetRaCertResponse>, tonic::Status> {
        let now = Instant::now();
        let request_body = request.into_inner();
        let reply = match self
            .capsule_manager_service
            .get_ra_cert(&request_body)
            .await
        {
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
        let elapsed = now.elapsed();
        if let Some(ref status) = reply.status {
            log::info!(target: "monitor", "|get_ra_cert|{:?}|{:?}|{:?}", if status.code == 0 {"Y"} else {"N"}, elapsed.as_millis(), status.message);
        }

        Ok(Response::new(reply))
    }

    async fn delete_data_key(
        &self,
        request: Request<EncryptedRequest>,
    ) -> Result<Response<EncryptedResponse>, tonic::Status> {
        let now = Instant::now();
        let request_body = request.into_inner();
        let reply = match self
            .capsule_manager_service
            .delete_data_key(&request_body)
            .await
        {
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
        let elapsed = now.elapsed();
        if let Some(ref status) = reply.status {
            log::info!(target: "monitor", "|delete_data_key|{:?}|{:?}|{:?}", if status.code == 0 {"Y"} else {"N"}, elapsed.as_millis(), status.message);
        }
        Ok(Response::new(reply))
    }

    async fn create_data_keys(
        &self,
        request: Request<EncryptedRequest>,
    ) -> Result<Response<EncryptedResponse>, tonic::Status> {
        let now = Instant::now();
        let request_body = request.into_inner();
        let reply = match self
            .capsule_manager_service
            .create_data_keys(&request_body)
            .await
        {
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
        let elapsed = now.elapsed();
        if let Some(ref status) = reply.status {
            log::info!(target: "monitor", "|create_data_keys|{:?}|{:?}|{:?}", if status.code == 0 {"Y"} else {"N"}, elapsed.as_millis(), status.message);
        }
        Ok(Response::new(reply))
    }

    async fn get_export_data_key(
        &self,
        request: Request<EncryptedRequest>,
    ) -> Result<Response<EncryptedResponse>, tonic::Status> {
        let now = Instant::now();
        let request_body = request.into_inner();
        let reply = match self
            .capsule_manager_service
            .get_export_data_key(&request_body)
            .await
        {
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
        let elapsed = now.elapsed();
        if let Some(ref status) = reply.status {
            log::info!(target: "monitor", "|get_export_data_key|{:?}|{:?}|{:?}", if status.code == 0 {"Y"} else {"N"}, elapsed.as_millis(), status.message);
        }
        Ok(Response::new(reply))
    }

    // warning: the rpc interface only take effect for party cert,
    // doesn't take effect for certs derived from the party cert
    async fn register_cert(
        &self,
        request: Request<EncryptedRequest>,
    ) -> Result<Response<EncryptedResponse>, tonic::Status> {
        let now = Instant::now();
        let request_body = request.into_inner();
        let reply = match self
            .capsule_manager_service
            .register_cert(&request_body)
            .await
        {
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
        let elapsed = now.elapsed();
        if let Some(ref status) = reply.status {
            log::info!(target: "monitor", "|register_cert|{:?}|{:?}|{:?}", if status.code == 0 {"Y"} else {"N"}, elapsed.as_millis(), status.message);
        }
        Ok(Response::new(reply))
    }

    async fn get_data_keys(
        &self,
        request: Request<EncryptedRequest>,
    ) -> Result<Response<EncryptedResponse>, tonic::Status> {
        let now = Instant::now();
        let request_body = request.into_inner();
        let reply = match self
            .capsule_manager_service
            .get_data_keys(&request_body)
            .await
        {
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
        let elapsed = now.elapsed();
        if let Some(ref status) = reply.status {
            log::info!(target: "monitor", "|get_data_keys|{:?}|{:?}|{:?}", if status.code == 0 {"Y"} else {"N"}, elapsed.as_millis(), status.message);
        }
        Ok(Response::new(reply))
    }

    async fn create_data_policy(
        &self,
        request: Request<EncryptedRequest>,
    ) -> Result<Response<EncryptedResponse>, tonic::Status> {
        let now = Instant::now();
        let request_body = request.into_inner();
        let reply = match self
            .capsule_manager_service
            .create_data_policy(&request_body)
            .await
        {
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
        let elapsed = now.elapsed();
        if let Some(ref status) = reply.status {
            log::info!(target: "monitor", "|create_data_policy|{:?}|{:?}|{:?}", if status.code == 0 {"Y"} else {"N"}, elapsed.as_millis(), status.message);
        }
        Ok(Response::new(reply))
    }

    async fn list_data_policy(
        &self,
        request: Request<EncryptedRequest>,
    ) -> Result<Response<EncryptedResponse>, tonic::Status> {
        let now = Instant::now();
        let request_body = request.into_inner();
        let reply = match self
            .capsule_manager_service
            .list_data_policy(&request_body)
            .await
        {
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
        let elapsed = now.elapsed();
        if let Some(ref status) = reply.status {
            log::info!(target: "monitor", "|list_data_policy|{:?}|{:?}|{:?}", if status.code == 0 {"Y"} else {"N"}, elapsed.as_millis(), status.message);
        }
        Ok(Response::new(reply))
    }

    async fn add_data_rule(
        &self,
        request: Request<EncryptedRequest>,
    ) -> Result<Response<EncryptedResponse>, tonic::Status> {
        let now = Instant::now();
        let request_body = request.into_inner();
        let reply = match self
            .capsule_manager_service
            .add_data_rule(&request_body)
            .await
        {
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
        let elapsed = now.elapsed();
        if let Some(ref status) = reply.status {
            log::info!(target: "monitor", "|add_data_rule|{:?}|{:?}|{:?}", if status.code == 0 {"Y"} else {"N"}, elapsed.as_millis(), status.message);
        }
        Ok(Response::new(reply))
    }

    async fn delete_data_policy(
        &self,
        request: Request<EncryptedRequest>,
    ) -> Result<Response<EncryptedResponse>, tonic::Status> {
        let now = Instant::now();
        let request_body = request.into_inner();
        let reply = match self
            .capsule_manager_service
            .delete_data_policy(&request_body)
            .await
        {
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
        let elapsed = now.elapsed();
        if let Some(ref status) = reply.status {
            log::info!(target: "monitor", "|delete_data_policy|{:?}|{:?}|{:?}", if status.code == 0 {"Y"} else {"N"}, elapsed.as_millis(), status.message);
        }
        Ok(Response::new(reply))
    }

    async fn delete_data_rule(
        &self,
        request: Request<EncryptedRequest>,
    ) -> Result<Response<EncryptedResponse>, tonic::Status> {
        let now = Instant::now();
        let request_body = request.into_inner();
        let reply = match self
            .capsule_manager_service
            .delete_data_rule(&request_body)
            .await
        {
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
        let elapsed = now.elapsed();
        if let Some(ref status) = reply.status {
            log::info!(target: "monitor", "|delete_data_rule|{:?}|{:?}|{:?}", if status.code == 0 {"Y"} else {"N"}, elapsed.as_millis(), status.message);
        }
        Ok(Response::new(reply))
    }

    async fn create_result_data_key(
        &self,
        request: Request<EncryptedRequest>,
    ) -> Result<Response<EncryptedResponse>, tonic::Status> {
        let now = Instant::now();
        let request_body = request.into_inner();
        let reply = match self
            .capsule_manager_service
            .create_result_data_key(&request_body)
            .await
        {
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
        let elapsed = now.elapsed();
        if let Some(ref status) = reply.status {
            log::info!(target: "monitor", "|create_result_data_key|{:?}|{:?}|{:?}", if status.code == 0 {"Y"} else {"N"}, elapsed.as_millis(), status.message);
        }
        Ok(Response::new(reply))
    }
}
