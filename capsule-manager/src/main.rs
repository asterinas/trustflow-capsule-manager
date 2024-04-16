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

pub mod config;
pub mod server;

use capsule_manager::storage::in_memory_storage::InMemoryStorage;
use capsule_manager::storage::storage_engine::StorageEngine;
use capsule_manager::utils;
use config::config::Config;
use log::info;
use sdc_apis::secretflowapis::v2::sdc::capsule_manager::capsule_manager_server::CapsuleManagerServer;
use std::fs;
use std::str::from_utf8;
use tonic::transport::Server;

#[tokio::main(worker_threads = 16)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse whole args with clap
    let cfg = Config::new();

    // init log
    utils::log::init_log(
        &cfg.log_config.log_dir.unwrap(),
        &cfg.log_config.log_level.unwrap(),
        cfg.log_config.enable_console_logger.unwrap(),
    );

    let addr = format!("0.0.0.0:{}", cfg.port.unwrap()).parse()?;

    // get backend storage client
    let storage_engine: std::sync::Arc<dyn StorageEngine> =
        match cfg.storage_backend.as_ref().unwrap().as_str() {
            "inmemory" => std::sync::Arc::new(InMemoryStorage::new()),
            _ => panic!("unsupport storage engine"),
        };

    let capsule_manager = server::CapsuleManagerImpl::new(
        storage_engine.clone(),
        &cfg.mode.as_ref().unwrap().as_str(),
    )
    .expect("capsule_manager init error");

    info!("Server run at: {:?} mode {:?}", addr, cfg.mode);
    if cfg.enable_tls.unwrap() {
        // Configure the server certificate for the client to verify the server
        let svr_cert = fs::read_to_string(cfg.server_cert_path.as_ref().unwrap()).unwrap();
        let svr_key = fs::read_to_string(cfg.server_cert_key_path.as_ref().unwrap()).unwrap();
        let id = tonic::transport::Identity::from_pem(svr_cert.as_bytes(), svr_key.as_bytes());
        // Configure the client CA certificate to verify the client certificate
        let mut client_pem_vec: Vec<u8> = vec![];
        for entry in fs::read_dir(cfg.client_ca_cert_path.as_ref().unwrap())? {
            let path = entry?.path();
            let mut client_ca_pem = fs::read_to_string(&path).unwrap().as_bytes().to_vec();
            client_pem_vec.append(&mut client_ca_pem);
        }

        let client_ca_cert = tonic::transport::Certificate::from_pem(client_pem_vec);
        let tls_config = tonic::transport::ServerTlsConfig::new()
            .identity(id)
            .client_ca_root(client_ca_cert);
        Server::builder()
            .tls_config(tls_config)?
            .add_service(CapsuleManagerServer::new(capsule_manager))
            .serve(addr)
            .await?;
    } else {
        Server::builder()
            .add_service(CapsuleManagerServer::new(capsule_manager))
            .serve(addr)
            .await?;
    }

    Ok(())
}
