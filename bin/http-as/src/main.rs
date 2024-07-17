use axum::{extract::State, http::StatusCode, routing::post, Json, Router};

use capsule_manager::{
    common::constants,
    config,
    server::{self, CapsuleManagerService},
    utils::{self, tool},
};
use sdc_apis::secretflowapis::v2::{
    sdc::capsule_manager::{
        EncryptedRequest, EncryptedResponse, GetRaCertRequest, GetRaCertResponse,
    },
    Status,
};

use capsule_manager::storage::in_memory_storage::InMemoryStorage;
use capsule_manager::storage::sql_storage::SqlStoreEngineBuilder;
use capsule_manager::storage::storage_engine::StorageEngine;
use std::{fs, time::Instant};

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

    let app = Router::new()
        .route("/api/v1/ra_report/get", post(get_ra_cert))
        .route("/api/v1/data_keys/create", post(create_data_keys))
        .route("/api/v1/data_keys/get", post(get_data_keys))
        .route("/api/v1/data_key/delete", post(delete_data_key))
        .route("/api/v1/export_data_key/get", post(get_export_data_key))
        .route("/api/v1/cert/register", post(register_cert))
        .route("/api/v1/data_policy/create", post(create_data_policy))
        .route("/api/v1/data_policy/list", post(list_data_policy))
        .route("/api/v1/data_rule/add", post(add_data_rule))
        .route("/api/v1/data_policy/delete", post(delete_data_policy))
        .route("/api/v1/data_rule/delete", post(delete_data_rule))
        .route(
            "/api/v1/result_data_key/create",
            post(create_result_data_key),
        )
        .with_state(capsule_manager_service);
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", cfg.port.unwrap()))
        .await
        .unwrap();
    log::info!(
        "Server run at: {:?} mode {:?}",
        format!("0.0.0.0:{}", cfg.port.unwrap()),
        cfg.mode
    );
    axum::serve(listener, app).await?;

    Ok(())
}

async fn get_ra_cert(
    State(capsule_manager_service): State<server::CapsuleManagerImpl>,
    Json(ra_cert_request): Json<GetRaCertRequest>,
) -> Result<Json<GetRaCertResponse>, (StatusCode, String)> {
    let now = Instant::now();
    let reply = match capsule_manager_service.get_ra_cert(&ra_cert_request).await {
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
    Ok(Json(reply))
}

async fn create_data_keys(
    State(capsule_manager_service): State<server::CapsuleManagerImpl>,
    Json(encrypted_request): Json<EncryptedRequest>,
) -> Result<Json<EncryptedResponse>, (StatusCode, String)> {
    let now = Instant::now();
    let reply = match capsule_manager_service
        .create_data_keys(&encrypted_request)
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
    Ok(Json(reply))
}

async fn get_data_keys(
    State(capsule_manager_service): State<server::CapsuleManagerImpl>,
    Json(encrypted_request): Json<EncryptedRequest>,
) -> Result<Json<EncryptedResponse>, (StatusCode, String)> {
    let now = Instant::now();
    let reply = match capsule_manager_service
        .get_data_keys(&encrypted_request)
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
    Ok(Json(reply))
}

async fn delete_data_key(
    State(capsule_manager_service): State<server::CapsuleManagerImpl>,
    Json(encrypted_request): Json<EncryptedRequest>,
) -> Result<Json<EncryptedResponse>, (StatusCode, String)> {
    let now = Instant::now();
    let reply = match capsule_manager_service
        .delete_data_key(&encrypted_request)
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
    Ok(Json(reply))
}

async fn get_export_data_key(
    State(capsule_manager_service): State<server::CapsuleManagerImpl>,
    Json(encrypted_request): Json<EncryptedRequest>,
) -> Result<Json<EncryptedResponse>, (StatusCode, String)> {
    let now = Instant::now();
    let reply = match capsule_manager_service
        .get_export_data_key(&encrypted_request)
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
    Ok(Json(reply))
}

// warning: the rpc interface only take effect for party cert,
// doesn't take effect for certs derived from the party cert
async fn register_cert(
    State(capsule_manager_service): State<server::CapsuleManagerImpl>,
    Json(encrypted_request): Json<EncryptedRequest>,
) -> Result<Json<EncryptedResponse>, (StatusCode, String)> {
    let now = Instant::now();
    let reply = match capsule_manager_service
        .register_cert(&encrypted_request)
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
    Ok(Json(reply))
}

async fn create_data_policy(
    State(capsule_manager_service): State<server::CapsuleManagerImpl>,
    Json(encrypted_request): Json<EncryptedRequest>,
) -> Result<Json<EncryptedResponse>, (StatusCode, String)> {
    let now = Instant::now();
    let reply = match capsule_manager_service
        .create_data_policy(&encrypted_request)
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
    Ok(Json(reply))
}

async fn list_data_policy(
    State(capsule_manager_service): State<server::CapsuleManagerImpl>,
    Json(encrypted_request): Json<EncryptedRequest>,
) -> Result<Json<EncryptedResponse>, (StatusCode, String)> {
    let now = Instant::now();
    let reply = match capsule_manager_service
        .list_data_policy(&encrypted_request)
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
    Ok(Json(reply))
}

async fn add_data_rule(
    State(capsule_manager_service): State<server::CapsuleManagerImpl>,
    Json(encrypted_request): Json<EncryptedRequest>,
) -> Result<Json<EncryptedResponse>, (StatusCode, String)> {
    let now = Instant::now();
    let reply = match capsule_manager_service
        .add_data_rule(&encrypted_request)
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
    Ok(Json(reply))
}

async fn delete_data_policy(
    State(capsule_manager_service): State<server::CapsuleManagerImpl>,
    Json(encrypted_request): Json<EncryptedRequest>,
) -> Result<Json<EncryptedResponse>, (StatusCode, String)> {
    let now = Instant::now();
    let reply = match capsule_manager_service
        .delete_data_policy(&encrypted_request)
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
    Ok(Json(reply))
}

async fn delete_data_rule(
    State(capsule_manager_service): State<server::CapsuleManagerImpl>,
    Json(encrypted_request): Json<EncryptedRequest>,
) -> Result<Json<EncryptedResponse>, (StatusCode, String)> {
    let now = Instant::now();
    let reply = match capsule_manager_service
        .delete_data_rule(&encrypted_request)
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
    Ok(Json(reply))
}

async fn create_result_data_key(
    State(capsule_manager_service): State<server::CapsuleManagerImpl>,
    Json(encrypted_request): Json<EncryptedRequest>,
) -> Result<Json<EncryptedResponse>, (StatusCode, String)> {
    let now = Instant::now();
    let reply = match capsule_manager_service
        .create_result_data_key_impl(&encrypted_request)
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
    Ok(Json(reply))
}
