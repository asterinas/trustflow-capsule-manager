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

use clap::Parser;
use merge::Merge;
use serde::Deserialize;
use std::fs::File;
use std::io::BufReader;

#[derive(Parser)]
pub struct LineArgs {
    #[clap(long = "config_path", default_value = "/host/config.yaml")]
    pub config_path: std::path::PathBuf,

    /// Rest of arguments
    #[clap(flatten)]
    pub config: Config,
}

#[derive(Parser, Deserialize, Merge, Debug)]
pub struct Config {
    /// listening port
    #[clap(long)]
    pub port: Option<u32>,

    /// log config
    #[clap(flatten)]
    pub log_config: LogConfig,

    /// key scheme: SM2, RSA
    #[clap(long)]
    pub scheme: Option<String>,

    // the storage backend
    #[clap(long)]
    pub storage_backend: Option<String>,

    // server cert path
    #[clap(long)]
    pub server_cert_path: Option<String>,

    // server cert key path
    #[clap(long)]
    pub server_cert_key_path: Option<String>,

    // root ca cert path
    #[clap(long)]
    pub client_ca_cert_path: Option<String>,

    // Tls
    #[clap(long)]
    pub enable_tls: Option<bool>,

    // the mod of capsule manager
    pub mode: Option<String>,
}

#[derive(Parser, Deserialize, Merge, Debug)]
pub struct LogConfig {
    /// log file name
    #[clap(long = "log_config.log_dir")]
    pub log_dir: Option<String>,

    /// log level
    #[clap(long = "log_config.log_level")]
    pub log_level: Option<String>,

    /// enable console logger
    #[clap(long = "log_config.enable_console_logger")]
    pub enable_console_logger: Option<bool>,
}

impl Config {
    pub fn new() -> Self {
        // Parse whole args with clap
        let args = LineArgs::parse();

        // Get config file
        let mut config: Config = if let Ok(f) = File::open(&args.config_path) {
            // Parse config with serde
            match serde_yaml::from_reader::<_, Config>(BufReader::new(f)) {
                // merge config already parsed from clap
                Ok(config) => {
                    let mut cfg = Config::from(args.config);
                    cfg.merge(config);
                    cfg
                }
                Err(err) => panic!("Error in configuration file:\n{}", err),
            }
        } else {
            // If there is not config file return only config parsed from clap
            Config::from(args.config)
        };

        // config merge default value
        config.merge(Config {
            port: Some(8888),
            log_config: LogConfig {
                log_dir: Some(String::from("log")),
                log_level: Some(String::from("info")),
                enable_console_logger: Some(true),
            },
            scheme: Some(String::from("RSA")),
            storage_backend: Some(String::from("inmemory")),
            server_cert_path: Some(String::from("/host/resources/cert/server.crt")),
            server_cert_key_path: Some(String::from("/host/resources/cert/server.key")),
            client_ca_cert_path: Some(String::from("/host/resources/client_ca/")),
            enable_tls: Some(true),
            mode: Some(String::from("production")),
        });

        // set mode according to cfg
        if cfg!(feature = "production") {
            config.mode = Some("production".to_owned());
        } else {
            config.mode = Some("simulation".to_owned());
        }
        println!("config {:#?}", config);
        config
    }
}
