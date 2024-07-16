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

use log::LevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::append::rolling_file::policy::compound::roll::fixed_window::FixedWindowRoller;
use log4rs::append::rolling_file::policy::compound::trigger::size::SizeTrigger;
use log4rs::append::rolling_file::policy::compound::CompoundPolicy;
use log4rs::append::rolling_file::RollingFileAppender;
use log4rs::config::{Appender, Config, Logger, Root};
use log4rs::encode::pattern::PatternEncoder;
use std::collections::HashMap;
use std::path::Path;

const MONITOR_LOG_RELATIVE_PATH: &str = "monitor.log";
const MONITOR_LOG_PATTERN: &str = "monitor.{}.log";
const CAPSULE_MANAGER_LOG_RELATIVE_PATH: &str = "capsule_manager.log";
const CAPSULE_MANAGER_LOG_PATTERN: &str = "capsule_manager.{}.log";

const LOG_WINDOW_SIZE: u32 = 65536;
const SINGLE_LOG_FILE_SIZE_IN_MB: u64 = 10;

// init log
pub fn init_log(dir: &str, level: &str, enable_console_logger: bool) {
    let dir_path = Path::new(dir);
    let level_map = HashMap::from([
        ("debug", LevelFilter::Debug),
        ("info", LevelFilter::Info),
        ("warn", LevelFilter::Warn),
        ("error", LevelFilter::Error),
    ]);

    // init stdout appender
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "[{d}] [{l}] [stdout] [{f}:{M}:{L}] {m}{n}",
        )))
        .build();

    // init monitor_log appender
    let fixed_window_roller = FixedWindowRoller::builder()
        .build(
            dir_path.join(MONITOR_LOG_PATTERN).to_str().unwrap(),
            LOG_WINDOW_SIZE,
        )
        .unwrap();
    let size_trigger = SizeTrigger::new(SINGLE_LOG_FILE_SIZE_IN_MB * 1024 * 1024);
    let compound_policy =
        CompoundPolicy::new(Box::new(size_trigger), Box::new(fixed_window_roller));
    let monitor_log = RollingFileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "[{d}] [{l}] [capsulemanager] [{f}:{M}:{L}] {m}{n}",
        )))
        .build(
            dir_path.join(MONITOR_LOG_RELATIVE_PATH).to_str().unwrap(),
            Box::new(compound_policy),
        )
        .unwrap();

    // init capsule_manager appender
    let fixed_window_roller = FixedWindowRoller::builder()
        .build(
            dir_path.join(CAPSULE_MANAGER_LOG_PATTERN).to_str().unwrap(),
            LOG_WINDOW_SIZE,
        )
        .unwrap();
    let size_trigger = SizeTrigger::new(SINGLE_LOG_FILE_SIZE_IN_MB * 1024 * 1024);
    let compound_policy =
        CompoundPolicy::new(Box::new(size_trigger), Box::new(fixed_window_roller));
    let capsule_manager_log = RollingFileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "[{d}] [{l}] [{f}:{L}] {m}{n}",
        )))
        .build(
            dir_path
                .join(CAPSULE_MANAGER_LOG_RELATIVE_PATH)
                .to_str()
                .unwrap(),
            Box::new(compound_policy),
        )
        .unwrap();

    let mut root_builder = Root::builder().appender("capsule_manager_log");
    if enable_console_logger {
        root_builder = root_builder.appender("stdout");
    }

    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .appender(Appender::builder().build("monitor_log", Box::new(monitor_log)))
        .appender(Appender::builder().build("capsule_manager_log", Box::new(capsule_manager_log)))
        .logger(
            Logger::builder().appender("monitor_log").build(
                "monitor",
                level_map
                    .get(level)
                    .unwrap_or(&LevelFilter::Info)
                    .to_owned(),
            ),
        )
        .build(
            root_builder.build(
                level_map
                    .get(level)
                    .unwrap_or(&LevelFilter::Info)
                    .to_owned(),
            ),
        )
        .expect("failed to build log config");

    log4rs::init_config(config).expect("failed to init log");
}
