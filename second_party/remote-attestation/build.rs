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

use std::process::Command;

fn main() {
    // load dynamic library
    let _root = std::env::current_dir().unwrap();
    let compile_path = format!("{}/compile.sh", _root.to_str().unwrap());
    Command::new("bash")
        .arg(compile_path)
        .output()
        .expect("failed to execute compile");

    if cfg!(feature = "ua_gen") {
        println!("cargo:rustc-link-lib=dylib=generation");
        println!(
            "cargo:rustc-link-search=native={}/c/lib/",
            _root.to_str().unwrap()
        );
    }

    if cfg!(feature = "ua_val") {
        println!("cargo:rustc-link-lib=dylib=verification");
        println!(
            "cargo:rustc-link-search=native={}/c/lib/",
            _root.to_str().unwrap()
        );
    }
}
