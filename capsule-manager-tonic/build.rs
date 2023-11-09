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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // compile protobuf
    tonic_build::configure()
        .type_attribute(".", "#[derive(serde::Deserialize, serde::Serialize)]")
        .field_attribute("protected_header", "#[serde(rename=\"protected\")]")
        .field_attribute(".secretflowapis.v2.sdc", "#[serde(default)]")
        .extern_path(".google.protobuf.Any", "::prost_wkt_types::Any")
        .compile(
            &["secretflow_apis/secretflowapis/v2/sdc/capsule_manager/capsule_manager.proto"],
            &["secretflow_apis"], // specify the root location to search proto dependencies
        )?;
    Ok(())
}
