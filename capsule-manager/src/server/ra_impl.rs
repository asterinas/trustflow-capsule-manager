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

use super::CapsuleManagerImpl;
use crate::server::constant::SEPARATOR;
use ::capsule_manager::errno;
use ::capsule_manager::error::errors::{AuthResult, Error, ErrorCode, ErrorLocation};
use ::capsule_manager::remote_attestation::unified_attestation_wrapper::runified_attestation_generate_auth_report;
use ::capsule_manager::utils::tool::sha256;
use capsule_manager_tonic::secretflowapis::v2::sdc::capsule_manager::{
    GetRaCertRequest, GetRaCertResponse,
};
use capsule_manager_tonic::secretflowapis::v2::sdc::{
    UnifiedAttestationReport, UnifiedAttestationReportParams,
};
use capsule_manager_tonic::secretflowapis::v2::{Code, Status};
use hex::encode_upper;
use log::debug;

impl CapsuleManagerImpl {
    pub async fn get_ra_cert_impl(
        &self,
        request: &GetRaCertRequest,
    ) -> AuthResult<GetRaCertResponse> {
        // the fixed data
        let tee_identity: &str = "1";
        let hex_report_type = "Passport".to_string();
        // generate one report for nonce

        let attestation_report: Option<UnifiedAttestationReport> = match self.mode.as_str() {
            // get RA report
            "production" => {
                let data = [&self.kek_cert, request.nonce.as_bytes()].join(SEPARATOR.as_bytes());
                // fill report params
                let report_params = UnifiedAttestationReportParams {
                    str_report_identity: "".to_owned(),
                    hex_user_data: encode_upper(sha256(&data)),
                    json_nested_reports: "".to_owned(),
                    hex_spid: "".to_owned(),
                };

                let report_json = runified_attestation_generate_auth_report(
                    tee_identity,
                    hex_report_type.as_str(),
                    "",
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
                Some(serde_json::from_str(report_json.as_str()).map_err(|e| {
                    errno!(
                        ErrorCode::InternalErr,
                        "json {:?} to attentation_report err: {:?}",
                        &report_json,
                        e
                    )
                })?)
            }
            // simulation mode doesn't need report
            "simulation" => None,
            _ => {
                return Err(errno!(
                    ErrorCode::InvalidArgument,
                    "mode {} not supported",
                    &self.mode
                ));
            }
        };
        let response = GetRaCertResponse {
            status: Some(Status {
                code: Code::Ok as i32,
                message: "success".to_owned(),
                details: vec![],
            }),
            attestation_report,
            cert: String::from_utf8(self.kek_cert.clone())?,
        };

        Ok(response)
    }
}
