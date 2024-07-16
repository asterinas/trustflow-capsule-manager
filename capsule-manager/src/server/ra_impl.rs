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
use crate::common::constants::HASH_SEPARATOR;
use crate::errno;
use crate::error::errors::{AuthResult, Error, ErrorCode, ErrorLocation};
use crate::utils::tool::sha256;
use hex::encode_upper;
use sdc_apis::secretflowapis::v2::sdc::capsule_manager::{GetRaCertRequest, GetRaCertResponse};
use sdc_apis::secretflowapis::v2::sdc::{
    UnifiedAttestationGenerationParams, UnifiedAttestationReport, UnifiedAttestationReportParams,
};
use sdc_apis::secretflowapis::v2::{Code, Status};

impl CapsuleManagerImpl {
    pub async fn get_ra_cert_impl(
        &self,
        request: &GetRaCertRequest,
    ) -> AuthResult<GetRaCertResponse> {
        // generate one report for nonce
        let attestation_report: Option<UnifiedAttestationReport> = match self.mode.as_str() {
            // get RA report
            "production" => {
                let data =
                    [&self.kek_cert, request.nonce.as_bytes()].join(HASH_SEPARATOR.as_bytes());

                // fill report params
                let report_params = UnifiedAttestationGenerationParams {
                    // tee instance id: unused field, filled with empty string
                    tee_identity: "".to_owned(),
                    // TODO: add report type in protobuf
                    report_type: "Passport".to_owned(),
                    report_hex_nonce: "".to_owned(),
                    report_params: Some(UnifiedAttestationReportParams {
                        str_report_identity: "".to_owned(),
                        hex_user_data: encode_upper(sha256(&data)),
                        json_nested_reports: "".to_owned(),
                        hex_spid: "".to_owned(),
                        pem_public_key: "".to_owned(),
                    }),
                };

                let report_json = trustedflow_attestation_rs::generate_attestation_report(
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
