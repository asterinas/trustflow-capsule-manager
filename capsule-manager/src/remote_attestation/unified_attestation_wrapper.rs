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

use crate::errno;
use crate::error::errors::{AuthResult, Error, ErrorCode, ErrorLocation};
use crate::remote_attestation::constant::UA_REPORT_SIZE_PASSPORT;
use remote_attestation::ua_gen::UnifiedAttestationGenerateReport;
use remote_attestation::ua_val::UnifiedAttestationVerifyReport;

use log::info;
use std::ffi::{CStr, CString};

pub fn runified_attestation_verify_auth_report(
    auth_json: &str,
    rules_json: &str,
) -> AuthResult<()> {
    let c_auth_json = CString::new(auth_json.as_bytes()).map_err(|_| {
        errno!(
            ErrorCode::InvalidArgument,
            "runified_attestation_verify_auth_report: auth_json ffi failure"
        )
    })?;
    let c_rules_json = CString::new(rules_json.as_bytes()).map_err(|_| {
        errno!(
            ErrorCode::InvalidArgument,
            "runified_attestation_verify_auth_report: rules_json ffi failure"
        )
    })?;
    // c lib interface
    let ret = unsafe {
        UnifiedAttestationVerifyReport(
            c_auth_json.as_ptr(),
            auth_json.len() as i32,
            c_rules_json.as_ptr(),
            rules_json.len() as i32,
        )
    };

    if ret != 0 {
        return Err(errno!(
            ErrorCode::UnifiedAttErr {
                errcode: ret as i32
            },
            "runified_attestation_verify_auth_report: report verification failure"
        ));
    }

    Ok(())
}

pub fn runified_attestation_generate_auth_report(
    tee_identity: &str,
    report_type: &str,
    report_hex_nonce: &str,
    report_params: &str,
) -> AuthResult<String> {
    let c_tee_identity = CString::new(tee_identity.as_bytes()).map_err(|_| {
        errno!(
            ErrorCode::InvalidArgument,
            "runified_attestation_generate_auth_report: tee_identity ffi failure"
        )
    })?;
    let c_report_type = CString::new(report_type.as_bytes()).map_err(|_| {
        errno!(
            ErrorCode::InvalidArgument,
            "runified_attestation_generate_auth_report: report_type ffi failure"
        )
    })?;

    let c_report_hex_nonce = CString::new(report_hex_nonce.as_bytes()).map_err(|_| {
        errno!(
            ErrorCode::InvalidArgument,
            "runified_attestation_generate_auth_report: report_hex_nonce ffi failure"
        )
    })?;

    let c_report_params = CString::new(report_params.as_bytes()).map_err(|_| {
        errno!(
            ErrorCode::InvalidArgument,
            "runified_attestation_generate_auth_report: report_params ffi failure"
        )
    })?;

    let mut buffer_len: ::std::os::raw::c_uint = 2 * UA_REPORT_SIZE_PASSPORT + 1;
    let mut buffer = vec![0; buffer_len as usize];

    // c lib interface
    let ret = unsafe {
        UnifiedAttestationGenerateReport(
            c_tee_identity.as_ptr(),
            c_report_type.as_ptr(),
            c_report_hex_nonce.as_ptr(),
            c_report_params.as_ptr(),
            report_params.len() as u32,
            buffer.as_mut_ptr(),
            &mut buffer_len,
        )
    };

    if ret != 0 {
        return Err(errno!(
            ErrorCode::UnifiedAttErr {
                errcode: ret as i32
            },
            "runified_attestation_generate_auth_report: report generate failure"
        ));
    }

    let report_json: String = unsafe {
        CStr::from_ptr(buffer.as_ptr())
            .to_str()
            .map_err(|e| {
                errno!(
                    ErrorCode::InternalErr,
                    "runified_attestation_generate_auth_report: utf8error {:?}",
                    e
                )
            })?
            .to_string()
    };

info!("report_json len {}", buffer_len);
    Ok(report_json)
}
