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

#![allow(dead_code)]
extern "C" {
    /// @brief C API for unified attestation report generation
    /// @param tee_identity: The identity of TEE or TA instance
    /// @param report_type: Type of report, "BackgroundCheck"|"Passport"|"Uas"
    /// @param report_hex_nonce: Provide freshness if necessary.
    ///                          It's hex string less than 64 Bytes.
    /// @param report_params_buf: The TEE special report generation parameters
    /// buffer. @param report_params_len: The length of TEE special report
    /// generation parameters. @param report_josn_buf: The output serialized
    /// JSON string of AttestationReport. @param report_josn_len: The
    /// maximal JSON report buffer size as input,
    /// and the real JSON report string size as output.
    ///
    /// @return 0 means success or other error code
    pub fn UnifiedAttestationGenerateReport(
        tee_identify: *const ::std::os::raw::c_char,
        report_type: *const ::std::os::raw::c_char,
        report_hex_nonce: *const ::std::os::raw::c_char,
        report_params_buf: *const ::std::os::raw::c_char,
        report_params_len: ::std::os::raw::c_uint,
        report_json_buf: *mut ::std::os::raw::c_char,
        report_json_len: *mut ::std::os::raw::c_uint,
    ) -> ::std::os::raw::c_int;
}
