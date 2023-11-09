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
    /// @brief C API for unified attestation report verification
    ///
    /// @param report_json_str: The serialized JSON string of
    /// UnifiedAttestationReport. @param report_json_len: The length of
    /// serialized JSON string of UnifiedAttestationReport.
    /// @param policy_json_str: The serialized JSON string for
    /// UnifiedAttestationPolicy. @param policy_json_len: The length of
    /// serialized JSON string for UnifiedAttestationPolicy.
    ///
    /// @return 0 means success or other error code
    pub fn UnifiedAttestationVerifyReport(
        report_json_str: *const ::std::os::raw::c_char,
        report_json_len: std::os::raw::c_int,
        policy_json_str: *const ::std::os::raw::c_char,
        policy_json_len: std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
