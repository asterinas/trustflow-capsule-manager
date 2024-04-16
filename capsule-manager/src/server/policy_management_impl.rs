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
use capsule_manager::errno;
use capsule_manager::error::errors::{Error, ErrorCode, ErrorLocation};
use capsule_manager::utils::jwt::jwa::Secret;
use sdc_apis::secretflowapis::v2::sdc::capsule_manager::*;
use sdc_apis::secretflowapis::v2::{Code, Status};

impl CapsuleManagerImpl {
    pub async fn create_data_policy_impl(
        &self,
        encrypt_request: &EncryptedRequest,
    ) -> Result<EncryptedResponse, Error> {
        let (request_content, jws) =
            super::get_request::<CreateDataPolicyRequest>(&self.kek_pri, encrypt_request)?;
        let jws = jws.ok_or(errno!(ErrorCode::NotFound, "Missing signature"))?;
        // NOTE: Here, we assume the `x5c` of JWS is filled a public key.
        // We will support to read a public key from a data source also.
        super::verify_signature(&request_content.owner_party_id, None, &jws)?;
        let policy = request_content
            .policy
            .ok_or(errno!(ErrorCode::NotFound, "policy is empty."))?;
        log::debug!("policy: {:?}", policy);

        self.storage_engine
            .store_data_policy(
                &request_content.owner_party_id,
                &request_content.scope,
                &policy,
            )
            .await?;
        Ok(EncryptedResponse {
            status: Some(Status {
                code: Code::Ok as i32,
                message: "success".to_owned(),
                details: vec![],
            }),
            message: None,
        })
    }

    pub async fn add_data_rule_impl(
        &self,
        encrypt_request: &EncryptedRequest,
    ) -> Result<EncryptedResponse, Error> {
        let (request_content, jws) =
            super::get_request::<AddDataRuleRequest>(&self.kek_pri, encrypt_request)?;
        let jws = jws.ok_or(errno!(ErrorCode::NotFound, "Missing signature"))?;
        // NOTE: Here, we assume the `x5c` of JWS is filled a public key.
        // We will support to read a public key from a data source also.
        super::verify_signature(&request_content.owner_party_id, None, &jws)?;
        self.storage_engine
            .add_data_rule(
                &request_content.owner_party_id,
                &request_content.scope,
                &request_content.data_uuid,
                &request_content
                    .rule
                    .ok_or(errno!(ErrorCode::NotFound, "policy is empty."))?,
            )
            .await?;
        Ok(EncryptedResponse {
            status: Some(Status {
                code: Code::Ok as i32,
                message: "success".to_owned(),
                details: vec![],
            }),
            message: None,
        })
    }

    pub async fn list_data_policy_impl(
        &self,
        encrypt_request: &EncryptedRequest,
    ) -> Result<EncryptedResponse, Error> {
        let (request_content, jws) =
            super::get_request::<ListDataPolicyRequest>(&self.kek_pri, encrypt_request)?;
        let jws = jws.ok_or(errno!(ErrorCode::NotFound, "Missing signature"))?;
        // NOTE: Here, we assume the `x5c` of JWS is filled a public key.
        // We will support to read a public key from a data source also.
        super::verify_signature(&request_content.owner_party_id, None, &jws)?;
        let response_content = ListDataPolicyResponse {
            policies: self
                .storage_engine
                .get_data_policys(&request_content.owner_party_id, &request_content.scope)
                .await?,
        };
        let secret = Secret::PublicKey(jws.public_key()?);

        super::encrypt_response(secret, &response_content)
    }

    pub async fn delete_data_policy_impl(
        &self,
        encrypt_request: &EncryptedRequest,
    ) -> Result<EncryptedResponse, Error> {
        let (request_content, jws) =
            super::get_request::<DeleteDataPolicyRequest>(&self.kek_pri, encrypt_request)?;
        let jws = jws.ok_or(errno!(ErrorCode::NotFound, "Missing signature"))?;
        // NOTE: Here, we assume the `x5c` of JWS is filled a public key.
        // We will support to read a public key from a data source also.
        super::verify_signature(&request_content.owner_party_id, None, &jws)?;
        self.storage_engine
            .delete_data_policy(
                &request_content.owner_party_id,
                &request_content.scope,
                &request_content.data_uuid,
            )
            .await?;
        Ok(EncryptedResponse {
            status: Some(Status {
                code: Code::Ok as i32,
                message: "success".to_owned(),
                details: vec![],
            }),
            message: None,
        })
    }

    pub async fn delete_data_rule_impl(
        &self,
        encrypt_request: &EncryptedRequest,
    ) -> Result<EncryptedResponse, Error> {
        let (request_content, jws) =
            super::get_request::<DeleteDataRuleRequest>(&self.kek_pri, encrypt_request)?;
        let jws = jws.ok_or(errno!(ErrorCode::NotFound, "Missing signature"))?;
        // NOTE: Here, we assume the `x5c` of JWS is filled a public key.
        // We will support to read a public key from a data source also.
        super::verify_signature(&request_content.owner_party_id, None, &jws)?;
        self.storage_engine
            .delete_data_rule(
                &request_content.owner_party_id,
                &request_content.scope,
                &request_content.data_uuid,
                &request_content.rule_id,
            )
            .await?;
        Ok(EncryptedResponse {
            status: Some(Status {
                code: Code::Ok as i32,
                message: "success".to_owned(),
                details: vec![],
            }),
            message: None,
        })
    }
}
