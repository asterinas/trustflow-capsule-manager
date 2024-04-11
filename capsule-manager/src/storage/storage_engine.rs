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

use crate::error::errors::AuthResult;
use crate::proto;
use std::fmt::Debug;
use tonic::async_trait;

#[async_trait]
pub trait StorageEngine: Send + Sync + Debug {
    async fn store_data_policy(
        &self,
        owner_party_id: &str,
        scope: &str,
        policy: &proto::Policy,
    ) -> AuthResult<()>;

    async fn store_data_keys(
        &self,
        owner_party_id: &str,
        data_keys: &Vec<proto::DataKey>,
    ) -> AuthResult<()>;

    async fn store_data_key(
        &self,
        resource_uri: &str,
        owner_party_id: &str,
        data_key: &str,
        ancestor_uuids: &Vec<String>,
    ) -> AuthResult<()>;

    // the func will verify whether owner_party_id is the real owner
    async fn delete_data_key(&self, owner_party_id: &str, resource_uri: &str) -> AuthResult<()>;

    async fn add_data_rule(
        &self,
        owner_party_id: &str,
        scope: &str,
        data_uuid: &str,
        rule: &proto::Rule,
    ) -> AuthResult<()>;

    async fn delete_data_policy(
        &self,
        owner_party_id: &str,
        scope: &str,
        data_uuid: &str,
    ) -> AuthResult<()>;

    async fn delete_data_rule(
        &self,
        owner_party_id: &str,
        scope: &str,
        data_uuid: &str,
        rule_id: &str,
    ) -> AuthResult<()>;

    async fn store_public_key(&self, owner_party_id: &str, public_key: &str) -> AuthResult<()>;

    async fn get_data_keys(&self, resource_uris: &Vec<&str>) -> AuthResult<Vec<proto::DataKey>>;

    async fn get_data_party(&self, resource_uri: &str) -> AuthResult<String>;

    async fn get_data_policys(
        &self,
        owner_party_id: &str,
        scope: &str,
    ) -> AuthResult<Vec<proto::Policy>>;

    async fn get_data_policy_by_id(
        &self,
        data_uuid: &str,
        scope: &str,
    ) -> AuthResult<proto::Policy>;

    async fn get_policy_party_by_id(&self, data_uuid: &str, scope: &str) -> AuthResult<String>;

    async fn get_public_key(&self, owner_party_id: &str) -> AuthResult<String>;

    async fn get_original_parties(&self, data_uuid: &str) -> AuthResult<Vec<String>>;
}
